// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// SourceAcquisitionMode records how the immutable lifecycle delivery entered
// AlertINT. A later on-demand API read may refresh evidence, but it must
// never rewrite this provenance from webhook to poll or back.
type SourceAcquisitionMode string

const (
	SourceAcquisitionWebhook SourceAcquisitionMode = "webhook"
	SourceAcquisitionPoll    SourceAcquisitionMode = "poll"
)

// SourceProvenance binds one immutable delivery to the reusable source
// signal whose lifecycle owns envelope authority. SignalID and SignalVersion
// are nil unless the Receiver can prove them from the source payload itself
// — never synthesized from an event ID, Alert fingerprint, wall clock, UUID,
// or a generic source/schema fallback. Unavailable provenance is honest
// durable state; it grants no envelope authority.
type SourceProvenance struct {
	SignalID            *string
	SignalVersion       *string
	GeneratorURL        string
	AcquisitionMode     SourceAcquisitionMode
	PollIntervalSeconds int
}

// DeliveryInput is one validated source lifecycle delivery to commit with its
// latest Alert projection and durable correlation dispatch.
type DeliveryInput struct {
	ID                       string
	Alert                    Alert
	Source                   string
	SourceEventID            *string
	SourceEpisodeKey         string
	SourceStartedAt          *time.Time
	SourceResolvedAt         *time.Time
	StartedAtBasis           situationmodel.SourceTimeBasis
	ResolvedAtBasis          situationmodel.SourceTimeBasis
	ReceiverGroupingIdentity string
	PayloadDigest            string
	SourceProvenance         SourceProvenance
}

// AlertDelivery is the immutable accepted source lifecycle record. Once
// committed, none of its fields are ever rewritten — a duplicate delivery ID
// returns the original row unchanged.
type AlertDelivery struct {
	ID                       string
	Alert                    Alert
	Source                   string
	SourceEventID            *string
	SourceEpisodeKey         string
	SourceStartedAt          *time.Time
	SourceResolvedAt         *time.Time
	StartedAtBasis           situationmodel.SourceTimeBasis
	ResolvedAtBasis          situationmodel.SourceTimeBasis
	ReceiverGroupingIdentity string
	PayloadDigest            string
	ReceivedAt               time.Time
	SourceProvenance         SourceProvenance
}

// AlertDispatch is the durable correlation outbox state for one delivery.
// It is fenced by (lease_owner, claim_token): every state transition after
// a claim must present both, and any mismatch means the lease moved on.
type AlertDispatch struct {
	Delivery       AlertDelivery
	Status         string
	LeaseOwner     *string
	LeaseExpiresAt *time.Time
	ClaimToken     int64
	AttemptCount   int
	LastErrorClass *string
	RetryAt        *time.Time
	AppliedAt      *time.Time
}

// ErrAlertDispatchLeaseLost means a worker no longer owns the claimed
// delivery dispatch — its lease token was superseded, most often because the
// original lease expired and a different worker reclaimed the row. Callers
// must discard the stale claim, not retry with it, on receiving this error.
var ErrAlertDispatchLeaseLost = errors.New("store: alert dispatch lease lost")

// ErrIncidentOwnerNotCollapsible means a plan to attach a delivery to an
// existing Incident (recurrence collapse, or a same-group retry-backoff
// attach) is no longer valid — the target Incident's status moved to a
// terminal state between planning and commit, or the Incident's owning
// Situation has reached a terminal lifecycle (a later firing must never
// cross a terminal Situation boundary). The caller must discard the plan
// and correlate the delivery as a fresh Incident instead; that fresh
// Incident's Situation input then opens a linked new Situation.
var ErrIncidentOwnerNotCollapsible = errors.New("store: incident owner does not permit correlated attach")

// CorrelatedDeliveryMutation is everything ApplyCorrelatedDelivery needs to
// commit one durably claimed delivery's correlation outcome in a single
// transaction. Incident carries the caller's plan — an existing Incident's
// identity to attach to, or a fresh Incident's proposed identity and times —
// preserving its exact GroupKey either way. Occurrence is non-nil only when
// the caller's plan is a recurrence collapse: a nil Occurrence.ID means
// "insert a new occurrence row", a non-zero one means "touch this existing
// occurrence's last_seen". RequireNonterminalOwner gates an attach-to-
// existing-Incident plan (recurrence collapse, retry-backoff attach) on the
// owner not having gone terminal between planning and commit — both the
// Incident's own status and, per the spec's terminal-boundary rule, its
// owning Situation's lifecycle, re-checked inside the transaction; it is
// never set for a fresh-Incident or resolved-delivery-association plan.
type CorrelatedDeliveryMutation struct {
	DeliveryID              string
	DispatchOwner           string
	DispatchClaimToken      int64
	Incident                Incident
	Occurrence              *Occurrence
	Input                   SituationInput
	RequireNonterminalOwner bool
}

// CorrelatedDeliveryResult is the durable outcome ApplyCorrelatedDelivery
// returns after its transaction commits. Incident reflects the row exactly
// as committed (whether freshly inserted, reused across a concurrent-first-
// delivery race, or already owning the delivery). Created is true only when
// this call's transaction itself inserted the Incident row. Resolved is true
// only when this call's transaction itself flipped the Incident to
// "resolved" (i.e. the Situation input Kind came out "incident_resolved").
// Duplicate is true when the delivery already owned an immutable
// incident_alert_deliveries link before this call — a successful no-op that
// still repairs a missing idempotent input or a stuck dispatch projection.
type CorrelatedDeliveryResult struct {
	Incident   Incident
	Created    bool
	Occurrence *Occurrence
	Resolved   bool
	Duplicate  bool
}

const incidentSelectByID = `
	SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at
	FROM incidents WHERE id = ?`

// validateCorrelatedDeliveryMutation checks the fields ApplyCorrelatedDelivery
// must have before it can safely open a transaction. It never touches the
// database.
func validateCorrelatedDeliveryMutation(m CorrelatedDeliveryMutation) error {
	if strings.TrimSpace(m.DeliveryID) == "" {
		return errors.New("store: correlated delivery requires a delivery id")
	}
	if strings.TrimSpace(m.DispatchOwner) == "" || m.DispatchClaimToken <= 0 {
		return errors.New("store: correlated delivery requires a complete dispatch claim")
	}
	if strings.TrimSpace(m.Incident.ID) == "" || strings.TrimSpace(m.Incident.GroupKey) == "" {
		return errors.New("store: correlated delivery requires incident identity")
	}
	if m.Incident.FirstAlertAt.IsZero() || m.Incident.LastAlertAt.IsZero() || m.Incident.ReadyAt.IsZero() {
		return errors.New("store: correlated delivery requires incident times")
	}
	if strings.TrimSpace(m.Input.ID) == "" || strings.TrimSpace(m.Input.IdempotencyKey) == "" || strings.TrimSpace(m.Input.Kind) == "" || m.Input.OccurredAt.IsZero() {
		return errors.New("store: correlated delivery requires situation input identity, kind, and time")
	}
	if m.Input.IncidentID != m.Incident.ID {
		return errors.New("store: correlated situation input incident does not match incident")
	}
	if m.Input.GroupKey != m.Incident.GroupKey {
		return errors.New("store: correlated situation input group key does not match incident")
	}
	if m.Input.DeliveryID == nil || *m.Input.DeliveryID != m.DeliveryID {
		return errors.New("store: correlated situation input does not match delivery")
	}
	if m.Occurrence != nil && m.Occurrence.IncidentID != m.Incident.ID {
		return errors.New("store: correlated occurrence does not match incident")
	}
	return nil
}

// verifyCorrelatedDispatchClaimTx confirms delivery_id is still claimed by
// (owner, token) at the instant this transaction observes it. A mismatch —
// the lease expired and moved on, or was never claimed — is
// ErrAlertDispatchLeaseLost, never a silent no-op.
func verifyCorrelatedDispatchClaimTx(ctx context.Context, tx *sql.Tx, deliveryID, owner string, token int64) error {
	var valid int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM alert_delivery_dispatches
		WHERE delivery_id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		deliveryID, owner, token).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAlertDispatchLeaseLost
	}
	if err != nil {
		return fmt.Errorf("store: verify correlated dispatch claim: %w", err)
	}
	return nil
}

// ensureCorrelatedIncidentTx resolves the Incident a correlated delivery
// attaches to. It first looks the plan up by ID — the ordinary case for a
// plan that already names a real, existing Incident (recurrence collapse,
// retry-backoff attach, resolved-delivery association, or a duplicate
// replay). Only when the plan is a genuinely fresh Incident (reuseCollecting)
// does it re-check for a collecting Incident under the same exact group_key
// before inserting — closing the concurrent-first-delivery race: two
// callers racing to open the first Incident for a brand-new group both
// resolve to the SAME collecting row, because every ApplyCorrelatedDelivery
// transaction runs on the store's single database connection (Open sets
// SetMaxOpenConns(1)), so this select-then-insert can never interleave with
// another one — there is never more than one such transaction in flight.
func ensureCorrelatedIncidentTx(ctx context.Context, tx *sql.Tx, inc Incident, reuseCollecting bool) (created bool, status, incidentID string, err error) {
	var groupKey string
	err = tx.QueryRowContext(ctx, `SELECT group_key, status FROM incidents WHERE id = ?`, inc.ID).Scan(&groupKey, &status)
	if err == nil {
		if groupKey != inc.GroupKey {
			return false, "", "", fmt.Errorf("store: correlated incident %s group key mismatch: have %q, want %q", inc.ID, groupKey, inc.GroupKey)
		}
		return false, status, inc.ID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, "", "", fmt.Errorf("store: read correlated incident: %w", err)
	}
	if reuseCollecting {
		var existingID string
		err = tx.QueryRowContext(ctx, `
			SELECT id, status FROM incidents
			WHERE group_key = ? AND status = 'collecting'
			ORDER BY created_at ASC, id ASC LIMIT 1`, inc.GroupKey).Scan(&existingID, &status)
		if err == nil {
			return false, status, existingID, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, "", "", fmt.Errorf("store: read collecting correlated incident: %w", err)
		}
	}
	now := canonicalTime(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, 'collecting', ?, ?, ?, 0, ?, ?)`,
		inc.ID, inc.GroupKey, canonicalTime(inc.FirstAlertAt), canonicalTime(inc.LastAlertAt), canonicalTime(inc.ReadyAt), now, now); err != nil {
		return false, "", "", fmt.Errorf("store: insert correlated incident: %w", err)
	}
	return true, "collecting", inc.ID, nil
}

// applyCorrelatedOccurrenceTx applies the caller's Occurrence plan, if any:
// nil does nothing; an Occurrence with ID == 0 inserts a new occurrence row
// (a genuine new episode); a non-zero ID only slides that occurrence's
// last_seen forward (an unchanged repeat touch). It returns the occurrence
// id to stamp onto the immutable delivery link, if any.
func applyCorrelatedOccurrenceTx(ctx context.Context, tx *sql.Tx, incidentID string, occ *Occurrence, deliveryReceivedAt time.Time) (sql.NullInt64, error) {
	if occ == nil {
		return sql.NullInt64{}, nil
	}
	if occ.ID == 0 {
		return insertCorrelatedOccurrenceTx(ctx, tx, *occ)
	}
	return touchCorrelatedOccurrenceTx(ctx, tx, incidentID, *occ, deliveryReceivedAt)
}

// insertCorrelatedOccurrenceTx records a genuinely new episode.
func insertCorrelatedOccurrenceTx(ctx context.Context, tx *sql.Tx, occ Occurrence) (sql.NullInt64, error) {
	trigger := occ.TriggerKind
	if trigger == "" {
		trigger = "none"
	}
	if !validTriggerKinds[trigger] {
		return sql.NullInt64{}, fmt.Errorf("store: occurrence: trigger_kind %q invalid", trigger)
	}
	lastSeen := occ.LastSeen
	if lastSeen.IsZero() {
		lastSeen = occ.OccurredAt
	}
	fpsJSON, err := json.Marshal(occ.Fingerprints)
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: occurrence: marshal fingerprints: %w", err)
	}
	payloadJSON, err := json.Marshal(occ.Payload)
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: occurrence: marshal payload: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO incident_occurrences (incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind, snapshot_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		occ.IncidentID, fmtOccTime(occ.OccurredAt), fmtOccTime(lastSeen), string(fpsJSON), string(payloadJSON), trigger, occ.SnapshotRef)
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: insert correlated occurrence: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: insert correlated occurrence id: %w", err)
	}
	return sql.NullInt64{Int64: id, Valid: true}, nil
}

// touchCorrelatedOccurrenceTx slides an unchanged repeat's last_seen forward
// without minting a new episode.
func touchCorrelatedOccurrenceTx(ctx context.Context, tx *sql.Tx, incidentID string, occ Occurrence, deliveryReceivedAt time.Time) (sql.NullInt64, error) {
	lastSeen := occ.LastSeen
	if lastSeen.IsZero() {
		lastSeen = deliveryReceivedAt
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_occurrences SET last_seen = MAX(last_seen, ?)
		WHERE id = ? AND incident_id = ?`, fmtOccTime(lastSeen), occ.ID, incidentID)
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: touch correlated occurrence: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return sql.NullInt64{}, fmt.Errorf("store: count touched correlated occurrence: %w", err)
	}
	if changed != 1 {
		return sql.NullInt64{}, ErrNotFound
	}
	return sql.NullInt64{Int64: occ.ID, Valid: true}, nil
}

// attachCorrelatedDeliveryTx attaches the current Alert projection to the
// Incident with INSERT OR IGNORE (a delivery whose alert already joined the
// Incident, e.g. an unchanged repeat, is a no-op here), updates the
// Incident's count and times from the rows actually affected (never a blind
// increment), and inserts the delivery's unique immutable ownership link.
func attachCorrelatedDeliveryTx(ctx context.Context, tx *sql.Tx, incidentID, deliveryID, alertID string, occurrenceID sql.NullInt64, deliveryReceivedAt, now time.Time) error {
	memberRes, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, created_at)
		VALUES (?, ?, ?)`, incidentID, alertID, canonicalTime(now))
	if err != nil {
		return fmt.Errorf("store: attach correlated alert projection: %w", err)
	}
	memberAdded, err := memberRes.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count correlated alert projection: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE incidents
		SET alert_count = alert_count + ?, last_alert_at = MAX(last_alert_at, ?), updated_at = ?
		WHERE id = ?`, memberAdded, canonicalTime(deliveryReceivedAt), canonicalTime(now), incidentID); err != nil {
		return fmt.Errorf("store: update correlated incident: %w", err)
	}

	var occurrenceValue any
	if occurrenceID.Valid {
		occurrenceValue = occurrenceID.Int64
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, occurrence_id, created_at)
		VALUES (?, ?, ?, ?)`, incidentID, deliveryID, occurrenceValue, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: link correlated delivery: %w", err)
	}
	return nil
}

// unresolvedIncidentMembersTx counts the Incident's current members (from
// the compatibility incident_alerts table) whose most recent immutable
// delivery status is not "resolved" — an alert with no delivery-ledger row
// at all defaults to "firing", the safe (unresolved) assumption. Zero means
// every immutable member delivery agrees the condition has recovered.
func unresolvedIncidentMembersTx(ctx context.Context, tx *sql.Tx, incidentID string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM incident_alerts AS ia
		WHERE ia.incident_id = ?
		  AND COALESCE((
			SELECT ad.status
			FROM incident_alert_deliveries AS iad
			JOIN alert_deliveries AS ad ON ad.id = iad.delivery_id
			WHERE iad.incident_id = ia.incident_id AND ad.alert_id = ia.alert_id
			ORDER BY ad.received_at DESC, ad.id DESC
			LIMIT 1
		  ), 'firing') <> 'resolved'`, incidentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: count unresolved correlated incident members: %w", err)
	}
	return count, nil
}

// correlatedSituationInputKindTx derives the Situation input Kind from
// committed state, never from the caller's pre-transaction guess alone: a
// freshly inserted Incident is always "incident_created"; otherwise, only a
// resolved delivery landing on a "ready" or "analyzed" Incident whose every
// immutable member delivery now agrees the condition recovered flips the
// Incident to "resolved" and reports "incident_resolved". Anything else
// keeps the caller's requested Kind (ordinarily "membership_changed").
func correlatedSituationInputKindTx(ctx context.Context, tx *sql.Tx, requested, incidentID, deliveryStatus, incidentStatus string, created bool, now time.Time) (kind string, resolved bool, err error) {
	if created {
		return "incident_created", false, nil
	}
	if deliveryStatus != "resolved" || (incidentStatus != "ready" && incidentStatus != "analyzed") {
		return requested, false, nil
	}
	unresolved, err := unresolvedIncidentMembersTx(ctx, tx, incidentID)
	if err != nil {
		return requested, false, err
	}
	if unresolved != 0 {
		return requested, false, nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'resolved', updated_at = ? WHERE id = ? AND status IN ('ready', 'analyzed')`,
		canonicalTime(now), incidentID)
	if err != nil {
		return "", false, fmt.Errorf("store: resolve correlated incident: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("store: count resolved correlated incident: %w", err)
	}
	if changed == 1 {
		return "incident_resolved", true, nil
	}
	return requested, false, nil
}

// markCorrelatedDispatchAppliedTx fences the applied transition on the exact
// claim this call verified at the top of its transaction, so nothing else
// could have moved the lease in between.
func markCorrelatedDispatchAppliedTx(ctx context.Context, tx *sql.Tx, deliveryID, owner string, token int64, at time.Time) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status='applied', lease_owner=NULL, lease_expires_at=NULL, retry_at=NULL, applied_at=?
		WHERE delivery_id=? AND status='claimed' AND lease_owner=? AND claim_token=?`,
		canonicalTime(at), deliveryID, owner, token)
	if err != nil {
		return fmt.Errorf("store: mark correlated dispatch applied: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count correlated dispatch applied: %w", err)
	}
	if n != 1 {
		return ErrAlertDispatchLeaseLost
	}
	return nil
}

// ApplyCorrelatedDelivery verifies the current dispatch lease and atomically
// performs the Incident/Occurrence mutation, current incident_alerts
// compatibility attachment, immutable incident_alert_deliveries ownership,
// Situation-input insertion, and dispatch transition to "applied" in one
// transaction. Reapplying an already-owned delivery is a successful no-op
// (Duplicate=true) that still repairs a missing idempotent input or a stuck
// "claimed" dispatch projection before acknowledging the current claim —
// there is no separate success acknowledgment after this method, which
// removes the crash window between applying correlation and completing the
// dispatch.
func (s *Store) ApplyCorrelatedDelivery(ctx context.Context, m CorrelatedDeliveryMutation) (CorrelatedDeliveryResult, error) {
	if err := validateCorrelatedDeliveryMutation(m); err != nil {
		return CorrelatedDeliveryResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: begin correlated delivery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyCorrelatedDispatchClaimTx(ctx, tx, m.DeliveryID, m.DispatchOwner, m.DispatchClaimToken); err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	var existingIncidentID string
	err = tx.QueryRowContext(ctx, `SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = ?`, m.DeliveryID).Scan(&existingIncidentID)
	switch {
	case err == nil:
		return applyDuplicateCorrelatedDeliveryTx(ctx, tx, m, existingIncidentID)
	case !errors.Is(err, sql.ErrNoRows):
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: read correlated delivery ownership: %w", err)
	}

	var alertID, deliveryStatus, receivedAtStr string
	if err := tx.QueryRowContext(ctx, `SELECT alert_id, status, received_at FROM alert_deliveries WHERE id = ?`, m.DeliveryID).
		Scan(&alertID, &deliveryStatus, &receivedAtStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CorrelatedDeliveryResult{}, ErrNotFound
		}
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: read correlated delivery: %w", err)
	}
	deliveryReceivedAt, err := time.Parse(time.RFC3339Nano, receivedAtStr)
	if err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: parse correlated delivery received time: %w", err)
	}

	reuseCollecting := m.Input.Kind == "incident_created" && m.Occurrence == nil
	created, incidentStatus, incidentID, err := ensureCorrelatedIncidentTx(ctx, tx, m.Incident, reuseCollecting)
	if err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	requestedKind := m.Input.Kind
	if incidentID != m.Incident.ID {
		// The plan's imagined Incident ID lost the race (or never existed to
		// begin with, for a plan that already named a real Incident under a
		// mismatched ID — which fails the group-key check inside
		// ensureCorrelatedIncidentTx instead). Downgrade to plain membership.
		m.Incident.ID = incidentID
		m.Input.IncidentID = incidentID
		requestedKind = "membership_changed"
	}

	if m.RequireNonterminalOwner {
		if incidentStatus == "failed" {
			return CorrelatedDeliveryResult{}, ErrIncidentOwnerNotCollapsible
		}
		terminal, err := terminalSituationOwnerTx(ctx, tx, m.Incident.ID)
		if err != nil {
			return CorrelatedDeliveryResult{}, err
		}
		if terminal {
			return CorrelatedDeliveryResult{}, ErrIncidentOwnerNotCollapsible
		}
	}

	now := time.Now().UTC()
	occurrenceID, err := applyCorrelatedOccurrenceTx(ctx, tx, m.Incident.ID, m.Occurrence, deliveryReceivedAt)
	if err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	if err := attachCorrelatedDeliveryTx(ctx, tx, m.Incident.ID, m.DeliveryID, alertID, occurrenceID, deliveryReceivedAt, now); err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	kind, resolved, err := correlatedSituationInputKindTx(ctx, tx, requestedKind, m.Incident.ID, deliveryStatus, incidentStatus, created, now)
	if err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
		m.Input.ID, m.Input.IdempotencyKey, m.Incident.ID, m.DeliveryID, kind, m.Incident.GroupKey, canonicalTime(deliveryReceivedAt.UTC())); err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: insert correlated situation input: %w", err)
	}

	if err := markCorrelatedDispatchAppliedTx(ctx, tx, m.DeliveryID, m.DispatchOwner, m.DispatchClaimToken, now); err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	incPtr, err := scanIncident(tx.QueryRowContext(ctx, incidentSelectByID, m.Incident.ID))
	if err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: read committed correlated incident: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: commit correlated delivery: %w", err)
	}

	result := CorrelatedDeliveryResult{Incident: *incPtr, Created: created, Resolved: resolved}
	if m.Occurrence != nil {
		occ := *m.Occurrence
		occ.IncidentID = m.Incident.ID
		if occurrenceID.Valid {
			occ.ID = occurrenceID.Int64
		}
		result.Occurrence = &occ
	}
	return result, nil
}

// terminalSituationOwnerTx reports whether incidentID's owning Situation —
// if it has one — has reached a terminal lifecycle ("recovered" or
// "closed_unknown"). A later firing must not cross a terminal Situation
// boundary: correlation re-checks the owner inside the durable mutation so
// a recurrence collapse or retry attach onto an Incident whose episode
// already closed is rejected (ErrIncidentOwnerNotCollapsible) and the
// delivery falls through to a fresh Incident, whose Situation input then
// opens a linked new Situation (previous_situation_id).
func terminalSituationOwnerTx(ctx context.Context, tx *sql.Tx, incidentID string) (bool, error) {
	var lifecycle string
	err := tx.QueryRowContext(ctx, `
		SELECT s.lifecycle FROM situation_incidents si
		JOIN situations s ON s.id = si.situation_id
		WHERE si.incident_id = ?`, incidentID).Scan(&lifecycle)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read correlated incident's situation owner: %w", err)
	}
	return lifecycle == "recovered" || lifecycle == "closed_unknown", nil
}

// applyDuplicateCorrelatedDeliveryTx handles a delivery that already owns an
// immutable incident_alert_deliveries link: steps 3–7 (the Incident/
// Occurrence mutation, membership, and ownership link) never re-run, but
// steps 8–10 still repair a missing idempotent input or a stuck "claimed"
// dispatch projection before this call acknowledges the current claim.
func applyDuplicateCorrelatedDeliveryTx(ctx context.Context, tx *sql.Tx, m CorrelatedDeliveryMutation, incidentID string) (CorrelatedDeliveryResult, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
		m.Input.ID, m.Input.IdempotencyKey, incidentID, m.DeliveryID, m.Input.Kind, m.Input.GroupKey, canonicalTime(m.Input.OccurredAt.UTC())); err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: repair correlated situation input: %w", err)
	}

	now := time.Now().UTC()
	if err := markCorrelatedDispatchAppliedTx(ctx, tx, m.DeliveryID, m.DispatchOwner, m.DispatchClaimToken, now); err != nil {
		return CorrelatedDeliveryResult{}, err
	}

	incPtr, err := scanIncident(tx.QueryRowContext(ctx, incidentSelectByID, incidentID))
	if err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: read duplicate correlated incident: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return CorrelatedDeliveryResult{}, fmt.Errorf("store: commit duplicate correlated delivery: %w", err)
	}
	return CorrelatedDeliveryResult{Incident: *incPtr, Duplicate: true}, nil
}

// MarkIncidentReadyWithSituationInput atomically transitions incidentID from
// "collecting" to "ready", appends its one delivery-independent
// incident_ready Situation input (idempotency key "incident-ready:<incident
// id>"), and creates its awaiting_decision Acute Triage schedule row at
// attempt zero — all in the same commit (Task 6: "ready and schedule
// awaiting_decision are committed together"). Every ready Incident begins in
// awaiting_decision; no dispatch can happen before a controller decision
// (Task 8's CommitController, via the unexported applyTriageDecisionsTx)
// moves it to pending. An already-"ready" Incident carrying the matching
// input is a successful no-op — the idempotent replay a crash between this
// method's commit and its caller's next step would produce; INSERT OR
// IGNORE on the schedule row makes that replay safe even if a prior attempt
// committed the ready transition/input but crashed before this method
// itself returned. Any other Incident state — "processing", "analyzed",
// "resolved", "failed", or no such Incident at all — is ErrNotFound. This
// method does not begin or complete incident_triage.
func (s *Store) MarkIncidentReadyWithSituationInput(ctx context.Context, incidentID string, now time.Time) error {
	if strings.TrimSpace(incidentID) == "" {
		return errors.New("store: mark incident ready requires an incident id")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mark incident ready: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status, groupKey string
	err = tx.QueryRowContext(ctx, `SELECT status, group_key FROM incidents WHERE id = ?`, incidentID).Scan(&status, &groupKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: read incident for ready transition: %w", err)
	}

	idempotencyKey := "incident-ready:" + incidentID
	switch status {
	case "collecting":
		res, err := tx.ExecContext(ctx, `UPDATE incidents SET status='ready', updated_at=? WHERE id=? AND status='collecting'`, canonicalTime(now), incidentID)
		if err != nil {
			return fmt.Errorf("store: mark incident ready: %w", err)
		}
		if n, rerr := res.RowsAffected(); rerr != nil {
			return fmt.Errorf("store: count mark incident ready: %w", rerr)
		} else if n != 1 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
			VALUES (?, ?, ?, 'incident_ready', ?, ?, 'pending')`,
			"situation-input:"+idempotencyKey, idempotencyKey, incidentID, groupKey, canonicalTime(now)); err != nil {
			return fmt.Errorf("store: insert incident ready situation input: %w", err)
		}
		if err := seedAwaitingDecisionTriageTx(ctx, tx, incidentID, now); err != nil {
			return err
		}
	case "ready":
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM situation_input_outbox WHERE idempotency_key = ?`, idempotencyKey).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: incident %s is ready without its incident_ready situation input", incidentID)
		}
		if err != nil {
			return fmt.Errorf("store: check incident ready situation input: %w", err)
		}
		// Idempotent no-op for the ready transition and its input, which
		// already committed together; the schedule row insert below is
		// itself INSERT-OR-IGNORE, repairing a crash that landed between
		// this method's own two inserts on an earlier call.
		if err := seedAwaitingDecisionTriageTx(ctx, tx, incidentID, now); err != nil {
			return err
		}
	default:
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit mark incident ready: %w", err)
	}
	return nil
}

// validateDeliveryInput checks the fields AcceptDeliveries must have before
// it can safely open a transaction. It never touches the database.
func validateDeliveryInput(d DeliveryInput) error {
	if err := validateAlert(d.Alert); err != nil {
		return err
	}
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("store: delivery id is required")
	}
	if strings.TrimSpace(d.Source) == "" {
		return errors.New("store: delivery source is required")
	}
	if strings.TrimSpace(d.SourceEpisodeKey) == "" {
		return errors.New("store: delivery source episode key is required")
	}
	if strings.TrimSpace(d.ReceiverGroupingIdentity) == "" {
		return errors.New("store: delivery receiver grouping identity is required")
	}
	if strings.TrimSpace(d.PayloadDigest) == "" {
		return errors.New("store: delivery payload digest is required")
	}
	return validateSourceProvenance(d)
}

// validateSourceProvenance enforces the two provenance rules the store must
// never relax: SignalVersion requires SignalID (identity may be provable
// while version is not), and the acquisition mode's poll interval contract
// (zero for webhook, positive for poll).
func validateSourceProvenance(d DeliveryInput) error {
	p := d.SourceProvenance
	switch p.AcquisitionMode {
	case SourceAcquisitionWebhook:
		if p.PollIntervalSeconds != 0 {
			return errors.New("store: delivery poll interval must be zero for webhook acquisition")
		}
	case SourceAcquisitionPoll:
		if p.PollIntervalSeconds <= 0 {
			return errors.New("store: delivery poll interval must be positive for poll acquisition")
		}
	default:
		return fmt.Errorf("store: delivery acquisition mode %q must be webhook or poll", p.AcquisitionMode)
	}
	if p.SignalID != nil && strings.TrimSpace(*p.SignalID) == "" {
		return errors.New("store: delivery source signal id must not be blank when present")
	}
	if p.SignalVersion != nil {
		if strings.TrimSpace(*p.SignalVersion) == "" {
			return errors.New("store: delivery source signal version must not be blank when present")
		}
		if p.SignalID == nil {
			return errors.New("store: delivery source signal version requires a source signal id")
		}
	}
	return nil
}

func validSourceTimeBasis(v situationmodel.SourceTimeBasis) bool {
	switch v {
	case situationmodel.SourceTimeBasisSourcePayload, situationmodel.SourceTimeBasisSourceAPI,
		situationmodel.SourceTimeBasisReceiptFallback, situationmodel.SourceTimeBasisMissing,
		situationmodel.SourceTimeBasisMixed:
		return true
	default:
		return false
	}
}

// preparedDelivery holds one validated, normalized delivery plus the exact
// SQL argument encodings it will need, so AcceptDeliveries never does string
// or JSON work after opening its transaction.
type preparedDelivery struct {
	in         DeliveryInput
	labelsJSON string
	annosJSON  string
	receivedAt string
	startsAt   string
	endsAt     any
	startedAt  any
	resolvedAt any
}

// prepareDelivery validates d and normalizes it into the exact form
// AcceptDeliveries writes. It performs no I/O.
func prepareDelivery(d DeliveryInput) (preparedDelivery, error) {
	if err := validateDeliveryInput(d); err != nil {
		return preparedDelivery{}, err
	}
	if !validSourceTimeBasis(d.StartedAtBasis) || !validSourceTimeBasis(d.ResolvedAtBasis) {
		return preparedDelivery{}, fmt.Errorf("store: invalid delivery source time basis started=%q resolved=%q", d.StartedAtBasis, d.ResolvedAtBasis)
	}
	d.SourceProvenance = normalizeSourceProvenance(d.SourceProvenance)

	labelsJSON, err := json.Marshal(d.Alert.Labels)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery labels: %w", err)
	}
	annosJSON, err := json.Marshal(d.Alert.Annotations)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery annotations: %w", err)
	}

	p := preparedDelivery{
		in:         d,
		labelsJSON: string(labelsJSON),
		annosJSON:  string(annosJSON),
		receivedAt: canonicalTime(d.Alert.ReceivedAt),
		startsAt:   canonicalTime(d.Alert.StartsAt),
	}
	if d.Alert.EndsAt != nil {
		p.endsAt = canonicalTime(*d.Alert.EndsAt)
	}
	if d.SourceStartedAt != nil {
		p.startedAt = canonicalTime(*d.SourceStartedAt)
	}
	if d.SourceResolvedAt != nil {
		p.resolvedAt = canonicalTime(*d.SourceResolvedAt)
	}
	return p, nil
}

// normalizeSourceProvenance trims whitespace only. It must never invent a
// SignalID, SignalVersion, or GeneratorURL — those are Receiver-proven or
// absent; the caller (an ingress receiver) is responsible for supplying them.
func normalizeSourceProvenance(p SourceProvenance) SourceProvenance {
	if p.SignalID != nil {
		v := strings.TrimSpace(*p.SignalID)
		p.SignalID = &v
	}
	if p.SignalVersion != nil {
		v := strings.TrimSpace(*p.SignalVersion)
		p.SignalVersion = &v
	}
	p.GeneratorURL = strings.TrimSpace(p.GeneratorURL)
	return p
}

func canonicalTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// AcceptDeliveries validates every input before opening a transaction, then
// atomically commits the latest Alert projection, the immutable delivery
// row, and a pending correlation dispatch row for each new delivery. A
// duplicate delivery ID is a successful no-op: it returns the existing
// immutable delivery and touches no other row, so transport redelivery of
// the same normalized payload can never mutate an already accepted
// projection. One invalid member fails the whole batch before any row is
// written.
func (s *Store) AcceptDeliveries(ctx context.Context, in []DeliveryInput) ([]AlertDelivery, error) {
	prepared := make([]preparedDelivery, len(in))
	for i, d := range in {
		p, err := prepareDelivery(d)
		if err != nil {
			return nil, err
		}
		prepared[i] = p
	}
	if len(prepared) == 0 {
		return []AlertDelivery{}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin accept deliveries: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	out := make([]AlertDelivery, 0, len(prepared))
	for _, p := range prepared {
		existing, err := getDeliveryTx(ctx, tx, p.in.ID)
		switch {
		case err == nil:
			out = append(out, existing)
			continue
		case !errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("store: read existing delivery: %w", err)
		}

		alert, err := upsertDeliveryAlertTx(ctx, tx, p)
		if err != nil {
			return nil, err
		}
		delivery, err := insertDeliveryTx(ctx, tx, p, alert)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_delivery_dispatches (delivery_id, status) VALUES (?, 'pending')`, delivery.ID); err != nil {
			return nil, fmt.Errorf("store: insert alert delivery dispatch: %w", err)
		}
		out = append(out, delivery)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit accept deliveries: %w", err)
	}
	return out, nil
}

// upsertDeliveryAlertTx applies the "latest wins" Alert projection update
// inside the caller's transaction, mirroring UpsertAlertByFingerprint.
func upsertDeliveryAlertTx(ctx context.Context, tx *sql.Tx, p preparedDelivery) (Alert, error) {
	a := p.in.Alert
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, ends_at, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			status = excluded.status, labels_json = excluded.labels_json,
			annotations_json = excluded.annotations_json, starts_at = excluded.starts_at,
			ends_at = excluded.ends_at, received_at = excluded.received_at
	`, a.ID, a.Fingerprint, a.Status, p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt, p.receivedAt)
	if err != nil {
		return Alert{}, fmt.Errorf("store: upsert delivery alert: %w", err)
	}
	row := tx.QueryRowContext(ctx, `SELECT id FROM alerts WHERE fingerprint = ?`, a.Fingerprint)
	if err := row.Scan(&a.ID); err != nil {
		return Alert{}, fmt.Errorf("store: read back delivery alert: %w", err)
	}
	a.ReceiverGroupingIdentity = p.in.ReceiverGroupingIdentity
	return a, nil
}

func insertDeliveryTx(ctx context.Context, tx *sql.Tx, p preparedDelivery, a Alert) (AlertDelivery, error) {
	d := p.in
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			id, alert_id, source, source_event_id, source_episode_key, status,
			labels_json, annotations_json, starts_at, ends_at,
			source_started_at, source_resolved_at, started_at_basis, resolved_at_basis,
			receiver_grouping_identity, payload_digest,
			source_signal_id, source_signal_version, generator_url, acquisition_mode, poll_interval_seconds,
			received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		d.ID, a.ID, d.Source, nullableString(d.SourceEventID), d.SourceEpisodeKey, d.Alert.Status,
		p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt,
		p.startedAt, p.resolvedAt, string(d.StartedAtBasis), string(d.ResolvedAtBasis),
		d.ReceiverGroupingIdentity, d.PayloadDigest,
		nullableString(d.SourceProvenance.SignalID), nullableString(d.SourceProvenance.SignalVersion),
		d.SourceProvenance.GeneratorURL, string(d.SourceProvenance.AcquisitionMode), d.SourceProvenance.PollIntervalSeconds,
		p.receivedAt,
	)
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: insert alert delivery: %w", err)
	}
	return AlertDelivery{
		ID: d.ID, Alert: a, Source: d.Source, SourceEventID: copyStringPtr(d.SourceEventID),
		SourceEpisodeKey: d.SourceEpisodeKey, SourceStartedAt: copyTimePtr(d.SourceStartedAt), SourceResolvedAt: copyTimePtr(d.SourceResolvedAt),
		StartedAtBasis: d.StartedAtBasis, ResolvedAtBasis: d.ResolvedAtBasis, ReceiverGroupingIdentity: d.ReceiverGroupingIdentity,
		PayloadDigest: d.PayloadDigest, ReceivedAt: d.Alert.ReceivedAt.UTC(), SourceProvenance: d.SourceProvenance,
	}, nil
}

// ClaimAlertDispatches leases due dispatches — pending rows never claimed,
// or claimed rows whose lease has expired — in one atomic transaction.
// Claiming increments both claim_token (fencing every prior lease holder
// out) and attempt_count. Rows are claimed and returned in a deterministic
// order: retry_at (nulls last, i.e. behind pending's receipt time), then
// delivery receipt time, then delivery ID. Claiming never calls outbound
// code; callers apply the claimed work only after this transaction commits.
//
// This deliberately mirrors ClaimSituationInputs' claim shape one table over
// (alert_delivery_dispatches vs. situation_input_outbox); this plan's own
// pre-flight conflict scan already ruled the analogous per-package
// WorkerConfig duplication intentional rather than something to unify across
// the two claim mechanisms.
//
//nolint:dupl // mirrors ClaimSituationInputs deliberately; see doc comment above
func (s *Store) ClaimAlertDispatches(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]AlertDispatch, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: dispatch claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim alert dispatches: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?,
		    claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE delivery_id IN (
			SELECT d.delivery_id
			FROM alert_delivery_dispatches AS d
			JOIN alert_deliveries AS ad ON ad.id = d.delivery_id
			WHERE (d.status = 'pending' AND (d.retry_at IS NULL OR d.retry_at <= ?))
			   OR (d.status = 'claimed' AND d.lease_expires_at IS NOT NULL AND d.lease_expires_at <= ?)
			ORDER BY COALESCE(d.retry_at, ad.received_at) ASC, ad.received_at ASC, d.delivery_id ASC
			LIMIT ?
		)
		RETURNING delivery_id
	`, owner, leaseExpires, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim alert dispatches: %w", err)
	}
	claimedIDs, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatch ids: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty alert dispatch claim: %w", err)
		}
		return []AlertDispatch{}, nil
	}

	out, err := loadClaimedDispatchesTx(ctx, tx, claimedIDs, owner)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim alert dispatches: %w", err)
	}
	return out, nil
}

// scanStringRows drains rows into a []string and always closes rows, even on
// a scan error, so the caller's connection is never left with an open
// result set blocking the next statement on the same transaction.
func scanStringRows(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// loadClaimedDispatchesTx re-reads the just-claimed rows in the same
// deterministic order ClaimAlertDispatches claimed them in. A bare
// UPDATE ... RETURNING does not guarantee it preserves the subquery's
// ORDER BY, so this issues one more SELECT with an explicit ORDER BY of its
// own — using retry_at/received_at/delivery_id, which the claiming UPDATE
// never touches, so they still reflect the pre-claim ordering.
func loadClaimedDispatchesTx(ctx context.Context, tx *sql.Tx, ids []string, owner string) ([]AlertDispatch, error) {
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, owner)
	query := dispatchSelect + ` WHERE d.delivery_id IN (` + strings.Join(placeholders, ",") +
		`) AND d.status = 'claimed' AND d.lease_owner = ?
		ORDER BY COALESCE(d.retry_at, ad.received_at) ASC, ad.received_at ASC, d.delivery_id ASC` // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(ids) only; all runtime values bound via ? in args

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]AlertDispatch, 0, len(ids))
	for rows.Next() {
		d, err := scanDispatch(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan claimed alert dispatch: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed alert dispatches: %w", err)
	}
	return out, nil
}

// errorClassPattern is the stable-lowercase-identifier contract for
// last_error_class: lowercase letters, digits, and underscores, starting
// with a letter. It exists to keep this column a closed-vocabulary-shaped
// classification, never a place a raw error message (which could embed a
// URL, header value, or other sensitive/verbose text) can land.
var errorClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// maxErrorClassLength bounds last_error_class well below anything a raw
// error message would need, so an oversized value is rejected rather than
// silently truncated.
const maxErrorClassLength = 64

// validateErrorClass enforces that class is a stable lowercase identifier
// (e.g. "transient", "rate_limited"), never raw error text. It never
// sanitizes or truncates — a non-conforming class is a validation error,
// not something this function repairs.
func validateErrorClass(class string) error {
	if class == "" {
		return errors.New("store: alert dispatch error class is required")
	}
	if len(class) > maxErrorClassLength {
		return fmt.Errorf("store: alert dispatch error class exceeds %d characters", maxErrorClassLength)
	}
	if !errorClassPattern.MatchString(class) {
		return errors.New("store: alert dispatch error class must be a lowercase identifier (e.g. \"transient\"), not raw error text")
	}
	return nil
}

// RetryAlertDispatch releases a claimed dispatch back to "pending" for a
// future retry, or marks it terminally "failed" when terminal is true. The
// update is fenced on (delivery_id, status='claimed', lease_owner,
// claim_token) all at once: if any of those has moved on since claim was
// issued, exactly zero rows change and this returns
// ErrAlertDispatchLeaseLost instead of silently doing nothing.
func (s *Store) RetryAlertDispatch(ctx context.Context, claim AlertDispatch, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(claim.Delivery.ID) == "" || claim.LeaseOwner == nil || strings.TrimSpace(*claim.LeaseOwner) == "" ||
		claim.ClaimToken <= 0 {
		return errors.New("store: alert dispatch retry requires a complete claim")
	}
	if err := validateErrorClass(class); err != nil {
		return err
	}
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status, retry = "failed", nil
	} else if retryAt.IsZero() {
		return errors.New("store: alert dispatch retry time is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status=?, lease_owner=NULL, lease_expires_at=NULL,
		    last_error_class=?, retry_at=?
		WHERE delivery_id=? AND status='claimed' AND lease_owner=? AND claim_token=?`,
		status, class, retry, claim.Delivery.ID, *claim.LeaseOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: retry alert dispatch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried alert dispatch: %w", err)
	}
	if n != 1 {
		return ErrAlertDispatchLeaseLost
	}
	return nil
}

const deliverySelect = `
SELECT ad.id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest,
       ad.source_signal_id, ad.source_signal_version, ad.generator_url, ad.acquisition_mode, ad.poll_interval_seconds,
       ad.received_at, a.fingerprint
FROM alert_deliveries ad JOIN alerts a ON a.id = ad.alert_id`

const dispatchSelect = `
SELECT d.delivery_id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest,
       ad.source_signal_id, ad.source_signal_version, ad.generator_url, ad.acquisition_mode, ad.poll_interval_seconds,
       ad.received_at, a.fingerprint,
       d.status, d.lease_owner, d.lease_expires_at, d.claim_token, d.attempt_count, d.last_error_class, d.retry_at, d.applied_at
FROM alert_delivery_dispatches d
JOIN alert_deliveries ad ON ad.id = d.delivery_id
JOIN alerts a ON a.id = ad.alert_id`

func getDeliveryTx(ctx context.Context, tx *sql.Tx, id string) (AlertDelivery, error) {
	row := tx.QueryRowContext(ctx, deliverySelect+` WHERE ad.id = ?`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertDelivery{}, ErrNotFound
	}
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: read delivery: %w", err)
	}
	return d, nil
}

// rawDeliveryFields holds the string-typed columns shared by deliverySelect
// and dispatchSelect, scanned before being parsed/typed by hydrateDelivery.
type rawDeliveryFields struct {
	sourceEvent, alertEnds, sourceStarted, sourceResolved, signalID, signalVersion sql.NullString
	status, labels, annotations, startsAt, startedBasis, resolvedBasis             string
	generatorURL, acquisitionMode, receivedAt                                      string
	pollInterval                                                                   int
}

// deliveryScanDest returns the Scan destinations for the deliverySelect
// column list (and the shared prefix of dispatchSelect), writing directly
// into dest and r.
func deliveryScanDest(dest *AlertDelivery, r *rawDeliveryFields) []any {
	return []any{
		&dest.ID, &dest.Alert.ID, &dest.Source, &r.sourceEvent, &dest.SourceEpisodeKey, &r.status,
		&r.labels, &r.annotations, &r.startsAt, &r.alertEnds, &r.sourceStarted, &r.sourceResolved,
		&r.startedBasis, &r.resolvedBasis, &dest.ReceiverGroupingIdentity, &dest.PayloadDigest,
		&r.signalID, &r.signalVersion, &r.generatorURL, &r.acquisitionMode, &r.pollInterval,
		&r.receivedAt, &dest.Alert.Fingerprint,
	}
}

func hydrateDelivery(d *AlertDelivery, r rawDeliveryFields) error {
	if err := json.Unmarshal([]byte(r.labels), &d.Alert.Labels); err != nil {
		return fmt.Errorf("store: unmarshal delivery labels: %w", err)
	}
	if err := json.Unmarshal([]byte(r.annotations), &d.Alert.Annotations); err != nil {
		return fmt.Errorf("store: unmarshal delivery annotations: %w", err)
	}
	startsAt, err := time.Parse(time.RFC3339Nano, r.startsAt)
	if err != nil {
		return fmt.Errorf("store: parse delivery alert starts at: %w", err)
	}
	d.Alert.StartsAt = startsAt
	if d.Alert.EndsAt, err = timePtr(r.alertEnds); err != nil {
		return err
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, r.receivedAt)
	if err != nil {
		return fmt.Errorf("store: parse delivery received at: %w", err)
	}
	d.Alert.ReceivedAt = receivedAt
	d.ReceivedAt = receivedAt
	d.Alert.Status = r.status
	d.Alert.ReceiverGroupingIdentity = d.ReceiverGroupingIdentity
	d.SourceEventID = stringPtr(r.sourceEvent)
	if d.SourceStartedAt, err = timePtr(r.sourceStarted); err != nil {
		return err
	}
	if d.SourceResolvedAt, err = timePtr(r.sourceResolved); err != nil {
		return err
	}
	d.StartedAtBasis = situationmodel.SourceTimeBasis(r.startedBasis)
	d.ResolvedAtBasis = situationmodel.SourceTimeBasis(r.resolvedBasis)
	d.SourceProvenance = SourceProvenance{
		SignalID:            stringPtr(r.signalID),
		SignalVersion:       stringPtr(r.signalVersion),
		GeneratorURL:        r.generatorURL,
		AcquisitionMode:     SourceAcquisitionMode(r.acquisitionMode),
		PollIntervalSeconds: r.pollInterval,
	}
	return nil
}

func scanDelivery(s scanner) (AlertDelivery, error) {
	var d AlertDelivery
	var r rawDeliveryFields
	if err := s.Scan(deliveryScanDest(&d, &r)...); err != nil {
		return AlertDelivery{}, err
	}
	if err := hydrateDelivery(&d, r); err != nil {
		return AlertDelivery{}, err
	}
	return d, nil
}

func scanDispatch(s scanner) (AlertDispatch, error) {
	var disp AlertDispatch
	var r rawDeliveryFields
	var dispatchStatus string
	var leaseOwner, leaseExpires, lastClass, retryAt, appliedAt sql.NullString

	dest := deliveryScanDest(&disp.Delivery, &r)
	dest = append(dest, &dispatchStatus, &leaseOwner, &leaseExpires, &disp.ClaimToken, &disp.AttemptCount, &lastClass, &retryAt, &appliedAt)
	if err := s.Scan(dest...); err != nil {
		return AlertDispatch{}, err
	}
	if err := hydrateDelivery(&disp.Delivery, r); err != nil {
		return AlertDispatch{}, err
	}
	disp.Status = dispatchStatus
	disp.LeaseOwner = stringPtr(leaseOwner)
	disp.LastErrorClass = stringPtr(lastClass)
	var err error
	if disp.LeaseExpiresAt, err = timePtr(leaseExpires); err != nil {
		return AlertDispatch{}, err
	}
	if disp.RetryAt, err = timePtr(retryAt); err != nil {
		return AlertDispatch{}, err
	}
	if disp.AppliedAt, err = timePtr(appliedAt); err != nil {
		return AlertDispatch{}, err
	}
	return disp, nil
}

func nullableString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func copyStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func copyTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	out := v.UTC()
	return &out
}

func stringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	out := v.String
	return &out
}

func timePtr(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil //nolint:nilnil // a NULL column is a nil time, not an error; callers branch on nil
	}
	out, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil, fmt.Errorf("store: parse delivery time: %w", err)
	}
	return &out, nil
}
