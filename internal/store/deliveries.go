// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

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
}

// AlertDelivery is the immutable accepted source lifecycle record.
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
}

// AlertDispatch is the durable correlation outbox state for one delivery.
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
// delivery dispatch. Callers must not acknowledge or rewrite the replacement
// worker's lease after receiving it.
var ErrAlertDispatchLeaseLost = errors.New("store: alert dispatch lease lost")

// ErrIncidentOwnerNotCollapsible means recurrence planning selected an
// Incident whose primary Situation is missing or terminal. The caller must
// take the safe-new-Incident path instead of collapsing across that boundary.
var ErrIncidentOwnerNotCollapsible = errors.New("store: incident owner does not permit recurrence collapse")

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

// AcceptDeliveries atomically updates latest alert projections, appends their
// immutable delivery records, and queues durable correlation dispatches. A
// duplicate delivery ID is a successful no-op, so transport redelivery cannot
// mutate an already accepted projection.
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
		existing, err := getDelivery(ctx, tx, p.in.ID)
		switch {
		case err == nil:
			out = append(out, existing)
			continue
		case !errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("store: read existing delivery: %w", err)
		}

		alert, err := upsertAlertTx(ctx, tx, p)
		if err != nil {
			return nil, err
		}
		delivery, err := insertDelivery(ctx, tx, p, alert)
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

func prepareDelivery(d DeliveryInput) (preparedDelivery, error) {
	if err := validateAlert(d.Alert); err != nil {
		return preparedDelivery{}, err
	}
	if strings.TrimSpace(d.ID) == "" {
		return preparedDelivery{}, errors.New("store: delivery id is required")
	}
	if strings.TrimSpace(d.Source) == "" {
		return preparedDelivery{}, errors.New("store: delivery source is required")
	}
	if strings.TrimSpace(d.SourceEpisodeKey) == "" {
		return preparedDelivery{}, errors.New("store: delivery source episode key is required")
	}
	if strings.TrimSpace(d.ReceiverGroupingIdentity) == "" {
		return preparedDelivery{}, errors.New("store: delivery receiver grouping identity is required")
	}
	if strings.TrimSpace(d.PayloadDigest) == "" {
		return preparedDelivery{}, errors.New("store: delivery payload digest is required")
	}
	if !validSourceTimeBasis(d.StartedAtBasis) || !validSourceTimeBasis(d.ResolvedAtBasis) {
		return preparedDelivery{}, fmt.Errorf("store: invalid delivery source time basis started=%q resolved=%q", d.StartedAtBasis, d.ResolvedAtBasis)
	}
	labelsJSON, err := json.Marshal(d.Alert.Labels)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery labels: %w", err)
	}
	annosJSON, err := json.Marshal(d.Alert.Annotations)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery annotations: %w", err)
	}
	p := preparedDelivery{
		in: d, labelsJSON: string(labelsJSON), annosJSON: string(annosJSON),
		receivedAt: canonicalTime(d.Alert.ReceivedAt), startsAt: canonicalTime(d.Alert.StartsAt),
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

func canonicalTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func upsertAlertTx(ctx context.Context, tx *sql.Tx, p preparedDelivery) (Alert, error) {
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

func insertDelivery(ctx context.Context, tx *sql.Tx, p preparedDelivery, a Alert) (AlertDelivery, error) {
	d := p.in
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			id, alert_id, source, source_event_id, source_episode_key, status, labels_json, annotations_json,
			starts_at, ends_at, source_started_at, source_resolved_at, started_at_basis, resolved_at_basis,
			receiver_grouping_identity, payload_digest, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, d.ID, a.ID, d.Source, nullableString(d.SourceEventID), d.SourceEpisodeKey, d.Alert.Status,
		p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt, p.startedAt, p.resolvedAt, d.StartedAtBasis, d.ResolvedAtBasis,
		d.ReceiverGroupingIdentity, d.PayloadDigest, p.receivedAt)
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: insert alert delivery: %w", err)
	}
	return AlertDelivery{ID: d.ID, Alert: a, Source: d.Source, SourceEventID: copyStringPtr(d.SourceEventID),
		SourceEpisodeKey: d.SourceEpisodeKey, SourceStartedAt: copyTimePtr(d.SourceStartedAt), SourceResolvedAt: copyTimePtr(d.SourceResolvedAt),
		StartedAtBasis: d.StartedAtBasis, ResolvedAtBasis: d.ResolvedAtBasis, ReceiverGroupingIdentity: d.ReceiverGroupingIdentity,
		PayloadDigest: d.PayloadDigest, ReceivedAt: d.Alert.ReceivedAt.UTC()}, nil
}

// ClaimAlertDispatches leases due dispatches. Claiming is durable and never
// calls outbound code; callers apply the claimed work after this transaction.
func (s *Store) ClaimAlertDispatches(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]AlertDispatch, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: dispatch claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim alert dispatches: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	leaseExpires := canonicalTime(now.Add(lease))
	candidateRows, err := tx.QueryContext(ctx, `
		SELECT d.delivery_id
		FROM alert_delivery_dispatches AS d
		JOIN alert_deliveries AS ad ON ad.id = d.delivery_id
		WHERE (d.status = 'pending' AND (d.retry_at IS NULL OR d.retry_at <= ?))
			OR (d.status = 'claimed' AND d.lease_expires_at IS NOT NULL AND d.lease_expires_at <= ?)
		ORDER BY COALESCE(d.retry_at, ad.received_at) ASC, ad.received_at ASC, d.delivery_id ASC LIMIT ?
	`, canonicalTime(now), canonicalTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: select alert dispatch candidates: %w", err)
	}
	defer func() { _ = candidateRows.Close() }()
	claimedIDs := make([]string, 0, limit)
	for candidateRows.Next() {
		var id string
		if err := candidateRows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan alert dispatch candidate: %w", err)
		}
		claimedIDs = append(claimedIDs, id)
	}
	if err := candidateRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate alert dispatch candidates: %w", err)
	}
	if err := candidateRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close alert dispatch candidates: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty alert dispatch claim: %w", err)
		}
		return []AlertDispatch{}, nil
	}
	args := make([]any, len(claimedIDs))
	placeholders := make([]string, len(claimedIDs))
	for i, id := range claimedIDs {
		args[i], placeholders[i] = id, "?"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?,
		    claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE delivery_id IN (`+strings.Join(placeholders, ",")+`)`, append([]any{owner, leaseExpires}, args...)...); err != nil {
		return nil, fmt.Errorf("store: claim alert dispatches: %w", err)
	}
	orderTerms := make([]string, len(claimedIDs))
	orderArgs := make([]any, len(claimedIDs))
	for i, id := range claimedIDs {
		orderTerms[i] = "WHEN ? THEN " + fmt.Sprint(i)
		orderArgs[i] = id
	}
	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, owner)
	queryArgs = append(queryArgs, orderArgs...)
	rows, err := tx.QueryContext(ctx, dispatchSelect+` WHERE d.delivery_id IN (`+strings.Join(placeholders, ",")+
		`) AND d.status = 'claimed' AND d.lease_owner = ? ORDER BY CASE d.delivery_id `+strings.Join(orderTerms, " ")+` END`, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AlertDispatch{}
	for rows.Next() {
		d, err := scanDispatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed alert dispatches: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim alert dispatches: %w", err)
	}
	return out, nil
}

// MarkAlertDispatchApplied records successful correlation after its own
// transaction has committed.
func (s *Store) MarkAlertDispatchApplied(ctx context.Context, claim AlertDispatch, at time.Time) error {
	if strings.TrimSpace(claim.Delivery.ID) == "" || claim.LeaseOwner == nil || strings.TrimSpace(*claim.LeaseOwner) == "" || claim.ClaimToken <= 0 || at.IsZero() {
		return errors.New("store: applied alert dispatch requires a complete claim and applied time")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status='applied', lease_owner=NULL, lease_expires_at=NULL,
		    retry_at=NULL, applied_at=?
		WHERE delivery_id=? AND status='claimed' AND lease_owner=? AND claim_token=?`,
		canonicalTime(at), claim.Delivery.ID, *claim.LeaseOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: mark alert dispatch applied: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count applied alert dispatch: %w", err)
	}
	if n != 1 {
		return ErrAlertDispatchLeaseLost
	}
	return nil
}

// RetryAlertDispatch releases a dispatch for retry or marks it terminal.
func (s *Store) RetryAlertDispatch(ctx context.Context, claim AlertDispatch, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(claim.Delivery.ID) == "" || claim.LeaseOwner == nil || strings.TrimSpace(*claim.LeaseOwner) == "" || claim.ClaimToken <= 0 || strings.TrimSpace(class) == "" {
		return errors.New("store: alert dispatch retry requires a complete claim and error class")
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

// ApplyCorrelatedDelivery atomically mutates the Incident/Occurrence,
// establishes immutable delivery ownership, retains the compatibility current
// Alert membership, and produces one durable Situation input. Reapplying an
// already-owned delivery is a successful no-op.
func (s *Store) ApplyCorrelatedDelivery(ctx context.Context, m CorrelatedDeliveryMutation) error {
	if err := validateCorrelatedDeliveryMutation(m); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin correlated delivery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifyCorrelatedDispatchClaimTx(ctx, tx, m); err != nil {
		return err
	}

	var alreadyLinked int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM incident_alert_deliveries WHERE delivery_id = ?`, m.DeliveryID).Scan(&alreadyLinked)
	switch {
	case err == nil:
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit duplicate correlated delivery: %w", err)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("store: read correlated delivery ownership: %w", err)
	}

	var alertID, deliveryStatus, receivedAt string
	if err := tx.QueryRowContext(ctx, `SELECT alert_id, status, received_at FROM alert_deliveries WHERE id = ?`, m.DeliveryID).
		Scan(&alertID, &deliveryStatus, &receivedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: read correlated delivery: %w", err)
	}
	deliveryReceivedAt, err := time.Parse(time.RFC3339Nano, receivedAt)
	if err != nil {
		return fmt.Errorf("store: parse correlated delivery received time: %w", err)
	}

	if m.RequireNonterminalOwner {
		var lifecycle string
		err := tx.QueryRowContext(ctx, `
			SELECT s.lifecycle
			FROM situations AS s
			JOIN situation_incidents AS si ON si.situation_id = s.id
			WHERE si.incident_id = ?`, m.Incident.ID).Scan(&lifecycle)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIncidentOwnerNotCollapsible
		}
		if err != nil {
			return fmt.Errorf("store: read recurrence Situation owner: %w", err)
		}
		if lifecycle != string(situationmodel.LifecycleActive) && lifecycle != string(situationmodel.LifecycleRecoveryPending) {
			return ErrIncidentOwnerNotCollapsible
		}
	}

	created, incidentStatus, incidentID, err := ensureCorrelatedIncident(ctx, tx, m.Incident, m.Input.Kind == "incident_created" && m.Occurrence == nil)
	if err != nil {
		return err
	}
	if incidentID != m.Incident.ID {
		m.Incident.ID = incidentID
		m.Input.IncidentID = incidentID
		m.Input.Kind = "membership_changed"
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO incident_analysis_state(incident_id, status, decision_reason, updated_at)
		VALUES (?, 'not_requested', 'correlation_collecting', ?)`, m.Incident.ID, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: ensure correlated incident analysis state: %w", err)
	}

	occurrenceID, err := applyCorrelatedOccurrenceTx(ctx, tx, m, deliveryReceivedAt)
	if err != nil {
		return err
	}
	if err := attachCorrelatedDeliveryTx(ctx, tx, m, alertID, occurrenceID, deliveryReceivedAt, now); err != nil {
		return err
	}

	input := m.Input
	// Delivery-backed lifecycle time always comes from the immutable ledger,
	// never from a mutable caller projection.
	input.OccurredAt = deliveryReceivedAt.UTC()
	input.Kind, err = correlatedSituationInputKind(ctx, tx, input.Kind, m.Incident.ID, deliveryStatus, incidentStatus, created, now)
	if err != nil {
		return err
	}
	if _, err := dueReasonForInputKind(input.Kind); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_input_outbox(
			id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`, input.ID, input.IdempotencyKey, input.IncidentID,
		m.DeliveryID, input.Kind, input.GroupKey, canonicalTime(input.OccurredAt)); err != nil {
		return fmt.Errorf("store: insert correlated Situation input: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit correlated delivery: %w", err)
	}
	return nil
}

func applyCorrelatedOccurrenceTx(ctx context.Context, tx *sql.Tx, m CorrelatedDeliveryMutation, receivedAt time.Time) (sql.NullInt64, error) {
	if m.Occurrence == nil {
		return sql.NullInt64{}, nil
	}
	if m.Occurrence.ID == 0 {
		id, err := insertOccurrenceTx(ctx, tx, *m.Occurrence)
		if err != nil {
			return sql.NullInt64{}, err
		}
		return sql.NullInt64{Int64: id, Valid: true}, nil
	}
	lastSeen := m.Occurrence.LastSeen
	if lastSeen.IsZero() {
		lastSeen = receivedAt
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_occurrences SET last_seen = MAX(last_seen, ?)
		WHERE id = ? AND incident_id = ?`, fmtOccTime(lastSeen), m.Occurrence.ID, m.Incident.ID)
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
	return sql.NullInt64{Int64: m.Occurrence.ID, Valid: true}, nil
}

func attachCorrelatedDeliveryTx(ctx context.Context, tx *sql.Tx, m CorrelatedDeliveryMutation, alertID string, occurrenceID sql.NullInt64, receivedAt, now time.Time) error {
	memberRes, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO incident_alerts(incident_id, alert_id, created_at)
		VALUES (?, ?, ?)`, m.Incident.ID, alertID, canonicalTime(now))
	if err != nil {
		return fmt.Errorf("store: attach correlated Alert projection: %w", err)
	}
	memberAdded, err := memberRes.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count correlated Alert projection: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE incidents
		SET alert_count = alert_count + ?, last_alert_at = MAX(last_alert_at, ?), updated_at = ?
		WHERE id = ?`, memberAdded, canonicalTime(receivedAt), canonicalTime(now), m.Incident.ID); err != nil {
		return fmt.Errorf("store: update correlated Incident: %w", err)
	}
	var occurrenceValue any
	if occurrenceID.Valid {
		occurrenceValue = occurrenceID.Int64
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries(incident_id, delivery_id, occurrence_id, created_at)
		VALUES (?, ?, ?, ?)`, m.Incident.ID, m.DeliveryID, occurrenceValue, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: link correlated delivery: %w", err)
	}
	return nil
}

func correlatedSituationInputKind(ctx context.Context, tx *sql.Tx, requested, incidentID, deliveryStatus, incidentStatus string, created bool, now time.Time) (string, error) {
	if created {
		return "incident_created", nil
	}
	if deliveryStatus != "resolved" || (incidentStatus != "ready" && incidentStatus != "analyzed") {
		return requested, nil
	}
	unresolved, err := unresolvedIncidentMembersTx(ctx, tx, incidentID)
	if err != nil || unresolved != 0 {
		return requested, err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'resolved', updated_at = ?
		WHERE id = ? AND status IN ('ready', 'analyzed')`, canonicalTime(now), incidentID)
	if err != nil {
		return "", fmt.Errorf("store: resolve correlated Incident: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("store: count resolved correlated Incident: %w", err)
	}
	if changed == 1 {
		return "incident_resolved", nil
	}
	return requested, nil
}

func validateCorrelatedDeliveryMutation(m CorrelatedDeliveryMutation) error {
	if strings.TrimSpace(m.DeliveryID) == "" || strings.TrimSpace(m.DispatchOwner) == "" || m.DispatchClaimToken <= 0 {
		return errors.New("store: correlated delivery requires a complete dispatch claim")
	}
	if strings.TrimSpace(m.Incident.ID) == "" || strings.TrimSpace(m.Incident.GroupKey) == "" {
		return errors.New("store: correlated delivery requires Incident identity")
	}
	if m.Incident.FirstAlertAt.IsZero() || m.Incident.LastAlertAt.IsZero() || m.Incident.ReadyAt.IsZero() {
		return errors.New("store: correlated delivery requires Incident times")
	}
	if strings.TrimSpace(m.Input.ID) == "" || strings.TrimSpace(m.Input.IdempotencyKey) == "" || m.Input.OccurredAt.IsZero() {
		return errors.New("store: correlated delivery requires Situation input identity and time")
	}
	if m.Input.IncidentID != m.Incident.ID || m.Input.GroupKey != m.Incident.GroupKey {
		return errors.New("store: correlated Situation input does not match Incident")
	}
	if m.Input.DeliveryID == nil || *m.Input.DeliveryID != m.DeliveryID {
		return errors.New("store: correlated Situation input does not match delivery")
	}
	if m.Occurrence != nil && m.Occurrence.IncidentID != m.Incident.ID {
		return errors.New("store: correlated Occurrence does not match Incident")
	}
	if _, err := dueReasonForInputKind(m.Input.Kind); err != nil {
		return err
	}
	return nil
}

func verifyCorrelatedDispatchClaimTx(ctx context.Context, tx *sql.Tx, m CorrelatedDeliveryMutation) error {
	var valid int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM alert_delivery_dispatches
		WHERE delivery_id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		m.DeliveryID, m.DispatchOwner, m.DispatchClaimToken).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAlertDispatchLeaseLost
	}
	if err != nil {
		return fmt.Errorf("store: verify correlated dispatch claim: %w", err)
	}
	return nil
}

func ensureCorrelatedIncident(ctx context.Context, tx *sql.Tx, inc Incident, reuseCollecting bool) (created bool, status, incidentID string, err error) {
	var groupKey string
	err = tx.QueryRowContext(ctx, `SELECT group_key, status FROM incidents WHERE id = ?`, inc.ID).Scan(&groupKey, &status)
	if err == nil {
		if groupKey != inc.GroupKey {
			return false, "", "", errors.New("store: correlated Incident group key mismatch")
		}
		return false, status, inc.ID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, "", "", fmt.Errorf("store: read correlated Incident: %w", err)
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
			return false, "", "", fmt.Errorf("store: read collecting correlated Incident: %w", err)
		}
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents(
			id, group_key, status, first_alert_at, last_alert_at, ready_at,
			alert_count, created_at, updated_at, dispatch_managed
		) VALUES (?, ?, 'collecting', ?, ?, ?, 0, ?, ?, 1)`, inc.ID, inc.GroupKey,
		canonicalTime(inc.FirstAlertAt), canonicalTime(inc.LastAlertAt), canonicalTime(inc.ReadyAt),
		canonicalTime(now), canonicalTime(now)); err != nil {
		return false, "", "", fmt.Errorf("store: insert correlated Incident: %w", err)
	}
	return true, "collecting", inc.ID, nil
}

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
		return 0, fmt.Errorf("store: count unresolved correlated Incident members: %w", err)
	}
	return count, nil
}

const dispatchSelect = `
SELECT d.delivery_id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest, ad.received_at,
       a.fingerprint, d.status, d.lease_owner, d.lease_expires_at,
       d.claim_token, d.attempt_count, d.last_error_class, d.retry_at, d.applied_at
FROM alert_delivery_dispatches d
JOIN alert_deliveries ad ON ad.id = d.delivery_id
JOIN alerts a ON a.id = ad.alert_id`

func getDelivery(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (AlertDelivery, error) {
	row := q.QueryRowContext(ctx, deliverySelect+` WHERE ad.id = ?`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertDelivery{}, ErrNotFound
	}
	return d, err
}

const deliverySelect = `
SELECT ad.id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest, ad.received_at,
       a.fingerprint
FROM alert_deliveries ad JOIN alerts a ON a.id = ad.alert_id`

func scanDispatch(s scanner) (AlertDispatch, error) {
	var d AlertDispatch
	var sourceEvent, alertEnds, sourceStarted, sourceResolved, leaseOwner, leaseExpires, lastClass, retryAt, appliedAt sql.NullString
	var status, labels, annotations, startedBasis, resolvedBasis, received, alertStarts string
	err := s.Scan(&d.Delivery.ID, &d.Delivery.Alert.ID, &d.Delivery.Source, &sourceEvent, &d.Delivery.SourceEpisodeKey, &status,
		&labels, &annotations, &alertStarts, &alertEnds, &sourceStarted, &sourceResolved, &startedBasis, &resolvedBasis, &d.Delivery.ReceiverGroupingIdentity,
		&d.Delivery.PayloadDigest, &received, &d.Delivery.Alert.Fingerprint, &d.Status, &leaseOwner, &leaseExpires,
		&d.ClaimToken, &d.AttemptCount, &lastClass, &retryAt, &appliedAt)
	if err != nil {
		return AlertDispatch{}, err
	}
	d.Delivery.Alert.Status = status
	if err := hydrateDelivery(&d.Delivery, labels, annotations, sourceEvent, sourceStarted, sourceResolved, startedBasis, resolvedBasis, received, alertStarts, alertEnds); err != nil {
		return AlertDispatch{}, err
	}
	d.LeaseOwner, d.LastErrorClass = stringPtr(leaseOwner), stringPtr(lastClass)
	if d.LeaseExpiresAt, err = timePtr(leaseExpires); err != nil {
		return AlertDispatch{}, err
	}
	if d.RetryAt, err = timePtr(retryAt); err != nil {
		return AlertDispatch{}, err
	}
	if d.AppliedAt, err = timePtr(appliedAt); err != nil {
		return AlertDispatch{}, err
	}
	return d, nil
}

func scanDelivery(s scanner) (AlertDelivery, error) {
	var d AlertDelivery
	var sourceEvent, alertEnds, sourceStarted, sourceResolved sql.NullString
	var status, labels, annotations, startedBasis, resolvedBasis, received, alertStarts string
	err := s.Scan(&d.ID, &d.Alert.ID, &d.Source, &sourceEvent, &d.SourceEpisodeKey, &status,
		&labels, &annotations, &alertStarts, &alertEnds, &sourceStarted, &sourceResolved, &startedBasis, &resolvedBasis, &d.ReceiverGroupingIdentity,
		&d.PayloadDigest, &received, &d.Alert.Fingerprint)
	if err != nil {
		return AlertDelivery{}, err
	}
	d.Alert.Status = status
	if err := hydrateDelivery(&d, labels, annotations, sourceEvent, sourceStarted, sourceResolved, startedBasis, resolvedBasis, received, alertStarts, alertEnds); err != nil {
		return AlertDelivery{}, err
	}
	return d, nil
}

func hydrateDelivery(d *AlertDelivery, labels, annotations string, sourceEvent, sourceStarted, sourceResolved sql.NullString, startedBasis, resolvedBasis, received, alertStarts string, alertEnds sql.NullString) error {
	if err := json.Unmarshal([]byte(labels), &d.Alert.Labels); err != nil {
		return fmt.Errorf("store: unmarshal delivery labels: %w", err)
	}
	if err := json.Unmarshal([]byte(annotations), &d.Alert.Annotations); err != nil {
		return fmt.Errorf("store: unmarshal delivery annotations: %w", err)
	}
	var err error
	if d.Alert.StartsAt, err = time.Parse(time.RFC3339Nano, alertStarts); err != nil {
		return fmt.Errorf("store: parse delivery alert starts at: %w", err)
	}
	if d.Alert.EndsAt, err = timePtr(alertEnds); err != nil {
		return err
	}
	if d.Alert.ReceivedAt, err = time.Parse(time.RFC3339Nano, received); err != nil {
		return fmt.Errorf("store: parse delivery received at: %w", err)
	}
	d.ReceivedAt = d.Alert.ReceivedAt
	d.Alert.ReceiverGroupingIdentity = d.ReceiverGroupingIdentity
	d.SourceEventID = stringPtr(sourceEvent)
	if d.SourceStartedAt, err = timePtr(sourceStarted); err != nil {
		return err
	}
	if d.SourceResolvedAt, err = timePtr(sourceResolved); err != nil {
		return err
	}
	d.StartedAtBasis, d.ResolvedAtBasis = situationmodel.SourceTimeBasis(startedBasis), situationmodel.SourceTimeBasis(resolvedBasis)
	return nil
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
		return nil, nil
	}
	out, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil, fmt.Errorf("store: parse delivery time: %w", err)
	}
	return &out, nil
}

// PendingAlertDispatches counts accepted deliveries still awaiting
// correlation — the backlog startup replay drains before ordinary
// reconciliation begins.
func (s *Store) PendingAlertDispatches(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status IN ('pending', 'claimed')`).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count pending alert dispatches: %w", err)
	}
	return count, nil
}
