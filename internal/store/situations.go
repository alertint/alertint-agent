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

	"github.com/google/uuid"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// SituationInput is one durable, deterministically-idempotent fact destined
// for the situation_input_outbox — the only channel through which a
// correlation-side mutation (a correlated delivery, an Incident's ready
// transition, ...) hands work to the Situation controller. Task 5 needs only
// this struct to insert a Situation input atomically alongside an Incident
// mutation; Task 7 extends this file with the rest of the Situation store
// surface (claims, advancement, and friends).
type SituationInput struct {
	ID             string
	IdempotencyKey string
	IncidentID     string
	Kind           string
	GroupKey       string
	DeliveryID     *string
	OccurredAt     time.Time
}

// SituationClaim is one claimed situation_input_outbox row: the input's own
// identity (embedded SituationInput) plus the lease-fencing triple recorded
// at claim time. ApplySituationInput and RetrySituationInput both re-verify
// this triple against the row's current state before writing anything —
// receiving a SituationClaim is never itself proof the claim still holds.
type SituationClaim struct {
	SituationInput

	LeaseOwner   string
	ClaimToken   int64
	AttemptCount int
}

// ErrSituationLeaseLost means a caller no longer owns the lease it is trying
// to act on — either a claimed situation_input_outbox row (ApplySituationInput,
// RetrySituationInput) or a claimed Situation aggregate (ReleaseSituationClaim)
// — because the lease's (owner, claim_token) pair was superseded, most often
// by another worker reclaiming it after the original lease expired. Callers
// must discard the stale claim, not retry with it, on receiving this error.
var ErrSituationLeaseLost = errors.New("store: situation lease lost")

// ErrSituationVersionConflict means a Situation's input_version advanced
// between the moment a caller last observed it and the moment it tried to
// commit against that observed version — distinct from ErrSituationLeaseLost,
// which signals a lease/claim-token mismatch. Under this store's
// single-writer transaction model (Store.Open sets SetMaxOpenConns(1)) this
// guards an invariant that cannot actually race within one call; it exists
// as a defensive compare-and-swap here, and as the contract a later
// assessment-commit method (a future task, consuming ClaimDueSituations'
// lease) returns when a Situation input was applied after that method's
// caller took its claim.
var ErrSituationVersionConflict = errors.New("store: situation version conflict")

// dueReasonForInputKind maps a durable situation_input_outbox kind to the
// DueReason ApplySituationInput merges into the owning Situation. Every kind
// the situation_input_outbox schema accepts must be listed here —
// unsupported kinds are a hard error, never silently ignored.
func dueReasonForInputKind(kind string) (situationmodel.DueReason, error) {
	switch kind {
	case "incident_created":
		return situationmodel.DueIncidentCreated, nil
	case "membership_changed", "incident_ready":
		return situationmodel.DueMembershipChanged, nil
	case "finding_persisted":
		return situationmodel.DueNewSymptom, nil
	case "triage_skipped", "triage_retry_changed", "triage_exhausted":
		return situationmodel.DueTriageChanged, nil
	case "incident_resolved":
		return situationmodel.DueAlertResolved, nil
	default:
		return "", fmt.Errorf("store: unsupported situation input kind %q", kind)
	}
}

// ----------------------------------------------------------------------
// situation_input_outbox claim/apply/retry (Task 7)
// ----------------------------------------------------------------------

// ClaimSituationInputs leases due situation_input_outbox rows — pending rows
// never claimed, or claimed rows whose lease has expired — in one atomic
// transaction. Claiming increments both claim_token (fencing every prior
// lease holder out) and attempt_count. Rows are claimed and returned in
// deterministic (occurred_at, id) order. Claiming never applies anything;
// callers apply claimed work only after this transaction commits.
//
// This deliberately mirrors ClaimAlertDispatches' claim shape one table over
// (situation_input_outbox vs. alert_delivery_dispatches); this plan's own
// pre-flight conflict scan already ruled the analogous per-package
// WorkerConfig duplication intentional rather than something to unify across
// the two claim mechanisms.
//
//nolint:dupl // mirrors ClaimAlertDispatches deliberately; see doc comment above
func (s *Store) ClaimSituationInputs(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]SituationClaim, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: situation input claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim situation inputs: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE situation_input_outbox
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?,
		    claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE id IN (
			SELECT id FROM situation_input_outbox
			WHERE (status = 'pending' AND (retry_at IS NULL OR retry_at <= ?))
			   OR (status = 'claimed' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
			ORDER BY occurred_at ASC, id ASC
			LIMIT ?
		)
		RETURNING id
	`, owner, leaseExpires, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim situation inputs: %w", err)
	}
	claimedIDs, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed situation input ids: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty situation input claim: %w", err)
		}
		return []SituationClaim{}, nil
	}

	out, err := loadClaimedSituationInputsTx(ctx, tx, claimedIDs, owner)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim situation inputs: %w", err)
	}
	return out, nil
}

// loadClaimedSituationInputsTx re-reads the just-claimed rows in their
// deterministic (occurred_at, id) order — a bare UPDATE ... RETURNING does
// not guarantee it preserves the subquery's ORDER BY, so this issues one
// more SELECT with an explicit ORDER BY of its own.
func loadClaimedSituationInputsTx(ctx context.Context, tx *sql.Tx, ids []string, owner string) ([]SituationClaim, error) {
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, owner)

	query := `
		SELECT id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, claim_token, attempt_count
		FROM situation_input_outbox
		WHERE id IN (` + strings.Join(placeholders, ",") + `) AND status = 'claimed' AND lease_owner = ?
		ORDER BY occurred_at ASC, id ASC`

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed situation inputs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]SituationClaim, 0, len(ids))
	for rows.Next() {
		var c SituationClaim
		var deliveryID sql.NullString
		var occurredAtStr string
		if err := rows.Scan(&c.ID, &c.IdempotencyKey, &c.IncidentID, &deliveryID, &c.Kind, &c.GroupKey, &occurredAtStr, &c.ClaimToken, &c.AttemptCount); err != nil {
			return nil, fmt.Errorf("store: scan claimed situation input: %w", err)
		}
		c.DeliveryID = stringPtr(deliveryID)
		occurredAt, err := time.Parse(time.RFC3339Nano, occurredAtStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse claimed situation input occurred_at: %w", err)
		}
		c.OccurredAt = occurredAt
		c.LeaseOwner = owner
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed situation inputs: %w", err)
	}
	return out, nil
}

// RetrySituationInput releases a claimed situation_input_outbox row back to
// "pending" for a future retry, or marks it terminally "failed" when
// terminal is true. The update is fenced on (id, status='claimed',
// lease_owner, claim_token) all at once: if any of those moved on since the
// claim was issued, exactly zero rows change and this returns
// ErrSituationLeaseLost instead of silently doing nothing.
func (s *Store) RetrySituationInput(ctx context.Context, claim SituationClaim, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(claim.ID) == "" || strings.TrimSpace(claim.LeaseOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: situation input retry requires a complete claim")
	}
	if err := validateErrorClass(class); err != nil {
		return err
	}
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status, retry = "failed", nil
	} else if retryAt.IsZero() {
		return errors.New("store: situation input retry time is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
		    last_error_class = ?, retry_at = ?
		WHERE id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		status, class, retry, claim.ID, claim.LeaseOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: retry situation input: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried situation input: %w", err)
	}
	if n != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

// situationInputRow is the freshly re-read state of one situation_input_outbox
// row, as ApplySituationInput observes it inside its own transaction — never
// trusted from the caller's SituationClaim snapshot beyond the lease-fencing
// triple.
type situationInputRow struct {
	id, idempotencyKey, incidentID, kind, groupKey, status string
	deliveryID                                             *string
	occurredAt                                             time.Time
	leaseOwner                                             *string
	claimToken                                             int64
}

func readSituationInputTx(ctx context.Context, tx *sql.Tx, id string) (situationInputRow, error) {
	var r situationInputRow
	var deliveryID, leaseOwner sql.NullString
	var occurredAtStr string
	err := tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status, lease_owner, claim_token
		FROM situation_input_outbox WHERE id = ?`, id).Scan(
		&r.id, &r.idempotencyKey, &r.incidentID, &deliveryID, &r.kind, &r.groupKey, &occurredAtStr, &r.status, &leaseOwner, &r.claimToken)
	if errors.Is(err, sql.ErrNoRows) {
		return situationInputRow{}, ErrNotFound
	}
	if err != nil {
		return situationInputRow{}, fmt.Errorf("store: read situation input: %w", err)
	}
	r.deliveryID = stringPtr(deliveryID)
	r.leaseOwner = stringPtr(leaseOwner)
	if r.occurredAt, err = time.Parse(time.RFC3339Nano, occurredAtStr); err != nil {
		return situationInputRow{}, fmt.Errorf("store: parse situation input occurred_at: %w", err)
	}
	return r, nil
}

// ApplySituationInput atomically attaches one claimed situation_input_outbox
// row to its owning Situation, advancing that Situation's durable state, and
// marks the input applied — attach once, advance input_version once, merge
// the mapped due reason once, mark applied to the owning Situation. It is
// fenced by the SituationClaim's (lease_owner, claim_token) pair and is
// idempotent: an input already marked applied is a successful no-op.
func (s *Store) ApplySituationInput(ctx context.Context, claim SituationClaim) error {
	if strings.TrimSpace(claim.ID) == "" || strings.TrimSpace(claim.LeaseOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: apply situation input requires a complete claim")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin apply situation input: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row, err := readSituationInputTx(ctx, tx, claim.ID)
	if err != nil {
		return err
	}
	if row.status == "applied" {
		// Idempotent replay: this exact input already attached to its
		// Situation and there is nothing left to do.
		return nil
	}
	if row.status != "claimed" || row.leaseOwner == nil || *row.leaseOwner != claim.LeaseOwner || row.claimToken != claim.ClaimToken {
		return ErrSituationLeaseLost
	}

	dueReason, err := dueReasonForInputKind(row.kind)
	if err != nil {
		return err
	}

	var incidentGroupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, row.incidentID).Scan(&incidentGroupKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: read situation input incident: %w", err)
	}
	if incidentGroupKey != row.groupKey {
		return fmt.Errorf("store: situation input %s group key mismatch: incident has %q, input has %q", row.id, incidentGroupKey, row.groupKey)
	}

	if row.deliveryID != nil {
		var exists int
		err := tx.QueryRowContext(ctx, `
			SELECT 1 FROM incident_alert_deliveries WHERE incident_id = ? AND delivery_id = ?`,
			row.incidentID, *row.deliveryID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: situation input %s: delivery %s is not owned by incident %s", row.id, *row.deliveryID, row.incidentID)
		}
		if err != nil {
			return fmt.Errorf("store: verify situation input delivery ownership: %w", err)
		}
	}

	startAt, basis, receivedAt, err := sourceTimesForInputTx(ctx, tx, row.deliveryID, row.occurredAt)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	situationID, err := resolveAndApplySituationTx(ctx, tx, row, startAt, basis, receivedAt, dueReason, now)
	if err != nil {
		return err
	}
	if err := attachSituationMembershipTx(ctx, tx, situationID, row.incidentID, now); err != nil {
		return err
	}
	if err := markSituationInputAppliedTx(ctx, tx, row.id, claim.LeaseOwner, claim.ClaimToken, situationID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// sourceTimesForInputTx resolves the (effectiveStart, basis, receivedAt)
// triple one input contributes to its Situation's source-derived times. A
// delivery-carrying input derives them from the immutable delivery's own
// SourceStartedAt/StartedAtBasis, falling back to the delivery's ReceivedAt
// with basis receipt_fallback whenever the delivery itself has no provable
// source-payload/API start — including a StartedAtBasis of "missing", which
// situations.effective_started_at_basis's CHECK constraint deliberately does
// not accept as a persisted value. A delivery-less input (a controller-side
// event with no backing delivery, e.g. incident_ready) contributes its own
// OccurredAt as a receipt_fallback basis start/receipt time — the closest
// honest substitute for "when this fact became known".
func sourceTimesForInputTx(ctx context.Context, tx *sql.Tx, deliveryID *string, occurredAt time.Time) (time.Time, situationmodel.SourceTimeBasis, time.Time, error) {
	if deliveryID == nil {
		return occurredAt, situationmodel.SourceTimeBasisReceiptFallback, occurredAt, nil
	}

	var sourceStarted sql.NullString
	var startedBasis, receivedAtStr string
	err := tx.QueryRowContext(ctx, `
		SELECT source_started_at, started_at_basis, received_at
		FROM alert_deliveries WHERE id = ?`, *deliveryID).Scan(&sourceStarted, &startedBasis, &receivedAtStr)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", time.Time{}, fmt.Errorf("store: situation input delivery %s: %w", *deliveryID, ErrNotFound)
	}
	if err != nil {
		return time.Time{}, "", time.Time{}, fmt.Errorf("store: read situation input delivery: %w", err)
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, receivedAtStr)
	if err != nil {
		return time.Time{}, "", time.Time{}, fmt.Errorf("store: parse situation input delivery received_at: %w", err)
	}

	basis := situationmodel.SourceTimeBasis(startedBasis)
	if sourceStarted.Valid && (basis == situationmodel.SourceTimeBasisSourcePayload || basis == situationmodel.SourceTimeBasisSourceAPI) {
		startAt, err := time.Parse(time.RFC3339Nano, sourceStarted.String)
		if err != nil {
			return time.Time{}, "", time.Time{}, fmt.Errorf("store: parse situation input delivery source_started_at: %w", err)
		}
		return startAt, basis, receivedAt, nil
	}
	return receivedAt, situationmodel.SourceTimeBasisReceiptFallback, receivedAt, nil
}

// resolveAndApplySituationTx implements the owner-selection precedence: an
// Incident that already owns a Situation always continues feeding it
// (regardless of that Situation's own lifecycle); otherwise the exact
// group's nonterminal Situation joins; otherwise a new active "observe"
// Situation is created, linked via previous_situation_id to the newest
// terminal same-group Situation, if any. It returns the id of the Situation
// the input was applied to.
func resolveAndApplySituationTx(ctx context.Context, tx *sql.Tx, row situationInputRow, startAt time.Time, basis situationmodel.SourceTimeBasis, receivedAt time.Time, dueReason situationmodel.DueReason, now time.Time) (string, error) {
	situationID, err := situationOwnerForIncidentTx(ctx, tx, row.incidentID)
	if err != nil {
		return "", err
	}
	if situationID == "" {
		situationID, err = nonterminalSituationIDByGroupTx(ctx, tx, row.groupKey)
		if err != nil {
			return "", err
		}
	}

	if situationID != "" {
		if err := joinSituationTx(ctx, tx, situationID, startAt, basis, receivedAt, dueReason, row.occurredAt, now); err != nil {
			return "", err
		}
		return situationID, nil
	}

	return createSituationTx(ctx, tx, row.groupKey, startAt, basis, receivedAt, dueReason, row.occurredAt, now)
}

// situationOwnerForIncidentTx returns the Situation id this Incident already
// belongs to, or "" if the Incident has never been attached to one.
func situationOwnerForIncidentTx(ctx context.Context, tx *sql.Tx, incidentID string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT situation_id FROM situation_incidents WHERE incident_id = ?`, incidentID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read situation owner for incident: %w", err)
	}
	return id, nil
}

// nonterminalSituationIDByGroupTx returns the id of the exact group's one
// nonterminal Situation ("active" or "recovery_pending"), or "" if none
// exists. situations_one_nonterminal_group_idx guarantees at most one.
func nonterminalSituationIDByGroupTx(ctx context.Context, tx *sql.Tx, groupKey string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read nonterminal situation for group: %w", err)
	}
	return id, nil
}

// newestTerminalSituationIDTx returns the id of the exact group's most
// recently terminalized Situation ("recovered" or "closed_unknown"), or nil
// if the group has never had one. A freshly created Situation links to this
// via previous_situation_id — the record of "a later firing creates a new
// Situation" per this plan's global constraints.
func newestTerminalSituationIDTx(ctx context.Context, tx *sql.Tx, groupKey string) (*string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM situations
		WHERE group_key = ? AND lifecycle IN ('recovered','closed_unknown')
		ORDER BY terminal_at DESC, id DESC LIMIT 1`, groupKey).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no terminal predecessor is a legitimate, common outcome, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("store: read newest terminal situation: %w", err)
	}
	return &id, nil
}

// mergeBasis folds one more contributing input's source-time basis into a
// Situation's running effective_started_at_basis: agreement keeps the
// shared basis, any disagreement — including a Situation that is already
// "mixed" — settles permanently on "mixed".
func mergeBasis(existing, incoming situationmodel.SourceTimeBasis) situationmodel.SourceTimeBasis {
	if existing == incoming {
		return existing
	}
	return situationmodel.SourceTimeBasisMixed
}

// mergeDueReason appends reason to reasons unless it is already present,
// preserving the existing order — due_reasons_json is a stable,
// de-duplicated list, never reordered or reset by a repeat contributor.
func mergeDueReason(reasons []situationmodel.DueReason, reason situationmodel.DueReason) []situationmodel.DueReason {
	for _, r := range reasons {
		if r == reason {
			return reasons
		}
	}
	out := make([]situationmodel.DueReason, 0, len(reasons)+1)
	out = append(out, reasons...)
	return append(out, reason)
}

// earlierTime returns whichever of a, b is not after the other.
func earlierTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// joinSituationTx advances an existing Situation with one more applied
// input: input_version increments exactly once, effective_started_at and
// first_received_at each take the earlier of their current value and this
// input's contribution, effective_started_at_basis merges per mergeBasis,
// next_assessment_at takes the earlier of its current value and the input's
// OccurredAt (a new due reason pulls reassessment forward, never pushes it
// out), and due_reasons_json merges the mapped reason. It also clears any
// aggregate lease owner/expiry while leaving claim_token untouched (monotonic):
// a controller that claimed this Situation before this input's application
// holds a lease_owner/claim_token pair that can no longer match once
// lease_owner goes NULL here, fencing it out of committing a decision based
// on stale input_version data.
func joinSituationTx(ctx context.Context, tx *sql.Tx, situationID string, startAt time.Time, basis situationmodel.SourceTimeBasis, receivedAt time.Time, dueReason situationmodel.DueReason, occurredAt, now time.Time) error {
	current, err := getSituationTx(ctx, tx, situationID)
	if err != nil {
		return err
	}

	newStart := earlierTime(current.EffectiveStartedAt, startAt)
	newBasis := mergeBasis(current.EffectiveStartedAtBasis, basis)
	newFirstReceived := earlierTime(current.FirstReceivedAt, receivedAt)
	newNextAssessment := earlierTime(current.NextAssessmentAt, occurredAt)
	newDueReasons := mergeDueReason(current.DueReasons, dueReason)

	dueReasonsJSON, err := json.Marshal(newDueReasons)
	if err != nil {
		return fmt.Errorf("store: marshal situation due reasons: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situations
		SET input_version = input_version + 1,
		    effective_started_at = ?, effective_started_at_basis = ?,
		    first_received_at = ?, next_assessment_at = ?, due_reasons_json = ?,
		    lease_owner = NULL, lease_expires_at = NULL,
		    updated_at = ?
		WHERE id = ? AND input_version = ?`,
		canonicalTime(newStart), string(newBasis), canonicalTime(newFirstReceived), canonicalTime(newNextAssessment), string(dueReasonsJSON),
		canonicalTime(now), situationID, current.InputVersion)
	if err != nil {
		return fmt.Errorf("store: update situation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count updated situation: %w", err)
	}
	if n != 1 {
		return ErrSituationVersionConflict
	}
	return nil
}

// createSituationTx inserts a brand-new active "observe" Situation at
// input_version 1, seeded entirely from this one input, linked via
// previous_situation_id to the newest terminal same-group Situation if one
// exists.
func createSituationTx(ctx context.Context, tx *sql.Tx, groupKey string, startAt time.Time, basis situationmodel.SourceTimeBasis, receivedAt time.Time, dueReason situationmodel.DueReason, occurredAt, now time.Time) (string, error) {
	previousID, err := newestTerminalSituationIDTx(ctx, tx, groupKey)
	if err != nil {
		return "", err
	}
	var previousArg any
	if previousID != nil {
		previousArg = *previousID
	}

	id := uuid.NewString()
	dueReasonsJSON, err := json.Marshal([]situationmodel.DueReason{dueReason})
	if err != nil {
		return "", fmt.Errorf("store: marshal new situation due reasons: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO situations (
			id, previous_situation_id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json,
			created_at, updated_at
		) VALUES (?, ?, ?, 'active', 'observe', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, previousArg, groupKey,
		canonicalTime(now), canonicalTime(startAt), string(basis), canonicalTime(receivedAt),
		canonicalTime(receivedAt), canonicalTime(occurredAt), string(dueReasonsJSON),
		canonicalTime(now), canonicalTime(now))
	if err != nil {
		return "", fmt.Errorf("store: insert situation: %w", err)
	}
	return id, nil
}

// attachSituationMembershipTx records the immutable situation_incidents
// membership link. INSERT OR IGNORE makes a repeat attach for the same
// (situation, incident) pair — the idempotent-replay case, or an Incident
// whose owner-selection resolves back to the Situation it already belongs
// to — a safe no-op; situation_incidents' own UNIQUE(incident_id) and
// no-update/no-delete triggers keep membership otherwise immutable.
func attachSituationMembershipTx(ctx context.Context, tx *sql.Tx, situationID, incidentID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO situation_incidents (situation_id, incident_id, attached_at)
		VALUES (?, ?, ?)`, situationID, incidentID, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: attach situation membership: %w", err)
	}
	return nil
}

// markSituationInputAppliedTx fences the applied transition on the exact
// claim this call verified at the top of ApplySituationInput's transaction,
// so nothing else could have moved the lease in between.
func markSituationInputAppliedTx(ctx context.Context, tx *sql.Tx, id, owner string, token int64, situationID string, at time.Time) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET status = 'applied', lease_owner = NULL, lease_expires_at = NULL, retry_at = NULL,
		    applied_situation_id = ?, applied_at = ?
		WHERE id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		situationID, canonicalTime(at), id, owner, token)
	if err != nil {
		return fmt.Errorf("store: mark situation input applied: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count situation input applied: %w", err)
	}
	if n != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

// ----------------------------------------------------------------------
// Situation reads and the due-Situation claim (Task 7)
// ----------------------------------------------------------------------

const situationSelect = `
	SELECT id, previous_situation_id, group_key, public_handle, lifecycle, attention, input_version,
	       opened_at, effective_started_at, effective_started_at_basis, first_received_at,
	       last_lifecycle_observed_at, recovery_observed_at, grace_until, terminal_at, terminal_reason,
	       next_assessment_at, due_reasons_json, lease_owner, lease_expires_at, claim_token, attempt_count,
	       last_error_class, retry_at, created_at, updated_at
	FROM situations`

func scanSituation(s scanner) (situationmodel.Situation, error) {
	var sit situationmodel.Situation
	var (
		previousID, publicHandle, terminalReasonStr, leaseOwner, lastErrorClass        sql.NullString
		recoveryObservedStr, graceUntilStr, terminalAtStr, leaseExpiresStr, retryAtStr sql.NullString
		lifecycle, attention, effStartedBasis                                          string
		openedAtStr, effStartedStr, firstReceivedStr, lastLifecycleStr                 string
		nextAssessmentStr, createdStr, updatedStr, dueReasonsJSON                      string
	)
	if err := s.Scan(
		&sit.ID, &previousID, &sit.GroupKey, &publicHandle, &lifecycle, &attention, &sit.InputVersion,
		&openedAtStr, &effStartedStr, &effStartedBasis, &firstReceivedStr,
		&lastLifecycleStr, &recoveryObservedStr, &graceUntilStr, &terminalAtStr, &terminalReasonStr,
		&nextAssessmentStr, &dueReasonsJSON, &leaseOwner, &leaseExpiresStr, &sit.ClaimToken, &sit.AttemptCount,
		&lastErrorClass, &retryAtStr, &createdStr, &updatedStr,
	); err != nil {
		return situationmodel.Situation{}, err
	}

	sit.Lifecycle = situationmodel.Lifecycle(lifecycle)
	sit.Attention = situationmodel.Attention(attention)
	sit.EffectiveStartedAtBasis = situationmodel.SourceTimeBasis(effStartedBasis)
	sit.PreviousSituationID = stringPtr(previousID)
	sit.PublicHandle = stringPtr(publicHandle)
	sit.LeaseOwner = stringPtr(leaseOwner)
	sit.LastErrorClass = stringPtr(lastErrorClass)
	if tr := stringPtr(terminalReasonStr); tr != nil {
		reason := situationmodel.TerminalReason(*tr)
		sit.TerminalReason = &reason
	}

	parse := func(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }
	var err error
	if sit.OpenedAt, err = parse(openedAtStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation opened_at: %w", err)
	}
	if sit.EffectiveStartedAt, err = parse(effStartedStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation effective_started_at: %w", err)
	}
	if sit.FirstReceivedAt, err = parse(firstReceivedStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation first_received_at: %w", err)
	}
	if sit.LastLifecycleObservedAt, err = parse(lastLifecycleStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation last_lifecycle_observed_at: %w", err)
	}
	if sit.NextAssessmentAt, err = parse(nextAssessmentStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation next_assessment_at: %w", err)
	}
	if sit.CreatedAt, err = parse(createdStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation created_at: %w", err)
	}
	if sit.UpdatedAt, err = parse(updatedStr); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: parse situation updated_at: %w", err)
	}
	if sit.RecoveryObservedAt, err = timePtr(recoveryObservedStr); err != nil {
		return situationmodel.Situation{}, err
	}
	if sit.GraceUntil, err = timePtr(graceUntilStr); err != nil {
		return situationmodel.Situation{}, err
	}
	if sit.TerminalAt, err = timePtr(terminalAtStr); err != nil {
		return situationmodel.Situation{}, err
	}
	if sit.LeaseExpiresAt, err = timePtr(leaseExpiresStr); err != nil {
		return situationmodel.Situation{}, err
	}
	if sit.RetryAt, err = timePtr(retryAtStr); err != nil {
		return situationmodel.Situation{}, err
	}

	if err := json.Unmarshal([]byte(dueReasonsJSON), &sit.DueReasons); err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: unmarshal situation due reasons: %w", err)
	}
	return sit, nil
}

// getSituationTx reads one Situation by id inside an existing transaction,
// returning ErrNotFound if it does not exist.
func getSituationTx(ctx context.Context, tx *sql.Tx, id string) (situationmodel.Situation, error) {
	sit, err := scanSituation(tx.QueryRowContext(ctx, situationSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.Situation{}, ErrNotFound
	}
	if err != nil {
		return situationmodel.Situation{}, fmt.Errorf("store: read situation: %w", err)
	}
	return sit, nil
}

// ClaimDueSituations leases due Situations — nonterminal ("active" or
// "recovery_pending") rows whose next_assessment_at or retry_at has arrived,
// and that are not already held under an unexpired lease — in one atomic
// transaction. Claiming increments both claim_token (fencing every prior
// lease holder out) and attempt_count. Rows are claimed and returned in
// next_assessment_at order. This is the Situation controller's own claim
// primitive; ApplySituationInput never calls it and is not fenced by it.
func (s *Store) ClaimDueSituations(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situationmodel.Situation, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: due situation claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim due situations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE situations
		SET lease_owner = ?, lease_expires_at = ?, claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE id IN (
			SELECT id FROM situations
			WHERE lifecycle IN ('active','recovery_pending')
			  AND (lease_owner IS NULL OR lease_expires_at <= ?)
			  AND (next_assessment_at <= ? OR (retry_at IS NOT NULL AND retry_at <= ?))
			ORDER BY next_assessment_at ASC, id ASC
			LIMIT ?
		)
		RETURNING id
	`, owner, leaseExpires, nowStr, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim due situations: %w", err)
	}
	claimedIDs, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed due situation ids: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty due situation claim: %w", err)
		}
		return []situationmodel.Situation{}, nil
	}

	placeholders := make([]string, len(claimedIDs))
	args := make([]any, 0, len(claimedIDs))
	for i, id := range claimedIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	query := situationSelect + ` WHERE id IN (` + strings.Join(placeholders, ",") + `) ORDER BY next_assessment_at ASC, id ASC`
	rows2, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed due situations: %w", err)
	}
	defer func() { _ = rows2.Close() }()

	out := make([]situationmodel.Situation, 0, len(claimedIDs))
	for rows2.Next() {
		sit, err := scanSituation(rows2)
		if err != nil {
			return nil, fmt.Errorf("store: scan claimed due situation: %w", err)
		}
		out = append(out, sit)
	}
	if err := rows2.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed due situations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim due situations: %w", err)
	}
	return out, nil
}

// ReleaseSituationClaim releases a claimed Situation's lease, fenced on
// (id, lease_owner, claim_token) all at once: if any of those moved on since
// the claim was issued — including ApplySituationInput clearing the lease
// owner while advancing input_version — exactly zero rows change and this
// returns ErrSituationLeaseLost instead of silently doing nothing or
// clobbering a newer claimant's lease.
func (s *Store) ReleaseSituationClaim(ctx context.Context, claim situationmodel.Situation, now time.Time) error {
	if strings.TrimSpace(claim.ID) == "" || claim.LeaseOwner == nil || strings.TrimSpace(*claim.LeaseOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: release situation claim requires a complete claim")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations SET lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(now.UTC()), claim.ID, *claim.LeaseOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: release situation claim: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count released situation claim: %w", err)
	}
	if n != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}
