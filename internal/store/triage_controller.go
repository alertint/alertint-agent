// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 6: gate the shipped Acute Triage schedule behind the controller's
// B+ decision (migration 0016_incident_triage_controller.sql is the binding
// schema ground truth) and fence every attempt claim/completion by both
// membership_digest and incident_input_digest. This file extends
// triage.go's shipped five-attempt schedule methods; it does not replace
// them — triage.go's claim/backoff/exhaust/recover methods still service
// the pending/backoff/in_flight rows the old schedule already understands.
//
// applyTriageDecisionsTx is unexported and used only inside this package's
// own tests (triage_controller_test.go) and, later, Task 8's
// CommitController — there is no independent controller-decision
// transaction in production, per this task's brief.
// ----------------------------------------------------------------------

// ErrTriageNotDecided means a claim was attempted against an incident_triage
// row with no recorded situation_id/decision_input_version — a row the
// controller has never actually decided "request" for (e.g. one seeded by
// the legacy pre-controller SeedIncidentTriage path, or an awaiting_decision
// row no decision has touched yet). ClaimIncidentTriageAttempt needs both
// values to build a valid incident_triage_attempts row.
var ErrTriageNotDecided = errors.New("store: incident triage row has no controller decision to claim against")

// ErrTriageAttemptCompletedDifferently means a replayed
// CompleteIncidentTriageAttempt call named an attempt already completed
// with different content than this call would produce — a genuine content
// conflict, not an idempotent replay.
var ErrTriageAttemptCompletedDifferently = errors.New("store: incident triage attempt already completed with different content")

// ErrTriageNotDue means a claim was attempted against an incident_triage row
// that is pending/backoff and carries a controller decision, but whose
// next_at has not yet arrived — the row exists and is claimable, just not
// yet, unlike ErrNotFound (no such claimable row at all) or
// ErrTriageNotDecided (claimable timing-wise, but never decided).
var ErrTriageNotDue = errors.New("store: incident triage row is not yet due")

const triageDecisionOriginController = "controller_decision"
const triageDecisionOriginUpgrade = "upgrade_existing_schedule"

// ----------------------------------------------------------------------
// Shared helpers.
// ----------------------------------------------------------------------

// loadIncidentDeliveriesTx reads incidentID's own group_key plus every
// immutable delivery currently attached to it — the same shape
// loadSituationDeliveriesTx builds for a whole Situation, scoped here to one
// Incident, so ClaimIncidentTriageAttempt/CompleteIncidentTriageAttempt can
// compute MembershipDigest/IncidentInputDigest without needing the
// Incident's owning Situation at all.
func loadIncidentDeliveriesTx(ctx context.Context, tx *sql.Tx, incidentID string) (groupKey string, deliveries []situation.Delivery, err error) {
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrNotFound
		}
		return "", nil, fmt.Errorf("store: read incident group key: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT ad.id, ad.alert_id, ad.status, ad.payload_digest,
		       ad.source_started_at, ad.started_at_basis, ad.source_resolved_at, ad.resolved_at_basis, ad.received_at,
		       ad.labels_json
		FROM incident_alert_deliveries iad
		JOIN alert_deliveries ad ON ad.id = iad.delivery_id
		WHERE iad.incident_id = ?
		ORDER BY ad.received_at ASC, ad.id ASC`, incidentID)
	if err != nil {
		return "", nil, fmt.Errorf("store: load incident deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situation.Delivery{}
	for rows.Next() {
		var d situation.Delivery
		var status, startedBasis, resolvedBasis, receivedAtStr, labelsJSON string
		var sourceStarted, sourceResolved sql.NullString
		if err := rows.Scan(&d.ID, &d.AlertID, &status, &d.PayloadDigest,
			&sourceStarted, &startedBasis, &sourceResolved, &resolvedBasis, &receivedAtStr, &labelsJSON); err != nil {
			return "", nil, fmt.Errorf("store: scan incident delivery: %w", err)
		}
		d.IncidentID = incidentID
		d.Status = situationmodel.DeliveryStatus(status)
		d.StartedAtBasis = situationmodel.SourceTimeBasis(startedBasis)
		d.ResolvedAtBasis = situationmodel.SourceTimeBasis(resolvedBasis)
		started, err := timePtr(sourceStarted)
		if err != nil {
			return "", nil, err
		}
		d.SourceStartedAt = started
		resolved, err := timePtr(sourceResolved)
		if err != nil {
			return "", nil, err
		}
		d.SourceResolvedAt = resolved
		if d.ReceivedAt, err = time.Parse(time.RFC3339Nano, receivedAtStr); err != nil {
			return "", nil, fmt.Errorf("store: parse incident delivery received_at: %w", err)
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			return "", nil, fmt.Errorf("store: unmarshal incident delivery %s labels: %w", d.ID, err)
		}
		d.Severity = labels["severity"]
		d.Drill = labels[DrillMarkerLabel] == DrillMarkerValue
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("store: iterate incident deliveries: %w", err)
	}
	return groupKey, out, nil
}

// incidentDigestsTx recomputes incidentID's CURRENT membership and
// Incident-input digests from live durable delivery data — the single
// source of truth every claim, decision-apply, and completion fences
// against, never a caller-supplied value.
func incidentDigestsTx(ctx context.Context, tx *sql.Tx, incidentID string) (membershipDigest, incidentInputDigest string, err error) {
	groupKey, deliveries, err := loadIncidentDeliveriesTx(ctx, tx, incidentID)
	if err != nil {
		return "", "", err
	}
	return situation.MembershipDigest(incidentID, deliveries), situation.IncidentInputDigest(incidentID, groupKey, deliveries), nil
}

// memberDeliveryIDsTx returns the sorted, bounded immutable delivery IDs
// currently attached to incidentID — the "bounded immutable member/delivery
// identities used for analysis" a claim freezes and returns verbatim.
func memberDeliveryIDsTx(ctx context.Context, tx *sql.Tx, incidentID string) ([]string, error) {
	_, deliveries, err := loadIncidentDeliveriesTx(ctx, tx, incidentID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(deliveries))
	for _, d := range deliveries {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return ids, nil
}

// canonicalDigest is this package's own "sha256:<hex>" digest helper — the
// same convention internal/situation's canonicalDigest uses, reimplemented
// locally rather than exported from that pure package: this package hashes
// its own store-local DTOs (bounded sanitized attempt output, Finding
// content), never a situation-package value.
func canonicalDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// v is always one of this file's own closed local DTOs — a marshal
		// failure here is a programming-time invariant violation, not a
		// runtime data condition this store layer can meaningfully recover
		// from (mirrors internal/situation's own mustMarshal panic).
		panic(fmt.Sprintf("store: marshal invariant violated: %v", err))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// insertTriageSituationInputTx idempotently appends one pending
// situation_input_outbox row of kind for incidentID/groupKey — the shared
// primitive behind every Situation input this file's decision/attempt
// methods append (triage_skipped, triage_retry_changed, finding_persisted).
// idempotencyKey must already be globally unique for the specific event
// being recorded (e.g. "triage-retry-changed:"+attemptID+":begin") so a
// replay of the same durable transition never manufactures a duplicate
// input. ON CONFLICT DO NOTHING makes the insert itself idempotent; this
// function never verifies the existing row's content matches (unlike
// AppendSituationFacts' ErrImmutableConflict path) because every caller here
// derives idempotencyKey from an identity (an attempt id, a decision's own
// input version) that can only ever describe one specific event.
func insertTriageSituationInputTx(ctx context.Context, tx *sql.Tx, kind, idempotencyKey, incidentID, groupKey string, occurredAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')
		ON CONFLICT(idempotency_key) DO NOTHING`,
		"situation-input:"+idempotencyKey, idempotencyKey, incidentID, kind, groupKey, canonicalTime(occurredAt)); err != nil {
		return fmt.Errorf("store: insert %s situation input: %w", kind, err)
	}
	return nil
}

// ----------------------------------------------------------------------
// applyTriageDecisionsTx — Task 6's decision-commit transaction helper.
// Unexported: there is no independent controller-decision transaction in
// production. Task 8's CommitController is the only future caller, applying
// this inside the same fenced transaction that commits the Assessment the
// decisions share; this task tests it directly against its own transaction.
// ----------------------------------------------------------------------

// applyTriageDecisionsTx commits every decision DecideTriage produced,
// inside tx. Each decision is applied against the incident_triage row's
// CURRENT phase, read fresh inside this same transaction (never trusted
// from the decision's own snapshot):
//
//   - a fresh awaiting_decision row + Decision=request moves it to pending,
//     due immediately, preserving attempt zero (no Situation input: request
//     alone does not change the durable Operator contract — only actually
//     beginning an attempt does, per spec.md);
//   - a fresh awaiting_decision row + Decision=skip moves it to skipped,
//     records the decision, and appends exactly one triage_skipped input;
//   - an already-decided pending/backoff row (a "refresh" decision, always
//     Decision=request) has its recorded digests/decision metadata
//     overwritten in place WITHOUT touching phase, next_at, or attempts —
//     "without consuming an attempt or moving the due time earlier merely
//     to accelerate retry".
//
// A decision whose Incident row is no longer in a phase this function
// recognizes (raced away by something else since DecideTriage's read) is
// skipped rather than applied — decisions are advisory until committed;
// only the fenced write here is authoritative.
func applyTriageDecisionsTx(ctx context.Context, tx *sql.Tx, decisions []situation.TriageDecision, now time.Time) error {
	for _, d := range decisions {
		if err := applyOneTriageDecisionTx(ctx, tx, d, now); err != nil {
			return err
		}
	}
	return nil
}

func applyOneTriageDecisionTx(ctx context.Context, tx *sql.Tx, d situation.TriageDecision, now time.Time) error {
	var phase string
	var groupKey string
	err := tx.QueryRowContext(ctx, `
		SELECT t.phase, i.group_key FROM incident_triage t
		JOIN incidents i ON i.id = t.incident_id
		WHERE t.incident_id = ?`, d.IncidentID).Scan(&phase, &groupKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // raced away entirely; nothing left to apply this decision to
	}
	if err != nil {
		return fmt.Errorf("store: read incident triage row for decision: %w", err)
	}

	switch {
	case phase == "awaiting_decision" && d.Decision == situation.TriageDecisionRequest:
		return applyRequestFromAwaitingDecisionTx(ctx, tx, d, now)
	case phase == "awaiting_decision" && d.Decision == situation.TriageDecisionSkip:
		return applySkipFromAwaitingDecisionTx(ctx, tx, d, groupKey, now)
	case (phase == "pending" || phase == "backoff") && d.Decision == situation.TriageDecisionRequest:
		return applyRefreshDecisionTx(ctx, tx, d, phase, now)
	default:
		// A skip decision can never legally apply to a pending/backoff row
		// (DecideTriage's own refresh path forces Decision=request), and any
		// other phase (in_flight/skipped/exhausted) is no longer decidable —
		// silently drop rather than corrupt state a different path already
		// owns.
		return nil
	}
}

func applyRequestFromAwaitingDecisionTx(ctx context.Context, tx *sql.Tx, d situation.TriageDecision, now time.Time) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'pending', next_at = ?,
		    situation_id = ?, decision = 'request', decision_reason = ?, decision_origin = ?,
		    decision_input_version = ?, material_fact_hash = ?, membership_digest = ?, incident_input_digest = ?,
		    decided_at = ?, updated_at = ?
		WHERE incident_id = ? AND phase = 'awaiting_decision'`,
		canonicalTime(now), d.SituationID, d.DecisionReason, triageDecisionOriginController,
		d.SituationInputVersion, d.MaterialFactHash, d.MembershipDigest, d.IncidentInputDigest,
		canonicalTime(d.DecidedAt), canonicalTime(now), d.IncidentID)
	if err != nil {
		return fmt.Errorf("store: apply triage request decision: %w", err)
	}
	return requireOneRow(res, "store: apply triage request decision", ErrNotFound)
}

func applySkipFromAwaitingDecisionTx(ctx context.Context, tx *sql.Tx, d situation.TriageDecision, groupKey string, now time.Time) error {
	var assessmentID any
	if d.CoveredAssessmentID != nil {
		assessmentID = *d.CoveredAssessmentID
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'skipped', next_at = NULL,
		    situation_id = ?, decision = 'skip', decision_reason = ?, decision_origin = ?,
		    decision_input_version = ?, material_fact_hash = ?, membership_digest = ?, incident_input_digest = ?,
		    assessment_id = ?, decided_at = ?, updated_at = ?
		WHERE incident_id = ? AND phase = 'awaiting_decision'`,
		d.SituationID, d.DecisionReason, triageDecisionOriginController,
		d.SituationInputVersion, d.MaterialFactHash, d.MembershipDigest, d.IncidentInputDigest,
		assessmentID, canonicalTime(d.DecidedAt), canonicalTime(now), d.IncidentID)
	if err != nil {
		return fmt.Errorf("store: apply triage skip decision: %w", err)
	}
	if err := requireOneRow(res, "store: apply triage skip decision", ErrNotFound); err != nil {
		return err
	}

	idempotencyKey := fmt.Sprintf("triage-skipped:%s:%d", d.IncidentID, d.SituationInputVersion)
	return insertTriageSituationInputTx(ctx, tx, "triage_skipped", idempotencyKey, d.IncidentID, groupKey, d.DecidedAt)
}

func applyRefreshDecisionTx(ctx context.Context, tx *sql.Tx, d situation.TriageDecision, phase string, now time.Time) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET situation_id = ?, decision = 'request', decision_reason = ?, decision_origin = ?,
		    decision_input_version = ?, material_fact_hash = ?, membership_digest = ?, incident_input_digest = ?,
		    decided_at = ?, updated_at = ?
		WHERE incident_id = ? AND phase = ?`,
		d.SituationID, d.DecisionReason, triageDecisionOriginController,
		d.SituationInputVersion, d.MaterialFactHash, d.MembershipDigest, d.IncidentInputDigest,
		canonicalTime(d.DecidedAt), canonicalTime(now), d.IncidentID, phase)
	if err != nil {
		return fmt.Errorf("store: apply triage refresh decision: %w", err)
	}
	return requireOneRow(res, "store: apply triage refresh decision", ErrNotFound)
}

// requireOneRow fails closed with sentinel if res did not affect exactly
// one row — every fenced write in this file uses this instead of silently
// tolerating zero rows, since a decision/claim/completion that no-ops
// unexpectedly is a concurrency bug, not a legitimate outcome (unlike
// applyOneTriageDecisionTx's own "row vanished entirely" branch above, which
// is a legitimate race this package's single-writer model still defends
// against).
func requireOneRow(res sql.Result, context string, sentinel error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: rows affected: %w", context, err)
	}
	if n != 1 {
		return fmt.Errorf("%s: %w", context, sentinel)
	}
	return nil
}

// ----------------------------------------------------------------------
// ClaimIncidentTriageAttempt — the fenced attempt claim (spec.md "Attempt
// identity and completion"). Only due pending/backoff rows carrying a
// controller decision (situation_id/decision_input_version set) are
// claimable; awaiting_decision is never claimable by construction (this
// method never even queries for that phase).
// ----------------------------------------------------------------------

// ClaimedTriageAttempt is one freshly claimed incident_triage_attempts row
// plus the fenced lease pair a worker must present back to complete,
// back off, exhaust, or extend it.
type ClaimedTriageAttempt struct {
	AttemptID            string
	IncidentID           string
	AttemptNumber        int
	SituationID          string
	DecisionInputVersion int
	MembershipDigest     string
	IncidentInputDigest  string
	MemberDeliveryIDs    []string
	StartedAt            time.Time
	LeaseOwner           string
	LeaseExpiresAt       time.Time
	ClaimToken           int64
}

// ClaimIncidentTriageAttempt claims incidentID's due pending/backoff row for
// analysis: recomputes and freezes the current membership/Incident-input
// digests and the bounded immutable member delivery IDs, inserts the
// attempt ledger row under a stable derived identity, moves the schedule to
// in_flight under a fenced lease (owner/expiry/claim_token), marks the
// Incident processing, increments attempts, and appends triage_retry_changed
// ("Beginning an attempt likewise appends triage_retry_changed so the
// controller can change the durable contract from planned to running").
// Returns ErrNotFound if the row is not currently pending/backoff for a
// ready Incident, ErrTriageNotDue if it is pending/backoff but its next_at
// has not yet arrived, or ErrTriageNotDecided if it has never received a
// controller decision.
func (s *Store) ClaimIncidentTriageAttempt(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (ClaimedTriageAttempt, error) {
	if strings.TrimSpace(incidentID) == "" || strings.TrimSpace(owner) == "" || lease <= 0 {
		return ClaimedTriageAttempt{}, errors.New("store: claim incident triage attempt requires incident id, owner, and a positive lease")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: begin claim incident triage attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var phase string
	var attempts int
	var situationID, groupKey, nextAtStr sql.NullString
	var decisionInputVersion sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT t.phase, t.attempts, t.situation_id, t.decision_input_version, t.next_at, i.group_key
		FROM incident_triage t JOIN incidents i ON i.id = t.incident_id
		WHERE t.incident_id = ? AND i.status = 'ready'`, incidentID).
		Scan(&phase, &attempts, &situationID, &decisionInputVersion, &nextAtStr, &groupKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ClaimedTriageAttempt{}, ErrNotFound
	}
	if err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: read incident triage row for claim: %w", err)
	}
	if phase != "pending" && phase != "backoff" {
		return ClaimedTriageAttempt{}, ErrNotFound
	}
	nextAt, err := timePtr(nextAtStr)
	if err != nil {
		return ClaimedTriageAttempt{}, err
	}
	if nextAt != nil && nextAt.After(now) {
		return ClaimedTriageAttempt{}, ErrTriageNotDue
	}
	if !situationID.Valid || !decisionInputVersion.Valid {
		return ClaimedTriageAttempt{}, ErrTriageNotDecided
	}

	membership, inputDigest, err := incidentDigestsTx(ctx, tx, incidentID)
	if err != nil {
		return ClaimedTriageAttempt{}, err
	}
	memberDeliveryIDs, err := memberDeliveryIDsTx(ctx, tx, incidentID)
	if err != nil {
		return ClaimedTriageAttempt{}, err
	}
	memberDeliveryIDsJSON, err := json.Marshal(memberDeliveryIDs)
	if err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: marshal member delivery ids: %w", err)
	}

	attemptNumber := attempts + 1
	attemptID := uuid.NewString()
	leaseExpires := now.Add(lease)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incident_triage_attempts
			(id, incident_id, attempt_number, situation_id, decision_input_version,
			 membership_digest, incident_input_digest, member_delivery_ids_json, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		attemptID, incidentID, attemptNumber, situationID.String, decisionInputVersion.Int64,
		membership, inputDigest, string(memberDeliveryIDsJSON), canonicalTime(now)); err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: insert incident triage attempt: %w", err)
	}

	// claim_token increments monotonically (never derived from attempt
	// count, which this method already tracks separately) — the same
	// fencing idiom ClaimDueSituations/ClaimSituationInputs use, so no
	// prior lease holder's (lease_owner, claim_token) pair can ever match
	// again.
	row := tx.QueryRowContext(ctx, `
		UPDATE incident_triage
		SET phase = 'in_flight', attempts = attempts + 1, started_at = ?, next_at = NULL,
		    decision_origin = ?, lease_owner = ?, lease_expires_at = ?, claim_token = claim_token + 1, current_attempt_id = ?,
		    updated_at = ?
		WHERE incident_id = ? AND phase IN ('pending','backoff')
		RETURNING claim_token`,
		canonicalTime(now), triageDecisionOriginController, owner, canonicalTime(leaseExpires), attemptID,
		canonicalTime(now), incidentID)
	var claimToken int64
	if err := row.Scan(&claimToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ClaimedTriageAttempt{}, fmt.Errorf("store: claim incident triage schedule: %w", ErrNotFound)
		}
		return ClaimedTriageAttempt{}, fmt.Errorf("store: claim incident triage schedule: %w", err)
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'processing', updated_at = ? WHERE id = ? AND status = 'ready'`,
		canonicalTime(now), incidentID)
	if err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: mark incident processing: %w", err)
	}
	if err := requireOneRow(res2, "store: mark incident processing", ErrNotFound); err != nil {
		return ClaimedTriageAttempt{}, err
	}

	idempotencyKey := "triage-retry-changed:" + attemptID + ":begin"
	if err := insertTriageSituationInputTx(ctx, tx, "triage_retry_changed", idempotencyKey, incidentID, groupKey.String, now); err != nil {
		return ClaimedTriageAttempt{}, err
	}

	if err := tx.Commit(); err != nil {
		return ClaimedTriageAttempt{}, fmt.Errorf("store: commit claim incident triage attempt: %w", err)
	}
	return ClaimedTriageAttempt{
		AttemptID: attemptID, IncidentID: incidentID, AttemptNumber: attemptNumber,
		SituationID: situationID.String, DecisionInputVersion: int(decisionInputVersion.Int64),
		MembershipDigest: membership, IncidentInputDigest: inputDigest, MemberDeliveryIDs: memberDeliveryIDs,
		StartedAt: now, LeaseOwner: owner, LeaseExpiresAt: leaseExpires, ClaimToken: claimToken,
	}, nil
}

// ExtendIncidentTriageLease renews a claimed attempt's lease — the
// heartbeat a long-running worker calls periodically so a slow but healthy
// analysis is never reclaimed as interrupted. Fenced on the exact
// (incident_id, current_attempt_id, lease_owner) triple the claim returned;
// a mismatch (attempt already completed/backed off/exhausted, or a
// different owner now holds it) returns ErrTriageAttemptLeaseLost.
func (s *Store) ExtendIncidentTriageLease(ctx context.Context, attemptID, incidentID, owner string, now time.Time, lease time.Duration) error {
	if strings.TrimSpace(attemptID) == "" || strings.TrimSpace(incidentID) == "" || strings.TrimSpace(owner) == "" || lease <= 0 {
		return errors.New("store: extend incident triage lease requires attempt id, incident id, owner, and a positive lease")
	}
	now = now.UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE incident_triage
		SET lease_expires_at = ?, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight' AND current_attempt_id = ? AND lease_owner = ?`,
		canonicalTime(now.Add(lease)), canonicalTime(now), incidentID, attemptID, owner)
	if err != nil {
		return fmt.Errorf("store: extend incident triage lease: %w", err)
	}
	return requireOneRow(res, "store: extend incident triage lease", ErrTriageAttemptLeaseLost)
}

// ErrTriageAttemptLeaseLost means a fenced write named an
// (incident, attempt, owner) triple that no longer matches the current
// in_flight lease — another recovery pass or a completed/backed-off/
// exhausted transition already moved the row on.
var ErrTriageAttemptLeaseLost = errors.New("store: incident triage attempt lease lost")

// ----------------------------------------------------------------------
// CompleteIncidentTriageAttempt — spec.md's single atomic/idempotent
// completion boundary: it verifies the claimed attempt's frozen digests
// against the CURRENT Incident digests (recomputed fresh, never trusted
// from finding's caller-supplied content) and branches, inside the SAME
// transaction, between a current-compatible success and a sanitized
// stale_membership/stale_incident_input record — never as two separate
// caller-selected code paths.
// ----------------------------------------------------------------------

// TriageFinding is the bounded Finding content a current-compatible
// completion persists. Its shape mirrors SaveIncidentOutput's own
// parameters exactly (output_json, summary, root_cause, confidence,
// enrichment_json) — the pre-Plan-2 compatible Incident output projection
// spec.md names; Plan 2 defines no separate durable Findings table.
type TriageFinding struct {
	OutputJSON, Summary, RootCause string
	Confidence                     float64
	EnrichmentJSON                 string
	EvidencePackDigest             string
}

// TriageCompletionOutcome is the closed result CompleteIncidentTriageAttempt
// commits.
type TriageCompletionOutcome string

const (
	TriageCompletionSuccess            TriageCompletionOutcome = "success"
	TriageCompletionStaleMembership    TriageCompletionOutcome = "stale_membership"
	TriageCompletionStaleIncidentInput TriageCompletionOutcome = "stale_incident_input"
)

// TriageCompletionResult is CompleteIncidentTriageAttempt's committed (or,
// on identical replay, already-committed) outcome.
type TriageCompletionResult struct {
	Outcome      TriageCompletionOutcome
	FindingID    string // set only for TriageCompletionSuccess
	OutputDigest string
}

type findingContentDTO struct {
	OutputJSON     string  `json:"output_json"`
	Summary        string  `json:"summary"`
	RootCause      string  `json:"root_cause"`
	Confidence     float64 `json:"confidence"`
	EnrichmentJSON string  `json:"enrichment_json"`
}

func findingOutputDigest(f TriageFinding) string {
	return canonicalDigest(findingContentDTO{
		OutputJSON: f.OutputJSON, Summary: f.Summary, RootCause: f.RootCause,
		Confidence: f.Confidence, EnrichmentJSON: f.EnrichmentJSON,
	})
}

func triageFindingID(attemptID string) string { return "finding:" + attemptID }

type staleAttemptOutputDTO struct {
	FrozenMembershipDigest     string `json:"frozen_membership_digest"`
	CurrentMembershipDigest    string `json:"current_membership_digest"`
	FrozenIncidentInputDigest  string `json:"frozen_incident_input_digest"`
	CurrentIncidentInputDigest string `json:"current_incident_input_digest"`
}

// triageAttemptRow is one incident_triage_attempts row as
// CompleteIncidentTriageAttempt reads it inside its own transaction.
type triageAttemptRow struct {
	incidentID                            string
	membershipDigest, incidentInputDigest string
	resultCode, outputDigest, findingID   sql.NullString
	evidencePackDigest                    sql.NullString
	completed                             bool
}

func readTriageAttemptTx(ctx context.Context, tx *sql.Tx, attemptID string) (triageAttemptRow, error) {
	var r triageAttemptRow
	var completedAt sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT incident_id, membership_digest, incident_input_digest,
		       result_code, output_digest, finding_id, evidence_pack_digest, completed_at
		FROM incident_triage_attempts WHERE id = ?`, attemptID).Scan(
		&r.incidentID, &r.membershipDigest, &r.incidentInputDigest,
		&r.resultCode, &r.outputDigest, &r.findingID, &r.evidencePackDigest, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return triageAttemptRow{}, ErrNotFound
	}
	if err != nil {
		return triageAttemptRow{}, fmt.Errorf("store: read incident triage attempt: %w", err)
	}
	r.completed = completedAt.Valid
	return r, nil
}

// CompleteIncidentTriageAttempt is the fenced, idempotent completion
// boundary for one claimed attempt (spec.md "Attempt identity and
// completion"): it verifies attemptID belongs to incidentID, recomputes the
// CURRENT membership/Incident-input digests, and — inside one transaction —
// either persists finding as a current-compatible success (Finding under a
// stable derived identity, the compatible Incident output projection and
// first-judgment time, closed schedule, one finding_persisted input) or
// records a sanitized stale_membership/stale_incident_input attempt output
// (no Finding, no output projection, restored Incident ready, schedule back
// to awaiting_decision, one triage_retry_changed input). Replaying an
// already-completed attempt with byte-identical finding content returns the
// same committed result; different content fails closed with
// ErrTriageAttemptCompletedDifferently.
func (s *Store) CompleteIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, finding TriageFinding, now time.Time) (TriageCompletionResult, error) {
	if strings.TrimSpace(attemptID) == "" || strings.TrimSpace(incidentID) == "" {
		return TriageCompletionResult{}, errors.New("store: complete incident triage attempt requires attempt id and incident id")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: begin complete incident triage attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	attempt, err := readTriageAttemptTx(ctx, tx, attemptID)
	if err != nil {
		return TriageCompletionResult{}, err
	}
	if attempt.incidentID != incidentID {
		return TriageCompletionResult{}, fmt.Errorf("store: incident triage attempt %s belongs to incident %s, not %s: %w", attemptID, attempt.incidentID, incidentID, ErrNotFound)
	}

	if attempt.completed {
		result, ok := idempotentReplayResult(attempt, finding)
		if !ok {
			return TriageCompletionResult{}, ErrTriageAttemptCompletedDifferently
		}
		return result, tx.Commit()
	}

	currentMembership, currentInputDigest, err := incidentDigestsTx(ctx, tx, incidentID)
	if err != nil {
		return TriageCompletionResult{}, err
	}

	switch {
	case currentMembership != attempt.membershipDigest:
		return completeStaleTx(ctx, tx, attemptID, incidentID, TriageCompletionStaleMembership,
			staleAttemptOutputDTO{
				FrozenMembershipDigest: attempt.membershipDigest, CurrentMembershipDigest: currentMembership,
				FrozenIncidentInputDigest: attempt.incidentInputDigest, CurrentIncidentInputDigest: currentInputDigest,
			}, now)
	case currentInputDigest != attempt.incidentInputDigest:
		return completeStaleTx(ctx, tx, attemptID, incidentID, TriageCompletionStaleIncidentInput,
			staleAttemptOutputDTO{
				FrozenMembershipDigest: attempt.membershipDigest, CurrentMembershipDigest: currentMembership,
				FrozenIncidentInputDigest: attempt.incidentInputDigest, CurrentIncidentInputDigest: currentInputDigest,
			}, now)
	default:
		return completeSuccessTx(ctx, tx, attemptID, incidentID, finding, now)
	}
}

// idempotentReplayResult reports whether an already-completed attempt's
// stored content matches what completing it again with finding would
// produce. A stale completion (no caller content to compare) is treated as
// idempotent by attempt identity alone — a worker never legitimately
// replays CompleteIncidentTriageAttempt with fresh Finding content against
// an attempt it already knows went stale.
func idempotentReplayResult(attempt triageAttemptRow, finding TriageFinding) (TriageCompletionResult, bool) {
	code := ""
	if attempt.resultCode.Valid {
		code = attempt.resultCode.String
	}
	switch code {
	case "success":
		wantDigest := findingOutputDigest(finding)
		gotDigest := ""
		if attempt.outputDigest.Valid {
			gotDigest = attempt.outputDigest.String
		}
		if gotDigest != wantDigest {
			return TriageCompletionResult{}, false
		}
		findingID := ""
		if attempt.findingID.Valid {
			findingID = attempt.findingID.String
		}
		return TriageCompletionResult{Outcome: TriageCompletionSuccess, FindingID: findingID, OutputDigest: gotDigest}, true
	case string(TriageCompletionStaleMembership), string(TriageCompletionStaleIncidentInput):
		outputDigest := ""
		if attempt.outputDigest.Valid {
			outputDigest = attempt.outputDigest.String
		}
		return TriageCompletionResult{Outcome: TriageCompletionOutcome(code), OutputDigest: outputDigest}, true
	default:
		return TriageCompletionResult{}, false
	}
}

func completeSuccessTx(ctx context.Context, tx *sql.Tx, attemptID, incidentID string, finding TriageFinding, now time.Time) (TriageCompletionResult, error) {
	findingID := triageFindingID(attemptID)
	outputDigest := findingOutputDigest(finding)

	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage_attempts
		SET result_code = 'success', output_digest = ?, finding_id = ?, evidence_pack_digest = ?, completed_at = ?
		WHERE id = ? AND completed_at IS NULL`,
		outputDigest, findingID, finding.EvidencePackDigest, canonicalTime(now), attemptID)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: complete incident triage attempt success: %w", err)
	}
	if err := requireOneRow(res, "store: complete incident triage attempt success", ErrTriageAttemptLeaseLost); err != nil {
		return TriageCompletionResult{}, err
	}

	var enrichment any
	if finding.EnrichmentJSON != "" {
		enrichment = finding.EnrichmentJSON
	}
	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents
		SET status = 'analyzed', output_json = ?, summary = ?, root_cause = ?, confidence = ?,
		    enrichment_json = ?, last_judged_at = ?, updated_at = ?
		WHERE id = ? AND status = 'processing'`,
		finding.OutputJSON, finding.Summary, finding.RootCause, finding.Confidence, enrichment,
		canonicalTime(now), canonicalTime(now), incidentID)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: complete incident triage attempt: update incident output: %w", err)
	}
	if err := requireOneRow(res2, "store: complete incident triage attempt: update incident output", ErrNotFound); err != nil {
		return TriageCompletionResult{}, err
	}

	var groupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: read incident group key for finding_persisted: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM incident_triage WHERE incident_id = ?`, incidentID); err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: close incident triage schedule: %w", err)
	}

	idempotencyKey := "finding-persisted:" + attemptID
	if err := insertTriageSituationInputTx(ctx, tx, "finding_persisted", idempotencyKey, incidentID, groupKey, now); err != nil {
		return TriageCompletionResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: commit complete incident triage attempt success: %w", err)
	}
	return TriageCompletionResult{Outcome: TriageCompletionSuccess, FindingID: findingID, OutputDigest: outputDigest}, nil
}

func completeStaleTx(ctx context.Context, tx *sql.Tx, attemptID, incidentID string, outcome TriageCompletionOutcome, dto staleAttemptOutputDTO, now time.Time) (TriageCompletionResult, error) {
	outputDigest := canonicalDigest(dto)

	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage_attempts
		SET result_code = ?, output_digest = ?, completed_at = ?
		WHERE id = ? AND completed_at IS NULL`,
		string(outcome), outputDigest, canonicalTime(now), attemptID)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: complete incident triage attempt stale: %w", err)
	}
	if err := requireOneRow(res, "store: complete incident triage attempt stale", ErrTriageAttemptLeaseLost); err != nil {
		return TriageCompletionResult{}, err
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'processing'`,
		canonicalTime(now), incidentID)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: restore incident ready after stale triage: %w", err)
	}
	if err := requireOneRow(res2, "store: restore incident ready after stale triage", ErrNotFound); err != nil {
		return TriageCompletionResult{}, err
	}

	var groupKey string
	res3, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'awaiting_decision', next_at = NULL, started_at = NULL,
		    lease_owner = NULL, lease_expires_at = NULL, current_attempt_id = NULL, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight' AND current_attempt_id = ?`,
		canonicalTime(now), incidentID, attemptID)
	if err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: restore triage schedule after stale completion: %w", err)
	}
	if err := requireOneRow(res3, "store: restore triage schedule after stale completion", ErrTriageAttemptLeaseLost); err != nil {
		return TriageCompletionResult{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: read incident group key for triage_retry_changed: %w", err)
	}

	idempotencyKey := "triage-retry-changed:" + attemptID + ":stale"
	if err := insertTriageSituationInputTx(ctx, tx, "triage_retry_changed", idempotencyKey, incidentID, groupKey, now); err != nil {
		return TriageCompletionResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return TriageCompletionResult{}, fmt.Errorf("store: commit complete incident triage attempt stale: %w", err)
	}
	return TriageCompletionResult{Outcome: outcome, OutputDigest: outputDigest}, nil
}

// ----------------------------------------------------------------------
// Backoff / exhaust — complete a failed in_flight attempt and either
// reschedule (backoff) or close it out terminally (exhaust), extending the
// shipped five-attempt schedule's own BackoffIncidentTriage/
// ExhaustIncidentTriage behavior (triage.go) onto the new attempt ledger.
// ----------------------------------------------------------------------

type failureOutputDTO struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// completeFailedAttemptTx marks attemptID's ledger row completed with a
// bounded, sanitized typed code/detail — the one legal completing UPDATE
// shared by BackoffIncidentTriageAttempt, ExhaustIncidentTriageAttempt, and
// CompleteIncidentTriageAttemptAsCleanSkip. The name predates the clean-skip
// caller (a clean skip is not a "failure"); the column pair itself is a
// general "how did this attempt end" code/detail, not failure-only — see
// each caller's own doc comment for what its code means.
func completeFailedAttemptTx(ctx context.Context, tx *sql.Tx, attemptID, code, detail string, now time.Time) error {
	sanitized := sanitizeTriageDetail(detail)
	outputDigest := canonicalDigest(failureOutputDTO{Code: code, Detail: sanitized})
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage_attempts
		SET result_code = ?, output_digest = ?, completed_at = ?
		WHERE id = ? AND completed_at IS NULL`,
		code, outputDigest, canonicalTime(now), attemptID)
	if err != nil {
		return fmt.Errorf("store: complete failed incident triage attempt: %w", err)
	}
	return requireOneRow(res, "store: complete failed incident triage attempt", ErrTriageAttemptLeaseLost)
}

// BackoffIncidentTriageAttempt completes attemptID's ledger row with a
// bounded typed failure, releases its lease, and returns the schedule to
// backoff at nextAt without consuming a further attempt slot itself (the
// attempt was already consumed at claim time) — mirroring
// BackoffIncidentTriage's Incident/error semantics, extended to the fenced
// attempt ledger and appending triage_retry_changed ("Backoff commits the
// returned Incident status, typed bounded error, next due time, and
// triage_retry_changed input when the change affects the Operator
// contract").
func (s *Store) BackoffIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, nextAt time.Time, code, detail string, now time.Time) error {
	if strings.TrimSpace(attemptID) == "" || strings.TrimSpace(incidentID) == "" {
		return errors.New("store: backoff incident triage attempt requires attempt id and incident id")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin backoff incident triage attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := completeFailedAttemptTx(ctx, tx, attemptID, code, detail, now); err != nil {
		return err
	}

	sanitized := sanitizeTriageDetail(detail)
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'backoff', next_at = ?, last_error_code = ?, last_error_detail = ?,
		    lease_owner = NULL, lease_expires_at = NULL, current_attempt_id = NULL, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight' AND current_attempt_id = ?`,
		canonicalTime(nextAt), code, sanitized, canonicalTime(now), incidentID, attemptID)
	if err != nil {
		return fmt.Errorf("store: backoff incident triage schedule: %w", err)
	}
	if err := requireOneRow(res, "store: backoff incident triage schedule", ErrTriageAttemptLeaseLost); err != nil {
		return err
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'processing'`,
		canonicalTime(now), incidentID)
	if err != nil {
		return fmt.Errorf("store: restore incident ready after backoff: %w", err)
	}
	if err := requireOneRow(res2, "store: restore incident ready after backoff", ErrNotFound); err != nil {
		return err
	}

	var groupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return fmt.Errorf("store: read incident group key for triage_retry_changed: %w", err)
	}
	idempotencyKey := "triage-retry-changed:" + attemptID + ":backoff"
	if err := insertTriageSituationInputTx(ctx, tx, "triage_retry_changed", idempotencyKey, incidentID, groupKey, now); err != nil {
		return err
	}

	return tx.Commit()
}

// ExhaustIncidentTriageAttempt completes attemptID's ledger row with a
// bounded typed failure and closes the schedule out terminally: Incident ->
// "failed", triage phase -> "exhausted", appending one triage_exhausted
// input ("Clean skip and terminal exhaustion similarly commit their
// Incident/Triage state and unique Situation input together").
func (s *Store) ExhaustIncidentTriageAttempt(ctx context.Context, attemptID, incidentID, code, detail string, now time.Time) error {
	if strings.TrimSpace(attemptID) == "" || strings.TrimSpace(incidentID) == "" {
		return errors.New("store: exhaust incident triage attempt requires attempt id and incident id")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin exhaust incident triage attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := completeFailedAttemptTx(ctx, tx, attemptID, code, detail, now); err != nil {
		return err
	}

	sanitized := sanitizeTriageDetail(detail)
	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'exhausted', next_at = NULL, last_error_code = ?, last_error_detail = ?,
		    lease_owner = NULL, lease_expires_at = NULL, current_attempt_id = NULL, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight' AND current_attempt_id = ?`,
		code, sanitized, canonicalTime(now), incidentID, attemptID)
	if err != nil {
		return fmt.Errorf("store: exhaust incident triage schedule: %w", err)
	}
	if err := requireOneRow(res, "store: exhaust incident triage schedule", ErrTriageAttemptLeaseLost); err != nil {
		return err
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'failed', updated_at = ? WHERE id = ? AND status = 'processing'`,
		canonicalTime(now), incidentID)
	if err != nil {
		return fmt.Errorf("store: mark incident failed after exhaustion: %w", err)
	}
	if err := requireOneRow(res2, "store: mark incident failed after exhaustion", ErrNotFound); err != nil {
		return err
	}

	var groupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return fmt.Errorf("store: read incident group key for triage_exhausted: %w", err)
	}
	idempotencyKey := "triage-exhausted:" + attemptID
	if err := insertTriageSituationInputTx(ctx, tx, "triage_exhausted", idempotencyKey, incidentID, groupKey, now); err != nil {
		return err
	}

	return tx.Commit()
}

// CompleteIncidentTriageAttemptAsCleanSkip closes a claimed attempt whose
// AcuteAnalyzer found nothing worth judging (skills/acutetriage's own
// ErrCleanSkip: too few member alerts, or a known-rule short circuit that
// still consumed a claim) — distinct from DecideTriage's earlier B+-gate-
// level skip (applySkipFromAwaitingDecisionTx), which never claims an
// attempt at all. This clean skip DOES consume the attempt already claimed
// for it (the attempt ledger row it closes proves that), but its end state
// must read as a genuine skip, never a failure:
//
//   - the schedule closes to the SAME terminal 'skipped' phase the B+-gate
//     skip uses, not 'exhausted' — consistency: both readings of "skip"
//     land the same way;
//   - the Incident is restored to "ready", never "failed" (Global
//     Constraint: "Triage exhaustion never closes a Situation" — a skipped
//     Incident must stay collapse-eligible, so a later re-fire is never
//     blocked by ErrIncidentOwnerNotCollapsible the way a "failed" Incident
//     would block it);
//   - it appends exactly one triage_skipped input — reusing the SAME
//     idempotent kind applySkipFromAwaitingDecisionTx's own B+ skip
//     appends, since both mean "no Finding needed, a clean judgment", never
//     triage_exhausted's own, unrelated meaning ("five attempts burned").
//
// Fenced identically to BackoffIncidentTriageAttempt/
// ExhaustIncidentTriageAttempt: attemptID must still be the row's current
// in_flight attempt, verified inside one transaction; a second call against
// an already-completed attempt fails closed with ErrTriageAttemptLeaseLost
// (completeFailedAttemptTx's own `WHERE ... AND completed_at IS NULL`
// fence) rather than silently no-oping or re-appending a duplicate
// Situation input.
func (s *Store) CompleteIncidentTriageAttemptAsCleanSkip(ctx context.Context, attemptID, incidentID, code, detail string, now time.Time) error {
	if strings.TrimSpace(attemptID) == "" || strings.TrimSpace(incidentID) == "" {
		return errors.New("store: complete incident triage attempt as clean skip requires attempt id and incident id")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin complete incident triage attempt as clean skip: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := completeFailedAttemptTx(ctx, tx, attemptID, code, detail, now); err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'skipped', next_at = NULL, last_error_code = NULL, last_error_detail = NULL,
		    lease_owner = NULL, lease_expires_at = NULL, current_attempt_id = NULL, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight' AND current_attempt_id = ?`,
		canonicalTime(now), incidentID, attemptID)
	if err != nil {
		return fmt.Errorf("store: skip incident triage schedule: %w", err)
	}
	if err := requireOneRow(res, "store: skip incident triage schedule", ErrTriageAttemptLeaseLost); err != nil {
		return err
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'processing'`,
		canonicalTime(now), incidentID)
	if err != nil {
		return fmt.Errorf("store: restore incident ready after clean skip: %w", err)
	}
	if err := requireOneRow(res2, "store: restore incident ready after clean skip", ErrNotFound); err != nil {
		return err
	}

	var groupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return fmt.Errorf("store: read incident group key for triage_skipped: %w", err)
	}
	idempotencyKey := "triage-skipped:" + attemptID
	if err := insertTriageSituationInputTx(ctx, tx, "triage_skipped", idempotencyKey, incidentID, groupKey, now); err != nil {
		return err
	}

	return tx.Commit()
}

// ----------------------------------------------------------------------
// RecoverExpiredIncidentTriageAttempts — startup/heartbeat-loss recovery
// over the new attempt ledger, mirroring RecoverInterruptedIncidentTriage's
// contract (ADR-0045: the interrupted attempt counts) for rows now carrying
// a fenced lease. Call before any worker resumes claiming, or periodically
// as a heartbeat-loss sweep; never concurrently with a live claim holder for
// the same row (the exact same operational contract
// RecoverInterruptedAssessmentCalls documents for its own table).
// ----------------------------------------------------------------------

type expiredTriageAttemptRow struct {
	incidentID, attemptID string
	attempts              int
	startedAt             time.Time
}

func listExpiredInFlightTriageTx(ctx context.Context, tx *sql.Tx, now time.Time) ([]expiredTriageAttemptRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT incident_id, current_attempt_id, attempts, started_at
		FROM incident_triage
		WHERE phase = 'in_flight' AND current_attempt_id IS NOT NULL
		  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
		ORDER BY started_at ASC`, canonicalTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: list expired in-flight incident triage: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []expiredTriageAttemptRow{}
	for rows.Next() {
		var r expiredTriageAttemptRow
		var startedAtStr sql.NullString
		if err := rows.Scan(&r.incidentID, &r.attemptID, &r.attempts, &startedAtStr); err != nil {
			return nil, fmt.Errorf("store: scan expired in-flight incident triage: %w", err)
		}
		if startedAtStr.Valid {
			if r.startedAt, err = time.Parse(time.RFC3339Nano, startedAtStr.String); err != nil {
				return nil, fmt.Errorf("store: parse expired in-flight started_at: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate expired in-flight incident triage: %w", err)
	}
	return out, nil
}

// RecoverExpiredIncidentTriageAttempts resolves every in_flight row whose
// lease has expired (or, for a migrated legacy row, carries no lease at
// all) — a process crash mid-attempt, or a heartbeat that stopped arriving.
// A row already at the five-attempt ceiling exhausts; otherwise it backs
// off, next due immediately (now), so a restart's own next tick can retry
// it without an extra artificial delay. Returns the number of rows
// recovered.
func (s *Store) RecoverExpiredIncidentTriageAttempts(ctx context.Context, now time.Time) (int, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin recover expired incident triage attempts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	expired, err := listExpiredInFlightTriageTx(ctx, tx, now)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit list expired incident triage attempts: %w", err)
	}

	const code = "process_interrupted"
	const detail = "attempt interrupted before completion or lease heartbeat lost"
	recovered := 0
	for _, r := range expired {
		var opErr error
		if r.attempts >= 5 {
			opErr = s.ExhaustIncidentTriageAttempt(ctx, r.attemptID, r.incidentID, code, detail, now)
		} else {
			opErr = s.BackoffIncidentTriageAttempt(ctx, r.attemptID, r.incidentID, now, code, detail, now)
		}
		switch {
		case opErr == nil:
			recovered++
		case errors.Is(opErr, ErrNotFound) || errors.Is(opErr, ErrTriageAttemptLeaseLost):
			// Already reconciled by another path between the listing read
			// above and this write (e.g. a genuinely completing worker) —
			// not a failure, just nothing left to do for this row.
		default:
			return recovered, opErr
		}
	}
	return recovered, nil
}

// ----------------------------------------------------------------------
// BackfillUpgradedIncidentTriageSchedule — startup-only upgrade backfill
// (migration 0016's own doc comment: "Task 6 startup backfills the owning
// Situation ID, current input version, and current membership digest onto
// retained schedulable rows... decision_origin is upgrade_existing_schedule;
// the controller does not retroactively revoke work that v0.13.6 had
// already authorized"). Call once, after Plan 1 reconstruction has
// established Situation ownership (situation_incidents), before any worker
// resumes claiming triage work — the same startup-only contract
// RecoverInterruptedAssessmentCalls and RecoverExpiredIncidentTriageAttempts
// both document for their own tables. Never wired into a production startup
// path by this task (Task 9 owns that per the Task 2 report's own
// correction); tested directly here.
// ----------------------------------------------------------------------

type upgradableTriageRow struct {
	incidentID string
}

func listUpgradableTriageRowsTx(ctx context.Context, tx *sql.Tx) ([]upgradableTriageRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT incident_id FROM incident_triage
		WHERE situation_id IS NULL AND phase IN ('pending','backoff','in_flight')
		ORDER BY incident_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list upgradable incident triage rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []upgradableTriageRow{}
	for rows.Next() {
		var r upgradableTriageRow
		if err := rows.Scan(&r.incidentID); err != nil {
			return nil, fmt.Errorf("store: scan upgradable incident triage row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate upgradable incident triage rows: %w", err)
	}
	return out, nil
}

// BackfillUpgradedIncidentTriageSchedule sets situation_id,
// decision_input_version, and membership_digest onto every retained
// schedulable incident_triage row (pending/backoff/in_flight) that has no
// situation_id yet, tagging decision_origin=upgrade_existing_schedule. It
// deliberately never sets decision/decision_reason/material_fact_hash/
// incident_input_digest/assessment_id/decided_at — those remain null for a
// retained upgraded row, matching the migration's own preserved-row example
// exactly. A row whose Incident has not yet been attached to any Situation
// (Plan 1 reconstruction has not reached it yet) is left untouched for a
// later pass; it is not an error. Returns the number of rows backfilled.
func (s *Store) BackfillUpgradedIncidentTriageSchedule(ctx context.Context, now time.Time) (int, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin backfill upgraded incident triage schedule: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := listUpgradableTriageRowsTx(ctx, tx)
	if err != nil {
		return 0, err
	}

	backfilled := 0
	for _, r := range rows {
		situationID, err := situationOwnerForIncidentTx(ctx, tx, r.incidentID)
		if err != nil {
			return backfilled, err
		}
		if situationID == "" {
			continue // no owning Situation yet; leave for a later pass
		}
		sit, err := getSituationTx(ctx, tx, situationID)
		if err != nil {
			return backfilled, err
		}
		membership, _, err := incidentDigestsTx(ctx, tx, r.incidentID)
		if err != nil {
			return backfilled, err
		}

		res, err := tx.ExecContext(ctx, `
			UPDATE incident_triage
			SET situation_id = ?, decision_input_version = ?, membership_digest = ?,
			    decision_origin = ?, updated_at = ?
			WHERE incident_id = ? AND situation_id IS NULL`,
			situationID, sit.InputVersion, membership, triageDecisionOriginUpgrade, canonicalTime(now), r.incidentID)
		if err != nil {
			return backfilled, fmt.Errorf("store: backfill incident triage schedule: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return backfilled, fmt.Errorf("store: count backfilled incident triage schedule: %w", err)
		}
		backfilled += int(n)
	}

	if err := tx.Commit(); err != nil {
		return backfilled, fmt.Errorf("store: commit backfill upgraded incident triage schedule: %w", err)
	}
	return backfilled, nil
}
