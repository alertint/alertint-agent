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

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 3: Situation controller persistence — immutable facts, immutable L2
// provider dispatch/outcome history, interrupted-call recovery, and the
// fenced CommitController transaction skeleton (Task 8 completes its
// decision/projection behavior).
// ----------------------------------------------------------------------

// ErrImmutableConflict means an idempotent bounded-append call
// (AppendSituationFacts, RecordAssessmentCall, AppendAssessmentOutcome)
// collided with an existing immutable row under the same identity but
// different content. Replaying byte-identical canonical content is a
// successful no-op; this error is reserved for a genuine content mismatch,
// which the store fails closed on — every table these methods write to
// rejects UPDATE via trigger, so there is no "keep the newer one" option.
var ErrImmutableConflict = errors.New("store: immutable record already exists with different content")

// verifyClaimTx confirms claim's (situation id, lease owner, claim token)
// triple still matches the Situation's current row — the same lease-fencing
// check ApplySituationInput/RetrySituationInput perform, reused here so
// AppendSituationFacts and RecordAssessmentCall fail closed
// (ErrSituationLeaseLost) the instant a newer Situation input has cleared
// the lease (joinSituationTx always clears lease_owner on every join,
// per situations.go) or a competing claim has advanced claim_token.
func verifyClaimTx(ctx context.Context, tx *sql.Tx, claim situation.Claim) error {
	var valid int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM situations WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.ErrSituationLeaseLost
	}
	if err != nil {
		return fmt.Errorf("store: verify situation claim: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// LoadReconciliationInput
// ----------------------------------------------------------------------

// LoadReconciliationInput reads one coherent snapshot of durable local truth
// for claim's Situation — its own current row, member Incidents' immutable
// deliveries, member Incidents' current Triage state, prior same-group
// terminal Situations, and the current authoritative Assessment (if any) —
// in a single read transaction. It performs no external I/O and takes now
// only to stamp SnapshotInput.Now; it never calls time.Now itself.
//
// This is a plain read: it does not verify claim's lease is still current.
// CommitController is the only method that fences a controller cycle's
// write; a read reflecting a claim that has since gone stale is harmless —
// Task 8's controller discovers staleness at commit time and discards the
// whole cycle's work, never partially applying it.
func (s *Store) LoadReconciliationInput(ctx context.Context, claim situation.Claim, now time.Time) (situation.SnapshotInput, error) {
	if strings.TrimSpace(claim.Situation.ID) == "" {
		return situation.SnapshotInput{}, errors.New("store: load reconciliation input requires a situation id")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return situation.SnapshotInput{}, fmt.Errorf("store: begin load reconciliation input: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	sit, err := getSituationTx(ctx, tx, claim.Situation.ID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}

	deliveries, err := loadSituationDeliveriesTx(ctx, tx, sit.ID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}

	incidents, err := loadSituationIncidentStatesTx(ctx, tx, sit.ID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}

	prior, err := loadPriorTerminalSituationsTx(ctx, tx, sit.GroupKey, sit.ID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}

	current, err := loadCurrentAssessmentTx(ctx, tx, sit.ID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}

	if err := tx.Commit(); err != nil {
		return situation.SnapshotInput{}, fmt.Errorf("store: commit load reconciliation input: %w", err)
	}

	return situation.SnapshotInput{
		Situation:         sit,
		Deliveries:        deliveries,
		Incidents:         incidents,
		PriorSituations:   prior,
		CurrentAssessment: current,
		Now:               now.UTC(),
	}, nil
}

// loadSituationDeliveriesTx reads every immutable delivery belonging to any
// current member Incident of situationID, across the whole Situation (not
// grouped) — callers group by Delivery.IncidentID themselves. It also reads
// the delivery's immutable alert_id FK straight into Delivery.AlertID, and
// parses its immutable labels_json to extract two narrow, durable-per-
// delivery values: the raw severity label (Delivery.Severity — ranking it
// is internal/situation's job via internal/severity.Rank, not this store
// layer's) and whether the Drill marker
// (store.DrillMarkerLabel=store.DrillMarkerValue) is set (Delivery.Drill).
func loadSituationDeliveriesTx(ctx context.Context, tx *sql.Tx, situationID string) ([]situation.Delivery, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT ad.id, iad.incident_id, ad.alert_id, ad.status, ad.payload_digest,
		       ad.source_started_at, ad.started_at_basis, ad.source_resolved_at, ad.resolved_at_basis, ad.received_at,
		       ad.labels_json
		FROM situation_incidents si
		JOIN incident_alert_deliveries iad ON iad.incident_id = si.incident_id
		JOIN alert_deliveries ad ON ad.id = iad.delivery_id
		WHERE si.situation_id = ?
		ORDER BY ad.received_at ASC, ad.id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: load situation deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situation.Delivery{}
	for rows.Next() {
		var d situation.Delivery
		var status, startedBasis, resolvedBasis, receivedAtStr, labelsJSON string
		var sourceStarted, sourceResolved sql.NullString
		if err := rows.Scan(&d.ID, &d.IncidentID, &d.AlertID, &status, &d.PayloadDigest,
			&sourceStarted, &startedBasis, &sourceResolved, &resolvedBasis, &receivedAtStr, &labelsJSON); err != nil {
			return nil, fmt.Errorf("store: scan situation delivery: %w", err)
		}
		d.Status = situationmodel.DeliveryStatus(status)
		d.StartedAtBasis = situationmodel.SourceTimeBasis(startedBasis)
		d.ResolvedAtBasis = situationmodel.SourceTimeBasis(resolvedBasis)
		started, err := timePtr(sourceStarted)
		if err != nil {
			return nil, err
		}
		d.SourceStartedAt = started
		resolved, err := timePtr(sourceResolved)
		if err != nil {
			return nil, err
		}
		d.SourceResolvedAt = resolved
		if d.ReceivedAt, err = time.Parse(time.RFC3339Nano, receivedAtStr); err != nil {
			return nil, fmt.Errorf("store: parse situation delivery received_at: %w", err)
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			// Defensive only: labels_json carries a CHECK (json_valid(...))
			// constraint, so a real row should never fail to unmarshal as an
			// object. Fail closed rather than panic on a scan/decode edge
			// case, matching this function's existing error-handling style.
			return nil, fmt.Errorf("store: unmarshal situation delivery %s labels: %w", d.ID, err)
		}
		d.Severity = labels["severity"]
		d.Drill = labels[DrillMarkerLabel] == DrillMarkerValue
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation deliveries: %w", err)
	}
	return out, nil
}

// loadSituationIncidentStatesTx reads every current member Incident of
// situationID plus its current incident_triage row (LEFT JOIN: an Incident
// that has never reached "ready" has none — TriageState.Phase stays "").
func loadSituationIncidentStatesTx(ctx context.Context, tx *sql.Tx, situationID string) ([]situation.IncidentState, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT i.id, i.group_key, i.status, i.first_alert_at, i.last_alert_at, i.ready_at, i.alert_count,
		       COALESCE(t.phase, ''), COALESCE(t.attempts, 0), t.next_at,
		       t.decision, t.decision_reason, t.decision_input_version,
		       t.material_fact_hash, t.membership_digest, t.incident_input_digest,
		       t.assessment_id, t.decided_at
		FROM situation_incidents si
		JOIN incidents i ON i.id = si.incident_id
		LEFT JOIN incident_triage t ON t.incident_id = i.id
		WHERE si.situation_id = ?
		ORDER BY si.attached_at ASC, i.id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: load situation incident states: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situation.IncidentState{}
	for rows.Next() {
		var st situation.IncidentState
		var firstStr, lastStr, readyStr string
		var nextAt, decision, decisionReason, materialHash, membershipDigest, incidentInputDigest, assessmentID, decidedAt sql.NullString
		var decisionInputVersion sql.NullInt64
		if err := rows.Scan(&st.ID, &st.GroupKey, &st.Status, &firstStr, &lastStr, &readyStr, &st.AlertCount,
			&st.Triage.Phase, &st.Triage.Attempts, &nextAt,
			&decision, &decisionReason, &decisionInputVersion,
			&materialHash, &membershipDigest, &incidentInputDigest,
			&assessmentID, &decidedAt); err != nil {
			return nil, fmt.Errorf("store: scan situation incident state: %w", err)
		}

		var err error
		if st.FirstAlertAt, err = time.Parse(time.RFC3339Nano, firstStr); err != nil {
			return nil, fmt.Errorf("store: parse incident first_alert_at: %w", err)
		}
		if st.LastAlertAt, err = time.Parse(time.RFC3339Nano, lastStr); err != nil {
			return nil, fmt.Errorf("store: parse incident last_alert_at: %w", err)
		}
		if st.ReadyAt, err = time.Parse(time.RFC3339Nano, readyStr); err != nil {
			return nil, fmt.Errorf("store: parse incident ready_at: %w", err)
		}
		if st.Triage.NextAt, err = timePtr(nextAt); err != nil {
			return nil, err
		}
		if st.Triage.DecidedAt, err = timePtr(decidedAt); err != nil {
			return nil, err
		}
		st.Triage.Decision = stringPtr(decision)
		st.Triage.DecisionReason = stringPtr(decisionReason)
		st.Triage.MaterialFactHash = stringPtr(materialHash)
		st.Triage.MembershipDigest = stringPtr(membershipDigest)
		st.Triage.IncidentInputDigest = stringPtr(incidentInputDigest)
		st.Triage.AssessmentID = stringPtr(assessmentID)
		if decisionInputVersion.Valid {
			v := int(decisionInputVersion.Int64)
			st.Triage.DecisionInputVersion = &v
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation incident states: %w", err)
	}
	return out, nil
}

// loadPriorTerminalSituationsTx reads every terminal ("recovered" or
// "closed_unknown") Situation sharing groupKey, other than excludeID,
// ordered chronologically — the same exact-group lineage
// newestTerminalSituationIDTx already draws on for previous_situation_id
// linkage, but every prior terminal member rather than just the newest one.
func loadPriorTerminalSituationsTx(ctx context.Context, tx *sql.Tx, groupKey, excludeID string) ([]situation.CompletedSituation, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, group_key, effective_started_at, terminal_at, terminal_reason
		FROM situations
		WHERE group_key = ? AND id != ? AND lifecycle IN ('recovered','closed_unknown')
		ORDER BY terminal_at ASC, id ASC`, groupKey, excludeID)
	if err != nil {
		return nil, fmt.Errorf("store: load prior terminal situations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situation.CompletedSituation{}
	for rows.Next() {
		var cs situation.CompletedSituation
		var startedStr string
		var terminalAt, terminalReason sql.NullString
		if err := rows.Scan(&cs.ID, &cs.GroupKey, &startedStr, &terminalAt, &terminalReason); err != nil {
			return nil, fmt.Errorf("store: scan prior terminal situation: %w", err)
		}
		var err error
		if cs.EffectiveStartedAt, err = time.Parse(time.RFC3339Nano, startedStr); err != nil {
			return nil, fmt.Errorf("store: parse prior situation effective_started_at: %w", err)
		}
		if terminalAt.Valid {
			if cs.TerminalAt, err = time.Parse(time.RFC3339Nano, terminalAt.String); err != nil {
				return nil, fmt.Errorf("store: parse prior situation terminal_at: %w", err)
			}
		}
		if terminalReason.Valid {
			cs.TerminalReason = situationmodel.TerminalReason(terminalReason.String)
		}
		out = append(out, cs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate prior terminal situations: %w", err)
	}
	return out, nil
}

// loadCurrentAssessmentTx reads situationID's current_assessment_id pointer
// and, when set, the full authoritative attempt (and its coverage tuples)
// it names. Returns (nil, nil) when the Situation has no current Assessment
// yet.
func loadCurrentAssessmentTx(ctx context.Context, tx *sql.Tx, situationID string) (*situation.AuthoritativeAssessment, error) {
	var attemptID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT current_assessment_id FROM situations WHERE id = ?`, situationID).Scan(&attemptID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: read current assessment pointer: %w", err)
	}
	if !attemptID.Valid {
		return nil, nil //nolint:nilnil // no current Assessment yet is a legitimate, common outcome, not an error
	}
	return loadAuthoritativeAssessmentTx(ctx, tx, attemptID.String)
}

// loadAuthoritativeAssessmentTx reads one authoritative attempt's full
// content plus its bounded per-Incident coverage tuples. It returns an error
// if attemptID does not name a status='authoritative' row — the guard
// trigger on situations.current_assessment_id already guarantees this can't
// happen for a value read straight off that column, but this function is
// also the natural building block for the future LastTrustworthyAssessment.
func loadAuthoritativeAssessmentTx(ctx context.Context, tx *sql.Tx, attemptID string) (*situation.AuthoritativeAssessment, error) {
	var a situation.AuthoritativeAssessment
	var basisHash sql.NullString
	var derivation, assessmentJSON string
	var reusedFrom sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT situation_id, input_version, assessment_basis_hash, material_fact_hash, derivation, assessment_json, reused_from_assessment_id
		FROM situation_assessment_attempts WHERE id = ? AND status = 'authoritative'`, attemptID).
		Scan(&a.SituationID, &a.InputVersion, &basisHash, &a.MaterialFactHash, &derivation, &assessmentJSON, &reusedFrom)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: authoritative assessment %s: %w", attemptID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: read authoritative assessment: %w", err)
	}
	a.ID = attemptID
	if basisHash.Valid {
		a.AssessmentBasisHash = basisHash.String
	}
	a.Derivation = situationmodel.AssessmentDerivation(derivation)
	a.ReusedFromAssessmentID = stringPtr(reusedFrom)
	if err := json.Unmarshal([]byte(assessmentJSON), &a.Assessment); err != nil {
		return nil, fmt.Errorf("store: unmarshal authoritative assessment content: %w", err)
	}

	coverage, err := loadAssessmentCoverageTx(ctx, tx, attemptID)
	if err != nil {
		return nil, err
	}
	a.Coverage = coverage
	return &a, nil
}

func loadAssessmentCoverageTx(ctx context.Context, tx *sql.Tx, attemptID string) ([]situationmodel.IncidentCoverage, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT incident_id, membership_digest, incident_input_digest
		FROM situation_assessment_coverage WHERE assessment_attempt_id = ? ORDER BY incident_id ASC`, attemptID)
	if err != nil {
		return nil, fmt.Errorf("store: load assessment coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situationmodel.IncidentCoverage{}
	for rows.Next() {
		var c situationmodel.IncidentCoverage
		if err := rows.Scan(&c.IncidentID, &c.MembershipDigest, &c.IncidentInputDigest); err != nil {
			return nil, fmt.Errorf("store: scan assessment coverage: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate assessment coverage: %w", err)
	}
	return out, nil
}

// ----------------------------------------------------------------------
// AppendSituationFacts — the canonical bounded fact-append method.
// ----------------------------------------------------------------------

// AppendSituationFacts idempotently appends facts to situation_facts, fenced
// on claim's current lease. Each fact is inserted with ON CONFLICT(id) DO
// NOTHING; when a row with that id already exists, its content is compared
// field-for-field against the incoming fact — an exact match is a
// successful no-op (idempotent replay), any mismatch fails closed with
// ErrImmutableConflict (situation_facts rows are immutable — UPDATE is
// trigger-rejected, so there is no way to "correct" a wrong row after the
// fact). An empty facts slice is a successful no-op.
func (s *Store) AppendSituationFacts(ctx context.Context, claim situation.Claim, facts []situationmodel.Fact) error {
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: append situation facts requires a complete claim")
	}
	if len(facts) == 0 {
		return nil
	}
	prepared := make([]preparedFact, len(facts))
	for i, f := range facts {
		if f.SituationID != claim.Situation.ID {
			return fmt.Errorf("store: situation fact %s situation %s does not match claim situation %s", f.ID, f.SituationID, claim.Situation.ID)
		}
		p, err := prepareFact(f)
		if err != nil {
			return err
		}
		prepared[i] = p
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin append situation facts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyClaimTx(ctx, tx, claim); err != nil {
		return err
	}
	for _, p := range prepared {
		if err := appendFactTx(ctx, tx, p); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type preparedFact struct {
	f                situationmodel.Fact
	valueJSON        string
	evidenceRefsJSON string
	observedAt       string
	material         int
}

func prepareFact(f situationmodel.Fact) (preparedFact, error) {
	if strings.TrimSpace(f.ID) == "" {
		return preparedFact{}, errors.New("store: situation fact id is required")
	}
	if strings.TrimSpace(f.SituationID) == "" {
		return preparedFact{}, fmt.Errorf("store: situation fact %s situation id is required", f.ID)
	}
	if f.InputVersion < 1 {
		return preparedFact{}, fmt.Errorf("store: situation fact %s input version must be >= 1", f.ID)
	}
	if strings.TrimSpace(f.Kind) == "" {
		return preparedFact{}, fmt.Errorf("store: situation fact %s kind is required", f.ID)
	}
	if strings.TrimSpace(f.Subject) == "" {
		return preparedFact{}, fmt.Errorf("store: situation fact %s subject is required", f.ID)
	}
	if strings.TrimSpace(f.Digest) == "" {
		return preparedFact{}, fmt.Errorf("store: situation fact %s digest is required", f.ID)
	}
	if len(f.Value) == 0 || !json.Valid(f.Value) {
		return preparedFact{}, fmt.Errorf("store: situation fact %s value must be valid non-empty JSON", f.ID)
	}
	if err := f.ResultStatus.Validate(); err != nil {
		return preparedFact{}, fmt.Errorf("store: situation fact %s: %w", f.ID, err)
	}
	if f.ObservedAt.IsZero() {
		return preparedFact{}, fmt.Errorf("store: situation fact %s observed_at is required", f.ID)
	}

	refs := f.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return preparedFact{}, fmt.Errorf("store: marshal situation fact %s evidence refs: %w", f.ID, err)
	}

	material := 0
	if f.Material {
		material = 1
	}
	return preparedFact{
		f:                f,
		valueJSON:        string(f.Value),
		evidenceRefsJSON: string(refsJSON),
		observedAt:       canonicalTime(f.ObservedAt),
		material:         material,
	}, nil
}

func appendFactTx(ctx context.Context, tx *sql.Tx, p preparedFact) error {
	res, err := tx.ExecContext(ctx, `
		INSERT INTO situation_facts (id, situation_id, input_version, kind, subject, digest, value_json, result_status, evidence_refs_json, material, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		p.f.ID, p.f.SituationID, p.f.InputVersion, p.f.Kind, p.f.Subject, p.f.Digest,
		p.valueJSON, string(p.f.ResultStatus), p.evidenceRefsJSON, p.material, p.observedAt)
	if err != nil {
		return fmt.Errorf("store: insert situation fact %s: %w", p.f.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count inserted situation fact %s: %w", p.f.ID, err)
	}
	if n == 1 {
		return nil
	}

	var situationID, kind, subject, digest, valueJSON, resultStatus, evidenceRefsJSON, observedAt string
	var inputVersion, material int
	err = tx.QueryRowContext(ctx, `
		SELECT situation_id, input_version, kind, subject, digest, value_json, result_status, evidence_refs_json, material, observed_at
		FROM situation_facts WHERE id = ?`, p.f.ID).Scan(
		&situationID, &inputVersion, &kind, &subject, &digest, &valueJSON, &resultStatus, &evidenceRefsJSON, &material, &observedAt)
	if err != nil {
		return fmt.Errorf("store: read existing situation fact %s: %w", p.f.ID, err)
	}
	if situationID != p.f.SituationID || inputVersion != p.f.InputVersion || kind != p.f.Kind || subject != p.f.Subject ||
		digest != p.f.Digest || valueJSON != p.valueJSON || resultStatus != string(p.f.ResultStatus) ||
		evidenceRefsJSON != p.evidenceRefsJSON || material != p.material || observedAt != p.observedAt {
		return fmt.Errorf("store: situation fact %s: %w", p.f.ID, ErrImmutableConflict)
	}
	return nil
}

// ----------------------------------------------------------------------
// RecordAssessmentCall — the canonical dispatch-append method.
// ----------------------------------------------------------------------

// RecordAssessmentCall idempotently appends one immutable L2 provider
// dispatch row to situation_assessment_calls, fenced on claim's current
// lease. This must commit before the physical HTTP request it records is
// made (spec: "A provider call is consumed when its immutable dispatch row
// commits, before I/O") — the caller, not this method, is responsible for
// calling it first. The idempotent-append pattern matches
// AppendSituationFacts exactly.
func (s *Store) RecordAssessmentCall(ctx context.Context, claim situation.Claim, call situation.AssessmentCall) error {
	if err := validateAssessmentCall(call); err != nil {
		return err
	}
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: record assessment call requires a complete claim")
	}
	if call.SituationID != claim.Situation.ID {
		return fmt.Errorf("store: assessment call situation %s does not match claim situation %s", call.SituationID, claim.Situation.ID)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin record assessment call: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyClaimTx(ctx, tx, claim); err != nil {
		return err
	}
	if err := insertAssessmentCallTx(ctx, tx, call); err != nil {
		return err
	}
	return tx.Commit()
}

func validateAssessmentCall(call situation.AssessmentCall) error {
	if strings.TrimSpace(call.ID) == "" {
		return errors.New("store: assessment call id is required")
	}
	if strings.TrimSpace(call.SituationID) == "" {
		return fmt.Errorf("store: assessment call %s situation id is required", call.ID)
	}
	if strings.TrimSpace(call.MaterialFactHash) == "" {
		return fmt.Errorf("store: assessment call %s material fact hash is required", call.ID)
	}
	if call.InputVersion < 1 {
		return fmt.Errorf("store: assessment call %s input version must be >= 1", call.ID)
	}
	if call.RetryEpoch < 0 {
		return fmt.Errorf("store: assessment call %s retry epoch must be >= 0", call.ID)
	}
	if call.WorkAttempt < 1 || call.WorkAttempt > 5 {
		return fmt.Errorf("store: assessment call %s work attempt must be in [1,5]", call.ID)
	}
	if call.CallNumber != 1 && call.CallNumber != 2 {
		return fmt.Errorf("store: assessment call %s call number must be 1 or 2", call.ID)
	}
	if call.DispatchedAt.IsZero() {
		return fmt.Errorf("store: assessment call %s dispatched_at is required", call.ID)
	}
	return nil
}

func insertAssessmentCallTx(ctx context.Context, tx *sql.Tx, call situation.AssessmentCall) error {
	dispatchedAt := canonicalTime(call.DispatchedAt)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO situation_assessment_calls (id, situation_id, input_version, retry_epoch, work_attempt, call_number, material_fact_hash, provider_profile, dispatched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		call.ID, call.SituationID, call.InputVersion, call.RetryEpoch, call.WorkAttempt, call.CallNumber,
		call.MaterialFactHash, nullableString(call.ProviderProfile), dispatchedAt)
	if err != nil {
		return fmt.Errorf("store: insert assessment call %s: %w", call.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count inserted assessment call %s: %w", call.ID, err)
	}
	if n == 1 {
		return nil
	}

	var situationID, materialFactHash, dispatchedAtGot string
	var inputVersion, retryEpoch, workAttempt, callNumber int
	var providerProfile sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT situation_id, input_version, retry_epoch, work_attempt, call_number, material_fact_hash, provider_profile, dispatched_at
		FROM situation_assessment_calls WHERE id = ?`, call.ID).Scan(
		&situationID, &inputVersion, &retryEpoch, &workAttempt, &callNumber, &materialFactHash, &providerProfile, &dispatchedAtGot)
	if err != nil {
		return fmt.Errorf("store: read existing assessment call %s: %w", call.ID, err)
	}
	gotProfile, wantProfile := "", ""
	if providerProfile.Valid {
		gotProfile = providerProfile.String
	}
	if call.ProviderProfile != nil {
		wantProfile = *call.ProviderProfile
	}
	if situationID != call.SituationID || inputVersion != call.InputVersion || retryEpoch != call.RetryEpoch ||
		workAttempt != call.WorkAttempt || callNumber != call.CallNumber || materialFactHash != call.MaterialFactHash ||
		gotProfile != wantProfile || dispatchedAtGot != dispatchedAt {
		return fmt.Errorf("store: assessment call %s: %w", call.ID, ErrImmutableConflict)
	}
	return nil
}

// ----------------------------------------------------------------------
// AppendAssessmentOutcome — non-authoritative call-backed outcome history.
// ----------------------------------------------------------------------

// AppendAssessmentOutcome idempotently appends one non-authoritative
// (rejected, failed, or stale) call-backed Assessment outcome. Unlike
// AppendSituationFacts/RecordAssessmentCall, it takes no Claim and never
// checks the current Situation lease: a rejected/failed/stale outcome must
// still append after the claim/input that dispatched its call has gone
// obsolete, as long as it exactly matches its immutable dispatch row
// (situation/input/retry-epoch/work-attempt identity). Authoritative rows
// (model_validated, deterministic_controller, deterministic_fallback,
// revalidated_reuse) are inserted only by fenced CommitController — this
// method rejects a status='authoritative' attempt outright.
func (s *Store) AppendAssessmentOutcome(ctx context.Context, attempt situation.AssessmentAttempt) error {
	if err := validateNonAuthoritativeAttempt(attempt); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin append assessment outcome: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := appendAssessmentOutcomeTx(ctx, tx, attempt); err != nil {
		return err
	}
	return tx.Commit()
}

func validateNonAuthoritativeAttempt(attempt situation.AssessmentAttempt) error {
	if strings.TrimSpace(attempt.ID) == "" {
		return errors.New("store: assessment outcome id is required")
	}
	if strings.TrimSpace(attempt.SituationID) == "" {
		return fmt.Errorf("store: assessment outcome %s situation id is required", attempt.ID)
	}
	if attempt.CallID == nil || strings.TrimSpace(*attempt.CallID) == "" {
		return fmt.Errorf("store: assessment outcome %s requires a linked dispatch call id", attempt.ID)
	}
	switch attempt.Status {
	case "rejected", "failed", "stale":
	case "authoritative":
		return fmt.Errorf("store: assessment outcome %s: authoritative attempts are inserted only by CommitController", attempt.ID)
	default:
		return fmt.Errorf("store: assessment outcome %s: status %q must be rejected, failed, or stale", attempt.ID, attempt.Status)
	}
	if attempt.Derivation != "" {
		return fmt.Errorf("store: assessment outcome %s must not carry a derivation (authoritative-only field)", attempt.ID)
	}
	if attempt.ProviderRequestStarted == nil {
		return fmt.Errorf("store: assessment outcome %s requires provider_request_started", attempt.ID)
	}
	if err := attempt.ProviderRequestStarted.Validate(); err != nil {
		return fmt.Errorf("store: assessment outcome %s: %w", attempt.ID, err)
	}
	if attempt.InputVersion < 1 {
		return fmt.Errorf("store: assessment outcome %s input version must be >= 1", attempt.ID)
	}
	if attempt.RetryEpoch < 0 {
		return fmt.Errorf("store: assessment outcome %s retry epoch must be >= 0", attempt.ID)
	}
	if attempt.WorkAttempt < 1 || attempt.WorkAttempt > 5 {
		return fmt.Errorf("store: assessment outcome %s work attempt must be in [1,5]", attempt.ID)
	}
	if attempt.Sequence < 1 {
		return fmt.Errorf("store: assessment outcome %s sequence must be >= 1", attempt.ID)
	}
	if attempt.CreatedAt.IsZero() || attempt.CompletedAt.IsZero() {
		return fmt.Errorf("store: assessment outcome %s requires created_at and completed_at", attempt.ID)
	}
	if attempt.ReusedFromAssessmentID != nil {
		return fmt.Errorf("store: assessment outcome %s must not carry reused_from_assessment_id (authoritative-only field)", attempt.ID)
	}
	return nil
}

// assessmentCallRecord is the subset of an immutable situation_assessment_calls
// row appendAssessmentOutcomeTx needs to validate and derive an outcome's
// material_fact_hash from.
type assessmentCallRecord struct {
	SituationID                                       string
	MaterialFactHash                                  string
	InputVersion, RetryEpoch, WorkAttempt, CallNumber int
}

func readAssessmentCallTx(ctx context.Context, tx *sql.Tx, id string) (assessmentCallRecord, error) {
	var r assessmentCallRecord
	err := tx.QueryRowContext(ctx, `
		SELECT situation_id, input_version, retry_epoch, work_attempt, call_number, material_fact_hash
		FROM situation_assessment_calls WHERE id = ?`, id).Scan(
		&r.SituationID, &r.InputVersion, &r.RetryEpoch, &r.WorkAttempt, &r.CallNumber, &r.MaterialFactHash)
	if errors.Is(err, sql.ErrNoRows) {
		return assessmentCallRecord{}, fmt.Errorf("store: assessment call %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return assessmentCallRecord{}, fmt.Errorf("store: read assessment call %s: %w", id, err)
	}
	return r, nil
}

// appendAssessmentOutcomeTx validates attempt against its linked immutable
// dispatch call — situation/input-version/retry-epoch/work-attempt identity
// must match exactly — derives material_fact_hash from that call (the
// outcome's "basis" linkage: situation_assessment_calls has no
// assessment_basis_hash column of its own, only material_fact_hash; see
// AssessmentCall's doc comment), and idempotently inserts the bounded
// outcome row. Shared by AppendAssessmentOutcome and
// RecoverInterruptedAssessmentCalls.
func appendAssessmentOutcomeTx(ctx context.Context, tx *sql.Tx, attempt situation.AssessmentAttempt) error {
	call, err := readAssessmentCallTx(ctx, tx, *attempt.CallID)
	if err != nil {
		return err
	}
	if call.SituationID != attempt.SituationID || call.InputVersion != attempt.InputVersion ||
		call.RetryEpoch != attempt.RetryEpoch || call.WorkAttempt != attempt.WorkAttempt {
		return fmt.Errorf("store: assessment outcome %s does not match dispatched call %s identity", attempt.ID, *attempt.CallID)
	}

	p, err := prepareAssessmentAttempt(attempt, call.MaterialFactHash)
	if err != nil {
		return err
	}
	return insertAssessmentAttemptTx(ctx, tx, p)
}

// preparedAttempt holds one validated, normalized AssessmentAttempt plus the
// exact SQL argument encodings insertAssessmentAttemptTx writes.
type preparedAttempt struct {
	a                    situation.AssessmentAttempt
	materialFactHash     string
	assessmentBasisHash  sql.NullString
	callID               sql.NullString
	derivation           sql.NullString
	proposalJSON         sql.NullString
	validationErrorsJSON string
	assessmentJSON       sql.NullString
	reusedFrom           sql.NullString
	usageInputTokens     sql.NullInt64
	usageOutputTokens    sql.NullInt64
	createdAt            string
	completedAt          string
}

func prepareAssessmentAttempt(a situation.AssessmentAttempt, materialFactHash string) (preparedAttempt, error) {
	if a.ProviderRequestStarted == nil {
		return preparedAttempt{}, fmt.Errorf("store: assessment attempt %s requires provider_request_started", a.ID)
	}
	p := preparedAttempt{
		a:                a,
		materialFactHash: materialFactHash,
		createdAt:        canonicalTime(a.CreatedAt),
		completedAt:      canonicalTime(a.CompletedAt),
	}
	if a.CallID != nil {
		p.callID = sql.NullString{String: *a.CallID, Valid: true}
	}
	if a.AssessmentBasisHash != "" {
		p.assessmentBasisHash = sql.NullString{String: a.AssessmentBasisHash, Valid: true}
	}
	if a.Derivation != "" {
		p.derivation = sql.NullString{String: string(a.Derivation), Valid: true}
	}
	if a.ReusedFromAssessmentID != nil {
		p.reusedFrom = sql.NullString{String: *a.ReusedFromAssessmentID, Valid: true}
	}
	if len(a.Proposal) > 0 {
		if !json.Valid(a.Proposal) {
			return preparedAttempt{}, fmt.Errorf("store: assessment attempt %s proposal must be valid JSON", a.ID)
		}
		p.proposalJSON = sql.NullString{String: string(a.Proposal), Valid: true}
	}
	if len(a.Validated) > 0 {
		if !json.Valid(a.Validated) {
			return preparedAttempt{}, fmt.Errorf("store: assessment attempt %s validated content must be valid JSON", a.ID)
		}
		p.assessmentJSON = sql.NullString{String: string(a.Validated), Valid: true}
	}
	errs := a.ValidationErrors
	if len(errs) == 0 {
		errs = json.RawMessage("[]")
	}
	if !json.Valid(errs) {
		return preparedAttempt{}, fmt.Errorf("store: assessment attempt %s validation errors must be valid JSON", a.ID)
	}
	p.validationErrorsJSON = string(errs)
	if a.UsageInputTokens != nil {
		p.usageInputTokens = sql.NullInt64{Int64: int64(*a.UsageInputTokens), Valid: true}
	}
	if a.UsageOutputTokens != nil {
		p.usageOutputTokens = sql.NullInt64{Int64: int64(*a.UsageOutputTokens), Valid: true}
	}
	return p, nil
}

func insertAssessmentAttemptTx(ctx context.Context, tx *sql.Tx, p preparedAttempt) error {
	res, err := tx.ExecContext(ctx, `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, retry_epoch, work_attempt, call_id,
			status, derivation, provider_request_started, material_fact_hash, assessment_basis_hash,
			proposal_json, validation_errors_json, assessment_json, reused_from_assessment_id,
			usage_input_tokens, usage_output_tokens, created_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		p.a.ID, p.a.SituationID, p.a.Sequence, p.a.InputVersion, p.a.RetryEpoch, p.a.WorkAttempt, p.callID,
		p.a.Status, p.derivation, string(*p.a.ProviderRequestStarted), p.materialFactHash, p.assessmentBasisHash,
		p.proposalJSON, p.validationErrorsJSON, p.assessmentJSON, p.reusedFrom,
		p.usageInputTokens, p.usageOutputTokens, p.createdAt, p.completedAt)
	if err != nil {
		return fmt.Errorf("store: insert assessment attempt %s: %w", p.a.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count inserted assessment attempt %s: %w", p.a.ID, err)
	}
	if n == 1 {
		return nil
	}

	var got preparedAttempt
	got.a.ID = p.a.ID
	var providerStarted string
	err = tx.QueryRowContext(ctx, `
		SELECT situation_id, sequence, input_version, retry_epoch, work_attempt, call_id,
		       status, derivation, provider_request_started, material_fact_hash, assessment_basis_hash,
		       proposal_json, validation_errors_json, assessment_json, reused_from_assessment_id,
		       usage_input_tokens, usage_output_tokens, created_at, completed_at
		FROM situation_assessment_attempts WHERE id = ?`, p.a.ID).Scan(
		&got.a.SituationID, &got.a.Sequence, &got.a.InputVersion, &got.a.RetryEpoch, &got.a.WorkAttempt, &got.callID,
		&got.a.Status, &got.derivation, &providerStarted, &got.materialFactHash, &got.assessmentBasisHash,
		&got.proposalJSON, &got.validationErrorsJSON, &got.assessmentJSON, &got.reusedFrom,
		&got.usageInputTokens, &got.usageOutputTokens, &got.createdAt, &got.completedAt)
	if err != nil {
		return fmt.Errorf("store: read existing assessment attempt %s: %w", p.a.ID, err)
	}

	if got.a.SituationID != p.a.SituationID || got.a.Sequence != p.a.Sequence || got.a.InputVersion != p.a.InputVersion ||
		got.a.RetryEpoch != p.a.RetryEpoch || got.a.WorkAttempt != p.a.WorkAttempt || got.callID != p.callID ||
		got.a.Status != p.a.Status || got.derivation != p.derivation || providerStarted != string(*p.a.ProviderRequestStarted) ||
		got.materialFactHash != p.materialFactHash || got.assessmentBasisHash != p.assessmentBasisHash ||
		got.proposalJSON != p.proposalJSON || got.validationErrorsJSON != p.validationErrorsJSON ||
		got.assessmentJSON != p.assessmentJSON || got.reusedFrom != p.reusedFrom ||
		got.usageInputTokens != p.usageInputTokens || got.usageOutputTokens != p.usageOutputTokens ||
		got.createdAt != p.createdAt || got.completedAt != p.completedAt {
		return fmt.Errorf("store: assessment attempt %s: %w", p.a.ID, ErrImmutableConflict)
	}
	return nil
}

// ----------------------------------------------------------------------
// Interrupted-call recovery.
// ----------------------------------------------------------------------

// RecoverInterruptedAssessmentCalls turns every outcome-less L2 dispatch
// whose owning Situation is not currently under an active claim (lease_owner
// is NULL, or its lease has expired) into one immutable "process_interrupted"
// failed attempt with provider_request_started="unknown" — the call slot was
// already durably consumed before I/O (spec: "the slot is never refunded"),
// so this never re-dispatches it — and merges retry_due into that
// Situation's due reasons so a controller cycle picks the input back up.
//
// Like RecoverExpiredFoundationLeases and ListInterruptedIncidentTriage,
// this is a startup-only primitive: call it once, before any worker resumes
// ClaimDueSituations, never concurrently with live controller work — a call
// dispatched under a claim that is still actively held (fresh, unexpired
// lease) is correctly left untouched, and calling this while a live
// controller holds such a lease could, in principle, race with it.
func (s *Store) RecoverInterruptedAssessmentCalls(ctx context.Context, now time.Time) (int, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin recover interrupted assessment calls: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	orphaned, err := loadOrphanedAssessmentCallsTx(ctx, tx, now)
	if err != nil {
		return 0, err
	}
	if len(orphaned) == 0 {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("store: commit empty interrupted assessment call recovery: %w", err)
		}
		return 0, nil
	}

	touched := map[string]bool{}
	for _, call := range orphaned {
		seq, err := nextAssessmentAttemptSequenceTx(ctx, tx, call.SituationID)
		if err != nil {
			return 0, err
		}
		callID := call.ID
		started := situationmodel.ProviderRequestStartedUnknown
		attempt := situation.AssessmentAttempt{
			ID:                     uuid.NewString(),
			SituationID:            call.SituationID,
			CallID:                 &callID,
			InputVersion:           call.InputVersion,
			RetryEpoch:             call.RetryEpoch,
			WorkAttempt:            call.WorkAttempt,
			Sequence:               seq,
			Status:                 "failed",
			ValidationErrors:       json.RawMessage(`["process_interrupted"]`),
			ProviderRequestStarted: &started,
			CreatedAt:              call.DispatchedAt,
			CompletedAt:            now,
		}
		if err := appendAssessmentOutcomeTx(ctx, tx, attempt); err != nil {
			return 0, err
		}
		touched[call.SituationID] = true
	}

	for situationID := range touched {
		if err := mergeSituationDueReasonTx(ctx, tx, situationID, situationmodel.DueRetry, now); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit recover interrupted assessment calls: %w", err)
	}
	return len(orphaned), nil
}

type orphanedAssessmentCall struct {
	ID, SituationID string
	InputVersion    int
	RetryEpoch      int
	WorkAttempt     int
	DispatchedAt    time.Time
}

// loadOrphanedAssessmentCallsTx finds every dispatched call with no recorded
// outcome (no situation_assessment_attempts row referencing it via call_id)
// whose owning Situation is not currently under an active claim.
func loadOrphanedAssessmentCallsTx(ctx context.Context, tx *sql.Tx, now time.Time) ([]orphanedAssessmentCall, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.situation_id, c.input_version, c.retry_epoch, c.work_attempt, c.dispatched_at
		FROM situation_assessment_calls c
		JOIN situations s ON s.id = c.situation_id
		WHERE (s.lease_owner IS NULL OR s.lease_expires_at <= ?)
		  AND NOT EXISTS (SELECT 1 FROM situation_assessment_attempts a WHERE a.call_id = c.id)
		ORDER BY c.dispatched_at ASC, c.id ASC`, canonicalTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: load orphaned assessment calls: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orphanedAssessmentCall{}
	for rows.Next() {
		var c orphanedAssessmentCall
		var dispatchedAtStr string
		if err := rows.Scan(&c.ID, &c.SituationID, &c.InputVersion, &c.RetryEpoch, &c.WorkAttempt, &dispatchedAtStr); err != nil {
			return nil, fmt.Errorf("store: scan orphaned assessment call: %w", err)
		}
		var err error
		if c.DispatchedAt, err = time.Parse(time.RFC3339Nano, dispatchedAtStr); err != nil {
			return nil, fmt.Errorf("store: parse orphaned assessment call dispatched_at: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate orphaned assessment calls: %w", err)
	}
	return out, nil
}

func nextAssessmentAttemptSequenceTx(ctx context.Context, tx *sql.Tx, situationID string) (int, error) {
	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(sequence) FROM situation_assessment_attempts WHERE situation_id = ?`, situationID).Scan(&maxSeq); err != nil {
		return 0, fmt.Errorf("store: read next assessment attempt sequence: %w", err)
	}
	if !maxSeq.Valid {
		return 1, nil
	}
	return int(maxSeq.Int64) + 1, nil
}

// mergeSituationDueReasonTx folds reason into situationID's due_reasons_json
// exactly like joinSituationTx's mergeDueReason step — order-preserving,
// de-duplicated, a no-op if reason is already present.
func mergeSituationDueReasonTx(ctx context.Context, tx *sql.Tx, situationID string, reason situationmodel.DueReason, now time.Time) error {
	sit, err := getSituationTx(ctx, tx, situationID)
	if err != nil {
		return err
	}
	merged := mergeDueReason(sit.DueReasons, reason)
	if len(merged) == len(sit.DueReasons) {
		return nil
	}
	reasonsJSON, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("store: marshal merged situation due reasons: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE situations SET due_reasons_json = ?, updated_at = ? WHERE id = ?`,
		string(reasonsJSON), canonicalTime(now), situationID); err != nil {
		return fmt.Errorf("store: merge situation due reason: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// CommitController — fencing skeleton only. Task 8 completes the
// decision/projection commit behavior inside the same fenced transaction.
// ----------------------------------------------------------------------

// errCommitControllerNotImplemented is returned by every call to
// CommitController in this build: the fencing skeleton is real (it opens a
// transaction and verifies Situation ID, input version, lease owner, and
// claim token all still match), but Task 8 has not yet implemented the
// decision/projection commit itself, so this method always rolls back and
// reports that honestly rather than silently no-oping or partially
// committing.
var errCommitControllerNotImplemented = errors.New("store: CommitController decision/projection commit is not yet implemented (Task 8)")

// CommitController is the Situation controller's single fenced write
// transaction. Task 3 implements only its fencing skeleton: it opens a
// transaction, re-reads the current Situation row, and verifies Situation
// ID, input version, lease owner, and claim token still match claim exactly
// — returning ErrSituationLeaseLost for an owner/token mismatch or
// ErrSituationVersionConflict for an input-version mismatch, matching the
// spec's concurrency rule ("It commits only when Situation ID, input
// version, lease owner, and claim token still match"). It never partially
// commits: every path below either returns before touching a row, or rolls
// back via the deferred Rollback because it never calls tx.Commit. Task 8
// fills in the real body — persisting commit.Attempt (and, for a new
// authoritative attempt, advancing current_assessment_id under the guard
// trigger), commit.TriageDecisions, the projected lifecycle/Attention/
// recovery/terminal/contract fields, subtracting only claim's consumed due
// reasons while preserving concurrently added ones, and taking the earlier
// of commit's proposed checkpoint and any concurrently persisted one.
func (s *Store) CommitController(ctx context.Context, claim situation.Claim, commit situation.ControllerCommit) error {
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: commit controller requires a complete claim")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin commit controller: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := getSituationTx(ctx, tx, claim.Situation.ID)
	if err != nil {
		return err
	}
	if current.LeaseOwner == nil || *current.LeaseOwner != claim.ClaimOwner || current.ClaimToken != claim.ClaimToken {
		return situationmodel.ErrSituationLeaseLost
	}
	if current.InputVersion != claim.Situation.InputVersion {
		return ErrSituationVersionConflict
	}

	_ = commit // Task 8 persists commit's content inside this same fenced transaction.
	return errCommitControllerNotImplemented
}
