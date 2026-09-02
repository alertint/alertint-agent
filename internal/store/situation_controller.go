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

	parked, err := readControllerParkedStateTx(ctx, tx, sit.ID)
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
		ControllerParked:  parked,
	}, nil
}

// readControllerParkedStateTx reads situationID's current controller_parked_at/
// controller_parked_reason/current_material_fact_hash columns directly — raw
// ALTER TABLE columns (migration 0015) Plan 1's model.Situation carries no Go
// struct field for (see BeginControllerAttempt's own doc comment for why),
// mirroring exactly how BeginControllerAttempt itself reads them. Finding I1:
// Reconcile needs this to decide whether a policy/capability park still
// covers the CURRENT basis before dispatching new L2 work.
func readControllerParkedStateTx(ctx context.Context, tx *sql.Tx, situationID string) (situation.ControllerParkedState, error) {
	var parkedAt, parkedReason, materialFactHash sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT controller_parked_at, controller_parked_reason, current_material_fact_hash
		FROM situations WHERE id = ?`, situationID).Scan(&parkedAt, &parkedReason, &materialFactHash)
	if errors.Is(err, sql.ErrNoRows) {
		return situation.ControllerParkedState{}, ErrNotFound
	}
	if err != nil {
		return situation.ControllerParkedState{}, fmt.Errorf("store: read controller parked state: %w", err)
	}
	var out situation.ControllerParkedState
	if parkedAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, parkedAt.String)
		if err != nil {
			return situation.ControllerParkedState{}, fmt.Errorf("store: parse controller_parked_at: %w", err)
		}
		out.At = &t
	}
	if parkedReason.Valid {
		out.Reason = parkedReason.String
	}
	if materialFactHash.Valid {
		out.MaterialFactHash = materialFactHash.String
	}
	return out, nil
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
// BeginControllerAttempt — durable pre-registration of one work-bearing
// controller attempt, before any provider work.
// ----------------------------------------------------------------------

// BeginControllerAttempt fences and durably advances the current unchanged
// input's work-attempt counter before any provider work — spec.md: "the
// five-attempt counter advances only for a work-bearing controller cycle
// that dispatches or fails bounded Assessment work." It reads and writes
// situations.controller_work_attempts and reads controller_retry_epoch/
// current_material_fact_hash directly (Plan 1's model.Situation carries
// none of Plan 2's own controller-projection columns; migration 0015 adds
// them as raw ALTER TABLE columns with no Go struct field of their own —
// see the Task 8 report).
//
// sameBasis compares materialFactHash against the CURRENTLY PERSISTED
// current_material_fact_hash (last set by a prior fenced CommitController
// commit, never written here): unchanged means this is a continuation of
// the same input's attempt budget (work_attempts+1, fenced at 5); changed
// means a fresh epoch (work_attempts resets to 1) — this covers BOTH "a
// genuinely new material input arrived" and "a dependency-recovery
// generation already reset controller_work_attempts to 0 for this
// situation" (see the dependency-recovery wake primitive below) — either
// way, current_material_fact_hash still reads as unchanged from THIS
// input's own perspective, controller_work_attempts reads 0, and 0+1=1
// naturally starts a fresh attempt count. controller_retry_epoch is
// returned read-only; only the wake primitive ever writes it.
//
// Returns situation.ErrControllerAttemptsExhausted (not a generic error)
// when advancing would exceed 5 — Reconcile treats that as "already
// parked; refresh the projection only," never as a call failure.
func (s *Store) BeginControllerAttempt(ctx context.Context, claim situation.Claim, materialFactHash string, now time.Time) (int, int, error) {
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return 0, 0, errors.New("store: begin controller attempt requires a complete claim")
	}
	if strings.TrimSpace(materialFactHash) == "" {
		return 0, 0, errors.New("store: begin controller attempt requires a material fact hash")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: begin begin-controller-attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyClaimTx(ctx, tx, claim); err != nil {
		return 0, 0, err
	}

	var currentHash sql.NullString
	var retryEpoch, workAttempts int
	err = tx.QueryRowContext(ctx, `
		SELECT current_material_fact_hash, controller_retry_epoch, controller_work_attempts
		FROM situations WHERE id = ?`, claim.Situation.ID).Scan(&currentHash, &retryEpoch, &workAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("store: read controller attempt counters: %w", err)
	}

	nextAttempt := 1
	if currentHash.Valid && currentHash.String == materialFactHash {
		nextAttempt = workAttempts + 1
	}
	if nextAttempt > 5 {
		return 0, 0, situation.ErrControllerAttemptsExhausted
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE situations SET controller_work_attempts = ?, updated_at = ? WHERE id = ?`,
		nextAttempt, canonicalTime(now), claim.Situation.ID); err != nil {
		return 0, 0, fmt.Errorf("store: advance controller attempt counter: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store: commit begin controller attempt: %w", err)
	}
	return retryEpoch, nextAttempt, nil
}

// ----------------------------------------------------------------------
// LastTrustworthyAssessment.
// ----------------------------------------------------------------------

// LastTrustworthyAssessment reads the most recent authoritative attempt for
// claim's Situation whose own derivation is trustworthy in Task 5's sense
// (model_validated, deterministic_controller, or revalidated_reuse — never
// deterministic_fallback, spec.md: "that fallback is never a semantic reuse
// source"), regardless of whether it is still the CURRENT pointer. Returns
// (nil, nil) when no such attempt exists yet. This is a read-only
// convenience surface (e.g. a future MCP/operator-facing "last real
// judgment" view distinct from a current deterministic_fallback notice);
// Reconcile's own fallback-vs-preserve decision deliberately uses only
// claim's own current AuthoritativeAssessment (SnapshotInput.
// CurrentAssessment), never this wider history scan — see the Task 8
// report for the full rationale (reusing an OLDER trustworthy judgment
// against a possibly-changed current basis without RevalidateReuse's own
// revalidation would risk exactly the staleness bug its doc comment warns
// against).
func (s *Store) LastTrustworthyAssessment(ctx context.Context, claim situation.Claim) (*situation.AuthoritativeAssessment, error) {
	if strings.TrimSpace(claim.Situation.ID) == "" {
		return nil, errors.New("store: last trustworthy assessment requires a situation id")
	}
	var attemptID string
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM situation_assessment_attempts
		WHERE situation_id = ? AND status = 'authoritative' AND derivation != 'deterministic_fallback'
		ORDER BY sequence DESC LIMIT 1`, claim.Situation.ID).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no trustworthy attempt yet is a legitimate, common outcome, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("store: read last trustworthy assessment: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: begin last trustworthy assessment read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	a, err := loadAuthoritativeAssessmentTx(ctx, tx, attemptID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit last trustworthy assessment read: %w", err)
	}
	return a, nil
}

// ----------------------------------------------------------------------
// CommitController — the fenced projection/decision commit.
// ----------------------------------------------------------------------

// currentControllerProjectionTx reads the current bounded controller
// projection columns CommitController needs to merge/preserve, inside its
// own transaction — never trusted from any caller-supplied snapshot.
type currentControllerProjectionTx struct {
	dueReasons       []situationmodel.DueReason
	nextAssessmentAt string
	parkedAt         sql.NullString
	parkedReason     sql.NullString
}

func readCurrentControllerProjectionTx(ctx context.Context, tx *sql.Tx, situationID string) (currentControllerProjectionTx, error) {
	var out currentControllerProjectionTx
	var dueReasonsJSON string
	err := tx.QueryRowContext(ctx, `
		SELECT due_reasons_json, next_assessment_at, controller_parked_at, controller_parked_reason
		FROM situations WHERE id = ?`, situationID).Scan(&dueReasonsJSON, &out.nextAssessmentAt, &out.parkedAt, &out.parkedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return currentControllerProjectionTx{}, ErrNotFound
	}
	if err != nil {
		return currentControllerProjectionTx{}, fmt.Errorf("store: read current controller projection: %w", err)
	}
	if err := json.Unmarshal([]byte(dueReasonsJSON), &out.dueReasons); err != nil {
		return currentControllerProjectionTx{}, fmt.Errorf("store: unmarshal current due reasons: %w", err)
	}
	return out, nil
}

// subtractDueReasonsStore removes every reason in consumed from current,
// preserving current's order — evaluated fresh against the row this
// transaction just read inside its own fenced commit, never trusting the
// caller's claim-time snapshot. spec.md: "It subtracts only reasons present
// in the claim. Reasons raised after the claim survive."
func subtractDueReasonsStore(current, consumed []situationmodel.DueReason) []situationmodel.DueReason {
	remove := make(map[situationmodel.DueReason]bool, len(consumed))
	for _, r := range consumed {
		remove[r] = true
	}
	out := make([]situationmodel.DueReason, 0, len(current))
	for _, r := range current {
		if !remove[r] {
			out = append(out, r)
		}
	}
	return out
}

// CommitController is the Situation controller's single fenced write
// transaction (spec.md's "fenced atomic controller commit"). It verifies
// Situation ID, input version, lease owner, and claim token still match
// claim exactly, then: inserts commit.Attempt (and its coverage rows) and
// advances current_assessment_id only when Attempt.ID is non-empty
// (situation.ControllerCommit's own doc comment: the zero value means "no
// new authoritative row this cycle"); applies commit.TriageDecisions via
// Task 6's applyTriageDecisionsTx inside this SAME transaction; refreshes
// the bounded current lifecycle/Attention/contract/hash projection on
// EVERY commit regardless of whether Attempt is populated; applies
// commit.Parked's explicit touch/clear/set instruction; subtracts only
// claim.Situation.DueReasons from the due-reasons row read fresh inside
// this transaction (never claim's own possibly-stale snapshot); sets
// next_assessment_at to SQL min(current, commit.NextAssessmentAt); and
// clears the lease. It never partially commits: every failure path returns
// before calling tx.Commit, so the deferred Rollback undoes everything.
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

	proj, err := readCurrentControllerProjectionTx(ctx, tx, claim.Situation.ID)
	if err != nil {
		return err
	}

	// 1. Insert the new authoritative attempt (if any) and its coverage.
	var newAssessmentID sql.NullString
	if commit.Attempt.ID != "" {
		seq, err := nextAssessmentAttemptSequenceTx(ctx, tx, claim.Situation.ID)
		if err != nil {
			return err
		}
		attempt := commit.Attempt
		attempt.Sequence = seq
		p, err := prepareAssessmentAttempt(attempt, commit.MaterialFactHash)
		if err != nil {
			return err
		}
		if err := insertAssessmentAttemptTx(ctx, tx, p); err != nil {
			return err
		}
		for _, cov := range commit.Coverage {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO situation_assessment_coverage (assessment_attempt_id, incident_id, membership_digest, incident_input_digest)
				VALUES (?, ?, ?, ?) ON CONFLICT(assessment_attempt_id, incident_id) DO NOTHING`,
				attempt.ID, cov.IncidentID, cov.MembershipDigest, cov.IncidentInputDigest); err != nil {
				return fmt.Errorf("store: insert assessment coverage: %w", err)
			}
		}
		newAssessmentID = sql.NullString{String: attempt.ID, Valid: true}
	}

	// 2. Apply Triage decisions sharing this same commit.
	if err := applyTriageDecisionsTx(ctx, tx, commit.TriageDecisions, canonicalCommitTime(commit)); err != nil {
		return err
	}

	// 3. Projected lifecycle/Attention/contract/hashes.
	actionContractJSON, err := json.Marshal(commit.Assessment.ActionContract)
	if err != nil {
		return fmt.Errorf("store: marshal current action contract: %w", err)
	}

	// 4. Parked state.
	parkedAt, parkedReason := proj.parkedAt, proj.parkedReason
	if commit.Parked.Touch {
		if commit.Parked.Reason == "" {
			parkedAt, parkedReason = sql.NullString{}, sql.NullString{}
		} else {
			parkedAt = sql.NullString{String: canonicalTime(commit.Parked.At), Valid: true}
			parkedReason = sql.NullString{String: commit.Parked.Reason, Valid: true}
		}
	}

	// 5. Due reasons: subtract only what claim itself consumed.
	remainingDueReasons := subtractDueReasonsStore(proj.dueReasons, claim.Situation.DueReasons)
	dueReasonsJSON, err := json.Marshal(remainingDueReasons)
	if err != nil {
		return fmt.Errorf("store: marshal remaining due reasons: %w", err)
	}

	// 6. next_assessment_at: spec.md's own checkpoint rule is
	// min(controller proposed, any CONCURRENTLY PERSISTED earlier
	// checkpoint) — deliberately NOT min(proposed, whatever next_assessment_at
	// already held at claim time). The row was claimed BECAUSE
	// next_assessment_at was already <= now (it was due), so claim.Situation.
	// NextAssessmentAt is always a stale past due-time, not new information;
	// naively taking min() against it would pin next_assessment_at to that
	// stale value forever, since a freshly-derived proposed checkpoint is
	// always > now by construction (nextUpdateAt's own clamp) and so can
	// never win a min() against an already-past value. A genuinely
	// concurrent write IS still possible without invalidating this claim's
	// lease/token fence: WakeDependencyRecoveredSituations's own UPDATE
	// (below) touches next_assessment_at without touching lease_owner/
	// claim_token at all — exactly the case spec.md's rule protects. proj.
	// nextAssessmentAt (read fresh, inside this same transaction) differing
	// from claim.Situation.NextAssessmentAt (the claim-time snapshot) is
	// what proves such a write happened since claim; only then does the
	// earlier of the two survive.
	nextAssessmentAt := canonicalTime(commit.NextAssessmentAt)
	if proj.nextAssessmentAt != canonicalTime(claim.Situation.NextAssessmentAt) && proj.nextAssessmentAt < nextAssessmentAt {
		nextAssessmentAt = proj.nextAssessmentAt
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situations SET
			lifecycle = ?, attention = ?,
			recovery_observed_at = ?, grace_until = ?, terminal_at = ?, terminal_reason = ?,
			current_assessment_id = COALESCE(?, current_assessment_id),
			current_assessment_basis_hash = ?, current_material_fact_hash = ?,
			current_action_contract_json = ?,
			controller_parked_at = ?, controller_parked_reason = ?,
			due_reasons_json = ?,
			next_assessment_at = ?,
			retry_at = ?, last_error_class = ?,
			lease_owner = NULL, lease_expires_at = NULL,
			updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ? AND input_version = ?`,
		string(commit.Lifecycle), string(commit.Attention),
		nullableTimePtr(commit.RecoveryObservedAt), nullableTimePtr(commit.GraceUntil),
		nullableTimePtr(commit.TerminalAt), nullableTerminalReason(commit.TerminalReason),
		newAssessmentID,
		nullableStringValue(commit.AssessmentBasisHash), nullableStringValue(commit.MaterialFactHash),
		string(actionContractJSON),
		parkedAt, parkedReason,
		string(dueReasonsJSON),
		nextAssessmentAt,
		nullableTimePtr(commit.RetryAt), nullableString(commit.LastErrorClass),
		canonicalTime(canonicalCommitTime(commit)),
		claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken, claim.Situation.InputVersion)
	if err != nil {
		return fmt.Errorf("store: commit controller projection: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count commit controller projection: %w", err)
	}
	if n != 1 {
		// The fence at the top of this method already re-read the row and
		// confirmed owner/token/version match; a zero-row UPDATE here means
		// something changed between that read and this write within the
		// SAME transaction, which cannot happen under this store's
		// single-writer/single-connection model — fail closed rather than
		// silently no-op.
		return situationmodel.ErrSituationLeaseLost
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit controller transaction: %w", err)
	}
	return nil
}

// canonicalCommitTime is the single "now" CommitController's own writes
// (Triage decision decided_at passthrough, updated_at) anchor to: the new
// attempt's own CompletedAt when one exists (the actual moment this cycle's
// work concluded), else the earliest due-reason timestamp available —
// commit.NextAssessmentAt's own basis — falling back to time.Now() only if
// neither is set (a defensive case that should not occur given Reconcile
// always populates one of them).
func canonicalCommitTime(commit situation.ControllerCommit) time.Time {
	if !commit.Attempt.CompletedAt.IsZero() {
		return commit.Attempt.CompletedAt
	}
	if len(commit.TriageDecisions) > 0 && !commit.TriageDecisions[0].DecidedAt.IsZero() {
		return commit.TriageDecisions[0].DecidedAt
	}
	if !commit.NextAssessmentAt.IsZero() {
		return commit.NextAssessmentAt
	}
	return time.Now().UTC()
}

func nullableTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return canonicalTime(*t)
}

func nullableTerminalReason(r *situationmodel.TerminalReason) any {
	if r == nil {
		return nil
	}
	return string(*r)
}

func nullableStringValue(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ----------------------------------------------------------------------
// ClaimControllerWork / ExtendControllerLease / ReleaseControllerWork —
// wrappers over Plan 1's ClaimDueSituations/ReleaseSituationClaim claim
// state, converting model.Situation's own LeaseOwner/ClaimToken pair into
// this package's transport-neutral situation.Claim (see controller.go's own
// Claim doc comment).
// ----------------------------------------------------------------------

// ClaimControllerWork leases due Situations via ClaimDueSituations and
// returns them as situation.Claim, ready for Controller.Reconcile.
func (s *Store) ClaimControllerWork(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
	sits, err := s.ClaimDueSituations(ctx, owner, now, lease, limit)
	if err != nil {
		return nil, err
	}
	out := make([]situation.Claim, 0, len(sits))
	for _, sit := range sits {
		if sit.LeaseOwner == nil {
			continue // defensive: ClaimDueSituations always sets it; never surface an unclaimed row as a Claim.
		}
		out = append(out, situation.Claim{Situation: sit, ClaimOwner: *sit.LeaseOwner, ClaimToken: sit.ClaimToken})
	}
	return out, nil
}

// ExtendControllerLease renews claim's lease for another lease duration,
// fenced on (id, lease_owner, claim_token) — the same fencing
// ReleaseSituationClaim uses, reused directly rather than duplicated.
func (s *Store) ExtendControllerLease(ctx context.Context, claim situation.Claim, now time.Time, lease time.Duration) error {
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: extend controller lease requires a complete claim")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations SET lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(now.Add(lease)), canonicalTime(now.UTC()), claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: extend controller lease: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count extended controller lease: %w", err)
	}
	if n != 1 {
		return situationmodel.ErrSituationLeaseLost
	}
	return nil
}

// ReleaseControllerWork releases claim's lease early — the worker's own
// safety net when Reconcile returns before ever reaching CommitController
// (which otherwise always clears the lease itself on a successful commit).
//
// Finding I2 fix: retryAt/errorClass, when non-nil, additionally push
// next_assessment_at/retry_at forward and record errorClass — so a
// persistently-failing Situation is not instantly re-claimable on the very
// next poll (without this, ControllerWorker.Drain would spin at 100% CPU
// reclaiming the same always-failing Situation forever — see
// controller_worker.go's processOne). retryAt/errorClass both nil is a plain
// release with no backoff, equivalent to the pre-fix behavior (a thin
// wrapper over ReleaseSituationClaim) — used by any future caller with
// nothing useful to classify.
//
// The next_assessment_at push mirrors CommitController's own rule: never
// clobber a genuinely earlier, concurrently-persisted checkpoint (e.g. a
// fresh material input landing mid-cycle wants to be reprocessed SOONER, not
// pushed later by this failure's own backoff) — detected the same way
// CommitController detects it, by comparing the freshly-read current value
// against claim's own claim-time snapshot.
func (s *Store) ReleaseControllerWork(ctx context.Context, claim situation.Claim, now time.Time, retryAt *time.Time, errorClass *string) error {
	if retryAt == nil {
		owner := claim.ClaimOwner
		sit := claim.Situation
		sit.LeaseOwner = &owner
		sit.ClaimToken = claim.ClaimToken
		return s.ReleaseSituationClaim(ctx, sit, now)
	}
	if strings.TrimSpace(claim.Situation.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: release controller work requires a complete claim")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin release controller work: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentNextAssessmentAt string
	err = tx.QueryRowContext(ctx, `SELECT next_assessment_at FROM situations WHERE id = ?`, claim.Situation.ID).Scan(&currentNextAssessmentAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: read current next_assessment_at: %w", err)
	}

	nextAssessmentAt := canonicalTime(*retryAt)
	if currentNextAssessmentAt != canonicalTime(claim.Situation.NextAssessmentAt) && currentNextAssessmentAt < nextAssessmentAt {
		// A concurrent write (detected by divergence from the claim-time
		// snapshot) already pulled the checkpoint earlier than our proposed
		// backoff — that genuinely newer due time survives, never clobbered
		// by this failure's own later backoff.
		nextAssessmentAt = currentNextAssessmentAt
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situations SET
			lease_owner = NULL, lease_expires_at = NULL,
			retry_at = ?, last_error_class = ?,
			next_assessment_at = ?,
			updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(*retryAt), nullableString(errorClass),
		nextAssessmentAt, canonicalTime(now.UTC()),
		claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: release controller work with backoff: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count released controller work: %w", err)
	}
	if n != 1 {
		return situationmodel.ErrSituationLeaseLost
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------
// Dependency-recovery wake primitive.
// ----------------------------------------------------------------------

// WakeDependencyRecoveredSituations is the idempotent, startup-safe primitive
// spec.md's retry/parking section names: "a durable dependency recovery
// generation may open one new bounded retry epoch for work parked
// specifically on that dependency." Called once before each controller
// claim poll (never concurrently with live controller work on the same
// Situation — the same discipline RecoverInterruptedAssessmentCalls/
// RecoverExpiredFoundationLeases already document), it finds every
// Situation parked with controller_parked_reason=situation.ParkedReasonDependency
// whose last_consumed_recovery_generation is older than outageGeneration —
// the caller supplies this from internal/llmhealth.Tracker.Snapshot().
// OutageGeneration once healthy again (this package cannot import
// internal/llmhealth: that package imports internal/store, so the reverse
// import here would cycle) — and for each: increments controller_retry_epoch,
// resets controller_work_attempts to 0, clears the parked marker, merges
// retry_due into due_reasons, moves next_assessment_at earlier (to now), and
// persists last_consumed_recovery_generation = outageGeneration, all in one
// transaction per Situation. Repeated calls within the SAME generation are a
// no-op (last_consumed_recovery_generation already >= outageGeneration), so
// this never resets counters twice for one recovery event, and never
// re-arms a policy/capability park (those never carry
// ParkedReasonDependency). Returns how many Situations it woke.
func (s *Store) WakeDependencyRecoveredSituations(ctx context.Context, outageGeneration int64, now time.Time) (int, error) {
	if outageGeneration <= 0 {
		return 0, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM situations
		WHERE lifecycle IN ('active','recovery_pending')
		  AND controller_parked_reason = ?
		  AND last_consumed_recovery_generation < ?`,
		situation.ParkedReasonDependency, outageGeneration)
	if err != nil {
		return 0, fmt.Errorf("store: list dependency-parked situations: %w", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read dependency-parked situation ids: %w", err)
	}

	woken := 0
	for _, id := range ids {
		ok, err := wakeOneDependencyRecoveredSituationTx(ctx, s.db, id, outageGeneration, now)
		if err != nil {
			return woken, err
		}
		if ok {
			woken++
		}
	}
	return woken, nil
}

func wakeOneDependencyRecoveredSituationTx(ctx context.Context, db *sql.DB, situationID string, outageGeneration int64, now time.Time) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: begin wake dependency-recovered situation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	sit, err := getSituationTx(ctx, tx, situationID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil // raced away (e.g. terminalized) since the listing read; nothing to wake.
		}
		return false, err
	}

	var lastConsumed int64
	if err := tx.QueryRowContext(ctx, `SELECT last_consumed_recovery_generation FROM situations WHERE id = ?`, situationID).Scan(&lastConsumed); err != nil {
		return false, fmt.Errorf("store: read last consumed recovery generation: %w", err)
	}
	if lastConsumed >= outageGeneration {
		return false, nil // already consumed by a prior poll within this same generation.
	}

	mergedReasons := mergeDueReason(sit.DueReasons, situationmodel.DueRetry)
	dueReasonsJSON, err := json.Marshal(mergedReasons)
	if err != nil {
		return false, fmt.Errorf("store: marshal woken due reasons: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situations SET
			controller_retry_epoch = controller_retry_epoch + 1,
			controller_work_attempts = 0,
			controller_parked_at = NULL, controller_parked_reason = NULL,
			last_consumed_recovery_generation = ?,
			due_reasons_json = ?,
			next_assessment_at = min(next_assessment_at, ?),
			updated_at = ?
		WHERE id = ? AND controller_parked_reason = ? AND last_consumed_recovery_generation < ?`,
		outageGeneration, string(dueReasonsJSON), canonicalTime(now), canonicalTime(now),
		situationID, situation.ParkedReasonDependency, outageGeneration)
	if err != nil {
		return false, fmt.Errorf("store: wake dependency-recovered situation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: count woken dependency-recovered situation: %w", err)
	}
	if n != 1 {
		return false, nil // raced away between the read above and this write.
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: commit wake dependency-recovered situation: %w", err)
	}
	return true, nil
}
