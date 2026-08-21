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

const (
	maxEnvelopeScopeBytes      = 16 * 1024
	maxEnvelopeConditionsBytes = 64 * 1024
	maxJudgmentEvidenceRefs    = 128
	maxJudgmentListBytes       = 16 * 1024
	defaultEnvelopeReviewAfter = 30 * 24 * time.Hour
)

// SituationPolicyAuditAppender is the minimal transactional audit boundary
// required for a judgment or envelope write. Store deliberately does not
// import audit (internal/audit is the concrete implementation used by
// wiring code).
type SituationPolicyAuditAppender interface {
	AppendTx(context.Context, *sql.Tx, string, string, any) error
}

// SituationPolicyAuditEvent is one caller-supplied audit row appended in the
// same transaction as the durable write it describes.
type SituationPolicyAuditEvent struct {
	Kind    string
	Payload map[string]any
}

const situationPolicyAuditActor = "situationpolicy"

// ---------------------------------------------------------------------
// Judgments
// ---------------------------------------------------------------------

// RecordSituationJudgment appends one already-built, already-validated
// Judgment. It is the low-level append primitive; RecordJudgment is the
// orchestration most callers want (validation, exact coverage derivation,
// due-reason scheduling, and audit all in one transaction).
func (s *Store) RecordSituationJudgment(ctx context.Context, j situationmodel.Judgment) error {
	prepared, err := prepareSituationJudgment(j)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin record situation judgment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertSituationJudgmentTx(ctx, tx, prepared); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit record situation judgment: %w", err)
	}
	return nil
}

// RecordJudgment validates a confirmed operator request, stamps it with the
// exact input version and material fact/symptom/impact coverage carried by
// snap, persists it, and — when the request commits a ValidUntil — schedules
// a judgment_boundary reconsideration no later than that instant. Recording
// a judgment is itself material: it always unions operator_judgment too.
// The write is fenced against snap.SituationID/InputVersion with no lease
// requirement (MCP callers never hold the reconciliation lease); a
// concurrent input change rejects the write outright rather than applying it
// against a view the operator never saw, and the rejection itself is
// audited even though the underlying transaction rolls back.
func (s *Store) RecordJudgment(ctx context.Context, snap situation.Snapshot, req situationmodel.JudgmentRequest, authenticatedAs string, now time.Time, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) (*situationmodel.Judgment, error) {
	if auditor == nil || len(events) == 0 {
		return nil, errors.New("store: judgment recording requires audit events")
	}
	j, err := situation.BuildJudgment(uuid.NewString(), snap, req, authenticatedAs, now)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareSituationJudgment(j)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin record judgment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := situationForPolicyUpdateTx(ctx, tx, snap.SituationID)
	if err != nil {
		return nil, err
	}
	if current.inputVersion != snap.InputVersion {
		_ = tx.Rollback()
		s.auditSituationPolicyRejection(ctx, auditor, "judgment.rejected", map[string]any{
			"situation_id": snap.SituationID, "expected_input_version": snap.InputVersion, "actual_input_version": current.inputVersion,
			"authenticated_as": authenticatedAs, "asserted_operator": req.ConfirmedBy,
		})
		return nil, ErrSituationVersionConflict
	}
	if current.lifecycle == string(situationmodel.LifecycleRecovered) || current.lifecycle == string(situationmodel.LifecycleClosedUnknown) {
		return nil, errors.New("store: cannot record a judgment against a terminal situation")
	}

	if err := insertSituationJudgmentTx(ctx, tx, prepared); err != nil {
		return nil, err
	}

	due := situation.MergeDueReasons(current.dueReasons, situationmodel.DueOperatorJudgment)
	nextAt := current.nextAssessmentAt
	if j.ValidUntil != nil {
		due = situation.MergeDueReasons(due, situationmodel.DueJudgmentBoundary)
		nextAt = situation.EarlierAssessmentAt(nextAt, *j.ValidUntil)
	}
	dueJSON, err := json.Marshal(due)
	if err != nil {
		return nil, fmt.Errorf("store: marshal judgment due reasons: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE situations SET due_reasons_json=?, next_assessment_at=?, updated_at=? WHERE id=? AND input_version=?`,
		string(dueJSON), canonicalTime(nextAt), canonicalTime(now), snap.SituationID, snap.InputVersion)
	if err != nil {
		return nil, fmt.Errorf("store: schedule judgment due reasons: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: count judgment due reason schedule: %w", err)
	}
	if changed != 1 {
		return nil, ErrSituationVersionConflict
	}

	if err := appendSituationPolicyAuditEvents(ctx, tx, auditor, events); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit record judgment: %w", err)
	}
	return &j, nil
}

type situationPolicyFence struct {
	inputVersion     int
	lifecycle        string
	dueReasons       []situationmodel.DueReason
	nextAssessmentAt time.Time
}

func situationForPolicyUpdateTx(ctx context.Context, tx *sql.Tx, situationID string) (situationPolicyFence, error) {
	var inputVersion int
	var lifecycle, dueReasonsJSON, nextAssessmentAt string
	err := tx.QueryRowContext(ctx, `SELECT input_version, lifecycle, due_reasons_json, next_assessment_at FROM situations WHERE id=?`, situationID).
		Scan(&inputVersion, &lifecycle, &dueReasonsJSON, &nextAssessmentAt)
	if errors.Is(err, sql.ErrNoRows) {
		return situationPolicyFence{}, ErrNotFound
	}
	if err != nil {
		return situationPolicyFence{}, fmt.Errorf("store: read situation for policy update: %w", err)
	}
	var due []situationmodel.DueReason
	if err := json.Unmarshal([]byte(dueReasonsJSON), &due); err != nil {
		return situationPolicyFence{}, fmt.Errorf("store: decode situation due reasons: %w", err)
	}
	next, err := parseSituationTime("next_assessment_at", nextAssessmentAt)
	if err != nil {
		return situationPolicyFence{}, err
	}
	return situationPolicyFence{inputVersion: inputVersion, lifecycle: lifecycle, dueReasons: due, nextAssessmentAt: next}, nil
}

type preparedSituationJudgment struct {
	id, situationID, factHash, symptomsJSON, impactJSON, judgment, basis string
	workload                                                             any
	validUntil                                                           any
	evidenceRefsJSON, authenticatedAs, assertedOperator, createdAt       string
	inputVersion                                                         int
}

func prepareSituationJudgment(j situationmodel.Judgment) (preparedSituationJudgment, error) {
	if strings.TrimSpace(j.ID) == "" || strings.TrimSpace(j.SituationID) == "" || j.JudgedInputVersion < 1 ||
		strings.TrimSpace(j.CoveredFactHash) == "" || strings.TrimSpace(j.AuthenticatedAs) == "" || strings.TrimSpace(j.AssertedOperator) == "" ||
		j.CreatedAt.IsZero() || j.CreatedAt.Location() != time.UTC {
		return preparedSituationJudgment{}, errors.New("store: judgment requires identity, coverage, attribution, and a canonical creation time")
	}
	switch j.Judgment {
	case situationmodel.JudgmentExpectedThisEpisode, situationmodel.JudgmentUnexpected, situationmodel.JudgmentInconclusive:
	default:
		return preparedSituationJudgment{}, fmt.Errorf("store: judgment kind %q is invalid", j.Judgment)
	}
	switch j.Basis {
	case situationmodel.JudgmentBasisOperatorKnowledge, situationmodel.JudgmentBasisAlertintEvidence:
	default:
		return preparedSituationJudgment{}, fmt.Errorf("store: judgment basis %q is invalid", j.Basis)
	}
	if len(j.EvidenceRefs) > maxJudgmentEvidenceRefs {
		return preparedSituationJudgment{}, errors.New("store: judgment carries too many evidence references")
	}
	symptoms := j.CoveredSymptoms
	if symptoms == nil {
		symptoms = []string{}
	}
	impact := j.CoveredImpact
	if impact == nil {
		impact = []string{}
	}
	evidenceRefs := j.EvidenceRefs
	if evidenceRefs == nil {
		evidenceRefs = []string{}
	}
	symptomsJSON, err := json.Marshal(symptoms)
	if err != nil {
		return preparedSituationJudgment{}, fmt.Errorf("store: marshal covered symptoms: %w", err)
	}
	impactJSON, err := json.Marshal(impact)
	if err != nil {
		return preparedSituationJudgment{}, fmt.Errorf("store: marshal covered impact: %w", err)
	}
	evidenceJSON, err := json.Marshal(evidenceRefs)
	if err != nil {
		return preparedSituationJudgment{}, fmt.Errorf("store: marshal judgment evidence refs: %w", err)
	}
	if len(symptomsJSON) > maxJudgmentListBytes || len(impactJSON) > maxJudgmentListBytes {
		return preparedSituationJudgment{}, errors.New("store: judgment coverage exceeds persistence bound")
	}
	prepared := preparedSituationJudgment{
		id: j.ID, situationID: j.SituationID, inputVersion: j.JudgedInputVersion, factHash: j.CoveredFactHash,
		symptomsJSON: string(symptomsJSON), impactJSON: string(impactJSON), judgment: string(j.Judgment), basis: string(j.Basis),
		evidenceRefsJSON: string(evidenceJSON), authenticatedAs: j.AuthenticatedAs, assertedOperator: j.AssertedOperator,
		createdAt: canonicalTime(j.CreatedAt),
	}
	if j.Workload != nil {
		prepared.workload = strings.TrimSpace(*j.Workload)
	}
	if j.ValidUntil != nil {
		if j.ValidUntil.IsZero() || j.ValidUntil.Location() != time.UTC {
			return preparedSituationJudgment{}, errors.New("store: judgment valid_until must be a canonical utc time")
		}
		prepared.validUntil = canonicalTime(*j.ValidUntil)
	}
	return prepared, nil
}

func insertSituationJudgmentTx(ctx context.Context, tx *sql.Tx, p preparedSituationJudgment) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO situation_judgments (
		id, situation_id, judged_input_version, covered_fact_hash, covered_symptoms_json, covered_impact_json,
		judgment, basis, workload, valid_until, evidence_refs_json, authenticated_as, asserted_operator, created_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.id, p.situationID, p.inputVersion, p.factHash, p.symptomsJSON, p.impactJSON,
		p.judgment, p.basis, p.workload, p.validUntil, p.evidenceRefsJSON, p.authenticatedAs, p.assertedOperator, p.createdAt); err != nil {
		return fmt.Errorf("store: insert situation judgment: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Expected-behaviour envelopes
// ---------------------------------------------------------------------

// AppendEnvelopeVersion appends expected+1 to an existing envelope and
// advances its head in the same transaction; version rows are never
// otherwise rewritten. It never creates a new envelope — ConfirmEnvelope
// owns first-time creation, since only it carries the source judgment a new
// envelope must be attributed to.
func (s *Store) AppendEnvelopeVersion(ctx context.Context, expected int, v situationmodel.EnvelopeVersion) error {
	return s.appendEnvelopeVersion(ctx, expected, v, nil, nil)
}

// AppendEnvelopeVersionWithAudit atomically appends an envelope version and
// writes every required audit event in the same transaction — the shape a
// system-driven append (a trigger/template-change caller appending
// `invalidated`) needs, matching RecordJudgment/ConfirmEnvelope/RevokeEnvelope's
// mandatory-audit requirement for every judgment/envelope write.
func (s *Store) AppendEnvelopeVersionWithAudit(ctx context.Context, expected int, v situationmodel.EnvelopeVersion, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) error {
	if auditor == nil || len(events) == 0 {
		return errors.New("store: envelope version audit is required")
	}
	return s.appendEnvelopeVersion(ctx, expected, v, auditor, events)
}

func (s *Store) appendEnvelopeVersion(ctx context.Context, expected int, v situationmodel.EnvelopeVersion, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin append envelope version: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := appendEnvelopeVersionTx(ctx, tx, expected, v); err != nil {
		return err
	}
	if auditor != nil {
		if err := appendSituationPolicyAuditEvents(ctx, tx, auditor, events); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit append envelope version: %w", err)
	}
	return nil
}

// ConfirmEnvelope creates (ExpectedCurrentVersion==0) or amends an existing
// envelope, keyed by its one source judgment, after explicit operator
// confirmation and closed-vocabulary condition validation (disjoint
// required/allowed companions, a positive duration ceiling, a resolvable
// schedule, and no free-text uncertainty ceiling). A stale
// ExpectedCurrentVersion is rejected outright and audited as rejected.
func (s *Store) ConfirmEnvelope(ctx context.Context, confirmation situationmodel.EnvelopeConfirmation, authenticatedAs string, now time.Time, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) (*situationmodel.EnvelopeVersion, error) {
	if auditor == nil || len(events) == 0 {
		return nil, errors.New("store: envelope confirmation requires audit events")
	}
	if !confirmation.OperatorConfirmed {
		return nil, errors.New("store: envelope confirmation requires explicit operator confirmation")
	}
	if strings.TrimSpace(confirmation.ConfirmedBy) == "" {
		return nil, errors.New("store: envelope confirmation requires an asserted confirming operator")
	}
	if strings.TrimSpace(confirmation.SourceJudgmentID) == "" {
		return nil, errors.New("store: envelope confirmation requires a source judgment")
	}
	if strings.TrimSpace(authenticatedAs) == "" {
		return nil, errors.New("store: envelope confirmation requires an authenticated trust domain")
	}
	if strings.TrimSpace(confirmation.Scope.GroupKey) == "" {
		return nil, errors.New("store: envelope scope requires an exact group key")
	}
	if err := situation.ValidateEnvelopeConditions(confirmation.Conditions); err != nil {
		return nil, err
	}
	reviewDueAt := confirmation.ReviewDueAt
	if reviewDueAt.IsZero() {
		reviewDueAt = now.Add(defaultEnvelopeReviewAfter)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin confirm envelope: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var judgmentExists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_judgments WHERE id=?`, confirmation.SourceJudgmentID).Scan(&judgmentExists); err != nil {
		return nil, fmt.Errorf("store: verify envelope source judgment: %w", err)
	}
	if judgmentExists == 0 {
		return nil, ErrNotFound
	}

	envelopeID, err := resolveOrCreateEnvelopeHeadTx(ctx, tx, confirmation.SourceJudgmentID, confirmation.ExpectedCurrentVersion, now)
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			_ = tx.Rollback()
			s.auditSituationPolicyRejection(ctx, auditor, "envelope.confirm.rejected", map[string]any{
				"source_judgment_id": confirmation.SourceJudgmentID, "expected_current_version": confirmation.ExpectedCurrentVersion,
				"authenticated_as": authenticatedAs, "asserted_operator": confirmation.ConfirmedBy,
			})
		}
		return nil, err
	}

	v := situationmodel.EnvelopeVersion{
		EnvelopeID: envelopeID, Status: situationmodel.EnvelopeStatusActive, Scope: confirmation.Scope, Conditions: confirmation.Conditions,
		ReviewDueAt: reviewDueAt.UTC(), AuthenticatedAs: authenticatedAs, AssertedOperator: strings.TrimSpace(confirmation.ConfirmedBy), CreatedAt: now.UTC(),
	}
	finalized, err := appendEnvelopeVersionTx(ctx, tx, confirmation.ExpectedCurrentVersion, v)
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			_ = tx.Rollback()
			s.auditSituationPolicyRejection(ctx, auditor, "envelope.confirm.rejected", map[string]any{
				"envelope_id": envelopeID, "expected_current_version": confirmation.ExpectedCurrentVersion,
				"authenticated_as": authenticatedAs, "asserted_operator": confirmation.ConfirmedBy,
			})
		}
		return nil, err
	}

	if err := appendSituationPolicyAuditEvents(ctx, tx, auditor, events); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit confirm envelope: %w", err)
	}
	return &finalized, nil
}

// RevokeEnvelope appends a revoked version after explicit operator
// confirmation, carrying forward the revoked version's own scope and
// conditions (history stays legible: what, exactly, was revoked), and
// schedules every active/recovery_pending Situation that has ever evaluated
// this envelope for reconsideration.
func (s *Store) RevokeEnvelope(ctx context.Context, revocation situationmodel.EnvelopeRevocation, authenticatedAs string, now time.Time, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) (*situationmodel.EnvelopeVersion, error) {
	if auditor == nil || len(events) == 0 {
		return nil, errors.New("store: envelope revocation requires audit events")
	}
	if !revocation.OperatorConfirmed {
		return nil, errors.New("store: envelope revocation requires explicit operator confirmation")
	}
	if strings.TrimSpace(revocation.ConfirmedBy) == "" {
		return nil, errors.New("store: envelope revocation requires an asserted confirming operator")
	}
	if strings.TrimSpace(revocation.Reason) == "" {
		return nil, errors.New("store: envelope revocation requires a reason")
	}
	if strings.TrimSpace(revocation.EnvelopeID) == "" {
		return nil, errors.New("store: envelope revocation requires an envelope id")
	}
	if strings.TrimSpace(authenticatedAs) == "" {
		return nil, errors.New("store: envelope revocation requires an authenticated trust domain")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin revoke envelope: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := currentEnvelopeVersionTx(ctx, tx, revocation.EnvelopeID)
	if err != nil {
		return nil, err
	}

	reason := revocation.Reason
	v := situationmodel.EnvelopeVersion{
		EnvelopeID: revocation.EnvelopeID, Status: situationmodel.EnvelopeStatusRevoked,
		Scope: current.Scope, Conditions: current.Conditions, ReviewDueAt: current.ReviewDueAt,
		AuthenticatedAs: authenticatedAs, AssertedOperator: strings.TrimSpace(revocation.ConfirmedBy), Reason: &reason, CreatedAt: now.UTC(),
	}
	finalized, err := appendEnvelopeVersionTx(ctx, tx, revocation.ExpectedCurrentVersion, v)
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			_ = tx.Rollback()
			s.auditSituationPolicyRejection(ctx, auditor, "envelope.revoke.rejected", map[string]any{
				"envelope_id": revocation.EnvelopeID, "expected_current_version": revocation.ExpectedCurrentVersion,
				"authenticated_as": authenticatedAs, "asserted_operator": revocation.ConfirmedBy,
			})
		}
		return nil, err
	}

	if err := scheduleEnvelopeChangeForActiveSituations(ctx, tx, revocation.EnvelopeID, now); err != nil {
		return nil, err
	}

	if err := appendSituationPolicyAuditEvents(ctx, tx, auditor, events); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit revoke envelope: %w", err)
	}
	return &finalized, nil
}

func resolveOrCreateEnvelopeHeadTx(ctx context.Context, tx *sql.Tx, sourceJudgmentID string, expected int, now time.Time) (string, error) {
	var id string
	var current int
	err := tx.QueryRowContext(ctx, `SELECT id, current_version FROM expected_behavior_envelopes WHERE source_judgment_id=?`, sourceJudgmentID).Scan(&id, &current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expected != 0 {
			return "", ErrVersionConflict
		}
		id = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `INSERT INTO expected_behavior_envelopes (id, current_version, source_judgment_id, created_at, updated_at) VALUES (?,0,?,?,?)`,
			id, sourceJudgmentID, canonicalTime(now), canonicalTime(now)); err != nil {
			return "", fmt.Errorf("store: create envelope head: %w", err)
		}
		return id, nil
	case err != nil:
		return "", fmt.Errorf("store: read envelope head: %w", err)
	case current != expected:
		return "", ErrVersionConflict
	default:
		return id, nil
	}
}

func appendEnvelopeVersionTx(ctx context.Context, tx *sql.Tx, expected int, v situationmodel.EnvelopeVersion) (situationmodel.EnvelopeVersion, error) {
	prepared, err := prepareEnvelopeVersion(v)
	if err != nil {
		return situationmodel.EnvelopeVersion{}, err
	}
	if expected < 0 {
		return situationmodel.EnvelopeVersion{}, errors.New("store: envelope expected version must be nonnegative")
	}
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT current_version FROM expected_behavior_envelopes WHERE id=?`, v.EnvelopeID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return situationmodel.EnvelopeVersion{}, ErrNotFound
		}
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: read envelope head: %w", err)
	}
	if current != expected {
		return situationmodel.EnvelopeVersion{}, ErrVersionConflict
	}
	v.Version = expected + 1
	prepared.version = v.Version
	if _, err := tx.ExecContext(ctx, `INSERT INTO expected_behavior_envelope_versions (
		envelope_id, version, status, scope_json, conditions_json, review_due_at, authenticated_as, asserted_operator, reason, created_at
	) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		prepared.envelopeID, prepared.version, prepared.status, prepared.scopeJSON, prepared.conditionsJSON,
		prepared.reviewDueAt, prepared.authenticatedAs, prepared.assertedOperator, prepared.reason, prepared.createdAt); err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: insert envelope version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE expected_behavior_envelopes SET current_version=?, updated_at=? WHERE id=? AND current_version=?`,
		v.Version, canonicalTime(v.CreatedAt), v.EnvelopeID, expected)
	if err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: advance envelope head: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: count advanced envelope head: %w", err)
	}
	if changed != 1 {
		return situationmodel.EnvelopeVersion{}, ErrVersionConflict
	}
	return v, nil
}

type preparedEnvelopeVersion struct {
	envelopeID, status, scopeJSON, conditionsJSON, reviewDueAt string
	authenticatedAs, assertedOperator, createdAt               string
	reason                                                     any
	version                                                    int
}

func prepareEnvelopeVersion(v situationmodel.EnvelopeVersion) (preparedEnvelopeVersion, error) {
	if strings.TrimSpace(v.EnvelopeID) == "" {
		return preparedEnvelopeVersion{}, errors.New("store: envelope version requires an envelope id")
	}
	switch v.Status {
	case situationmodel.EnvelopeStatusActive, situationmodel.EnvelopeStatusRevoked, situationmodel.EnvelopeStatusInvalidated:
	default:
		return preparedEnvelopeVersion{}, fmt.Errorf("store: envelope version status %q is invalid", v.Status)
	}
	if strings.TrimSpace(v.AuthenticatedAs) == "" || strings.TrimSpace(v.AssertedOperator) == "" {
		return preparedEnvelopeVersion{}, errors.New("store: envelope version requires authenticated trust domain and asserted operator")
	}
	if v.ReviewDueAt.IsZero() {
		return preparedEnvelopeVersion{}, errors.New("store: envelope version requires a review due time")
	}
	if v.CreatedAt.IsZero() || v.CreatedAt.Location() != time.UTC {
		return preparedEnvelopeVersion{}, errors.New("store: envelope version requires a canonical creation time")
	}
	if strings.TrimSpace(v.Scope.GroupKey) == "" {
		return preparedEnvelopeVersion{}, errors.New("store: envelope scope requires an exact group key")
	}
	if err := situation.ValidateEnvelopeConditions(v.Conditions); err != nil {
		return preparedEnvelopeVersion{}, err
	}
	scopeJSON, err := json.Marshal(v.Scope)
	if err != nil {
		return preparedEnvelopeVersion{}, fmt.Errorf("store: marshal envelope scope: %w", err)
	}
	if len(scopeJSON) > maxEnvelopeScopeBytes {
		return preparedEnvelopeVersion{}, errors.New("store: envelope scope is too large")
	}
	conditionsJSON, err := json.Marshal(v.Conditions)
	if err != nil {
		return preparedEnvelopeVersion{}, fmt.Errorf("store: marshal envelope conditions: %w", err)
	}
	if len(conditionsJSON) > maxEnvelopeConditionsBytes {
		return preparedEnvelopeVersion{}, errors.New("store: envelope conditions are too large")
	}
	prepared := preparedEnvelopeVersion{
		envelopeID: v.EnvelopeID, status: string(v.Status), scopeJSON: string(scopeJSON), conditionsJSON: string(conditionsJSON),
		reviewDueAt: canonicalTime(v.ReviewDueAt), authenticatedAs: v.AuthenticatedAs, assertedOperator: v.AssertedOperator,
		createdAt: canonicalTime(v.CreatedAt),
	}
	if v.Reason != nil {
		prepared.reason = strings.TrimSpace(*v.Reason)
	}
	return prepared, nil
}

// currentEnvelopeVersionTx reads the head's own current active version row,
// used to carry Scope/Conditions/ReviewDueAt forward on revocation.
func currentEnvelopeVersionTx(ctx context.Context, tx *sql.Tx, envelopeID string) (situationmodel.EnvelopeVersion, error) {
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT current_version FROM expected_behavior_envelopes WHERE id=?`, envelopeID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return situationmodel.EnvelopeVersion{}, ErrNotFound
		}
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: read envelope head: %w", err)
	}
	if current == 0 {
		return situationmodel.EnvelopeVersion{}, errors.New("store: envelope has no confirmed version to revoke")
	}
	return scanEnvelopeVersion(ctx, tx, envelopeID, current)
}

func scanEnvelopeVersion(ctx context.Context, q queryRower, envelopeID string, version int) (situationmodel.EnvelopeVersion, error) {
	var status, scopeJSON, conditionsJSON, reviewDueAt, authenticatedAs, assertedOperator, createdAt string
	var reason sql.NullString
	err := q.QueryRowContext(ctx, `SELECT status, scope_json, conditions_json, review_due_at, authenticated_as, asserted_operator, reason, created_at
		FROM expected_behavior_envelope_versions WHERE envelope_id=? AND version=?`, envelopeID, version).
		Scan(&status, &scopeJSON, &conditionsJSON, &reviewDueAt, &authenticatedAs, &assertedOperator, &reason, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.EnvelopeVersion{}, ErrNotFound
	}
	if err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: read envelope version: %w", err)
	}
	out := situationmodel.EnvelopeVersion{
		EnvelopeID: envelopeID, Version: version, Status: situationmodel.EnvelopeStatus(status),
		AuthenticatedAs: authenticatedAs, AssertedOperator: assertedOperator,
	}
	if err := json.Unmarshal([]byte(scopeJSON), &out.Scope); err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: decode envelope scope: %w", err)
	}
	if err := json.Unmarshal([]byte(conditionsJSON), &out.Conditions); err != nil {
		return situationmodel.EnvelopeVersion{}, fmt.Errorf("store: decode envelope conditions: %w", err)
	}
	if out.ReviewDueAt, err = parseSituationTime("envelope review_due_at", reviewDueAt); err != nil {
		return situationmodel.EnvelopeVersion{}, err
	}
	if out.CreatedAt, err = parseSituationTime("envelope version created_at", createdAt); err != nil {
		return situationmodel.EnvelopeVersion{}, err
	}
	if reason.Valid {
		out.Reason = &reason.String
	}
	return out, nil
}

// Envelope returns the current head together with its active version.
func (s *Store) Envelope(ctx context.Context, envelopeID string) (*situationmodel.Envelope, error) {
	if strings.TrimSpace(envelopeID) == "" {
		return nil, errors.New("store: envelope id is required")
	}
	var currentVersion int
	var sourceJudgmentID, createdAt, updatedAt string
	var lastReviewPromptAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT current_version, source_judgment_id, last_review_prompt_at, created_at, updated_at
		FROM expected_behavior_envelopes WHERE id=?`, envelopeID).
		Scan(&currentVersion, &sourceJudgmentID, &lastReviewPromptAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read envelope: %w", err)
	}
	out := &situationmodel.Envelope{ID: envelopeID, CurrentVersion: currentVersion, SourceJudgmentID: sourceJudgmentID}
	if out.CreatedAt, err = parseSituationTime("envelope created_at", createdAt); err != nil {
		return nil, err
	}
	if out.UpdatedAt, err = parseSituationTime("envelope updated_at", updatedAt); err != nil {
		return nil, err
	}
	if lastReviewPromptAt.Valid {
		at, err := parseSituationTime("envelope last_review_prompt_at", lastReviewPromptAt.String)
		if err != nil {
			return nil, err
		}
		out.LastReviewPromptAt = &at
	}
	if currentVersion > 0 {
		version, err := scanEnvelopeVersion(ctx, s.db, envelopeID, currentVersion)
		if err != nil {
			return nil, err
		}
		out.Version = &version
	}
	return out, nil
}

// scheduleEnvelopeChangeForActiveSituations unions envelope_changed and pulls
// next_assessment_at to now for every nonterminal Situation that has ever
// evaluated this envelope. A concurrent input-version change on a given
// Situation is skipped rather than failing the whole revocation: whatever
// concurrently changed that Situation's input already schedules its own
// reconsideration.
func scheduleEnvelopeChangeForActiveSituations(ctx context.Context, tx *sql.Tx, envelopeID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT s.id, s.due_reasons_json, s.next_assessment_at, s.input_version
		FROM situations s
		JOIN envelope_evaluations ee ON ee.situation_id = s.id
		WHERE ee.envelope_id = ? AND s.lifecycle IN ('active', 'recovery_pending')`, envelopeID)
	if err != nil {
		return fmt.Errorf("store: read situations affected by envelope revocation: %w", err)
	}
	type affected struct {
		id           string
		dueReasons   []situationmodel.DueReason
		nextAt       time.Time
		inputVersion int
	}
	var targets []affected
	for rows.Next() {
		var id, dueReasonsJSON, nextAssessmentAt string
		var inputVersion int
		if err := rows.Scan(&id, &dueReasonsJSON, &nextAssessmentAt, &inputVersion); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: scan situation affected by envelope revocation: %w", err)
		}
		var due []situationmodel.DueReason
		if err := json.Unmarshal([]byte(dueReasonsJSON), &due); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: decode due reasons for envelope revocation: %w", err)
		}
		next, err := parseSituationTime("next_assessment_at", nextAssessmentAt)
		if err != nil {
			_ = rows.Close()
			return err
		}
		targets = append(targets, affected{id: id, dueReasons: due, nextAt: next, inputVersion: inputVersion})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: iterate situations affected by envelope revocation: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: close situations affected by envelope revocation: %w", err)
	}
	for _, target := range targets {
		due := situation.MergeDueReasons(target.dueReasons, situationmodel.DueEnvelopeChanged)
		dueJSON, err := json.Marshal(due)
		if err != nil {
			return fmt.Errorf("store: marshal envelope-revocation due reasons: %w", err)
		}
		next := situation.EarlierAssessmentAt(target.nextAt, now)
		if _, err := tx.ExecContext(ctx, `UPDATE situations SET due_reasons_json=?, next_assessment_at=?, updated_at=?
			WHERE id=? AND input_version=?`, string(dueJSON), canonicalTime(next), canonicalTime(now), target.id, target.inputVersion); err != nil {
			return fmt.Errorf("store: schedule situation for envelope revocation: %w", err)
		}
	}
	return nil
}

// DueEnvelopeReviews returns active envelopes whose current version's
// review_due_at has passed and which have not been prompted within the last
// interval — the one-reminder-per-interval floor. Review due leaves the
// policy active; it is purely a reminder candidate.
func (s *Store) DueEnvelopeReviews(ctx context.Context, now time.Time, interval time.Duration, limit int) ([]situationmodel.Envelope, error) {
	if interval <= 0 || limit <= 0 {
		return nil, errors.New("store: due envelope reviews requires a positive interval and limit")
	}
	threshold := now.Add(-interval)
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.current_version, e.source_judgment_id, e.last_review_prompt_at, e.created_at, e.updated_at
		FROM expected_behavior_envelopes e
		JOIN expected_behavior_envelope_versions v ON v.envelope_id = e.id AND v.version = e.current_version
		WHERE v.status = 'active' AND v.review_due_at <= ?
		  AND (e.last_review_prompt_at IS NULL OR e.last_review_prompt_at <= ?)
		ORDER BY v.review_due_at ASC, e.id ASC
		LIMIT ?`, canonicalTime(now), canonicalTime(threshold), limit)
	if err != nil {
		return nil, fmt.Errorf("store: read due envelope reviews: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	heads := make(map[string]situationmodel.Envelope)
	for rows.Next() {
		var id, sourceJudgmentID, createdAt, updatedAt string
		var currentVersion int
		var lastReviewPromptAt sql.NullString
		if err := rows.Scan(&id, &currentVersion, &sourceJudgmentID, &lastReviewPromptAt, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: scan due envelope review: %w", err)
		}
		env := situationmodel.Envelope{ID: id, CurrentVersion: currentVersion, SourceJudgmentID: sourceJudgmentID}
		var parseErr error
		if env.CreatedAt, parseErr = parseSituationTime("envelope created_at", createdAt); parseErr != nil {
			return nil, parseErr
		}
		if env.UpdatedAt, parseErr = parseSituationTime("envelope updated_at", updatedAt); parseErr != nil {
			return nil, parseErr
		}
		if lastReviewPromptAt.Valid {
			at, parseErr := parseSituationTime("envelope last_review_prompt_at", lastReviewPromptAt.String)
			if parseErr != nil {
				return nil, parseErr
			}
			env.LastReviewPromptAt = &at
		}
		heads[id] = env
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate due envelope reviews: %w", err)
	}
	out := make([]situationmodel.Envelope, 0, len(ids))
	for _, id := range ids {
		env := heads[id]
		version, err := scanEnvelopeVersion(ctx, s.db, id, env.CurrentVersion)
		if err != nil {
			return nil, err
		}
		env.Version = &version
		out = append(out, env)
	}
	return out, nil
}

// MarkEnvelopeReviewPrompted records that a review reminder was created for
// envelopeID at now, so DueEnvelopeReviews does not surface it again until
// another full interval has elapsed.
func (s *Store) MarkEnvelopeReviewPrompted(ctx context.Context, envelopeID string, now time.Time) error {
	if strings.TrimSpace(envelopeID) == "" || now.IsZero() {
		return errors.New("store: marking an envelope review prompted requires an id and time")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE expected_behavior_envelopes SET last_review_prompt_at=?, updated_at=? WHERE id=?`,
		canonicalTime(now), canonicalTime(now), envelopeID)
	if err != nil {
		return fmt.Errorf("store: mark envelope review prompted: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count marked envelope review prompt: %w", err)
	}
	if changed != 1 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Envelope evaluations
// ---------------------------------------------------------------------

// AppendEnvelopeEvaluation idempotently appends one deterministic evaluation
// attempt. Exact replay (identical id and content) succeeds; a reused id
// with different content fails closed.
func (s *Store) AppendEnvelopeEvaluation(ctx context.Context, e situationmodel.EnvelopeEvaluation) error {
	return s.appendEnvelopeEvaluation(ctx, e, nil, nil)
}

// AppendEnvelopeEvaluationWithAudit atomically appends one deterministic
// evaluation attempt and writes every required audit event in the same
// transaction, matching RecordJudgment/ConfirmEnvelope/RevokeEnvelope's
// mandatory-audit requirement for every judgment/envelope write.
func (s *Store) AppendEnvelopeEvaluationWithAudit(ctx context.Context, e situationmodel.EnvelopeEvaluation, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) error {
	if auditor == nil || len(events) == 0 {
		return errors.New("store: envelope evaluation audit is required")
	}
	return s.appendEnvelopeEvaluation(ctx, e, auditor, events)
}

func (s *Store) appendEnvelopeEvaluation(ctx context.Context, e situationmodel.EnvelopeEvaluation, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) error {
	prepared, err := prepareEnvelopeEvaluation(e)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin append envelope evaluation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO envelope_evaluations (
		id, envelope_id, envelope_version, situation_id, input_version, result,
		matched_fields_json, violations_json, observability_json,
		schedule_window_start, schedule_window_end, quieting_authority, created_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		prepared.id, prepared.envelopeID, prepared.envelopeVersion, prepared.situationID, prepared.inputVersion, prepared.result,
		prepared.matchedFieldsJSON, prepared.violationsJSON, prepared.observabilityJSON,
		nullableTimeString(prepared.scheduleWindowStart), nullableTimeString(prepared.scheduleWindowEnd), prepared.quietingAuthority, prepared.createdAt)
	if err != nil {
		return fmt.Errorf("store: append envelope evaluation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count envelope evaluation append: %w", err)
	}
	if changed == 0 {
		existing, err := readPreparedEnvelopeEvaluation(ctx, tx, e.ID)
		if err != nil {
			return err
		}
		if existing != prepared {
			return errors.New("store: envelope evaluation identity collision")
		}
	}
	if auditor != nil {
		if err := appendSituationPolicyAuditEvents(ctx, tx, auditor, events); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit append envelope evaluation: %w", err)
	}
	return nil
}

type preparedEnvelopeEvaluation struct {
	id, envelopeID, situationID, result                  string
	matchedFieldsJSON, violationsJSON, observabilityJSON string
	scheduleWindowStart, scheduleWindowEnd               string
	createdAt                                            string
	envelopeVersion, inputVersion, quietingAuthority     int
}

func prepareEnvelopeEvaluation(e situationmodel.EnvelopeEvaluation) (preparedEnvelopeEvaluation, error) {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.EnvelopeID) == "" || e.EnvelopeVersion < 1 ||
		strings.TrimSpace(e.SituationID) == "" || e.InputVersion < 1 || e.CreatedAt.IsZero() || e.CreatedAt.Location() != time.UTC {
		return preparedEnvelopeEvaluation{}, errors.New("store: envelope evaluation requires identity and a canonical creation time")
	}
	switch e.Result {
	case situationmodel.EnvelopeEvaluationMatch, situationmodel.EnvelopeEvaluationViolation,
		situationmodel.EnvelopeEvaluationAuthorityRemoved, situationmodel.EnvelopeEvaluationNotApplicable:
	default:
		return preparedEnvelopeEvaluation{}, fmt.Errorf("store: envelope evaluation result %q is invalid", e.Result)
	}
	if e.QuietingAuthority && e.Result != situationmodel.EnvelopeEvaluationMatch {
		return preparedEnvelopeEvaluation{}, errors.New("store: only a matched envelope evaluation may carry quieting authority")
	}
	if (e.ScheduleWindowStart == nil) != (e.ScheduleWindowEnd == nil) {
		return preparedEnvelopeEvaluation{}, errors.New("store: envelope evaluation schedule window requires both start and end or neither")
	}
	var scheduleStart, scheduleEnd string
	if e.ScheduleWindowStart != nil {
		if e.ScheduleWindowStart.IsZero() || e.ScheduleWindowStart.Location() != time.UTC ||
			e.ScheduleWindowEnd.IsZero() || e.ScheduleWindowEnd.Location() != time.UTC {
			return preparedEnvelopeEvaluation{}, errors.New("store: envelope evaluation schedule window must be canonical utc times")
		}
		if !e.ScheduleWindowStart.Before(*e.ScheduleWindowEnd) {
			return preparedEnvelopeEvaluation{}, errors.New("store: envelope evaluation schedule window start must precede end")
		}
		scheduleStart = canonicalTime(*e.ScheduleWindowStart)
		scheduleEnd = canonicalTime(*e.ScheduleWindowEnd)
	}
	matched, violations, observability := e.MatchedFields, e.Violations, e.Observability
	if matched == nil {
		matched = []string{}
	}
	if violations == nil {
		violations = []string{}
	}
	if observability == nil {
		observability = []string{}
	}
	matchedJSON, err := json.Marshal(matched)
	if err != nil {
		return preparedEnvelopeEvaluation{}, fmt.Errorf("store: marshal envelope evaluation matched fields: %w", err)
	}
	violationsJSON, err := json.Marshal(violations)
	if err != nil {
		return preparedEnvelopeEvaluation{}, fmt.Errorf("store: marshal envelope evaluation violations: %w", err)
	}
	observabilityJSON, err := json.Marshal(observability)
	if err != nil {
		return preparedEnvelopeEvaluation{}, fmt.Errorf("store: marshal envelope evaluation observability: %w", err)
	}
	return preparedEnvelopeEvaluation{
		id: e.ID, envelopeID: e.EnvelopeID, envelopeVersion: e.EnvelopeVersion, situationID: e.SituationID, inputVersion: e.InputVersion,
		result: string(e.Result), matchedFieldsJSON: string(matchedJSON), violationsJSON: string(violationsJSON), observabilityJSON: string(observabilityJSON),
		scheduleWindowStart: scheduleStart, scheduleWindowEnd: scheduleEnd,
		quietingAuthority: boolInt(e.QuietingAuthority), createdAt: canonicalTime(e.CreatedAt),
	}, nil
}

func readPreparedEnvelopeEvaluation(ctx context.Context, tx *sql.Tx, id string) (preparedEnvelopeEvaluation, error) {
	var out preparedEnvelopeEvaluation
	var scheduleStart, scheduleEnd sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id, envelope_id, envelope_version, situation_id, input_version, result,
		matched_fields_json, violations_json, observability_json,
		schedule_window_start, schedule_window_end, quieting_authority, created_at
		FROM envelope_evaluations WHERE id=?`, id).
		Scan(&out.id, &out.envelopeID, &out.envelopeVersion, &out.situationID, &out.inputVersion, &out.result,
			&out.matchedFieldsJSON, &out.violationsJSON, &out.observabilityJSON,
			&scheduleStart, &scheduleEnd, &out.quietingAuthority, &out.createdAt)
	if err != nil {
		return preparedEnvelopeEvaluation{}, fmt.Errorf("store: read envelope evaluation replay: %w", err)
	}
	out.scheduleWindowStart = scheduleStart.String
	out.scheduleWindowEnd = scheduleEnd.String
	return out, nil
}

// nullableTimeString converts a canonical time string ("" meaning unset)
// into a SQL argument: NULL when unset, the string itself otherwise.
func nullableTimeString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ---------------------------------------------------------------------
// Shared audit helpers
// ---------------------------------------------------------------------

func appendSituationPolicyAuditEvents(ctx context.Context, tx *sql.Tx, auditor SituationPolicyAuditAppender, events []SituationPolicyAuditEvent) error {
	for _, event := range events {
		if strings.TrimSpace(event.Kind) == "" {
			return errors.New("store: situation policy audit kind is required")
		}
		if err := auditor.AppendTx(ctx, tx, situationPolicyAuditActor, event.Kind, event.Payload); err != nil {
			return fmt.Errorf("store: append situation policy audit: %w", err)
		}
	}
	return nil
}

// auditSituationPolicyRejection best-effort audits a rejected optimistic
// write in its own committed transaction — the write's own transaction is
// about to roll back, but the fact that it was rejected must still survive.
// A failure here never masks or replaces the original rejection error.
func (s *Store) auditSituationPolicyRejection(ctx context.Context, auditor SituationPolicyAuditAppender, kind string, payload map[string]any) {
	if auditor == nil {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := auditor.AppendTx(ctx, tx, situationPolicyAuditActor, kind, payload); err != nil {
		return
	}
	_ = tx.Commit()
}

// ---------------------------------------------------------------------
// Read views (MCP alertint_expected_behavior_list/alertint_situation_get)
// ---------------------------------------------------------------------

// ListEnvelopes returns every Expected-behaviour envelope's current head,
// including revoked/invalidated ones — envelopes never expire automatically
// and their history stays visible.
func (s *Store) ListEnvelopes(ctx context.Context) ([]situationmodel.Envelope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM expected_behavior_envelopes ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list envelopes: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan envelope id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store: iterate envelope ids: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: close envelope id list: %w", err)
	}
	out := make([]situationmodel.Envelope, 0, len(ids))
	for _, id := range ids {
		head, err := s.Envelope(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, *head)
	}
	return out, nil
}

// SituationJudgments returns the Situation's append-only operator judgments,
// oldest first.
func (s *Store) SituationJudgments(ctx context.Context, situationID string) ([]situationmodel.Judgment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, situation_id, judged_input_version, covered_fact_hash, covered_symptoms_json,
		covered_impact_json, judgment, basis, workload, valid_until, evidence_refs_json, authenticated_as, asserted_operator, created_at
		FROM situation_judgments WHERE situation_id = ? ORDER BY created_at ASC, id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation judgments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []situationmodel.Judgment
	for rows.Next() {
		var j situationmodel.Judgment
		var symptomsJSON, impactJSON, evidenceRefsJSON, createdAt string
		var workload, validUntil sql.NullString
		if err := rows.Scan(&j.ID, &j.SituationID, &j.JudgedInputVersion, &j.CoveredFactHash, &symptomsJSON,
			&impactJSON, &j.Judgment, &j.Basis, &workload, &validUntil, &evidenceRefsJSON, &j.AuthenticatedAs, &j.AssertedOperator, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan situation judgment: %w", err)
		}
		if err := json.Unmarshal([]byte(symptomsJSON), &j.CoveredSymptoms); err != nil {
			return nil, fmt.Errorf("store: decode judgment covered symptoms: %w", err)
		}
		if err := json.Unmarshal([]byte(impactJSON), &j.CoveredImpact); err != nil {
			return nil, fmt.Errorf("store: decode judgment covered impact: %w", err)
		}
		if err := json.Unmarshal([]byte(evidenceRefsJSON), &j.EvidenceRefs); err != nil {
			return nil, fmt.Errorf("store: decode judgment evidence refs: %w", err)
		}
		if workload.Valid {
			w := workload.String
			j.Workload = &w
		}
		if validUntil.Valid {
			at, err := parseSituationTime("judgment valid_until", validUntil.String)
			if err != nil {
				return nil, err
			}
			j.ValidUntil = &at
		}
		if j.CreatedAt, err = parseSituationTime("judgment created_at", createdAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation judgments: %w", err)
	}
	return out, nil
}

// SituationEnvelopeEvaluations returns the Situation's deterministic
// envelope-evaluation audit trail, oldest first.
func (s *Store) SituationEnvelopeEvaluations(ctx context.Context, situationID string) ([]situationmodel.EnvelopeEvaluation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, envelope_id, envelope_version, situation_id, input_version, result,
		matched_fields_json, violations_json, observability_json, schedule_window_start, schedule_window_end, quieting_authority, created_at
		FROM envelope_evaluations WHERE situation_id = ? ORDER BY created_at ASC, id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation envelope evaluations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []situationmodel.EnvelopeEvaluation
	for rows.Next() {
		var e situationmodel.EnvelopeEvaluation
		var matchedJSON, violationsJSON, observabilityJSON, createdAt string
		var scheduleStart, scheduleEnd sql.NullString
		var quietingAuthority int
		if err := rows.Scan(&e.ID, &e.EnvelopeID, &e.EnvelopeVersion, &e.SituationID, &e.InputVersion, &e.Result,
			&matchedJSON, &violationsJSON, &observabilityJSON, &scheduleStart, &scheduleEnd, &quietingAuthority, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan situation envelope evaluation: %w", err)
		}
		if err := json.Unmarshal([]byte(matchedJSON), &e.MatchedFields); err != nil {
			return nil, fmt.Errorf("store: decode envelope evaluation matched fields: %w", err)
		}
		if err := json.Unmarshal([]byte(violationsJSON), &e.Violations); err != nil {
			return nil, fmt.Errorf("store: decode envelope evaluation violations: %w", err)
		}
		if err := json.Unmarshal([]byte(observabilityJSON), &e.Observability); err != nil {
			return nil, fmt.Errorf("store: decode envelope evaluation observability: %w", err)
		}
		e.QuietingAuthority = quietingAuthority != 0
		if scheduleStart.Valid {
			at, err := parseSituationTime("envelope evaluation schedule_window_start", scheduleStart.String)
			if err != nil {
				return nil, err
			}
			e.ScheduleWindowStart = &at
		}
		if scheduleEnd.Valid {
			at, err := parseSituationTime("envelope evaluation schedule_window_end", scheduleEnd.String)
			if err != nil {
				return nil, err
			}
			e.ScheduleWindowEnd = &at
		}
		if e.CreatedAt, err = parseSituationTime("envelope evaluation created_at", createdAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation envelope evaluations: %w", err)
	}
	return out, nil
}
