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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

var (
	ErrSituationJudgmentRequestConflict = errors.New("store: situation judgment request identity reused with different arguments")
	ErrSituationJudgmentVersionConflict = errors.New("store: situation judgment version conflict")
	ErrSituationJudgmentNotAllowed      = errors.New("store: situation judgment not allowed")
	ErrSituationJudgmentStale           = errors.New("store: situation judgment authority changed or expired")
)

// AuditTx is the transaction type accepted by JudgmentAuditAppender.
type AuditTx = *sql.Tx

// JudgmentAuditAppender writes the audit row inside the judgment transaction.
type JudgmentAuditAppender interface {
	AppendTx(context.Context, *sql.Tx, string, string, any, time.Time) error
}

// SituationJudgmentWrite is the fenced MCP command shape shared by record,
// replace, revoke and restore.
type SituationJudgmentWrite struct {
	Operation               model.JudgmentOperation
	SituationID             string
	SituationInputVersion   int
	ExpectedJudgmentVersion int
	RequestID               string
	AssertedOperator        string
	Confirmed               bool
	ValidUntil              time.Time
	Now                     time.Time
}

type SituationJudgmentWriteResult struct {
	Judgment              model.SituationJudgment `json:"judgment"`
	SituationInputVersion int                     `json:"situation_input_version"`
	IdempotentReplay      bool                    `json:"idempotent_replay"`
}

type SituationJudgmentView struct {
	Judgment      model.SituationJudgment     `json:"judgment"`
	Applicability model.JudgmentApplicability `json:"applicability"`
}

func (s *Store) WriteSituationJudgment(ctx context.Context, auditor JudgmentAuditAppender, req SituationJudgmentWrite) (SituationJudgmentWriteResult, error) {
	if auditor == nil {
		return SituationJudgmentWriteResult{}, errors.New("store: situation judgment requires an atomic auditor")
	}
	if err := validateSituationJudgmentWrite(req); err != nil {
		return SituationJudgmentWriteResult{}, err
	}
	hash, err := situationJudgmentRequestHash(req)
	if err != nil {
		return SituationJudgmentWriteResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: begin situation judgment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if prior, found, err := readSituationJudgmentByRequestTx(ctx, tx, req.RequestID); err != nil {
		return SituationJudgmentWriteResult{}, err
	} else if found {
		if prior.requestHash != hash {
			return SituationJudgmentWriteResult{}, ErrSituationJudgmentRequestConflict
		}
		return SituationJudgmentWriteResult{Judgment: prior.judgment, SituationInputVersion: prior.resultInputVersion, IdempotentReplay: true}, nil
	}
	if req.Operation != model.JudgmentOperationRevoke && !req.ValidUntil.After(req.Now) {
		return SituationJudgmentWriteResult{}, errors.New("store: situation judgment valid_until must be in the future")
	}

	in, err := loadSituationJudgmentInputTx(ctx, tx, req.SituationID, req.Now)
	if err != nil {
		return SituationJudgmentWriteResult{}, err
	}
	if in.Situation.InputVersion != req.SituationInputVersion {
		return SituationJudgmentWriteResult{}, ErrSituationVersionConflict
	}
	if in.Situation.Lifecycle.Terminal() {
		return SituationJudgmentWriteResult{}, fmt.Errorf("%w: terminal situations cannot receive judgments", ErrSituationJudgmentNotAllowed)
	}
	head, hasHead, err := readSituationJudgmentHeadTx(ctx, tx, req.SituationID)
	if err != nil {
		return SituationJudgmentWriteResult{}, err
	}
	actualVersion := 0
	if hasHead {
		actualVersion = head.Revision
	}
	if actualVersion != req.ExpectedJudgmentVersion {
		return SituationJudgmentWriteResult{}, fmt.Errorf("%w: current version is %d", ErrSituationJudgmentVersionConflict, actualVersion)
	}
	if err := validateJudgmentOperation(req.Operation, hasHead, head.State); err != nil {
		return SituationJudgmentWriteResult{}, err
	}

	state := model.JudgmentStateExpected
	coverage := head.Coverage
	validUntil := head.ValidUntil
	if req.Operation == model.JudgmentOperationRevoke {
		state = model.JudgmentStateRevoked
	} else {
		coverage, err = situation.DeriveExpectedJudgmentCoverage(in)
		if err != nil {
			return SituationJudgmentWriteResult{}, fmt.Errorf("%w: %v", ErrSituationJudgmentNotAllowed, err)
		}
		probe := model.SituationJudgment{State: model.JudgmentStateExpected, ValidUntil: req.ValidUntil, Coverage: coverage}
		app := situation.EvaluateExpectedJudgment(probe, in, req.Now)
		if !app.Applicable {
			return SituationJudgmentWriteResult{}, fmt.Errorf("%w: current condition is %s", ErrSituationJudgmentNotAllowed, app.Reason)
		}
		validUntil = req.ValidUntil.UTC()
	}

	revision := actualVersion + 1
	newVersion := req.SituationInputVersion + 1
	judgment := model.SituationJudgment{
		ID: uuid.NewString(), SituationID: req.SituationID, Revision: revision,
		Operation: req.Operation, State: state, AssertedOperator: strings.TrimSpace(req.AssertedOperator),
		TrustDomain: model.JudgmentTrustAuthenticatedMCP, RequestID: req.RequestID,
		ValidUntil: validUntil, Coverage: coverage, CreatedAt: req.Now.UTC(),
	}
	coverageJSON, err := json.Marshal(coverage)
	if err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: marshal situation judgment coverage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_judgments (
			id, situation_id, revision, operation, state, asserted_operator, trust_domain,
			request_id, request_hash, result_input_version, valid_until, coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, judgment.ID, judgment.SituationID, judgment.Revision, judgment.Operation, judgment.State,
		judgment.AssertedOperator, judgment.TrustDomain, judgment.RequestID, hash,
		newVersion, canonicalTime(judgment.ValidUntil), string(coverageJSON), canonicalTime(judgment.CreatedAt)); err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: insert situation judgment: %w", err)
	}
	if hasHead {
		res, err := tx.ExecContext(ctx, `UPDATE situation_judgment_heads SET judgment_id=?, revision=?, updated_at=?, invalidated_at=NULL, invalidation_reason=NULL WHERE situation_id=? AND revision=?`,
			judgment.ID, revision, canonicalTime(req.Now), req.SituationID, actualVersion)
		if err != nil {
			return SituationJudgmentWriteResult{}, fmt.Errorf("store: advance situation judgment head: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return SituationJudgmentWriteResult{}, ErrSituationJudgmentVersionConflict
		}
	} else if _, err := tx.ExecContext(ctx, `INSERT INTO situation_judgment_heads (situation_id, judgment_id, revision, updated_at) VALUES (?, ?, ?, ?)`,
		req.SituationID, judgment.ID, revision, canonicalTime(req.Now)); err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: create situation judgment head: %w", err)
	}

	due := mergeDueReason(in.Situation.DueReasons, model.DueOperatorJudgment)
	due = mergeDueReason(due, model.DueJudgmentBoundary)
	dueJSON, _ := json.Marshal(due)
	res, err := tx.ExecContext(ctx, `
		UPDATE situations SET input_version=input_version+1, next_assessment_at=?, due_reasons_json=?,
			lease_owner=NULL, lease_expires_at=NULL, retry_at=NULL, updated_at=?
		WHERE id=? AND input_version=? AND lifecycle IN ('active','recovery_pending')
	`, canonicalTime(req.Now), string(dueJSON), canonicalTime(req.Now), req.SituationID, req.SituationInputVersion)
	if err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: wake situation for judgment: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return SituationJudgmentWriteResult{}, ErrSituationVersionConflict
	}
	payload := map[string]any{
		"situation_id": req.SituationID, "judgment_id": judgment.ID, "revision": revision,
		"operation": req.Operation, "asserted_operator": judgment.AssertedOperator,
		"trust_domain": judgment.TrustDomain, "valid_until": judgment.ValidUntil,
		"request_id": req.RequestID, "situation_input_version": newVersion,
	}
	if err := auditor.AppendTx(ctx, tx, "mcp", "situation.judgment."+string(req.Operation), payload, req.Now); err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: audit situation judgment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SituationJudgmentWriteResult{}, fmt.Errorf("store: commit situation judgment: %w", err)
	}
	return SituationJudgmentWriteResult{Judgment: judgment, SituationInputVersion: newVersion}, nil
}

func validateSituationJudgmentWrite(req SituationJudgmentWrite) error {
	if strings.TrimSpace(req.SituationID) == "" || req.SituationInputVersion < 1 || req.ExpectedJudgmentVersion < 0 ||
		strings.TrimSpace(req.RequestID) == "" || strings.TrimSpace(req.AssertedOperator) == "" {
		return errors.New("store: situation judgment requires situation, versions, request identity, and asserted operator")
	}
	if !req.Confirmed {
		return errors.New("store: situation judgment requires explicit confirmation")
	}
	if req.Now.IsZero() {
		return errors.New("store: situation judgment requires current time")
	}
	switch req.Operation {
	case model.JudgmentOperationRecord, model.JudgmentOperationReplace, model.JudgmentOperationRestore:
		if req.ValidUntil.IsZero() {
			return errors.New("store: situation judgment valid_until is required")
		}
	case model.JudgmentOperationRevoke:
	default:
		return fmt.Errorf("store: unknown situation judgment operation %q", req.Operation)
	}
	return nil
}

func validateJudgmentOperation(op model.JudgmentOperation, hasHead bool, state model.JudgmentState) error {
	switch op {
	case model.JudgmentOperationRecord:
		if hasHead {
			return fmt.Errorf("%w: record requires no judgment history", ErrSituationJudgmentNotAllowed)
		}
	case model.JudgmentOperationReplace, model.JudgmentOperationRevoke:
		if !hasHead || state != model.JudgmentStateExpected {
			return fmt.Errorf("%w: %s requires active expectedness", ErrSituationJudgmentNotAllowed, op)
		}
	case model.JudgmentOperationRestore:
		if !hasHead || state != model.JudgmentStateRevoked {
			return fmt.Errorf("%w: restore requires a revoked head", ErrSituationJudgmentNotAllowed)
		}
	}
	return nil
}

func situationJudgmentRequestHash(req SituationJudgmentWrite) (string, error) {
	canonical := struct {
		Operation               model.JudgmentOperation `json:"operation"`
		SituationID             string                  `json:"situation_id"`
		SituationInputVersion   int                     `json:"situation_input_version"`
		ExpectedJudgmentVersion int                     `json:"expected_judgment_version"`
		RequestID               string                  `json:"request_id"`
		AssertedOperator        string                  `json:"asserted_operator"`
		Confirmed               bool                    `json:"confirmed"`
		ValidUntil              time.Time               `json:"valid_until"`
	}{req.Operation, req.SituationID, req.SituationInputVersion, req.ExpectedJudgmentVersion, req.RequestID, strings.TrimSpace(req.AssertedOperator), req.Confirmed, req.ValidUntil.UTC()}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("store: marshal situation judgment request: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type persistedJudgment struct {
	judgment           model.SituationJudgment
	requestHash        string
	resultInputVersion int
}

func readSituationJudgmentByRequestTx(ctx context.Context, tx *sql.Tx, requestID string) (persistedJudgment, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT id,situation_id,revision,operation,state,asserted_operator,trust_domain,request_id,request_hash,result_input_version,valid_until,coverage_json,created_at FROM situation_judgments WHERE request_id=?`, requestID)
	p, err := scanSituationJudgment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedJudgment{}, false, nil
	}
	if err != nil {
		return persistedJudgment{}, false, err
	}
	return p, true, nil
}

func readSituationJudgmentHeadTx(ctx context.Context, tx *sql.Tx, situationID string) (model.SituationJudgment, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT j.id,j.situation_id,j.revision,j.operation,j.state,j.asserted_operator,j.trust_domain,j.request_id,j.request_hash,j.result_input_version,j.valid_until,j.coverage_json,j.created_at FROM situation_judgment_heads h JOIN situation_judgments j ON j.id=h.judgment_id WHERE h.situation_id=?`, situationID)
	p, err := scanSituationJudgment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SituationJudgment{}, false, nil
	}
	if err != nil {
		return model.SituationJudgment{}, false, err
	}
	return p.judgment, true, nil
}

func readSituationJudgmentInvalidationTx(ctx context.Context, tx *sql.Tx, situationID string) (model.JudgmentApplicabilityReason, bool, error) {
	var reason sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT invalidation_reason FROM situation_judgment_heads WHERE situation_id=?`, situationID).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return model.JudgmentApplicabilityReason(reason.String), reason.Valid, nil
}

type rowScanner interface{ Scan(...any) error }

func scanSituationJudgment(row rowScanner) (persistedJudgment, error) {
	var p persistedJudgment
	var operation, state, trust, validUntil, coverageJSON, createdAt string
	if err := row.Scan(&p.judgment.ID, &p.judgment.SituationID, &p.judgment.Revision, &operation, &state, &p.judgment.AssertedOperator, &trust, &p.judgment.RequestID, &p.requestHash, &p.resultInputVersion, &validUntil, &coverageJSON, &createdAt); err != nil {
		return persistedJudgment{}, err
	}
	p.judgment.Operation, p.judgment.State, p.judgment.TrustDomain = model.JudgmentOperation(operation), model.JudgmentState(state), model.JudgmentTrustDomain(trust)
	var err error
	if p.judgment.ValidUntil, err = time.Parse(time.RFC3339Nano, validUntil); err != nil {
		return persistedJudgment{}, fmt.Errorf("store: parse judgment valid_until: %w", err)
	}
	if p.judgment.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return persistedJudgment{}, fmt.Errorf("store: parse judgment created_at: %w", err)
	}
	if err := json.Unmarshal([]byte(coverageJSON), &p.judgment.Coverage); err != nil {
		return persistedJudgment{}, fmt.Errorf("store: unmarshal judgment coverage: %w", err)
	}
	return p, nil
}

func loadSituationJudgmentInputTx(ctx context.Context, tx *sql.Tx, situationID string, now time.Time) (situation.SnapshotInput, error) {
	sit, err := getSituationTx(ctx, tx, situationID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}
	deliveries, err := loadSituationDeliveriesTx(ctx, tx, situationID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}
	assessment, err := loadCurrentAssessmentTx(ctx, tx, situationID)
	if err != nil {
		return situation.SnapshotInput{}, err
	}
	return situation.SnapshotInput{Situation: sit, Deliveries: deliveries, CurrentAssessment: assessment, Now: now.UTC()}, nil
}

func (s *Store) GetCurrentSituationJudgment(ctx context.Context, situationID string, now time.Time) (*SituationJudgmentView, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	j, ok, err := readSituationJudgmentHeadTx(ctx, tx, situationID)
	if err != nil || !ok {
		return nil, err
	}
	in, err := loadSituationJudgmentInputTx(ctx, tx, situationID, now)
	if err != nil {
		return nil, err
	}
	invalidated, hasInvalidation, err := readSituationJudgmentInvalidationTx(ctx, tx, situationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	app := situation.EvaluateExpectedJudgment(j, in, now.UTC())
	if hasInvalidation {
		app = model.JudgmentApplicability{Reason: invalidated}
	}
	return &SituationJudgmentView{Judgment: j, Applicability: app}, nil
}

func (s *Store) ListSituationJudgments(ctx context.Context, situationID string, afterRevision, limit int) ([]model.SituationJudgment, error) {
	// MCP reads one look-ahead row to decide whether a next cursor exists.
	if limit < 1 || limit > 101 {
		limit = 100
	}
	if afterRevision < 0 {
		afterRevision = 0
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,situation_id,revision,operation,state,asserted_operator,trust_domain,request_id,request_hash,result_input_version,valid_until,coverage_json,created_at FROM situation_judgments WHERE situation_id=? AND revision>? ORDER BY revision ASC LIMIT ?`, situationID, afterRevision, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []model.SituationJudgment{}
	for rows.Next() {
		p, err := scanSituationJudgment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p.judgment)
	}
	return out, rows.Err()
}

func verifySituationJudgmentFenceTx(ctx context.Context, tx *sql.Tx, situationID string, commit situation.ControllerCommit) error {
	head, ok, err := readSituationJudgmentHeadTx(ctx, tx, situationID)
	if err != nil {
		return err
	}
	currentRevision := 0
	if ok {
		currentRevision = head.Revision
	}
	if currentRevision != commit.JudgmentRevision {
		return ErrSituationJudgmentStale
	}
	if commit.JudgmentApplicable {
		_, invalidated, err := readSituationJudgmentInvalidationTx(ctx, tx, situationID)
		if err != nil {
			return err
		}
		if !ok || invalidated || head.State != model.JudgmentStateExpected || !commit.JudgmentCheckedAt.Before(head.ValidUntil) {
			return ErrSituationJudgmentStale
		}
	}
	return nil
}

func persistSituationJudgmentInvalidationTx(ctx context.Context, tx *sql.Tx, situationID string, commit situation.ControllerCommit) error {
	if commit.JudgmentRevision == 0 || commit.JudgmentApplicable {
		return nil
	}
	switch commit.JudgmentApplicabilityReason {
	case "", model.JudgmentApplicable, model.JudgmentExpired, model.JudgmentRevoked, model.JudgmentSituationTerminal:
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE situation_judgment_heads
		SET invalidated_at=COALESCE(invalidated_at, ?), invalidation_reason=COALESCE(invalidation_reason, ?), updated_at=?
		WHERE situation_id=? AND revision=?`,
		canonicalTime(commit.JudgmentCheckedAt), string(commit.JudgmentApplicabilityReason), canonicalTime(commit.JudgmentCheckedAt),
		situationID, commit.JudgmentRevision)
	return err
}

// persistObservedSituationJudgmentInvalidationTx retires authority as part of
// the same transaction that makes changed source facts observable. This keeps
// a short-lived added symptom, severity escalation, or source-signature change
// from disappearing before the controller can durably observe it and thereby
// silently reviving an older judgment.
func persistObservedSituationJudgmentInvalidationTx(ctx context.Context, tx *sql.Tx, situationID string, now time.Time) error {
	head, ok, err := readSituationJudgmentHeadTx(ctx, tx, situationID)
	if err != nil || !ok || head.State != model.JudgmentStateExpected {
		return err
	}
	if _, invalidated, err := readSituationJudgmentInvalidationTx(ctx, tx, situationID); err != nil || invalidated {
		return err
	}
	in, err := loadSituationJudgmentInputTx(ctx, tx, situationID, now)
	if err != nil {
		return err
	}
	app := situation.EvaluateExpectedJudgment(head, in, now.UTC())
	if app.Applicable {
		return nil
	}
	switch app.Reason {
	case "", model.JudgmentApplicable, model.JudgmentExpired, model.JudgmentRevoked, model.JudgmentSituationTerminal:
		return nil
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE situation_judgment_heads
		SET invalidated_at=?, invalidation_reason=?, updated_at=?
		WHERE situation_id=? AND revision=? AND invalidated_at IS NULL`,
		canonicalTime(now), string(app.Reason), canonicalTime(now), situationID, head.Revision)
	return err
}
