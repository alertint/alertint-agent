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
	ErrExpectedBehaviorRequestConflict = errors.New("store: expected behavior request identity reused with different arguments")
	ErrExpectedBehaviorVersionConflict = errors.New("store: expected behavior version conflict")
	ErrExpectedBehaviorNotAllowed      = errors.New("store: expected behavior operation not allowed")
	ErrExpectedBehaviorStale           = errors.New("store: expected behavior authority changed")
)

// ExpectedBehaviorWrite is one explicitly confirmed, version-fenced command.
type ExpectedBehaviorWrite struct {
	Operation              model.ExpectedBehaviorOperation
	EnvelopeID             string
	SourceJudgmentID       string
	ValidationID           string
	SituationID            string
	SituationInputVersion  int
	ExpectedCurrentVersion int
	RequestID              string
	AssertedOperator       string
	Confirmed              bool
	Policy                 *model.ExpectedBehaviorPolicy
	Now                    time.Time
}

type ExpectedBehaviorWriteResult struct {
	Revision           model.ExpectedBehaviorRevision `json:"revision"`
	Head               model.ExpectedBehaviorHead     `json:"head"`
	AffectedSituations []string                       `json:"affected_situations"`
	IdempotentReplay   bool                           `json:"idempotent_replay"`
}

type persistedExpectedBehaviorRevision struct {
	revision    model.ExpectedBehaviorRevision
	requestHash string
}

// ExpectedBehaviorListFilter selects current envelope heads.
type ExpectedBehaviorListFilter struct {
	GroupKey         string
	SourceInstanceID string
	TriggerID        string
	IncludeInactive  bool
}

// WriteExpectedBehavior appends one immutable revision, advances its head,
// appends audit, and wakes exactly affected open Situations in one transaction.
//
//nolint:gocyclo // the version, source-proof, idempotency, audit, and wake fences intentionally share one transaction
func (s *Store) WriteExpectedBehavior(ctx context.Context, auditor JudgmentAuditAppender, req ExpectedBehaviorWrite) (ExpectedBehaviorWriteResult, error) {
	if auditor == nil {
		return ExpectedBehaviorWriteResult{}, errors.New("store: expected behavior requires an atomic auditor")
	}
	if err := validateExpectedBehaviorWrite(req); err != nil {
		return ExpectedBehaviorWriteResult{}, err
	}
	requestHash, err := expectedBehaviorRequestHash(req)
	if err != nil {
		return ExpectedBehaviorWriteResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: begin expected behavior: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if prior, found, err := readExpectedBehaviorRevisionByRequestTx(ctx, tx, req.RequestID); err != nil {
		return ExpectedBehaviorWriteResult{}, err
	} else if found {
		if prior.requestHash != requestHash {
			return ExpectedBehaviorWriteResult{}, ErrExpectedBehaviorRequestConflict
		}
		head, err := readExpectedBehaviorHeadTx(ctx, tx, prior.revision.EnvelopeID)
		if err != nil {
			return ExpectedBehaviorWriteResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return ExpectedBehaviorWriteResult{}, err
		}
		return ExpectedBehaviorWriteResult{Revision: prior.revision, Head: head, IdempotentReplay: true}, nil
	}

	envelopeID := strings.TrimSpace(req.EnvelopeID)
	var priorHead model.ExpectedBehaviorHead
	hasHead := false
	if envelopeID != "" {
		priorHead, err = readExpectedBehaviorHeadTx(ctx, tx, envelopeID)
		if errors.Is(err, ErrNotFound) {
			err = nil
		} else if err != nil {
			return ExpectedBehaviorWriteResult{}, err
		} else {
			hasHead = true
		}
	}
	actualVersion := 0
	if hasHead {
		actualVersion = priorHead.Version
	}
	if actualVersion != req.ExpectedCurrentVersion {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("%w: current version is %d", ErrExpectedBehaviorVersionConflict, actualVersion)
	}
	if err := validateExpectedBehaviorOperation(req.Operation, hasHead, priorHead); err != nil {
		return ExpectedBehaviorWriteResult{}, err
	}

	state := model.ExpectedBehaviorStateActive
	policy := req.Policy
	sourceJudgmentID, sourceSituationID := req.SourceJudgmentID, req.SituationID
	if req.Operation == model.ExpectedBehaviorOperationRevoke {
		state, policy = model.ExpectedBehaviorStateRevoked, nil
		sourceJudgmentID, sourceSituationID = "", ""
	} else {
		if err := situation.ValidateExpectedBehaviorPolicy(*policy, req.Now); err != nil {
			return ExpectedBehaviorWriteResult{}, fmt.Errorf("%w: %v", ErrExpectedBehaviorNotAllowed, err)
		}
		if err := verifyExpectedBehaviorSourceTx(ctx, tx, req); err != nil {
			return ExpectedBehaviorWriteResult{}, err
		}
	}
	if !hasHead {
		envelopeID = uuid.NewString()
	}
	version := actualVersion + 1
	revision := model.ExpectedBehaviorRevision{
		ID: uuid.NewString(), EnvelopeID: envelopeID, Version: version, Operation: req.Operation, State: state,
		Policy: policy, SourceJudgmentID: sourceJudgmentID, SourceSituationID: sourceSituationID,
		AssertedOperator: strings.TrimSpace(req.AssertedOperator), TrustDomain: model.JudgmentTrustAuthenticatedMCP,
		RequestID: req.RequestID, ExpectedPreviousVersion: req.ExpectedCurrentVersion, CreatedAt: req.Now.UTC(),
	}
	var policyJSON any
	if policy != nil {
		encoded, err := json.Marshal(policy)
		if err != nil {
			return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: marshal expected behavior policy: %w", err)
		}
		policyJSON = string(encoded)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO expected_behavior_envelope_revisions (
			id,envelope_id,version,operation,state,policy_json,source_judgment_id,source_situation_id,
			asserted_operator,trust_domain,request_id,request_hash,expected_previous_version,created_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		revision.ID, envelopeID, version, revision.Operation, revision.State, policyJSON,
		nullIfEmpty(sourceJudgmentID), nullIfEmpty(sourceSituationID), revision.AssertedOperator, revision.TrustDomain,
		revision.RequestID, requestHash, revision.ExpectedPreviousVersion, canonicalTime(revision.CreatedAt)); err != nil {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: insert expected behavior revision: %w", err)
	}

	headScope := model.ExpectedBehaviorScope{}
	if policy != nil {
		headScope = policy.Scope
	} else {
		headScope = priorHead.Scope
	}
	if hasHead {
		res, err := tx.ExecContext(ctx, `
			UPDATE expected_behavior_envelope_heads SET revision_id=?,version=?,state=?,group_key=?,source=?,source_instance_id=?,
				host=?,primary_trigger_id=?,primary_trigger_version=?,invalidated_at=NULL,invalidation_reason=NULL,updated_at=?
			WHERE envelope_id=? AND version=?`, revision.ID, version, state, headScope.GroupKey, headScope.Source,
			headScope.SourceInstanceID, headScope.Host, headScope.PrimaryTriggerID, headScope.PrimaryTriggerVersion,
			canonicalTime(req.Now), envelopeID, actualVersion)
		if err != nil {
			return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: advance expected behavior head: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ExpectedBehaviorWriteResult{}, ErrExpectedBehaviorVersionConflict
		}
	} else if _, err := tx.ExecContext(ctx, `
		INSERT INTO expected_behavior_envelope_heads (
			envelope_id,revision_id,version,state,group_key,source,source_instance_id,host,primary_trigger_id,primary_trigger_version,updated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, envelopeID, revision.ID, version, state, headScope.GroupKey, headScope.Source,
		headScope.SourceInstanceID, headScope.Host, headScope.PrimaryTriggerID, headScope.PrimaryTriggerVersion, canonicalTime(req.Now)); err != nil {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: create expected behavior head: %w", err)
	}

	groups := []string{headScope.GroupKey}
	if hasHead && priorHead.Scope.GroupKey != headScope.GroupKey {
		groups = append(groups, priorHead.Scope.GroupKey)
	}
	affected, err := wakeExpectedBehaviorGroupsTx(ctx, tx, groups, req.Now)
	if err != nil {
		return ExpectedBehaviorWriteResult{}, err
	}
	payload := map[string]any{
		"envelope_id": envelopeID, "version": version, "operation": req.Operation,
		"asserted_operator": revision.AssertedOperator, "request_id": req.RequestID,
		"affected_situations": affected,
	}
	if err := auditor.AppendTx(ctx, tx, "mcp", "expected_behavior."+string(req.Operation), payload, req.Now); err != nil {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: audit expected behavior: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ExpectedBehaviorWriteResult{}, fmt.Errorf("store: commit expected behavior: %w", err)
	}
	head := model.ExpectedBehaviorHead{
		EnvelopeID: envelopeID, RevisionID: revision.ID, Version: version, State: state,
		Scope: headScope, Policy: policy, AssertedOperator: revision.AssertedOperator, UpdatedAt: req.Now.UTC(),
	}
	return ExpectedBehaviorWriteResult{Revision: revision, Head: head, AffectedSituations: affected}, nil
}

func validateExpectedBehaviorWrite(req ExpectedBehaviorWrite) error {
	if strings.TrimSpace(req.RequestID) == "" || strings.TrimSpace(req.AssertedOperator) == "" || req.ExpectedCurrentVersion < 0 {
		return errors.New("store: expected behavior requires request identity, asserted operator, and expected version")
	}
	if !req.Confirmed {
		return errors.New("store: expected behavior requires explicit confirmation")
	}
	if req.Now.IsZero() {
		return errors.New("store: expected behavior requires current time")
	}
	switch req.Operation {
	case model.ExpectedBehaviorOperationConfirm:
		if req.ExpectedCurrentVersion != 0 || strings.TrimSpace(req.EnvelopeID) != "" {
			return errors.New("store: expected behavior confirm requires no existing envelope")
		}
	case model.ExpectedBehaviorOperationReplace, model.ExpectedBehaviorOperationRestore:
		if strings.TrimSpace(req.EnvelopeID) == "" || req.ExpectedCurrentVersion < 1 {
			return errors.New("store: expected behavior replace/restore requires envelope and current version")
		}
	case model.ExpectedBehaviorOperationRevoke:
		if strings.TrimSpace(req.EnvelopeID) == "" || req.ExpectedCurrentVersion < 1 || req.Policy != nil {
			return errors.New("store: expected behavior revoke requires envelope/version and no policy")
		}
		return nil
	default:
		return fmt.Errorf("store: unknown expected behavior operation %q", req.Operation)
	}
	if req.Policy == nil || strings.TrimSpace(req.SituationID) == "" || req.SituationInputVersion < 1 || strings.TrimSpace(req.SourceJudgmentID) == "" {
		return errors.New("store: active expected behavior requires situation, source judgment, and complete policy")
	}
	return nil
}

func validateExpectedBehaviorOperation(operation model.ExpectedBehaviorOperation, hasHead bool, head model.ExpectedBehaviorHead) error {
	switch operation {
	case model.ExpectedBehaviorOperationConfirm:
		if hasHead {
			return fmt.Errorf("%w: confirm requires no existing envelope", ErrExpectedBehaviorNotAllowed)
		}
	case model.ExpectedBehaviorOperationReplace, model.ExpectedBehaviorOperationRevoke:
		if !hasHead || head.State != model.ExpectedBehaviorStateActive || head.InvalidatedAt != nil {
			return fmt.Errorf("%w: %s requires an active head", ErrExpectedBehaviorNotAllowed, operation)
		}
	case model.ExpectedBehaviorOperationRestore:
		if !hasHead || (head.State != model.ExpectedBehaviorStateRevoked && head.InvalidatedAt == nil) {
			return fmt.Errorf("%w: restore requires a revoked or invalidated head", ErrExpectedBehaviorNotAllowed)
		}
	}
	return nil
}

func verifyExpectedBehaviorSourceTx(ctx context.Context, tx *sql.Tx, req ExpectedBehaviorWrite) error {
	in, err := loadSituationJudgmentInputTx(ctx, tx, req.SituationID, req.Now)
	if err != nil {
		return err
	}
	if in.Situation.InputVersion != req.SituationInputVersion {
		return ErrSituationVersionConflict
	}
	if in.Situation.Lifecycle.Terminal() {
		return fmt.Errorf("%w: terminal situations cannot create reusable authority", ErrExpectedBehaviorNotAllowed)
	}
	judgment, ok, err := readSituationJudgmentHeadTx(ctx, tx, req.SituationID)
	if err != nil {
		return err
	}
	if !ok || judgment.ID != req.SourceJudgmentID || judgment.State != model.JudgmentStateExpected {
		return fmt.Errorf("%w: source judgment is not current expected authority", ErrExpectedBehaviorNotAllowed)
	}
	if _, invalidated, err := readSituationJudgmentInvalidationTx(ctx, tx, req.SituationID); err != nil {
		return err
	} else if invalidated {
		return fmt.Errorf("%w: source judgment is invalidated", ErrExpectedBehaviorNotAllowed)
	}
	app := situation.EvaluateExpectedJudgment(judgment, in, req.Now)
	if !app.Applicable {
		return fmt.Errorf("%w: source judgment is %s", ErrExpectedBehaviorNotAllowed, app.Reason)
	}
	policy := req.Policy
	if judgment.Coverage.Scope != policy.Scope.GroupKey {
		return fmt.Errorf("%w: policy group does not match source judgment", ErrExpectedBehaviorNotAllowed)
	}
	for _, symptom := range judgment.Coverage.Symptoms {
		if symptom.Source != "zabbix" || symptom.ObservedSourceInstanceID == nil || symptom.ObservedSourceConfigVersion == nil {
			continue
		}
		if *symptom.ObservedSourceInstanceID == policy.Scope.SourceInstanceID &&
			*symptom.ObservedSourceConfigVersion == policy.Scope.PrimaryTriggerVersion &&
			symptom.IdentityLabels["host"] == policy.Scope.Host &&
			symptom.IdentityLabels["zabbix_trigger_id"] == policy.Scope.PrimaryTriggerID {
			return nil
		}
	}
	return fmt.Errorf("%w: primary binding is not proven by the source judgment", ErrExpectedBehaviorNotAllowed)
}

func expectedBehaviorRequestHash(req ExpectedBehaviorWrite) (string, error) {
	canonical := struct {
		Operation              model.ExpectedBehaviorOperation `json:"operation"`
		EnvelopeID             string                          `json:"envelope_id"`
		SourceJudgmentID       string                          `json:"source_judgment_id"`
		ValidationID           string                          `json:"validation_id"`
		SituationID            string                          `json:"situation_id"`
		SituationInputVersion  int                             `json:"situation_input_version"`
		ExpectedCurrentVersion int                             `json:"expected_current_version"`
		RequestID              string                          `json:"request_id"`
		AssertedOperator       string                          `json:"asserted_operator"`
		Confirmed              bool                            `json:"confirmed"`
		Policy                 *model.ExpectedBehaviorPolicy   `json:"policy"`
	}{req.Operation, strings.TrimSpace(req.EnvelopeID), strings.TrimSpace(req.SourceJudgmentID), strings.TrimSpace(req.ValidationID),
		strings.TrimSpace(req.SituationID), req.SituationInputVersion, req.ExpectedCurrentVersion, strings.TrimSpace(req.RequestID),
		strings.TrimSpace(req.AssertedOperator), req.Confirmed, req.Policy}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("store: marshal expected behavior request: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func wakeExpectedBehaviorGroupsTx(ctx context.Context, tx *sql.Tx, groups []string, now time.Time) ([]string, error) {
	seen := make(map[string]struct{})
	var affected []string
	for _, group := range groups {
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		rows, err := tx.QueryContext(ctx, `SELECT id,due_reasons_json FROM situations WHERE group_key=? AND lifecycle IN ('active','recovery_pending') ORDER BY id`, group)
		if err != nil {
			return nil, fmt.Errorf("store: list expected behavior wake targets: %w", err)
		}
		type target struct{ id, dueJSON string }
		var targets []target
		for rows.Next() {
			var target target
			if err := rows.Scan(&target.id, &target.dueJSON); err != nil {
				_ = rows.Close()
				return nil, err
			}
			targets = append(targets, target)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		for _, target := range targets {
			var due []model.DueReason
			if err := json.Unmarshal([]byte(target.dueJSON), &due); err != nil {
				return nil, fmt.Errorf("store: unmarshal expected behavior wake reasons: %w", err)
			}
			due = mergeDueReason(due, model.DueEnvelopeChanged)
			encoded, _ := json.Marshal(due)
			if _, err := tx.ExecContext(ctx, `UPDATE situations SET input_version=input_version+1,next_assessment_at=?,due_reasons_json=?,lease_owner=NULL,lease_expires_at=NULL,retry_at=NULL,updated_at=? WHERE id=? AND lifecycle IN ('active','recovery_pending')`,
				canonicalTime(now), string(encoded), canonicalTime(now), target.id); err != nil {
				return nil, fmt.Errorf("store: wake situation for expected behavior: %w", err)
			}
			affected = append(affected, target.id)
		}
	}
	return affected, nil
}

func readExpectedBehaviorRevisionByRequestTx(ctx context.Context, tx *sql.Tx, requestID string) (persistedExpectedBehaviorRevision, bool, error) {
	p, err := scanExpectedBehaviorRevision(tx.QueryRowContext(ctx, expectedBehaviorRevisionSelect+` WHERE request_id=?`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return persistedExpectedBehaviorRevision{}, false, nil
	}
	return p, err == nil, err
}

const expectedBehaviorRevisionSelect = `SELECT id,envelope_id,version,operation,state,policy_json,source_judgment_id,source_situation_id,asserted_operator,trust_domain,request_id,request_hash,expected_previous_version,created_at FROM expected_behavior_envelope_revisions`

func scanExpectedBehaviorRevision(row scanner) (persistedExpectedBehaviorRevision, error) {
	var p persistedExpectedBehaviorRevision
	var operation, state, trust, createdAt string
	var policyJSON, sourceJudgmentID, sourceSituationID sql.NullString
	if err := row.Scan(&p.revision.ID, &p.revision.EnvelopeID, &p.revision.Version, &operation, &state, &policyJSON,
		&sourceJudgmentID, &sourceSituationID, &p.revision.AssertedOperator, &trust, &p.revision.RequestID, &p.requestHash,
		&p.revision.ExpectedPreviousVersion, &createdAt); err != nil {
		return p, err
	}
	p.revision.Operation = model.ExpectedBehaviorOperation(operation)
	p.revision.State = model.ExpectedBehaviorState(state)
	p.revision.TrustDomain = model.JudgmentTrustDomain(trust)
	p.revision.SourceJudgmentID, p.revision.SourceSituationID = sourceJudgmentID.String, sourceSituationID.String
	if policyJSON.Valid {
		p.revision.Policy = &model.ExpectedBehaviorPolicy{}
		if err := json.Unmarshal([]byte(policyJSON.String), p.revision.Policy); err != nil {
			return p, fmt.Errorf("store: unmarshal expected behavior policy: %w", err)
		}
	}
	var err error
	p.revision.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	return p, err
}

func readExpectedBehaviorHeadTx(ctx context.Context, tx *sql.Tx, envelopeID string) (model.ExpectedBehaviorHead, error) {
	head, err := scanExpectedBehaviorHead(tx.QueryRowContext(ctx, `
		SELECT h.envelope_id,h.revision_id,h.version,h.state,h.group_key,h.source,h.source_instance_id,h.host,
		       h.primary_trigger_id,h.primary_trigger_version,r.policy_json,r.asserted_operator,
		       h.invalidated_at,h.invalidation_reason,h.updated_at
		FROM expected_behavior_envelope_heads h
		JOIN expected_behavior_envelope_revisions r ON r.id=h.revision_id
		WHERE h.envelope_id=?`, envelopeID))
	if errors.Is(err, sql.ErrNoRows) {
		return head, ErrNotFound
	}
	if err != nil {
		return head, fmt.Errorf("store: read expected behavior head: %w", err)
	}
	return head, nil
}

func (s *Store) GetExpectedBehavior(ctx context.Context, envelopeID string) (model.ExpectedBehaviorHead, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ExpectedBehaviorHead{}, err
	}
	defer func() { _ = tx.Rollback() }()
	head, err := readExpectedBehaviorHeadTx(ctx, tx, envelopeID)
	if err != nil {
		return head, err
	}
	return head, tx.Commit()
}

func (s *Store) ListExpectedBehaviorHistory(ctx context.Context, envelopeID string, afterVersion, limit int) ([]model.ExpectedBehaviorRevision, error) {
	if limit < 1 || limit > 101 {
		limit = 100
	}
	if afterVersion < 0 {
		afterVersion = 0
	}
	rows, err := s.db.QueryContext(ctx, expectedBehaviorRevisionSelect+` WHERE envelope_id=? AND version>? ORDER BY version LIMIT ?`, envelopeID, afterVersion, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []model.ExpectedBehaviorRevision{}
	for rows.Next() {
		p, err := scanExpectedBehaviorRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p.revision)
	}
	return out, rows.Err()
}

// ListExpectedBehaviors returns current heads in stable envelope order.
func (s *Store) ListExpectedBehaviors(ctx context.Context, filter ExpectedBehaviorListFilter, limit int) ([]model.ExpectedBehaviorHead, error) {
	if limit < 1 || limit > 101 {
		limit = 100
	}
	query := `
		SELECT h.envelope_id,h.revision_id,h.version,h.state,h.group_key,h.source,h.source_instance_id,h.host,
		       h.primary_trigger_id,h.primary_trigger_version,r.policy_json,r.asserted_operator,
		       h.invalidated_at,h.invalidation_reason,h.updated_at
		FROM expected_behavior_envelope_heads h
		JOIN expected_behavior_envelope_revisions r ON r.id=h.revision_id
		WHERE 1=1`
	args := []any{}
	if !filter.IncludeInactive {
		query += ` AND h.state='active' AND h.invalidated_at IS NULL`
	}
	if filter.GroupKey != "" {
		query += ` AND h.group_key=?`
		args = append(args, filter.GroupKey)
	}
	if filter.SourceInstanceID != "" {
		query += ` AND h.source_instance_id=?`
		args = append(args, filter.SourceInstanceID)
	}
	if filter.TriggerID != "" {
		query += ` AND h.primary_trigger_id=?`
		args = append(args, filter.TriggerID)
	}
	query += ` ORDER BY h.envelope_id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list expected behavior heads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []model.ExpectedBehaviorHead
	for rows.Next() {
		head, err := scanExpectedBehaviorHead(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, head)
	}
	return out, rows.Err()
}

// InvalidateExpectedBehavior permanently retires one proven source version.
// Repeating the same invalidation is a no-op and never wakes twice.
func (s *Store) InvalidateExpectedBehavior(ctx context.Context, auditor JudgmentAuditAppender, envelopeID string, expectedVersion int,
	reason model.ExpectedBehaviorInvalidationReason, evidence map[string]any, now time.Time,
) (bool, error) {
	if auditor == nil || strings.TrimSpace(envelopeID) == "" || expectedVersion < 1 || now.IsZero() {
		return false, errors.New("store: expected behavior invalidation requires envelope, version, time, and auditor")
	}
	switch reason {
	case model.ExpectedBehaviorSourceInstanceChanged, model.ExpectedBehaviorPrimaryDefinitionChanged, model.ExpectedBehaviorBindingDefinitionChanged:
	default:
		return false, errors.New("store: invalid expected behavior invalidation reason")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	head, err := readExpectedBehaviorHeadTx(ctx, tx, envelopeID)
	if err != nil {
		return false, err
	}
	if head.Version != expectedVersion {
		return false, ErrExpectedBehaviorVersionConflict
	}
	if head.InvalidatedAt != nil {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if head.State != model.ExpectedBehaviorStateActive || head.Policy == nil {
		return false, fmt.Errorf("%w: only an active head can be invalidated", ErrExpectedBehaviorNotAllowed)
	}
	res, err := tx.ExecContext(ctx, `UPDATE expected_behavior_envelope_heads SET invalidated_at=?,invalidation_reason=?,updated_at=? WHERE envelope_id=? AND version=? AND invalidated_at IS NULL`,
		canonicalTime(now), reason, canonicalTime(now), envelopeID, expectedVersion)
	if err != nil {
		return false, fmt.Errorf("store: invalidate expected behavior head: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, ErrExpectedBehaviorStale
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return false, fmt.Errorf("store: marshal expected behavior invalidation evidence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO expected_behavior_system_events (id,envelope_id,envelope_version,kind,reason,evidence_json,created_at) VALUES (?,?,?,?,?,?,?)`,
		uuid.NewString(), envelopeID, expectedVersion, "invalidated", reason, string(evidenceJSON), canonicalTime(now)); err != nil {
		return false, fmt.Errorf("store: insert expected behavior invalidation event: %w", err)
	}
	affected, err := wakeExpectedBehaviorGroupsTx(ctx, tx, []string{head.Scope.GroupKey}, now)
	if err != nil {
		return false, err
	}
	if err := auditor.AppendTx(ctx, tx, "alertint", "expected_behavior.invalidated", map[string]any{
		"envelope_id": envelopeID, "version": expectedVersion, "reason": reason,
		"evidence": evidence, "affected_situations": affected,
	}, now); err != nil {
		return false, fmt.Errorf("store: audit expected behavior invalidation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// CommitExpectedBehaviorEvaluation stores a deterministic evaluation only if
// its Situation and every referenced envelope revision are still current.
func (s *Store) CommitExpectedBehaviorEvaluation(ctx context.Context, evaluation model.ExpectedBehaviorEvaluation) (model.ExpectedBehaviorEvaluation, error) {
	if strings.TrimSpace(evaluation.SituationID) == "" || evaluation.SituationVersion < 1 || strings.TrimSpace(evaluation.BasisHash) == "" || evaluation.EvaluatedAt.IsZero() {
		return model.ExpectedBehaviorEvaluation{}, errors.New("store: expected behavior evaluation requires situation, version, basis, and time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ExpectedBehaviorEvaluation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	sit, err := getSituationTx(ctx, tx, evaluation.SituationID)
	if err != nil {
		return model.ExpectedBehaviorEvaluation{}, err
	}
	if sit.InputVersion != evaluation.SituationVersion || sit.Lifecycle.Terminal() {
		return model.ExpectedBehaviorEvaluation{}, ErrExpectedBehaviorStale
	}
	for _, candidate := range evaluation.Candidates {
		head, err := readExpectedBehaviorHeadTx(ctx, tx, candidate.EnvelopeID)
		if err != nil || head.Version != candidate.Version {
			return model.ExpectedBehaviorEvaluation{}, ErrExpectedBehaviorStale
		}
	}
	encoded, err := json.Marshal(evaluation)
	if err != nil {
		return model.ExpectedBehaviorEvaluation{}, err
	}
	var priorJSON string
	var priorID string
	err = tx.QueryRowContext(ctx, `SELECT id,evaluation_json FROM expected_behavior_evaluations WHERE situation_id=? AND basis_hash=?`, evaluation.SituationID, evaluation.BasisHash).Scan(&priorID, &priorJSON)
	if err == nil {
		var prior model.ExpectedBehaviorEvaluation
		if err := json.Unmarshal([]byte(priorJSON), &prior); err != nil {
			return model.ExpectedBehaviorEvaluation{}, err
		}
		prior.ID = priorID
		if err := tx.Commit(); err != nil {
			return model.ExpectedBehaviorEvaluation{}, err
		}
		return prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ExpectedBehaviorEvaluation{}, err
	}
	evaluation.ID = uuid.NewString()
	encoded, _ = json.Marshal(evaluation)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO expected_behavior_evaluations (
			id,situation_id,situation_input_version,disposition,reason,chosen_envelope_id,chosen_version,evaluation_json,basis_hash,evaluated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?)`, evaluation.ID, evaluation.SituationID, evaluation.SituationVersion,
		evaluation.Disposition, nullIfEmpty(string(evaluation.Reason)), nullIfEmpty(evaluation.ChosenEnvelopeID),
		nullIfZero(evaluation.ChosenVersion), string(encoded), evaluation.BasisHash, canonicalTime(evaluation.EvaluatedAt)); err != nil {
		return model.ExpectedBehaviorEvaluation{}, fmt.Errorf("store: insert expected behavior evaluation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO expected_behavior_evaluation_heads (situation_id,evaluation_id,updated_at) VALUES (?,?,?)
		ON CONFLICT(situation_id) DO UPDATE SET evaluation_id=excluded.evaluation_id,updated_at=excluded.updated_at`,
		evaluation.SituationID, evaluation.ID, canonicalTime(evaluation.EvaluatedAt)); err != nil {
		return model.ExpectedBehaviorEvaluation{}, fmt.Errorf("store: advance expected behavior evaluation head: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.ExpectedBehaviorEvaluation{}, err
	}
	return evaluation, nil
}

// GetCurrentExpectedBehaviorEvaluation returns one Situation's committed head.
func (s *Store) GetCurrentExpectedBehaviorEvaluation(ctx context.Context, situationID string) (model.ExpectedBehaviorEvaluation, bool, error) {
	var id, raw string
	err := s.db.QueryRowContext(ctx, `
		SELECT e.id,e.evaluation_json FROM expected_behavior_evaluation_heads h
		JOIN expected_behavior_evaluations e ON e.id=h.evaluation_id WHERE h.situation_id=?`, situationID).Scan(&id, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExpectedBehaviorEvaluation{}, false, nil
	}
	if err != nil {
		return model.ExpectedBehaviorEvaluation{}, false, err
	}
	var evaluation model.ExpectedBehaviorEvaluation
	if err := json.Unmarshal([]byte(raw), &evaluation); err != nil {
		return model.ExpectedBehaviorEvaluation{}, false, err
	}
	evaluation.ID = id
	return evaluation, true, nil
}

func scanExpectedBehaviorHead(row scanner) (model.ExpectedBehaviorHead, error) {
	var head model.ExpectedBehaviorHead
	var state, updatedAt string
	var policyJSON, invalidatedAt, invalidationReason sql.NullString
	if err := row.Scan(&head.EnvelopeID, &head.RevisionID, &head.Version, &state,
		&head.Scope.GroupKey, &head.Scope.Source, &head.Scope.SourceInstanceID, &head.Scope.Host,
		&head.Scope.PrimaryTriggerID, &head.Scope.PrimaryTriggerVersion, &policyJSON, &head.AssertedOperator,
		&invalidatedAt, &invalidationReason, &updatedAt); err != nil {
		return head, err
	}
	head.State = model.ExpectedBehaviorState(state)
	if policyJSON.Valid {
		head.Policy = &model.ExpectedBehaviorPolicy{}
		if err := json.Unmarshal([]byte(policyJSON.String), head.Policy); err != nil {
			return head, err
		}
	}
	if invalidatedAt.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, invalidatedAt.String)
		if err != nil {
			return head, err
		}
		head.InvalidatedAt = &parsed
		head.InvalidationReason = model.ExpectedBehaviorInvalidationReason(invalidationReason.String)
	}
	var err error
	head.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return head, err
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullIfZero(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
