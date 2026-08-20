// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

const (
	maxObservationPlanBytes  = 64 << 10
	maxObservationParamBytes = 32 << 10
	maxFactValueBytes        = 512 << 10
	maxEvidenceRefs          = 128
	maxAssessmentJSONBytes   = 512 << 10
)

// ObservationRun is durable reduced execution metadata. There is no raw
// response field by design.
type ObservationRun struct {
	ID              string
	SituationID     string
	InputVersion    int
	ProposedPlan    observationmodel.Plan
	ValidatedPlan   observationmodel.Plan
	Capability      observationmodel.Capability
	Status          observationmodel.ResultStatus
	ObservedAt      time.Time
	Freshness       observationmodel.Freshness
	Truncated       bool
	Digest          string
	RetryErrorClass string
	TokenCost       int
	SourceCallCost  int
	CreatedAt       time.Time
}

// AssessmentActor is the closed origin of an Assessment attempt.
type AssessmentActor string

const (
	AssessmentActorDeterministicController AssessmentActor = "deterministic_controller"
	AssessmentActorLLM                     AssessmentActor = "llm"
)

// AssessmentStatus is the closed attempt outcome.
type AssessmentStatus string

const (
	AssessmentStatusProposed      AssessmentStatus = "proposed"
	AssessmentStatusAuthoritative AssessmentStatus = "authoritative"
	AssessmentStatusRejected      AssessmentStatus = "rejected"
	AssessmentStatusFailed        AssessmentStatus = "failed"
	AssessmentStatusStale         AssessmentStatus = "stale"
)

// AssessmentAttempt keeps model proposal and deterministic validation output
// separate for replay and audit.
type AssessmentAttempt struct {
	ID                    string
	SituationID           string
	Sequence              int
	InputVersion          int
	FactHash              string
	Actor                 AssessmentActor
	Status                AssessmentStatus
	TriggerReasons        []string
	SnapshotDigest        string
	Proposal              json.RawMessage
	Validated             json.RawMessage
	ValidationAdjustments json.RawMessage
	ModelUsage            json.RawMessage
	CreatedAt             time.Time
	CompletedAt           *time.Time
}

// AppendObservationRun appends one idempotent run under the exact claimed
// Situation input version.
func (s *Store) AppendObservationRun(ctx context.Context, claim SituationClaim, run ObservationRun) error {
	prepared, err := prepareObservationRun(claim, run)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin observation run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifySituationFence(ctx, tx, claim); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_runs (
			id, situation_id, input_version, proposed_plan_json, validated_plan_json,
			capability, scope_json, parameters_json, budget, status, observed_at,
			freshness, truncated, digest, retry_error_class, token_cost,
			source_call_cost, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		prepared.id, prepared.situationID, prepared.inputVersion, prepared.proposedJSON,
		prepared.validatedJSON, prepared.capability, prepared.scopeJSON, prepared.parametersJSON,
		prepared.budget, prepared.status, prepared.observedAt, prepared.freshness,
		prepared.truncated, prepared.digest, prepared.retryClass, prepared.tokenCost,
		prepared.sourceCallCost, prepared.createdAt)
	if err != nil {
		return fmt.Errorf("store: append observation run: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count observation run append: %w", err)
	}
	if changed == 0 {
		var situationID, digest, status, proposed, validated string
		var inputVersion int
		if err := tx.QueryRowContext(ctx, `SELECT situation_id,input_version,digest,status,proposed_plan_json,validated_plan_json
			FROM situation_observation_runs WHERE id=?`, run.ID).
			Scan(&situationID, &inputVersion, &digest, &status, &proposed, &validated); err != nil {
			return fmt.Errorf("store: read replayed observation run: %w", err)
		}
		if situationID != prepared.situationID || inputVersion != prepared.inputVersion || digest != prepared.digest ||
			status != prepared.status || proposed != prepared.proposedJSON || validated != prepared.validatedJSON {
			return errors.New("store: observation run identity collision")
		}
		existing, err := readPreparedObservationRun(ctx, tx, run.ID)
		if err != nil {
			return err
		}
		if existing != prepared {
			return errors.New("store: observation run identity collision")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit observation run: %w", err)
	}
	return nil
}

// AppendSituationFacts appends a normalized fact batch atomically. Exact
// replay succeeds; a reused fact ID with different evidence fails closed.
func (s *Store) AppendSituationFacts(ctx context.Context, claim SituationClaim, facts []observationmodel.Fact) error {
	prepared := make([]preparedFact, len(facts))
	for index, fact := range facts {
		value, err := prepareFact(claim, fact)
		if err != nil {
			return fmt.Errorf("store: prepare fact %d: %w", index, err)
		}
		prepared[index] = value
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin append facts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifySituationFence(ctx, tx, claim); err != nil {
		return err
	}
	for _, fact := range prepared {
		result, err := tx.ExecContext(ctx, `INSERT INTO situation_facts (
			id,situation_id,input_version,kind,subject,value_json,source_capability,
			observed_at,freshness,result_status,digest,evidence_refs_json,material,created_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
			fact.id, fact.situationID, fact.inputVersion, fact.kind, fact.subject, fact.valueJSON,
			fact.capability, fact.observedAt, fact.freshness, fact.status, fact.digest,
			fact.evidenceRefsJSON, fact.material, fact.createdAt)
		if err != nil {
			return fmt.Errorf("store: append situation fact: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: count situation fact append: %w", err)
		}
		if changed == 0 {
			var situationID, digest, status, valueJSON string
			var inputVersion int
			if err := tx.QueryRowContext(ctx, `SELECT situation_id,input_version,digest,result_status,value_json FROM situation_facts WHERE id=?`, fact.id).
				Scan(&situationID, &inputVersion, &digest, &status, &valueJSON); err != nil {
				return fmt.Errorf("store: read replayed situation fact: %w", err)
			}
			if situationID != fact.situationID || inputVersion != fact.inputVersion || digest != fact.digest || status != fact.status || valueJSON != fact.valueJSON {
				return errors.New("store: situation fact identity collision")
			}
			existing, err := readPreparedFact(ctx, tx, fact.id)
			if err != nil {
				return err
			}
			if existing != fact {
				return errors.New("store: situation fact identity collision")
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit situation facts: %w", err)
	}
	return nil
}

// AppendAssessmentAttempt appends one attempt under a current fence. Only an
// authoritative attempt atomically advances situations.current_assessment_id.
func (s *Store) AppendAssessmentAttempt(ctx context.Context, claim SituationClaim, attempt AssessmentAttempt) error {
	prepared, err := prepareAssessmentAttempt(claim, attempt)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin assessment attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifySituationFence(ctx, tx, claim); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO situation_assessment_attempts (
		id,situation_id,sequence,input_version,fact_hash,actor,status,trigger_reasons_json,
		snapshot_digest,proposal_json,validated_json,validation_adjustments_json,model_usage_json,
		created_at,completed_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		prepared.id, prepared.situationID, prepared.sequence, prepared.inputVersion, prepared.factHash,
		prepared.actor, prepared.status, prepared.triggerReasonsJSON, prepared.snapshotDigest,
		prepared.proposalJSON, prepared.validatedJSON, prepared.adjustmentsJSON, prepared.modelUsageJSON,
		prepared.createdAt, prepared.completedAt)
	if err != nil {
		return fmt.Errorf("store: append assessment attempt: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count assessment attempt append: %w", err)
	}
	if changed == 0 {
		var situationID, status, factHash string
		var sequence, inputVersion int
		if err := tx.QueryRowContext(ctx, `SELECT situation_id,sequence,input_version,status,fact_hash
			FROM situation_assessment_attempts WHERE id=?`, attempt.ID).
			Scan(&situationID, &sequence, &inputVersion, &status, &factHash); err != nil {
			return fmt.Errorf("store: read replayed assessment attempt: %w", err)
		}
		if situationID != prepared.situationID || sequence != prepared.sequence || inputVersion != prepared.inputVersion || status != prepared.status || factHash != prepared.factHash {
			return errors.New("store: assessment attempt identity collision")
		}
		existing, err := readPreparedAssessmentAttempt(ctx, tx, attempt.ID)
		if err != nil {
			return err
		}
		if !equalPreparedAssessmentAttempt(existing, prepared) {
			return errors.New("store: assessment attempt identity collision")
		}
	}
	if attempt.Status == AssessmentStatusAuthoritative {
		result, err := tx.ExecContext(ctx, `UPDATE situations SET current_assessment_id=?, updated_at=?
			WHERE id=? AND input_version=? AND lease_owner=? AND claim_token=?`,
			attempt.ID, prepared.createdAt, claim.Situation.ID, claim.Situation.InputVersion, claim.ClaimOwner, claim.ClaimToken)
		if err != nil {
			return fmt.Errorf("store: advance current assessment: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: count current assessment advance: %w", err)
		}
		if changed != 1 {
			return ErrSituationVersionConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit assessment attempt: %w", err)
	}
	return nil
}

// UpdateDeliverySourceTimes records a canonical source-API correction without
// rewriting immutable receipt/payload provenance. A material correction
// advances the owning Situation input version and schedules reassessment.
func (s *Store) UpdateDeliverySourceTimes(ctx context.Context, claim SituationClaim, deliveryID string, startedAt, resolvedAt *time.Time, observedAt time.Time) error {
	if strings.TrimSpace(deliveryID) == "" || (startedAt == nil && resolvedAt == nil) {
		return errors.New("store: source time correction requires a delivery and source time")
	}
	if observedAt.IsZero() || observedAt.Location() != time.UTC || !canonicalSourceTime(startedAt) || !canonicalSourceTime(resolvedAt) {
		return errors.New("store: source time correction requires canonical utc times")
	}
	if startedAt != nil && resolvedAt != nil && resolvedAt.Before(*startedAt) {
		return errors.New("store: resolved source time precedes started source time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin source time correction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifySituationFence(ctx, tx, claim); err != nil {
		return err
	}
	var ownerID, alertID, deliveryStarts string
	var sourceStarted, sourceResolved, deliveryEnds sql.NullString
	var startedBasis, resolvedBasis situationmodel.SourceTimeBasis
	if err := tx.QueryRowContext(ctx, `
		SELECT si.situation_id,d.alert_id,d.starts_at,d.ends_at,d.source_started_at,d.source_resolved_at,d.started_at_basis,d.resolved_at_basis
		FROM alert_deliveries d
		JOIN incident_alert_deliveries iad ON iad.delivery_id=d.id
		JOIN situation_incidents si ON si.incident_id=iad.incident_id
		WHERE d.id=?`, deliveryID).
		Scan(&ownerID, &alertID, &deliveryStarts, &deliveryEnds, &sourceStarted, &sourceResolved, &startedBasis, &resolvedBasis); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: read delivery source time owner: %w", err)
	}
	if ownerID != claim.Situation.ID {
		return errors.New("store: delivery source time owner does not match claim")
	}
	newStarted, newStartedBasis, startChanged, err := correctedSourceTime("started", sourceStarted, startedBasis, startedAt)
	if err != nil {
		return err
	}
	newResolved, newResolvedBasis, resolvedChanged, err := correctedSourceTime("resolved", sourceResolved, resolvedBasis, resolvedAt)
	if err != nil {
		return err
	}
	if !startChanged && !resolvedChanged {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE alert_deliveries
		SET source_started_at=?,source_resolved_at=?,started_at_basis=?,resolved_at_basis=? WHERE id=?`,
		newStarted, newResolved, newStartedBasis, newResolvedBasis, deliveryID); err != nil {
		return fmt.Errorf("store: update delivery source times: %w", err)
	}
	var latest int
	if err := tx.QueryRowContext(ctx, `SELECT NOT EXISTS(
		SELECT 1 FROM alert_deliveries newer JOIN alert_deliveries current ON current.id=?
		WHERE newer.alert_id=current.alert_id AND (newer.received_at>current.received_at OR (newer.received_at=current.received_at AND newer.id>current.id)))`, deliveryID).Scan(&latest); err != nil {
		return fmt.Errorf("store: identify current alert projection: %w", err)
	}
	if latest == 1 {
		projectionStart := any(deliveryStarts)
		projectionEnd := any(nil)
		if deliveryEnds.Valid {
			projectionEnd = deliveryEnds.String
		}
		if startedAt != nil && startChanged {
			projectionStart = canonicalTime(*startedAt)
		}
		if resolvedAt != nil && resolvedChanged {
			projectionEnd = canonicalTime(*resolvedAt)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE alerts SET starts_at=?,ends_at=? WHERE id=?`, projectionStart, projectionEnd, alertID); err != nil {
			return fmt.Errorf("store: update alert source time projection: %w", err)
		}
	}
	current, err := querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id=?`, ownerID)
	if err != nil {
		return err
	}
	effective := current.EffectiveStartedAt
	basis := current.EffectiveStartedAtBasis
	if startedAt != nil && startedAt.Before(effective) {
		effective = startedAt.UTC()
		basis = situationmodel.SourceTimeBasisSourceAPI
		var different int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents si
			JOIN incident_alert_deliveries iad ON iad.incident_id=si.incident_id
			JOIN alert_deliveries d ON d.id=iad.delivery_id
			WHERE si.situation_id=? AND d.id<>? AND d.started_at_basis IN ('source_payload','receipt_fallback','mixed')`, ownerID, deliveryID).Scan(&different); err != nil {
			return fmt.Errorf("store: inspect source time basis: %w", err)
		}
		if different > 0 {
			basis = situationmodel.SourceTimeBasisMixed
		}
	}
	reasons := situation.MergeDueReasons(current.DueReasons, situationmodel.DueMembershipChanged)
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return fmt.Errorf("store: marshal source time due reasons: %w", err)
	}
	lastObserved := current.LastLifecycleObservedAt
	if observedAt.After(lastObserved) {
		lastObserved = observedAt
	}
	next := situation.EarlierAssessmentAt(current.NextAssessmentAt, observedAt)
	result, err := tx.ExecContext(ctx, `UPDATE situations SET
		input_version=input_version+1,effective_started_at=?,effective_started_at_basis=?,
		last_lifecycle_observed_at=?,next_assessment_at=?,due_reasons_json=?,
		lease_owner=NULL,lease_expires_at=NULL,attempt_count=0,last_error_class=NULL,retry_at=NULL,updated_at=?
		WHERE id=? AND input_version=? AND lease_owner=? AND claim_token=?`,
		canonicalTime(effective), basis, canonicalTime(lastObserved), canonicalTime(next), string(reasonsJSON),
		canonicalTime(observedAt), ownerID, claim.Situation.InputVersion, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: schedule source time correction: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count source time schedule: %w", err)
	}
	if changed != 1 {
		return ErrSituationVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit source time correction: %w", err)
	}
	return nil
}

type preparedObservationRun struct {
	id, situationID, proposedJSON, validatedJSON, capability, scopeJSON, parametersJSON string
	status, observedAt, freshness, digest, retryClass, createdAt                        string
	inputVersion, budget, truncated, tokenCost, sourceCallCost                          int
}

func prepareObservationRun(claim SituationClaim, run ObservationRun) (preparedObservationRun, error) {
	if run.ID == "" || run.SituationID != claim.Situation.ID || run.InputVersion != claim.Situation.InputVersion ||
		run.Capability == "" || run.Digest == "" || run.ObservedAt.IsZero() || run.CreatedAt.IsZero() ||
		run.ObservedAt.Location() != time.UTC || run.CreatedAt.Location() != time.UTC || run.TokenCost < 0 || run.SourceCallCost < 0 {
		return preparedObservationRun{}, errors.New("store: observation run requires matching identity, canonical times, and nonnegative cost")
	}
	if !storeValidResultStatus(run.Status) || !storeValidFreshness(run.Freshness) || run.ValidatedPlan.Capability != run.Capability {
		return preparedObservationRun{}, errors.New("store: invalid observation run classification")
	}
	proposed, err := json.Marshal(run.ProposedPlan)
	if err != nil {
		return preparedObservationRun{}, fmt.Errorf("store: marshal proposed observation plan: %w", err)
	}
	validated, err := json.Marshal(run.ValidatedPlan)
	if err != nil {
		return preparedObservationRun{}, fmt.Errorf("store: marshal validated observation plan: %w", err)
	}
	if len(proposed) > maxObservationPlanBytes || len(validated) > maxObservationPlanBytes {
		return preparedObservationRun{}, errors.New("store: observation plan exceeds persistence bound")
	}
	scope, err := json.Marshal(run.ValidatedPlan.Scope)
	if err != nil {
		return preparedObservationRun{}, fmt.Errorf("store: marshal observation scope: %w", err)
	}
	parameters := run.ValidatedPlan.Parameters
	if len(parameters) == 0 {
		parameters = json.RawMessage(`{}`)
	}
	if !json.Valid(parameters) || len(scope) == 0 || len(scope) > maxObservationPlanBytes || len(parameters) > maxObservationParamBytes {
		return preparedObservationRun{}, errors.New("store: observation plan json is invalid")
	}
	return preparedObservationRun{
		id: run.ID, situationID: run.SituationID, inputVersion: run.InputVersion,
		proposedJSON: string(proposed), validatedJSON: string(validated), capability: string(run.Capability),
		scopeJSON: string(scope), parametersJSON: string(parameters), budget: run.ValidatedPlan.Budget,
		status: string(run.Status), observedAt: canonicalTime(run.ObservedAt), freshness: string(run.Freshness),
		truncated: boolInt(run.Truncated), digest: run.Digest, retryClass: run.RetryErrorClass,
		tokenCost: run.TokenCost, sourceCallCost: run.SourceCallCost, createdAt: canonicalTime(run.CreatedAt),
	}, nil
}

type preparedFact struct {
	id, situationID, kind, subject, valueJSON, capability, observedAt string
	freshness, status, digest, evidenceRefsJSON, createdAt            string
	inputVersion, material                                            int
}

func prepareFact(claim SituationClaim, fact observationmodel.Fact) (preparedFact, error) {
	if fact.ID == "" || fact.SituationID != claim.Situation.ID || fact.InputVersion != claim.Situation.InputVersion ||
		fact.Kind == "" || fact.Subject == "" || fact.SourceCapability == "" || fact.Digest == "" ||
		fact.ObservedAt.IsZero() || fact.ObservedAt.Location() != time.UTC || !storeValidFreshness(fact.Freshness) || !storeValidResultStatus(fact.ResultStatus) {
		return preparedFact{}, errors.New("store: fact requires matching identity and closed classification")
	}
	value := fact.Value
	if len(value) == 0 {
		value = json.RawMessage(`null`)
	}
	if !json.Valid(value) {
		return preparedFact{}, errors.New("store: fact value must be json")
	}
	if len(value) > maxFactValueBytes || len(fact.EvidenceRefs) > maxEvidenceRefs {
		return preparedFact{}, errors.New("store: fact exceeds persistence bound")
	}
	if fact.EvidenceRefs == nil {
		fact.EvidenceRefs = []string{}
	}
	evidenceRefs, err := json.Marshal(fact.EvidenceRefs)
	if err != nil {
		return preparedFact{}, fmt.Errorf("store: marshal fact evidence references: %w", err)
	}
	return preparedFact{id: fact.ID, situationID: fact.SituationID, inputVersion: fact.InputVersion,
		kind: fact.Kind, subject: fact.Subject, valueJSON: string(value), capability: string(fact.SourceCapability),
		observedAt: canonicalTime(fact.ObservedAt), freshness: string(fact.Freshness), status: string(fact.ResultStatus),
		digest: fact.Digest, evidenceRefsJSON: string(evidenceRefs), material: boolInt(fact.Material), createdAt: canonicalTime(fact.ObservedAt)}, nil
}

type preparedAssessmentAttempt struct {
	id, situationID, factHash, actor, status, triggerReasonsJSON, snapshotDigest string
	proposalJSON, validatedJSON, adjustmentsJSON, modelUsageJSON                 any
	createdAt, completedAt                                                       any
	sequence, inputVersion                                                       int
}

func prepareAssessmentAttempt(claim SituationClaim, attempt AssessmentAttempt) (preparedAssessmentAttempt, error) {
	if attempt.ID == "" || attempt.SituationID != claim.Situation.ID || attempt.InputVersion != claim.Situation.InputVersion ||
		attempt.Sequence < 1 || attempt.FactHash == "" || attempt.SnapshotDigest == "" || attempt.CreatedAt.IsZero() || attempt.CreatedAt.Location() != time.UTC {
		return preparedAssessmentAttempt{}, errors.New("store: assessment attempt requires matching identity and canonical creation time")
	}
	if !validAssessmentActor(attempt.Actor) || !validAssessmentStatus(attempt.Status) {
		return preparedAssessmentAttempt{}, errors.New("store: invalid assessment attempt actor or status")
	}
	if attempt.TriggerReasons == nil {
		attempt.TriggerReasons = []string{}
	}
	triggerReasons, err := json.Marshal(attempt.TriggerReasons)
	if err != nil {
		return preparedAssessmentAttempt{}, fmt.Errorf("store: marshal assessment trigger reasons: %w", err)
	}
	adjustments := attempt.ValidationAdjustments
	if len(adjustments) == 0 {
		adjustments = json.RawMessage(`[]`)
	}
	if !json.Valid(adjustments) {
		return preparedAssessmentAttempt{}, errors.New("store: assessment validation adjustments must be json")
	}
	if len(triggerReasons) > maxObservationPlanBytes || len(adjustments) > maxAssessmentJSONBytes/2 {
		return preparedAssessmentAttempt{}, errors.New("store: assessment metadata exceeds persistence bound")
	}
	prepared := preparedAssessmentAttempt{id: attempt.ID, situationID: attempt.SituationID, sequence: attempt.Sequence,
		inputVersion: attempt.InputVersion, factHash: attempt.FactHash, actor: string(attempt.Actor), status: string(attempt.Status),
		triggerReasonsJSON: string(triggerReasons), snapshotDigest: attempt.SnapshotDigest, adjustmentsJSON: string(adjustments),
		createdAt: canonicalTime(attempt.CreatedAt)}
	var errJSON error
	if prepared.proposalJSON, errJSON = nullableJSON(attempt.Proposal); errJSON != nil {
		return preparedAssessmentAttempt{}, fmt.Errorf("store: proposal json: %w", errJSON)
	}
	if prepared.validatedJSON, errJSON = nullableJSON(attempt.Validated); errJSON != nil {
		return preparedAssessmentAttempt{}, fmt.Errorf("store: validated json: %w", errJSON)
	}
	if prepared.modelUsageJSON, errJSON = nullableJSON(attempt.ModelUsage); errJSON != nil {
		return preparedAssessmentAttempt{}, fmt.Errorf("store: model usage json: %w", errJSON)
	}
	if anyTextSize(prepared.proposalJSON) > maxAssessmentJSONBytes || anyTextSize(prepared.validatedJSON) > maxAssessmentJSONBytes || anyTextSize(prepared.modelUsageJSON) > maxAssessmentJSONBytes/2 {
		return preparedAssessmentAttempt{}, errors.New("store: assessment json exceeds persistence bound")
	}
	if attempt.CompletedAt != nil {
		if attempt.CompletedAt.IsZero() || attempt.CompletedAt.Location() != time.UTC || attempt.CompletedAt.Before(attempt.CreatedAt) {
			return preparedAssessmentAttempt{}, errors.New("store: assessment completion time must be canonical and ordered")
		}
		prepared.completedAt = canonicalTime(*attempt.CompletedAt)
	}
	if attempt.Status == AssessmentStatusAuthoritative && (prepared.validatedJSON == nil || prepared.completedAt == nil) {
		return preparedAssessmentAttempt{}, errors.New("store: authoritative assessment requires validated json and completion time")
	}
	return prepared, nil
}

func readPreparedObservationRun(ctx context.Context, tx *sql.Tx, id string) (preparedObservationRun, error) {
	var out preparedObservationRun
	err := tx.QueryRowContext(ctx, `SELECT id,situation_id,input_version,proposed_plan_json,validated_plan_json,
		capability,scope_json,parameters_json,budget,status,observed_at,freshness,truncated,digest,
		retry_error_class,token_cost,source_call_cost,created_at FROM situation_observation_runs WHERE id=?`, id).
		Scan(&out.id, &out.situationID, &out.inputVersion, &out.proposedJSON, &out.validatedJSON,
			&out.capability, &out.scopeJSON, &out.parametersJSON, &out.budget, &out.status, &out.observedAt,
			&out.freshness, &out.truncated, &out.digest, &out.retryClass, &out.tokenCost,
			&out.sourceCallCost, &out.createdAt)
	if err != nil {
		return preparedObservationRun{}, fmt.Errorf("store: read observation run replay: %w", err)
	}
	return out, nil
}

func readPreparedFact(ctx context.Context, tx *sql.Tx, id string) (preparedFact, error) {
	var out preparedFact
	err := tx.QueryRowContext(ctx, `SELECT id,situation_id,input_version,kind,subject,value_json,source_capability,
		observed_at,freshness,result_status,digest,evidence_refs_json,material,created_at FROM situation_facts WHERE id=?`, id).
		Scan(&out.id, &out.situationID, &out.inputVersion, &out.kind, &out.subject, &out.valueJSON,
			&out.capability, &out.observedAt, &out.freshness, &out.status, &out.digest,
			&out.evidenceRefsJSON, &out.material, &out.createdAt)
	if err != nil {
		return preparedFact{}, fmt.Errorf("store: read situation fact replay: %w", err)
	}
	return out, nil
}

func readPreparedAssessmentAttempt(ctx context.Context, tx *sql.Tx, id string) (preparedAssessmentAttempt, error) {
	var out preparedAssessmentAttempt
	var proposal, validated, modelUsage, completed sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id,situation_id,sequence,input_version,fact_hash,actor,status,
		trigger_reasons_json,snapshot_digest,proposal_json,validated_json,validation_adjustments_json,
		model_usage_json,created_at,completed_at FROM situation_assessment_attempts WHERE id=?`, id).
		Scan(&out.id, &out.situationID, &out.sequence, &out.inputVersion, &out.factHash, &out.actor,
			&out.status, &out.triggerReasonsJSON, &out.snapshotDigest, &proposal, &validated,
			&out.adjustmentsJSON, &modelUsage, &out.createdAt, &completed)
	if err != nil {
		return preparedAssessmentAttempt{}, fmt.Errorf("store: read assessment attempt replay: %w", err)
	}
	out.proposalJSON = nullableAny(proposal)
	out.validatedJSON = nullableAny(validated)
	out.modelUsageJSON = nullableAny(modelUsage)
	out.completedAt = nullableAny(completed)
	return out, nil
}

func equalPreparedAssessmentAttempt(left, right preparedAssessmentAttempt) bool {
	return left.id == right.id && left.situationID == right.situationID && left.sequence == right.sequence &&
		left.inputVersion == right.inputVersion && left.factHash == right.factHash && left.actor == right.actor &&
		left.status == right.status && left.triggerReasonsJSON == right.triggerReasonsJSON &&
		left.snapshotDigest == right.snapshotDigest && left.adjustmentsJSON == right.adjustmentsJSON &&
		left.createdAt == right.createdAt && equalNullableAny(left.proposalJSON, right.proposalJSON) &&
		equalNullableAny(left.validatedJSON, right.validatedJSON) && equalNullableAny(left.modelUsageJSON, right.modelUsageJSON) &&
		equalNullableAny(left.completedAt, right.completedAt)
}

func nullableAny(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func equalNullableAny(left, right any) bool {
	leftText, leftOK := left.(string)
	rightText, rightOK := right.(string)
	return leftOK == rightOK && (!leftOK || leftText == rightText)
}

func anyTextSize(value any) int {
	text, _ := value.(string)
	return len(text)
}

func verifySituationFence(ctx context.Context, tx *sql.Tx, claim SituationClaim) error {
	if claim.Situation.ID == "" || claim.Situation.InputVersion < 1 || claim.ClaimOwner == "" || claim.ClaimToken <= 0 {
		return errors.New("store: situation persistence requires a claimed input version")
	}
	var inputVersion int
	var owner sql.NullString
	var token int64
	if err := tx.QueryRowContext(ctx, `SELECT input_version,lease_owner,claim_token FROM situations WHERE id=?`, claim.Situation.ID).
		Scan(&inputVersion, &owner, &token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: read situation persistence fence: %w", err)
	}
	if inputVersion != claim.Situation.InputVersion {
		return ErrSituationVersionConflict
	}
	if !owner.Valid || owner.String != claim.ClaimOwner || token != claim.ClaimToken {
		return ErrSituationLeaseLost
	}
	return nil
}

func correctedSourceTime(field string, existing sql.NullString, basis situationmodel.SourceTimeBasis, proposed *time.Time) (any, situationmodel.SourceTimeBasis, bool, error) {
	if proposed == nil {
		if existing.Valid {
			return existing.String, basis, false, nil
		}
		return nil, basis, false, nil
	}
	canonical := canonicalTime(*proposed)
	if existing.Valid && existing.String == canonical && basis == situationmodel.SourceTimeBasisSourceAPI {
		return existing.String, basis, false, nil
	}
	if basis == situationmodel.SourceTimeBasisSourcePayload {
		return nil, basis, false, fmt.Errorf("store: source api cannot replace source_payload %s provenance", field)
	}
	if basis == situationmodel.SourceTimeBasisSourceAPI && existing.Valid {
		return nil, basis, false, fmt.Errorf("store: source api %s provenance is immutable after confirmation", field)
	}
	return canonical, situationmodel.SourceTimeBasisSourceAPI, true, nil
}

func canonicalSourceTime(value *time.Time) bool {
	return value == nil || (!value.IsZero() && value.Location() == time.UTC)
}

func nullableJSON(value json.RawMessage) (any, error) {
	if len(value) == 0 {
		return nil, nil
	}
	if !json.Valid(value) || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, errors.New("must be non-null json")
	}
	return string(value), nil
}

func validAssessmentActor(value AssessmentActor) bool {
	return value == AssessmentActorDeterministicController || value == AssessmentActorLLM
}

func validAssessmentStatus(value AssessmentStatus) bool {
	switch value {
	case AssessmentStatusProposed, AssessmentStatusAuthoritative, AssessmentStatusRejected, AssessmentStatusFailed, AssessmentStatusStale:
		return true
	default:
		return false
	}
}

func storeValidResultStatus(value observationmodel.ResultStatus) bool {
	switch value {
	case observationmodel.ResultStatusConfirmedValue, observationmodel.ResultStatusConfirmedEmpty,
		observationmodel.ResultStatusUnconfirmedEmpty, observationmodel.ResultStatusUnavailable,
		observationmodel.ResultStatusFailed, observationmodel.ResultStatusStale,
		observationmodel.ResultStatusTruncated, observationmodel.ResultStatusWithheldByBudget,
		observationmodel.ResultStatusVocabularyUnresolved:
		return true
	default:
		return false
	}
}

func storeValidFreshness(value observationmodel.Freshness) bool {
	return value == observationmodel.FreshnessFresh || value == observationmodel.FreshnessStale || value == observationmodel.FreshnessUnknown
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
