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
	"maps"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

var ErrExpectedBehaviorValidationStale = errors.New("store: expected behavior validation is stale")

// ExpectedBehaviorValidationPrepare requests bounded, non-authoritative
// current-state proof for proposed companion/forbidden bindings.
type ExpectedBehaviorValidationPrepare struct {
	SituationID           string
	SituationInputVersion int
	Bindings              []model.ExpectedBehaviorBinding
	Now                   time.Time
	FreshFor              time.Duration
}

// PrepareExpectedBehaviorValidation coalesces an identical current request.
// A new request wakes only its Situation and stores the post-wake input
// version so its own durable wake does not immediately make it stale.
func (s *Store) PrepareExpectedBehaviorValidation(ctx context.Context, req ExpectedBehaviorValidationPrepare) (model.ExpectedBehaviorValidation, error) {
	bindings, digest, err := canonicalExpectedBehaviorBindings(req.Bindings)
	if err != nil {
		return model.ExpectedBehaviorValidation{}, err
	}
	if strings.TrimSpace(req.SituationID) == "" || req.SituationInputVersion < 1 || req.Now.IsZero() {
		return model.ExpectedBehaviorValidation{}, errors.New("store: validation requires situation, input version, and time")
	}
	if req.FreshFor <= 0 {
		req.FreshFor = 5 * time.Minute
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: begin expected behavior validation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Coalesce both an exact retry using the pre-wake version and a client
	// retry that first re-read the post-wake Situation version.
	for _, version := range []int{req.SituationInputVersion, req.SituationInputVersion + 1} {
		prior, found, err := readExpectedBehaviorValidationTx(ctx, tx, req.SituationID, version, digest)
		if err != nil {
			return model.ExpectedBehaviorValidation{}, err
		}
		if found && req.Now.Before(prior.ExpiresAt) {
			if err := tx.Commit(); err != nil {
				return model.ExpectedBehaviorValidation{}, err
			}
			return prior, nil
		}
	}

	sit, err := getSituationTx(ctx, tx, req.SituationID)
	if err != nil {
		return model.ExpectedBehaviorValidation{}, err
	}
	if sit.InputVersion != req.SituationInputVersion || sit.Lifecycle.Terminal() {
		return model.ExpectedBehaviorValidation{}, ErrExpectedBehaviorValidationStale
	}

	status := model.ExpectedBehaviorValidationPending
	targetVersion := sit.InputVersion + 1
	if len(bindings) == 0 {
		status = model.ExpectedBehaviorValidationReady
		targetVersion = sit.InputVersion
	}
	bindingsJSON, err := json.Marshal(bindings)
	if err != nil {
		return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: marshal expected behavior bindings: %w", err)
	}
	now := req.Now.UTC()
	validation := model.ExpectedBehaviorValidation{
		ID: uuid.NewString(), SituationID: sit.ID, SituationInputVersion: targetVersion,
		BindingDigest: digest, Bindings: bindings, Status: status,
		Observations: []model.ExpectedBehaviorBindingObservation{}, ExpiresAt: now.Add(req.FreshFor), CreatedAt: now, UpdatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO expected_behavior_validation_requests (
			id,situation_id,situation_input_version,binding_digest,bindings_json,status,
			observation_refs_json,observations_json,unavailable_reason,expires_at,created_at,updated_at
		) VALUES (?,?,?,?,?,?,'[]','[]',NULL,?,?,?)`, validation.ID, validation.SituationID,
		validation.SituationInputVersion, validation.BindingDigest, string(bindingsJSON), validation.Status,
		canonicalTime(validation.ExpiresAt), canonicalTime(now), canonicalTime(now)); err != nil {
		return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: insert expected behavior validation: %w", err)
	}
	if status == model.ExpectedBehaviorValidationPending {
		due := mergeDueReason(sit.DueReasons, model.DueEnvelopeChanged)
		dueJSON, err := json.Marshal(due)
		if err != nil {
			return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: marshal expected behavior validation wake: %w", err)
		}
		res, err := tx.ExecContext(ctx, `UPDATE situations SET input_version=input_version+1,next_assessment_at=?,due_reasons_json=?,lease_owner=NULL,lease_expires_at=NULL,retry_at=NULL,updated_at=? WHERE id=? AND input_version=? AND lifecycle IN ('active','recovery_pending')`,
			canonicalTime(now), string(dueJSON), canonicalTime(now), sit.ID, sit.InputVersion)
		if err != nil {
			return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: wake expected behavior validation: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return model.ExpectedBehaviorValidation{}, ErrExpectedBehaviorValidationStale
		}
	}
	if err := tx.Commit(); err != nil {
		return model.ExpectedBehaviorValidation{}, fmt.Errorf("store: commit expected behavior validation: %w", err)
	}
	return validation, nil
}

// GetExpectedBehaviorValidation reads a receipt and derives staleness and
// expiry against current durable state.
func (s *Store) GetExpectedBehaviorValidation(ctx context.Context, id string, now time.Time) (model.ExpectedBehaviorValidation, error) {
	var currentVersion int
	v, err := scanExpectedBehaviorValidation(s.db.QueryRowContext(ctx, expectedBehaviorValidationSelect+` WHERE v.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT input_version FROM situations WHERE id=?`, v.SituationID).Scan(&currentVersion); err != nil {
		return v, err
	}
	if currentVersion != v.SituationInputVersion {
		v.Status = model.ExpectedBehaviorValidationStale
		return v, nil
	}
	if !now.IsZero() && !now.Before(v.ExpiresAt) {
		v.Status = model.ExpectedBehaviorValidationUnavailable
		v.UnavailableReason = "validation_expired"
	}
	return v, nil
}

// ListPendingExpectedBehaviorValidations returns the exact requests this
// fenced preparation cycle must observe.
func (s *Store) ListPendingExpectedBehaviorValidations(ctx context.Context, situationID string, inputVersion int, now time.Time) ([]model.ExpectedBehaviorValidation, error) {
	rows, err := s.db.QueryContext(ctx, expectedBehaviorValidationSelect+`
		WHERE v.situation_id=? AND v.situation_input_version=? AND v.status='pending' AND v.expires_at>?
		ORDER BY v.created_at,v.id`, situationID, inputVersion, canonicalTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: list pending expected behavior validations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []model.ExpectedBehaviorValidation{}
	for rows.Next() {
		v, err := scanExpectedBehaviorValidation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CompleteExpectedBehaviorValidation commits worker observations under the
// original Situation/input/binding fence.
func (s *Store) CompleteExpectedBehaviorValidation(ctx context.Context, id, situationID string, inputVersion int, observations []model.ExpectedBehaviorBindingObservation, unavailableReason string, now time.Time) (model.ExpectedBehaviorValidation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ExpectedBehaviorValidation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	v, err := scanExpectedBehaviorValidation(tx.QueryRowContext(ctx, expectedBehaviorValidationSelect+` WHERE v.id=?`, id))
	if err != nil {
		return v, err
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, `SELECT input_version FROM situations WHERE id=?`, situationID).Scan(&currentVersion); err != nil {
		return v, err
	}
	if v.SituationID != situationID || v.SituationInputVersion != inputVersion || currentVersion != inputVersion || v.Status != model.ExpectedBehaviorValidationPending || !now.Before(v.ExpiresAt) {
		return v, ErrExpectedBehaviorValidationStale
	}
	status := model.ExpectedBehaviorValidationReady
	if unavailableReason != "" {
		status = model.ExpectedBehaviorValidationUnavailable
		observations = []model.ExpectedBehaviorBindingObservation{}
	} else if err := validateExpectedBehaviorObservations(v.Bindings, observations, now); err != nil {
		return v, err
	}
	refs := make([]string, 0, len(observations))
	for _, observation := range observations {
		refs = append(refs, observation.EvidenceRefs...)
	}
	sort.Strings(refs)
	refs = compactStrings(refs)
	observationsJSON, err := json.Marshal(observations)
	if err != nil {
		return v, fmt.Errorf("store: marshal expected behavior observations: %w", err)
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return v, fmt.Errorf("store: marshal expected behavior observation refs: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE expected_behavior_validation_requests SET status=?,observation_refs_json=?,observations_json=?,unavailable_reason=?,updated_at=? WHERE id=? AND status='pending'`,
		status, string(refsJSON), string(observationsJSON), nullIfEmpty(unavailableReason), canonicalTime(now), id)
	if err != nil {
		return v, fmt.Errorf("store: complete expected behavior validation: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return v, ErrExpectedBehaviorValidationStale
	}
	if err := tx.Commit(); err != nil {
		return v, err
	}
	v.Status, v.Observations, v.UnavailableReason, v.UpdatedAt = status, observations, unavailableReason, now.UTC()
	return v, nil
}

// CompleteExpectedBehaviorValidationsFromCycle reduces ordinary persisted
// observation runs into validation receipts. The runs remain the evidence
// source; the receipt only records their fact identities and normalized
// current-state values.
func (s *Store) CompleteExpectedBehaviorValidationsFromCycle(ctx context.Context, fence observationmodel.Fence, cycle observationmodel.Cycle, now time.Time) error { //nolint:gocyclo // ordered validation gates must preserve precise unavailable reasons.
	validations, err := s.ListPendingExpectedBehaviorValidations(ctx, fence.SituationID, fence.InputVersion, now)
	if err != nil {
		return err
	}
	for _, validation := range validations {
		byRole := make(map[string]model.ExpectedBehaviorBindingObservation, len(validation.Bindings))
		unavailable := ""
		for _, binding := range validation.Bindings {
			purpose := "expected_behavior_validation:" + validation.ID + ":" + binding.Role
			var plan *observationmodel.Plan
			for i := range cycle.Draft.Plans {
				if cycle.Draft.Plans[i].Purpose == purpose {
					plan = &cycle.Draft.Plans[i]
					break
				}
			}
			if plan == nil {
				unavailable = "validation_plan_missing"
				break
			}
			record, found, err := s.LoadObservationRun(ctx, "run:"+plan.ID)
			if err != nil {
				return err
			}
			if !found || (record.Run.Status != observationmodel.ResultConfirmedValue && record.Run.Status != observationmodel.ResultConfirmedEmpty) || len(record.Run.Facts) != 1 {
				unavailable = validationUnavailableReason(record.Run.Status)
				break
			}
			fact := record.Run.Facts[0]
			if fact.Freshness != observationmodel.FreshnessFresh || !fact.ExpiresAt.After(now) {
				unavailable = "observation_unavailable"
				break
			}
			if binding.Source == "alertmanager" {
				if fact.Kind != "source_definition" {
					unavailable = "observation_unavailable"
					break
				}
				var observed observationmodel.SourceDefinitionObservation
				if err := json.Unmarshal(fact.Value, &observed); err != nil {
					return fmt.Errorf("store: decode expected behavior validation fact: %w", err)
				}
				if !observed.Available || observed.InstanceID != binding.SourceInstanceID || observed.ProducerID != binding.ProducerID || observed.RuleID != binding.RuleID || observed.Version != binding.RuleVersion || !maps.Equal(observed.ScopeLabels, binding.ScopeLabels) {
					unavailable = "binding_identity_changed"
					break
				}
				byRole[binding.Role] = model.ExpectedBehaviorBindingObservation{Binding: binding, Presence: observed.Presence, EvidenceRefs: []string{fact.ID}, ObservedAt: fact.ObservedAt, ExpiresAt: fact.ExpiresAt}
				continue
			}
			if fact.Kind != "zabbix_problem_state" {
				unavailable = "observation_unavailable"
				break
			}
			var observed observationmodel.ZabbixProblemStateObservation
			if err := json.Unmarshal(fact.Value, &observed); err != nil {
				return fmt.Errorf("store: decode expected behavior validation fact: %w", err)
			}
			if observed.SourceInstanceID != binding.SourceInstanceID || observed.Host != binding.Host || observed.TriggerID != binding.TriggerID || observed.TriggerVersion != binding.TriggerVersion {
				unavailable = "binding_identity_changed"
				break
			}
			byRole[binding.Role] = model.ExpectedBehaviorBindingObservation{
				Binding: binding, Presence: string(observed.Presence), EvidenceRefs: []string{fact.ID},
				ObservedAt: fact.ObservedAt, ExpiresAt: fact.ExpiresAt,
			}
		}
		observations := make([]model.ExpectedBehaviorBindingObservation, 0, len(validation.Bindings))
		if unavailable == "" {
			for _, binding := range validation.Bindings {
				observations = append(observations, byRole[binding.Role])
			}
		}
		if _, err := s.CompleteExpectedBehaviorValidation(ctx, validation.ID, fence.SituationID, fence.InputVersion, observations, unavailable, now); err != nil {
			if errors.Is(err, ErrExpectedBehaviorValidationStale) {
				continue
			}
			return err
		}
	}
	return nil
}

func validationUnavailableReason(status observationmodel.ResultStatus) string {
	switch status { //nolint:exhaustive // every other closed result is a generic unavailable observation here.
	case observationmodel.ResultWithheldByBudget:
		return "budget_deferred"
	case observationmodel.ResultVocabularyUnresolved:
		return "capability_unavailable"
	case observationmodel.ResultUnavailable, observationmodel.ResultFailed:
		return "source_unavailable"
	default:
		return "observation_unavailable"
	}
}

const expectedBehaviorValidationSelect = `SELECT v.id,v.situation_id,v.situation_input_version,v.binding_digest,v.bindings_json,v.status,v.observations_json,COALESCE(v.unavailable_reason,''),v.expires_at,v.created_at,v.updated_at FROM expected_behavior_validation_requests v`

func readExpectedBehaviorValidationTx(ctx context.Context, tx *sql.Tx, situationID string, inputVersion int, digest string) (model.ExpectedBehaviorValidation, bool, error) {
	v, err := scanExpectedBehaviorValidation(tx.QueryRowContext(ctx, expectedBehaviorValidationSelect+` WHERE v.situation_id=? AND v.situation_input_version=? AND v.binding_digest=?`, situationID, inputVersion, digest))
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	return v, err == nil, err
}

func scanExpectedBehaviorValidation(row scanner) (model.ExpectedBehaviorValidation, error) {
	var v model.ExpectedBehaviorValidation
	var bindingsJSON, observationsJSON, status, expiresAt, createdAt, updatedAt string
	if err := row.Scan(&v.ID, &v.SituationID, &v.SituationInputVersion, &v.BindingDigest, &bindingsJSON, &status, &observationsJSON, &v.UnavailableReason, &expiresAt, &createdAt, &updatedAt); err != nil {
		return v, err
	}
	v.Status = model.ExpectedBehaviorValidationStatus(status)
	if err := json.Unmarshal([]byte(bindingsJSON), &v.Bindings); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(observationsJSON), &v.Observations); err != nil {
		return v, err
	}
	var err error
	if v.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt); err != nil {
		return v, err
	}
	if v.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return v, err
	}
	v.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return v, err
}

// ExpectedBehaviorBindingDigest exposes the canonical proof identity used by
// MCP and controller code without exposing persistence details.
func ExpectedBehaviorBindingDigest(bindings []model.ExpectedBehaviorBinding) (string, error) {
	_, digest, err := canonicalExpectedBehaviorBindings(bindings)
	return digest, err
}

func canonicalExpectedBehaviorBindings(bindings []model.ExpectedBehaviorBinding) ([]model.ExpectedBehaviorBinding, string, error) {
	out := append([]model.ExpectedBehaviorBinding{}, bindings...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		aRaw, _ := json.Marshal(a)
		bRaw, _ := json.Marshal(b)
		return string(aRaw) < string(bRaw)
	})
	seenRoles, seenBindings := map[string]bool{}, map[string]bool{}
	for _, b := range out {
		if strings.TrimSpace(b.Role) == "" || strings.TrimSpace(b.SourceInstanceID) == "" {
			return nil, "", errors.New("store: validation bindings require role and exact source identity")
		}
		key := b.SourceInstanceID + "\x00" + b.Host + "\x00" + b.TriggerID
		switch b.Source {
		case "zabbix":
			if b.Host == "" || b.TriggerID == "" || b.TriggerVersion == "" {
				return nil, "", errors.New("store: validation bindings require exact Zabbix host, trigger, and version")
			}
		case "alertmanager":
			if b.ProducerID == "" || b.RuleID == "" || b.RuleVersion == "" || b.RuleGroup == "" || b.RuleName == "" || len(b.ScopeLabels) == 0 {
				return nil, "", errors.New("store: validation bindings require exact Alertmanager producer, rule, scope, and version")
			}
			scope, err := json.Marshal(b.ScopeLabels)
			if err != nil {
				return nil, "", fmt.Errorf("store: encode validation binding scope: %w", err)
			}
			key = b.SourceInstanceID + "\x00" + b.ProducerID + "\x00" + b.RuleID + "\x00" + string(scope)
		default:
			return nil, "", errors.New("store: validation bindings require a supported source")
		}
		if seenRoles[b.Role] || seenBindings[key] {
			return nil, "", errors.New("store: validation bindings must have unique roles and source identities")
		}
		seenRoles[b.Role], seenBindings[key] = true, true
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, "", fmt.Errorf("store: marshal validation binding digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return out, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateExpectedBehaviorObservations(bindings []model.ExpectedBehaviorBinding, observations []model.ExpectedBehaviorBindingObservation, now time.Time) error {
	if len(bindings) != len(observations) {
		return errors.New("store: validation completion requires one observation per binding")
	}
	byRole := make(map[string]model.ExpectedBehaviorBindingObservation, len(observations))
	for _, observation := range observations {
		if observation.Presence != "present" && observation.Presence != "absent" {
			return errors.New("store: validation observation presence must be present or absent")
		}
		if observation.ObservedAt.IsZero() || !observation.ExpiresAt.After(now) || len(observation.EvidenceRefs) == 0 {
			return errors.New("store: validation observation must be fresh and carry evidence")
		}
		byRole[observation.Binding.Role] = observation
	}
	for _, binding := range bindings {
		observation, ok := byRole[binding.Role]
		if !ok || !reflect.DeepEqual(observation.Binding, binding) {
			return errors.New("store: validation observation does not match proposed binding")
		}
	}
	return nil
}

func compactStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
