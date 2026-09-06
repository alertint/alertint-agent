// SPDX-License-Identifier: FSL-1.1-ALv2

// Package connectors implements internal/observation's Executor interface
// for each production evidence source. store.go is the local (no external
// I/O) store_read capability; the remaining six live alongside it as later
// tasks land.
package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// LocalStore is the narrow local-read boundary StoreReadExecutor depends
// on; *store.Store structurally satisfies it.
type LocalStore interface {
	PriorTerminalSituationSummaries(ctx context.Context, groupKey, excludeSituationID string, limit int) ([]model.LocalSituationSummary, error)
	RecentFindingsForGroup(ctx context.Context, groupKey string, since time.Time, limit int) ([]model.LocalFinding, error)
}

// StoreReadExecutor implements observation.Executor for store_read: bounded
// prior Situations and durable Findings drawn from AlertINT's own local
// store, existing delivery truth only (spec.md: "a lack of prior rows is
// insufficient history"). It never performs external I/O and never spends
// the RequestRecorder's physical-request budget: spec.md says store_read
// consumes a local plan/row budget, not a physical network slot.
type StoreReadExecutor struct {
	Store LocalStore
	Clock func() time.Time
}

// storeReadParameters is store_read's own typed Plan.Parameters shape.
// ExcludeSituationID lets the planner keep the current Situation's own row
// out of its "prior Situations" evidence.
type storeReadParameters struct {
	GroupKey           string `json:"group_key"`
	ExcludeSituationID string `json:"exclude_situation_id,omitempty"`
}

func (e *StoreReadExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

// Execute never uses recorder: see the type doc comment. It is still
// accepted (matching observation.Executor) so the runner can treat every
// capability identically.
func (e *StoreReadExecutor) Execute(ctx context.Context, plan model.Plan, _ observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	params := storeReadParameters{GroupKey: plan.Scope.GroupKey}
	if len(plan.Parameters) > 0 {
		if err := json.Unmarshal(plan.Parameters, &params); err != nil {
			return unresolvedRun(plan, now), nil
		}
	}
	if params.GroupKey == "" {
		return unresolvedRun(plan, now), nil
	}

	limit := plan.Limit
	if limit <= 0 {
		limit = 20
	}

	situations, err := e.Store.PriorTerminalSituationSummaries(ctx, params.GroupKey, params.ExcludeSituationID, limit)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: store_read prior situations: %w", err)
	}
	since := now.Add(-model.MaxWindowDaysHistory * 24 * time.Hour)
	findings, err := e.Store.RecentFindingsForGroup(ctx, params.GroupKey, since, limit)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: store_read recent findings: %w", err)
	}

	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	var facts []model.Fact
	if len(situations) > 0 {
		f, err := situationSummaryFact(plan, situations, now, expiresAt)
		if err != nil {
			return model.Run{}, err
		}
		facts = append(facts, f)
	}
	if len(findings) > 0 {
		f, err := findingsFact(plan, findings, now, expiresAt)
		if err != nil {
			return model.Run{}, err
		}
		facts = append(facts, f)
	}

	status := model.ResultConfirmedEmpty
	if len(facts) > 0 {
		status = model.ResultConfirmedValue
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage:   model.Coverage{Start: plan.Start, End: plan.End, Complete: true, Returned: len(facts)},
		Facts:      facts,
		ObservedAt: now, ExpiresAt: expiresAt,
	}, nil
}

func unresolvedRun(plan model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: model.ResultVocabularyUnresolved,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: false},
		LimitationCodes: []string{"vocabulary_unresolved"},
		ObservedAt:      now, ExpiresAt: now.Add(24 * time.Hour),
	}
}

func situationSummaryFact(plan model.Plan, situations []model.LocalSituationSummary, now, expiresAt time.Time) (model.Fact, error) {
	value, err := json.Marshal(situations)
	if err != nil {
		return model.Fact{}, fmt.Errorf("connectors: marshal prior situation summaries: %w", err)
	}
	return model.Fact{
		ID: factID(plan.ID, "source_lifecycle", value), RunID: "run:" + plan.ID,
		Kind: "source_lifecycle", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: model.ResultConfirmedValue, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}, nil
}

func findingsFact(plan model.Plan, findings []model.LocalFinding, now, expiresAt time.Time) (model.Fact, error) {
	value, err := json.Marshal(findings)
	if err != nil {
		return model.Fact{}, fmt.Errorf("connectors: marshal recent findings: %w", err)
	}
	return model.Fact{
		ID: factID(plan.ID, "prior_finding", value), RunID: "run:" + plan.ID,
		Kind: "capability_result", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: model.ResultConfirmedValue, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}, nil
}

func digestOf(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func factID(planID, kind string, value []byte) string {
	return "fact:" + kind + ":" + planID + ":" + digestOf(value)[:16]
}
