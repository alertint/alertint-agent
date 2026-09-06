// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// ChangesStore is the narrow bounded-query boundary ChangesExecutor
// depends on; *store.Store structurally satisfies it via
// ChangesInScopeWindow. Like store_read, this is a local SQL read against
// AlertINT's own store, never external I/O, so it never uses the
// RequestRecorder's physical-request budget (spec.md's capability table
// describes change_events, like store_read, as reading the "existing
// locally ingested change ledger" — there is no uncertain external
// dispatch here for the reservation system to protect).
type ChangesStore interface {
	ChangesInScopeWindow(ctx context.Context, labels map[string]string, start, end time.Time, limit int) ([]model.LocalChange, bool, error)
}

// ChangesExecutor implements observation.Executor for change_events: the
// existing locally ingested change ledger, exact applicable scope, and a
// bounded UTC window — never the installation-wide ChangesInWindow query.
type ChangesExecutor struct {
	Store ChangesStore
	Clock func() time.Time
}

func (e *ChangesExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

// Execute never uses recorder: see the type doc comment. It is still
// accepted (matching observation.Executor) so the runner can treat every
// capability identically.
func (e *ChangesExecutor) Execute(ctx context.Context, plan model.Plan, _ observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	if len(plan.Scope.Labels) == 0 {
		return unresolvedRun(plan, now), nil
	}

	limit := plan.Limit
	if limit <= 0 {
		limit = 10
	}
	changes, truncated, err := e.Store.ChangesInScopeWindow(ctx, plan.Scope.Labels, plan.Start, plan.End, limit)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: changes in scope window: %w", err)
	}

	status := model.ResultConfirmedEmpty
	if len(changes) > 0 {
		status = model.ResultConfirmedValue
	}
	if truncated {
		status = model.ResultTruncated
	}

	value, err := json.Marshal(changes)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal changes: %w", err)
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	fact := model.Fact{
		ID: factID(plan.ID, "change_event", value), RunID: "run:" + plan.ID,
		Kind: "change_event", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: status, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}

	var limitationCodes []string
	if truncated {
		limitationCodes = []string{"truncated"}
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: !truncated, Returned: len(changes)},
		Facts:           []model.Fact{fact},
		LimitationCodes: limitationCodes,
		ObservedAt:      now, ExpiresAt: expiresAt,
	}, nil
}
