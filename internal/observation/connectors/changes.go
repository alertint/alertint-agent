// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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

	// Canonical order (newest first, then id) before hashing (F28); an empty
	// ledger marshals as "[]", never "null".
	changes = slices.Clone(changes)
	if changes == nil {
		changes = []model.LocalChange{}
	}
	slices.SortFunc(changes, func(a, b model.LocalChange) int {
		if c := b.OccurredAt.Compare(a.OccurredAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	value, kept, err := fitFactValue(len(changes), func(n int) ([]byte, error) {
		return json.Marshal(changes[:n])
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal changes: %w", err)
	}
	omitted := len(changes) - kept
	if truncated {
		omitted++ // the store reported more rows than the limit
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "change_event", Value: value, Returned: kept, Omitted: omitted,
		Truncated: truncated, Capped: kept < len(changes),
		ExpiresAt: now.Add(model.MaxWindowDaysHistory * 24 * time.Hour),
	}), nil
}
