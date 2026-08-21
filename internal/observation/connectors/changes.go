// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ChangeReader is the read-only change-event surface. Change rows are already
// AlertINT's own durable projection of deploys/releases, so this reads local
// state and touches no operated system at all.
type ChangeReader interface {
	ChangesInWindow(ctx context.Context, start, end time.Time) ([]store.Change, error)
}

// changeEventFact is one bounded change event.
type changeEventFact struct {
	ChangeID   string    `json:"change_id"`
	Source     string    `json:"source"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title"`
	Version    string    `json:"version,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// changeExecutor reduces the change events inside the plan's window, narrowed
// to the plan's scope so an unrelated deploy never becomes this Situation's
// evidence.
type changeExecutor struct {
	store ChangeReader
}

func (e changeExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	cost := observation.Cost{SourceCalls: 1}
	changes, err := e.store.ChangesInWindow(ctx, in.Start, in.End)
	if err != nil {
		return nil, cost, err
	}
	facts := make([]observationmodel.Fact, 0, len(changes))
	for _, change := range changes {
		if !changeInScope(change, plan.Scope) {
			continue
		}
		if in.Limit > 0 && len(facts) >= in.Limit {
			break
		}
		reduced := changeEventFact{
			ChangeID: change.ID, Source: change.Source, Kind: change.Kind, Title: change.Title,
			Version: change.Version, OccurredAt: change.OccurredAt.UTC(),
		}
		fact, err := in.fact(observationmodel.CapabilityChangeEvents, "change_event", change.ID, reduced,
			reduced.OccurredAt, []string{"change:" + change.ID})
		if err != nil {
			return nil, cost, err
		}
		facts = append(facts, fact)
	}
	if len(facts) == 0 {
		return nil, cost, nil
	}
	sortFactsBySubject(facts)
	return facts, cost, nil
}

// changeInScope keeps only changes whose own labels agree with every scope
// key the plan constrained. A change with no opinion on a key is not excluded
// by it — absence of a label is not disagreement.
func changeInScope(change store.Change, scope map[string]string) bool {
	for _, key := range []string{"host", "service", "environment", "project"} {
		want := strings.TrimSpace(scope[key])
		if want == "" {
			continue
		}
		got, ok := change.Labels[key]
		if ok && !strings.EqualFold(strings.TrimSpace(got), want) {
			return false
		}
	}
	return true
}
