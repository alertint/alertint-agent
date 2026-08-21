// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// problemEpisodeFact is one closed or ongoing Zabbix problem episode — the
// problem timeline the Situation controller reasons about duration and
// recurrence with. It carries no raw API payload.
type problemEpisodeFact struct {
	EventID         string     `json:"event_id"`
	TriggerID       string     `json:"trigger_id"`
	Name            string     `json:"name"`
	Severity        string     `json:"severity"`
	StartedAt       time.Time  `json:"started_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	DurationSeconds int64      `json:"duration_seconds"`
	Ongoing         bool       `json:"ongoing"`
	Acknowledged    bool       `json:"acknowledged"`
	Suppressed      bool       `json:"suppressed"`
}

// zabbixProblemExecutor reduces one host's problem history to bounded episode
// facts. It is a pure read (problem.get/event.get); nothing is acknowledged,
// closed, or otherwise mutated in Zabbix.
type zabbixProblemExecutor struct {
	client ZabbixReader
}

func (e zabbixProblemExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	host := plan.Scope["host"]
	if host == "" {
		return nil, observation.Cost{}, fmt.Errorf("%w: zabbix_problem_history requires host scope", ErrPlanParameters)
	}
	// Host resolution, the problem read, and the resolution read.
	cost := observation.Cost{SourceCalls: 3}
	rows, err := e.client.ProblemHistory(ctx, host, in.Start, in.End, in.Params.SeverityMin, in.Limit)
	if err != nil {
		return nil, cost, err
	}
	if len(rows) == 0 {
		return nil, cost, nil
	}
	facts := make([]observationmodel.Fact, 0, len(rows))
	truncated := false
	for _, row := range rows {
		if row.Truncated {
			truncated = true
		}
		episode := problemEpisodeFact{
			EventID: row.EventID, TriggerID: row.TriggerID, Name: row.Name, Severity: row.Severity,
			StartedAt: row.StartedAt.UTC(), DurationSeconds: row.DurationSeconds, Ongoing: row.Ongoing,
			Acknowledged: row.Acknowledged, Suppressed: row.Suppressed,
		}
		if row.ResolvedAt != nil {
			resolved := row.ResolvedAt.UTC()
			episode.ResolvedAt = &resolved
		}
		observedAt := episode.StartedAt
		if episode.ResolvedAt != nil {
			observedAt = *episode.ResolvedAt
		}
		fact, err := in.fact(observationmodel.CapabilityZabbixProblemHistory, "problem_episode",
			host+":"+row.EventID, episode, observedAt, []string{"zabbix:event:" + row.EventID})
		if err != nil {
			return nil, cost, err
		}
		facts = append(facts, fact)
	}
	sortFactsBySubject(facts)
	if truncated {
		// The source itself reported a cut result; saying so is what keeps a
		// bounded read from reading as a complete history.
		return facts, cost, fmt.Errorf("%w: zabbix problem history was cut at the source bound", observation.ErrTruncated)
	}
	return facts, cost, nil
}
