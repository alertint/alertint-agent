// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/sentry"
)

// IssueLister is the read-only Sentry issue surface.
type IssueLister interface {
	ListIssues(ctx context.Context, project, env string, start, end time.Time, query string) ([]sentry.Issue, error)
}

// errorIssueFact is the bounded shape of one Sentry issue. It deliberately
// omits Title and any message body: an exception value routinely embeds user
// data, and evidence keeps the shape, not the payload (KTD8).
type errorIssueFact struct {
	IssueID   string    `json:"issue_id"`
	Level     string    `json:"level"`
	Culprit   string    `json:"culprit"`
	Events    int       `json:"events"`
	Users     int       `json:"affected_users"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// issueExecutor reduces one Sentry issue listing.
type issueExecutor struct {
	client IssueLister
}

func (e issueExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	project := plan.Scope["project"]
	if project == "" {
		return nil, observation.Cost{}, fmt.Errorf("%w: sentry_issues requires project scope", ErrPlanParameters)
	}
	cost := observation.Cost{SourceCalls: 1}
	issues, err := e.client.ListIssues(ctx, project, plan.Scope["environment"], in.Start, in.End, in.Params.Query)
	if err != nil {
		return nil, cost, err
	}
	if len(issues) == 0 {
		return nil, cost, nil
	}
	if in.Limit > 0 && len(issues) > in.Limit {
		issues = issues[:in.Limit]
	}
	facts := make([]observationmodel.Fact, 0, len(issues))
	for _, issue := range issues {
		reduced := errorIssueFact{
			IssueID: issue.ID, Level: issue.Level, Culprit: issue.Culprit,
			Events: int(issue.Count), Users: issue.UserCount,
			FirstSeen: issue.FirstSeen.UTC(), LastSeen: issue.LastSeen.UTC(),
		}
		fact, err := in.fact(observationmodel.CapabilitySentryIssues, "error_issue",
			project+":"+issue.ID, reduced, reduced.LastSeen, []string{"sentry:issue:" + issue.ID})
		if err != nil {
			return nil, cost, err
		}
		facts = append(facts, fact)
	}
	sortFactsBySubject(facts)
	return facts, cost, nil
}
