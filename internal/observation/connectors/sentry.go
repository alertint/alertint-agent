// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/sentry"
)

// maxSentryIssues bounds how many issues one fact keeps — the K of the
// existing 1+K enrichment budget's own shape, applied here as the plan's
// own Limit.
const defaultMaxSentryIssues = 10

// SentryClient is the narrow bounded-query boundary SentryExecutor depends
// on; *sentry.Client structurally satisfies it via ListIssuesBounded.
type SentryClient interface {
	ListIssuesBounded(ctx context.Context, project, env string, start, end time.Time, query string, limit int,
		before func() error, after func(started bool, err error)) (sentry.IssuePage, error)
}

// sentryParameters is sentry_issues' own typed Plan.Parameters shape: the
// planner-resolved configured project slug and (optional) environment.
// When present with a project it is authoritative; the ProjectEnv scope
// callback is only the fallback for a plan that carries none.
type sentryParameters struct {
	Project     string `json:"project"`
	Environment string `json:"environment,omitempty"`
}

// SentryExecutor implements observation.Executor for sentry_issues: the
// planner's typed project/environment parameters (or, absent those, the
// existing configured service-to-project/environment mapping), bounded
// issue-summary fetch with pagination/truncation metadata, and the
// existing exception/message privacy switch (IncludeMessage) — never
// Issue.Title, which embeds the message unconditionally.
type SentryExecutor struct {
	Client SentryClient
	// ProjectEnv resolves scope to its configured Sentry project/environment
	// when Plan.Parameters carries no project; ok=false means no mapping
	// exists for this scope (unresolvable, never a broad fallback to an
	// arbitrary project). Scope.Labels carries only allowlisted selector
	// labels, never alert-only ones such as alertname/severity.
	ProjectEnv     func(scope model.Scope) (project, env string, ok bool)
	IncludeMessage bool
	Clock          func() time.Time
}

func (e *SentryExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

// resolveProjectEnv reads the typed parameters first and falls back to the
// scope mapping only when they carry no project. Malformed parameters are
// unresolvable, never silently ignored.
func (e *SentryExecutor) resolveProjectEnv(plan model.Plan) (project, env string, ok bool) {
	if len(plan.Parameters) > 0 {
		var params sentryParameters
		if err := json.Unmarshal(plan.Parameters, &params); err != nil {
			return "", "", false
		}
		if params.Project != "" {
			return params.Project, params.Environment, true
		}
	}
	if e.ProjectEnv == nil {
		return "", "", false
	}
	project, env, ok = e.ProjectEnv(plan.Scope)
	if !ok || project == "" {
		return "", "", false
	}
	return project, env, true
}

func (e *SentryExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	project, env, ok := e.resolveProjectEnv(plan)
	if !ok {
		return unresolvedRun(plan, now), nil
	}

	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = defaultMaxSentryIssues
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	// limit+1: one overflow sentinel issue proves "more than limit" even when
	// the Link header is absent; the header's own more-pages signal is still
	// honoured when present (F20).
	page, err := e.Client.ListIssuesBounded(ctx, project, env, plan.Start, plan.End, "", limit+1, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		if isResponseTooLarge(err) {
			return responseTooLargeRun(plan, now, expiresAt), nil
		}
		return model.Run{}, fmt.Errorf("connectors: sentry list issues: %w", err)
	}

	issues := make([]sentryIssueSummary, 0, len(page.Issues))
	for _, issue := range page.Issues {
		s := sentryIssueSummary{
			ID: issue.ID, ExceptionType: issue.Metadata.Type, Culprit: issue.Culprit, Level: issue.Level,
			Count: issue.EventCount(), UserCount: issue.UserCount,
			FirstSeen: issue.FirstSeen, LastSeen: issue.LastSeen,
		}
		if e.IncludeMessage {
			s.ExceptionMessage = issue.Metadata.Value
		}
		issues = append(issues, s)
	}
	// Canonical order (newest issue id first) before truncation and hashing
	// (F28); the source's own date sort is not a stable identity.
	slices.SortFunc(issues, func(a, b sentryIssueSummary) int { return compareIDs(b.ID, a.ID) })
	issues, omitted, truncated := truncateToLimit(issues, limit)
	if page.HasMore {
		truncated = true
		if omitted == 0 {
			omitted = 1 // the source reports at least one further page
		}
	}

	value, kept, err := fitFactValue(len(issues), func(n int) ([]byte, error) {
		return json.Marshal(sentryIssuesSummary{Project: project, Environment: env, HasMore: truncated, Issues: issues[:n]})
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal sentry issues summary: %w", err)
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "error_issue", Value: value, Returned: kept, Omitted: omitted + len(issues) - kept,
		Truncated: truncated, Capped: kept < len(issues), ExpiresAt: expiresAt,
	}), nil
}

type sentryIssueSummary struct {
	ID               string    `json:"id"`
	ExceptionType    string    `json:"exception_type,omitempty"`
	ExceptionMessage string    `json:"exception_message,omitempty"`
	Culprit          string    `json:"culprit,omitempty"`
	Level            string    `json:"level,omitempty"`
	Count            int       `json:"count"`
	UserCount        int       `json:"user_count"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

type sentryIssuesSummary struct {
	Project     string               `json:"project"`
	Environment string               `json:"environment,omitempty"`
	HasMore     bool                 `json:"has_more"`
	Issues      []sentryIssueSummary `json:"issues,omitempty"`
}
