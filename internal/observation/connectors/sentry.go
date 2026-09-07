// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
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

// SentryExecutor implements observation.Executor for sentry_issues: the
// existing configured service-to-project/environment mapping, bounded
// issue-summary fetch with pagination/truncation metadata, and the
// existing exception/message privacy switch (IncludeMessage) — never
// Issue.Title, which embeds the message unconditionally.
type SentryExecutor struct {
	Client SentryClient
	// ProjectEnv resolves scope to its configured Sentry project/environment;
	// ok=false means no mapping exists for this scope (unresolvable, never a
	// broad fallback to an arbitrary project).
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

func (e *SentryExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	if e.ProjectEnv == nil {
		return unresolvedRun(plan, now), nil
	}
	project, env, ok := e.ProjectEnv(plan.Scope)
	if !ok || project == "" {
		return unresolvedRun(plan, now), nil
	}

	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = defaultMaxSentryIssues
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	page, err := e.Client.ListIssuesBounded(ctx, project, env, plan.Start, plan.End, "", limit, before, after)
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

	value, kept, err := fitFactValue(len(issues), func(n int) ([]byte, error) {
		return json.Marshal(sentryIssuesSummary{Project: project, Environment: env, HasMore: page.HasMore, Issues: issues[:n]})
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal sentry issues summary: %w", err)
	}
	omitted := len(issues) - kept
	if page.HasMore {
		omitted++ // the source reports at least one further page
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "error_issue", Value: value, Returned: kept, Omitted: omitted,
		Truncated: page.HasMore, Capped: kept < len(issues), ExpiresAt: expiresAt,
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
