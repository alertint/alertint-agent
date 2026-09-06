// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/sentry"
)

type fakeSentryClient struct {
	page          sentry.IssuePage
	err           error
	physicalCalls int
}

func (f *fakeSentryClient) ListIssuesBounded(ctx context.Context, project, env string, start, end time.Time, query string, limit int,
	before func() error, after func(started bool, err error)) (sentry.IssuePage, error) {
	if err := before(); err != nil {
		return sentry.IssuePage{}, err
	}
	f.physicalCalls++
	after(true, f.err)
	if f.err != nil {
		return sentry.IssuePage{}, f.err
	}
	return f.page, nil
}

func mappedProjectEnv(project, env string) func(model.Scope) (string, string, bool) {
	return func(model.Scope) (string, string, bool) { return project, env, true }
}

func TestSentryExecutorConfirmedValueWithMessageGated(t *testing.T) {
	client := &fakeSentryClient{page: sentry.IssuePage{Issues: []sentry.Issue{
		{ID: "1", Metadata: sentry.IssueMetadata{Type: "ValueError", Value: "sensitive detail"}},
	}}}
	e := &SentryExecutor{Client: client, ProjectEnv: mappedProjectEnv("checkout", "prod"), IncludeMessage: false}
	plan := testStorePlan()

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_value" {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}
	var summary sentryIssuesSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Issues[0].ExceptionType != "ValueError" {
		t.Fatalf("exception type = %q, want ValueError", summary.Issues[0].ExceptionType)
	}
	if summary.Issues[0].ExceptionMessage != "" {
		t.Fatal("exception message must be gated off when IncludeMessage=false")
	}
}

func TestSentryExecutorIncludesMessageWhenEnabled(t *testing.T) {
	client := &fakeSentryClient{page: sentry.IssuePage{Issues: []sentry.Issue{
		{ID: "1", Metadata: sentry.IssueMetadata{Type: "ValueError", Value: "detail"}},
	}}}
	e := &SentryExecutor{Client: client, ProjectEnv: mappedProjectEnv("checkout", "prod"), IncludeMessage: true}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	var summary sentryIssuesSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Issues[0].ExceptionMessage != "detail" {
		t.Fatal("expected exception message included when IncludeMessage=true")
	}
}

func TestSentryExecutorTruncatedWhenHasMore(t *testing.T) {
	client := &fakeSentryClient{page: sentry.IssuePage{Issues: []sentry.Issue{{ID: "1"}}, HasMore: true}}
	e := &SentryExecutor{Client: client, ProjectEnv: mappedProjectEnv("checkout", "prod")}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "truncated" {
		t.Fatalf("status = %q, want truncated", run.Status)
	}
}

func TestSentryExecutorUnresolvedWithoutMapping(t *testing.T) {
	e := &SentryExecutor{Client: &fakeSentryClient{}, ProjectEnv: func(model.Scope) (string, string, bool) { return "", "", false }}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}
