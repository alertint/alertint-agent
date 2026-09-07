// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
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

// TestSentryExecutorOversizedResponseIsTruncatedWithoutData proves the
// transport's ErrResponseTooLarge (F10) maps to a truncated, incomplete,
// response_too_large run with no facts and a response_too_large outcome.
func TestSentryExecutorOversizedResponseIsTruncatedWithoutData(t *testing.T) {
	client := &fakeSentryClient{err: sentry.ErrResponseTooLarge}
	e := &SentryExecutor{Client: client, ProjectEnv: mappedProjectEnv("checkout", "prod")}
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), testStorePlan(), rec)
	if err != nil {
		t.Fatalf("an over-limit response is a limitation, not an execution error: %v", err)
	}
	if got := rec.codes(); len(got) != 1 || got[0] != "response_too_large" {
		t.Fatalf("outcome codes = %v, want [response_too_large]", got)
	}
	if run.Status != model.ResultTruncated || run.Coverage.Complete || len(run.Facts) != 0 {
		t.Fatalf("run = %+v, want truncated/incomplete with no facts", run)
	}
	if len(run.LimitationCodes) != 1 || run.LimitationCodes[0] != "response_too_large" {
		t.Fatalf("limitation codes = %v", run.LimitationCodes)
	}
}

// TestSentryExecutorCapsFactBytes proves the error_issue fact never exceeds
// model.MaxFactBytes: issues past the cap are dropped deterministically and
// the run says so.
func TestSentryExecutorCapsFactBytes(t *testing.T) {
	issues := make([]sentry.Issue, 40)
	for i := range issues {
		issues[i] = sentry.Issue{ID: strconv.Itoa(1000 + i), Culprit: strings.Repeat("c", 800), Level: "error"}
	}
	client := &fakeSentryClient{page: sentry.IssuePage{Issues: issues}}
	e := &SentryExecutor{Client: client, ProjectEnv: mappedProjectEnv("payments", "staging")}
	plan := testStorePlan()
	plan.Limit = 50

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
		t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
	}
	if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") || run.Coverage.Complete || run.Status != model.ResultTruncated {
		t.Fatalf("run = status %q complete=%v codes=%v, want truncated/fact_bytes_capped", run.Status, run.Coverage.Complete, run.LimitationCodes)
	}
	if run.Coverage.Returned+run.Coverage.Omitted != 40 || run.Coverage.Omitted < 1 {
		t.Fatalf("coverage returned=%d omitted=%d, want a sum of 40 with omitted >= 1", run.Coverage.Returned, run.Coverage.Omitted)
	}
}
