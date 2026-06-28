// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
)

// --------------------------------------------------------------------------
// Fake SentryReader + JSON construction helpers
// --------------------------------------------------------------------------

type fakeSentry struct {
	issues    []sentry.Issue
	listErr   error
	events    map[string]sentry.IssueEvent
	eventErrs map[string]error

	listCalls          int
	eventCalls         int
	listCtxHadDeadline bool
	listedProject      string
	listedEnv          string
}

func (f *fakeSentry) ListIssues(ctx context.Context, project, env string, _, _ time.Time, _ string) ([]sentry.Issue, error) {
	f.listCalls++
	f.listedProject, f.listedEnv = project, env
	_, f.listCtxHadDeadline = ctx.Deadline()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.issues, nil
}

func (f *fakeSentry) LatestEvent(_ context.Context, issueID string) (sentry.IssueEvent, error) {
	f.eventCalls++
	if f.eventErrs != nil {
		if err := f.eventErrs[issueID]; err != nil {
			return sentry.IssueEvent{}, err
		}
	}
	return f.events[issueID], nil
}

// mkIssue builds a sentry.Issue from JSON so the unexported count-decode type is
// exercised through the real path (the acutetriage package can't name it).
func mkIssue(t *testing.T, raw string) sentry.Issue {
	t.Helper()
	var i sentry.Issue
	if err := json.Unmarshal([]byte(raw), &i); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	return i
}

func mkEvent(t *testing.T, raw string) sentry.IssueEvent {
	t.Helper()
	var ev sentry.IssueEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	return ev
}

func sentryParams(includeMessage bool) SentryParams {
	return SentryParams{Enabled: true, LookbackMinutes: 8, MaxIssues: 3, FetchTimeoutSeconds: 15, IncludeMessage: includeMessage}
}

var (
	scopeFirst = time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	scopeLast  = time.Date(2026, 6, 26, 12, 8, 0, 0, time.UTC) // W = [11:52, 12:08]
)

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestFetchSentry_UnconfiguredReturnsNil(t *testing.T) {
	alerts := alertsWithLabels(map[string]string{"service": "checkout"})
	// Disabled.
	if got := FetchSentry(context.Background(), &fakeSentry{}, SentryParams{Enabled: false}, alerts, scopeFirst, scopeLast, "i", slog.Default()); got != nil {
		t.Fatal("disabled must return nil")
	}
	// Nil reader (true nil interface) even when enabled.
	if got := FetchSentry(context.Background(), nil, sentryParams(true), alerts, scopeFirst, scopeLast, "i", slog.Default()); got != nil {
		t.Fatal("nil reader must return nil")
	}
}

func TestFetchSentry_MembershipNoveltyRanking(t *testing.T) {
	fk := &fakeSentry{
		issues: []sentry.Issue{
			mkIssue(t, `{"id":"A","level":"error","userCount":3,"count":"40",
				"firstSeen":"2026-06-26T11:54:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"KeyError"}}`),
			mkIssue(t, `{"id":"B","level":"error","userCount":50,"count":"900",
				"firstSeen":"2026-06-05T09:00:00Z","lastSeen":"2026-06-26T12:05:00Z","metadata":{"type":"TimeoutError"}}`),
			mkIssue(t, `{"id":"C","level":"error","userCount":1,"count":"5",
				"firstSeen":"2026-06-26T11:40:00Z","lastSeen":"2026-06-26T11:45:00Z","metadata":{"type":"OldError"}}`),
		},
		events: map[string]sentry.IssueEvent{},
	}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout", "environment": "production"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil {
		t.Fatal("want non-nil enrichment")
	}
	if len(got.Issues) != 2 {
		t.Fatalf("want 2 in-window issues (C dropped, not active in W), got %d: %#v", len(got.Issues), got.Issues)
	}
	// A is NEW (firstSeen ∈ W) → ranks first despite far smaller blast radius than B.
	if got.Issues[0].ExceptionType != "KeyError" || !got.Issues[0].New {
		t.Errorf("issue[0] should be NEW KeyError: %#v", got.Issues[0])
	}
	if got.Issues[1].ExceptionType != "TimeoutError" || got.Issues[1].New {
		t.Errorf("issue[1] should be chronic TimeoutError: %#v", got.Issues[1])
	}
	if got.MoreCount != 0 {
		t.Errorf("MoreCount = %d, want 0", got.MoreCount)
	}
	if fk.listCalls != 1 || fk.eventCalls != 2 {
		t.Errorf("calls: list=%d event=%d, want 1 + 2", fk.listCalls, fk.eventCalls)
	}
	if fk.listedProject != "checkout" || fk.listedEnv != "production" {
		t.Errorf("scope passed = %q/%q, want checkout/production", fk.listedProject, fk.listedEnv)
	}
}

func TestFetchSentry_ZeroMatchesNegativeSignal(t *testing.T) {
	fk := &fakeSentry{issues: nil}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout", "environment": "production"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || len(got.Issues) != 0 {
		t.Fatalf("want non-nil enrichment with no issues, got %#v", got)
	}
	if got.Note != "no Sentry issues for project=checkout env=production in window" {
		t.Errorf("note = %q", got.Note)
	}
	if fk.listCalls != 1 || fk.eventCalls != 0 {
		t.Errorf("calls: list=%d event=%d, want 1 + 0", fk.listCalls, fk.eventCalls)
	}
}

func TestFetchSentry_RateLimitedDegrades(t *testing.T) {
	fk := &fakeSentry{listErr: &sentry.APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"}}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || !strings.Contains(got.Note, "rate-limited") {
		t.Fatalf("want rate-limited degraded note, got %#v", got)
	}
	if fk.eventCalls != 0 {
		t.Errorf("no LatestEvent calls expected on degrade, got %d", fk.eventCalls)
	}
}

func TestFetchSentry_UnknownProject404(t *testing.T) {
	fk := &fakeSentry{listErr: &sentry.APIError{StatusCode: http.StatusNotFound, Body: "not found"}}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "typo-slug"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil {
		t.Fatal("want non-nil enrichment")
	}
	if strings.Contains(got.Note, "rate-limited") {
		t.Errorf("404 must NOT read as rate-limited: %q", got.Note)
	}
	if !strings.Contains(got.Note, "typo-slug") || !strings.Contains(got.Note, "did not match") {
		t.Errorf("want unknown-project note mentioning the slug, got %q", got.Note)
	}
	if fk.eventCalls != 0 {
		t.Errorf("no LatestEvent calls on unknown project, got %d", fk.eventCalls)
	}
}

func TestFetchSentry_NoScopeOmits(t *testing.T) {
	fk := &fakeSentry{}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"alertname": "HighLatency", "severity": "page"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got != nil {
		t.Fatalf("no derivable project → nil omit, got %#v", got)
	}
	if fk.listCalls != 0 {
		t.Errorf("no Sentry calls expected with no scope, got %d", fk.listCalls)
	}
}

func TestFetchSentry_PIIMessageToggle(t *testing.T) {
	const pii = "jane.doe@acme.com"
	raw := `{"id":"X","title":"KeyError: missing tenant_id for ` + pii + `","level":"fatal","userCount":2,"count":"10",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z",
		"metadata":{"type":"KeyError","value":"missing tenant_id for ` + pii + `"},"culprit":"app.checkout in pay"}`

	for _, includeMsg := range []bool{true, false} {
		fk := &fakeSentry{issues: []sentry.Issue{mkIssue(t, raw)}, events: map[string]sentry.IssueEvent{}}
		got := FetchSentry(context.Background(), fk, sentryParams(includeMsg),
			alertsWithLabels(map[string]string{"service": "checkout"}),
			scopeFirst, scopeLast, "inc1", slog.Default())
		if got == nil || len(got.Issues) != 1 {
			t.Fatalf("include=%v: want one issue, got %#v", includeMsg, got)
		}
		v := got.Issues[0]
		// Exception type always from metadata.type — never the PII-bearing title.
		if v.ExceptionType != "KeyError" {
			t.Errorf("include=%v: ExceptionType = %q, want KeyError", includeMsg, v.ExceptionType)
		}
		for _, field := range []string{v.ExceptionType, v.Culprit, v.FileLine, v.Level} {
			if strings.Contains(field, pii) {
				t.Errorf("include=%v: PII leaked into a non-message field %q", includeMsg, field)
			}
		}
		if includeMsg {
			if !strings.Contains(v.Message, pii) {
				t.Errorf("include on: message should carry the verbatim value, got %q", v.Message)
			}
		} else if v.Message != "" {
			t.Errorf("include off: message must be stripped, got %q", v.Message)
		}
	}
}

// When metadata.type is absent (e.g. a captureMessage-style issue), the type is
// sourced from the issue title, which Sentry formats as "{type}: {value}" and so
// embeds the (often PII) exception value. The title fallback must therefore honor
// the include_message toggle exactly like Message does — otherwise the value
// leaks into ExceptionType (and thus the prompt, SQLite, and MCP) even with the
// toggle off (KTD8/R14). The KeyError-typed PIIMessageToggle case never reaches
// this branch, so it is covered here explicitly.
func TestFetchSentry_NoMetadataTypeTitleFallbackRespectsToggle(t *testing.T) {
	const pii = "jane.doe@acme.com"
	raw := `{"id":"X","title":"missing tenant_id for ` + pii + `","level":"error","userCount":1,"count":"4",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z",
		"metadata":{},"culprit":"app.checkout in pay"}`

	t.Run("toggle off strips the title-embedded value from ExceptionType", func(t *testing.T) {
		fk := &fakeSentry{issues: []sentry.Issue{mkIssue(t, raw)}, events: map[string]sentry.IssueEvent{}}
		got := FetchSentry(context.Background(), fk, sentryParams(false),
			alertsWithLabels(map[string]string{"service": "checkout"}),
			scopeFirst, scopeLast, "inc1", slog.Default())
		if got == nil || len(got.Issues) != 1 {
			t.Fatalf("want one issue, got %#v", got)
		}
		v := got.Issues[0]
		for _, field := range []string{v.ExceptionType, v.Culprit, v.FileLine, v.Level, v.Message} {
			if strings.Contains(field, pii) {
				t.Errorf("include off: PII leaked via title fallback into %q", field)
			}
		}
		if v.ExceptionType != "unknown" {
			t.Errorf("include off, no metadata.type: ExceptionType = %q, want neutral placeholder", v.ExceptionType)
		}
	})

	t.Run("toggle on may surface the title (operator opted into messages)", func(t *testing.T) {
		fk := &fakeSentry{issues: []sentry.Issue{mkIssue(t, raw)}, events: map[string]sentry.IssueEvent{}}
		got := FetchSentry(context.Background(), fk, sentryParams(true),
			alertsWithLabels(map[string]string{"service": "checkout"}),
			scopeFirst, scopeLast, "inc1", slog.Default())
		if got == nil || len(got.Issues) != 1 {
			t.Fatalf("want one issue, got %#v", got)
		}
		if v := got.Issues[0]; v.ExceptionType == "unknown" || !strings.Contains(v.ExceptionType, pii) {
			t.Errorf("include on: want title fallback carrying the value, got ExceptionType %q", v.ExceptionType)
		}
	})
}

func TestFetchSentry_BudgetOnePlusK(t *testing.T) {
	issues := make([]sentry.Issue, 0, 5)
	for _, id := range []string{"i1", "i2", "i3", "i4", "i5"} {
		issues = append(issues, mkIssue(t, `{"id":"`+id+`","level":"error","userCount":1,"count":"3",
			"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"}}`))
	}
	fk := &fakeSentry{issues: issues, events: map[string]sentry.IssueEvent{}}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || len(got.Issues) != 3 || got.MoreCount != 2 {
		t.Fatalf("want top-3 + MoreCount 2, got %#v", got)
	}
	if fk.listCalls != 1 || fk.eventCalls != 3 {
		t.Errorf("budget violated: list=%d event=%d, want 1 + 3", fk.listCalls, fk.eventCalls)
	}
}

func TestFetchSentry_DeepestFrameAndCulpritFallback(t *testing.T) {
	withFrame := mkIssue(t, `{"id":"hasframe","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.a in f"}`)
	noFrame := mkIssue(t, `{"id":"noframe","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.b in g"}`)
	fk := &fakeSentry{
		issues: []sentry.Issue{withFrame, noFrame},
		events: map[string]sentry.IssueEvent{
			"hasframe": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[
				{"type":"E","stacktrace":{"frames":[{"filename":"app/x.py","lineNo":99,"inApp":true}]}}]}}]}`),
			"noframe": {}, // empty event → no in-app frame → culprit fallback
		},
	}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || len(got.Issues) != 2 {
		t.Fatalf("want 2 issues, got %#v", got)
	}
	byType := map[string]SentryIssueView{}
	for _, v := range got.Issues {
		byType[v.FileLine] = v
	}
	if _, ok := byType["app/x.py:99"]; !ok {
		t.Errorf("deepest in-app frame not rendered as file:line: %#v", got.Issues)
	}
	// The no-frame issue carries an empty FileLine; the renderer falls back to culprit.
	var sawCulpritFallback bool
	for _, v := range got.Issues {
		if v.FileLine == "" && v.Culprit == "app.b in g" {
			sawCulpritFallback = true
		}
	}
	if !sawCulpritFallback {
		t.Errorf("no-frame issue should fall back to culprit with empty FileLine: %#v", got.Issues)
	}
}

// TestAnalysis_ShortCircuitSkipsSentry pins R1: the known-issue short-circuit
// returns before the enrichment fan-out, so FetchSentry is never reached and no
// Sentry call is made — verified directly against the unexported analysis() path
// with a recording fake (no rule-pack scaffolding needed).
func TestAnalysis_ShortCircuitSkipsSentry(t *testing.T) {
	fk := &fakeSentry{issues: []sentry.Issue{mkIssue(t, `{"id":"x","metadata":{"type":"E"},
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z"}`)}}
	s := &Skill{cfg: Config{Sentry: fk, SentryParams: sentryParams(true)}, logger: slog.Default()}
	decision := rules.Decision{
		Rule:          &rules.Rule{ID: "ki.x", Description: "known issue"},
		ShortCircuit:  true,
		RootCauseHint: "boom",
	}
	alerts := alertsWithLabels(map[string]string{"service": "checkout"})
	raw, logEnr, chg, sen, err := s.analysis(context.Background(), store.Incident{ID: "i1"}, alerts, decision, EvidencePack{}, []byte("{}"))
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if len(raw) == 0 {
		t.Error("short-circuit should still synthesize a finding")
	}
	if logEnr != nil || chg != nil || sen != nil {
		t.Errorf("short-circuit must return nil enrichments, got sentry=%v", sen)
	}
	if fk.listCalls != 0 {
		t.Errorf("short-circuit must make no Sentry call, got %d", fk.listCalls)
	}
}

func TestFetchSentry_SharedDeadlineAndPerIssueErrorDegrades(t *testing.T) {
	good := mkIssue(t, `{"id":"good","level":"error","userCount":5,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.good in f"}`)
	bad := mkIssue(t, `{"id":"bad","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.bad in g"}`)
	fk := &fakeSentry{
		issues:    []sentry.Issue{good, bad},
		events:    map[string]sentry.IssueEvent{"good": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","stacktrace":{"frames":[{"filename":"app/ok.py","lineNo":7,"inApp":true}]}}]}}]}`)},
		eventErrs: map[string]error{"bad": context.DeadlineExceeded},
	}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || len(got.Issues) != 2 {
		t.Fatalf("one failing LatestEvent must not abort the section, got %#v", got)
	}
	if !fk.listCtxHadDeadline {
		t.Error("ListIssues ctx should carry the shared fetch deadline")
	}
	// The good issue keeps its file:line; the bad one degrades to culprit only.
	for _, v := range got.Issues {
		if v.Culprit == "app.bad in g" && v.FileLine != "" {
			t.Errorf("failed-fetch issue should have no FileLine: %#v", v)
		}
	}
}
