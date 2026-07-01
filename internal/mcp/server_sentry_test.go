// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// fakeSentryReader is a no-HTTP acutetriage.SentryReader for the handler tests; it
// records the query token forwarded to ListIssues so status mapping is observable.
type fakeSentryReader struct {
	issues    []sentry.Issue
	events    map[string]sentry.IssueEvent
	listErr   error
	eventErrs map[string]error
	gotQuery  string
}

func (f *fakeSentryReader) ListIssues(_ context.Context, _, _ string, _, _ time.Time, query string) ([]sentry.Issue, error) {
	f.gotQuery = query
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.issues, nil
}

func (f *fakeSentryReader) LatestEvent(_ context.Context, id string) (sentry.IssueEvent, error) {
	if f.eventErrs != nil {
		if err := f.eventErrs[id]; err != nil {
			return sentry.IssueEvent{}, err
		}
	}
	return f.events[id], nil
}

func mkSentryIssue(t *testing.T, raw string) sentry.Issue {
	t.Helper()
	var i sentry.Issue
	if err := json.Unmarshal([]byte(raw), &i); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	return i
}

func mkSentryEvent(t *testing.T, raw string) sentry.IssueEvent {
	t.Helper()
	var ev sentry.IssueEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	return ev
}

func sentryMCPConfig(r acutetriage.SentryReader, include bool) Config {
	return Config{
		Sentry: r,
		SentryParams: acutetriage.SentryParams{
			Enabled: true, MaxIssues: 3, FetchTimeoutSeconds: 15, IncludeMessage: include,
		},
		SentryLiveWindowMinutes: 60,
	}
}

func TestSentryTools_Definitions(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(sentryMCPConfig(&fakeSentryReader{}, true), st, audit.New(st.DB()))

	list, _ := s.toolSentryIssuesList()
	if list.Name != "sentry_issues_list" {
		t.Errorf("list tool name = %q", list.Name)
	}
	for _, want := range []string{"Read-only", "distilled", "PII"} {
		if !strings.Contains(list.Description, want) {
			t.Errorf("list description missing %q: %q", want, list.Description)
		}
	}
	trace, _ := s.toolSentryIssuesTrace()
	if trace.Name != "sentry_issues_trace" {
		t.Errorf("trace tool name = %q", trace.Name)
	}
	if !strings.Contains(trace.Description, "abs_path") {
		t.Errorf("trace description should state abs_path stays out: %q", trace.Description)
	}
}

// AE6 intent: with no Sentry reader configured (a releases-only / off build), the
// handlers refuse — the same disabled-guard convention the logs/changes tools use,
// and the registration gate (cfg.Sentry != nil) keeps the tools off the surface.
func TestSentryTools_DisabledGuards(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB())) // no Sentry

	lr, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout"}))
	if !lr.IsError || !strings.Contains(resultText(t, lr), "not configured") {
		t.Errorf("list disabled guard: %q", resultText(t, lr))
	}
	tr, _ := s.handleSentryIssuesTrace(context.Background(), reqWith(map[string]any{"issue_ids": []any{"1"}}))
	if !tr.IsError || !strings.Contains(resultText(t, tr), "not configured") {
		t.Errorf("trace disabled guard: %q", resultText(t, tr))
	}
}

// Covers AE1, AE5: the list returns distilled issues + has_more + pii_notice; a
// missing project is an error.
func TestSentryIssuesList_HappyPath(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeSentryReader{
		issues: []sentry.Issue{
			mkSentryIssue(t, `{"id":"NEW","level":"error","userCount":3,"count":"40","permalink":"https://acme.sentry.io/issues/NEW/",
				"firstSeen":"`+recent()+`","lastSeen":"`+recent()+`","metadata":{"type":"KeyError"},"culprit":"app.pay"}`),
		},
		events: map[string]sentry.IssueEvent{"NEW": {}},
	}
	s := NewServer(sentryMCPConfig(fk, true), st, audit.New(st.DB()))

	res, err := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout", "environment": "prod"}))
	if err != nil || res.IsError {
		t.Fatalf("happy path errored: %v / %q", err, resultText(t, res))
	}
	var payload struct {
		Issues    []acutetriage.SentryIssueView `json:"issues"`
		HasMore   bool                          `json:"has_more"`
		PIINotice string                        `json:"pii_notice"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Issues) != 1 || payload.Issues[0].ID != "NEW" {
		t.Fatalf("issues = %+v", payload.Issues)
	}
	if payload.Issues[0].Permalink != "https://acme.sentry.io/issues/NEW/" {
		t.Errorf("permalink not surfaced: %q", payload.Issues[0].Permalink)
	}
	if payload.PIINotice == "" {
		t.Error("pii_notice must be present (AE5)")
	}

	// Missing project → error.
	bad, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{}))
	if !bad.IsError || !strings.Contains(resultText(t, bad), "project is required") {
		t.Errorf("missing project should error: %q", resultText(t, bad))
	}
}

// Covers AE2: status=resolved is forwarded as is:resolved; an invalid status errors.
func TestSentryIssuesList_StatusForwardedAndInvalid(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeSentryReader{issues: nil, events: map[string]sentry.IssueEvent{}}
	s := NewServer(sentryMCPConfig(fk, true), st, audit.New(st.DB()))

	res, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout", "status": "resolved"}))
	if res.IsError {
		t.Fatalf("status=resolved should be accepted: %q", resultText(t, res))
	}
	if fk.gotQuery != "is:resolved" {
		t.Errorf("forwarded query = %q, want is:resolved", fk.gotQuery)
	}

	bad, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout", "status": "bogus"}))
	if !bad.IsError || !strings.Contains(resultText(t, bad), "unknown status") {
		t.Errorf("invalid status should error: %q", resultText(t, bad))
	}
}

func TestSentryIssuesList_WindowValidation(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeSentryReader{issues: nil, events: map[string]sentry.IssueEvent{}}
	s := NewServer(sentryMCPConfig(fk, true), st, audit.New(st.DB()))

	// Explicit start>end → error.
	bad, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{
		"project": "checkout",
		"start":   "2026-06-26T13:00:00Z",
		"end":     "2026-06-26T12:00:00Z",
	}))
	if !bad.IsError || !strings.Contains(resultText(t, bad), "start must be before end") {
		t.Errorf("start>end should error: %q", resultText(t, bad))
	}

	// Malformed start → error.
	bad2, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout", "start": "not-a-time"}))
	if !bad2.IsError || !strings.Contains(resultText(t, bad2), "invalid start") {
		t.Errorf("malformed start should error: %q", resultText(t, bad2))
	}
}

// Covers AE7: the trace returns a partial per-id error; an over-cap or empty id
// list errors. Covers AE5: pii_notice present.
func TestSentryIssuesTrace_PartialOverCapEmpty(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeSentryReader{
		events: map[string]sentry.IssueEvent{
			"ok": mkSentryEvent(t, `{"dateCreated":"2026-06-26T12:07:00Z","entries":[{"type":"exception","data":{"values":[{"type":"KeyError",
				"stacktrace":{"frames":[{"filename":"app/x.py","function":"f","lineNo":1,"inApp":true}]}}]}}]}`),
		},
		eventErrs: map[string]error{"gone": context.DeadlineExceeded},
	}
	s := NewServer(sentryMCPConfig(fk, true), st, audit.New(st.DB()))

	res, err := s.handleSentryIssuesTrace(context.Background(), reqWith(map[string]any{"issue_ids": []any{"ok", "gone"}}))
	if err != nil || res.IsError {
		t.Fatalf("trace errored: %v / %q", err, resultText(t, res))
	}
	var payload struct {
		Traces    []acutetriage.SentryTrace `json:"traces"`
		PIINotice string                    `json:"pii_notice"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Traces) != 2 || payload.PIINotice == "" {
		t.Fatalf("want 2 traces + notice, got %+v", payload)
	}
	var sawError, sawFrames bool
	for _, tr := range payload.Traces {
		if tr.IssueID == "gone" && tr.Error != "" {
			sawError = true
		}
		if tr.IssueID == "ok" && len(tr.Frames) == 1 {
			sawFrames = true
		}
	}
	if !sawError || !sawFrames {
		t.Errorf("want a per-id error for 'gone' and frames for 'ok': %+v", payload.Traces)
	}

	// Over-cap (>10) → error.
	ids := make([]any, 11)
	for i := range ids {
		ids[i] = "x"
	}
	over, _ := s.handleSentryIssuesTrace(context.Background(), reqWith(map[string]any{"issue_ids": ids}))
	if !over.IsError || !strings.Contains(resultText(t, over), "too many issue ids") {
		t.Errorf("over-cap should error: %q", resultText(t, over))
	}

	// Empty → error.
	empty, _ := s.handleSentryIssuesTrace(context.Background(), reqWith(map[string]any{"issue_ids": []any{}}))
	if !empty.IsError || !strings.Contains(resultText(t, empty), "issue_ids is required") {
		t.Errorf("empty ids should error: %q", resultText(t, empty))
	}
}

// Covers AE4: include_message off (resolved via Config.SentryParams.IncludeMessage)
// omits the exception value on both tools.
func TestSentryTools_IncludeMessageOff(t *testing.T) {
	const pii = "card=4111111111111111"
	st := newMCPStore(t)
	ev := mkSentryEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"KeyError","value":"`+pii+`",
		"stacktrace":{"frames":[{"filename":"app/x.py","function":"f","lineNo":1,"inApp":true}]}}]}}]}`)
	fk := &fakeSentryReader{
		issues: []sentry.Issue{mkSentryIssue(t, `{"id":"i","level":"error","userCount":1,"count":"3",
			"firstSeen":"`+recent()+`","lastSeen":"`+recent()+`","metadata":{"type":"KeyError","value":"`+pii+`"}}`)},
		events: map[string]sentry.IssueEvent{"i": ev},
	}
	s := NewServer(sentryMCPConfig(fk, false), st, audit.New(st.DB())) // include OFF

	lr, _ := s.handleSentryIssuesList(context.Background(), reqWith(map[string]any{"project": "checkout"}))
	if strings.Contains(resultText(t, lr), pii) {
		t.Errorf("include off: list leaked the value: %q", resultText(t, lr))
	}
	tr, _ := s.handleSentryIssuesTrace(context.Background(), reqWith(map[string]any{"issue_ids": []any{"i"}}))
	if strings.Contains(resultText(t, tr), pii) {
		t.Errorf("include off: trace leaked the value: %q", resultText(t, tr))
	}
}

// recent returns an RFC3339 timestamp inside the default 60-minute live window so
// the unresolved in-window filter keeps the fixture issue.
func recent() string {
	return time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
}
