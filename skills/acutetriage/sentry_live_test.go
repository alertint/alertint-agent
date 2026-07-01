// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/sentry"
)

// Live window bounds used across the live-read tests (distinct from the triage
// scopeFirst/scopeLast). W = [11:00, 12:08].
var (
	liveStart = time.Date(2026, 6, 26, 11, 0, 0, 0, time.UTC)
	liveEnd   = time.Date(2026, 6, 26, 12, 8, 0, 0, time.UTC)
)

func listParams(includeMsg bool, status SentryStatus, limit int) ListParams {
	return ListParams{
		Params:  sentryParams(includeMsg),
		Project: "checkout",
		Env:     "prod",
		Start:   liveStart,
		End:     liveEnd,
		Status:  status,
		Limit:   limit,
	}
}

// serialize marshals any value so a test can assert a substring appears nowhere in
// the output the agent would receive — the end-to-end boundary check.
func serialize(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestParseSentryStatus(t *testing.T) {
	cases := map[string]SentryStatus{
		"":           StatusUnresolved, // default
		"unresolved": StatusUnresolved,
		"resolved":   StatusResolved,
		"ignored":    StatusIgnored,
	}
	for in, want := range cases {
		got, err := ParseSentryStatus(in)
		if err != nil || got != want {
			t.Errorf("ParseSentryStatus(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
	if _, err := ParseSentryStatus("muted"); err == nil {
		t.Error("unknown status must be rejected")
	}
}

// Covers AE2: each status maps to exactly one explicit is: token; the token passed
// to ListIssues is NEVER the empty string (so the empty-query coercion is never hit).
func TestSentryStatus_ExplicitQueryTokens(t *testing.T) {
	want := map[SentryStatus]string{
		StatusUnresolved: "is:unresolved",
		StatusResolved:   "is:resolved",
		StatusIgnored:    "is:ignored",
	}
	for status, token := range want {
		fk := &fakeSentry{issues: nil}
		_, _, err := ListSentryIssues(context.Background(), fk, listParams(true, status, 20))
		if err != nil {
			t.Fatalf("status %q: %v", status, err)
		}
		if fk.listedQuery != token {
			t.Errorf("status %q → query %q, want %q", status, fk.listedQuery, token)
		}
		if fk.listedQuery == "" {
			t.Errorf("status %q passed an empty query (would hit the coercion trap)", status)
		}
	}
}

// Covers AE1: distilled views ranked NEW-first, each with the allowlist fields and a
// permalink when the issue carried one; more matches than limit → has_more.
func TestListSentryIssues_RankedDistilledHasMore(t *testing.T) {
	newIssue := mkIssue(t, `{"id":"NEW","level":"error","userCount":3,"count":"40","permalink":"https://acme.sentry.io/issues/NEW/",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"KeyError"},"culprit":"app.checkout in pay"}`)
	chronic := mkIssue(t, `{"id":"OLD","level":"error","userCount":50,"count":"900",
		"firstSeen":"2026-06-05T09:00:00Z","lastSeen":"2026-06-26T12:05:00Z","metadata":{"type":"TimeoutError"}}`)
	fk := &fakeSentry{
		issues: []sentry.Issue{chronic, newIssue},
		events: map[string]sentry.IssueEvent{
			"NEW": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"KeyError","stacktrace":{"frames":[{"filename":"app/pay.py","function":"charge","lineNo":88,"inApp":true}]}}]}}]}`),
		},
	}
	views, hasMore, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 1))
	if err != nil {
		t.Fatalf("ListSentryIssues: %v", err)
	}
	if !hasMore {
		t.Error("has_more should be true: 2 active matches, limit 1")
	}
	if len(views) != 1 {
		t.Fatalf("limit 1 → 1 view, got %d", len(views))
	}
	v := views[0]
	if v.ExceptionType != "KeyError" || !v.New {
		t.Errorf("NEW issue should rank first: %+v", v)
	}
	if v.ID != "NEW" || v.Permalink != "https://acme.sentry.io/issues/NEW/" {
		t.Errorf("id/permalink = %q/%q", v.ID, v.Permalink)
	}
	if v.FileLine != "app/pay.py:88" {
		t.Errorf("file_line = %q, want app/pay.py:88 (deepest in-app, relative)", v.FileLine)
	}
}

// fan-out is 1 ListIssues + (≤limit) LatestEvent — never 1 per page item.
func TestListSentryIssues_HonorsLimitFanout(t *testing.T) {
	issues := make([]sentry.Issue, 0, 10)
	events := map[string]sentry.IssueEvent{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		issues = append(issues, mkIssue(t, `{"id":"`+id+`","level":"error","userCount":1,"count":"3",
			"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"}}`))
		events[id] = sentry.IssueEvent{}
	}
	fk := &fakeSentry{issues: issues, events: events}
	views, hasMore, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 3))
	if err != nil {
		t.Fatalf("ListSentryIssues: %v", err)
	}
	if len(views) != 3 || !hasMore {
		t.Fatalf("want 3 views + has_more, got %d / %v", len(views), hasMore)
	}
	if fk.listCalls != 1 || fk.eventCalls != 3 {
		t.Errorf("fan-out = 1 list + %d events, want 1 + 3 (not 1 per page item)", fk.eventCalls)
	}
}

// limit defaults to 20 and is capped at 50.
func TestListSentryIssues_LimitClamp(t *testing.T) {
	fk := &fakeSentry{issues: nil}
	if _, _, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 0)); err != nil {
		t.Fatal(err)
	}
	// We cannot observe the internal clamp directly with an empty list, so assert via
	// the helper that drives the same clamp on a populated list.
	mk := func(n int) []sentry.Issue {
		out := make([]sentry.Issue, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, mkIssue(t, `{"id":"x","level":"error","userCount":1,"count":"1",
				"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"}}`))
		}
		return out
	}
	fk2 := &fakeSentry{issues: mk(60), events: map[string]sentry.IssueEvent{"x": {}}}
	views, _, err := ListSentryIssues(context.Background(), fk2, listParams(true, StatusUnresolved, 999))
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 50 {
		t.Errorf("limit 999 should clamp to 50, got %d views", len(views))
	}
}

// Covers AE5: an issue without a permalink → view omits it; nothing is constructed.
func TestListSentryIssues_PermalinkAbsentNotConstructed(t *testing.T) {
	iss := mkIssue(t, `{"id":"NP","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"}}`)
	fk := &fakeSentry{issues: []sentry.Issue{iss}, events: map[string]sentry.IssueEvent{"NP": {}}}
	views, _, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Permalink != "" {
		t.Errorf("absent permalink must stay empty, got %q", views[0].Permalink)
	}
	if strings.Contains(serialize(t, views), "sentry.io/issues") {
		t.Error("a permalink was constructed from nothing")
	}
}

// KTD7: the recurring-now in-window filter is applied ONLY for unresolved. A
// resolved issue last-seen OUTSIDE the live window (a genuinely historical
// resolution) must still surface, so the disposition lookup is not silently
// restricted to errors recurring this hour.
func TestListSentryIssues_ResolvedSkipsInWindowFilter(t *testing.T) {
	historical := mkIssue(t, `{"id":"H","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-05-01T00:00:00Z","lastSeen":"2026-05-01T00:10:00Z","metadata":{"type":"KeyError"}}`)
	fk := &fakeSentry{issues: []sentry.Issue{historical}, events: map[string]sentry.IssueEvent{"H": {}}}

	// Unresolved: the in-window filter drops it (last-seen far before the window).
	uViews, _, _ := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if len(uViews) != 0 {
		t.Errorf("unresolved should drop the out-of-window issue, got %d", len(uViews))
	}

	// Resolved: the filter is skipped, so the historical disposition surfaces.
	fk2 := &fakeSentry{issues: []sentry.Issue{historical}, events: map[string]sentry.IssueEvent{"H": {}}}
	rViews, _, _ := ListSentryIssues(context.Background(), fk2, listParams(true, StatusResolved, 20))
	if len(rViews) != 1 {
		t.Fatalf("resolved should surface the historical issue, got %d", len(rViews))
	}
}

// The prior P1 leak class, re-checked on the wider list surface: empty metadata.type
// × include_message OFF × a PII-bearing title → exception_type is "unknown" and the
// PII appears nowhere; toggle ON may surface it (operator opted in).
func TestListSentryIssues_TitleFallbackToggle(t *testing.T) {
	const pii = "alice@x.com"
	raw := `{"id":"T","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z",
		"title":"KeyError: user=` + pii + ` not found","metadata":{},"culprit":"app.checkout in pay"}`

	fkOff := &fakeSentry{issues: []sentry.Issue{mkIssue(t, raw)}, events: map[string]sentry.IssueEvent{"T": {}}}
	off, _, _ := ListSentryIssues(context.Background(), fkOff, listParams(false, StatusUnresolved, 20))
	if len(off) != 1 || off[0].ExceptionType != "unknown" {
		t.Fatalf("toggle off: want exception_type unknown, got %+v", off)
	}
	if strings.Contains(serialize(t, off), pii) {
		t.Error("toggle off: PII leaked through the list title fallback")
	}

	fkOn := &fakeSentry{issues: []sentry.Issue{mkIssue(t, raw)}, events: map[string]sentry.IssueEvent{"T": {}}}
	on, _, _ := ListSentryIssues(context.Background(), fkOn, listParams(true, StatusUnresolved, 20))
	if !strings.Contains(on[0].ExceptionType, pii) {
		t.Errorf("toggle on: title may surface, got %q", on[0].ExceptionType)
	}
}

// The list sources file:line from the relative-only frame view, NEVER
// DeepestInAppFrame, so the absPath fallback cannot leak on this wider surface
// (KTD2/KTD3). Both an absPath-only frame and an absolute filename key yield empty.
func TestListSentryIssues_FileLineNeverAbsolute(t *testing.T) {
	const home = "/home/deploy/app/views.py"
	iss := mkIssue(t, `{"id":"A","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.a in f"}`)
	// in_app:true, only absPath populated → relative file empty → file_line empty.
	fk := &fakeSentry{
		issues: []sentry.Issue{iss},
		events: map[string]sentry.IssueEvent{
			"A": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","stacktrace":{"frames":[{"absPath":"`+home+`","lineNo":5,"inApp":true}]}}]}}]}`),
		},
	}
	views, _, _ := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if len(views) != 1 || views[0].FileLine != "" {
		t.Fatalf("absPath-only frame should give empty file_line, got %q", views[0].FileLine)
	}
	if strings.Contains(serialize(t, views), home) {
		t.Error("absolute path leaked into the list output")
	}

	// in_app:true, filename key itself absolute (non-Python SDK) → empty too.
	fk2 := &fakeSentry{
		issues: []sentry.Issue{iss},
		events: map[string]sentry.IssueEvent{
			"A": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","stacktrace":{"frames":[{"filename":"/home/deploy/app/handler.js","lineNo":5,"inApp":true}]}}]}}]}`),
		},
	}
	v2, _, _ := ListSentryIssues(context.Background(), fk2, listParams(true, StatusUnresolved, 20))
	if v2[0].FileLine != "" {
		t.Errorf("absolute filename key should give empty file_line, got %q", v2[0].FileLine)
	}
}

// A LatestEvent miss during the list distill degrades that issue to an empty
// file_line (culprit fallback at render) — the list still returns, never an error.
func TestListSentryIssues_PartialOnMiss(t *testing.T) {
	good := mkIssue(t, `{"id":"good","level":"error","userCount":5,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.good"}`)
	bad := mkIssue(t, `{"id":"bad","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"app.bad"}`)
	fk := &fakeSentry{
		issues:    []sentry.Issue{good, bad},
		events:    map[string]sentry.IssueEvent{"good": mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","stacktrace":{"frames":[{"filename":"ok.py","lineNo":7,"inApp":true}]}}]}}]}`)},
		eventErrs: map[string]error{"bad": context.DeadlineExceeded},
	}
	views, _, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if err != nil {
		t.Fatalf("a per-issue miss must not error the list: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("want both issues, got %d", len(views))
	}
	for _, v := range views {
		if v.Culprit == "app.bad" && v.FileLine != "" {
			t.Errorf("missed issue should have empty file_line, got %q", v.FileLine)
		}
	}
}

// Covers AE3, AE7: full frames (file:line + function + in_app) incl. a library frame,
// the event timestamp, and a per-id error for a failing id — partial, never wholesale.
func TestTraceSentryIssues_FullFramesTimestampPartial(t *testing.T) {
	ts := time.Date(2026, 6, 26, 12, 7, 0, 0, time.UTC)
	fk := &fakeSentry{
		events: map[string]sentry.IssueEvent{
			"ok": mkEvent(t, `{"dateCreated":"2026-06-26T12:07:00Z","entries":[{"type":"exception","data":{"values":[{"type":"KeyError","value":"boom",
				"stacktrace":{"frames":[
					{"filename":"app/views.py","function":"checkout","lineNo":88,"inApp":true},
					{"filename":"site-packages/lib.py","function":"wrap","lineNo":12,"inApp":false}
				]}}]}}]}`),
		},
		eventErrs: map[string]error{"gone": context.DeadlineExceeded},
	}
	traces, err := TraceSentryIssues(context.Background(), fk, sentryParams(true), []string{"ok", "gone"})
	if err != nil {
		t.Fatalf("TraceSentryIssues: %v", err)
	}
	if len(traces) != 2 {
		t.Fatalf("want 2 traces, got %d", len(traces))
	}
	byID := map[string]SentryTrace{}
	for _, tr := range traces {
		byID[tr.IssueID] = tr
	}
	ok := byID["ok"]
	if ok.ExceptionType != "KeyError" || ok.ExceptionValue != "boom" {
		t.Errorf("ok trace type/value = %q/%q", ok.ExceptionType, ok.ExceptionValue)
	}
	if ok.EventTimestamp == nil || !ok.EventTimestamp.Equal(ts) {
		t.Errorf("event timestamp = %v, want %v", ok.EventTimestamp, ts)
	}
	if len(ok.Frames) != 2 || ok.Frames[0].File != "app/views.py" || ok.Frames[0].Function != "checkout" || !ok.Frames[0].InApp {
		t.Errorf("ok frames = %+v", ok.Frames)
	}
	if ok.Frames[1].InApp || ok.Frames[1].File != "site-packages/lib.py" {
		t.Errorf("library frame should be present, in_app false: %+v", ok.Frames[1])
	}
	gone := byID["gone"]
	if gone.Error == "" {
		t.Error("the failing id should carry a per-id error")
	}
	// The failed id must OMIT event_timestamp entirely, not plant a year-1 zero
	// value next to its error (the *time.Time omitempty fix).
	if gone.EventTimestamp != nil {
		t.Errorf("failed id must have nil EventTimestamp, got %v", gone.EventTimestamp)
	}
	if out := serialize(t, gone); strings.Contains(out, "event_timestamp") {
		t.Errorf("failed id must omit event_timestamp in JSON, got %s", out)
	}
}

// A 404 from the list endpoint (an unknown project slug) maps to an actionable
// "project not found" error, not the raw "http 404: <body>" — mirroring the triage
// path so an agent can self-correct (and so the response body is not echoed).
func TestListSentryIssues_UnknownProject404(t *testing.T) {
	fk := &fakeSentry{listErr: &sentry.APIError{StatusCode: http.StatusNotFound, Body: "the-raw-404-body"}}
	_, _, err := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if err == nil {
		t.Fatal("a 404 must surface as an error")
	}
	if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "checkout") {
		t.Errorf("want an actionable project-not-found error, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "the-raw-404-body") {
		t.Errorf("the raw 404 body must not be echoed to the agent, got %q", err.Error())
	}
}

func TestTraceSentryIssues_OverCapAndEmptyRejected(t *testing.T) {
	fk := &fakeSentry{events: map[string]sentry.IssueEvent{}}
	ids := make([]string, 11)
	for i := range ids {
		ids[i] = "x"
	}
	if _, err := TraceSentryIssues(context.Background(), fk, sentryParams(true), ids); err == nil {
		t.Error("an over-cap (>10) id list must be rejected")
	}
	if _, err := TraceSentryIssues(context.Background(), fk, sentryParams(true), nil); err == nil {
		t.Error("an empty id list must be rejected")
	}
}

func TestTraceSentryIssues_FrameCap(t *testing.T) {
	var frames strings.Builder
	for i := 0; i < 150; i++ {
		if i > 0 {
			frames.WriteByte(',')
		}
		// Innermost frames last; the innermost (i=149) must survive truncation.
		frames.WriteString(`{"filename":"f` + strconv.Itoa(i) + `.py","function":"fn","lineNo":1,"inApp":true}`)
	}
	ev := mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","stacktrace":{"frames":[`+frames.String()+`]}}]}}]}`)
	fk := &fakeSentry{events: map[string]sentry.IssueEvent{"deep": ev}}
	traces, err := TraceSentryIssues(context.Background(), fk, sentryParams(true), []string{"deep"})
	if err != nil {
		t.Fatal(err)
	}
	tr := traces[0]
	if len(tr.Frames) != 100 || !tr.FramesTruncated {
		t.Fatalf("want 100 frames + truncated flag, got %d / %v", len(tr.Frames), tr.FramesTruncated)
	}
	// The innermost frame (the cause) is kept.
	if tr.Frames[len(tr.Frames)-1].File != "f149.py" {
		t.Errorf("truncation should keep innermost frames, last = %q", tr.Frames[len(tr.Frames)-1].File)
	}
}

// Covers AE4: include_message OFF strips the exception value on the trace but keeps
// the type and frames; ON surfaces the value.
func TestTraceSentryIssues_IncludeMessageToggle(t *testing.T) {
	const pii = "card=4111111111111111"
	ev := mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"KeyError","value":"`+pii+`",
		"stacktrace":{"frames":[{"filename":"app/x.py","function":"f","lineNo":1,"inApp":true}]}}]}}]}`)
	for _, include := range []bool{true, false} {
		fk := &fakeSentry{events: map[string]sentry.IssueEvent{"i": ev}}
		traces, _ := TraceSentryIssues(context.Background(), fk, sentryParams(include), []string{"i"})
		tr := traces[0]
		if tr.ExceptionType != "KeyError" || len(tr.Frames) != 1 {
			t.Fatalf("include=%v: type+frames must always be present, got %+v", include, tr)
		}
		if include {
			if tr.ExceptionValue != pii {
				t.Errorf("include on: want the value present, got %q", tr.ExceptionValue)
			}
		} else {
			if tr.ExceptionValue != "" || strings.Contains(serialize(t, traces), pii) {
				t.Errorf("include off: the value must be stripped, got %q / %s", tr.ExceptionValue, serialize(t, traces))
			}
		}
	}
}

// The trace type has no symmetric title/value fallback: empty exceptionValue.Type →
// empty type, never pulled from anything else (the trace never fetches the Issue).
func TestTraceSentryIssues_TypeNoFallback(t *testing.T) {
	ev := mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"","value":"x",
		"stacktrace":{"frames":[{"filename":"a.py","function":"f","lineNo":1,"inApp":true}]}}]}}]}`)
	fk := &fakeSentry{events: map[string]sentry.IssueEvent{"i": ev}}
	traces, _ := TraceSentryIssues(context.Background(), fk, sentryParams(false), []string{"i"})
	if traces[0].ExceptionType != "" {
		t.Errorf("empty type must stay empty (no fallback), got %q", traces[0].ExceptionType)
	}
}

// End-to-end boundary: a PII-dense event (locals, source context, request,
// breadcrumbs, user) → none of those substrings appear in the trace OR list output.
func TestLive_EndToEndBoundaryNegative(t *testing.T) {
	dense := mkEvent(t, `{"entries":[
		{"type":"exception","data":{"values":[{"type":"KeyError","value":"missing key",
			"stacktrace":{"frames":[{"filename":"app/x.py","function":"f","lineNo":1,"inApp":true,
				"vars":{"password":"hunter2"},"context_line":"secret=load()","pre_context":["pre_leak"],"post_context":["post_leak"]}]}}]}},
		{"type":"request","data":{"url":"https://x/pay?card=4111111111111111"}},
		{"type":"breadcrumbs","data":{"values":[{"message":"bob@acme.com signed in"}]}}
	]}`)
	leaks := []string{"hunter2", "secret=load()", "pre_leak", "post_leak", "4111111111111111", "bob@acme.com"}

	// Trace path (include OFF — the strictest).
	fk := &fakeSentry{events: map[string]sentry.IssueEvent{"i": dense}}
	traces, _ := TraceSentryIssues(context.Background(), fk, sentryParams(false), []string{"i"})
	out := serialize(t, traces)
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Errorf("trace leaked %q: %s", leak, out)
		}
	}

	// List path.
	iss := mkIssue(t, `{"id":"i","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"KeyError"}}`)
	fk2 := &fakeSentry{issues: []sentry.Issue{iss}, events: map[string]sentry.IssueEvent{"i": dense}}
	views, _, _ := ListSentryIssues(context.Background(), fk2, listParams(false, StatusUnresolved, 20))
	lout := serialize(t, views)
	for _, leak := range leaks {
		if strings.Contains(lout, leak) {
			t.Errorf("list leaked %q: %s", leak, lout)
		}
	}
}

// Verbatim Sentry-controlled strings (culprit, function, exception value) are
// length-capped so a payload cannot dominate the agent's context (Risks).
func TestLive_VerbatimLengthCap(t *testing.T) {
	long := strings.Repeat("A", 500)
	// List: long culprit.
	iss := mkIssue(t, `{"id":"i","level":"error","userCount":1,"count":"3",
		"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"},"culprit":"`+long+`"}`)
	fk := &fakeSentry{issues: []sentry.Issue{iss}, events: map[string]sentry.IssueEvent{"i": {}}}
	views, _, _ := ListSentryIssues(context.Background(), fk, listParams(true, StatusUnresolved, 20))
	if len([]rune(views[0].Culprit)) > maxVerbatimLen+1 {
		t.Errorf("culprit not capped: %d runes", len([]rune(views[0].Culprit)))
	}
	// Trace: long function + long exception value + long (relative) frame file.
	longFile := "a/" + strings.Repeat("b", 500) + ".py"
	ev := mkEvent(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E","value":"`+long+`",
		"stacktrace":{"frames":[{"filename":"`+longFile+`","function":"`+long+`","lineNo":1,"inApp":true}]}}]}}]}`)
	fk2 := &fakeSentry{events: map[string]sentry.IssueEvent{"i": ev}}
	traces, _ := TraceSentryIssues(context.Background(), fk2, sentryParams(true), []string{"i"})
	if len([]rune(traces[0].ExceptionValue)) > maxVerbatimLen+1 {
		t.Errorf("exception value not capped: %d runes", len([]rune(traces[0].ExceptionValue)))
	}
	if len([]rune(traces[0].Frames[0].Function)) > maxVerbatimLen+1 {
		t.Errorf("frame function not capped: %d runes", len([]rune(traces[0].Frames[0].Function)))
	}
	// The frame File is a verbatim Sentry-controlled string too — capped (a relative
	// path is still attacker-influenceable).
	if len([]rune(traces[0].Frames[0].File)) > maxVerbatimLen+1 {
		t.Errorf("frame file not capped: %d runes", len([]rune(traces[0].Frames[0].File)))
	}
}

// KTD5/KTD8: the live deadline scales with fan-out, is capped at a ceiling, and is
// NEVER zero (a zero deadline would expire immediately — the KTD8 trap).
func TestLiveDeadline_ScalesCapsNonZero(t *testing.T) {
	p := sentryParams(true) // FetchTimeoutSeconds 15, MaxIssues 3
	d1 := liveDeadline(p, 1)
	d50 := liveDeadline(p, 50)
	if d1 <= 0 {
		t.Errorf("deadline must never be 0 (KTD8), got %v", d1)
	}
	if d50 <= d1 {
		t.Errorf("deadline should scale with fan-out: d(1)=%v d(50)=%v", d1, d50)
	}
	if d50 > liveDeadlineCeiling {
		t.Errorf("deadline must be capped at %v, got %v", liveDeadlineCeiling, d50)
	}
	// Even a degenerate envelope (zero timeout) must not yield a zero deadline.
	if d := liveDeadline(SentryParams{}, 5); d <= 0 {
		t.Errorf("degenerate envelope yielded a non-positive deadline: %v", d)
	}
}

// Adding Permalink to SentryIssueView must not change the triage-persisted JSON:
// the triage distill never sets it, and omitempty drops it.
func TestSentryIssueView_PermalinkOmitemptyTriage(t *testing.T) {
	fk := &fakeSentry{
		issues: []sentry.Issue{mkIssue(t, `{"id":"i","level":"error","userCount":1,"count":"3",
			"firstSeen":"2026-06-26T11:55:00Z","lastSeen":"2026-06-26T12:06:00Z","metadata":{"type":"E"}}`)},
		events: map[string]sentry.IssueEvent{},
	}
	got := FetchSentry(context.Background(), fk, sentryParams(true),
		alertsWithLabels(map[string]string{"service": "checkout"}),
		scopeFirst, scopeLast, "inc1", slog.Default())
	if got == nil || len(got.Issues) != 1 {
		t.Fatalf("want one issue, got %#v", got)
	}
	if strings.Contains(serialize(t, got.Issues[0]), "permalink") {
		t.Errorf("triage view must not serialize a permalink key: %s", serialize(t, got.Issues[0]))
	}
}
