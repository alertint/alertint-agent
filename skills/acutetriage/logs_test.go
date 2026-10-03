// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/logs/loki"
	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSource is a controllable logs.Source for skill-level tests. It records the
// selector, window, and limit it was called with, and whether the context it
// received carried a deadline.
type fakeSource struct {
	name        string
	fetched     logs.Fetched
	err         error
	gotSel      logs.Selector
	gotLimit    int
	gotStart    time.Time
	gotEnd      time.Time
	hadDeadline bool
	deadline    time.Time
	calls       int
}

type fakeContrastSource struct {
	*fakeSource

	contrast         logs.Fetched
	contrastErr      error
	contrastCalls    int
	contrastLimit    int
	contrastDeadline time.Time
}

func (f *fakeContrastSource) FetchContrast(ctx context.Context, _ logs.Selector, _, _ time.Time, limit int) (logs.Fetched, error) {
	f.contrastCalls++
	f.contrastLimit = limit
	f.contrastDeadline, _ = ctx.Deadline()
	return f.contrast, f.contrastErr
}

func TestFetchLogs_ContrastOnlyAfterFilteredLines(t *testing.T) {
	lines := []logs.Line{{Timestamp: time.Unix(1, 0), Line: "error loyalty_level=gold"}}
	comparison := make([]logs.Line, 12)
	for i := range comparison {
		comparison[i] = logs.Line{Timestamp: time.Unix(int64(20-i), 0), Line: strings.Repeat("x", 600)}
	}
	for _, tc := range []struct {
		name     string
		filtered bool
		lines    []logs.Line
		want     int
	}{
		{"filtered", true, lines, 1},
		{"fallback", false, lines, 0},
		{"no lines", true, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeContrastSource{fakeSource: &fakeSource{name: "loki", fetched: logs.Fetched{Lines: tc.lines, Filtered: tc.filtered}},
				contrast: logs.Fetched{Lines: comparison}}
			e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50}, alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "inc", nil)
			if src.contrastCalls != tc.want {
				t.Fatalf("contrast calls = %d, want %d", src.contrastCalls, tc.want)
			}
			if tc.want == 1 && (src.contrastLimit != 20 || !src.contrastDeadline.Equal(src.deadline) || len(e.Contrast) != 10 || len([]rune(e.Contrast[0].Line)) != logs.MaxLineChars) {
				t.Fatalf("contrast = %+v, limit %d, deadline %v/%v", e.Contrast, src.contrastLimit, src.contrastDeadline, src.deadline)
			}
		})
	}
}

func TestFetchLogs_ContrastFailureIsBestEffort(t *testing.T) {
	src := &fakeContrastSource{fakeSource: &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Line: "error"}}, Filtered: true}}, contrastErr: context.DeadlineExceeded}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50}, alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "inc", nil)
	if e.Outcome != OutcomeFetched || e.ContrastNote == "" || len(e.Contrast) != 0 {
		t.Fatalf("contrast failure changed main result: %+v", e)
	}
}

func TestContrastSummary_Case014Inconclusive(t *testing.T) {
	errors := make([]logs.Line, 14)
	for i := range errors {
		errors[i] = logs.Line{Line: "Payment request failed. Invalid token. demo.user_context.loyalty_level=gold"}
	}
	comparison := make([]logs.Line, 10)
	for i := range comparison {
		comparison[i] = logs.Line{Line: "Transaction complete."}
	}
	got := contrastSummary(errors, comparison)
	if len(got) != 1 || got[0] != "`demo.user_context.loyalty_level=gold` is on all 14 error lines; the comparison lines don't carry `demo.user_context.loyalty_level`, so the affected group is unknown." {
		t.Fatalf("summary = %v", got)
	}
	if tokens := inconclusiveTokens(errors, comparison); len(tokens) != 1 || tokens[0] != "demo.user_context.loyalty_level=gold" {
		t.Fatalf("inconclusive tokens = %v", tokens)
	}
}

func TestContrastSummary_CountsLinesAndCapsTokens(t *testing.T) {
	errors := []logs.Line{{Line: "a=1 b=2 c=3 d=4"}, {Line: "a=1 b=2 c=3 d=4"}}
	comparison := []logs.Line{{Line: "a=1 then a=1 b=9"}, {Line: "Transaction complete."}}
	got := contrastSummary(errors, comparison)
	if len(got) != 3 || got[0] != "`a=1`: on 2/2 error lines, on 1/2 comparison lines" || got[1] != "`b=2`: on 2/2 error lines, on 0/2 comparison lines" || got[2] != "`c=3` is on all 2 error lines; the comparison lines don't carry `c`, so the affected group is unknown." {
		t.Fatalf("summary = %v", got)
	}
	if strings.Contains(strings.Join(got, "\n"), "d=4") || strings.Contains(strings.Join(got, "\n"), "key b is not") {
		t.Fatalf("token cap or key-presence check failed: %v", got)
	}
	if missing := inconclusiveTokens(errors, comparison); len(missing) != 1 || missing[0] != "c=3" {
		t.Fatalf("missing tokens = %v, want c=3 only", missing)
	}
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) FetchRecent(ctx context.Context, sel logs.Selector, start, end time.Time, limit int) (logs.Fetched, error) {
	f.calls++
	f.gotSel = sel
	f.gotLimit = limit
	f.gotStart = start
	f.gotEnd = end
	f.deadline, f.hadDeadline = ctx.Deadline()
	return f.fetched, f.err
}

func (f *fakeSource) QueryRange(context.Context, string, time.Time, time.Time, int, string) (json.RawMessage, error) {
	return nil, nil
}

func alertsWith(labels map[string]string) []store.Alert {
	// Two identical-labelled alerts so every label is "shared".
	return []store.Alert{
		{ID: "a1", Labels: labels},
		{ID: "a2", Labels: labels},
	}
}

func bufLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})), &buf
}

func TestFetchLogs_NilSourceReturnsNil(t *testing.T) {
	if got := FetchLogs(context.Background(), nil, LogParams{}, alertsWith(map[string]string{"namespace": "p"}), time.Now(), time.Now(), "inc-test", nil); got != nil {
		t.Fatalf("nil source must yield nil enrichment, got %+v", got)
	}
}

func TestFetchLogs_SelectorIsAllowlistIntersection(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}, Query: "{...}"}}
	labels := map[string]string{
		"namespace": "prod", "service": "api", "job": "j", "pod": "p1",
		"container": "c1", "instance": "i1",
		// noise that must be dropped:
		"alertname": "HighCPU", "severity": "critical", "prometheus": "mon/k8s",
	}
	logger, _ := bufLogger()
	FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50}, alertsWith(labels), time.Now(), time.Now(), "inc-test", logger)

	for _, k := range logs.AllowedSelectorKeys {
		got := src.gotSel.Labels[k]
		if len(got) != 1 || got[0] != labels[k] {
			t.Errorf("selector allowlisted key %q = %v, want [%q]", k, got, labels[k])
		}
	}
	for _, noise := range []string{"alertname", "severity", "prometheus"} {
		if _, ok := src.gotSel.Labels[noise]; ok {
			t.Errorf("selector leaked alert-metadata key %q", noise)
		}
	}
	if len(src.gotSel.Labels) != 6 {
		t.Errorf("selector has %d keys, want 6 (no cap, all allowlist keys present)", len(src.gotSel.Labels))
	}
}

// TestFetchLogs_MultiServiceIncidentBuildsSelector is the BUG-1 regression: a
// correlated multi-service incident whose members share the KEYS service/instance
// but with different VALUES must still build a usable selector and fetch lines.
// The old shared-label intersection dropped every discriminating key, produced an
// empty selector, and never hit the backend — exactly on the incidents AlertINT
// exists to correlate.
func TestFetchLogs_MultiServiceIncidentBuildsSelector(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{
		Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "boom"}}, Query: "{...}"}}
	alerts := []store.Alert{
		{ID: "a1", Labels: map[string]string{"cluster": "prod", "service": "api", "instance": "api-1"}},
		{ID: "a2", Labels: map[string]string{"cluster": "prod", "service": "api", "instance": "api-2"}},
		{ID: "a3", Labels: map[string]string{"cluster": "prod", "service": "db-proxy", "instance": "db-proxy-1"}},
	}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alerts, time.Now(), time.Now(), "inc-multi", nil)
	if src.calls != 1 {
		t.Fatalf("correlated multi-service incident must build a usable log selector and hit the backend; calls=%d (empty-selector regression, BUG-1)", src.calls)
	}
	if e == nil || len(e.Lines) == 0 {
		t.Fatalf("want log lines for multi-service incident, got %+v", e)
	}
	// Each allowlisted key present on all members carries the UNION of its values
	// (sorted), not a single one — that is what lets the matcher span every stream.
	if got := src.gotSel.Labels["service"]; !sliceEq(got, []string{"api", "db-proxy"}) {
		t.Errorf("service selector = %v, want union [api db-proxy]", got)
	}
	if got := src.gotSel.Labels["instance"]; !sliceEq(got, []string{"api-1", "api-2", "db-proxy-1"}) {
		t.Errorf("instance selector = %v, want union of all three instances", got)
	}
	// A shared-but-non-allowlisted key (cluster) must not leak into the selector.
	if _, ok := src.gotSel.Labels["cluster"]; ok {
		t.Errorf("non-allowlisted key cluster leaked into selector: %v", src.gotSel.Labels)
	}
}

// TestFetchLogs_PartialKeyCoverageDropsNonUniversalKey proves the selector never
// over-constrains: a key present on only SOME members (here instance, missing on
// the db-proxy member) is dropped, while a key universal to all (service) is kept
// and unioned. AND-combining a non-universal key would exclude the members that
// lack it.
func TestFetchLogs_PartialKeyCoverageDropsNonUniversalKey(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{
		Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "boom"}}, Query: "{...}"}}
	alerts := []store.Alert{
		{ID: "a1", Labels: map[string]string{"service": "api", "instance": "api-1"}},
		{ID: "a2", Labels: map[string]string{"service": "db-proxy"}}, // no instance label
	}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alerts, time.Now(), time.Now(), "inc-partial", nil)
	if e == nil || len(e.Lines) == 0 {
		t.Fatalf("want log lines, got %+v", e)
	}
	if got := src.gotSel.Labels["service"]; !sliceEq(got, []string{"api", "db-proxy"}) {
		t.Errorf("service (universal) = %v, want [api db-proxy]", got)
	}
	if got, ok := src.gotSel.Labels["instance"]; ok {
		t.Errorf("instance (not on every member) must be dropped, got %v", got)
	}
}

// sliceEq reports whether a and b hold the same elements in the same order.
func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFetchLogs_WindowAndLimitAndDeadline(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}}}
	first := time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC)
	last := time.Date(2026, 6, 17, 14, 5, 0, 0, time.UTC)
	FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 42}, alertsWith(map[string]string{"namespace": "p"}), first, last, "inc-test", nil)

	if !src.gotStart.Equal(first.Add(-15 * time.Minute)) {
		t.Errorf("start = %v, want first-15m", src.gotStart)
	}
	if !src.gotEnd.Equal(last) {
		t.Errorf("end = %v, want last", src.gotEnd)
	}
	if src.gotLimit != 42 {
		t.Errorf("limit = %d, want 42 (max_lines)", src.gotLimit)
	}
	if !src.hadDeadline {
		t.Fatal("FetchRecent context must carry the timeout_seconds deadline")
	}
	// The single deadline must be ~timeout_seconds (10s) out — one budget for
	// the whole fetch, not per-pass.
	remaining := time.Until(src.deadline)
	if remaining < 8*time.Second || remaining > 11*time.Second {
		t.Errorf("deadline is %v out, want ~10s (timeout_seconds)", remaining)
	}
}

func TestFetchLogs_EmptySelectorNoteNoQueryNoCall(t *testing.T) {
	src := &fakeSource{name: "loki"}
	logger, buf := bufLogger()
	// No allowlisted labels shared → empty selector.
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alertsWith(map[string]string{"alertname": "X", "severity": "high"}), time.Now(), time.Now(), "inc-test", logger)
	if e == nil {
		t.Fatal("logs enabled: must return non-nil note enrichment, not nil")
	}
	if e.Note == "" || e.Query != "" || len(e.Lines) != 0 {
		t.Fatalf("want note enrichment with no query/lines, got %+v", e)
	}
	if src.calls != 0 {
		t.Errorf("empty selector must not hit the backend, calls=%d", src.calls)
	}
	if !strings.Contains(buf.String(), "empty selector") {
		t.Errorf("missing empty-selector info breadcrumb: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "incident=inc-test") {
		t.Errorf("empty-selector line must carry incident: %s", buf.String())
	}
}

func TestFetchLogs_SuccessEmitsLokiFetched(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{
		Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "boom"}},
		Query: `{namespace="prod"} |~ "(?i)error"`,
	}}
	logger, buf := bufLogger()
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "inc-42", logger)
	if e == nil || len(e.Lines) == 0 {
		t.Fatalf("want enrichment with lines, got %+v", e)
	}
	s := buf.String()
	if !strings.Contains(s, "loki fetched") {
		t.Errorf("missing loki fetched success line: %s", s)
	}
	for _, tok := range []string{"lines=1", "range=15m", "incident=inc-42"} {
		if !strings.Contains(s, tok) {
			t.Errorf("loki fetched missing %q: %s", tok, s)
		}
	}
}

func TestFetchLogs_QueriedEmptyNoteAndInfoLog(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: nil, Query: `{namespace="prod",app="api"}`}}
	logger, buf := bufLogger()
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "inc-test", logger)
	if e == nil || len(e.Lines) != 0 || e.Note == "" {
		t.Fatalf("want note enrichment, got %+v", e)
	}
	if e.Query != `{namespace="prod",app="api"}` {
		t.Errorf("note enrichment must carry the attempted query, got %q", e.Query)
	}
	if !strings.Contains(buf.String(), `{namespace=\"prod\",app=\"api\"}`) && !strings.Contains(buf.String(), `namespace="prod",app="api"`) {
		t.Errorf("info breadcrumb must name the query: %s", buf.String())
	}
}

func TestFetchLogs_ErrorNoteAndWarnLogTriageProceeds(t *testing.T) {
	src := &fakeSource{name: "loki", err: context.DeadlineExceeded, fetched: logs.Fetched{Query: `{namespace="prod"}`}}
	logger, buf := bufLogger()
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "inc-test", logger)
	if e == nil || e.Note == "" || len(e.Lines) != 0 {
		t.Fatalf("error path must yield note enrichment, got %+v", e)
	}
	if !strings.Contains(e.Note, "failed") {
		t.Errorf("note should explain failure: %q", e.Note)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("error path must warn-log: %s", buf.String())
	}
}

func TestFetchLogs_OutcomeTags(t *testing.T) {
	// no usable selector (alerts with no allowlisted labels).
	e := FetchLogs(context.Background(), &fakeSource{name: "loki"}, LogParams{DefaultRangeMinutes: 5, TimeoutSeconds: 5, MaxLines: 10},
		alertsWith(map[string]string{"alertname": "X"}), time.Now(), time.Now(), "i", nil)
	if e.Outcome != OutcomeNoSelector {
		t.Errorf("no-selector: got %q", e.Outcome)
	}

	// backend query failed.
	src := &fakeSource{name: "loki", err: context.DeadlineExceeded, fetched: logs.Fetched{Query: `{namespace="prod"}`}}
	e = FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 5, TimeoutSeconds: 5, MaxLines: 10},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "i", nil)
	if e.Outcome != OutcomeFailed {
		t.Errorf("failed: got %q", e.Outcome)
	}

	// queried but empty.
	src = &fakeSource{name: "loki", fetched: logs.Fetched{Lines: nil, Query: `{namespace="prod"}`}}
	e = FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 5, TimeoutSeconds: 5, MaxLines: 10},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "i", nil)
	if e.Outcome != OutcomeEmpty {
		t.Errorf("empty: got %q", e.Outcome)
	}

	// fetched.
	src = &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}, Query: `{namespace="prod"}`}}
	e = FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 5, TimeoutSeconds: 5, MaxLines: 10},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), "i", nil)
	if e.Outcome != OutcomeFetched {
		t.Errorf("fetched: got %q", e.Outcome)
	}
}

func TestFetchLogs_NormalizeCapsEnforced(t *testing.T) {
	// 60 lines, newest-first, 200 bytes each → byte cap (8192) keeps ~40.
	var in []logs.Line
	for i := 0; i < 60; i++ {
		in = append(in, logs.Line{Timestamp: time.Unix(int64(1000-i), 0), Line: strings.Repeat("z", 200)})
	}
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: in, Query: "{x}"}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 60},
		alertsWith(map[string]string{"namespace": "p"}), time.Now(), time.Now(), "inc-test", nil)
	if e == nil || len(e.Lines) == 0 {
		t.Fatal("want lines")
	}
	total := 0
	for _, ln := range e.Lines {
		total += len(ln.Line)
	}
	if total > logs.MaxBytes {
		t.Errorf("normalized total %d bytes exceeds cap %d", total, logs.MaxBytes)
	}
	if len(e.Lines) >= 60 {
		t.Errorf("expected byte cap to drop lines, kept %d/60", len(e.Lines))
	}
	// Newest-first preserved: first kept line is the newest input.
	if !e.Lines[0].Timestamp.Equal(in[0].Timestamp) {
		t.Error("newest line not first after normalize")
	}
}

// Issue #63: the window must be capped independently of incident age.
func TestFetchLogs_MaxWindowClampsOldSpanStart(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}}}
	last := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	first := last.Add(-48 * time.Hour) // incident open for two days
	p := LogParams{DefaultRangeMinutes: 15, MaxWindowMinutes: 120, TimeoutSeconds: 10, MaxLines: 50}
	e := FetchLogs(context.Background(), src, p, alertsWith(map[string]string{"namespace": "p"}), first, last, "inc-test", nil)

	if want := last.Add(-120 * time.Minute); !src.gotStart.Equal(want) {
		t.Errorf("start = %v, want last-120m (%v)", src.gotStart, want)
	}
	if !src.gotEnd.Equal(last) {
		t.Errorf("end = %v, want last", src.gotEnd)
	}
	if want := first.Add(-15 * time.Minute); !e.SpanStart.Equal(want) {
		t.Errorf("SpanStart = %v, want requested start %v", e.SpanStart, want)
	}
	var b strings.Builder
	renderLogs(&b, e)
	if !strings.Contains(b.String(), "last 2h0m0s only") || !strings.Contains(b.String(), "not fetched") {
		t.Errorf("prompt must say the window was clamped, got %q", b.String())
	}
}

func TestFetchLogs_MaxWindowNotAppliedCases(t *testing.T) {
	last := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		age       time.Duration
		maxWindow int
	}{
		{"recent span stays unclamped", 30 * time.Minute, 120},
		{"zero means unbounded", 48 * time.Hour, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}}}
			first := last.Add(-tc.age)
			p := LogParams{DefaultRangeMinutes: 15, MaxWindowMinutes: tc.maxWindow, TimeoutSeconds: 10, MaxLines: 50}
			e := FetchLogs(context.Background(), src, p, alertsWith(map[string]string{"namespace": "p"}), first, last, "inc-test", nil)

			if want := first.Add(-15 * time.Minute); !src.gotStart.Equal(want) {
				t.Errorf("start = %v, want first-15m (unclamped)", src.gotStart)
			}
			if !e.SpanStart.IsZero() {
				t.Errorf("SpanStart must be zero when no clamp applied, got %v", e.SpanStart)
			}
		})
	}
}

func TestRenderLogs_ClampDisclosedWhenEmpty(t *testing.T) {
	end := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	e := &LogEnrichment{
		Source:    "loki",
		Query:     `{namespace="p"}`,
		Start:     end.Add(-120 * time.Minute),
		End:       end,
		SpanStart: end.Add(-48 * time.Hour),
		Note:      "log backend returned no lines for this query",
		Outcome:   OutcomeEmpty,
	}
	var b strings.Builder
	renderLogs(&b, e)
	out := b.String()
	if !strings.Contains(out, "window clamped to the last 2h0m0s") || !strings.Contains(out, "not fetched") {
		t.Errorf("empty-result prompt must disclose the clamp, got %q", out)
	}
	if !strings.Contains(out, "missing evidence") {
		t.Errorf("empty-result prompt must keep the missing-evidence guidance, got %q", out)
	}
}

func TestFetchLogs_SelectsAttributesAcrossErrorAndComparisonLines(t *testing.T) {
	var entries []logs.Line
	raw := `[
 {"line":"Error one","attrs":{"service_name":"api","resource":"same","outcome":"failure","trace_id":"abcdef0123456789abcdef0123456789","span_id":"abcdef0123456789","transactionId":"123","multiline":"a\nb","long":"` + strings.Repeat("x", 65) + `","overflow":"1e999","decimal":"1.5"}},
 {"line":"Error two","attrs":{"service_name":"api","resource":"same","outcome":"failure","trace_id":"bbbbbb0123456789abcdef0123456789","span_id":"bbbbbb0123456789","transactionId":"456","multiline":"b\rc","long":"` + strings.Repeat("y", 65) + `","overflow":"2e999","decimal":"2.5"}},
 {"line":"Transaction complete.","attrs":{"service_name":"api","resource":"same","outcome":"success","loyalty_level":"gold","trace_id":"cccccc0123456789abcdef0123456789","span_id":"cccccc0123456789","transactionId":"01234567-89ab-cdef-0123-456789abcdef"}},
 {"line":"Transaction complete.","attrs":{"service_name":"api","resource":"same","outcome":"success","loyalty_level":"silver","trace_id":"dddddd0123456789abcdef0123456789","span_id":"dddddd0123456789","transactionId":"fedcba98-7654-3210-fedc-ba9876543210"}}
 ]`
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatal(err)
	}
	src := &fakeContrastSource{fakeSource: &fakeSource{name: "loki", fetched: logs.Fetched{Lines: entries[:2], Filtered: true}}, contrast: logs.Fetched{Lines: entries[2:]}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	var b strings.Builder
	renderLogs(&b, e)
	text := b.String()
	for _, want := range []string{"Error one {outcome=failure}", "Error two {outcome=failure}", "Transaction complete. {loyalty_level=gold, outcome=success}", "Transaction complete. {loyalty_level=silver, outcome=success}"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	for _, key := range []string{"service_name=", "resource=", "trace_id=", "span_id=", "transactionId=", "multiline=", "long=", "decimal=", "overflow="} {
		if strings.Contains(text, key) {
			t.Errorf("unhelpful attribute %q in %s", key, text)
		}
	}
	if got := contrastSummary(e.Lines, e.Contrast); len(got) != 0 {
		t.Fatalf("attributes must not enter message token comparison: %v", got)
	}
	if got := inconclusiveTokens(e.Lines, e.Contrast); len(got) != 0 {
		t.Fatalf("attributes must not enter missing-token comparison: %v", got)
	}
}

func TestFetchLogs_AttributeLimitPrefersFewerDistinctValuesThenKey(t *testing.T) {
	var entries []logs.Line
	if err := json.Unmarshal([]byte(`[
 {"line":"one","attrs":{"z":"red","a":"red","b":"red","c":"red","d":"red","e":"red","f":"red","g":"red","h":"red","i":"red"}},
 {"line":"two","attrs":{"z":"blue","a":"blue","b":"blue","c":"blue","d":"blue","e":"blue","f":"blue","g":"blue","h":"blue","i":"blue"}},
 {"line":"three","attrs":{"z":"blue","a":"green","b":"green","c":"green","d":"green","e":"green","f":"green","g":"green","h":"green","i":"green"}}
 ]`), &entries); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: entries}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	var b strings.Builder
	renderLogs(&b, e)
	if !strings.Contains(b.String(), "one {a=red, b=red, c=red, d=red, e=red, f=red, g=red, z=red}") || strings.Contains(b.String(), "h=") || strings.Contains(b.String(), "i=") {
		t.Fatal(b.String())
	}
}

func TestFetchLogs_ContrastLimitBeforeDedup(t *testing.T) {
	for _, duplicate := range []bool{true, false} {
		t.Run(fmt.Sprintf("duplicates_%v", duplicate), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				result := []map[string]any{{"stream": map[string]string{"service": "api"}, "values": [][2]string{{"200", "ERROR request failed"}}}}
				if strings.Contains(r.URL.Query().Get("query"), "!~") {
					limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					n := limit
					if duplicate {
						n = limit / 2
					}
					entries := make([][2]string, 0, n)
					for i := range n {
						entries = append(entries, [2]string{strconv.Itoa(100 + i), "Transaction complete."})
					}
					result = []map[string]any{{"stream": map[string]string{"service": "api", "copy": "first"}, "values": entries}}
					if duplicate {
						result = append(result, map[string]any{"stream": map[string]string{"service": "api", "copy": "second"}, "values": entries})
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result}}); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			src := loki.NewClient(loki.Config{BaseURL: srv.URL, LineFilter: `|~ "(?i)(error|warn|fatal|panic|fail)"`})
			e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
			if len(e.Contrast) != 10 {
				t.Fatalf("want 10 unique comparison lines, got %d", len(e.Contrast))
			}
			newest := int64(119)
			if duplicate {
				newest = 109
			}
			for i, line := range e.Contrast {
				if line.Timestamp.UnixNano() != newest-int64(i) {
					t.Fatalf("comparison order/uniqueness changed at %d: %+v", i, line)
				}
			}
		})
	}
}

func TestFetchLogs_AttributeLengthCountsCharacters(t *testing.T) {
	value := strings.Repeat("\u754c", 64)
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{
		{Line: "first", Attrs: map[string]string{"category": value}},
		{Line: "second", Attrs: map[string]string{"category": value + "\u754c"}},
	}}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	if len(e.Lines) != 2 || e.Lines[0].Attrs["category"] != value {
		t.Fatalf("64-character value omitted: %+v", e.Lines)
	}
	if len(e.Lines[1].Attrs) != 0 {
		t.Fatalf("65-character value retained: %+v", e.Lines[1])
	}
	var b strings.Builder
	renderLogs(&b, e)
	if !strings.Contains(b.String(), "first {category="+value+"}") {
		t.Fatal(b.String())
	}
}

func TestFetchLogs_MessageParameterAttributesSurvive(t *testing.T) {
	const message = "Request failed with {Status} after {Attempts} attempts: {ErrorDetail}"
	detail := "Backend connection failed: " + strings.Repeat("\u754c", 300) + "\nstack frame"
	entries := []logs.Line{
		{Line: message, Attrs: map[string]string{"Status": "Unavailable", "Attempts": "3", "ErrorDetail": detail, "resource": "same", "unrelated": detail}},
		{Line: message, Attrs: map[string]string{"Status": "Unavailable", "Attempts": "3", "ErrorDetail": detail, "resource": "same", "unrelated": detail}},
	}
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: entries}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	if len(e.Lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(e.Lines))
	}
	for _, line := range e.Lines {
		if line.Line != message {
			t.Fatalf("raw message changed: %q", line.Line)
		}
		if line.Attrs["Status"] != "Unavailable" || line.Attrs["Attempts"] != "3" {
			t.Errorf("constant/numeric message parameters lost: %+v", line.Attrs)
		}
		got := line.Attrs["ErrorDetail"]
		if !strings.HasPrefix(got, "Backend connection failed: ") || len([]rune(got)) != 256 || !strings.HasSuffix(got, "…") || strings.ContainsAny(got, "\r\n") {
			t.Errorf("bounded message detail lost or malformed: %q", got)
		}
		if len(line.Attrs) != 3 {
			t.Errorf("unreferenced attributes retained: %+v", line.Attrs)
		}
	}
	var b strings.Builder
	renderLogs(&b, e)
	if !strings.Contains(b.String(), "ErrorDetail=Backend connection failed: ") || !strings.Contains(b.String(), "Attempts=3") {
		t.Fatalf("message parameters missing from model evidence: %s", b.String())
	}
	if len(contrastSummary(e.Lines, e.Lines)) != 0 || len(inconclusiveTokens(e.Lines, e.Lines)) != 0 {
		t.Fatal("message parameters entered token comparison")
	}
}

func TestFetchLogs_MessageParametersPrioritizedAcrossBothSamples(t *testing.T) {
	attrs := map[string]string{"Reason": strings.Repeat("timeout ", 100)}
	for _, key := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		attrs[key] = "failure"
	}
	src := &fakeContrastSource{
		fakeSource: &fakeSource{name: "loki", fetched: logs.Fetched{Filtered: true, Lines: []logs.Line{{Line: "Failed: {Reason}", Attrs: attrs}}}},
		contrast:   logs.Fetched{Lines: []logs.Line{{Line: "Completed {Count}", Attrs: map[string]string{"Count": "42"}}}},
	}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	if len(e.Lines[0].Attrs) != 8 || !strings.HasPrefix(e.Lines[0].Attrs["Reason"], "timeout ") {
		t.Fatalf("message detail displaced by ordinary attributes: %+v", e.Lines[0].Attrs)
	}
	if len(e.Contrast) != 1 || e.Contrast[0].Attrs["Count"] != "42" {
		t.Fatalf("comparison message parameter lost: %+v", e.Contrast)
	}
	var b strings.Builder
	renderLogs(&b, e)
	if !strings.Contains(b.String(), "Reason=timeout ") || !strings.Contains(b.String(), "Completed {Count} {Count=42}") {
		t.Fatalf("parameter evidence missing from prompt: %s", b.String())
	}
}
