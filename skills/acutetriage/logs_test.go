// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
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
