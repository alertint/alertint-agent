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
	if got := FetchLogs(context.Background(), nil, LogParams{}, alertsWith(map[string]string{"namespace": "p"}), time.Now(), time.Now(), nil); got != nil {
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
	FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50}, alertsWith(labels), time.Now(), time.Now(), logger)

	for _, k := range logs.AllowedSelectorKeys {
		if src.gotSel.Labels[k] != labels[k] {
			t.Errorf("selector missing allowlisted key %q", k)
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

func TestFetchLogs_WindowAndLimitAndDeadline(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{{Timestamp: time.Unix(1, 0), Line: "x"}}}}
	first := time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC)
	last := time.Date(2026, 6, 17, 14, 5, 0, 0, time.UTC)
	FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 42}, alertsWith(map[string]string{"namespace": "p"}), first, last, nil)

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
		alertsWith(map[string]string{"alertname": "X", "severity": "high"}), time.Now(), time.Now(), logger)
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
}

func TestFetchLogs_QueriedEmptyNoteAndInfoLog(t *testing.T) {
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: nil, Query: `{namespace="prod",app="api"}`}}
	logger, buf := bufLogger()
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 10, MaxLines: 50},
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), logger)
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
		alertsWith(map[string]string{"namespace": "prod"}), time.Now(), time.Now(), logger)
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
		alertsWith(map[string]string{"namespace": "p"}), time.Now(), time.Now(), nil)
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
