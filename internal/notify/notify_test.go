// SPDX-License-Identifier: FSL-1.1-ALv2

package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/notify/stdout"
	"github.com/alertint/alertint-agent/internal/store"
)

// occCapableSink is a Notifier that also implements notify.OccurrenceSink.
type occCapableSink struct {
	fakeNotifier

	occ int
}

func (s *occCapableSink) OnOccurrenceAttached(context.Context, notify.RecurrenceEvent) error {
	s.occ++
	return nil
}

func TestMulti_OnOccurrenceAttachedFansOutOnlyToCapableSinks(t *testing.T) {
	occ := &occCapableSink{fakeNotifier: fakeNotifier{name: "occ"}}
	plain := &fakeNotifier{name: "plain"} // no OnOccurrenceAttached
	m := notify.NewMulti(slog.Default(), occ, plain)

	if err := m.OnOccurrenceAttached(context.Background(),
		notify.RecurrenceEvent{Incident: store.Incident{ID: "i1"}, Stats: store.OccurrenceStats{Count: 1}}); err != nil {
		t.Fatalf("OnOccurrenceAttached: %v", err)
	}
	if occ.occ != 1 {
		t.Errorf("occurrence-capable sink called %d times, want 1", occ.occ)
	}
	// A plain sink is skipped without panicking — reaching here proves it.
}

func sampleFinding() notify.Finding {
	return notify.Finding{
		IncidentID:          "inc-001",
		GroupKey:            "alertname=DiskFull,host=web1",
		AnalysisName:        "DiskFull on web1",
		OverallIssue:        "Disk utilisation at 95%",
		CorrelationFindings: []string{"same host", "same alertname"},
		Severity:            "high",
		Confidence:          0.85,
		AlertCount:          3,
		FirstAlertAt:        time.Now().Add(-10 * time.Minute),
		AnalyzedAt:          time.Now(),
	}
}

// --------------------------------------------------------------------------
// stdout notifier tests
// --------------------------------------------------------------------------

func TestStdoutWritesJSON(t *testing.T) {
	var buf bytes.Buffer
	n := stdout.New(&buf, nil, true)

	if err := n.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Error("output should end with newline")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &obj); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, line)
	}
	if obj["kind"] != "finding" {
		t.Errorf("kind = %v, want finding", obj["kind"])
	}
}

func TestStdoutContainsIncidentID(t *testing.T) {
	var buf bytes.Buffer
	n := stdout.New(&buf, nil, true)

	f := sampleFinding()
	f.IncidentID = "unique-test-id-999"
	_ = n.Notify(context.Background(), f)

	if !strings.Contains(buf.String(), "unique-test-id-999") {
		t.Errorf("output does not contain incident_id\noutput: %s", buf.String())
	}
}

// TestStdoutNonVerboseWritesNothing verifies the stdout sink is silent (but
// succeeds) when not verbose — the full JSON is reserved for debug level.
func TestStdoutNonVerboseWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	n := stdout.New(&buf, nil, false)
	if err := n.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("non-verbose stdout should write nothing, got: %q", buf.String())
	}
}

// --------------------------------------------------------------------------
// Slack notifier tests — use a mock SlackClient so no real HTTP is made.
// --------------------------------------------------------------------------

type mockSlackClient struct {
	postCalls   int
	updateCalls int
	returnTS    string
	returnCh    string
	postErr     error
	updateErr   error
}

func (m *mockSlackClient) PostMessageContext(_ context.Context, _ string, _ ...slacklib.MsgOption) (string, string, error) {
	m.postCalls++
	return m.returnCh, m.returnTS, m.postErr
}

func (m *mockSlackClient) UpdateMessageContext(_ context.Context, _, _ string, _ ...slacklib.MsgOption) (string, string, string, error) {
	m.updateCalls++
	return m.returnCh, m.returnTS, "", m.updateErr
}

type mockThreadStore struct {
	ts  string
	ch  string
	err error
}

func (m *mockThreadStore) GetIncidentSlackThread(_ context.Context, _ string) (string, string, error) {
	return m.ts, m.ch, m.err
}

func (m *mockThreadStore) SetIncidentSlackThread(_ context.Context, _, ts, ch string) error {
	m.ts = ts
	m.ch = ch
	return nil
}

// TestSlackFiringPostsMessage verifies a firing notification posts two messages:
// one to the main channel (brief summary) and one thread reply (full analysis).
func TestSlackFiringPostsMessage(t *testing.T) {
	client := &mockSlackClient{returnTS: "1234567890.000001", returnCh: "C123"}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	if err := n.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	// call 1: main channel message; call 2: immediate thread reply with analysis detail.
	if client.postCalls != 2 {
		t.Errorf("PostMessageContext calls = %d, want 2 (main + thread detail)", client.postCalls)
	}
	if client.updateCalls != 0 {
		t.Errorf("UpdateMessageContext calls = %d, want 0", client.updateCalls)
	}
	if store.ts != "1234567890.000001" {
		t.Errorf("stored ts = %q, want 1234567890.000001", store.ts)
	}
}

// TestSlackResolvedWithThread updates the original message and posts a thread reply.
func TestSlackResolvedWithThread(t *testing.T) {
	client := &mockSlackClient{returnTS: "1234567890.000002", returnCh: "C123"}
	store := &mockThreadStore{ts: "1234567890.000001", ch: "C123"}

	n := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	f := sampleFinding()
	f.Status = "resolved"
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if client.updateCalls != 1 {
		t.Errorf("UpdateMessageContext calls = %d, want 1", client.updateCalls)
	}
	if client.postCalls != 1 {
		t.Errorf("PostMessageContext calls = %d, want 1 (thread reply)", client.postCalls)
	}
}

// TestSlackResolvedNoThreadFallback posts a fresh message when no thread is stored.
func TestSlackResolvedNoThreadFallback(t *testing.T) {
	client := &mockSlackClient{returnTS: "1234567890.000003", returnCh: "C123"}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	f := sampleFinding()
	f.Status = "resolved"
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if client.postCalls != 1 {
		t.Errorf("PostMessageContext calls = %d, want 1 (fallback post)", client.postCalls)
	}
	if client.updateCalls != 0 {
		t.Errorf("UpdateMessageContext calls = %d, want 0", client.updateCalls)
	}
}

// TestSlackFiringSuppressedBelowMinSeverity verifies the severity gate: a
// low-severity finding never reaches Slack when min_severity is high.
func TestSlackFiringSuppressedBelowMinSeverity(t *testing.T) {
	client := &mockSlackClient{returnTS: "ts", returnCh: "C1"}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", "high", "change-gated", store, nil)
	f := sampleFinding()
	f.Severity = "low"
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if client.postCalls != 0 {
		t.Errorf("PostMessageContext calls = %d, want 0 (suppressed)", client.postCalls)
	}
}

// TestSlackResolvedNoThreadSuppressedBelowMinSeverity verifies the resolved
// fallback path is gated too: when the firing post was suppressed (no thread
// recorded), the resolution must not leak a fresh card into the channel.
func TestSlackResolvedNoThreadSuppressedBelowMinSeverity(t *testing.T) {
	client := &mockSlackClient{returnTS: "ts", returnCh: "C1"}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", "high", "change-gated", store, nil)
	f := sampleFinding()
	f.Severity = "low"
	f.Status = "resolved"
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if client.postCalls != 0 || client.updateCalls != 0 {
		t.Errorf("post/update calls = %d/%d, want 0/0 (suppressed)", client.postCalls, client.updateCalls)
	}
}

// TestSlackResolvedWithThreadNotGated verifies an already-posted incident is
// always resolved in place, regardless of the severity gate.
func TestSlackResolvedWithThreadNotGated(t *testing.T) {
	client := &mockSlackClient{returnTS: "ts", returnCh: "C1"}
	store := &mockThreadStore{ts: "1234567890.000001", ch: "C1"}

	n := slack.NewWithClient(client, "#alerts", "high", "change-gated", store, nil)
	f := sampleFinding()
	f.Severity = "low"
	f.Status = "resolved"
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if client.updateCalls != 1 {
		t.Errorf("UpdateMessageContext calls = %d, want 1 (in-place resolve is never gated)", client.updateCalls)
	}
}

// TestSlackClientErrorPropagates verifies that a client error is returned.
func TestSlackClientErrorPropagates(t *testing.T) {
	client := &mockSlackClient{postErr: errors.New("slack API error")}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	err := n.Notify(context.Background(), sampleFinding())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --------------------------------------------------------------------------
// Multi notifier tests
// --------------------------------------------------------------------------

// fakeNotifier is a controllable Notifier for testing Multi's outcome lines.
type fakeNotifier struct {
	name string
	err  error
}

func (f *fakeNotifier) Name() string                                 { return f.name }
func (f *fakeNotifier) Notify(context.Context, notify.Finding) error { return f.err }

// testLogger returns a logger writing text records to buf so tests can assert
// on the rendered notify outcome lines.
func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestMultiCallsBoth(t *testing.T) {
	client := &mockSlackClient{returnTS: "ts", returnCh: "C1"}
	store := &mockThreadStore{err: errors.New("not found")}

	var out bytes.Buffer
	sn := stdout.New(&out, nil, true)
	sk := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	var logBuf bytes.Buffer
	m := notify.NewMulti(testLogger(&logBuf), sn, sk)

	if err := m.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Multi.Notify: %v", err)
	}
	if out.Len() == 0 {
		t.Error("stdout notifier was not called")
	}
	if client.postCalls == 0 {
		t.Error("slack notifier was not called")
	}
}

// TestMultiLogsFindingSummary verifies Multi emits one human-readable "finding"
// summary line per analysis (the live-watch view of the result), even when no
// delivery sinks are wired.
func TestMultiLogsFindingSummary(t *testing.T) {
	var logBuf bytes.Buffer
	m := notify.NewMulti(testLogger(&logBuf)) // no sinks: console/info live view
	if err := m.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Multi.Notify: %v", err)
	}
	s := logBuf.String()
	if !strings.Contains(s, "msg=finding") {
		t.Fatalf("missing finding summary line: %s", s)
	}
	for _, tok := range []string{"severity=high", "confidence=85%", "alerts=3", "incident=inc-001"} {
		if !strings.Contains(s, tok) {
			t.Errorf("finding summary missing %q: %s", tok, s)
		}
	}
	// With no sinks there is nothing to deliver, so no per-sink outcome line.
	if strings.Contains(s, "notified") || strings.Contains(s, "notify ") {
		t.Errorf("no sinks should yield no notify outcome line: %s", s)
	}
}

// TestMultiAllOKLogsOneNotified verifies a fully-successful fan-out logs a
// single "notified" summary with one ok token per sink and no detail lines.
func TestMultiAllOKLogsOneNotified(t *testing.T) {
	var logBuf bytes.Buffer
	m := notify.NewMulti(testLogger(&logBuf),
		&fakeNotifier{name: "stdout"},
		&fakeNotifier{name: "card"},
		&fakeNotifier{name: "slack"},
	)
	if err := m.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Multi.Notify: %v", err)
	}
	s := logBuf.String()
	if !strings.Contains(s, "msg=notified") {
		t.Errorf("missing notified summary: %s", s)
	}
	for _, tok := range []string{"stdout=ok", "card=ok", "slack=ok", "incident=inc-001"} {
		if !strings.Contains(s, tok) {
			t.Errorf("summary missing %q: %s", tok, s)
		}
	}
	if strings.Contains(s, "notify sink failed") {
		t.Errorf("success path must not emit a sink-failed detail line: %s", s)
	}
}

// TestMultiPartialLogsSummaryAndDetail verifies one failing sink yields a
// "notify partial" WARN summary plus a "notify sink failed" detail line naming
// the sink and carrying its full wrapped error, and the aggregated error is
// still returned.
func TestMultiPartialLogsSummaryAndDetail(t *testing.T) {
	var logBuf bytes.Buffer
	wrapped := errors.New("channel #alerts: post message: invalid_auth")
	m := notify.NewMulti(testLogger(&logBuf),
		&fakeNotifier{name: "stdout"},
		&fakeNotifier{name: "card"},
		&fakeNotifier{name: "slack", err: wrapped},
	)
	err := m.Notify(context.Background(), sampleFinding())
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid_auth") {
		t.Errorf("aggregated error should be the failing sink's: %v", err)
	}
	s := logBuf.String()
	if !strings.Contains(s, `msg="notify partial"`) {
		t.Errorf("missing notify partial summary: %s", s)
	}
	if !strings.Contains(s, "slack=FAIL") || !strings.Contains(s, "stdout=ok") || !strings.Contains(s, "card=ok") {
		t.Errorf("partial summary tokens wrong: %s", s)
	}
	if !strings.Contains(s, `msg="notify sink failed"`) || !strings.Contains(s, "sink=slack") {
		t.Errorf("missing per-sink detail line: %s", s)
	}
	if !strings.Contains(s, "channel #alerts: post message: invalid_auth") {
		t.Errorf("detail line must carry the full wrapped error: %s", s)
	}
}

// TestMultiAllFailLogsError verifies that when every sink fails the summary is
// an ERROR "notify failed" and the aggregated error is still returned.
func TestMultiAllFailLogsError(t *testing.T) {
	var logBuf bytes.Buffer
	m := notify.NewMulti(testLogger(&logBuf),
		&fakeNotifier{name: "stdout", err: errors.New("stdout: write: broken pipe")},
		&fakeNotifier{name: "slack", err: errors.New("channel #alerts: post message: invalid_auth")},
	)
	if err := m.Notify(context.Background(), sampleFinding()); err == nil {
		t.Fatal("expected aggregated error, got nil")
	}
	s := logBuf.String()
	if !strings.Contains(s, "level=ERROR") || !strings.Contains(s, `msg="notify failed"`) {
		t.Errorf("all-fail must log ERROR notify failed: %s", s)
	}
	// One detail line per failing sink.
	if strings.Count(s, "notify sink failed") != 2 {
		t.Errorf("want 2 per-sink detail lines, got: %s", s)
	}
}

// TestMultiResolvedStatusFlows verifies a resolved Finding carries status=resolved
// into the outcome line (the path the resolution notifier relies on).
func TestMultiResolvedStatusFlows(t *testing.T) {
	var logBuf bytes.Buffer
	m := notify.NewMulti(testLogger(&logBuf), &fakeNotifier{name: "stdout"})
	f := sampleFinding()
	f.Status = "resolved"
	if err := m.Notify(context.Background(), f); err != nil {
		t.Fatalf("Multi.Notify: %v", err)
	}
	if !strings.Contains(logBuf.String(), "status=resolved") {
		t.Errorf("resolved finding should log status=resolved: %s", logBuf.String())
	}
}

// TestSlackFiringEditsInPlaceWhenThreadExists verifies a re-judgment (thread
// already recorded) edits the existing card in place and threads the analysis —
// it never posts a new card and never overwrites slack_ts (ADR-0019).
func TestSlackFiringEditsInPlaceWhenThreadExists(t *testing.T) {
	client := &mockSlackClient{returnTS: "should-not-be-stored", returnCh: "C1"}
	store := &mockThreadStore{ts: "orig-ts", ch: "C1"}

	n := slack.NewWithClient(client, "#alerts", "low", "change-gated", store, nil)
	if err := n.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if client.updateCalls != 1 {
		t.Errorf("UpdateMessageContext calls = %d, want 1 (edit in place)", client.updateCalls)
	}
	if client.postCalls != 1 {
		t.Errorf("PostMessageContext calls = %d, want 1 (thread reply only)", client.postCalls)
	}
	if store.ts != "orig-ts" {
		t.Errorf("slack_ts = %q, want orig-ts (never overwritten on a re-judgment)", store.ts)
	}
}

// TestSlackFiringEditNotReGatedByMinSeverity verifies an update to an
// already-visible incident is not re-suppressed by min_severity.
func TestSlackFiringEditNotReGatedByMinSeverity(t *testing.T) {
	client := &mockSlackClient{returnTS: "x", returnCh: "C1"}
	store := &mockThreadStore{ts: "orig-ts", ch: "C1"}

	n := slack.NewWithClient(client, "#alerts", "high", "change-gated", store, nil)
	f := sampleFinding()
	f.Severity = "low" // below the gate, but the incident already has a card
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if client.updateCalls != 1 {
		t.Errorf("UpdateMessageContext calls = %d, want 1 (in-place edit is never re-gated)", client.updateCalls)
	}
}

// TestFindingJSONDrillKey: the stdout JSON contract carries drill only when
// set (omitempty), so existing consumers see no noise on real findings.
func TestFindingJSONDrillKey(t *testing.T) {
	drill, err := json.Marshal(notify.Finding{IncidentID: "i1", Drill: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(drill), `"drill":true`) {
		t.Errorf("drill finding JSON missing drill key: %s", drill)
	}
	plain, err := json.Marshal(notify.Finding{IncidentID: "i2"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "drill") {
		t.Errorf("real finding JSON must omit drill: %s", plain)
	}
}
