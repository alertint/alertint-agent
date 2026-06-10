package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/notify/stdout"
)

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
	n := stdout.New(&buf, nil)

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
	n := stdout.New(&buf, nil)

	f := sampleFinding()
	f.IncidentID = "unique-test-id-999"
	_ = n.Notify(context.Background(), f)

	if !strings.Contains(buf.String(), "unique-test-id-999") {
		t.Errorf("output does not contain incident_id\noutput: %s", buf.String())
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

	n := slack.NewWithClient(client, "#alerts", store, nil)
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

	n := slack.NewWithClient(client, "#alerts", store, nil)
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

	n := slack.NewWithClient(client, "#alerts", store, nil)
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

// TestSlackClientErrorPropagates verifies that a client error is returned.
func TestSlackClientErrorPropagates(t *testing.T) {
	client := &mockSlackClient{postErr: errors.New("slack API error")}
	store := &mockThreadStore{err: errors.New("not found")}

	n := slack.NewWithClient(client, "#alerts", store, nil)
	err := n.Notify(context.Background(), sampleFinding())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --------------------------------------------------------------------------
// Multi notifier tests
// --------------------------------------------------------------------------

func TestMultiCallsBoth(t *testing.T) {
	client := &mockSlackClient{returnTS: "ts", returnCh: "C1"}
	store := &mockThreadStore{err: errors.New("not found")}

	var buf bytes.Buffer
	sn := stdout.New(&buf, nil)
	sk := slack.NewWithClient(client, "#alerts", store, nil)
	m := notify.NewMulti(sn, sk)

	if err := m.Notify(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Multi.Notify: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("stdout notifier was not called")
	}
	if client.postCalls == 0 {
		t.Error("slack notifier was not called")
	}
}
