// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

func TestHandleUsageStats_AggregatesFromAudit(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()

	a := audit.New(st.DB())
	seed := func(actor, kind string, payload map[string]any) {
		t.Helper()
		if err := a.Append(ctx, actor, kind, payload); err != nil {
			t.Fatalf("seed %s/%s: %v", actor, kind, err)
		}
	}
	seed("alertmanager", "alert.received", map[string]any{"alert_count": 2, "persisted_count": 2})
	seed("llm.anthropic", "llm.response", map[string]any{
		"model": "claude-x", "input_tokens": int64(10), "output_tokens": int64(5),
	})
	seed("notify.slack", "notify.sent", map[string]any{"incident_id": "inc-1", "event": "firing", "recipient": "slack"})
	seed("notify.slack", "notify.sent", map[string]any{"incident_id": "inc-1", "event": "rejudge", "recipient": "slack"})
	seed("skill:acute-triage", "incident.analyzed", nil)
	seed("correlator", "incident.triage_exhausted", nil)

	s := NewServer(Config{}, st, a)
	res, err := s.handleUsageStats(ctx, reqWith(nil))
	if err != nil || res.IsError {
		t.Fatalf("usage stats errored: %v %s", err, resultText(t, res))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}

	alerts, ok := payload["alerts"].(map[string]any)
	if !ok || alerts["deliveries"] != float64(1) || alerts["received"] != float64(2) {
		t.Errorf("alerts block wrong: %v", payload["alerts"])
	}
	llm, ok := payload["llm"].(map[string]any)
	if !ok || llm["calls"] != float64(1) || llm["input_tokens"] != float64(10) {
		t.Errorf("llm block wrong: %v", payload["llm"])
	}
	byModel, ok := llm["by_model"].([]any)
	if !ok || len(byModel) != 1 {
		t.Errorf("llm.by_model wrong: %v", llm["by_model"])
	}
	slack, ok := payload["slack"].(map[string]any)
	if !ok || slack["cards_posted"] != float64(1) || slack["skipped"] != float64(0) {
		t.Errorf("slack block wrong: %v", payload["slack"])
	}
	incidents, ok := payload["incidents"].(map[string]any)
	if !ok || incidents["analyzed"] != float64(1) || incidents["triage_exhausted"] != float64(1) {
		t.Errorf("incidents block wrong: %v", payload["incidents"])
	}
	if _, ok := payload["window"].(map[string]any); !ok {
		t.Errorf("window block missing: %v", payload)
	}
}

func TestHandleUsageStats_InvalidSince_ReturnsError(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleUsageStats(context.Background(), reqWith(map[string]any{"since": "not-a-date"}))
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool error for invalid since, got: %s", resultText(t, res))
	}
}

func TestHandleUsageStats_SinceAfterUntil_ReturnsError(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	now := time.Now().UTC()
	res, err := s.handleUsageStats(context.Background(), reqWith(map[string]any{
		"since": now.Format(time.RFC3339),
		"until": now.Add(-time.Hour).Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool error for since after until, got: %s", resultText(t, res))
	}
}
