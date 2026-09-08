// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestHandleUsageStats_AggregatesAcrossStoreAndAudit(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := st.UpsertAlertByFingerprint(ctx, store.Alert{
		ID: "a1", Fingerprint: "fp1", Status: "firing",
		Labels: map[string]string{}, Annotations: map[string]string{},
		StartsAt: now, ReceivedAt: now,
	}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	a := audit.New(st.DB())
	if err := a.Append(ctx, "llm.anthropic", "llm.response", map[string]any{
		"model": "claude-x", "input_tokens": int64(10), "output_tokens": int64(5),
	}); err != nil {
		t.Fatalf("seed llm.response: %v", err)
	}
	if err := a.Append(ctx, "notify.slack", "notify.sent", nil); err != nil {
		t.Fatalf("seed notify.sent: %v", err)
	}
	if err := a.Append(ctx, "skill:acute-triage", "incident.analyzed", nil); err != nil {
		t.Fatalf("seed incident.analyzed: %v", err)
	}

	s := NewServer(Config{}, st, a)
	res, err := s.handleUsageStats(ctx, reqWith(nil))
	if err != nil || res.IsError {
		t.Fatalf("usage stats errored: %v %s", err, resultText(t, res))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}

	if payload["alerts_received"] != float64(1) {
		t.Errorf("alerts_received = %v, want 1", payload["alerts_received"])
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
	if !ok || slack["sent"] != float64(1) {
		t.Errorf("slack block wrong: %v", payload["slack"])
	}
	incidents, ok := payload["incidents"].(map[string]any)
	if !ok || incidents["processed"] != float64(1) {
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
