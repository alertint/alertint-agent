// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

func TestHandleUsageStatsAggregatesCurrentAuditVocabulary(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	a := audit.New(st.DB())
	seed := func(actor, kind string, payload map[string]any) {
		t.Helper()
		if err := a.Append(ctx, actor, kind, payload); err != nil {
			t.Fatalf("seed %s/%s: %v", actor, kind, err)
		}
	}
	seed("alertmanager", "alert.received", map[string]any{"alert_count": 2})
	seed("llm.anthropic", "llm.response", map[string]any{"model": "claude-x", "input_tokens": 10, "output_tokens": 5})
	seed("situation.notification_worker", "situation.notification.delivered", map[string]any{"effect_class": "root_sync", "new_root": true})
	seed("situation.controller", "situation.notification.withheld", map[string]any{"main_channel_poke": true})
	seed("skill:acute-triage", "incident.analyzed", nil)
	seed("situation.triage_worker", "incident.triage_exhausted", nil)

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
	if !ok {
		t.Fatalf("alerts = %T, want object", payload["alerts"])
	}
	if alerts["deliveries"] != float64(1) || alerts["received"] != float64(2) {
		t.Errorf("alerts = %v", alerts)
	}
	slack, ok := payload["slack"].(map[string]any)
	if !ok {
		t.Fatalf("slack = %T, want object", payload["slack"])
	}
	if slack["cards_posted"] != float64(1) || slack["skipped"] != float64(1) {
		t.Errorf("slack = %v", slack)
	}
	incidents, ok := payload["incidents"].(map[string]any)
	if !ok {
		t.Fatalf("incidents = %T, want object", payload["incidents"])
	}
	if incidents["analyzed"] != float64(1) || incidents["triage_exhausted"] != float64(1) {
		t.Errorf("incidents = %v", incidents)
	}
}

func TestHandleUsageStatsRejectsInvalidWindow(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	now := time.Now().UTC()
	res, err := s.handleUsageStats(context.Background(), reqWith(map[string]any{
		"since": now.Format(time.RFC3339), "until": now.Add(-time.Hour).Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool error, got %s", resultText(t, res))
	}
}
