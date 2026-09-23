// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcplib "github.com/mark3labs/mcp-go/mcp"
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

func TestUsageStatsAuthenticatedDiscoveryAndInvocationAcrossLegacyAndSituationHistory(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	a := audit.New(st.DB())
	for _, row := range []struct {
		actor, kind string
		payload     map[string]any
	}{
		{"notify.slack", "notify.sent", map[string]any{"event": "firing"}},
		{"situation.notification_worker", "situation.notification.delivered", map[string]any{"effect_class": "root_sync", "new_root": true}},
		{"skill:acute-triage", "incident.analyzed", nil},
		{"situation.triage_worker", "incident.analyzed", nil},
	} {
		if err := a.Append(ctx, row.actor, row.kind, row.payload); err != nil {
			t.Fatalf("seed %s/%s: %v", row.actor, row.kind, err)
		}
	}

	const token = "usage-test-token"
	s := NewServer(Config{Token: token}, st, a)
	httpServer := httptest.NewServer(s.Handler())
	t.Cleanup(httpServer.Close)

	c, err := mcpclient.NewStreamableHttpClient(httpServer.URL+"/mcp",
		transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + token}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{
		ProtocolVersion: mcplib.LATEST_PROTOCOL_VERSION,
		ClientInfo:      mcplib.Implementation{Name: "usage-test", Version: "1"},
	}}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	tools, err := c.ListTools(ctx, mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	found := false
	for _, tool := range tools.Tools {
		found = found || tool.Name == "alertint_usage_stats"
	}
	if !found {
		t.Fatal("authenticated tools/list omitted alertint_usage_stats")
	}
	result, err := c.CallTool(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "alertint_usage_stats", Arguments: map[string]any{},
	}})
	if err != nil || result.IsError {
		t.Fatalf("call usage stats: err=%v result=%s", err, resultText(t, result))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, result)), &payload); err != nil {
		t.Fatalf("decode usage stats: %v", err)
	}
	slack, ok := payload["slack"].(map[string]any)
	if !ok {
		t.Fatalf("slack = %T, want object", payload["slack"])
	}
	if got := slack["cards_posted"]; got != float64(2) {
		t.Fatalf("cards_posted = %v, want legacy + Situation = 2", got)
	}
	incidents, ok := payload["incidents"].(map[string]any)
	if !ok {
		t.Fatalf("incidents = %T, want object", payload["incidents"])
	}
	if got := incidents["analyzed"]; got != float64(2) {
		t.Fatalf("analyzed = %v, want legacy + Situation actors = 2", got)
	}
}
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
