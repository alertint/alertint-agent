// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/mark3labs/mcp-go/mcp"
)

func protocolResult(t *testing.T, s *Server, method string) any {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if method == "initialize" {
		req["params"] = map[string]any{
			"protocolVersion": mcp.LATEST_PROTOCOL_VERSION,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "metadata-test", "version": "1"},
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response := s.protocol.HandleMessage(context.Background(), body)
	rpc, ok := response.(mcp.JSONRPCResponse)
	if !ok {
		t.Fatalf("%s response = %T, want JSONRPCResponse: %#v", method, response, response)
	}
	return rpc.Result
}

func TestInitializeIncludesSituationInvestigationInstructions(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	result, ok := protocolResult(t, s, "initialize").(mcp.InitializeResult)
	if !ok {
		t.Fatalf("initialize result has unexpected type")
	}
	for _, want := range []string{
		"alertint_get_situation",
		"recorded history",
		"Finding / Evidence / Now / Next",
		"explicit operator authorization",
	} {
		if !strings.Contains(result.Instructions, want) {
			t.Errorf("initialize instructions omit %q: %q", want, result.Instructions)
		}
	}
}

func listedTools(t *testing.T, s *Server) map[string]mcp.Tool {
	t.Helper()
	result, ok := protocolResult(t, s, "tools/list").(mcp.ListToolsResult)
	if !ok {
		t.Fatalf("tools/list result has unexpected type")
	}
	out := make(map[string]mcp.Tool, len(result.Tools))
	for _, tool := range result.Tools {
		out[tool.Name] = tool
	}
	return out
}

func TestToolMetadataCoversBaseAndOptionalSurfaces(t *testing.T) {
	st := newMCPStore(t)
	base := NewServer(Config{}, st, audit.New(st.DB()))
	baseTools := listedTools(t, base)
	for _, absent := range []string{"loki_query_range", "alertint_recent_changes", "sentry_issues_list", "zabbix_metric_history"} {
		if _, ok := baseTools[absent]; ok {
			t.Errorf("base tool list unexpectedly contains optional %q", absent)
		}
	}

	cfg := sentryMCPConfig(&fakeSentryReader{}, true)
	cfg.Logs = &spySource{}
	cfg.ChangesEnabled = true
	cfg.Zabbix = &fakeZabbixMCP{}
	allTools := listedTools(t, NewServer(cfg, st, audit.New(st.DB())))
	for _, present := range []string{"loki_query_range", "alertint_recent_changes", "sentry_issues_list", "sentry_issues_trace", "zabbix_metric_history", "zabbix_host_problems"} {
		if _, ok := allTools[present]; !ok {
			t.Errorf("configured tool list omits %q", present)
		}
	}
	for name, tool := range allTools {
		if strings.TrimSpace(tool.Description) == "" {
			t.Errorf("tool %q has no description", name)
		}
		a := tool.Annotations
		if a.ReadOnlyHint == nil || a.DestructiveHint == nil || a.IdempotentHint == nil || a.OpenWorldHint == nil {
			t.Errorf("tool %q has incomplete annotations: %+v", name, a)
		}
		if a.ReadOnlyHint != nil && !*a.ReadOnlyHint {
			description := strings.ToLower(tool.Description)
			if !strings.Contains(description, "explicit") ||
				(!strings.Contains(description, "operator") && !strings.Contains(description, "human")) {
				t.Errorf("write tool %q does not require explicit operator authorization in its description: %q", name, tool.Description)
			}
		}
	}

	assertHints := func(name string, readOnly, destructive, idempotent, openWorld bool) {
		t.Helper()
		tool, ok := allTools[name]
		if !ok {
			t.Fatalf("tool %q missing", name)
		}
		a := tool.Annotations
		if *a.ReadOnlyHint != readOnly || *a.DestructiveHint != destructive || *a.IdempotentHint != idempotent || *a.OpenWorldHint != openWorld {
			t.Errorf("tool %q annotations = %+v", name, a)
		}
	}
	assertHints("alertint_get_situation", true, false, true, false)
	assertHints("prometheus_query", true, false, true, true)
	assertHints("loki_query_range", true, false, true, true)
	assertHints("alertint_record_situation_expected", false, false, true, false)
	assertHints("alertint_revoke_situation_expected", false, true, true, false)
	assertHints("alertint_incident_capture_verdict", false, true, false, true)
}
