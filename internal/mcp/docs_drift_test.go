// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

const (
	mcpClientsDocPath     = "../../docs/integrations/mcp-clients.md"
	scopeAndLimitsDocPath = "../../docs/concepts/scope-and-limits.md"
	availableToolsHeading = "## Available tools"
	toolNameCellPattern   = "`([a-z_]+)`"
)

// TestDriftGate_ToolsDocumented asserts every registered MCP tool name
// appears in docs/integrations/mcp-clients.md's Available-tools table, and
// vice versa. Tool names are collected from the tool builders themselves so a
// new tool without a doc row (or a doc row without a tool) fails CI. This
// repo had no MCP tool↔docs gate before ADR-0027; modeled on
// internal/config/docs_drift_test.go.
func TestDriftGate_ToolsDocumented(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	cfg := sentryMCPConfig(&fakeSentryReader{}, true)
	cfg.Logs = &spySource{}
	cfg.ChangesEnabled = true
	s := &Server{cfg: cfg, st: st, auditor: audit.New(st.DB())}

	names := map[string]bool{}
	addTool := func(name string) { names[name] = true }

	t1, _ := s.toolListIncidents()
	addTool(t1.Name)
	t2, _ := s.toolGetIncident()
	addTool(t2.Name)
	t3, _ := s.toolSearchAlerts()
	addTool(t3.Name)
	t4, _ := s.toolGetEvidencePack()
	addTool(t4.Name)
	t5, _ := s.toolVerifyAudit()
	addTool(t5.Name)
	t6, _ := s.toolPrometheusQuery()
	addTool(t6.Name)
	t7, _ := s.toolPrometheusQueryRange()
	addTool(t7.Name)
	t8, _ := s.toolLogsQueryRange()
	addTool(t8.Name)
	t9, _ := s.toolRecentChanges()
	addTool(t9.Name)
	t10, _ := s.toolSentryIssuesList()
	addTool(t10.Name)
	t11, _ := s.toolSentryIssuesTrace()
	addTool(t11.Name)
	t12, _ := s.toolIncidentAnnotate()
	addTool(t12.Name)
	t13, _ := s.toolIncidentCaptureVerdict()
	addTool(t13.Name)

	documented := documentedToolNames(t)

	for name := range names {
		if !documented[name] {
			t.Errorf("tool %q is registered but not documented in %s", name, mcpClientsDocPath)
		}
	}
	for name := range documented {
		if !names[name] {
			t.Errorf("doc row %q in %s names a tool that is not registered", name, mcpClientsDocPath)
		}
	}
}

// documentedToolNames extracts backticked tool names from table rows between
// the "## Available tools" heading and the next heading.
func documentedToolNames(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(mcpClientsDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", mcpClientsDocPath, err)
	}
	lines := strings.Split(string(b), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == availableToolsHeading {
			start = i + 1
			break
		}
	}
	if start == -1 {
		t.Fatalf("%s: missing %q heading", mcpClientsDocPath, availableToolsHeading)
	}
	cellRe := regexp.MustCompile(toolNameCellPattern)
	out := map[string]bool{}
	for _, l := range lines[start:] {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "## ") {
			break
		}
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		if m := cellRe.FindStringSubmatch(trimmed); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// TestDriftGate_WriteBackWordingPresent asserts the reframed read-only claim
// (ADR-0027) is present on both public docs surfaces.
func TestDriftGate_WriteBackWordingPresent(t *testing.T) {
	for _, f := range []string{mcpClientsDocPath, scopeAndLimitsDocPath} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if !strings.Contains(string(b), "AlertINT's own incident") {
			t.Errorf("%s: missing the write-back wording (ADR-0027)", f)
		}
	}
}
