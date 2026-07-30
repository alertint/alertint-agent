// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// fakeZabbixMCP is a no-HTTP zabbix client stand-in for the MCP handler tests.
type fakeZabbixMCP struct {
	series      zabbix.Series
	historyErr  error
	problems    []zabbix.Problem
	problemsErr error
	gotHost     string
	gotItemKey  string
	gotSel      zabbix.ProblemSelector
}

func (f *fakeZabbixMCP) MetricHistory(_ context.Context, host, itemKey string, _, _ time.Time, _ int) (zabbix.Series, error) {
	f.gotHost, f.gotItemKey = host, itemKey
	if f.historyErr != nil {
		return zabbix.Series{}, f.historyErr
	}
	return f.series, nil
}

func (f *fakeZabbixMCP) OpenProblems(_ context.Context, host string, sel zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	f.gotHost, f.gotSel = host, sel
	if f.problemsErr != nil {
		return nil, f.problemsErr
	}
	return f.problems, nil
}

// Registration itself is gated on cfg.Zabbix != nil (mirrors the Sentry
// registration gate); with no client the two zabbix_* tools are absent from
// the tool list and only reachable via direct handler calls, which refuse
// below (the same disabled-guard convention every other source tool uses).
func TestZabbixTools_DisabledGuards(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB())) // no Zabbix

	hr, _ := s.handleZabbixMetricHistory(context.Background(), reqWith(map[string]any{"host": "web01", "item_key": "k"}))
	if !hr.IsError || !strings.Contains(resultText(t, hr), "not configured") {
		t.Errorf("metric history disabled guard: %q", resultText(t, hr))
	}
	pr, _ := s.handleZabbixHostProblems(context.Background(), reqWith(map[string]any{"host": "web01"}))
	if !pr.IsError || !strings.Contains(resultText(t, pr), "not configured") {
		t.Errorf("host problems disabled guard: %q", resultText(t, pr))
	}
}

func zabbixMCPConfig(c zabbixClient) Config {
	return Config{Zabbix: c, ZabbixDefaultRangeMinutes: 60}
}

func TestZabbixMetricHistory_ParamValidation(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeZabbixMCP{series: zabbix.Series{Source: "history"}}
	s := NewServer(zabbixMCPConfig(fk), st, audit.New(st.DB()))

	missing, _ := s.handleZabbixMetricHistory(context.Background(), reqWith(map[string]any{"item_key": "k"}))
	if !missing.IsError || !strings.Contains(resultText(t, missing), "host is required") {
		t.Errorf("missing host should error: %q", resultText(t, missing))
	}
	missingKey, _ := s.handleZabbixMetricHistory(context.Background(), reqWith(map[string]any{"host": "web01"}))
	if !missingKey.IsError || !strings.Contains(resultText(t, missingKey), "item_key is required") {
		t.Errorf("missing item_key should error: %q", resultText(t, missingKey))
	}
	badStart, _ := s.handleZabbixMetricHistory(context.Background(), reqWith(map[string]any{"host": "web01", "item_key": "k", "start": "not-a-time"}))
	if !badStart.IsError || !strings.Contains(resultText(t, badStart), "RFC3339") {
		t.Errorf("malformed start should error mentioning RFC3339: %q", resultText(t, badStart))
	}

	ok, err := s.handleZabbixMetricHistory(context.Background(), reqWith(map[string]any{"host": "web01", "item_key": "system.cpu.util"}))
	if err != nil || ok.IsError {
		t.Fatalf("happy path errored: %v / %q", err, resultText(t, ok))
	}
	if fk.gotHost != "web01" || fk.gotItemKey != "system.cpu.util" {
		t.Errorf("host/item_key not forwarded: host=%q item_key=%q", fk.gotHost, fk.gotItemKey)
	}
	var payload zabbix.Series
	if err := json.Unmarshal([]byte(resultText(t, ok)), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Source != "history" {
		t.Errorf("series not returned: %+v", payload)
	}
}

func TestZabbixHostProblems_ReturnsProblems(t *testing.T) {
	st := newMCPStore(t)
	fk := &fakeZabbixMCP{problems: []zabbix.Problem{{EventID: "1", Name: "disk full", Severity: "4"}}}
	s := NewServer(zabbixMCPConfig(fk), st, audit.New(st.DB()))

	res, err := s.handleZabbixHostProblems(context.Background(), reqWith(map[string]any{"host": "web01", "severity_min": "3"}))
	if err != nil || res.IsError {
		t.Fatalf("happy path errored: %v / %q", err, resultText(t, res))
	}
	if fk.gotHost != "web01" || fk.gotSel.SeverityMin != "3" {
		t.Errorf("host/severity_min not forwarded: host=%q sel=%+v", fk.gotHost, fk.gotSel)
	}
	var payload []zabbix.Problem
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload) != 1 || payload[0].EventID != "1" {
		t.Fatalf("problems = %+v", payload)
	}

	missing, _ := s.handleZabbixHostProblems(context.Background(), reqWith(map[string]any{}))
	if !missing.IsError || !strings.Contains(resultText(t, missing), "host is required") {
		t.Errorf("missing host should error: %q", resultText(t, missing))
	}
}
