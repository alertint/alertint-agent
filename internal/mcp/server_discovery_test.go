// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
)

// promServer starts an httptest Prometheus returning the given data envelope.
func promServer(t *testing.T, dataJSON string) *promclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":` + dataJSON + `}`))
	}))
	t.Cleanup(srv.Close)
	return promclient.NewClient(promclient.Config{BaseURL: srv.URL})
}

// TestPrometheusQuery_EmptyResultHint is the BUG-5 regression: a query that
// matches nothing must be annotated so an empty result is distinguishable from a
// misconfigured selector.
func TestPrometheusQuery_EmptyResultHint(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{Prometheus: promServer(t, `{"resultType":"vector","result":[]}`)}, st, audit.New(st.DB()))

	res, err := s.handlePrometheusQuery(context.Background(), reqWith(map[string]any{"expr": "up"}))
	if err != nil || res.IsError {
		t.Fatalf("query errored: %v %s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, "hint") || !strings.Contains(out, "0 series matched") {
		t.Fatalf("empty prometheus result must carry a discovery hint: %s", out)
	}
	// The hint must not corrupt the parseable envelope.
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("annotated result is not valid JSON: %v\n%s", err, out)
	}
	if payload["resultType"] != "vector" {
		t.Errorf("original fields must survive annotation: %v", payload)
	}
}

func TestPrometheusQuery_NonEmptyNoHint(t *testing.T) {
	st := newMCPStore(t)
	data := `{"resultType":"vector","result":[{"metric":{"__name__":"up"},"value":[1,"1"]}]}`
	s := NewServer(Config{Prometheus: promServer(t, data)}, st, audit.New(st.DB()))

	res, err := s.handlePrometheusQuery(context.Background(), reqWith(map[string]any{"expr": "up"}))
	if err != nil || res.IsError {
		t.Fatalf("query errored: %v %s", err, resultText(t, res))
	}
	if strings.Contains(resultText(t, res), "hint") {
		t.Fatalf("non-empty result must NOT carry a hint: %s", resultText(t, res))
	}
}

// TestPrometheusQuery_NoLocalParserInterception is a boundary regression
// (ADR-0043): the on-demand prometheus_query / prometheus_query_range MCP
// tools remain a direct backend-native passthrough, never intercepted by the
// bundled official-grammar PromQL parser skills/acutetriage's own unattended
// verification path uses (internal/prometheus.ValidateExpr). median_over_time
// is a real VictoriaMetrics/MetricsQL function name a non-vanilla backend may
// support natively, but the official Prometheus grammar does not recognize —
// ValidateExpr rejects it with "unknown function". Both an instant and a
// range call with that exact expression must still reach the fake backend
// byte-identical and come back successfully, proving this package never
// calls that parser (or any parser) at all — not merely that this one
// expression happens to pass it.
func TestPrometheusQuery_NoLocalParserInterception(t *testing.T) {
	const backendSpecificExpr = `median_over_time(metric_name[5m])`
	var gotExprs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExprs = append(gotExprs, r.URL.Query().Get("query"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(srv.Close)
	prom := promclient.NewClient(promclient.Config{BaseURL: srv.URL})

	st := newMCPStore(t)
	s := NewServer(Config{Prometheus: prom}, st, audit.New(st.DB()))

	res, err := s.handlePrometheusQuery(context.Background(), reqWith(map[string]any{"expr": backendSpecificExpr}))
	if err != nil || res.IsError {
		t.Fatalf("instant query errored: %v %s", err, resultText(t, res))
	}
	res, err = s.handlePrometheusQueryRange(context.Background(), reqWith(map[string]any{"expr": backendSpecificExpr}))
	if err != nil || res.IsError {
		t.Fatalf("range query errored: %v %s", err, resultText(t, res))
	}

	if len(gotExprs) != 2 || gotExprs[0] != backendSpecificExpr || gotExprs[1] != backendSpecificExpr {
		t.Fatalf("both exact expressions must reach the backend unmodified, got %v", gotExprs)
	}
}

func TestLogsQueryRange_EmptyResultHint(t *testing.T) {
	st := newMCPStore(t)
	spy := &spySource{data: json.RawMessage(`{"resultType":"streams","result":[]}`)}
	s := NewServer(Config{Logs: spy}, st, audit.New(st.DB()))

	res, err := s.handleLogsQueryRange(context.Background(), reqWith(map[string]any{"query": `{app="api"}`}))
	if err != nil || res.IsError {
		t.Fatalf("logs query errored: %v %s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, "hint") || !strings.Contains(out, "0 streams matched") {
		t.Fatalf("empty logs result must carry a discovery hint: %s", out)
	}
}

func TestLogsQueryRange_NonEmptyNoHint(t *testing.T) {
	st := newMCPStore(t)
	spy := &spySource{data: json.RawMessage(`{"resultType":"streams","result":[{"stream":{"app":"api"},"values":[["1","x"]]}]}`)}
	s := NewServer(Config{Logs: spy}, st, audit.New(st.DB()))

	res, err := s.handleLogsQueryRange(context.Background(), reqWith(map[string]any{"query": `{app="api"}`}))
	if err != nil || res.IsError {
		t.Fatalf("logs query errored: %v %s", err, resultText(t, res))
	}
	if strings.Contains(resultText(t, res), "hint") {
		t.Fatalf("non-empty logs result must NOT carry a hint: %s", resultText(t, res))
	}
}
