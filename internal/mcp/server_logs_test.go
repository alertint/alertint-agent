// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

// spySource is a logs.Source that records whether its network methods were
// called, so tests can assert the evidence-pack path never re-queries the
// backend (ADR-0001 replay).
type spySource struct {
	fetchCalled bool
	queryCalled bool
	data        json.RawMessage
	err         error
}

func (s *spySource) Name() string { return "loki" }
func (s *spySource) FetchRecent(context.Context, logs.Selector, time.Time, time.Time, int) (logs.Fetched, error) {
	s.fetchCalled = true
	return logs.Fetched{}, nil
}
func (s *spySource) QueryRange(context.Context, string, time.Time, time.Time, int, string) (json.RawMessage, error) {
	s.queryCalled = true
	return s.data, s.err
}

func newMCPStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func reqWith(args map[string]any) mcplib.CallToolRequest {
	var r mcplib.CallToolRequest
	r.Params.Arguments = args
	return r
}

func resultText(t *testing.T, r *mcplib.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range r.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestLogsTool_NameAndDescriptionFromSource(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{Logs: &spySource{}, LogsDefaultRangeMinutes: 15}, st, audit.New(st.DB()))
	tool, _ := s.toolLogsQueryRange()
	if tool.Name != "loki_query_range" {
		t.Errorf("tool name = %q, want loki_query_range", tool.Name)
	}
	if !strings.Contains(tool.Description, "loki") {
		t.Errorf("description should name the provider: %q", tool.Description)
	}
	if !strings.Contains(tool.Description, "LogQL") {
		t.Errorf("description should mention the native query language: %q", tool.Description)
	}
}

func TestLogsTool_NilGuardWhenDisabled(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB())) // no Logs
	res, err := s.handleLogsQueryRange(context.Background(), reqWith(map[string]any{"query": "{x}"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "logs source is not configured") {
		t.Fatalf("want 'logs source is not configured' error, got %q", resultText(t, res))
	}
}

func TestLogsTool_ParamValidation(t *testing.T) {
	st := newMCPStore(t)
	spy := &spySource{data: json.RawMessage(`{"resultType":"streams","result":[]}`)}
	s := NewServer(Config{Logs: spy, LogsDefaultRangeMinutes: 15}, st, audit.New(st.DB()))

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing query", map[string]any{}, "query is required"},
		{"bad start", map[string]any{"query": "{x}", "start": "not-a-time"}, "invalid start"},
		{"bad end", map[string]any{"query": "{x}", "end": "not-a-time"}, "invalid end"},
		{"bad direction", map[string]any{"query": "{x}", "direction": "sideways"}, `direction must be "backward" or "forward"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.handleLogsQueryRange(context.Background(), reqWith(tc.args))
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsError || !strings.Contains(resultText(t, res), tc.want) {
				t.Fatalf("want error %q, got %q", tc.want, resultText(t, res))
			}
		})
	}
}

func TestLogsTool_QueryRangePassthrough(t *testing.T) {
	st := newMCPStore(t)
	spy := &spySource{data: json.RawMessage(`{"resultType":"streams","result":[{"stream":{"app":"api"},"values":[["1","boom"]]}]}`)}
	s := NewServer(Config{Logs: spy, LogsDefaultRangeMinutes: 15}, st, audit.New(st.DB()))
	res, err := s.handleLogsQueryRange(context.Background(), reqWith(map[string]any{"query": `{app="api"}`}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, res))
	}
	if !spy.queryCalled {
		t.Error("QueryRange should have been invoked")
	}
	if !strings.Contains(resultText(t, res), "streams") {
		t.Errorf("passthrough did not return raw data: %s", resultText(t, res))
	}
}

func TestEvidencePack_ReplaysEnrichmentNoLokiCall(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()

	// Seed a ready incident, then persist an enrichment snapshot.
	now := time.Now().UTC()
	id := "inc-replay"
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=1", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatal(err)
	}
	// Post-migration 0006 shape: the persisted blob is the keyed envelope
	// {"logs": {...LogEnrichment...}}, replayed opaquely under the "enrichment" key.
	snapshot := `{"logs":{"source":"loki","query":"{namespace=\"prod\",app=\"api\"}","lines":[{"timestamp":"2026-06-17T14:03:11Z","line":"ERROR boom"}]}}`
	if err := st.SaveIncidentOutput(ctx, id, `{"ok":true}`, "n", "i", 0.9, snapshot); err != nil {
		t.Fatal(err)
	}

	spy := &spySource{}
	s := NewServer(Config{Logs: spy, LogsDefaultRangeMinutes: 15}, st, audit.New(st.DB()))
	res, err := s.handleGetEvidencePack(ctx, reqWith(map[string]any{"incident_id": id}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("evidence pack errored: %s", resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, "ERROR boom") || !strings.Contains(out, `"enrichment"`) || !strings.Contains(out, `"logs"`) {
		t.Fatalf("evidence pack did not replay the stored enrichment envelope: %s", out)
	}
	if spy.fetchCalled || spy.queryCalled {
		t.Fatal("evidence pack must NOT call the log backend (replay only)")
	}
}

func TestEvidencePack_OmitsLogsWhenAbsent(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := "inc-nologs"
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=2", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveIncidentOutput(ctx, id, `{"ok":true}`, "n", "i", 0.9, ""); err != nil {
		t.Fatal(err)
	}

	s := NewServer(Config{}, st, audit.New(st.DB())) // logs disabled
	res, err := s.handleGetEvidencePack(ctx, reqWith(map[string]any{"incident_id": id}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resultText(t, res), `"enrichment"`) {
		t.Fatalf("enrichment section must be omitted when absent: %s", resultText(t, res))
	}
}
