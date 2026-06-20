// SPDX-License-Identifier: FSL-1.1-ALv2

// Package mcp implements the AlertINT HTTP MCP server.
//
// alertint serve starts this server alongside the webhook receiver when
// mcp.enabled is true in config. MCP clients (Claude Code, Cursor, Windsurf)
// connect by URL over the network — no subprocess spawning, no shared files.
//
// Default endpoint: http://host:9912/mcp
// Auth: Bearer token (constant-time compare, same pattern as the webhook).
// All tools are read-only; no tool mutates store state or external systems.
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/logs"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// Config holds the values the MCP server needs at runtime.
type Config struct {
	Token         string             // resolved bearer token (not the env var name)
	WindowSeconds int                // correlator window size, forwarded into evidence packs
	Prometheus    *promclient.Client // nil = prometheus tools disabled
	// Logs is the configured read-only log source. nil = the log passthrough
	// tool is not registered. The tool is named <Logs.Name()>_query_range.
	Logs logs.Source
	// LogsDefaultRangeMinutes is the default look-back for the log range tool
	// when start is omitted (config's logs.default_range_minutes).
	LogsDefaultRangeMinutes int
	// ChangesEnabled registers alertint_recent_changes when true (gated on
	// changes.enrichment.enabled). ChangesWindowMinutes is the default look-back
	// when neither window nor start/end is supplied.
	ChangesEnabled       bool
	ChangesWindowMinutes int
}

// Server is the AlertINT MCP HTTP server. Construct with NewServer; start
// by passing Handler() to an http.Server on the configured addr.
type Server struct {
	cfg     Config
	st      *store.Store
	auditor *audit.Auditor
	handler http.Handler
}

// NewServer builds the MCP server with all five AlertINT tools registered.
func NewServer(cfg Config, st *store.Store, auditor *audit.Auditor) *Server {
	s := &Server{cfg: cfg, st: st, auditor: auditor}

	ms := mcpserver.NewMCPServer("AlertINT", "1.0.0",
		mcpserver.WithToolCapabilities(false),
	)

	ms.AddTool(s.toolListIncidents())
	ms.AddTool(s.toolGetIncident())
	ms.AddTool(s.toolSearchAlerts())
	ms.AddTool(s.toolGetEvidencePack())
	ms.AddTool(s.toolVerifyAudit())
	ms.AddTool(s.toolPrometheusQuery())
	ms.AddTool(s.toolPrometheusQueryRange())

	// Log passthrough tool, registered only when a log source is configured.
	// Named after the active backend (loki_query_range) so multiple sources can
	// coexist additively later — see ADR-0003.
	if s.cfg.Logs != nil {
		ms.AddTool(s.toolLogsQueryRange())
	}

	// Change-events tool, registered only when change enrichment is enabled.
	if s.cfg.ChangesEnabled {
		ms.AddTool(s.toolRecentChanges())
	}

	// StreamableHTTPServer mounts internally at /mcp. Final client URL:
	// http://host:<mcp_addr>/mcp
	httpSrv := mcpserver.NewStreamableHTTPServer(ms)
	s.handler = s.withBearerAuth(httpSrv)
	return s
}

// Handler returns the http.Handler to mount on an http.Server.
func (s *Server) Handler() http.Handler { return s.handler }

// withBearerAuth wraps h with constant-time bearer token verification.
func (s *Server) withBearerAuth(next http.Handler) http.Handler {
	token := []byte(s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare(token, got) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------------
// Tool definitions (read-only, never mutate state)
// -----------------------------------------------------------------------------

func (s *Server) toolListIncidents() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_list_incidents",
		mcplib.WithDescription("List recent AlertINT incidents, newest first. "+
			"Each incident groups one or more related alerts with an AI finding."),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of incidents to return (1–100, default 20)."),
		),
	)
	return tool, s.handleListIncidents
}

func (s *Server) toolGetIncident() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_incident",
		mcplib.WithDescription("Get full details for one incident: member alerts with their roles, "+
			"AI finding (analysis name, overall issue, correlation findings, severity, confidence), "+
			"and raw LLM output JSON."),
		mcplib.WithString("incident_id",
			mcplib.Description("Incident ID from alertint_list_incidents."),
			mcplib.Required(),
		),
	)
	return tool, s.handleGetIncident
}

func (s *Server) toolSearchAlerts() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_search_alerts",
		mcplib.WithDescription("Search stored alerts. All parameters are optional. "+
			"Returns alerts ordered by received_at descending."),
		mcplib.WithString("since",
			mcplib.Description("Return alerts received at or after this time (RFC3339, e.g. 2026-06-01T00:00:00Z)."),
		),
		mcplib.WithString("until",
			mcplib.Description("Return alerts received at or before this time (RFC3339)."),
		),
		mcplib.WithString("status",
			mcplib.Description(`Filter by status: "firing" or "resolved".`),
		),
		mcplib.WithString("label_key",
			mcplib.Description("Filter by label key (requires label_value to be set too)."),
		),
		mcplib.WithString("label_value",
			mcplib.Description("Filter by label value (requires label_key to be set too)."),
		),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of alerts to return (1–200, default 50)."),
		),
	)
	return tool, s.handleSearchAlerts
}

func (s *Server) toolGetEvidencePack() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_evidence_pack",
		mcplib.WithDescription("Return the compact evidence pack for an incident — the same "+
			"structured context that the acute-triage skill passed to the LLM: shared labels, "+
			"alert timeline, severity distribution, and top annotations."),
		mcplib.WithString("incident_id",
			mcplib.Description("Incident ID from alertint_list_incidents."),
			mcplib.Required(),
		),
	)
	return tool, s.handleGetEvidencePack
}

func (s *Server) toolVerifyAudit() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_verify_audit",
		mcplib.WithDescription("Walk the hash-chained audit log and verify tamper-evidence. "+
			"Returns the number of rows checked and whether the chain is intact."),
	)
	return tool, s.handleVerifyAudit
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

func (s *Server) handleListIncidents(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := mcplib.ParseInt(req, "limit", 20)
	if limit < 1 {
		limit = 20
	}

	incidents, err := s.st.ListRecentIncidents(ctx, limit)
	if err != nil {
		return errResult("failed to list incidents: " + err.Error()), nil
	}

	type row struct {
		ID           string    `json:"id"`
		GroupKey     string    `json:"group_key"`
		Status       string    `json:"status"`
		AlertCount   int       `json:"alert_count"`
		Summary      string    `json:"summary,omitempty"`
		RootCause    string    `json:"root_cause,omitempty"`
		Confidence   float64   `json:"confidence,omitempty"`
		FirstAlertAt time.Time `json:"first_alert_at"`
		LastAlertAt  time.Time `json:"last_alert_at"`
		CreatedAt    time.Time `json:"created_at"`
	}

	rows := make([]row, 0, len(incidents))
	for _, inc := range incidents {
		rows = append(rows, row{
			ID:           inc.ID,
			GroupKey:     inc.GroupKey,
			Status:       inc.Status,
			AlertCount:   inc.AlertCount,
			Summary:      inc.Summary,
			RootCause:    inc.RootCause,
			Confidence:   inc.Confidence,
			FirstAlertAt: inc.FirstAlertAt,
			LastAlertAt:  inc.LastAlertAt,
			CreatedAt:    inc.CreatedAt,
		})
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"incidents": rows})
	if err != nil {
		return errResult("failed to serialize incidents: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleGetIncident(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := mcplib.ParseString(req, "incident_id", "")
	if id == "" {
		return errResult("incident_id is required"), nil
	}

	inc, err := s.st.GetIncidentByID(ctx, id)
	if err != nil {
		return errResult("failed to get incident: " + err.Error()), nil
	}
	if inc == nil {
		return errResult(fmt.Sprintf("incident %q not found", id)), nil
	}

	alerts, err := s.st.GetIncidentAlertsWithRoles(ctx, id)
	if err != nil {
		return errResult("failed to get incident alerts: " + err.Error()), nil
	}

	// Parse output_json into a generic map so the LLM sees structured fields.
	var finding map[string]any
	if inc.OutputJSON != "" {
		_ = json.Unmarshal([]byte(inc.OutputJSON), &finding)
	}

	type alertRow struct {
		ID          string            `json:"id"`
		Fingerprint string            `json:"fingerprint"`
		Status      string            `json:"status"`
		Role        string            `json:"role,omitempty"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"starts_at"`
		EndsAt      *time.Time        `json:"ends_at,omitempty"`
	}

	alertRows := make([]alertRow, 0, len(alerts))
	for _, a := range alerts {
		alertRows = append(alertRows, alertRow{
			ID:          a.ID,
			Fingerprint: a.Fingerprint,
			Status:      a.Status,
			Role:        a.Role,
			Labels:      a.Labels,
			Annotations: a.Annotations,
			StartsAt:    a.StartsAt,
			EndsAt:      a.EndsAt,
		})
	}

	payload := map[string]any{
		"id":             inc.ID,
		"group_key":      inc.GroupKey,
		"status":         inc.Status,
		"alert_count":    inc.AlertCount,
		"first_alert_at": inc.FirstAlertAt,
		"last_alert_at":  inc.LastAlertAt,
		"created_at":     inc.CreatedAt,
		"updated_at":     inc.UpdatedAt,
		"summary":        inc.Summary,
		"root_cause":     inc.RootCause,
		"confidence":     inc.Confidence,
		"finding":        finding,
		"alerts":         alertRows,
	}

	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize incident: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleSearchAlerts(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	f := store.AlertFilter{
		Status:     mcplib.ParseString(req, "status", ""),
		LabelKey:   mcplib.ParseString(req, "label_key", ""),
		LabelValue: mcplib.ParseString(req, "label_value", ""),
		Limit:      mcplib.ParseInt(req, "limit", 50),
	}

	if sinceStr := mcplib.ParseString(req, "since", ""); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			return errResult("invalid since: must be RFC3339 (e.g. 2026-06-01T00:00:00Z)"), nil
		}
		f.Since = &t
	}
	if untilStr := mcplib.ParseString(req, "until", ""); untilStr != "" {
		t, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			return errResult("invalid until: must be RFC3339"), nil
		}
		f.Until = &t
	}

	if f.Status != "" && f.Status != "firing" && f.Status != "resolved" {
		return errResult(`status must be "firing" or "resolved"`), nil
	}

	alerts, err := s.st.SearchAlerts(ctx, f)
	if err != nil {
		return errResult("failed to search alerts: " + err.Error()), nil
	}

	type row struct {
		ID          string            `json:"id"`
		Fingerprint string            `json:"fingerprint"`
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"starts_at"`
		EndsAt      *time.Time        `json:"ends_at,omitempty"`
		ReceivedAt  time.Time         `json:"received_at"`
	}

	rows := make([]row, 0, len(alerts))
	for _, a := range alerts {
		rows = append(rows, row{
			ID:          a.ID,
			Fingerprint: a.Fingerprint,
			Status:      a.Status,
			Labels:      a.Labels,
			Annotations: a.Annotations,
			StartsAt:    a.StartsAt,
			EndsAt:      a.EndsAt,
			ReceivedAt:  a.ReceivedAt,
		})
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"alerts": rows})
	if err != nil {
		return errResult("failed to serialize alerts: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleGetEvidencePack(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := mcplib.ParseString(req, "incident_id", "")
	if id == "" {
		return errResult("incident_id is required"), nil
	}

	inc, err := s.st.GetIncidentByID(ctx, id)
	if err != nil {
		return errResult("failed to get incident: " + err.Error()), nil
	}
	if inc == nil {
		return errResult(fmt.Sprintf("incident %q not found", id)), nil
	}

	alerts, err := s.st.GetIncidentAlerts(ctx, id)
	if err != nil {
		return errResult("failed to get incident alerts: " + err.Error()), nil
	}

	pack := acutetriage.BuildEvidencePack(*inc, alerts, s.cfg.WindowSeconds)
	metrics := acutetriage.FetchMetrics(ctx, s.cfg.Prometheus, alerts, inc.FirstAlertAt)

	// Enrichment is REPLAYED from the persisted envelope, never re-queried — the
	// pack reflects exactly what the LLM saw (ADR-0001). Absent (short-circuited
	// / disabled) → omitted. After migration 0006 every non-null value is the
	// uniform {"logs":…,"changes":…} envelope, so this stays an opaque passthrough.
	var enrichmentSnapshot json.RawMessage
	if inc.EnrichmentJSON != "" {
		enrichmentSnapshot = json.RawMessage(inc.EnrichmentJSON)
	}

	type packWithEnrichment struct {
		acutetriage.EvidencePack

		Metrics    []acutetriage.MetricSnapshot `json:"metrics,omitempty"`
		Enrichment json.RawMessage              `json:"enrichment,omitempty"`
	}
	result, err := mcplib.NewToolResultJSON(packWithEnrichment{
		EvidencePack: pack,
		Metrics:      metrics,
		Enrichment:   enrichmentSnapshot,
	})
	if err != nil {
		return errResult("failed to serialize evidence pack: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleVerifyAudit(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	report, err := s.auditor.Verify(ctx)

	type response struct {
		OK           bool   `json:"ok"`
		RowsChecked  int    `json:"rows_checked"`
		FirstErrorAt *int64 `json:"first_error_seq,omitempty"`
		Message      string `json:"message"`
	}

	resp := response{}
	if err != nil {
		resp.OK = false
		if report != nil {
			seq := report.FailedSeq
			resp.FirstErrorAt = &seq
			resp.RowsChecked = report.RowsChecked
			resp.Message = fmt.Sprintf("chain broken at seq %d: %s", report.FailedSeq, report.Reason)
		} else {
			resp.Message = "verification failed: " + err.Error()
		}
	} else {
		resp.OK = true
		if report != nil {
			resp.RowsChecked = report.RowsChecked
		}
		resp.Message = fmt.Sprintf("audit chain intact: %d row(s) verified", resp.RowsChecked)
	}

	result, err := mcplib.NewToolResultJSON(resp)
	if err != nil {
		return errResult("failed to serialize audit result: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) toolPrometheusQuery() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prometheus_query",
		mcplib.WithDescription("Execute an instant PromQL query against the connected Prometheus. "+
			"Returns the current value(s) for the expression. "+
			"Use this to check live metric values during incident investigation."),
		mcplib.WithString("expr",
			mcplib.Description("PromQL expression to evaluate (e.g. rate(http_requests_total[5m]))."),
			mcplib.Required(),
		),
		mcplib.WithString("time",
			mcplib.Description("Evaluation timestamp (RFC3339). Defaults to now."),
		),
	)
	return tool, s.handlePrometheusQuery
}

func (s *Server) toolPrometheusQueryRange() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prometheus_query_range",
		mcplib.WithDescription("Execute a range PromQL query and return a time-series matrix. "+
			"Use this to see how a metric evolved over time around an incident."),
		mcplib.WithString("expr",
			mcplib.Description("PromQL expression to evaluate."),
			mcplib.Required(),
		),
		mcplib.WithString("start",
			mcplib.Description("Range start (RFC3339). Defaults to now minus the configured default_range_minutes."),
		),
		mcplib.WithString("end",
			mcplib.Description("Range end (RFC3339). Defaults to now."),
		),
		mcplib.WithString("step",
			mcplib.Description("Step duration in seconds (e.g. 30 for 30s). Auto-computed from range when omitted."),
		),
	)
	return tool, s.handlePrometheusQueryRange
}

func (s *Server) handlePrometheusQuery(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Prometheus == nil {
		return errResult("prometheus is not configured (prometheus.enabled is false in config)"), nil
	}

	expr := mcplib.ParseString(req, "expr", "")
	if expr == "" {
		return errResult("expr is required"), nil
	}

	var t time.Time
	if tsStr := mcplib.ParseString(req, "time", ""); tsStr != "" {
		parsed, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			return errResult("invalid time: must be RFC3339 (e.g. 2026-06-05T14:00:00Z)"), nil
		}
		t = parsed
	}

	data, err := s.cfg.Prometheus.QueryInstant(ctx, expr, t)
	if err != nil {
		return errResult("prometheus query failed: " + err.Error()), nil
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return errResult("failed to parse prometheus response: " + err.Error()), nil
	}
	result, err := mcplib.NewToolResultJSON(parsed)
	if err != nil {
		return errResult("failed to serialize result: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handlePrometheusQueryRange(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Prometheus == nil {
		return errResult("prometheus is not configured (prometheus.enabled is false in config)"), nil
	}

	expr := mcplib.ParseString(req, "expr", "")
	if expr == "" {
		return errResult("expr is required"), nil
	}

	now := time.Now().UTC()
	end := now
	start := now.Add(-time.Duration(s.cfg.Prometheus.DefaultRangeMinutes()) * time.Minute)

	if startStr := mcplib.ParseString(req, "start", ""); startStr != "" {
		parsed, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return errResult("invalid start: must be RFC3339"), nil
		}
		start = parsed
	}
	if endStr := mcplib.ParseString(req, "end", ""); endStr != "" {
		parsed, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return errResult("invalid end: must be RFC3339"), nil
		}
		end = parsed
	}
	if start.After(end) {
		return errResult("start must be before end"), nil
	}

	var step time.Duration
	if stepStr := mcplib.ParseString(req, "step", ""); stepStr != "" {
		secs := mcplib.ParseInt(req, "step", 0)
		if secs > 0 {
			step = time.Duration(secs) * time.Second
		}
	}

	data, err := s.cfg.Prometheus.QueryRange(ctx, expr, start, end, step)
	if err != nil {
		return errResult("prometheus range query failed: " + err.Error()), nil
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return errResult("failed to parse prometheus response: " + err.Error()), nil
	}
	result, err := mcplib.NewToolResultJSON(parsed)
	if err != nil {
		return errResult("failed to serialize result: " + err.Error()), nil
	}
	return result, nil
}

// toolLogsQueryRange builds the log passthrough tool. Its name and description
// are derived from the active source's Name() at construction time, e.g.
// "loki_query_range", because the tool exposes that backend's native query
// language (LogQL). For logs, range subsumes instant — a range query returns the
// lines an instant query would plus surrounding context — so v1 ships only the
// range tool (KISS).
func (s *Server) toolLogsQueryRange() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	name := s.cfg.Logs.Name() + "_query_range"
	desc := fmt.Sprintf("Range-query the configured log backend (%s) using its native query language (LogQL). "+
		"Use this to drill into or around an incident: widen the time window, change the label selector, "+
		"or grep for new patterns. Read-only.", s.cfg.Logs.Name())
	tool := mcplib.NewTool(name,
		mcplib.WithDescription(desc),
		mcplib.WithString("query",
			mcplib.Description("Native query in the backend's language (LogQL for loki), e.g. {app=\"api\"} |= \"panic\"."),
			mcplib.Required(),
		),
		mcplib.WithString("start",
			mcplib.Description("Range start (RFC3339). Defaults to now minus the configured default_range_minutes."),
		),
		mcplib.WithString("end",
			mcplib.Description("Range end (RFC3339). Defaults to now."),
		),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of log lines to return."),
		),
		mcplib.WithString("direction",
			mcplib.Description(`Scan direction: "backward" (newest first, default) or "forward".`),
		),
	)
	return tool, s.handleLogsQueryRange
}

func (s *Server) handleLogsQueryRange(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Logs == nil {
		return errResult("logs source is not configured"), nil
	}

	query := mcplib.ParseString(req, "query", "")
	if query == "" {
		return errResult("query is required"), nil
	}

	now := time.Now().UTC()
	end := now
	start := now.Add(-time.Duration(s.cfg.LogsDefaultRangeMinutes) * time.Minute)
	if startStr := mcplib.ParseString(req, "start", ""); startStr != "" {
		parsed, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return errResult("invalid start: must be RFC3339 (e.g. 2026-06-05T14:00:00Z)"), nil
		}
		start = parsed
	}
	if endStr := mcplib.ParseString(req, "end", ""); endStr != "" {
		parsed, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return errResult("invalid end: must be RFC3339"), nil
		}
		end = parsed
	}
	if start.After(end) {
		return errResult("start must be before end"), nil
	}

	limit := mcplib.ParseInt(req, "limit", 100)
	dir := mcplib.ParseString(req, "direction", "backward")
	if dir != "backward" && dir != "forward" {
		return errResult(`direction must be "backward" or "forward"`), nil
	}

	data, err := s.cfg.Logs.QueryRange(ctx, query, start, end, limit, dir)
	if err != nil {
		return errResult("logs range query failed: " + err.Error()), nil
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return errResult("failed to parse logs response: " + err.Error()), nil
	}
	result, err := mcplib.NewToolResultJSON(parsed)
	if err != nil {
		return errResult("failed to serialize result: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) toolRecentChanges() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_recent_changes",
		mcplib.WithDescription("List recent change events (deploys, config edits, flag flips) "+
			"newest-first. Use this to answer \"what changed?\" during investigation — widen the "+
			"window or pivot services. Read-only."),
		mcplib.WithObject("selector",
			mcplib.Description("Optional exact label AND-match, e.g. {\"service\":\"checkout\",\"namespace\":\"prod\"}. "+
				"Every key/value must be present on a change for it to match. Omit to return all recent changes."),
		),
		mcplib.WithInteger("window",
			mcplib.Description("Look-back in minutes from now (used when start/end are omitted)."),
		),
		mcplib.WithString("start",
			mcplib.Description("Range start (RFC3339). Overrides window."),
		),
		mcplib.WithString("end",
			mcplib.Description("Range end (RFC3339). Defaults to now."),
		),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of changes to return (default 50)."),
		),
	)
	return tool, s.handleRecentChanges
}

func (s *Server) handleRecentChanges(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if !s.cfg.ChangesEnabled {
		return errResult("change enrichment is not configured (changes.enrichment.enabled is false)"), nil
	}

	now := time.Now().UTC()
	end := now
	window := s.cfg.ChangesWindowMinutes
	if w := mcplib.ParseInt(req, "window", 0); w > 0 {
		window = w
	}
	start := now.Add(-time.Duration(window) * time.Minute)
	if startStr := mcplib.ParseString(req, "start", ""); startStr != "" {
		t, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return errResult("invalid start: must be RFC3339 (e.g. 2026-06-05T14:00:00Z)"), nil
		}
		start = t
	}
	if endStr := mcplib.ParseString(req, "end", ""); endStr != "" {
		t, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return errResult("invalid end: must be RFC3339"), nil
		}
		end = t
	}
	if start.After(end) {
		return errResult("start must be before end"), nil
	}

	// Exact AND-match selector — deliberate difference from triage's any-overlap:
	// the interactive agent supplies the selector deliberately, so precision wins.
	selector := map[string]string{}
	for k, v := range mcplib.ParseStringMap(req, "selector", nil) {
		selector[k] = fmt.Sprintf("%v", v)
	}
	limit := mcplib.ParseInt(req, "limit", 50)

	all, err := s.st.ChangesInWindow(ctx, start, end) // newest-first
	if err != nil {
		return errResult("failed to query changes: " + err.Error()), nil
	}

	type row struct {
		ID         string            `json:"id"`
		Source     string            `json:"source"`
		Kind       string            `json:"kind"`
		Title      string            `json:"title"`
		Labels     map[string]string `json:"labels"`
		Version    string            `json:"version,omitempty"`
		Link       string            `json:"link,omitempty"`
		OccurredAt time.Time         `json:"occurred_at"`
	}
	rows := make([]row, 0, limit)
	for _, c := range all {
		if !matchesAll(c.Labels, selector) {
			continue
		}
		rows = append(rows, row{
			ID: c.ID, Source: c.Source, Kind: c.Kind, Title: c.Title,
			Labels: c.Labels, Version: c.Version, Link: c.Link, OccurredAt: c.OccurredAt,
		})
		if len(rows) >= limit {
			break
		}
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"changes": rows})
	if err != nil {
		return errResult("failed to serialize changes: " + err.Error()), nil
	}
	return result, nil
}

// matchesAll reports whether every selector key/value is present on labels.
func matchesAll(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func errResult(msg string) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(msg)
}
