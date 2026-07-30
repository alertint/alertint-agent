// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

// zabbixClient is the read surface the MCP zabbix_* tools consume — the
// consumer-owned interface (the SentryReader idiom) so tests inject a fake
// with no HTTP. *zabbix.Client satisfies it.
type zabbixClient interface {
	MetricHistory(ctx context.Context, host, itemKey string, from, to time.Time, limit int) (zabbix.Series, error)
	OpenProblems(ctx context.Context, host string, sel zabbix.ProblemSelector) ([]zabbix.Problem, error)
}

// toolZabbixMetricHistory reads a Zabbix item's metric history for a host.
func (s *Server) toolZabbixMetricHistory() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("zabbix_metric_history",
		mcplib.WithDescription("Read a Zabbix item's metric history for a host (raw history or hourly "+
			"trends for older windows; the 'source' field says which). Inputs: host (technical name), "+
			"item_key, optional start/end RFC3339, optional limit."),
		mcplib.WithString("host",
			mcplib.Description("Zabbix technical host name (required)."),
			mcplib.Required(),
		),
		mcplib.WithString("item_key",
			mcplib.Description("Zabbix item key to read, e.g. system.cpu.util (required)."),
			mcplib.Required(),
		),
		mcplib.WithString("start",
			mcplib.Description("Range start (RFC3339). Defaults to now minus the configured default_range_minutes."),
		),
		mcplib.WithString("end",
			mcplib.Description("Range end (RFC3339). Defaults to now."),
		),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum points to return (default 100)."),
		),
	)
	return tool, s.handleZabbixMetricHistory
}

// toolZabbixHostProblems lists currently-open Zabbix problems on a host.
func (s *Server) toolZabbixHostProblems() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("zabbix_host_problems",
		mcplib.WithDescription("List currently-open Zabbix problems on a host, with severity, tags, "+
			"duration, ack/suppression state. Inputs: host, optional severity_min 0..5."),
		mcplib.WithString("host",
			mcplib.Description("Zabbix technical host name (required)."),
			mcplib.Required(),
		),
		mcplib.WithString("severity_min",
			mcplib.Description(`Minimum severity to include, numeric "0".."5" (optional; no floor when omitted).`),
		),
	)
	return tool, s.handleZabbixHostProblems
}

func (s *Server) handleZabbixMetricHistory(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Zabbix == nil {
		return errResult("zabbix api source is not configured"), nil
	}

	host := mcplib.ParseString(req, "host", "")
	if host == "" {
		return errResult("host is required"), nil
	}
	itemKey := mcplib.ParseString(req, "item_key", "")
	if itemKey == "" {
		return errResult("item_key is required"), nil
	}

	now := time.Now().UTC()
	end := now
	rangeMinutes := s.cfg.ZabbixDefaultRangeMinutes
	if rangeMinutes <= 0 {
		rangeMinutes = 60
	}
	start := now.Add(-time.Duration(rangeMinutes) * time.Minute)
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
	limit := mcplib.ParseInt(req, "limit", 100)
	if limit <= 0 {
		limit = 100
	}

	series, err := s.cfg.Zabbix.MetricHistory(ctx, host, itemKey, start, end, limit)
	if err != nil {
		return errResult("zabbix metric history failed: " + err.Error()), nil
	}
	result, err := mcplib.NewToolResultJSON(series)
	if err != nil {
		return errResult("failed to serialize zabbix metric history: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleZabbixHostProblems(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Zabbix == nil {
		return errResult("zabbix api source is not configured"), nil
	}

	host := mcplib.ParseString(req, "host", "")
	if host == "" {
		return errResult("host is required"), nil
	}
	sel := zabbix.ProblemSelector{SeverityMin: mcplib.ParseString(req, "severity_min", "")}

	problems, err := s.cfg.Zabbix.OpenProblems(ctx, host, sel)
	if err != nil {
		return errResult("zabbix host problems failed: " + err.Error()), nil
	}
	result, err := mcplib.NewToolResultJSON(problems)
	if err != nil {
		return errResult("failed to serialize zabbix host problems: " + err.Error()), nil
	}
	return result, nil
}
