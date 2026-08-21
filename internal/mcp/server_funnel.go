// SPDX-License-Identifier: FSL-1.1-ALv2

// The poke-funnel MCP tool: the same store.PokeFunnel query the `alertint
// funnel` CLI uses (cmd/alertint/funnel.go), so both surfaces report
// identical delivery -> source-episode -> Incident -> Situation ->
// main-channel-poke counts.

package mcp

import (
	"context"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

func (s *Server) toolPokeFunnelGet() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_poke_funnel_get",
		mcplib.WithDescription("Report the local-compression funnel for a window: accepted deliveries, distinct "+
			"source episodes, Incidents, Situations, root creates/edits, non-broadcast and broadcast thread "+
			"replies, envelope reviews, health pokes, and total main-channel pokes. Delivery and source-episode "+
			"counts are reported separately from each other so webhook retries and recovery deliveries are never "+
			"misrepresented as avoided operator interruptions. This does not claim a count of external "+
			"Zabbix-to-Slack messages avoided — that baseline is only observable from the operator's separate path."),
		mcplib.WithString("since", mcplib.Description("Window start (RFC3339, e.g. 2026-08-01T00:00:00Z)."), mcplib.Required()),
		mcplib.WithString("until", mcplib.Description("Window end (RFC3339)."), mcplib.Required()),
	)
	return tool, s.handlePokeFunnelGet
}

func (s *Server) handlePokeFunnelGet(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sinceStr := mcplib.ParseString(req, "since", "")
	untilStr := mcplib.ParseString(req, "until", "")
	if sinceStr == "" || untilStr == "" {
		return errResult("since and until are required (RFC3339)"), nil
	}
	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		return errResult("invalid since: must be RFC3339"), nil
	}
	until, err := time.Parse(time.RFC3339, untilStr)
	if err != nil {
		return errResult("invalid until: must be RFC3339"), nil
	}
	report, err := s.st.PokeFunnel(ctx, since, until)
	if err != nil {
		return errResult("failed to compute poke funnel: " + err.Error()), nil
	}
	return jsonResult(report)
}
