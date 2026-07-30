// SPDX-License-Identifier: FSL-1.1-ALv2

// The two write-back tools (ADR-0027): the only writes an MCP client can
// make, and they land exclusively in AlertINT's own incident state —
// additive, audit-chained. Registered unconditionally: the read-only promise
// is about the operator's systems, not AlertINT's own SQLite.

package mcp

import (
	"context"
	"encoding/json"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/skills/acutetriage"
)

func (s *Server) toolIncidentAnnotate() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_incident_annotate",
		mcplib.WithDescription("Attach an operator note to an incident — human context "+
			"for the next investigator, shown in the incident's history (Slack card and "+
			"MCP reads), permanent and age-stamped. Notes never influence triage or "+
			"memory recall; to correct or confirm a finding with machine effect, use "+
			"alertint_incident_capture_verdict. Writes land only in AlertINT's own "+
			"incident state, audit-chained — never in your systems."),
		mcplib.WithString("incident_id", mcplib.Description("Incident ID from alertint_list_incidents."), mcplib.Required()),
		mcplib.WithString("kind", mcplib.Description("correction | observation"), mcplib.Required()),
		mcplib.WithString("note", mcplib.Description("Free text, max 2000 chars."), mcplib.Required()),
	)
	return tool, s.handleIncidentAnnotate
}

func (s *Server) handleIncidentAnnotate(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Capture == nil {
		return errResult("capture engine unavailable"), nil
	}
	id := mcplib.ParseString(req, "incident_id", "")
	if id == "" {
		return errResult("incident_id is required"), nil
	}
	res, err := s.cfg.Capture.Annotate(ctx, acutetriage.AnnotateRequest{
		IncidentID: id,
		Kind:       mcplib.ParseString(req, "kind", ""),
		Note:       mcplib.ParseString(req, "note", ""),
	})
	if err != nil {
		return errResult(err.Error()), nil
	}
	return mcplib.NewToolResultJSON(map[string]any{
		"annotation_id": res.AnnotationID,
		"demoted":       res.Demoted,
	})
}

func (s *Server) toolIncidentCaptureVerdict() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_incident_capture_verdict",
		mcplib.WithDescription("Capture an operator-confirmed verdict for an incident — a correction or a "+
			"confirmation — as a replayable, graded record. NEVER call this without an explicit human "+
			"confirmation of the verdict. Persists the verdict + annotation first (a grading failure "+
			"cannot lose the capture), runs the widen_queries live once to freeze discriminating "+
			"evidence, then grades current triage against the expectation: red/green with a layer "+
			"(evidence_selection = fix a rule/check; synthesis = fix a hint/prompt). The grade is "+
			"advisory — one sample, not a certification. A repeat call re-grades without re-persisting; "+
			"a changed expectation or new widen_queries creates a new version."),
		mcplib.WithString("incident_id", mcplib.Description("Incident ID."), mcplib.Required()),
		mcplib.WithString("verdict", mcplib.Description("correction | confirmation"), mcplib.Required()),
		mcplib.WithObject("expectation", mcplib.Description(
			"Structured expectation: {cause_alert?, cause_series?: [Prometheus metric names — not Zabbix item keys], severity_rank?, "+
				"must_mention: [subjects], must_not_conclude: [wrong conclusions]}. "+
				"At least one of must_mention/must_not_conclude is required."), mcplib.Required()),
		mcplib.WithString("note", mcplib.Description("Optional annotation note; synthesized from the expectation when absent.")),
		mcplib.WithArray("widen_queries", mcplib.WithStringItems(),
			mcplib.Description("PromQL queries you ran that discriminate the true cause — fetched live once and frozen (max 10).")),
		mcplib.WithString("cause_category", mcplib.Description("Optional free-form cause category.")),
	)
	return tool, s.handleIncidentCaptureVerdict
}

func (s *Server) handleIncidentCaptureVerdict(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.Capture == nil {
		return errResult("capture engine unavailable"), nil
	}
	id := mcplib.ParseString(req, "incident_id", "")
	if id == "" {
		return errResult("incident_id is required"), nil
	}
	var expectation json.RawMessage
	if raw := mcplib.ParseArgument(req, "expectation", nil); raw != nil {
		b, err := json.Marshal(raw)
		if err != nil {
			return errResult("expectation must be a JSON object"), nil
		}
		expectation = b
	}
	var widen []string
	if raw := mcplib.ParseArgument(req, "widen_queries", nil); raw != nil {
		arr, ok := raw.([]any)
		if !ok {
			return errResult("widen_queries must be an array of strings"), nil
		}
		for _, v := range arr {
			sv, ok := v.(string)
			if !ok {
				return errResult("widen_queries must be an array of strings"), nil
			}
			widen = append(widen, sv)
		}
	}
	res, err := s.cfg.Capture.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID:    id,
		Verdict:       mcplib.ParseString(req, "verdict", ""),
		Expectation:   expectation,
		Note:          mcplib.ParseString(req, "note", ""),
		WidenQueries:  widen,
		CauseCategory: mcplib.ParseString(req, "cause_category", ""),
	})
	if err != nil {
		return errResult(err.Error()), nil
	}
	payload := map[string]any{
		"verdict_id": res.VerdictID,
		"version":    res.Version,
		"warnings":   res.Warnings,
	}
	if res.ReplayFailed {
		payload["replay_failed"] = true
	} else {
		payload["grade"] = res.Grade
		if res.Layer != "" {
			payload["layer"] = res.Layer
		}
		if res.ReplayFidelity != "" {
			payload["replay_fidelity"] = res.ReplayFidelity
		}
	}
	return mcplib.NewToolResultJSON(payload)
}
