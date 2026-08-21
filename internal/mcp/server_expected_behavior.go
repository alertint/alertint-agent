// SPDX-License-Identifier: FSL-1.1-ALv2

// Expected-behaviour envelope MCP tools: list, confirmed promotion from a
// judgment, and confirmed revocation. Every write is explicitly confirmed
// and attributed; envelopes never expire automatically (D3/spec "Versioning
// and review") — revoke is the only way to retire one early.

package mcp

import (
	"context"
	"encoding/json"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func (s *Server) toolExpectedBehaviorList() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_expected_behavior_list",
		mcplib.WithDescription("List every Expected-behaviour envelope's current head — active, revoked, and "+
			"invalidated. Envelopes never expire automatically; use alertint_expected_behavior_revoke to retire one."),
	)
	return tool, s.handleExpectedBehaviorList
}

func (s *Server) toolExpectedBehaviorConfirm() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_expected_behavior_confirm",
		mcplib.WithDescription("Promote a confirmed current judgment into a reusable Expected-behaviour envelope. "+
			"Every omitted condition means unknown/not authorized, never unlimited — absent duration does not "+
			"authorize arbitrary duration. Requires a confirmed source judgment and explicit confirmation."),
		mcplib.WithString("source_judgment_id", mcplib.Description("ID of a judgment previously recorded with alertint_situation_judgment_record."), mcplib.Required()),
		mcplib.WithNumber("expected_current_version", mcplib.Description("0 to create a new envelope; the envelope's current version to append a new one."), mcplib.Required()),
		mcplib.WithObject("scope", mcplib.Description("{group_key, source, trigger_id, trigger_version} — the exact group and source/trigger identity this envelope authorizes."), mcplib.Required()),
		mcplib.WithObject("conditions", mcplib.Description("{schedule?, duration_minutes?, workload?, required_companion_signals?, allowed_companion_signals?, forbidden_impact_signals?, maximum_uncertainty?, allow_expected_critical?}.")),
		mcplib.WithString("review_due_at", mcplib.Description("RFC3339 instant; creates at most one sparse confirmation reminder per 30-day interval."), mcplib.Required()),
		mcplib.WithBoolean("operator_confirmed", mcplib.Description("Must be true — explicit human confirmation of this envelope."), mcplib.Required()),
		mcplib.WithString("confirmed_by", mcplib.Description("Asserted operator identity (e.g. a name or handle)."), mcplib.Required()),
	)
	return tool, s.handleExpectedBehaviorConfirm
}

func (s *Server) toolExpectedBehaviorRevoke() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_expected_behavior_revoke",
		mcplib.WithDescription("Revoke an Expected-behaviour envelope: appends a revoked version and immediately "+
			"schedules every active Situation that has ever evaluated it for reconsideration."),
		mcplib.WithString("envelope_id", mcplib.Description("Envelope ID."), mcplib.Required()),
		mcplib.WithNumber("expected_current_version", mcplib.Description("The envelope's current version, for optimistic concurrency."), mcplib.Required()),
		mcplib.WithString("reason", mcplib.Description("Why this envelope is being revoked."), mcplib.Required()),
		mcplib.WithBoolean("operator_confirmed", mcplib.Description("Must be true — explicit human confirmation of this revocation."), mcplib.Required()),
		mcplib.WithString("confirmed_by", mcplib.Description("Asserted operator identity (e.g. a name or handle)."), mcplib.Required()),
	)
	return tool, s.handleExpectedBehaviorRevoke
}

func (s *Server) handleExpectedBehaviorList(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	envelopes, err := s.st.ListEnvelopes(ctx)
	if err != nil {
		return errResult("failed to list envelopes: " + err.Error()), nil
	}
	return jsonResult(map[string]any{"envelopes": envelopes})
}

func (s *Server) handleExpectedBehaviorConfirm(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.SituationCommands == nil {
		return errResult("situation commands are unavailable"), nil
	}
	confirmation := model.EnvelopeConfirmation{
		SourceJudgmentID:       mcplib.ParseString(req, "source_judgment_id", ""),
		ExpectedCurrentVersion: mcplib.ParseInt(req, "expected_current_version", -1),
		OperatorConfirmed:      mcplib.ParseBoolean(req, "operator_confirmed", false),
		ConfirmedBy:            mcplib.ParseString(req, "confirmed_by", ""),
	}
	if confirmation.SourceJudgmentID == "" {
		return errResult("source_judgment_id is required"), nil
	}
	if confirmation.ExpectedCurrentVersion < 0 {
		return errResult("expected_current_version is required"), nil
	}
	if errRes := requireConfirmation(confirmation.OperatorConfirmed, confirmation.ConfirmedBy); errRes != nil {
		return errRes, nil
	}
	if err := decodeArgument(req, "scope", &confirmation.Scope); err != nil {
		return errResult("invalid scope: " + err.Error()), nil
	}
	if err := decodeArgument(req, "conditions", &confirmation.Conditions); err != nil {
		return errResult("invalid conditions: " + err.Error()), nil
	}
	reviewDueAt := mcplib.ParseString(req, "review_due_at", "")
	if reviewDueAt == "" {
		return errResult("review_due_at is required"), nil
	}
	t, err := time.Parse(time.RFC3339, reviewDueAt)
	if err != nil {
		return errResult("invalid review_due_at: must be RFC3339"), nil
	}
	confirmation.ReviewDueAt = t.UTC()

	v, err := s.cfg.SituationCommands.ConfirmEnvelope(ctx, confirmation)
	if err != nil {
		return errResult("failed to confirm envelope: " + err.Error()), nil
	}
	return jsonResult(v)
}

func (s *Server) handleExpectedBehaviorRevoke(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.SituationCommands == nil {
		return errResult("situation commands are unavailable"), nil
	}
	revocation := model.EnvelopeRevocation{
		EnvelopeID:             mcplib.ParseString(req, "envelope_id", ""),
		ExpectedCurrentVersion: mcplib.ParseInt(req, "expected_current_version", -1),
		Reason:                 mcplib.ParseString(req, "reason", ""),
		OperatorConfirmed:      mcplib.ParseBoolean(req, "operator_confirmed", false),
		ConfirmedBy:            mcplib.ParseString(req, "confirmed_by", ""),
	}
	if revocation.EnvelopeID == "" {
		return errResult("envelope_id is required"), nil
	}
	if revocation.ExpectedCurrentVersion < 0 {
		return errResult("expected_current_version is required"), nil
	}
	if revocation.Reason == "" {
		return errResult("reason is required"), nil
	}
	if errRes := requireConfirmation(revocation.OperatorConfirmed, revocation.ConfirmedBy); errRes != nil {
		return errRes, nil
	}
	v, err := s.cfg.SituationCommands.RevokeEnvelope(ctx, revocation)
	if err != nil {
		return errResult("failed to revoke envelope: " + err.Error()), nil
	}
	return jsonResult(v)
}

// decodeArgument round-trips one object-typed MCP argument through JSON into
// a concrete struct — the mechanical way to map an arbitrary nested tool
// argument onto model.EnvelopeScope/EnvelopeConditions without hand-parsing
// each field. A missing argument leaves out at its zero value (every
// omitted condition means unknown/not authorized, never unlimited).
func decodeArgument(req mcplib.CallToolRequest, key string, out any) error {
	raw := mcplib.ParseArgument(req, key, nil)
	if raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
