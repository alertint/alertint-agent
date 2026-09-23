// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"errors"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func situationExpectedTool(name, verb string, deadline bool) mcplib.Tool {
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(verb + " one explicitly confirmed, episode-scoped decision that the current non-critical Situation condition is expected. " +
			"The command is version-fenced, audit-chained, and wakes reconciliation. Re-read with alertint_get_situation before calling. " +
			"NEVER call without explicit operator instruction or confirmation. It does not change lifecycle, stop monitoring, cancel investigation, or claim recovery."),
		mcplib.WithString("situation_id", mcplib.Description("Situation ID from alertint_get_situation."), mcplib.Required()),
		mcplib.WithNumber("situation_input_version", mcplib.Description("Current input_version from alertint_get_situation."), mcplib.Required()),
		mcplib.WithNumber("expected_judgment_version", mcplib.Description("Current judgment_version from alertint_get_situation; 0 when none exists."), mcplib.Required()),
		mcplib.WithString("request_id", mcplib.Description("Client-generated unique identity for safe idempotent retry."), mcplib.Required()),
		mcplib.WithString("asserted_operator", mcplib.Description("Name the authenticated MCP client asserts made this decision."), mcplib.Required()),
		mcplib.WithBoolean("confirmed", mcplib.Description("Must be true: the operator explicitly instructed or confirmed this exact decision."), mcplib.Required()),
	}
	if deadline {
		opts = append(opts, mcplib.WithString("valid_until", mcplib.Description("Future RFC3339 deadline with timezone; no indefinite default."), mcplib.Required()))
	}
	return newTool(name, opts...)
}

func (s *Server) toolRecordSituationExpected() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return situationExpectedTool("alertint_record_situation_expected", "Record", true), s.handleRecordSituationExpected
}

func (s *Server) toolReplaceSituationExpected() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return situationExpectedTool("alertint_replace_situation_expected", "Replace", true), s.handleReplaceSituationExpected
}

func (s *Server) toolRevokeSituationExpected() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return situationExpectedTool("alertint_revoke_situation_expected", "Withdraw", false), s.handleRevokeSituationExpected
}

func (s *Server) toolRestoreSituationExpected() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return situationExpectedTool("alertint_restore_situation_expected", "Restore", true), s.handleRestoreSituationExpected
}

func (s *Server) toolListSituationJudgments() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := newTool("alertint_list_situation_judgments",
		mcplib.WithDescription("List one Situation's immutable expectedness revisions oldest first. This is history; use alertint_get_situation for current authority."),
		mcplib.WithString("situation_id", mcplib.Description("Situation ID."), mcplib.Required()),
		mcplib.WithInteger("limit", mcplib.Description("Maximum revisions to return (1-100, default 50).")),
		mcplib.WithInteger("cursor_revision", mcplib.Description("Resume strictly after this revision from next_cursor.")),
	)
	return tool, s.handleListSituationJudgments
}

func (s *Server) handleRecordSituationExpected(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleSituationExpectedWrite(ctx, req, model.JudgmentOperationRecord)
}

func (s *Server) handleReplaceSituationExpected(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleSituationExpectedWrite(ctx, req, model.JudgmentOperationReplace)
}

func (s *Server) handleRevokeSituationExpected(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleSituationExpectedWrite(ctx, req, model.JudgmentOperationRevoke)
}

func (s *Server) handleRestoreSituationExpected(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleSituationExpectedWrite(ctx, req, model.JudgmentOperationRestore)
}

func (s *Server) handleSituationExpectedWrite(ctx context.Context, req mcplib.CallToolRequest, operation model.JudgmentOperation) (*mcplib.CallToolResult, error) {
	now := s.currentTime()
	write := store.SituationJudgmentWrite{
		Operation: operation, SituationID: strings.TrimSpace(mcplib.ParseString(req, "situation_id", "")),
		SituationInputVersion:   mcplib.ParseInt(req, "situation_input_version", -1),
		ExpectedJudgmentVersion: mcplib.ParseInt(req, "expected_judgment_version", -1),
		RequestID:               strings.TrimSpace(mcplib.ParseString(req, "request_id", "")),
		AssertedOperator:        strings.TrimSpace(mcplib.ParseString(req, "asserted_operator", "")),
		Confirmed:               mcplib.ParseBoolean(req, "confirmed", false), Now: now,
	}
	if write.SituationID == "" || write.SituationInputVersion < 1 || write.ExpectedJudgmentVersion < 0 || write.RequestID == "" || write.AssertedOperator == "" {
		return errResult("situation_id, situation_input_version, expected_judgment_version, request_id, and asserted_operator are required"), nil
	}
	if !write.Confirmed {
		return errResult("confirmed=true is required for an explicit operator decision"), nil
	}
	if operation != model.JudgmentOperationRevoke {
		raw := strings.TrimSpace(mcplib.ParseString(req, "valid_until", ""))
		deadline, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return errResult("valid_until must be an RFC3339 timestamp with timezone"), nil
		}
		write.ValidUntil = deadline.UTC()
	}
	result, err := s.st.WriteSituationJudgment(ctx, s.auditor, write)
	if err != nil {
		return errResult(situationExpectedWriteError(err)), nil
	}
	out, err := mcplib.NewToolResultJSON(result)
	if err != nil {
		return errResult("failed to serialize situation judgment"), nil
	}
	return out, nil
}

func situationExpectedWriteError(err error) string {
	switch {
	case errors.Is(err, store.ErrSituationVersionConflict), errors.Is(err, store.ErrSituationJudgmentVersionConflict):
		return "stale Situation or judgment version — re-read with alertint_get_situation and retry against its current input_version and judgment_version"
	case errors.Is(err, store.ErrSituationJudgmentRequestConflict):
		return "request_id was already used with different arguments; use the original arguments or a new request_id"
	case errors.Is(err, store.ErrSituationJudgmentNotAllowed) && strings.Contains(err.Error(), string(model.JudgmentUrgent)):
		return "the current Situation is urgent or critical and cannot be marked expected; use alertint_incident_annotate if human context should be retained"
	case errors.Is(err, store.ErrSituationJudgmentNotAllowed):
		return "this expectedness operation is not allowed for the current Situation state — re-read with alertint_get_situation"
	default:
		return "failed to write situation judgment"
	}
}

func (s *Server) handleListSituationJudgments(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	situationID := strings.TrimSpace(mcplib.ParseString(req, "situation_id", ""))
	if situationID == "" {
		return errResult("situation_id is required"), nil
	}
	limit := mcplib.ParseInt(req, "limit", 50)
	if limit < 1 || limit > 100 {
		limit = 50
	}
	cursorRevision := mcplib.ParseInt(req, "cursor_revision", 0)
	if cursorRevision < 0 {
		return errResult("cursor_revision must be non-negative"), nil
	}
	judgments, err := s.st.ListSituationJudgments(ctx, situationID, cursorRevision, limit+1)
	if err != nil {
		return errResult("failed to list situation judgments"), nil
	}
	var nextCursor any
	if len(judgments) > limit {
		judgments = judgments[:limit]
		nextCursor = map[string]int{"revision": judgments[len(judgments)-1].Revision}
	}
	result, err := mcplib.NewToolResultJSON(map[string]any{"situation_id": situationID, "judgments": judgments, "next_cursor": nextCursor})
	if err != nil {
		return errResult("failed to serialize situation judgments"), nil
	}
	return result, nil
}
