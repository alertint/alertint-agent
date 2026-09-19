// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func (s *Server) toolExpectedBehaviorPrepare() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return mcplib.NewTool("alertint_expected_behavior_prepare",
		mcplib.WithDescription("Prepare fresh exact Zabbix current-state proof for proposed reusable expected-schedule bindings. This creates no authority."),
		mcplib.WithString("situation_id", mcplib.Required()), mcplib.WithNumber("situation_input_version", mcplib.Required()),
		mcplib.WithArray("required_companions"), mcplib.WithArray("allowed_companions"), mcplib.WithArray("forbidden_signals"),
	), s.handleExpectedBehaviorPrepare
}

func (s *Server) toolGetExpectedBehaviorValidation() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return mcplib.NewTool("alertint_get_expected_behavior_validation", mcplib.WithDescription("Read one reusable expected-schedule binding validation."), mcplib.WithString("validation_id", mcplib.Required())), s.handleGetExpectedBehaviorValidation
}

func expectedBehaviorWriteTool(name, verb string, policy bool) mcplib.Tool {
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(verb + " one explicitly confirmed reusable Zabbix expected schedule. Monitoring, investigation, lifecycle, and recovery remain unchanged."),
		mcplib.WithString("envelope_id"), mcplib.WithNumber("expected_current_version", mcplib.Required()),
		mcplib.WithString("request_id", mcplib.Required()), mcplib.WithString("asserted_operator", mcplib.Required()),
		mcplib.WithBoolean("operator_confirmed", mcplib.Required()),
	}
	if policy {
		opts = append(opts,
			mcplib.WithString("source_judgment_id", mcplib.Required()), mcplib.WithString("validation_id"),
			mcplib.WithString("situation_id", mcplib.Required()), mcplib.WithNumber("situation_input_version", mcplib.Required()),
			mcplib.WithObject("scope", mcplib.Required()), mcplib.WithObject("conditions", mcplib.Required()),
			mcplib.WithString("review_due_at", mcplib.Required()),
		)
	}
	return mcplib.NewTool(name, opts...)
}

func (s *Server) toolExpectedBehaviorConfirm() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return expectedBehaviorWriteTool("alertint_expected_behavior_confirm", "Confirm", true), s.handleExpectedBehaviorConfirm
}
func (s *Server) toolExpectedBehaviorReplace() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return expectedBehaviorWriteTool("alertint_expected_behavior_replace", "Replace", true), s.handleExpectedBehaviorReplace
}
func (s *Server) toolExpectedBehaviorRevoke() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return expectedBehaviorWriteTool("alertint_expected_behavior_revoke", "Withdraw", false), s.handleExpectedBehaviorRevoke
}
func (s *Server) toolExpectedBehaviorRestore() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return expectedBehaviorWriteTool("alertint_expected_behavior_restore", "Restore", true), s.handleExpectedBehaviorRestore
}

func (s *Server) toolGetExpectedBehavior() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return mcplib.NewTool("alertint_get_expected_behavior", mcplib.WithDescription("Get one reusable expected schedule's current authority, review status, and usage."), mcplib.WithString("envelope_id", mcplib.Required())), s.handleGetExpectedBehavior
}
func (s *Server) toolListExpectedBehaviors() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return mcplib.NewTool("alertint_list_expected_behaviors", mcplib.WithDescription("List reusable expected schedules with current authority, review status, and usage."),
		mcplib.WithString("group_key"), mcplib.WithString("source_instance_id"), mcplib.WithString("trigger_id"), mcplib.WithString("review_status"), mcplib.WithBoolean("include_inactive"), mcplib.WithInteger("limit")), s.handleListExpectedBehaviors
}
func (s *Server) toolListExpectedBehaviorHistory() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	return mcplib.NewTool("alertint_list_expected_behavior_history", mcplib.WithDescription("List one reusable expected schedule's immutable operator revisions and source invalidation events."),
		mcplib.WithString("envelope_id", mcplib.Required()), mcplib.WithInteger("cursor_version"), mcplib.WithInteger("limit")), s.handleListExpectedBehaviorHistory
}

func (s *Server) handleExpectedBehaviorPrepare(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	bindings, err := expectedBehaviorBindingsFromRequest(req)
	if err != nil {
		return errResult(err.Error()), nil
	}
	result, err := s.st.PrepareExpectedBehaviorValidation(ctx, store.ExpectedBehaviorValidationPrepare{
		SituationID: strings.TrimSpace(mcplib.ParseString(req, "situation_id", "")), SituationInputVersion: mcplib.ParseInt(req, "situation_input_version", -1),
		Bindings: bindings, Now: s.currentTime(), FreshFor: 5 * time.Minute,
	})
	if err != nil {
		if errors.Is(err, store.ErrExpectedBehaviorValidationStale) || errors.Is(err, store.ErrSituationVersionConflict) {
			return errResult("stale Situation version — re-read with alertint_get_situation and retry"), nil
		}
		return errResult("invalid or unavailable expected-schedule validation request"), nil
	}
	return mcplib.NewToolResultJSON(result)
}

func (s *Server) handleGetExpectedBehaviorValidation(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	validation, err := s.st.GetExpectedBehaviorValidation(ctx, strings.TrimSpace(mcplib.ParseString(req, "validation_id", "")), s.currentTime())
	if err != nil {
		return errResult("expected-schedule validation not found"), nil
	}
	return mcplib.NewToolResultJSON(validation)
}

func (s *Server) handleExpectedBehaviorConfirm(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleExpectedBehaviorWrite(ctx, req, model.ExpectedBehaviorOperationConfirm)
}
func (s *Server) handleExpectedBehaviorReplace(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleExpectedBehaviorWrite(ctx, req, model.ExpectedBehaviorOperationReplace)
}
func (s *Server) handleExpectedBehaviorRevoke(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleExpectedBehaviorWrite(ctx, req, model.ExpectedBehaviorOperationRevoke)
}
func (s *Server) handleExpectedBehaviorRestore(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.handleExpectedBehaviorWrite(ctx, req, model.ExpectedBehaviorOperationRestore)
}

func (s *Server) handleExpectedBehaviorWrite(ctx context.Context, req mcplib.CallToolRequest, operation model.ExpectedBehaviorOperation) (*mcplib.CallToolResult, error) {
	now := s.currentTime()
	write := store.ExpectedBehaviorWrite{
		Operation: operation, EnvelopeID: strings.TrimSpace(mcplib.ParseString(req, "envelope_id", "")),
		SourceJudgmentID: strings.TrimSpace(mcplib.ParseString(req, "source_judgment_id", "")), ValidationID: strings.TrimSpace(mcplib.ParseString(req, "validation_id", "")),
		SituationID: strings.TrimSpace(mcplib.ParseString(req, "situation_id", "")), SituationInputVersion: mcplib.ParseInt(req, "situation_input_version", -1),
		ExpectedCurrentVersion: mcplib.ParseInt(req, "expected_current_version", -1), RequestID: strings.TrimSpace(mcplib.ParseString(req, "request_id", "")),
		AssertedOperator: strings.TrimSpace(mcplib.ParseString(req, "asserted_operator", "")), Confirmed: mcplib.ParseBoolean(req, "operator_confirmed", false), Now: now,
	}
	if operation != model.ExpectedBehaviorOperationRevoke {
		policy, err := expectedBehaviorPolicyFromRequest(req)
		if err != nil {
			return errResult(err.Error()), nil
		}
		write.Policy = &policy
	}
	result, err := s.st.WriteExpectedBehavior(ctx, s.auditor, write)
	if err != nil {
		return errResult(expectedBehaviorWriteError(err)), nil
	}
	return mcplib.NewToolResultJSON(result)
}

func expectedBehaviorWriteError(err error) string {
	switch {
	case errors.Is(err, store.ErrSituationVersionConflict), errors.Is(err, store.ErrExpectedBehaviorVersionConflict), errors.Is(err, store.ErrExpectedBehaviorStale):
		return "stale Situation, judgment, validation, or schedule version — re-read current state and retry"
	case errors.Is(err, store.ErrExpectedBehaviorRequestConflict):
		return "request_id was already used with different arguments; use the original arguments or a new request_id"
	case errors.Is(err, store.ErrExpectedBehaviorNotAllowed) && strings.Contains(err.Error(), "source must be zabbix"):
		return "reusable expected schedules currently support Zabbix only"
	case errors.Is(err, store.ErrExpectedBehaviorNotAllowed) && strings.Contains(err.Error(), "urgent"):
		return "the current Situation is urgent or critical and cannot use an expected schedule"
	case errors.Is(err, store.ErrExpectedBehaviorNotAllowed):
		return "the schedule is not allowed by current source proof or Situation state; re-read the Situation and validation"
	default:
		return "failed to write reusable expected schedule"
	}
}

func (s *Server) handleGetExpectedBehavior(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	overview, err := s.st.GetExpectedBehaviorOverview(ctx, strings.TrimSpace(mcplib.ParseString(req, "envelope_id", "")), s.now().UTC())
	if err != nil {
		return errResult("expected schedule not found"), nil
	}
	return mcplib.NewToolResultJSON(overview)
}

func (s *Server) handleListExpectedBehaviors(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := mcplib.ParseInt(req, "limit", 50)
	if limit < 1 || limit > 100 {
		limit = 50
	}
	reviewStatus := strings.TrimSpace(mcplib.ParseString(req, "review_status", ""))
	includeInactive := mcplib.ParseBoolean(req, "include_inactive", false) || reviewStatus == "inactive" || reviewStatus == "invalidated"
	heads, err := s.st.ListExpectedBehaviors(ctx, store.ExpectedBehaviorListFilter{
		GroupKey: mcplib.ParseString(req, "group_key", ""), SourceInstanceID: mcplib.ParseString(req, "source_instance_id", ""),
		TriggerID: mcplib.ParseString(req, "trigger_id", ""), IncludeInactive: includeInactive,
	}, 100)
	if err != nil {
		return errResult("failed to list expected schedules"), nil
	}
	overviews := make([]store.ExpectedBehaviorOverview, 0, min(limit, len(heads)))
	for _, head := range heads {
		overview, err := s.st.GetExpectedBehaviorOverview(ctx, head.EnvelopeID, s.now().UTC())
		if err != nil {
			return errResult("failed to list expected schedules"), nil
		}
		if reviewStatus != "" && overview.Review.Status != reviewStatus {
			continue
		}
		overviews = append(overviews, overview)
		if len(overviews) == limit {
			break
		}
	}
	return mcplib.NewToolResultJSON(map[string]any{"expected_behaviors": overviews})
}

func (s *Server) handleListExpectedBehaviorHistory(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := strings.TrimSpace(mcplib.ParseString(req, "envelope_id", ""))
	limit := mcplib.ParseInt(req, "limit", 50)
	if limit < 1 || limit > 100 {
		limit = 50
	}
	revisions, err := s.st.ListExpectedBehaviorHistory(ctx, id, mcplib.ParseInt(req, "cursor_version", 0), limit+1)
	if err != nil {
		return errResult("failed to list expected schedule history"), nil
	}
	var next any
	if len(revisions) > limit {
		revisions = revisions[:limit]
		next = map[string]int{"version": revisions[len(revisions)-1].Version}
	}
	events, err := s.st.ListExpectedBehaviorSystemEvents(ctx, id)
	if err != nil {
		return errResult("failed to list expected schedule history"), nil
	}
	return mcplib.NewToolResultJSON(map[string]any{"envelope_id": id, "revisions": revisions, "system_events": events, "next_cursor": next})
}

type expectedBehaviorConditionsMCP struct {
	Workload string                         `json:"workload"`
	Schedule model.ExpectedBehaviorSchedule `json:"schedule"`
	Duration struct {
		Max int `json:"max"`
	} `json:"duration_minutes"`
	Required  []model.ExpectedBehaviorBinding `json:"required_companions"`
	Allowed   []model.ExpectedBehaviorBinding `json:"allowed_companions"`
	Forbidden []model.ExpectedBehaviorBinding `json:"forbidden_signals"`
}

func expectedBehaviorPolicyFromRequest(req mcplib.CallToolRequest) (model.ExpectedBehaviorPolicy, error) {
	var scope model.ExpectedBehaviorScope
	if err := decodeToolArgument(req, "scope", &scope); err != nil {
		return model.ExpectedBehaviorPolicy{}, errors.New("scope must be a complete object")
	}
	var conditions expectedBehaviorConditionsMCP
	if err := decodeToolArgument(req, "conditions", &conditions); err != nil {
		return model.ExpectedBehaviorPolicy{}, errors.New("conditions must be a complete object")
	}
	review, err := time.Parse(time.RFC3339, mcplib.ParseString(req, "review_due_at", ""))
	if err != nil {
		return model.ExpectedBehaviorPolicy{}, errors.New("review_due_at must be an RFC3339 timestamp")
	}
	return model.ExpectedBehaviorPolicy{Scope: scope, Conditions: model.ExpectedBehaviorConditions{
		Workload: conditions.Workload, Schedule: conditions.Schedule, MaxDurationMinutes: conditions.Duration.Max,
		RequiredCompanions: conditions.Required, AllowedCompanions: conditions.Allowed, ForbiddenSignals: conditions.Forbidden,
	}, ReviewDueAt: review.UTC()}, nil
}

func expectedBehaviorBindingsFromRequest(req mcplib.CallToolRequest) ([]model.ExpectedBehaviorBinding, error) {
	var out []model.ExpectedBehaviorBinding
	for _, name := range []string{"required_companions", "allowed_companions", "forbidden_signals"} {
		var bindings []model.ExpectedBehaviorBinding
		if raw := mcplib.ParseArgument(req, name, nil); raw != nil {
			encoded, err := json.Marshal(raw)
			if err != nil || json.Unmarshal(encoded, &bindings) != nil {
				return nil, errors.New(name + " must be an array of exact Zabbix bindings")
			}
		}
		out = append(out, bindings...)
	}
	return out, nil
}

func decodeToolArgument(req mcplib.CallToolRequest, name string, out any) error {
	raw := mcplib.ParseArgument(req, name, nil)
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, out)
}
