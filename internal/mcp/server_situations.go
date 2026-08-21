// SPDX-License-Identifier: FSL-1.1-ALv2

// Situation MCP tools: complete read views (list/get/evidence) plus the
// confirmed, attributed write surface (manual reassessment, judgment
// recording). Envelope and semantic-profile tools live in their own files;
// all eleven Situation-mode tools register together, gated on
// Config.SituationCommands so serve never wires a partial Situation stream
// ahead of Task 13's cutover.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// SituationCommands is the narrow, confirmed-write command surface every
// Situation-mutating MCP tool goes through. Every write is additive local
// AlertINT state, explicitly confirmed and attributed — never a write
// toward an operated system. cmd/alertint wiring (Task 13) supplies the
// concrete implementation: Reassess composes the Situation controller;
// RecordJudgment/ConfirmEnvelope/RevokeEnvelope compose the store's
// policy writes; CorrectSemanticProfile composes the semantic-profile
// service. Every audit row carries authenticated_as=installation_mcp_token
// (the one MCP trust domain) alongside the caller-asserted operator.
type SituationCommands interface {
	// Reassess schedules one elevated manual_reassessment attempt for the
	// named Situation (id or public handle) and bypasses hash reuse once.
	// Repeated requests coalesce; it cannot bypass scope, concurrency,
	// safety floors, connector allowlists, or budgets.
	Reassess(ctx context.Context, situation string) error
	RecordJudgment(ctx context.Context, req model.JudgmentRequest) (*model.Judgment, error)
	ConfirmEnvelope(ctx context.Context, confirmation model.EnvelopeConfirmation) (*model.EnvelopeVersion, error)
	RevokeEnvelope(ctx context.Context, revocation model.EnvelopeRevocation) (*model.EnvelopeVersion, error)
	CorrectSemanticProfile(ctx context.Context, correction semanticprofile.Correction) (*profilemodel.ProfileVersion, error)
}

// -----------------------------------------------------------------------------
// Tool definitions
// -----------------------------------------------------------------------------

func (s *Server) toolSituationList() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_situation_list",
		mcplib.WithDescription("List Situations, most recently updated first. Every Situation is visible — "+
			"including silent ones (never published to Slack) and terminal ones (recovered, closed_unknown)."),
		mcplib.WithInteger("limit", mcplib.Description("Maximum number of Situations to return (1-500, default 200).")),
	)
	return tool, s.handleSituationList
}

func (s *Server) toolSituationGet() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_situation_get",
		mcplib.WithDescription("Get complete detail for one Situation: canonical times, lifecycle/Attention, "+
			"current Assessment, member Incidents with their L1 acute-analysis gate state, facts, limitations, "+
			"observation runs, judgments, envelope evaluations, transition history, notification history, the "+
			"Drill flag, and the linked previous Situation (recurrence across a terminal boundary). A terminal "+
			"Situation's response leads with a terminal status banner."),
		mcplib.WithString("situation", mcplib.Description("Situation id or public handle."), mcplib.Required()),
	)
	return tool, s.handleSituationGet
}

func (s *Server) toolSituationEvidenceGet() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_situation_evidence_get",
		mcplib.WithDescription("Get the Situation's immutable delivery evidence — every accepted source delivery "+
			"across its member Incidents, in the original ledger, not a latest-wins Alert projection."),
		mcplib.WithString("situation", mcplib.Description("Situation id or public handle."), mcplib.Required()),
	)
	return tool, s.handleSituationEvidenceGet
}

func (s *Server) toolSituationReassess() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_situation_reassess",
		mcplib.WithDescription("Request one manual reassessment of a Situation. Schedules one elevated attempt "+
			"and bypasses hash reuse once; it cannot bypass scope, concurrency, safety floors, connector "+
			"allowlists, or budgets. Repeated requests before the reassessment runs coalesce into one attempt."),
		mcplib.WithString("situation", mcplib.Description("Situation id or public handle."), mcplib.Required()),
	)
	return tool, s.handleSituationReassess
}

func (s *Server) toolSituationJudgmentRecord() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_situation_judgment_record",
		mcplib.WithDescription("Record the operator's current judgment of a Situation — expected_this_episode, "+
			"unexpected, or inconclusive — tied to the exact input/fact/symptom/impact view judged. Requires "+
			"explicit confirmation and an asserted operator; steers the existing root, never creates a new one. "+
			"To make this judgment reusable across later Situations, promote it with "+
			"alertint_expected_behavior_confirm."),
		mcplib.WithString("situation", mcplib.Description("Situation id or public handle."), mcplib.Required()),
		mcplib.WithString("judgment", mcplib.Description("expected_this_episode | unexpected | inconclusive"), mcplib.Required()),
		mcplib.WithString("basis", mcplib.Description("operator_knowledge | alertint_evidence"), mcplib.Required()),
		mcplib.WithString("workload", mcplib.Description("Optional free-form workload name this judgment attributes the episode to.")),
		mcplib.WithString("valid_until", mcplib.Description("Optional RFC3339 instant after which this judgment no longer covers the Situation.")),
		mcplib.WithBoolean("operator_confirmed", mcplib.Description("Must be true — explicit human confirmation of this judgment."), mcplib.Required()),
		mcplib.WithString("confirmed_by", mcplib.Description("Asserted operator identity (e.g. a name or handle)."), mcplib.Required()),
	)
	return tool, s.handleSituationJudgmentRecord
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

// resolveSituation loads one Situation by id or public handle, translating
// store.ErrNotFound into a clean tool-error result.
func (s *Server) resolveSituation(ctx context.Context, idOrHandle string) (model.Situation, *mcplib.CallToolResult) {
	if strings.TrimSpace(idOrHandle) == "" {
		return model.Situation{}, errResult("situation is required")
	}
	sit, err := s.st.GetSituation(ctx, idOrHandle)
	if err != nil {
		if err == store.ErrNotFound {
			return model.Situation{}, errResult(fmt.Sprintf("situation %q not found", idOrHandle))
		}
		return model.Situation{}, errResult("failed to get situation: " + err.Error())
	}
	return sit, nil
}

// jsonResult marshals v into a tool result, converting a marshal failure
// into a tool-error result rather than a transport error — the pattern every
// Situation/semantic-profile/expected-behavior/funnel handler shares.
func jsonResult(v any) (*mcplib.CallToolResult, error) {
	result, err := mcplib.NewToolResultJSON(v)
	if err != nil {
		return errResult("failed to serialize result: " + err.Error()), nil
	}
	return result, nil
}

type situationListRow struct {
	ID                  string     `json:"id"`
	PreviousSituationID *string    `json:"previous_situation_id,omitempty"`
	GroupKey            string     `json:"group_key"`
	PublicHandle        *string    `json:"public_handle,omitempty"`
	Title               *string    `json:"title,omitempty"`
	Lifecycle           string     `json:"lifecycle"`
	Attention           string     `json:"attention"`
	OpenedAt            time.Time  `json:"opened_at"`
	EffectiveStartedAt  time.Time  `json:"effective_started_at"`
	NextAssessmentAt    time.Time  `json:"next_assessment_at"`
	TerminalAt          *time.Time `json:"terminal_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func situationListRowFrom(sit model.Situation) situationListRow {
	return situationListRow{
		ID: sit.ID, PreviousSituationID: sit.PreviousSituationID, GroupKey: sit.GroupKey, PublicHandle: sit.PublicHandle,
		Title: sit.Title, Lifecycle: string(sit.Lifecycle), Attention: string(sit.Attention), OpenedAt: sit.OpenedAt,
		EffectiveStartedAt: sit.EffectiveStartedAt, NextAssessmentAt: sit.NextAssessmentAt, TerminalAt: sit.TerminalAt, UpdatedAt: sit.UpdatedAt,
	}
}

func (s *Server) handleSituationList(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := mcplib.ParseInt(req, "limit", 200)
	situations, err := s.st.ListSituations(ctx, limit)
	if err != nil {
		return errResult("failed to list situations: " + err.Error()), nil
	}
	rows := make([]situationListRow, 0, len(situations))
	for _, sit := range situations {
		rows = append(rows, situationListRowFrom(sit))
	}
	return jsonResult(map[string]any{"situations": rows})
}

// terminalBanner renders the leading terminal-status line a terminal
// Situation's alertint_situation_get response begins with.
func terminalBanner(sit model.Situation) string {
	switch sit.Lifecycle {
	case model.LifecycleRecovered:
		return "RECOVERED: this Situation reached a clean, confirmed recovery."
	case model.LifecycleClosedUnknown:
		reason := "unspecified"
		if sit.TerminalReason != nil {
			reason = string(*sit.TerminalReason)
		}
		return fmt.Sprintf("CLOSED WITH UNCERTAINTY: reason=%s — review the evidence below before treating this as resolved.", reason)
	default:
		return ""
	}
}

type situationMemberIncidentRow struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	AlertCount         int    `json:"alert_count"`
	AcuteFindingStatus string `json:"acute_finding_status"`
	AcuteFindingReason string `json:"acute_finding_reason,omitempty"`
	Drill              bool   `json:"drill,omitempty"`
}

type observationRunRow struct {
	ID              string    `json:"id"`
	InputVersion    int       `json:"input_version"`
	Capability      string    `json:"capability"`
	Status          string    `json:"status"`
	ObservedAt      time.Time `json:"observed_at"`
	Freshness       string    `json:"freshness"`
	Truncated       bool      `json:"truncated"`
	Digest          string    `json:"digest"`
	RetryErrorClass string    `json:"retry_error_class,omitempty"`
	TokenCost       int       `json:"token_cost"`
	SourceCallCost  int       `json:"source_call_cost"`
	CreatedAt       time.Time `json:"created_at"`
}

type situationTransitionRow struct {
	AttemptID    string          `json:"attempt_id"`
	Sequence     int             `json:"sequence"`
	InputVersion int             `json:"input_version"`
	Reason       string          `json:"reason,omitempty"`
	Assessment   json.RawMessage `json:"assessment,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (s *Server) handleSituationGet(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	target := mcplib.ParseString(req, "situation", "")
	sit, errRes := s.resolveSituation(ctx, target)
	if errRes != nil {
		return errRes, nil
	}

	members, err := s.st.SituationMemberIncidents(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load member incidents: " + err.Error()), nil
	}
	memberIDs := make([]string, len(members))
	for i, m := range members {
		memberIDs[i] = m.ID
	}
	analysis, err := s.st.AnalysisStates(ctx, memberIDs)
	if err != nil {
		return errResult("failed to load acute-analysis gate state: " + err.Error()), nil
	}
	drills, err := s.st.IncidentDrillFlags(ctx, memberIDs)
	if err != nil {
		return errResult("failed to load drill flags: " + err.Error()), nil
	}
	memberRows := make([]situationMemberIncidentRow, 0, len(members))
	drill := false
	for _, m := range members {
		state := analysis[m.ID]
		if drills[m.ID] {
			drill = true
		}
		memberRows = append(memberRows, situationMemberIncidentRow{
			ID: m.ID, Status: m.Status, AlertCount: m.AlertCount,
			AcuteFindingStatus: string(state.Status), AcuteFindingReason: state.DecisionReason, Drill: drills[m.ID],
		})
	}

	facts, err := s.st.SituationFacts(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load facts: " + err.Error()), nil
	}
	rawRuns, err := s.st.SituationObservationRuns(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load observation runs: " + err.Error()), nil
	}
	runs := make([]observationRunRow, 0, len(rawRuns))
	for _, r := range rawRuns {
		runs = append(runs, observationRunRow{
			ID: r.ID, InputVersion: r.InputVersion, Capability: string(r.Capability), Status: string(r.Status),
			ObservedAt: r.ObservedAt, Freshness: string(r.Freshness), Truncated: r.Truncated, Digest: r.Digest,
			RetryErrorClass: r.RetryErrorClass, TokenCost: r.TokenCost, SourceCallCost: r.SourceCallCost, CreatedAt: r.CreatedAt,
		})
	}
	judgments, err := s.st.SituationJudgments(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load judgments: " + err.Error()), nil
	}
	evaluations, err := s.st.SituationEnvelopeEvaluations(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load envelope evaluations: " + err.Error()), nil
	}
	notifications, err := s.st.SituationNotifications(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load notifications: " + err.Error()), nil
	}
	attempts, err := s.st.SituationAssessmentAttempts(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load assessment attempts: " + err.Error()), nil
	}

	var transitions []situationTransitionRow
	var currentAssessment json.RawMessage
	for _, a := range attempts {
		if a.Status != store.AssessmentStatusAuthoritative {
			continue
		}
		transitions = append(transitions, situationTransitionRow{
			AttemptID: a.ID, Sequence: a.Sequence, InputVersion: a.InputVersion,
			Reason: strings.Join(a.TriggerReasons, ","), Assessment: a.Validated, CreatedAt: a.CreatedAt,
		})
		if sit.CurrentAssessmentID != nil && a.ID == *sit.CurrentAssessmentID {
			currentAssessment = a.Validated
		}
	}

	var previous map[string]any
	if sit.PreviousSituationID != nil {
		if prior, err := s.st.GetSituation(ctx, *sit.PreviousSituationID); err == nil {
			previous = map[string]any{"id": prior.ID, "public_handle": prior.PublicHandle, "lifecycle": prior.Lifecycle}
		}
	}

	payload := map[string]any{
		"terminal_banner":            terminalBanner(sit),
		"id":                         sit.ID,
		"previous_situation":         previous,
		"group_key":                  sit.GroupKey,
		"public_handle":              sit.PublicHandle,
		"title":                      sit.Title,
		"lifecycle":                  sit.Lifecycle,
		"attention":                  sit.Attention,
		"opened_at":                  sit.OpenedAt,
		"effective_started_at":       sit.EffectiveStartedAt,
		"effective_started_at_basis": sit.EffectiveStartedAtBasis,
		"first_received_at":          sit.FirstReceivedAt,
		"recovery_observed_at":       sit.RecoveryObservedAt,
		"grace_until":                sit.GraceUntil,
		"terminal_at":                sit.TerminalAt,
		"terminal_reason":            sit.TerminalReason,
		"next_assessment_at":         sit.NextAssessmentAt,
		"current_assessment":         currentAssessment,
		"drill":                      drill,
		"incidents":                  memberRows,
		"facts":                      facts,
		"observation_runs":           runs,
		"judgments":                  judgments,
		"envelope_evaluations":       evaluations,
		"transitions":                transitions,
		"notifications":              notifications,
	}
	return jsonResult(payload)
}

func (s *Server) handleSituationEvidenceGet(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	target := mcplib.ParseString(req, "situation", "")
	sit, errRes := s.resolveSituation(ctx, target)
	if errRes != nil {
		return errRes, nil
	}
	deliveries, err := s.st.SituationDeliveries(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load situation evidence: " + err.Error()), nil
	}
	type deliveryRow struct {
		ID               string            `json:"id"`
		Source           string            `json:"source"`
		SourceEpisodeKey string            `json:"source_episode_key"`
		Status           string            `json:"status"`
		Labels           map[string]string `json:"labels"`
		Annotations      map[string]string `json:"annotations"`
		StartsAt         time.Time         `json:"starts_at"`
		EndsAt           *time.Time        `json:"ends_at,omitempty"`
		SourceStartedAt  *time.Time        `json:"source_started_at,omitempty"`
		SourceResolvedAt *time.Time        `json:"source_resolved_at,omitempty"`
		StartedAtBasis   string            `json:"started_at_basis"`
		ResolvedAtBasis  string            `json:"resolved_at_basis"`
		ReceivedAt       time.Time         `json:"received_at"`
	}
	rows := make([]deliveryRow, 0, len(deliveries))
	for _, d := range deliveries {
		rows = append(rows, deliveryRow{
			ID: d.ID, Source: d.Source, SourceEpisodeKey: d.SourceEpisodeKey, Status: d.Alert.Status,
			Labels: d.Alert.Labels, Annotations: d.Alert.Annotations, StartsAt: d.Alert.StartsAt, EndsAt: d.Alert.EndsAt,
			SourceStartedAt: d.SourceStartedAt, SourceResolvedAt: d.SourceResolvedAt,
			StartedAtBasis: string(d.StartedAtBasis), ResolvedAtBasis: string(d.ResolvedAtBasis), ReceivedAt: d.ReceivedAt,
		})
	}
	return jsonResult(map[string]any{"situation_id": sit.ID, "deliveries": rows})
}

func (s *Server) handleSituationReassess(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.SituationCommands == nil {
		return errResult("situation commands are unavailable"), nil
	}
	target := mcplib.ParseString(req, "situation", "")
	if strings.TrimSpace(target) == "" {
		return errResult("situation is required"), nil
	}
	if err := s.cfg.SituationCommands.Reassess(ctx, target); err != nil {
		return errResult("failed to schedule reassessment: " + err.Error()), nil
	}
	return jsonResult(map[string]any{"situation": target, "scheduled": true})
}

func (s *Server) handleSituationJudgmentRecord(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.SituationCommands == nil {
		return errResult("situation commands are unavailable"), nil
	}
	jr := model.JudgmentRequest{
		Situation:         mcplib.ParseString(req, "situation", ""),
		Judgment:          model.JudgmentKind(mcplib.ParseString(req, "judgment", "")),
		Basis:             model.JudgmentBasis(mcplib.ParseString(req, "basis", "")),
		OperatorConfirmed: mcplib.ParseBoolean(req, "operator_confirmed", false),
		ConfirmedBy:       mcplib.ParseString(req, "confirmed_by", ""),
	}
	if strings.TrimSpace(jr.Situation) == "" {
		return errResult("situation is required"), nil
	}
	if workload := mcplib.ParseString(req, "workload", ""); workload != "" {
		jr.Workload = &workload
	}
	if raw := mcplib.ParseString(req, "valid_until", ""); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return errResult("invalid valid_until: must be RFC3339"), nil
		}
		t = t.UTC()
		jr.ValidUntil = &t
	}
	j, err := s.cfg.SituationCommands.RecordJudgment(ctx, jr)
	if err != nil {
		return errResult("failed to record judgment: " + err.Error()), nil
	}
	return jsonResult(j)
}
