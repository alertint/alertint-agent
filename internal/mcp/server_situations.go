// SPDX-License-Identifier: FSL-1.1-ALv2

// The two read-only Situation views: alertint_list_situations (Task 3) and
// alertint_get_situation (Task 3, extended by Task 9). Both expose exactly
// the durable foundation and controller state Tasks 1-9 built — one
// Situation per exact group, its lifecycle/attention/scheduling fields, its
// immutable member Incidents, and (Task 9) the current authoritative
// Assessment/derivation, current Operator contract, material/basis hashes,
// up to 20 bounded sanitized recent Assessment attempts, per-Incident
// Triage decision/phase/attempts/due/digests, and controller retry/park
// state. Neither tool creates a judgment, note, verdict, envelope,
// Assessment, or reassessment request, and neither is reachable from any
// write path: no rejected free-form proposal text, raw prompt/response,
// provider error body, secret, SQL text, or unbounded fact history is ever
// returned. A Situation with no controller cycle run against it yet
// legitimately renders assessment/operator_contract/hashes as explicit JSON
// null and recent_attempts as an empty array — not an error, just "no
// controller state exists yet for this Situation." Both tools are always
// registered when MCP is enabled — unlike the source tools in server.go,
// there is no connector to gate them on.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func (s *Server) toolListSituations() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_list_situations",
		mcplib.WithDescription("List durable Situations, most recently updated first. A Situation is "+
			"the exact-group lineage that durably owns one or more Incidents. This is a bounded summary — "+
			"lifecycle/attention/scheduling fields and due reasons only, no Assessment or controller "+
			"detail (use alertint_get_situation for that) and no Slack presence."),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of situations to return (1-100, default 20)."),
		),
	)
	return tool, s.handleListSituations
}

func (s *Server) toolGetSituation() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_situation",
		mcplib.WithDescription("Get one Situation by id or public handle: its immutable member Incidents "+
			"(with each one's current Triage decision/phase/attempts/due time/covered digests), current "+
			"authoritative Assessment and derivation, current Operator contract, material/Assessment-basis "+
			"hashes, up to 20 bounded sanitized recent Assessment attempts, and controller retry/park "+
			"state. assessment/operator_contract/hashes render as explicit null, and recent_attempts as "+
			"an empty array, for a Situation no controller cycle has run against yet. Never returns a "+
			"rejected proposal, raw prompt/response, provider error body, or SQL text."),
		mcplib.WithString("id",
			mcplib.Description("Situation ID (from alertint_list_situations). Exactly one of id/handle is required."),
		),
		mcplib.WithString("handle",
			mcplib.Description("Situation public handle. Exactly one of id/handle is required."),
		),
	)
	return tool, s.handleGetSituation
}

// situationListRow is one row of alertint_list_situations' output — the
// Situation's identity, lifecycle/attention/scheduling state, and due
// reasons, without its member Incidents (a per-row Incident fetch would
// turn a bounded list into an N+1 query; alertint_get_situation carries
// that detail instead).
type situationListRow struct {
	ID                  string                     `json:"id"`
	PreviousSituationID *string                    `json:"previous_situation_id"`
	PublicHandle        *string                    `json:"public_handle"`
	GroupKey            string                     `json:"group_key"`
	Lifecycle           string                     `json:"lifecycle"`
	Attention           string                     `json:"attention"`
	InputVersion        int                        `json:"input_version"`
	DueReasons          []situationmodel.DueReason `json:"due_reasons"`
	OpenedAt            time.Time                  `json:"opened_at"`
	EffectiveStartedAt  time.Time                  `json:"effective_started_at"`
	FirstReceivedAt     time.Time                  `json:"first_received_at"`
	NextAssessmentAt    time.Time                  `json:"next_assessment_at"`
}

func situationListRowFrom(sit situationmodel.Situation) situationListRow {
	return situationListRow{
		ID:                  sit.ID,
		PreviousSituationID: sit.PreviousSituationID,
		PublicHandle:        sit.PublicHandle,
		GroupKey:            sit.GroupKey,
		Lifecycle:           string(sit.Lifecycle),
		Attention:           string(sit.Attention),
		InputVersion:        sit.InputVersion,
		DueReasons:          sit.DueReasons,
		OpenedAt:            sit.OpenedAt,
		EffectiveStartedAt:  sit.EffectiveStartedAt,
		FirstReceivedAt:     sit.FirstReceivedAt,
		NextAssessmentAt:    sit.NextAssessmentAt,
	}
}

func (s *Server) handleListSituations(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := mcplib.ParseInt(req, "limit", 20)
	if limit < 1 {
		limit = 20
	}

	sits, err := s.st.ListSituations(ctx, limit)
	if err != nil {
		return errResult("failed to list situations"), nil
	}

	rows := make([]situationListRow, 0, len(sits))
	for _, sit := range sits {
		rows = append(rows, situationListRowFrom(sit))
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"situations": rows})
	if err != nil {
		return errResult("failed to serialize situations: " + err.Error()), nil
	}
	return result, nil
}

// situationIncidentRow is one member Incident's identity, status, and
// bounded current Triage state — decision, phase, attempts, due time, and
// the covered digests the decision was made against (Task 9's MCP brief:
// "Incident Triage decision, phase, attempts, due time, and covered
// digests") — in attachment order. A caller wanting full Incident detail
// (Finding prose, alerts) follows up with alertint_get_incident.
type situationIncidentRow struct {
	ID                  string     `json:"id"`
	Status              string     `json:"status"`
	TriagePhase         string     `json:"triage_phase"`
	TriageDecision      *string    `json:"triage_decision"`
	TriageAttempts      int        `json:"triage_attempts"`
	TriageDueAt         *time.Time `json:"triage_due_at"`
	MembershipDigest    *string    `json:"membership_digest"`
	IncidentInputDigest *string    `json:"incident_input_digest"`
}

// sanitizedAssessmentAttemptRow is one bounded, sanitized entry in
// alertint_get_situation's "recent_attempts" array (Task 9's MCP brief:
// "bounded recent Assessment attempts with sanitized status/error codes") —
// the exact JSON-facing shape of store.SanitizedAssessmentAttempt. It never
// carries a raw proposal, validated content, or a provider response body —
// only the bounded typed identity/status/error-code columns
// GetSituationControllerView itself already sanitizes at the Store
// boundary.
type sanitizedAssessmentAttemptRow struct {
	ID                     string                                `json:"id"`
	Sequence               int                                   `json:"sequence"`
	InputVersion           int                                   `json:"input_version"`
	RetryEpoch             int                                   `json:"retry_epoch"`
	WorkAttempt            int                                   `json:"work_attempt"`
	Status                 string                                `json:"status"`
	Derivation             *situationmodel.AssessmentDerivation  `json:"derivation"`
	ProviderRequestStarted situationmodel.ProviderRequestStarted `json:"provider_request_started"`
	ValidationErrorCodes   []string                              `json:"validation_error_codes"`
	CreatedAt              time.Time                             `json:"created_at"`
	CompletedAt            time.Time                             `json:"completed_at"`
}

func sanitizedAssessmentAttemptRowFrom(a store.SanitizedAssessmentAttempt) sanitizedAssessmentAttemptRow {
	return sanitizedAssessmentAttemptRow{
		ID: a.ID, Sequence: a.Sequence, InputVersion: a.InputVersion, RetryEpoch: a.RetryEpoch,
		WorkAttempt: a.WorkAttempt, Status: a.Status, Derivation: a.Derivation,
		ProviderRequestStarted: a.ProviderRequestStarted, ValidationErrorCodes: a.ValidationErrorCodes,
		CreatedAt: a.CreatedAt, CompletedAt: a.CompletedAt,
	}
}

// controllerStateRow is alertint_get_situation's "controller_state" object —
// Task 9's MCP brief: "controller retry/park state" — read straight off
// store.ControllerRetryState.
type controllerStateRow struct {
	RetryEpoch     int        `json:"retry_epoch"`
	WorkAttempts   int        `json:"work_attempts"`
	ParkedAt       *time.Time `json:"parked_at"`
	ParkedReason   *string    `json:"parked_reason"`
	RetryAt        *time.Time `json:"retry_at"`
	LastErrorClass *string    `json:"last_error_class"`
}

func controllerStateRowFrom(r store.ControllerRetryState) controllerStateRow {
	return controllerStateRow{
		RetryEpoch: r.RetryEpoch, WorkAttempts: r.WorkAttempts, ParkedAt: r.ParkedAt,
		ParkedReason: r.ParkedReason, RetryAt: r.RetryAt, LastErrorClass: r.LastErrorClass,
	}
}

// handleGetSituation resolves a Situation by exactly one of id/handle and
// renders the exact response shape Step 1 of this task's plan specifies,
// including the two explicit nulls (assessment, operator_contract) that
// make the foundation honest: neither exists until a later plan builds the
// Situation controller and its operator surface. Every failure path returns
// a fixed, generic message — never a wrapped store/SQL error — so a lookup
// failure can never leak driver or query text to an MCP client.
func (s *Server) handleGetSituation(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := mcplib.ParseString(req, "id", "")
	handle := mcplib.ParseString(req, "handle", "")
	if (id == "") == (handle == "") {
		return errResult("exactly one of id or handle is required"), nil
	}

	var (
		sit situationmodel.Situation
		err error
	)
	if id != "" {
		sit, err = s.st.GetSituation(ctx, id)
	} else {
		sit, err = s.st.GetSituationByHandle(ctx, handle)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if id != "" {
				return errResult(fmt.Sprintf("situation %q not found", id)), nil
			}
			return errResult(fmt.Sprintf("situation with handle %q not found", handle)), nil
		}
		return errResult("failed to get situation"), nil
	}

	members, err := s.st.ListSituationIncidents(ctx, sit.ID)
	if err != nil {
		return errResult("failed to get situation incidents"), nil
	}

	// view carries the bounded controller-derived state Task 9 adds:
	// current authoritative Assessment/derivation, current Operator
	// contract, material/basis hashes, up to 20 sanitized recent attempts,
	// per-Incident Triage state, and controller retry/park state. A
	// never-reconciled Situation (no controller cycle has run against it
	// yet) legitimately renders every one of these as null/empty — the
	// same "no controller state yet" honesty the original two explicit
	// nulls documented, now backed by real controller state once it exists.
	view, err := s.st.GetSituationControllerView(ctx, sit.ID)
	if err != nil {
		return errResult("failed to get situation controller state"), nil
	}

	triageByIncident := make(map[string]store.IncidentTriageView, len(view.Triage))
	for _, tv := range view.Triage {
		triageByIncident[tv.IncidentID] = tv
	}
	incidentRows := make([]situationIncidentRow, 0, len(members))
	for _, m := range members {
		row := situationIncidentRow{ID: m.IncidentID, Status: m.Status}
		if tv, ok := triageByIncident[m.IncidentID]; ok {
			row.TriagePhase = tv.Phase
			row.TriageDecision = tv.Decision
			row.TriageAttempts = tv.Attempts
			row.TriageDueAt = tv.NextAt
			row.MembershipDigest = tv.MembershipDigest
			row.IncidentInputDigest = tv.IncidentInputDigest
		}
		incidentRows = append(incidentRows, row)
	}

	attemptRows := make([]sanitizedAssessmentAttemptRow, 0, len(view.RecentAttempts))
	for _, a := range view.RecentAttempts {
		attemptRows = append(attemptRows, sanitizedAssessmentAttemptRowFrom(a))
	}

	// assessment, assessment_derivation, and operator_contract are plain map
	// entries (not struct fields with omitempty) precisely so a nil Go value
	// still renders as JSON null instead of being dropped — never a
	// rejected proposal, raw prompt/response, or provider error body (Task
	// 9's own MCP brief).
	payload := map[string]any{
		"id":                    sit.ID,
		"previous_situation_id": sit.PreviousSituationID,
		"public_handle":         sit.PublicHandle,
		"group_key":             sit.GroupKey,
		"lifecycle":             string(sit.Lifecycle),
		"attention":             string(sit.Attention),
		"input_version":         sit.InputVersion,
		"due_reasons":           sit.DueReasons,
		"opened_at":             sit.OpenedAt,
		"effective_started_at":  sit.EffectiveStartedAt,
		"first_received_at":     sit.FirstReceivedAt,
		"next_assessment_at":    sit.NextAssessmentAt,
		"incidents":             incidentRows,
		"assessment":            view.CurrentAssessment,
		"assessment_derivation": view.CurrentDerivation,
		"operator_contract":     view.CurrentActionContract,
		"material_fact_hash":    view.CurrentMaterialFactHash,
		"assessment_basis_hash": view.CurrentAssessmentBasisHash,
		"recent_attempts":       attemptRows,
		"controller_state":      controllerStateRowFrom(view.Retry),
	}

	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize situation: " + err.Error()), nil
	}
	return result, nil
}
