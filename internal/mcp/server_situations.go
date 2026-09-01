// SPDX-License-Identifier: FSL-1.1-ALv2

// The two read-only Situation views (Task 9): alertint_list_situations and
// alertint_get_situation. Both expose exactly the durable foundation state
// Tasks 1-8 built — one Situation per exact group, its lifecycle/attention/
// scheduling fields, and its immutable member Incidents. Neither tool
// creates a judgment, note, verdict, envelope, Assessment, or reassessment
// request, and neither is reachable from any write path: assessment and
// operator_contract are always explicit JSON null in this build, because no
// Situation controller or operator-artifact surface exists yet. Both are
// always registered when MCP is enabled — unlike the source tools in
// server.go, there is no connector to gate them on.

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
			"the exact-group lineage that durably owns one or more Incidents — the foundation this build "+
			"exposes. There is no controller yet: no Situation here has an Assessment, an operator "+
			"contract, or a Slack presence."),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of situations to return (1-100, default 20)."),
		),
	)
	return tool, s.handleListSituations
}

func (s *Server) toolGetSituation() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_situation",
		mcplib.WithDescription("Get one Situation by id or public handle, with its immutable member "+
			"Incidents. assessment and operator_contract are always null in this build: no Situation "+
			"controller exists yet to produce either."),
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

// situationIncidentRow is one member Incident's identity and status, in
// attachment order — exactly what alertint_get_situation's "incidents"
// array carries; a caller wanting full Incident detail follows up with
// alertint_get_incident.
type situationIncidentRow struct {
	ID     string `json:"id"`
	Status string `json:"status"`
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
	incidentRows := make([]situationIncidentRow, 0, len(members))
	for _, m := range members {
		incidentRows = append(incidentRows, situationIncidentRow{ID: m.IncidentID, Status: m.Status})
	}

	// assessment and operator_contract are plain map entries (not struct
	// fields with omitempty) precisely so a nil Go value still renders as
	// JSON null instead of being dropped — the two explicit nulls this
	// task's plan calls out by name.
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
		"assessment":            nil,
		"operator_contract":     nil,
	}

	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize situation: " + err.Error()), nil
	}
	return result, nil
}
