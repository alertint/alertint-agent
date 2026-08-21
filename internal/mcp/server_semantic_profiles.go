// SPDX-License-Identifier: FSL-1.1-ALv2

// Semantic-profile MCP tools: the advisory L0 profile read (by signature or
// by Situation evidence) and the confirmed, versioned correction write.
// Profiles never carry Attention, membership, or notification authority —
// they only ever widen what the controller considers (package boundary,
// spec "Architecture and authority").

package mcp

import (
	"context"
	"encoding/json"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func (s *Server) toolSemanticProfileGet() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_semantic_profile_get",
		mcplib.WithDescription("Get the advisory L0 semantic profile history for a source signature — the "+
			"immutable version history plus the current head. Resolve either by an exact signature or by a "+
			"Situation (every distinct signature among its member deliveries)."),
		mcplib.WithString("signature", mcplib.Description("Exact profile signature (mutually exclusive with situation).")),
		mcplib.WithString("situation", mcplib.Description("Situation id or public handle (mutually exclusive with signature).")),
	)
	return tool, s.handleSemanticProfileGet
}

func (s *Server) toolSemanticProfileCorrect() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_semantic_profile_correct",
		mcplib.WithDescription("Append an operator-confirmed replacement semantic profile version at an exact "+
			"expected head version (optimistic concurrency). The profile JSON must contain exactly the profile "+
			"schema — free text never creates or modifies policy. Requires explicit confirmation and an "+
			"asserted operator."),
		mcplib.WithString("signature", mcplib.Description("Exact profile signature to correct."), mcplib.Required()),
		mcplib.WithNumber("expected_version", mcplib.Description("The signature's current head version, for optimistic concurrency."), mcplib.Required()),
		mcplib.WithObject("profile", mcplib.Description("Replacement profile — exactly the L0 profile schema fields."), mcplib.Required()),
		mcplib.WithBoolean("confirmed", mcplib.Description("Must be true — explicit human confirmation of this correction."), mcplib.Required()),
		mcplib.WithString("confirmed_by", mcplib.Description("Asserted operator identity (e.g. a name or handle)."), mcplib.Required()),
	)
	return tool, s.handleSemanticProfileCorrect
}

func (s *Server) handleSemanticProfileGet(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	signature := mcplib.ParseString(req, "signature", "")
	situation := mcplib.ParseString(req, "situation", "")
	if signature == "" && situation == "" {
		return errResult("one of signature or situation is required"), nil
	}

	if signature != "" {
		history, err := s.st.SemanticProfile(ctx, signature)
		if err != nil {
			if err == store.ErrNotFound {
				return errResult("no semantic profile found for that signature"), nil
			}
			return errResult("failed to get semantic profile: " + err.Error()), nil
		}
		return jsonResult(map[string]any{"profiles": map[string]*profilemodel.History{signature: history}})
	}

	sit, errRes := s.resolveSituation(ctx, situation)
	if errRes != nil {
		return errRes, nil
	}
	deliveries, err := s.st.SituationDeliveries(ctx, sit.ID)
	if err != nil {
		return errResult("failed to load situation evidence: " + err.Error()), nil
	}
	profiles := map[string]*profilemodel.History{}
	for _, d := range deliveries {
		sig := semanticprofile.Signature(d)
		if _, ok := profiles[sig]; ok {
			continue
		}
		history, err := s.st.SemanticProfile(ctx, sig)
		if err != nil {
			if err == store.ErrNotFound {
				continue
			}
			return errResult("failed to get semantic profile: " + err.Error()), nil
		}
		profiles[sig] = history
	}
	return jsonResult(map[string]any{"situation_id": sit.ID, "profiles": profiles})
}

func (s *Server) handleSemanticProfileCorrect(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	if s.cfg.SituationCommands == nil {
		return errResult("situation commands are unavailable"), nil
	}
	signature := mcplib.ParseString(req, "signature", "")
	if signature == "" {
		return errResult("signature is required"), nil
	}
	raw := mcplib.ParseArgument(req, "profile", nil)
	if raw == nil {
		return errResult("profile is required"), nil
	}
	profileJSON, err := json.Marshal(raw)
	if err != nil {
		return errResult("profile must be a JSON object"), nil
	}
	correction := semanticprofile.Correction{
		Signature:       signature,
		ExpectedVersion: mcplib.ParseInt(req, "expected_version", -1),
		Raw:             profileJSON,
		Confirmed:       mcplib.ParseBoolean(req, "confirmed", false),
		ConfirmedBy:     mcplib.ParseString(req, "confirmed_by", ""),
	}
	if correction.ExpectedVersion < 0 {
		return errResult("expected_version is required"), nil
	}
	v, err := s.cfg.SituationCommands.CorrectSemanticProfile(ctx, correction)
	if err != nil {
		return errResult("failed to correct semantic profile: " + err.Error()), nil
	}
	return jsonResult(v)
}
