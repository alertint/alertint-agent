// SPDX-License-Identifier: FSL-1.1-ALv2

// Plan 4 Task 9: the three durable, read-mostly Task 6-8 evidence-
// preparation/semantic-profile views spec.md names — alertint_list_
// observation_runs, alertint_get_semantic_profile, and
// alertint_correct_semantic_profile (the ONLY new write path this plan
// adds, mirroring server_feedback.go's own two write tools: additive,
// audit-chained, and nowhere else reachable). All three are always
// registered when MCP is enabled — like the Situation foundation tools in
// server_situations.go, there is no connector to gate them on: preparation/
// profile state exists (possibly empty) regardless of which source
// connectors are configured. None of them exposes a raw prompt/response,
// provider error body, SQL text, claim owner/token, or lease.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// ----------------------------------------------------------------------
// alertint_list_observation_runs
// ----------------------------------------------------------------------

func (s *Server) toolListObservationRuns() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_list_observation_runs",
		mcplib.WithDescription("Page one Situation's bounded evidence-preparation runs, oldest first: each "+
			"capability read's immutable result status, coverage, and normalized facts (or an explicit "+
			"detail_state=\"expired\" once its 10-day unused-detail retention window has passed — never a "+
			"fabricated or reconstructed value). Page with the returned next_cursor. Never returns a raw "+
			"connector request, provider response, or claim owner/token."),
		mcplib.WithString("id", mcplib.Description("Situation ID. Exactly one of id/handle is required.")),
		mcplib.WithString("handle", mcplib.Description("Situation public handle. Exactly one of id/handle is required.")),
		mcplib.WithString("cycle_id", mcplib.Description("Optional: restrict to one preparation cycle's runs.")),
		mcplib.WithInteger("limit", mcplib.Description("Maximum runs to return (1-100, default 20).")),
		mcplib.WithString("cursor", mcplib.Description("Resume from the previous page's next_cursor.")),
	)
	return tool, s.handleListObservationRuns
}

// observationCoverageRow/observationFactRow/observationRunRow render
// observationmodel.RunRecord with the same snake_case JSON convention every
// other tool in this package uses — the model package's own struct fields
// carry no JSON tags (internal/observation/model deliberately stays
// transport-neutral).
type observationCoverageRow struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Complete bool      `json:"complete"`
	Returned int       `json:"returned"`
	Omitted  int       `json:"omitted"`
}

type observationFactRow struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Subject       string          `json:"subject"`
	Digest        string          `json:"digest"`
	SchemaVersion int             `json:"schema_version"`
	Value         json.RawMessage `json:"value"`
	ResultStatus  string          `json:"result_status"`
	Freshness     string          `json:"freshness"`
	ObservedAt    time.Time       `json:"observed_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	EvidenceRefs  []string        `json:"evidence_refs"`
	Material      bool            `json:"material"`
}

type observationRunRow struct {
	ID              string                 `json:"id"`
	CycleID         string                 `json:"cycle_id"`
	PlanID          string                 `json:"plan_id"`
	Status          string                 `json:"status"`
	Coverage        observationCoverageRow `json:"coverage"`
	Facts           []observationFactRow   `json:"facts"`
	LimitationCodes []string               `json:"limitation_codes"`
	ObservedAt      time.Time              `json:"observed_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	CompletedAt     time.Time              `json:"completed_at"`
	ReusedFromRunID *string                `json:"reused_from_run_id"`
	DetailState     string                 `json:"detail_state"`
	DetailExpiredAt *time.Time             `json:"detail_expired_at"`
}

func observationRunRowFrom(rec observationmodel.RunRecord) observationRunRow {
	run := rec.Run
	facts := make([]observationFactRow, 0, len(run.Facts))
	for _, f := range run.Facts {
		facts = append(facts, observationFactRow{
			ID: f.ID, Kind: f.Kind, Subject: f.Subject, Digest: f.Digest, SchemaVersion: f.SchemaVersion,
			Value: f.Value, ResultStatus: string(f.ResultStatus), Freshness: string(f.Freshness),
			ObservedAt: f.ObservedAt, ExpiresAt: f.ExpiresAt, EvidenceRefs: f.EvidenceRefs, Material: f.Material,
		})
	}
	codes := run.LimitationCodes
	if codes == nil {
		codes = []string{}
	}
	return observationRunRow{
		ID: run.ID, CycleID: run.CycleID, PlanID: run.PlanID, Status: string(run.Status),
		Coverage: observationCoverageRow{
			Start: run.Coverage.Start, End: run.Coverage.End, Complete: run.Coverage.Complete,
			Returned: run.Coverage.Returned, Omitted: run.Coverage.Omitted,
		},
		Facts: facts, LimitationCodes: codes, ObservedAt: run.ObservedAt, ExpiresAt: run.ExpiresAt,
		CompletedAt: run.CompletedAt, ReusedFromRunID: run.ReusedFromRunID,
		DetailState: rec.DetailState, DetailExpiredAt: rec.DetailExpiredAt,
	}
}

func (s *Server) handleListObservationRuns(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sit, failed := s.resolveSituation(ctx, req)
	if failed != nil {
		return failed, nil
	}
	cycleID := mcplib.ParseString(req, "cycle_id", "")
	limit := mcplib.ParseInt(req, "limit", 20)
	cursor := mcplib.ParseString(req, "cursor", "")

	records, nextCursor, err := s.st.ListObservationRuns(ctx, sit.ID, cycleID, cursor, limit)
	if err != nil {
		return errResult("failed to list observation runs"), nil
	}
	rows := make([]observationRunRow, 0, len(records))
	for _, rec := range records {
		rows = append(rows, observationRunRowFrom(rec))
	}
	payload := map[string]any{"situation_id": sit.ID, "runs": rows, "next_cursor": nil}
	if nextCursor != "" {
		payload["next_cursor"] = nextCursor
	}
	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize observation runs: " + err.Error()), nil
	}
	return result, nil
}

// ----------------------------------------------------------------------
// alertint_get_semantic_profile
// ----------------------------------------------------------------------

func (s *Server) toolGetSemanticProfile() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_semantic_profile",
		mcplib.WithDescription("Get one or more advisory semantic profiles: current head, a bounded page of "+
			"immutable version history (newest first — model inferences and operator corrections alike), and "+
			"the current live inference job state, if any. Pass exactly one of signature (from a Situation's "+
			"evidence references) or a Situation (id/handle) — a Situation may resolve to more than one "+
			"distinct signature when its deliveries span sources with different proven identity. Advisory "+
			"content never asserts source state or bypasses proven identity."),
		mcplib.WithString("signature", mcplib.Description("Advisory signature key. Exactly one of signature or id/handle is required.")),
		mcplib.WithString("id", mcplib.Description("Situation ID. Exactly one of signature or id/handle is required.")),
		mcplib.WithString("handle", mcplib.Description("Situation public handle. Exactly one of signature or id/handle is required.")),
		mcplib.WithInteger("limit", mcplib.Description("Maximum version-history entries per signature (1-100, default 20).")),
		mcplib.WithString("cursor", mcplib.Description("Resume one signature's version history from a previous next_cursor.")),
	)
	return tool, s.handleGetSemanticProfile
}

type semanticProfileVersionRow struct {
	ID                  string               `json:"id"`
	Version             int                  `json:"version"`
	SchemaVersion       int                  `json:"schema_version"`
	PromptVersion       int                  `json:"prompt_version"`
	SemanticInputDigest string               `json:"semantic_input_digest"`
	Origin              string               `json:"origin"`
	Provider            string               `json:"provider,omitempty"`
	Model               string               `json:"model,omitempty"`
	UsageInputTokens    int                  `json:"usage_input_tokens"`
	UsageOutputTokens   int                  `json:"usage_output_tokens"`
	Profile             profilemodel.Profile `json:"profile"`
	CreatedAt           time.Time            `json:"created_at"`
	AssertedBy          string               `json:"asserted_by,omitempty"`
}

func semanticProfileVersionRowFrom(v profilemodel.Version) semanticProfileVersionRow {
	return semanticProfileVersionRow{
		ID: v.ID, Version: v.Version, SchemaVersion: v.SchemaVersion, PromptVersion: v.PromptVersion,
		SemanticInputDigest: v.SemanticInputDigest, Origin: v.Origin, Provider: v.Provider, Model: v.Model,
		UsageInputTokens: v.UsageInputTokens, UsageOutputTokens: v.UsageOutputTokens, Profile: v.Profile,
		CreatedAt: v.CreatedAt, AssertedBy: v.AssertedBy,
	}
}

type semanticProfileJobRow struct {
	Status     string     `json:"status"`
	Attempt    int        `json:"attempt"`
	RetryAt    *time.Time `json:"retry_at"`
	ErrorClass *string    `json:"error_class"`
}

type semanticProfileHistoryRow struct {
	Signature  string                      `json:"signature"`
	Current    *semanticProfileVersionRow  `json:"current"`
	Versions   []semanticProfileVersionRow `json:"versions"`
	Job        *semanticProfileJobRow      `json:"job"`
	NextCursor string                      `json:"next_cursor,omitempty"`
}

func semanticProfileHistoryRowFrom(signature string, h profilemodel.History) semanticProfileHistoryRow {
	row := semanticProfileHistoryRow{Signature: signature, NextCursor: h.NextCursor}
	if h.Current != nil {
		cur := semanticProfileVersionRowFrom(*h.Current)
		row.Current = &cur
	}
	row.Versions = make([]semanticProfileVersionRow, 0, len(h.Versions))
	for _, v := range h.Versions {
		row.Versions = append(row.Versions, semanticProfileVersionRowFrom(v))
	}
	if h.Job != nil {
		row.Job = &semanticProfileJobRow{Status: h.Job.Status, Attempt: h.Job.Attempt, RetryAt: h.Job.RetryAt, ErrorClass: h.Job.ErrorClass}
	}
	return row
}

func (s *Server) handleGetSemanticProfile(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	signature := mcplib.ParseString(req, "signature", "")
	id := mcplib.ParseString(req, "id", "")
	handle := mcplib.ParseString(req, "handle", "")
	hasSituationRef := id != "" || handle != ""
	if (signature != "") == hasSituationRef {
		return errResult("exactly one of signature or a situation (id/handle) is required"), nil
	}

	limit := mcplib.ParseInt(req, "limit", 20)
	cursor := mcplib.ParseString(req, "cursor", "")

	var signatures []string
	if signature != "" {
		signatures = []string{signature}
	} else {
		sit, failed := s.resolveSituation(ctx, req)
		if failed != nil {
			return failed, nil
		}
		keys, err := s.st.ListSituationSemanticSignatures(ctx, sit.ID)
		if err != nil {
			return errResult("failed to list situation semantic signatures"), nil
		}
		signatures = keys
	}

	profiles := make([]semanticProfileHistoryRow, 0, len(signatures))
	for _, key := range signatures {
		history, err := s.st.GetSemanticProfile(ctx, key, cursor, limit)
		if err != nil {
			return errResult("failed to get semantic profile"), nil
		}
		profiles = append(profiles, semanticProfileHistoryRowFrom(key, history))
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"profiles": profiles})
	if err != nil {
		return errResult("failed to serialize semantic profile: " + err.Error()), nil
	}
	return result, nil
}

// ----------------------------------------------------------------------
// alertint_correct_semantic_profile — the only write this plan adds
// ----------------------------------------------------------------------

func (s *Server) toolCorrectSemanticProfile() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_correct_semantic_profile",
		mcplib.WithDescription("Record an operator-confirmed correction to one advisory semantic profile — "+
			"always append-only: creates a new immutable version and advances the head, atomically enqueuing "+
			"its change for fan-out to every matching nonterminal Situation. NEVER call this without an "+
			"explicit human confirmation. expected_version must equal the signature's current head version "+
			"exactly (0 only when no head exists yet, to create the first one) or the correction is refused "+
			"as stale — re-read with alertint_get_semantic_profile and retry with the current version. A "+
			"correction never asserts source state, never bypasses proven identity, and never widens the "+
			"observation horizon downward."),
		mcplib.WithString("signature", mcplib.Description("Advisory signature key to correct."), mcplib.Required()),
		mcplib.WithNumber("expected_version", mcplib.Description(
			"The signature's current head version (from alertint_get_semantic_profile). 0 creates a missing head."), mcplib.Required()),
		mcplib.WithObject("profile", mcplib.Description(
			"The corrected Profile: subject_kind, event_kind, possible_role (required strings, max 128 chars); "+
				"candidate_scope, companion_signal_kinds, useful_capabilities, uncertainty (arrays, max 8 entries, "+
				"uncertainty entries max 256 chars); horizon_tier (unknown|minutes|hours|days). No other fields."),
			mcplib.Required()),
		mcplib.WithBoolean("confirm", mcplib.Description("Must be true — an explicit human confirmation of this correction."), mcplib.Required()),
		mcplib.WithString("asserted_by", mcplib.Description("Non-empty identity of the confirming operator."), mcplib.Required()),
	)
	return tool, s.handleCorrectSemanticProfile
}

// decodeStrictProfile decodes raw (already-parsed JSON from the MCP
// request) into a profilemodel.Profile, rejecting any field outside the
// closed eight-field schema (spec.md's "Reject ... forbidden fields").
func decodeStrictProfile(raw any) (profilemodel.Profile, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return profilemodel.Profile{}, errors.New("profile must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p profilemodel.Profile
	if err := dec.Decode(&p); err != nil {
		return profilemodel.Profile{}, fmt.Errorf("profile is invalid or has a forbidden field: %w", err)
	}
	return p, nil
}

// correctSemanticProfileErrorMessage renders CorrectSemanticProfile's error
// for an MCP caller. Its own pre-store validation failures (confirm/
// asserted_by/invalid profile — hand-written, safe, never touch SQL) pass
// through verbatim; anything the store already wrapped with its own
// "store: " prefix (an actual persistence failure) becomes a fixed generic
// message instead — this package's established "never leak a wrapped
// store/SQL error" convention (handleGetSituation's own doc comment).
func correctSemanticProfileErrorMessage(err error) string {
	if errors.Is(err, profilemodel.ErrVersionConflict) {
		return "expected_version does not match the current head — re-read with alertint_get_semantic_profile and retry"
	}
	if strings.HasPrefix(err.Error(), "store:") {
		return "failed to correct semantic profile"
	}
	return err.Error()
}

func (s *Server) handleCorrectSemanticProfile(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	signature := mcplib.ParseString(req, "signature", "")
	if signature == "" {
		return errResult("signature is required"), nil
	}
	if !mcplib.ParseBoolean(req, "confirm", false) {
		return errResult("confirm=true is required — an explicit human confirmation of this correction"), nil
	}
	assertedBy := mcplib.ParseString(req, "asserted_by", "")
	if assertedBy == "" {
		return errResult("asserted_by is required"), nil
	}
	raw := mcplib.ParseArgument(req, "profile", nil)
	if raw == nil {
		return errResult("profile is required"), nil
	}
	profile, err := decodeStrictProfile(raw)
	if err != nil {
		return errResult(err.Error()), nil
	}
	expectedVersion := mcplib.ParseInt(req, "expected_version", -1)
	if expectedVersion < 0 {
		return errResult("expected_version is required"), nil
	}

	v, err := s.st.CorrectSemanticProfile(ctx, profilemodel.Correction{
		Signature: signature, ExpectedVersion: expectedVersion, Profile: profile,
		Confirm: true, AssertedBy: assertedBy,
	}, time.Now().UTC())
	if err != nil {
		return errResult(correctSemanticProfileErrorMessage(err)), nil
	}
	// Best-effort, matching skills/acutetriage's own capture.go convention
	// (this package's Server carries no logger to report a failure to) — a
	// failed audit append must never undo or hide the correction that just
	// durably committed.
	_ = s.auditor.Append(ctx, "mcp.semantic_profile", "semantic_profile.correction_applied", map[string]any{
		"signature": signature, "version": v.Version, "asserted_by": assertedBy,
	})

	result, err := mcplib.NewToolResultJSON(semanticProfileVersionRowFrom(v))
	if err != nil {
		return errResult("failed to serialize corrected semantic profile: " + err.Error()), nil
	}
	return result, nil
}
