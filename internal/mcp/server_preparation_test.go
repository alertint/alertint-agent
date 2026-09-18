// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// TestPreparationToolsRegistered proves NewServer registers all three
// Plan 4 Task 9 tools under their exact spec.md names.
func TestPreparationToolsRegistered(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	runsTool, runsHandler := s.toolListObservationRuns()
	if runsTool.Name != "alertint_list_observation_runs" || runsHandler == nil {
		t.Fatalf("runs tool = %q (handler nil=%v)", runsTool.Name, runsHandler == nil)
	}
	getTool, getHandler := s.toolGetSemanticProfile()
	if getTool.Name != "alertint_get_semantic_profile" || getHandler == nil {
		t.Fatalf("get tool = %q (handler nil=%v)", getTool.Name, getHandler == nil)
	}
	correctTool, correctHandler := s.toolCorrectSemanticProfile()
	if correctTool.Name != "alertint_correct_semantic_profile" || correctHandler == nil {
		t.Fatalf("correct tool = %q (handler nil=%v)", correctTool.Name, correctHandler == nil)
	}
}

// ----------------------------------------------------------------------
// alertint_list_observation_runs
// ----------------------------------------------------------------------

// seedObservationRun claims situationID's due controller work, freezes and
// commits exactly one Prometheus plan/run through the real Task 2 store
// API (BeginPreparation/ReserveObservationRequest/CompleteObservationRequest/
// CommitObservationRun) — the exact sequence observation.Runner.RunPhase
// drives in production.
func seedObservationRun(t *testing.T, st *store.Store, situationID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	claims, err := st.ClaimDueSituations(ctx, "prep-test:"+situationID, now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim due situations: %v", err)
	}
	var claim situation.Claim
	found := false
	for _, c := range claims {
		if c.ID == situationID {
			claim = situation.Claim{Situation: c, ClaimOwner: *c.LeaseOwner, ClaimToken: c.ClaimToken}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("situation %s not among %d claimed due situations", situationID, len(claims))
	}

	fence := observationmodel.Fence{
		SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken,
	}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityPrometheusQuery, Phase: observationmodel.PhaseAssessment,
		Scope: observationmodel.Scope{
			GroupKey: claim.Situation.GroupKey, Source: "alertmanager",
			SubjectID: "signal-a", Labels: map[string]string{"service": "checkout"},
		},
		Parameters: []byte(`{"expression":"up{service=\"checkout\"}"}`),
		Start:      now.Add(-time.Minute), End: now, EligibleAt: now,
		Limit: 20, MaxRequests: 2, Purpose: "corroborate_member",
	}
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{
		Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{plan},
	}, 2)
	if err != nil {
		t.Fatalf("begin preparation: %v", err)
	}
	planID := cycle.Draft.Plans[0].ID

	reservation, err := st.ReserveObservationRequest(ctx, fence, cycle.ID, planID, now)
	if err != nil {
		t.Fatalf("reserve observation request: %v", err)
	}
	if err := st.CompleteObservationRequest(ctx, observationmodel.RequestOutcome{
		ReservationID: reservation.ID, RequestStarted: observationmodel.RequestStartedTrue, Code: "ok", CompletedAt: now,
	}); err != nil {
		t.Fatalf("complete observation request: %v", err)
	}

	run := observationmodel.Run{
		ID: "run-" + planID, CycleID: cycle.ID, PlanID: planID, Status: observationmodel.ResultConfirmedEmpty,
		Coverage:   observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: true},
		ObservedAt: now, ExpiresAt: now.Add(time.Hour), CompletedAt: now,
	}
	if err := st.CommitObservationRun(ctx, fence, run, now); err != nil {
		t.Fatalf("commit observation run: %v", err)
	}
}

func TestListObservationRunsRequiresIDOrHandle(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListObservationRuns(context.Background(), reqWith(map[string]any{}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result with neither id nor handle set")
	}
}

func TestListObservationRunsEmptyForSituationWithNoPreparationYet(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 7, 3, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-runs-empty", "service=runs-empty", "incident_created", at)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListObservationRuns(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("list observation runs errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Runs       []json.RawMessage `json:"runs"`
		NextCursor *string           `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if len(payload.Runs) != 0 {
		t.Fatalf("runs = %+v, want empty", payload.Runs)
	}
	if payload.NextCursor != nil {
		t.Fatalf("next_cursor = %v, want null", payload.NextCursor)
	}
}

func TestListObservationRunsReturnsCommittedRun(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 7, 3, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-runs-one", "service=runs-one", "incident_created", at)
	seedObservationRun(t, st, situationID, at.Add(time.Minute))

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListObservationRuns(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("list observation runs errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Runs []struct {
			Status      string `json:"status"`
			DetailState string `json:"detail_state"`
			Coverage    struct {
				Complete bool `json:"complete"`
			} `json:"coverage"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if len(payload.Runs) != 1 {
		t.Fatalf("runs = %+v, want exactly 1", payload.Runs)
	}
	if payload.Runs[0].Status != string(observationmodel.ResultConfirmedEmpty) {
		t.Fatalf("status = %q, want %q", payload.Runs[0].Status, observationmodel.ResultConfirmedEmpty)
	}
	if payload.Runs[0].DetailState != observationmodel.DetailStateRetained {
		t.Fatalf("detail_state = %q, want retained", payload.Runs[0].DetailState)
	}
	if !payload.Runs[0].Coverage.Complete {
		t.Fatal("coverage.complete = false, want true")
	}
}

// ----------------------------------------------------------------------
// alertint_get_semantic_profile
// ----------------------------------------------------------------------

func TestGetSemanticProfileRequiresExactlyOneOfSignatureOrSituation(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	res, err := s.handleGetSemanticProfile(context.Background(), reqWith(map[string]any{}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result with neither signature nor a situation set")
	}

	res, err = s.handleGetSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": "sig:both", "id": "sit-1",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result with BOTH signature and id set")
	}
}

func TestGetSemanticProfileBySignatureReturnsCurrentHead(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	sig := "zabbix:advisory:sha256:mcp-get"
	if _, err := st.CorrectSemanticProfile(context.Background(), profilemodel.Correction{
		Signature: sig,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:seed",
	}, now); err != nil {
		t.Fatalf("seed correction: %v", err)
	}

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSemanticProfile(context.Background(), reqWith(map[string]any{"signature": sig}))
	if err != nil || res.IsError {
		t.Fatalf("get semantic profile errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Profiles []struct {
			Signature string `json:"signature"`
			Current   *struct {
				Version int `json:"version"`
			} `json:"current"`
			Versions []json.RawMessage `json:"versions"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if len(payload.Profiles) != 1 || payload.Profiles[0].Signature != sig {
		t.Fatalf("profiles = %+v, want exactly one for %q", payload.Profiles, sig)
	}
	if payload.Profiles[0].Current == nil || payload.Profiles[0].Current.Version != 1 {
		t.Fatalf("current = %+v, want version 1", payload.Profiles[0].Current)
	}
	if len(payload.Profiles[0].Versions) != 1 {
		t.Fatalf("versions = %+v, want exactly 1", payload.Profiles[0].Versions)
	}
}

func TestGetSemanticProfileUnknownSignatureReturnsEmptyNotError(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSemanticProfile(context.Background(), reqWith(map[string]any{"signature": "no:such:signature"}))
	if err != nil || res.IsError {
		t.Fatalf("get semantic profile errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Profiles []struct {
			Current *json.RawMessage `json:"current"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if len(payload.Profiles) != 1 || payload.Profiles[0].Current != nil {
		t.Fatalf("profiles = %+v, want one entry with a null current", payload.Profiles)
	}
}

// ----------------------------------------------------------------------
// alertint_correct_semantic_profile
// ----------------------------------------------------------------------

func validProfileArg() map[string]any {
	return map[string]any{
		"subject_kind": "service", "event_kind": "availability", "possible_role": "symptom",
		"candidate_scope": []any{"service"}, "horizon_tier": "hours",
	}
}

func TestCorrectSemanticProfileRequiresConfirm(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": "sig:noconfirm", "expected_version": 0, "profile": validProfileArg(),
		"asserted_by": "operator:test",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result without confirm=true")
	}
}

func TestCorrectSemanticProfileRequiresAssertedBy(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": "sig:noactor", "expected_version": 0, "profile": validProfileArg(), "confirm": true,
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result without asserted_by")
	}
}

func TestCorrectSemanticProfileRejectsForbiddenField(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	profile := validProfileArg()
	profile["policy_action"] = "silence" // not part of the closed 8-field schema
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": "sig:forbidden", "expected_version": 0, "profile": profile,
		"confirm": true, "asserted_by": "operator:test",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a profile carrying a forbidden field")
	}
}

func TestCorrectSemanticProfileRejectsStaleExpectedVersion(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	sig := "sig:stale-mcp"
	args := map[string]any{
		"signature": sig, "expected_version": 0, "profile": validProfileArg(),
		"confirm": true, "asserted_by": "operator:test",
	}
	if res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(args)); err != nil || res.IsError {
		t.Fatalf("first correction errored: %v %s", err, resultText(t, res))
	}
	// expected_version still 0: stale now that the head is 1.
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(args))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a stale expected_version")
	}
}

func TestCorrectSemanticProfileCreatesVersionAndAdvancesHead(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	sig := "sig:create-mcp"
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": sig, "expected_version": 0, "profile": validProfileArg(),
		"confirm": true, "asserted_by": "operator:test",
	}))
	if err != nil || res.IsError {
		t.Fatalf("correction errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Version    int    `json:"version"`
		Origin     string `json:"origin"`
		AssertedBy string `json:"asserted_by"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if payload.Version != 1 || payload.Origin != profilemodel.OriginCorrection || payload.AssertedBy != "operator:test" {
		t.Fatalf("payload = %+v, want version=1 origin=correction asserted_by=operator:test", payload)
	}

	history, err := st.GetSemanticProfile(context.Background(), sig, "", 20)
	if err != nil {
		t.Fatalf("GetSemanticProfile: %v", err)
	}
	if history.Current == nil || history.Current.Version != 1 {
		t.Fatalf("stored head = %+v, want version 1", history.Current)
	}
}

// TestCorrectSemanticProfileAuditsTheCorrection proves a successful
// correction appends a "semantic_profile.correction_applied" audit row —
// Task 9's "Audit ... profile ... correction" requirement.
func TestCorrectSemanticProfileAuditsTheCorrection(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	sig := "sig:audit-mcp"
	res, err := s.handleCorrectSemanticProfile(context.Background(), reqWith(map[string]any{
		"signature": sig, "expected_version": 0, "profile": validProfileArg(),
		"confirm": true, "asserted_by": "operator:test",
	}))
	if err != nil || res.IsError {
		t.Fatalf("correction errored: %v %s", err, resultText(t, res))
	}

	var count int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM audit_log WHERE kind = ?`, "semantic_profile.correction_applied").Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit rows = %d, want 1", count)
	}
}
