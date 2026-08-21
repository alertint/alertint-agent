// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSituationCommands is a recording SituationCommands double shared by
// every Situation/semantic-profile/expected-behavior test in this package.
type fakeSituationCommands struct {
	reassessCalls []string
	reassessErr   error

	lastJudgmentReq model.JudgmentRequest
	judgment        *model.Judgment
	judgmentErr     error

	lastConfirm     model.EnvelopeConfirmation
	envelopeConfirm *model.EnvelopeVersion
	confirmErr      error

	lastRevoke     model.EnvelopeRevocation
	envelopeRevoke *model.EnvelopeVersion
	revokeErr      error

	lastCorrection semanticprofile.Correction
	profileVersion *profilemodel.ProfileVersion
	correctErr     error
}

func (f *fakeSituationCommands) Reassess(_ context.Context, situation string) error {
	f.reassessCalls = append(f.reassessCalls, situation)
	return f.reassessErr
}

func (f *fakeSituationCommands) RecordJudgment(_ context.Context, req model.JudgmentRequest) (*model.Judgment, error) {
	f.lastJudgmentReq = req
	return f.judgment, f.judgmentErr
}

func (f *fakeSituationCommands) ConfirmEnvelope(_ context.Context, confirmation model.EnvelopeConfirmation) (*model.EnvelopeVersion, error) {
	f.lastConfirm = confirmation
	return f.envelopeConfirm, f.confirmErr
}

func (f *fakeSituationCommands) RevokeEnvelope(_ context.Context, revocation model.EnvelopeRevocation) (*model.EnvelopeVersion, error) {
	f.lastRevoke = revocation
	return f.envelopeRevoke, f.revokeErr
}

func (f *fakeSituationCommands) CorrectSemanticProfile(_ context.Context, correction semanticprofile.Correction) (*profilemodel.ProfileVersion, error) {
	f.lastCorrection = correction
	return f.profileVersion, f.correctErr
}

func newMCPServer(t *testing.T) *Server {
	t.Helper()
	st := newMCPStore(t)
	return NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
}

func discoverTools(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	return s.registeredToolNames()
}

// seedTestSituation inserts a minimal, schema-valid situations row directly
// — the same shape internal/store's own insertSituationFixture test helper
// builds, reimplemented here because that helper is unexported to a
// different package.
func seedTestSituation(t *testing.T, st *store.Store, id, groupKey, handle string, lifecycle model.Lifecycle, now time.Time) {
	t.Helper()
	ts := now.UTC().Format(time.RFC3339Nano)
	var publicHandle any
	if handle != "" {
		publicHandle = handle
	}
	var recoveryObservedAt, graceUntil, terminalAt, terminalReason any
	if lifecycle == model.LifecycleRecoveryPending || lifecycle == model.LifecycleRecovered {
		recoveryObservedAt, graceUntil = ts, ts
	}
	if lifecycle == model.LifecycleRecovered || lifecycle == model.LifecycleClosedUnknown {
		terminalAt = ts
	}
	if lifecycle == model.LifecycleClosedUnknown {
		terminalReason = string(model.TerminalReasonResolutionMissing)
	}
	if _, err := st.DB().Exec(`
		INSERT INTO situations (
			id, group_key, public_handle, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis,
			first_received_at, last_lifecycle_observed_at, recovery_observed_at, grace_until, terminal_at, terminal_reason,
			next_assessment_at, due_reasons_json, attempt_count, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'observe', 1, ?, ?, 'source_payload', ?, ?, ?, ?, ?, ?, ?, '[]', 0, ?, ?)`,
		id, groupKey, publicHandle, lifecycle, ts, ts, ts, ts, recoveryObservedAt, graceUntil, terminalAt, terminalReason, ts, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func seedTestIncident(t *testing.T, st *store.Store, id, groupKey string, now time.Time) {
	t.Helper()
	ts := now.UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().Exec(`INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, 'ready', ?, ?, ?, 1, ?, ?)`, id, groupKey, ts, ts, ts, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func attachTestIncident(t *testing.T, st *store.Store, situationID, incidentID string, now time.Time) {
	t.Helper()
	if _, err := st.DB().Exec(`INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)`,
		situationID, incidentID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func TestSituationToolsRegistered(t *testing.T) {
	want := []string{
		"alertint_situation_list", "alertint_situation_get", "alertint_situation_evidence_get",
		"alertint_situation_reassess", "alertint_situation_judgment_record",
		"alertint_semantic_profile_get", "alertint_semantic_profile_correct",
		"alertint_expected_behavior_list", "alertint_expected_behavior_confirm", "alertint_expected_behavior_revoke",
		"alertint_poke_funnel_get",
	}
	got := discoverTools(t, newMCPServer(t))
	for _, name := range want {
		if !got[name] {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestSituationToolsNotRegisteredWithoutCommands(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	got := discoverTools(t, s)
	if got["alertint_situation_list"] || got["alertint_poke_funnel_get"] {
		t.Fatalf("situation tools registered without SituationCommands: %v", got)
	}
	// Existing tools remain unconditionally registered.
	if !got["alertint_list_incidents"] {
		t.Fatal("existing incident tools must remain registered")
	}
}

func TestHandleSituationListIncludesSilentAndTerminal(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	seedTestSituation(t, st, "sit-silent", "host=silent", "", model.LifecycleActive, now)
	seedTestSituation(t, st, "sit-terminal", "host=terminal", "terminal-handle", model.LifecycleClosedUnknown, now)

	res, err := s.handleSituationList(context.Background(), reqWith(nil))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, "sit-silent") || !strings.Contains(out, "sit-terminal") {
		t.Fatalf("list missing situations: %s", out)
	}
}

func TestHandleSituationGetReturnsTerminalBannerAndMemberGateState(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	seedTestSituation(t, st, "sit-get-1", "host=db-1", "db-prod-cpu", model.LifecycleClosedUnknown, now)
	seedTestIncident(t, st, "inc-get-1", "host=db-1", now)
	attachTestIncident(t, st, "sit-get-1", "inc-get-1", now)
	if _, err := st.DB().Exec(`INSERT INTO incident_analysis_state (incident_id, status, decision_reason, updated_at)
		VALUES ('inc-get-1', 'not_requested', 'covered_unchanged_fact_hash', ?)`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	res, err := s.handleSituationGet(context.Background(), reqWith(map[string]any{"situation": "sit-get-1"}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, "CLOSED WITH UNCERTAINTY") {
		t.Fatalf("terminal response must lead with a terminal banner: %s", out)
	}
	if !strings.Contains(out, "inc-get-1") || !strings.Contains(out, "covered_unchanged_fact_hash") {
		t.Fatalf("get view must include member incident acute-analysis gate state: %s", out)
	}

	// Resolves by public handle too.
	byHandle, err := s.handleSituationGet(context.Background(), reqWith(map[string]any{"situation": "db-prod-cpu"}))
	if err != nil || byHandle.IsError {
		t.Fatalf("by-handle err=%v result=%s", err, resultText(t, byHandle))
	}
}

func TestHandleSituationGetNotFound(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleSituationGet(context.Background(), reqWith(map[string]any{"situation": "does-not-exist"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for an unknown situation")
	}
}

func TestHandleSituationReassessDelegatesAndRequiresSituation(t *testing.T) {
	fake := &fakeSituationCommands{}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	if res, err := s.handleSituationReassess(context.Background(), reqWith(nil)); err != nil || !res.IsError {
		t.Fatalf("expected an error result for missing situation: err=%v", err)
	}

	res, err := s.handleSituationReassess(context.Background(), reqWith(map[string]any{"situation": "sit-1"}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if len(fake.reassessCalls) != 1 || fake.reassessCalls[0] != "sit-1" {
		t.Fatalf("reassess calls=%v", fake.reassessCalls)
	}
}

func TestHandleSituationReassessUnavailableWithoutCommands(t *testing.T) {
	st := newMCPStore(t)
	s := &Server{cfg: Config{}, st: st, auditor: audit.New(st.DB())}
	res, err := s.handleSituationReassess(context.Background(), reqWith(map[string]any{"situation": "sit-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result when situation commands are unavailable")
	}
}

func TestHandleSituationJudgmentRecordDelegatesToCommand(t *testing.T) {
	fake := &fakeSituationCommands{judgment: &model.Judgment{ID: "j1", SituationID: "sit-1", Judgment: model.JudgmentExpectedThisEpisode}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"situation": "sit-1", "judgment": "expected_this_episode", "basis": "operator_knowledge",
		"operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if fake.lastJudgmentReq.Situation != "sit-1" || fake.lastJudgmentReq.ConfirmedBy != "janis" || !fake.lastJudgmentReq.OperatorConfirmed {
		t.Fatalf("judgment request=%+v", fake.lastJudgmentReq)
	}
	out := resultText(t, res)
	if !strings.Contains(out, "j1") {
		t.Fatalf("expected recorded judgment id in response: %s", out)
	}
}

func TestHandleSituationJudgmentRecordRequiresSituation(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"judgment": "expected_this_episode", "basis": "operator_knowledge", "operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing situation")
	}
}

func TestHandleSituationJudgmentRecordRejectsUnconfirmed(t *testing.T) {
	fake := &fakeSituationCommands{judgment: &model.Judgment{ID: "j1"}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"situation": "sit-1", "judgment": "expected_this_episode", "basis": "operator_knowledge",
		"operator_confirmed": false, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for operator_confirmed=false")
	}
	if fake.lastJudgmentReq.Situation != "" {
		t.Fatalf("command must not be called on an unconfirmed request, got %+v", fake.lastJudgmentReq)
	}
}

func TestHandleSituationJudgmentRecordRejectsMissingConfirmedBy(t *testing.T) {
	fake := &fakeSituationCommands{judgment: &model.Judgment{ID: "j1"}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"situation": "sit-1", "judgment": "expected_this_episode", "basis": "operator_knowledge",
		"operator_confirmed": true, "confirmed_by": "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for an empty confirmed_by")
	}
	if fake.lastJudgmentReq.Situation != "" {
		t.Fatalf("command must not be called without asserted attribution, got %+v", fake.lastJudgmentReq)
	}
}

func TestHandleSituationJudgmentRecordRejectsInvalidJudgmentAndBasisEnums(t *testing.T) {
	fake := &fakeSituationCommands{judgment: &model.Judgment{ID: "j1"}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"situation": "sit-1", "judgment": "definitely_bad", "basis": "operator_knowledge",
		"operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for an invalid judgment enum value")
	}

	res, err = s.handleSituationJudgmentRecord(context.Background(), reqWith(map[string]any{
		"situation": "sit-1", "judgment": "expected_this_episode", "basis": "gut_feeling",
		"operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for an invalid basis enum value")
	}
	if fake.lastJudgmentReq.Situation != "" {
		t.Fatalf("command must not be called for an invalid enum, got %+v", fake.lastJudgmentReq)
	}
}
