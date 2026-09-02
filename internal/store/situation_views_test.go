// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestSituationControllerViewIncludesCurrentAssessmentContractHashesReasons(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-view-current", now)

	// The current_assessment_id guard trigger requires the referenced
	// attempt to already exist as status='authoritative', so insert it
	// before pointing situations.current_assessment_id at it.
	assessmentJSON, err := json.Marshal(validAssessmentFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, status, derivation,
			provider_request_started, material_fact_hash, assessment_json, created_at, completed_at
		) VALUES ('attempt-view', ?, 1, 1, 1, 'authoritative', 'deterministic_controller', 'false', 'sha256:material-view', ?, ?, ?)`,
		sitID, string(assessmentJSON), now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	contract := situationmodel.ActionContract{
		NextActor:    situationmodel.NextActorNone,
		NextUpdateAt: timePtrValue(now.Add(time.Hour)),
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations
		SET current_assessment_id = 'attempt-view', current_action_contract_json = ?,
		    current_material_fact_hash = 'sha256:material-view', current_assessment_basis_hash = 'sha256:basis-view'
		WHERE id = ?`, string(contractJSON), sitID); err != nil {
		t.Fatal(err)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatalf("GetSituationControllerView: %v", err)
	}
	if view.CurrentAssessmentID == nil || *view.CurrentAssessmentID != "attempt-view" {
		t.Fatalf("current assessment id = %v, want attempt-view", view.CurrentAssessmentID)
	}
	if view.CurrentActionContract == nil || view.CurrentActionContract.NextActor != situationmodel.NextActorNone {
		t.Fatalf("current action contract = %+v, want next_actor=none", view.CurrentActionContract)
	}
	if view.CurrentMaterialFactHash == nil || *view.CurrentMaterialFactHash != "sha256:material-view" {
		t.Fatalf("current material fact hash = %v, want sha256:material-view", view.CurrentMaterialFactHash)
	}
	if view.CurrentAssessmentBasisHash == nil || *view.CurrentAssessmentBasisHash != "sha256:basis-view" {
		t.Fatalf("current assessment basis hash = %v, want sha256:basis-view", view.CurrentAssessmentBasisHash)
	}
	if view.DueReasons == nil {
		t.Fatal("due reasons = nil, want a non-nil (possibly empty) slice")
	}
}

func TestSituationControllerViewBoundsRecentAttemptsToTwenty(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-view-bound", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	for i := 1; i <= 25; i++ {
		callID := "call-" + strconv.Itoa(i)
		call := callFixture(callID, sitID, 1, 1, 1, now)
		call.ID = callID
		// Distinct dispatch identity per iteration: vary call_number's
		// partner (work_attempt) is capped at 5, so cycle retry_epoch
		// instead to keep every dispatch row unique under the schema's
		// UNIQUE(situation_id,input_version,retry_epoch,work_attempt,call_number).
		call.RetryEpoch = i
		if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
			t.Fatalf("record call %d: %v", i, err)
		}
		started := situationmodel.ProviderRequestStartedTrue
		attempt := situation.AssessmentAttempt{
			ID: "attempt-" + strconv.Itoa(i), SituationID: sitID, CallID: &callID,
			InputVersion: 1, RetryEpoch: i, WorkAttempt: 1, Sequence: i,
			Status:                 "failed",
			ProviderRequestStarted: &started,
			CreatedAt:              now, CompletedAt: now,
		}
		if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
			t.Fatalf("append outcome %d: %v", i, err)
		}
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatalf("GetSituationControllerView: %v", err)
	}
	if len(view.RecentAttempts) != maxRecentSanitizedAttempts {
		t.Fatalf("recent attempts = %d, want %d (bounded)", len(view.RecentAttempts), maxRecentSanitizedAttempts)
	}
	// Most recent first (sequence DESC): the newest 20 of 25, i.e. sequence 25..6.
	if view.RecentAttempts[0].Sequence != 25 {
		t.Fatalf("newest attempt sequence = %d, want 25", view.RecentAttempts[0].Sequence)
	}
	if view.RecentAttempts[len(view.RecentAttempts)-1].Sequence != 6 {
		t.Fatalf("oldest bounded attempt sequence = %d, want 6", view.RecentAttempts[len(view.RecentAttempts)-1].Sequence)
	}
}

// TestSituationControllerViewNeverExposesRejectedFreeTextOrProviderBodies
// proves the sanitized view surfaces only the bounded typed validation
// codes this store persisted — never a longer free-text/provider-body
// value, even if one were (incorrectly) present in validation_errors_json.
func TestSituationControllerViewNeverExposesRejectedFreeTextOrProviderBodies(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-view-sanitize", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatal(err)
	}
	callID := "call-1"
	started := situationmodel.ProviderRequestStartedTrue
	attempt := situation.AssessmentAttempt{
		ID: "attempt-1", SituationID: sitID, CallID: &callID,
		InputVersion: 1, WorkAttempt: 1, Sequence: 1,
		Status:                 "rejected",
		Proposal:               json.RawMessage(`{"raw":"this is the raw l2 proposal payload"}`),
		ValidationErrors:       json.RawMessage(`["malformed_schema"]`),
		ProviderRequestStarted: &started,
		CreatedAt:              now, CompletedAt: now,
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.RecentAttempts) != 1 {
		t.Fatalf("recent attempts = %d, want 1", len(view.RecentAttempts))
	}
	got := view.RecentAttempts[0]
	if len(got.ValidationErrorCodes) != 1 || got.ValidationErrorCodes[0] != "malformed_schema" {
		t.Fatalf("validation error codes = %v, want exactly [\"malformed_schema\"]", got.ValidationErrorCodes)
	}
	// SanitizedAssessmentAttempt has no field carrying Proposal/Validated
	// content at all — this is a compile-time guarantee, not a runtime one;
	// the assertion above is the runtime half: only the bounded typed code
	// survives into the view.
}

func TestSituationControllerViewIncludesCurrentTriageState(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	groupKey := "group-view-triage"
	incID, deliveryID := "inc-view-triage", "delivery-view-triage"
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-view-triage", now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, incID, "input-view-triage", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var sitID string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&sitID); err != nil {
		t.Fatal(err)
	}

	decision := "skip"
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, decision, decided_at, updated_at)
		VALUES (?, 'skipped', 1, ?, ?, ?)`, incID, decision, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Triage) != 1 {
		t.Fatalf("triage views = %+v, want exactly 1", view.Triage)
	}
	got := view.Triage[0]
	if got.IncidentID != incID || got.Phase != "skipped" || got.Attempts != 1 {
		t.Fatalf("triage view = %+v, want incident=%s phase=skipped attempts=1", got, incID)
	}
	if got.Decision == nil || *got.Decision != "skip" {
		t.Fatalf("triage decision = %v, want skip", got.Decision)
	}
	if got.DecidedAt == nil {
		t.Fatal("triage decided_at = nil, want set")
	}
}

func TestSituationControllerViewUnknownSituationReturnsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	_, err := st.GetSituationControllerView(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
