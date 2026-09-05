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

// TestSituationControllerViewCountsConsumedTriageAttemptsAfterCompletion
// pins the lab finding from the 2026-09-04 Plan 2 acceptance run: a
// successful Finding deletes the incident_triage schedule row
// (CompleteIncidentTriage — membership closes at judgment), but the consumed
// attempt is durable in incident_triage_attempts. The MCP read must keep
// reporting that consumed attempt (check 10: MCP, audit, SQLite, logs and
// OTel must agree on "consumed Triage attempts"), and must say the schedule
// is completed rather than rendering the pre-controller "no Triage state"
// empty phase.
func TestSituationControllerViewCountsConsumedTriageAttemptsAfterCompletion(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 4, 8, 11, 0, 0, time.UTC)
	groupKey := "group-view-triage-completed"
	incID, deliveryID := "inc-view-triage-completed", "delivery-view-triage-completed"
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-view-triage-completed", now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, incID, "input-view-triage-completed", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var sitID string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&sitID); err != nil {
		t.Fatal(err)
	}

	// One consumed, successful attempt in the ledger; the schedule row is
	// already gone, exactly as the worker leaves it after a persisted Finding.
	ts := now.UTC().Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage_attempts (
			id, incident_id, attempt_number, situation_id, decision_input_version,
			membership_digest, incident_input_digest, member_delivery_ids_json, started_at,
			result_code, output_digest, finding_id, completed_at
		) VALUES (?, ?, 1, ?, 2, 'sha256:members', 'sha256:input', '[]', ?, 'success', 'sha256:out', 'finding:x', ?)`,
		"attempt-view-triage-completed", incID, sitID, ts, ts); err != nil {
		t.Fatal(err)
	}
	var scheduleRows int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM incident_triage WHERE incident_id = ?`, incID).Scan(&scheduleRows); err != nil {
		t.Fatal(err)
	}
	if scheduleRows != 0 {
		t.Fatalf("incident_triage rows = %d, want 0 (fixture must model the post-completion state)", scheduleRows)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Triage) != 1 {
		t.Fatalf("triage views = %+v, want exactly 1", view.Triage)
	}
	got := view.Triage[0]
	if got.IncidentID != incID || got.Phase != "completed" || got.Attempts != 1 {
		t.Fatalf("triage view = %+v, want incident=%s phase=completed attempts=1", got, incID)
	}
	if got.Decision != nil || got.NextAt != nil {
		t.Fatalf("triage view = %+v, want no decision/due time once the schedule row is gone", got)
	}
}

// TestSituationControllerViewTriageAttemptsNeverBelowLedger proves the
// attempt count reads the durable ledger even while the schedule row still
// exists: a schedule counter that lags (a legacy row, or a migrated one) can
// never make the MCP read under-report a consumed attempt.
func TestSituationControllerViewTriageAttemptsNeverBelowLedger(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 4, 8, 11, 0, 0, time.UTC)
	groupKey := "group-view-triage-ledger"
	incID, deliveryID := "inc-view-triage-ledger", "delivery-view-triage-ledger"
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-view-triage-ledger", now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, incID, "input-view-triage-ledger", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var sitID string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&sitID); err != nil {
		t.Fatal(err)
	}
	ts := now.UTC().Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at) VALUES (?, 'backoff', 0, ?)`, incID, ts); err != nil {
		t.Fatal(err)
	}
	for i, code := range []string{"lease_expired", "success"} {
		if _, err := st.db.ExecContext(context.Background(), `
			INSERT INTO incident_triage_attempts (
				id, incident_id, attempt_number, situation_id, decision_input_version,
				membership_digest, incident_input_digest, member_delivery_ids_json, started_at,
				result_code, completed_at
			) VALUES (?, ?, ?, ?, 2, 'sha256:members', 'sha256:input', '[]', ?, ?, ?)`,
			"attempt-view-triage-ledger-"+strconv.Itoa(i+1), incID, i+1, sitID, ts, code, ts); err != nil {
			t.Fatal(err)
		}
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Triage) != 1 {
		t.Fatalf("triage views = %+v, want exactly 1", view.Triage)
	}
	got := view.Triage[0]
	if got.Phase != "backoff" || got.Attempts != 2 {
		t.Fatalf("triage view = %+v, want phase=backoff (schedule) attempts=2 (ledger)", got)
	}
}

// TestSituationControllerViewIncludesCurrentAssessmentContentAndDerivation
// proves Task 9's own MCP-facing extension: the current authoritative
// Assessment's full content (persistence/impact/.../sufficient_reason with
// its evidence refs/schema version) and its derivation are read straight off
// the referenced attempt row's assessment_json/derivation columns — never a
// rejected proposal, never provider content.
func TestSituationControllerViewIncludesCurrentAssessmentContentAndDerivation(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-view-assessment-content", now)

	fixture := validAssessmentFixture()
	assessmentJSON, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, status, derivation,
			provider_request_started, material_fact_hash, assessment_json, created_at, completed_at
		) VALUES ('attempt-content', ?, 1, 1, 1, 'authoritative', 'deterministic_controller', 'false', 'sha256:material-content', ?, ?, ?)`,
		sitID, string(assessmentJSON), now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET current_assessment_id = 'attempt-content' WHERE id = ?`, sitID); err != nil {
		t.Fatal(err)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatalf("GetSituationControllerView: %v", err)
	}
	if view.CurrentAssessment == nil {
		t.Fatal("current assessment = nil, want the full assessment content")
	}
	if view.CurrentAssessment.Persistence != fixture.Persistence || view.CurrentAssessment.Impact != fixture.Impact {
		t.Fatalf("current assessment content = %+v, want %+v", view.CurrentAssessment, fixture)
	}
	if view.CurrentAssessment.SchemaVersion != fixture.SchemaVersion {
		t.Fatalf("current assessment schema_version = %d, want %d", view.CurrentAssessment.SchemaVersion, fixture.SchemaVersion)
	}
	if view.CurrentDerivation == nil || *view.CurrentDerivation != situationmodel.DerivationDeterministic {
		t.Fatalf("current derivation = %v, want deterministic_controller", view.CurrentDerivation)
	}
}

// TestSituationControllerViewIncludesControllerRetryParkState proves Task
// 9's own MCP-facing extension: retry epoch, work attempts, parked
// at/reason, retry_at, and last_error_class read straight off situations'
// own columns.
func TestSituationControllerViewIncludesControllerRetryParkState(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-view-retry-park", now)

	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET
			controller_retry_epoch = 2, controller_work_attempts = 3,
			controller_parked_at = ?, controller_parked_reason = 'dependency_exhausted',
			retry_at = ?, last_error_class = 'transport_failure'
		WHERE id = ?`,
		now.UTC().Format(time.RFC3339Nano), now.Add(5*time.Minute).UTC().Format(time.RFC3339Nano), sitID); err != nil {
		t.Fatal(err)
	}

	view, err := st.GetSituationControllerView(context.Background(), sitID)
	if err != nil {
		t.Fatalf("GetSituationControllerView: %v", err)
	}
	if view.Retry.RetryEpoch != 2 || view.Retry.WorkAttempts != 3 {
		t.Fatalf("retry state = %+v, want retry_epoch=2 work_attempts=3", view.Retry)
	}
	if view.Retry.ParkedAt == nil || !view.Retry.ParkedAt.Equal(now) {
		t.Fatalf("parked_at = %v, want %v", view.Retry.ParkedAt, now)
	}
	if view.Retry.ParkedReason == nil || *view.Retry.ParkedReason != "dependency_exhausted" {
		t.Fatalf("parked_reason = %v, want dependency_exhausted", view.Retry.ParkedReason)
	}
	if view.Retry.RetryAt == nil || !view.Retry.RetryAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("retry_at = %v, want %v", view.Retry.RetryAt, now.Add(5*time.Minute))
	}
	if view.Retry.LastErrorClass == nil || *view.Retry.LastErrorClass != "transport_failure" {
		t.Fatalf("last_error_class = %v, want transport_failure", view.Retry.LastErrorClass)
	}
}

// TestSituationControllerViewIncludesTriageDueTimeAndCoveredDigests proves
// Task 9's own MCP-facing extension: each member Incident's Triage view now
// also carries its due time (next_at) and the covered digests (membership,
// Incident-input) the decision was made against.
func TestSituationControllerViewIncludesTriageDueTimeAndCoveredDigests(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	groupKey := "group-view-triage-digests"
	incID, deliveryID := "inc-view-triage-digests", "delivery-view-triage-digests"
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-view-triage-digests", now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, incID, "input-view-triage-digests", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var sitID string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&sitID); err != nil {
		t.Fatal(err)
	}

	nextAt := now.Add(2 * time.Minute)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, next_at, membership_digest, incident_input_digest, updated_at)
		VALUES (?, 'backoff', 1, ?, 'sha256:membership', 'sha256:incident-input', ?)`,
		incID, nextAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
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
	if got.NextAt == nil || !got.NextAt.Equal(nextAt) {
		t.Fatalf("next_at = %v, want %v", got.NextAt, nextAt)
	}
	if got.MembershipDigest == nil || *got.MembershipDigest != "sha256:membership" {
		t.Fatalf("membership_digest = %v, want sha256:membership", got.MembershipDigest)
	}
	if got.IncidentInputDigest == nil || *got.IncidentInputDigest != "sha256:incident-input" {
		t.Fatalf("incident_input_digest = %v, want sha256:incident-input", got.IncidentInputDigest)
	}
}

func TestSituationControllerViewUnknownSituationReturnsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	_, err := st.GetSituationControllerView(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
