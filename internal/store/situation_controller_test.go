// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixture helpers
// ----------------------------------------------------------------------

// newSituationForGroup seeds one fresh Situation for groupKey via a real
// insertIncidentAndInput + ApplySituationInput round trip (Task 7 machinery,
// already exercised by situations_test.go), and returns its id.
func newSituationForGroup(t *testing.T, st *Store, groupKey string, now time.Time) string {
	t.Helper()
	incID, inputID := "inc-"+groupKey, "input-"+groupKey
	insertIncidentAndInput(t, st, incID, inputID, groupKey, now)
	claim := claimOneInput(t, st, "seed:"+groupKey, now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("seed apply situation input for group %s: %v", groupKey, err)
	}
	var id string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&id); err != nil {
		t.Fatalf("find situation for group %s: %v", groupKey, err)
	}
	return id
}

// claimSituation claims situationID as owner via ClaimDueSituations and
// returns it as a situation.Claim, ready for the controller-facing store
// methods this file tests.
func claimSituation(t *testing.T, st *Store, situationID, owner string, now time.Time) situation.Claim {
	t.Helper()
	claims, err := st.ClaimDueSituations(context.Background(), owner, now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim due situations: %v", err)
	}
	for _, c := range claims {
		if c.ID == situationID {
			return situation.Claim{Situation: c, ClaimOwner: *c.LeaseOwner, ClaimToken: c.ClaimToken}
		}
	}
	t.Fatalf("situation %s not among %d claimed due situations", situationID, len(claims))
	return situation.Claim{}
}

// factFixture builds one valid, minimal situationmodel.Fact for situationID
// at inputVersion, keyed by id.
func factFixture(id, situationID string, inputVersion int, observedAt time.Time) situationmodel.Fact {
	return situationmodel.Fact{
		ID:           id,
		SituationID:  situationID,
		Kind:         "current_duration",
		Subject:      "situation",
		Digest:       "sha256:" + id,
		InputVersion: inputVersion,
		Value:        json.RawMessage(`{"class":"short"}`),
		ResultStatus: situationmodel.FactConfirmedValue,
		EvidenceRefs: nil,
		Material:     true,
		ObservedAt:   observedAt,
	}
}

// callFixture builds one valid situation.AssessmentCall dispatch row.
func callFixture(id, situationID string, inputVersion, workAttempt, callNumber int, dispatchedAt time.Time) situation.AssessmentCall {
	return situation.AssessmentCall{
		ID:               id,
		SituationID:      situationID,
		MaterialFactHash: "sha256:material-" + situationID,
		InputVersion:     inputVersion,
		RetryEpoch:       0,
		WorkAttempt:      workAttempt,
		CallNumber:       callNumber,
		DispatchedAt:     dispatchedAt,
	}
}

// ----------------------------------------------------------------------
// AppendSituationFacts
// ----------------------------------------------------------------------

func TestAppendSituationFactsIdempotentReplaySucceeds(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-facts-idem", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	facts := []situationmodel.Fact{factFixture("fact-1", sitID, 1, now)}
	if err := st.AppendSituationFacts(context.Background(), claim, facts); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := st.AppendSituationFacts(context.Background(), claim, facts); err != nil {
		t.Fatalf("replay append: %v", err)
	}

	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_facts WHERE id = 'fact-1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("situation_facts rows for fact-1 = %d, want 1 (idempotent replay must not duplicate)", count)
	}
}

func TestAppendSituationFactsConflictingContentFailsClosed(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-facts-conflict", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if err := st.AppendSituationFacts(context.Background(), claim, []situationmodel.Fact{factFixture("fact-1", sitID, 1, now)}); err != nil {
		t.Fatalf("first append: %v", err)
	}

	conflicting := factFixture("fact-1", sitID, 1, now)
	conflicting.Value = json.RawMessage(`{"class":"long"}`)
	err := st.AppendSituationFacts(context.Background(), claim, []situationmodel.Fact{conflicting})
	if !errors.Is(err, ErrImmutableConflict) {
		t.Fatalf("conflicting append = %v, want ErrImmutableConflict", err)
	}
}

func TestAppendSituationFactsFencedOnStaleClaim(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-facts-stale", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	// A same-group input arrives and joins the Situation, clearing the
	// controller's lease exactly like TestApplySituationInputClearsControllerLeaseFencingStaleRelease
	// proves for ReleaseSituationClaim.
	insertIncidentAndInput(t, st, "inc-facts-stale-2", "input-facts-stale-2", "group-facts-stale", now.Add(time.Minute))
	inputClaim := claimOneInput(t, st, "worker-a", now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), inputClaim); err != nil {
		t.Fatal(err)
	}

	err := st.AppendSituationFacts(context.Background(), claim, []situationmodel.Fact{factFixture("fact-1", sitID, 1, now)})
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("append after stale claim = %v, want ErrSituationLeaseLost", err)
	}
}

func TestAppendSituationFactsEmptySliceIsNoOp(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-facts-empty", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if err := st.AppendSituationFacts(context.Background(), claim, nil); err != nil {
		t.Fatalf("empty append: %v", err)
	}
}

// ----------------------------------------------------------------------
// RecordAssessmentCall
// ----------------------------------------------------------------------

func TestRecordAssessmentCallIdempotentAndClaimFenced(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-calls-idem", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("replay record: %v", err)
	}

	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_assessment_calls WHERE id = 'call-1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("situation_assessment_calls rows for call-1 = %d, want 1", count)
	}

	conflicting := call
	conflicting.MaterialFactHash = "sha256:different"
	if err := st.RecordAssessmentCall(context.Background(), claim, conflicting); !errors.Is(err, ErrImmutableConflict) {
		t.Fatalf("conflicting record = %v, want ErrImmutableConflict", err)
	}

	// Fencing: a stale claim (superseded claim_token) must not be able to
	// dispatch a new call.
	staleClaim := claim
	if _, err := st.ClaimDueSituations(context.Background(), "controller-b", now.Add(2*time.Minute), time.Minute, 10); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	err := st.RecordAssessmentCall(context.Background(), staleClaim, callFixture("call-2", sitID, 1, 1, 2, now))
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("record with stale claim = %v, want ErrSituationLeaseLost", err)
	}
}

// ----------------------------------------------------------------------
// AppendAssessmentOutcome
// ----------------------------------------------------------------------

func TestAppendAssessmentOutcomeSucceedsAfterClaimGoesObsolete(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-outcome-obsolete", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	// The claim/input becomes obsolete: a same-group input joins, clearing
	// the lease (mirrors TestAppendSituationFactsFencedOnStaleClaim).
	insertIncidentAndInput(t, st, "inc-outcome-obsolete-2", "input-outcome-obsolete-2", "group-outcome-obsolete", now.Add(time.Minute))
	inputClaim := claimOneInput(t, st, "worker-a", now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), inputClaim); err != nil {
		t.Fatal(err)
	}

	callID := "call-1"
	started := situationmodel.ProviderRequestStartedTrue
	attempt := situation.AssessmentAttempt{
		ID:                     "attempt-1",
		SituationID:            sitID,
		CallID:                 &callID,
		InputVersion:           1,
		RetryEpoch:             0,
		WorkAttempt:            1,
		Sequence:               1,
		Status:                 "rejected",
		ValidationErrors:       json.RawMessage(`["malformed_schema"]`),
		ProviderRequestStarted: &started,
		CreatedAt:              now,
		CompletedAt:            now.Add(time.Second),
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
		t.Fatalf("append outcome after claim went obsolete: %v", err)
	}

	var status, materialHash string
	if err := st.db.QueryRowContext(context.Background(), `SELECT status, material_fact_hash FROM situation_assessment_attempts WHERE id = 'attempt-1'`).
		Scan(&status, &materialHash); err != nil {
		t.Fatal(err)
	}
	if status != "rejected" {
		t.Fatalf("status = %q, want rejected", status)
	}
	if materialHash != call.MaterialFactHash {
		t.Fatalf("material_fact_hash = %q, want %q (derived from the dispatch call)", materialHash, call.MaterialFactHash)
	}

	// Replaying identical content succeeds.
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
		t.Fatalf("replay append outcome: %v", err)
	}

	// It changes no current pointer or projection.
	var currentAssessmentID *string
	if err := st.db.QueryRowContext(context.Background(), `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID).Scan(&currentAssessmentID); err != nil {
		t.Fatal(err)
	}
	if currentAssessmentID != nil {
		t.Fatalf("current_assessment_id = %v, want nil (a rejected outcome must never become current)", *currentAssessmentID)
	}
}

func TestAppendAssessmentOutcomeIdentityMismatchFailsClosed(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-outcome-mismatch", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	callID := "call-1"
	started := situationmodel.ProviderRequestStartedTrue
	attempt := situation.AssessmentAttempt{
		ID:                     "attempt-mismatch",
		SituationID:            sitID,
		CallID:                 &callID,
		InputVersion:           2, // does not match the dispatched call's input_version=1
		WorkAttempt:            1,
		Sequence:               1,
		Status:                 "failed",
		ProviderRequestStarted: &started,
		CreatedAt:              now,
		CompletedAt:            now.Add(time.Second),
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err == nil {
		t.Fatal("expected identity mismatch against the dispatched call to fail")
	}
}

func TestAppendAssessmentOutcomeRejectsAuthoritativeStatus(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-outcome-authoritative", now)

	callID := "call-1"
	started := situationmodel.ProviderRequestStartedTrue
	attempt := situation.AssessmentAttempt{
		ID: "attempt-1", SituationID: sitID, CallID: &callID,
		InputVersion: 1, WorkAttempt: 1, Sequence: 1,
		Status:                 "authoritative",
		ProviderRequestStarted: &started,
		CreatedAt:              now, CompletedAt: now,
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err == nil {
		t.Fatal("expected AppendAssessmentOutcome to reject a status='authoritative' attempt")
	}
}

// ----------------------------------------------------------------------
// Interrupted-call recovery
// ----------------------------------------------------------------------

func TestRecoverInterruptedAssessmentCallTurnsOrphanedDispatchIntoProcessInterruptedFailure(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-recover-orphan", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	// Simulate a crash: the claim's lease expires with no outcome recorded.
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET lease_expires_at = ? WHERE id = ?`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano), sitID); err != nil {
		t.Fatal(err)
	}

	recovered, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("recover interrupted assessment calls: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}

	var status, providerStarted, callIDGot string
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT status, provider_request_started, call_id FROM situation_assessment_attempts WHERE call_id = 'call-1'`).
		Scan(&status, &providerStarted, &callIDGot); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("recovered attempt status = %q, want failed", status)
	}
	if providerStarted != "unknown" {
		t.Fatalf("recovered attempt provider_request_started = %q, want unknown", providerStarted)
	}
	if callIDGot != "call-1" {
		t.Fatalf("recovered attempt call_id = %q, want call-1 (consumes its dispatch slot)", callIDGot)
	}

	// retry_due merged into the Situation's due reasons.
	sit := getSituationByID(t, st, sitID)
	found := false
	for _, r := range sit.DueReasons {
		if r == situationmodel.DueRetry {
			found = true
		}
	}
	if !found {
		t.Fatalf("due_reasons = %v, want retry_due merged in", sit.DueReasons)
	}

	// It is never redispatched for free: running recovery again finds
	// nothing new (the call now has a recorded outcome).
	recoveredAgain, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	if recoveredAgain != 0 {
		t.Fatalf("second recovery recovered = %d, want 0 (call-1 already has an outcome)", recoveredAgain)
	}
	var callCount int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_assessment_calls WHERE situation_id = ?`, sitID).Scan(&callCount); err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("dispatch call count = %d, want 1 (never re-dispatched)", callCount)
	}
}

func TestRecoverInterruptedAssessmentCallLeavesActivelyClaimedCallsUntouched(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-recover-active", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}
	// Lease is still active (not expired) — recovery must not touch this call.

	recovered, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(time.Second))
	if err != nil {
		t.Fatalf("recover interrupted assessment calls: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("recovered = %d, want 0 (call is under an active claim)", recovered)
	}
	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_assessment_attempts WHERE call_id = 'call-1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("attempt count for actively claimed call = %d, want 0", count)
	}
}

func TestRecoverInterruptedAssessmentCallExplicitFailureRecordsFalseNotUnknown(t *testing.T) {
	// Explicit pre-request failure (a genuine AppendAssessmentOutcome call
	// with provider_request_started=false) must persist "false", never be
	// reinterpreted as "unknown" by recovery — recovery only ever touches
	// outcome-less calls.
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-explicit-false", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture("call-1", sitID, 1, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	callID := "call-1"
	started := situationmodel.ProviderRequestStartedFalse
	attempt := situation.AssessmentAttempt{
		ID: "attempt-1", SituationID: sitID, CallID: &callID,
		InputVersion: 1, WorkAttempt: 1, Sequence: 1,
		Status:                 "failed",
		ProviderRequestStarted: &started,
		CreatedAt:              now, CompletedAt: now.Add(time.Second),
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
		t.Fatalf("append explicit pre-request failure: %v", err)
	}

	// Expire the lease and run recovery — the call already has an outcome,
	// so recovery must be a no-op and the recorded value must stay "false".
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET lease_expires_at = ? WHERE id = ?`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano), sitID); err != nil {
		t.Fatal(err)
	}
	recovered, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("recovered = %d, want 0 (call-1 already has an explicit outcome)", recovered)
	}

	var providerStarted string
	if err := st.db.QueryRowContext(context.Background(), `SELECT provider_request_started FROM situation_assessment_attempts WHERE call_id = 'call-1'`).
		Scan(&providerStarted); err != nil {
		t.Fatal(err)
	}
	if providerStarted != "false" {
		t.Fatalf("provider_request_started = %q, want false (explicit pre-request failure untouched by recovery)", providerStarted)
	}
}

// ----------------------------------------------------------------------
// LoadReconciliationInput
// ----------------------------------------------------------------------

func TestLoadReconciliationInputReadsCoherentSnapshot(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	groupKey := "group-reconcile"

	// A prior terminal Situation in the same exact-group lineage.
	if err := insertSituation(context.Background(), st, situationRow{
		id: "sit-prior", groupKey: groupKey, lifecycle: "recovered",
		recoveryObservedAt: now.Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano),
		graceUntil:         now.Add(-150 * time.Minute).UTC().Format(time.RFC3339Nano),
		terminalAt:         now.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("insert prior terminal situation: %v", err)
	}

	incID, deliveryID := "inc-reconcile", "delivery-reconcile"
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-reconcile", now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	insertIncidentAndDeliveryInput(t, st, incID, "input-reconcile", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var sitID string
	if err := st.db.QueryRowContext(context.Background(), `SELECT id FROM situations WHERE group_key = ? AND lifecycle IN ('active','recovery_pending')`, groupKey).Scan(&sitID); err != nil {
		t.Fatal(err)
	}

	// Seed a Triage schedule row and current Assessment for the member
	// Incident — insertIncidentAndDeliveryInput already marked it ready.
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at) VALUES (?, 'awaiting_decision', 0, ?)`,
		incID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed incident_triage: %v", err)
	}

	assessmentJSON, err := json.Marshal(validAssessmentFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, status, derivation,
			provider_request_started, material_fact_hash, assessment_json, created_at, completed_at
		) VALUES ('attempt-authoritative', ?, 1, 1, 1, 'authoritative', 'deterministic_controller', 'false', 'sha256:material', ?, ?, ?)`,
		sitID, string(assessmentJSON), now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed authoritative attempt: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET current_assessment_id = 'attempt-authoritative' WHERE id = ?`, sitID); err != nil {
		t.Fatalf("set current assessment pointer: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_coverage (assessment_attempt_id, incident_id, membership_digest, incident_input_digest)
		VALUES ('attempt-authoritative', ?, 'sha256:membership', 'sha256:incident-input')`, incID); err != nil {
		t.Fatalf("seed coverage: %v", err)
	}

	controllerClaim := claimSituation(t, st, sitID, "controller-a", now.Add(time.Minute))

	snap, err := st.LoadReconciliationInput(context.Background(), controllerClaim, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}

	if snap.Situation.ID != sitID {
		t.Fatalf("snapshot situation id = %s, want %s", snap.Situation.ID, sitID)
	}
	if !snap.Now.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("snapshot now = %v, want %v", snap.Now, now.Add(2*time.Minute))
	}
	if len(snap.Deliveries) != 1 || snap.Deliveries[0].ID != deliveryID {
		t.Fatalf("snapshot deliveries = %+v, want exactly the one member delivery", snap.Deliveries)
	}
	if snap.Deliveries[0].IncidentID != incID {
		t.Fatalf("delivery incident id = %s, want %s", snap.Deliveries[0].IncidentID, incID)
	}
	if len(snap.Incidents) != 1 || snap.Incidents[0].ID != incID {
		t.Fatalf("snapshot incidents = %+v, want exactly the one member incident", snap.Incidents)
	}
	if snap.Incidents[0].Triage.Phase != "awaiting_decision" {
		t.Fatalf("triage phase = %q, want awaiting_decision", snap.Incidents[0].Triage.Phase)
	}
	if len(snap.PriorSituations) != 1 || snap.PriorSituations[0].ID != "sit-prior" {
		t.Fatalf("prior situations = %+v, want exactly sit-prior", snap.PriorSituations)
	}
	if snap.CurrentAssessment == nil {
		t.Fatal("current assessment = nil, want the authoritative attempt")
	}
	if snap.CurrentAssessment.ID != "attempt-authoritative" {
		t.Fatalf("current assessment id = %s, want attempt-authoritative", snap.CurrentAssessment.ID)
	}
	if len(snap.CurrentAssessment.Coverage) != 1 || snap.CurrentAssessment.Coverage[0].IncidentID != incID {
		t.Fatalf("current assessment coverage = %+v, want exactly one tuple for %s", snap.CurrentAssessment.Coverage, incID)
	}
}

func TestLoadReconciliationInputUnknownSituationReturnsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	claim := situation.Claim{Situation: situationmodel.Situation{ID: "does-not-exist"}, ClaimOwner: "controller-a", ClaimToken: 1}
	_, err := st.LoadReconciliationInput(context.Background(), claim, time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// validAssessmentFixture builds one minimal, schema-valid model.Assessment
// for seeding an authoritative attempt row directly.
func validAssessmentFixture() situationmodel.Assessment {
	return situationmodel.Assessment{
		SchemaVersion:   situationmodel.AssessmentSchemaVersion,
		Persistence:     situationmodel.PersistenceUnknown,
		Impact:          situationmodel.ImpactUnknown,
		Novelty:         situationmodel.NoveltyInsufficientHistory,
		Causality:       situationmodel.CausalityUnknown,
		Attention:       situationmodel.AttentionObserve,
		Lifecycle:       situationmodel.LifecycleActive,
		EvidenceQuality: situationmodel.EvidenceQualityDegraded,
		Cadence:         situationmodel.CadenceSlow,
		ActionContract: situationmodel.ActionContract{
			NextActor:    situationmodel.NextActorNone,
			NextUpdateAt: timePtrValue(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)),
		},
	}
}

func timePtrValue(t time.Time) *time.Time { return &t }

// ----------------------------------------------------------------------
// CommitController — fencing skeleton
// ----------------------------------------------------------------------

func TestCommitControllerFencesOnLeaseOwnerMismatch(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-owner", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	staleClaim := claim
	staleClaim.ClaimOwner = "some-other-owner"
	err := st.CommitController(context.Background(), staleClaim, situation.ControllerCommit{})
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("commit with wrong owner = %v, want ErrSituationLeaseLost", err)
	}
}

func TestCommitControllerFencesOnInputVersionMismatch(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-version", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	staleClaim := claim
	staleClaim.Situation.InputVersion = claim.Situation.InputVersion + 1
	err := st.CommitController(context.Background(), staleClaim, situation.ControllerCommit{})
	if !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("commit with wrong input version = %v, want ErrSituationVersionConflict", err)
	}
}

func TestCommitControllerFencingPassesButDecisionCommitNotYetImplemented(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-honest", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	err := st.CommitController(context.Background(), claim, situation.ControllerCommit{})
	if err == nil {
		t.Fatal("expected CommitController to report it is not yet implemented, not silently succeed")
	}
	if errors.Is(err, situationmodel.ErrSituationLeaseLost) || errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("expected the fence to pass (a real claim/version), got fencing error: %v", err)
	}

	// It must not have committed anything.
	sit := getSituationByID(t, st, sitID)
	if sit.LeaseOwner == nil || *sit.LeaseOwner != "controller-a" {
		t.Fatalf("lease_owner = %v, want unchanged controller-a (CommitController must roll back)", sit.LeaseOwner)
	}
}

// ----------------------------------------------------------------------
// Bounded views (situation_views_test.go covers GetSituationControllerView
// directly; this file's coverage stays scoped to situation_controller.go).
// ----------------------------------------------------------------------
