// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

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
//
//nolint:unparam // id is a general fixture parameter; every current test happens to use "fact-1".
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

// TestAppendSituationFactsLaterObservedAtSameContentSucceeds is the Task 10
// replay finding's own regression test: DeriveStoreFacts (internal/situation/
// facts.go) sets every fact's ObservedAt fresh to "now" on EVERY call — so a
// genuine retry of Reconcile's own unconditional second step for an
// UNCHANGED input (a transient L2 failure, a stale-claim race, or a crash
// after this exact append but before the cycle's own CommitController ever
// runs) always re-derives byte-identical semantic content (same Digest) at
// a strictly LATER wall-clock instant. Before the fix, appendFactTx's own
// conflict check additionally compared observed_at, so this exact retry
// failed closed with ErrImmutableConflict every single time — permanently
// wedging the Situation, since AppendSituationFacts runs before every other
// failure mode Reconcile has. observed_at is bookkeeping, not content:
// Digest already carries the fact's real semantic identity, so a later
// observed_at on an otherwise-identical fact must succeed as a no-op,
// exactly like TestAppendSituationFactsIdempotentReplaySucceeds's own
// byte-identical replay — just discovered later.
func TestAppendSituationFactsLaterObservedAtSameContentSucceeds(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-facts-later-observed", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if err := st.AppendSituationFacts(context.Background(), claim, []situationmodel.Fact{factFixture("fact-1", sitID, 1, now)}); err != nil {
		t.Fatalf("first append: %v", err)
	}

	retried := factFixture("fact-1", sitID, 1, now.Add(20*time.Minute))
	if err := st.AppendSituationFacts(context.Background(), claim, []situationmodel.Fact{retried}); err != nil {
		t.Fatalf("retry append with a later observed_at (same digest/content): %v", err)
	}

	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_facts WHERE id = 'fact-1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("situation_facts rows for fact-1 = %d, want 1 (a later observed_at on an otherwise-identical fact must not duplicate)", count)
	}

	var storedObservedAt string
	if err := st.db.QueryRowContext(context.Background(), `SELECT observed_at FROM situation_facts WHERE id = 'fact-1'`).Scan(&storedObservedAt); err != nil {
		t.Fatal(err)
	}
	if want := canonicalTime(now); storedObservedAt != want {
		t.Fatalf("stored observed_at = %q, want the FIRST write's %q preserved (never overwritten by a later retry)", storedObservedAt, want)
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

// TestRecoverInterruptedAssessmentCallAdvancesBasisSoNextAttemptDoesNotCollide
// is the Task 10 regression test for the interrupted-call recovery bug: a
// crash landing after RecordAssessmentCall's own durable dispatch commit but
// before that cycle's CommitController ever runs used to leave
// current_material_fact_hash/controller_work_attempts at their pre-cycle
// values, so the NEXT real BeginControllerAttempt call (with the SAME,
// unchanged material hash) recomputed the EXACT SAME work_attempt=1 the
// immutable pre-crash situation_assessment_calls row already occupies —
// colliding on that table's own UNIQUE(situation_id, input_version,
// retry_epoch, work_attempt, call_number) index. This reproduces the
// collision scenario directly (dispatch a call, never commit, recover, call
// BeginControllerAttempt again) and asserts it now correctly continues the
// SAME attempt budget (work_attempt=2 — not a free reset to 1, and not a
// collision error), and that a real subsequent dispatch at those
// coordinates succeeds.
func TestRecoverInterruptedAssessmentCallAdvancesBasisSoNextAttemptDoesNotCollide(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-recover-collision", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	materialHash := "sha256:material-" + sitID
	_, workAttempt, err := st.BeginControllerAttempt(context.Background(), claim, materialHash, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt: %v", err)
	}
	if workAttempt != 1 {
		t.Fatalf("workAttempt = %d, want 1", workAttempt)
	}

	call := callFixture(uuid.NewString(), sitID, claim.Situation.InputVersion, workAttempt, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	// Simulate a crash: the process dies before this cycle's own
	// CommitController ever runs. The call is durably dispatched, but
	// current_material_fact_hash/controller_work_attempts are never
	// advanced. Expire the lease, exactly like the other recovery tests.
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

	// The next real cycle reclaims the Situation and calls
	// BeginControllerAttempt again with the SAME material hash (nothing
	// material changed): it must correctly continue the same attempt
	// budget (work_attempt=2), never collide with the immutable pre-crash
	// call at work_attempt=1, and never silently reset to 1 either (that
	// would grant the crashed cycle's own wasted slot back for free).
	reclaim := claimSituation(t, st, sitID, "controller-b", now.Add(time.Minute))
	retryEpoch2, workAttempt2, err := st.BeginControllerAttempt(context.Background(), reclaim, materialHash, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("BeginControllerAttempt after recovery: %v", err)
	}
	if workAttempt2 != 2 {
		t.Fatalf("workAttempt after recovery = %d, want 2 (continue the same attempt budget, not a free reset to 1, and not a collision)", workAttempt2)
	}

	// A real subsequent dispatch at these coordinates must not collide with
	// situation_assessment_calls' own UNIQUE index.
	call2 := call
	call2.ID = uuid.NewString()
	call2.RetryEpoch = retryEpoch2
	call2.WorkAttempt = workAttempt2
	if err := st.RecordAssessmentCall(context.Background(), reclaim, call2); err != nil {
		t.Fatalf("record call after recovery: %v (want no UNIQUE-index collision)", err)
	}
}

// TestRecoverInterruptedAssessmentCallsCatchUpStaleBasisAfterResolvedRejectedOutcome
// covers the SAME underlying bug reached through a different door: a call
// whose own outcome DID get durably recorded for real (AppendAssessmentOutcome's
// own commit is separate from, and does not require, CommitController's) —
// but whose owning cycle's CommitController still never ran (crash landed
// between the outcome append and the projection commit). This call is never
// "orphaned" by loadOrphanedAssessmentCallsTx's own outcome-less definition
// (an attempt row DOES reference it), so it never turns into a
// process_interrupted failure and RecoverInterruptedAssessmentCalls' own
// returned count stays 0 — but the Situation's projection still needs the
// SAME basis catch-up (loadStaleControllerBasisTx) to avoid the identical
// UNIQUE-index collision on the next real BeginControllerAttempt call.
func TestRecoverInterruptedAssessmentCallsCatchUpStaleBasisAfterResolvedRejectedOutcome(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-recover-stale-basis", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	materialHash := "sha256:material-" + sitID
	_, workAttempt, err := st.BeginControllerAttempt(context.Background(), claim, materialHash, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt: %v", err)
	}

	call := callFixture(uuid.NewString(), sitID, claim.Situation.InputVersion, workAttempt, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	callID := call.ID
	started := situationmodel.ProviderRequestStartedTrue
	attempt := situation.AssessmentAttempt{
		ID: uuid.NewString(), SituationID: sitID, CallID: &callID,
		InputVersion: claim.Situation.InputVersion, WorkAttempt: workAttempt, Sequence: 1,
		Status:                 "rejected",
		ValidationErrors:       json.RawMessage(`["malformed_schema"]`),
		ProviderRequestStarted: &started,
		CreatedAt:              now, CompletedAt: now.Add(time.Second),
	}
	if err := st.AppendAssessmentOutcome(context.Background(), attempt); err != nil {
		t.Fatalf("append rejected outcome: %v", err)
	}

	// Simulate a crash strictly after the rejected outcome's own durable
	// commit, but before this cycle's own CommitController ever runs.
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET lease_expires_at = ? WHERE id = ?`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano), sitID); err != nil {
		t.Fatal(err)
	}

	recovered, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("recover interrupted assessment calls: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("recovered (orphaned count) = %d, want 0 (this call already has a real recorded outcome, so it is never orphaned)", recovered)
	}

	reclaim := claimSituation(t, st, sitID, "controller-b", now.Add(time.Minute))
	retryEpoch2, workAttempt2, err := st.BeginControllerAttempt(context.Background(), reclaim, materialHash, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("BeginControllerAttempt after recovery: %v", err)
	}
	if workAttempt2 != 2 {
		t.Fatalf("workAttempt after recovery = %d, want 2 (the stale-basis catch-up must still advance past the resolved-but-never-committed attempt)", workAttempt2)
	}

	call2 := call
	call2.ID = uuid.NewString()
	call2.RetryEpoch = retryEpoch2
	call2.WorkAttempt = workAttempt2
	call2.CallNumber = 1
	if err := st.RecordAssessmentCall(context.Background(), reclaim, call2); err != nil {
		t.Fatalf("record call after recovery: %v (want no UNIQUE-index collision)", err)
	}
}

// TestRecoverInterruptedAssessmentCallClearsStalePolicyParkOnBasisAdvance
// proves advanceControllerBasisForRecoveryTx's own park-clearing safety
// argument: a controller_parked_reason recorded against an OLDER basis is
// provably stale whenever an interrupted call exists for the SAME Situation
// (controllerParkBlocksDispatch would otherwise have prevented that call
// from ever being dispatched — see that function's doc comment). Without
// clearing it here, advancing current_material_fact_hash to the recovered
// call's own (new) basis would make the STALE park look like it freshly
// covers that new basis, wrongly re-blocking dispatch forever — a
// regression of controller.go's own Finding I1 invariant ("a park recorded
// against a DIFFERENT (older) basis no longer applies").
func TestRecoverInterruptedAssessmentCallClearsStalePolicyParkOnBasisAdvance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-recover-clears-park", now)

	// Seed a policy_rejected park recorded against an OLDER basis, as if a
	// prior (already-committed, non-crashed) cycle rejected the model's
	// proposal and parked permanently for that input.
	oldHash := "sha256:parked-basis"
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET controller_parked_at = ?, controller_parked_reason = ?, current_material_fact_hash = ?
		WHERE id = ?`, canonicalTime(now), situation.ParkedReasonPolicyRejected, oldHash, sitID); err != nil {
		t.Fatalf("seed stale park: %v", err)
	}

	// The basis genuinely changes (new material facts arrived), naturally
	// lifting the stale park (controller.go's own Finding I1 comment): a
	// real cycle proceeds to BeginControllerAttempt/dispatch exactly as if
	// it were never parked.
	claim := claimSituation(t, st, sitID, "controller-a", now)
	newHash := "sha256:material-" + sitID
	_, workAttempt, err := st.BeginControllerAttempt(context.Background(), claim, newHash, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt: %v", err)
	}
	if workAttempt != 1 {
		t.Fatalf("workAttempt = %d, want 1 (mismatched basis resets)", workAttempt)
	}
	call := callFixture(uuid.NewString(), sitID, claim.Situation.InputVersion, workAttempt, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record call: %v", err)
	}

	// Crash before this cycle's own CommitController ever runs — the stale
	// controller_parked_reason from before is left untouched in the DB.
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET lease_expires_at = ? WHERE id = ?`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano), sitID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatalf("recover interrupted assessment calls: %v", err)
	}

	var parkedReason, parkedAt, materialHash sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT controller_parked_reason, controller_parked_at, current_material_fact_hash FROM situations WHERE id = ?`, sitID).
		Scan(&parkedReason, &parkedAt, &materialHash); err != nil {
		t.Fatal(err)
	}
	if parkedReason.Valid {
		t.Fatalf("controller_parked_reason = %q, want cleared (any park present alongside an interrupted call is provably stale)", parkedReason.String)
	}
	if parkedAt.Valid {
		t.Fatalf("controller_parked_at = %q, want cleared", parkedAt.String)
	}
	if !materialHash.Valid || materialHash.String != newHash {
		t.Fatalf("current_material_fact_hash = %v, want %q (advanced to the recovered call's own basis)", materialHash, newHash)
	}

	// The next real cycle is no longer wrongly blocked by the (now-cleared)
	// stale park: BeginControllerAttempt succeeds and continues the SAME
	// attempt budget.
	reclaim := claimSituation(t, st, sitID, "controller-b", now.Add(time.Minute))
	_, workAttempt2, err := st.BeginControllerAttempt(context.Background(), reclaim, newHash, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("BeginControllerAttempt after recovery: %v", err)
	}
	if workAttempt2 != 2 {
		t.Fatalf("workAttempt after recovery = %d, want 2", workAttempt2)
	}
}

// TestRecoverInterruptedAssessmentCallDoesNotReExhaustFreshlyWokenSituation
// is the Task 10 fix round 3 regression test for Finding C1: the reviewer's
// own empirical probe that caught a Critical regression in loadStaleControllerBasisTx's
// now-removed "s.controller_work_attempts < c.work_attempt" disjunct. A
// Situation that genuinely exhausted its 5-attempt budget for one basis,
// then got dependency-parked, then WOKE via WakeDependencyRecoveredSituations
// (which resets controller_work_attempts to 0, bumps the epoch, and clears
// the park — while deliberately leaving current_material_fact_hash
// untouched, since a dependency-unavailability park has nothing to do with
// the input basis) must NOT have any of that undone by a
// RecoverInterruptedAssessmentCalls pass that runs immediately after, before
// any new dispatch occurs — even though the old (exhausted) call still sits
// at "same hash, counter behind" relative to the freshly-reset counter. The
// removed disjunct matched exactly this state and
// advanceControllerBasisForRecoveryTx's MAX(...) write silently restored
// controller_work_attempts back up to the OLD call's own work_attempt (5),
// permanently stranding the Situation exhausted and unparked.
func TestRecoverInterruptedAssessmentCallDoesNotReExhaustFreshlyWokenSituation(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-wake-then-recover", now)
	materialHash := "sha256:material-" + sitID

	// Reach a genuine exhausted state for materialHash: four ordinary
	// projection-only cycles, then a real 5th dispatch with a durably
	// recorded (non-orphaned) rejected outcome and a real commit closing
	// that cycle — establishing BOTH current_material_fact_hash =
	// materialHash and a real situation_assessment_calls row at
	// work_attempt=5 under that SAME hash, with no crash anywhere yet.
	for want := 1; want <= 4; want++ {
		c := claimSituation(t, st, sitID, "controller-a", now)
		if _, workAttempt := beginAttemptThenCommitProjectionOnly(t, st, c, materialHash, now); workAttempt != want {
			t.Fatalf("attempt %d: workAttempt = %d, want %d", want, workAttempt, want)
		}
	}
	finalClaim := claimSituation(t, st, sitID, "controller-a", now)
	_, workAttempt5, err := st.BeginControllerAttempt(context.Background(), finalClaim, materialHash, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt (5th): %v", err)
	}
	if workAttempt5 != 5 {
		t.Fatalf("workAttempt = %d, want 5", workAttempt5)
	}
	call := callFixture(uuid.NewString(), sitID, finalClaim.Situation.InputVersion, workAttempt5, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), finalClaim, call); err != nil {
		t.Fatalf("record 5th call: %v", err)
	}
	started := situationmodel.ProviderRequestStartedTrue
	outcome := situation.AssessmentAttempt{
		ID: uuid.NewString(), SituationID: sitID, CallID: &call.ID,
		InputVersion: finalClaim.Situation.InputVersion, WorkAttempt: workAttempt5, Sequence: 1,
		Status:                 "rejected",
		ValidationErrors:       json.RawMessage(`["dependency_unavailable"]`),
		ProviderRequestStarted: &started,
		CreatedAt:              now, CompletedAt: now.Add(time.Second),
	}
	if err := st.AppendAssessmentOutcome(context.Background(), outcome); err != nil {
		t.Fatalf("append 5th outcome: %v", err)
	}
	commit5 := situation.ControllerCommit{
		MaterialFactHash: materialHash, Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionObserve,
		NextAssessmentAt: now,
	}
	if err := st.CommitController(context.Background(), finalClaim, commit5); err != nil {
		t.Fatalf("commit 5th cycle: %v", err)
	}

	// Genuinely dependency-park it (mirrors what a real exhausted-attempts
	// dependency park would leave behind: controller_work_attempts=5,
	// controller_parked_reason=dependency).
	parkSituationTx(t, st, sitID, situation.ParkedReasonDependency, 1, now)

	woken, err := st.WakeDependencyRecoveredSituations(context.Background(), 2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("WakeDependencyRecoveredSituations: %v", err)
	}
	if woken != 1 {
		t.Fatalf("woken = %d, want 1", woken)
	}

	readState := func() (workAttempts int, parkedReason sql.NullString) {
		t.Helper()
		if err := st.db.QueryRowContext(context.Background(), `
			SELECT controller_work_attempts, controller_parked_reason FROM situations WHERE id = ?`, sitID).
			Scan(&workAttempts, &parkedReason); err != nil {
			t.Fatal(err)
		}
		return workAttempts, parkedReason
	}

	workAttempts, parkedReason := readState()
	if workAttempts != 0 {
		t.Fatalf("work_attempts after wake = %d, want 0 (reset)", workAttempts)
	}
	if parkedReason.Valid {
		t.Fatalf("parked_reason after wake = %v, want cleared", parkedReason)
	}

	// Simulate a restart happening immediately after the wake, before any
	// new dispatch occurs: zero actually-interrupted/orphaned calls exist
	// for this Situation (the only dispatched call already has a real
	// recorded outcome, so loadOrphanedAssessmentCallsTx's own
	// outcome-less definition never matches it either).
	recovered, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("recover interrupted assessment calls: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("recovered = %d, want 0 (no actually-interrupted calls exist for this situation)", recovered)
	}

	workAttempts, parkedReason = readState()
	if workAttempts != 0 {
		t.Fatalf("work_attempts after post-wake recovery pass = %d, want unchanged 0 (C1 regression: a recovery pass must not re-exhaust a freshly-woken situation)", workAttempts)
	}
	if parkedReason.Valid {
		t.Fatalf("parked_reason after post-wake recovery pass = %v, want unchanged nil (C1 regression: a recovery pass must not re-park a freshly-woken situation)", parkedReason)
	}
}

// TestControllerAttemptCrashFreeHashChangeAdvancesEpochAvoidingCollision is
// the Task 10 fix round 3 regression test for Finding I1: the bug `2e6fa67`
// targeted (a colliding situation_assessment_calls row) is also reachable
// with NO crash or restart at all. MaterialFactHash is time-derived (e.g.
// current_duration's DurationClass can cross a boundary between two
// ordinary reconcile cycles at the SAME input_version — see
// facts.go/snapshot.go), so two back-to-back NON-crashed cycles can each
// independently derive a different hash, both see sameBasis == false
// against the PRIOR cycle's own committed hash, and — before this fix round
// — both computed work_attempt=1 at the SAME retry_epoch (which
// BeginControllerAttempt never advanced), colliding on
// situation_assessment_calls' own UNIQUE(situation_id, input_version,
// retry_epoch, work_attempt, call_number) index exactly like the crash case
// did. This test reproduces the two-cycle sequence directly, with a real
// CommitController committing the first cycle's hash in between and NO
// crash/RecoverInterruptedAssessmentCalls call anywhere, and asserts the
// second call's returned retryEpoch differs from the first, and that
// dispatching a real RecordAssessmentCall for each (using the REAL
// retryEpoch/workAttempt values each call returned) succeeds for both
// without a UNIQUE-index collision.
func TestControllerAttemptCrashFreeHashChangeAdvancesEpochAvoidingCollision(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-begin-attempt-crash-free-epoch", now)

	claim := claimSituation(t, st, sitID, "controller-a", now)
	hash1 := "sha256:material-a"
	retryEpoch1, workAttempt1, err := st.BeginControllerAttempt(context.Background(), claim, hash1, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt (1st): %v", err)
	}
	if workAttempt1 != 1 {
		t.Fatalf("workAttempt1 = %d, want 1", workAttempt1)
	}

	call1 := callFixture(uuid.NewString(), sitID, claim.Situation.InputVersion, workAttempt1, 1, now)
	call1.MaterialFactHash = hash1
	call1.RetryEpoch = retryEpoch1
	if err := st.RecordAssessmentCall(context.Background(), claim, call1); err != nil {
		t.Fatalf("record call 1: %v", err)
	}
	commit1 := situation.ControllerCommit{
		MaterialFactHash: hash1, Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionObserve,
		NextAssessmentAt: now,
	}
	if err := st.CommitController(context.Background(), claim, commit1); err != nil {
		t.Fatalf("commit cycle 1: %v", err)
	}

	// A second, entirely NON-crashed cycle at the SAME input_version derives
	// a DIFFERENT material hash (e.g. a time-derived DurationClass boundary
	// crossed between two ordinary reconcile cycles). No crash, no
	// RecoverInterruptedAssessmentCalls call anywhere in this test.
	reclaim := claimSituation(t, st, sitID, "controller-b", now)
	hash2 := "sha256:material-b"
	retryEpoch2, workAttempt2, err := st.BeginControllerAttempt(context.Background(), reclaim, hash2, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt (2nd): %v", err)
	}
	if workAttempt2 != 1 {
		t.Fatalf("workAttempt2 = %d, want 1 (new basis resets the attempt budget)", workAttempt2)
	}
	if retryEpoch2 == retryEpoch1 {
		t.Fatalf("retryEpoch2 = %d, want different from retryEpoch1 = %d (I1: a crash-free basis transition at the same input_version must still get a fresh coordinate space)", retryEpoch2, retryEpoch1)
	}

	call2 := callFixture(uuid.NewString(), sitID, reclaim.Situation.InputVersion, workAttempt2, 1, now)
	call2.MaterialFactHash = hash2
	call2.RetryEpoch = retryEpoch2
	if err := st.RecordAssessmentCall(context.Background(), reclaim, call2); err != nil {
		t.Fatalf("record call 2: %v (want no UNIQUE-index collision against call 1)", err)
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

// loadOneSituationDeliveryForGroup is a minimal single-delivery,
// single-Incident LoadReconciliationInput round trip: it accepts one
// delivery (whose Alert labels the caller controls), links it to a fresh
// Incident/Situation, and returns the resulting snap.Deliveries[0].
func loadOneSituationDeliveryForGroup(t *testing.T, st *Store, groupKey string, fixture DeliveryInput, now time.Time) situation.Delivery {
	t.Helper()
	ctx := context.Background()
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{fixture}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	incID, inputID := "inc-"+groupKey, "input-"+groupKey
	insertIncidentAndDeliveryInput(t, st, incID, inputID, groupKey, fixture.ID, now)
	claim := claimOneInput(t, st, "seed:"+groupKey, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	var sitID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&sitID); err != nil {
		t.Fatalf("find situation for group %s: %v", groupKey, err)
	}
	controllerClaim := claimSituation(t, st, sitID, "controller:"+groupKey, now.Add(time.Minute))
	snap, err := st.LoadReconciliationInput(ctx, controllerClaim, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if len(snap.Deliveries) != 1 {
		t.Fatalf("snapshot deliveries = %+v, want exactly 1", snap.Deliveries)
	}
	return snap.Deliveries[0]
}

// TestLoadSituationDeliveriesThreadsAlertIDSeverityAndDrill proves Finding
// #1/#2's store-side fix: loadSituationDeliveriesTx now reads
// alert_deliveries.alert_id straight into Delivery.AlertID, and parses
// alert_deliveries.labels_json to extract the raw severity label and the
// Drill marker — the two pieces of data criticalAnchorEligible and
// MembershipDigest need that this task's SnapshotInput previously lacked.
func TestLoadSituationDeliveriesThreadsAlertIDSeverityAndDrill(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	fixture := deliveryFixture("delivery-critical-drill", "fp-critical-drill", now)
	fixture.Alert.Labels = map[string]string{
		"alertname":      "test",
		"severity":       "critical",
		DrillMarkerLabel: DrillMarkerValue,
	}
	accepted, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{fixture})
	if err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	wantAlertID := accepted[0].Alert.ID
	if wantAlertID == "" {
		t.Fatal("test setup invalid: accepted delivery has no alert id")
	}

	d := loadOneSituationDeliveryForGroup(t, st, "group-critical-drill", fixture, now)
	if d.AlertID != wantAlertID {
		t.Fatalf("AlertID = %q, want %q", d.AlertID, wantAlertID)
	}
	if d.Severity != "critical" {
		t.Fatalf("Severity = %q, want %q", d.Severity, "critical")
	}
	if !d.Drill {
		t.Fatal("Drill = false, want true for a delivery carrying the Drill marker label")
	}
}

// TestLoadSituationDeliveriesDefaultsSeverityAndDrillEmptyWhenLabelsAbsent
// proves the absence case: a delivery with no severity label and no Drill
// marker must read back Severity="" and Drill=false, never a parse failure
// or a manufactured value.
func TestLoadSituationDeliveriesDefaultsSeverityAndDrillEmptyWhenLabelsAbsent(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	fixture := deliveryFixture("delivery-no-severity", "fp-no-severity", now) // default labels: alertname, fp only
	d := loadOneSituationDeliveryForGroup(t, st, "group-no-severity", fixture, now)

	if d.Severity != "" {
		t.Fatalf("Severity = %q, want empty when no severity label is present", d.Severity)
	}
	if d.Drill {
		t.Fatal("Drill = true, want false when no Drill marker label is present")
	}
	if d.AlertID == "" {
		t.Fatal("AlertID must not be empty")
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

// basicControllerCommit builds one minimal, schema-valid ControllerCommit
// for situationID/inputVersion: a fresh authoritative attempt (no call —
// deterministic_controller), no Triage decisions, active/observe, and a
// next_assessment_at one hour past now.
func basicControllerCommit(situationID string, inputVersion int, now time.Time) situation.ControllerCommit {
	assessment := validAssessmentFixture()
	basisHash := "sha256:basis-" + situationID
	materialHash := "sha256:material-" + situationID
	return situation.ControllerCommit{
		Attempt: situation.AssessmentAttempt{
			ID: uuid.NewString(), SituationID: situationID, AssessmentBasisHash: basisHash,
			InputVersion: inputVersion, WorkAttempt: 1,
			Derivation: situationmodel.DerivationDeterministic, Status: "authoritative",
			Validated:              mustMarshalJSON(nil, assessment),
			ProviderRequestStarted: providerRequestStartedPtr(situationmodel.ProviderRequestStartedFalse),
			CreatedAt:              now, CompletedAt: now,
		},
		Assessment:          assessment,
		MaterialFactHash:    materialHash,
		AssessmentBasisHash: basisHash,
		Lifecycle:           situationmodel.LifecycleActive,
		Attention:           situationmodel.AttentionObserve,
		NextAssessmentAt:    now.Add(time.Hour),
	}
}

// mustMarshalJSON accepts a nil t for the rare package-level fixture built
// outside any test function (see its own nil call site) — t.Helper() would
// nil-panic there, so it is called only when t is non-nil.
//
//nolint:thelper // t.Helper() is conditional by design: this helper also runs with a nil t.
func mustMarshalJSON(t *testing.T, v any) json.RawMessage {
	if t != nil {
		t.Helper()
	}
	b, err := json.Marshal(v)
	if err != nil {
		if t != nil {
			t.Fatalf("marshal %#v: %v", v, err)
		}
		panic(err)
	}
	return b
}

func providerRequestStartedPtr(p situationmodel.ProviderRequestStarted) *situationmodel.ProviderRequestStarted {
	return &p
}

// TestCommitControllerRejectsWorkAttemptZeroCheckConstraint is Finding C1's
// regression test: migration 0015's situation_assessment_attempts CHECK
// requires work_attempt BETWEEN 1 AND 5. Before the fix, controller.go's
// revalidated-reuse and deterministic-urgent-floor commits both passed
// workAttempt=0 — every one of those commits would have FAILED against this
// real schema, completely hidden by controller_test.go's fake store (which
// never enforces the CHECK at all). This reproduces the exact bug shape
// directly and proves the CHECK genuinely rejects it.
func TestCommitControllerRejectsWorkAttemptZeroCheckConstraint(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-workattempt-zero", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	commit.Attempt.WorkAttempt = 0 // the exact pre-fix bug shape (Finding C1).
	if err := st.CommitController(context.Background(), claim, commit); err == nil {
		t.Fatal("CommitController with work_attempt=0 succeeded, want a CHECK constraint failure (migration 0015: work_attempt BETWEEN 1 AND 5)")
	}
}

// TestCommitControllerClosedUnknownRequiresGraceUntilPairedWithRecoveryObservedAt
// is Finding C2's regression test: migration 0014's unconditional recovery-
// field pairing CHECK ((recovery_observed_at IS NULL) = (grace_until IS
// NULL)) rejects a closed_unknown commit that carries RecoveryObservedAt
// non-nil but GraceUntil nil — the exact shape resolveLifecycle's
// recovery_pending -> closed_unknown-via-deadline branch produced before the
// fix — and accepts the fixed shape (GraceUntil carried forward alongside
// it).
func TestCommitControllerClosedUnknownRequiresGraceUntilPairedWithRecoveryObservedAt(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	reason := situationmodel.TerminalReasonObservationDeadline

	sitBuggy := newSituationForGroup(t, st, "group-commit-c2-buggy", now)
	claimBuggy := claimSituation(t, st, sitBuggy, "controller-a", now)
	commitBuggy := basicControllerCommit(sitBuggy, claimBuggy.Situation.InputVersion, now)
	commitBuggy.Lifecycle = situationmodel.LifecycleClosedUnknown
	commitBuggy.RecoveryObservedAt = timePtrValue(now.Add(-time.Minute))
	commitBuggy.GraceUntil = nil // the exact pre-fix bug shape (Finding C2).
	commitBuggy.TerminalAt = timePtrValue(now)
	commitBuggy.TerminalReason = &reason
	if err := st.CommitController(context.Background(), claimBuggy, commitBuggy); err == nil {
		t.Fatal("CommitController with RecoveryObservedAt non-nil and GraceUntil nil for closed_unknown succeeded, want a CHECK constraint failure (migration 0014's recovery-field pairing CHECK)")
	}

	sitFixed := newSituationForGroup(t, st, "group-commit-c2-fixed", now)
	claimFixed := claimSituation(t, st, sitFixed, "controller-a", now)
	commitFixed := basicControllerCommit(sitFixed, claimFixed.Situation.InputVersion, now)
	commitFixed.Lifecycle = situationmodel.LifecycleClosedUnknown
	commitFixed.RecoveryObservedAt = timePtrValue(now.Add(-time.Minute))
	commitFixed.GraceUntil = timePtrValue(now.Add(time.Minute)) // carried forward — the fixed shape.
	commitFixed.TerminalAt = timePtrValue(now)
	commitFixed.TerminalReason = &reason
	if err := st.CommitController(context.Background(), claimFixed, commitFixed); err != nil {
		t.Fatalf("CommitController with the fixed (GraceUntil carried forward) shape: %v", err)
	}

	sit := getSituationByID(t, st, sitFixed)
	if sit.Lifecycle != situationmodel.LifecycleClosedUnknown {
		t.Fatalf("lifecycle = %q, want closed_unknown", sit.Lifecycle)
	}
	if sit.GraceUntil == nil {
		t.Fatal("grace_until must be persisted non-nil")
	}
}

// TestLoadReconciliationInputReadsControllerParkedState proves Finding I1's
// store-side read: LoadReconciliationInput surfaces controller_parked_at/
// controller_parked_reason/current_material_fact_hash as
// situation.ControllerParkedState — the data Reconcile needs to decide
// whether a policy/capability park still covers the current basis before
// dispatching new L2 work.
func TestLoadReconciliationInputReadsControllerParkedState(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-parked-read", now)

	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET controller_parked_at = ?, controller_parked_reason = ?, current_material_fact_hash = ?
		WHERE id = ?`, canonicalTime(now), situation.ParkedReasonPolicyRejected, "sha256:parked-basis", sitID); err != nil {
		t.Fatalf("seed parked state: %v", err)
	}

	claim := claimSituation(t, st, sitID, "controller-a", now)
	snap, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if snap.ControllerParked.Reason != situation.ParkedReasonPolicyRejected {
		t.Fatalf("parked reason = %q, want %q", snap.ControllerParked.Reason, situation.ParkedReasonPolicyRejected)
	}
	if snap.ControllerParked.MaterialFactHash != "sha256:parked-basis" {
		t.Fatalf("parked material fact hash = %q, want sha256:parked-basis", snap.ControllerParked.MaterialFactHash)
	}
	if snap.ControllerParked.At == nil || !snap.ControllerParked.At.Equal(now) {
		t.Fatalf("parked at = %v, want %v", snap.ControllerParked.At, now)
	}
}

// TestCommitControllerNextAssessmentAtAdvancesOnOrdinaryCommit proves the
// checkpoint actually moves into the future on a normal commit — a Situation
// is claimed BECAUSE next_assessment_at was already <= now (it was due), so
// naively taking min(current, proposed) against that stale claim-time value
// would pin next_assessment_at there forever (a proposed future checkpoint
// can never win a min() against an already-past one), reconciling the same
// Situation again on literally the next poll, forever.
func TestCommitControllerNextAssessmentAtAdvancesOnOrdinaryCommit(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-advances", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if !claim.Situation.NextAssessmentAt.Before(now) && !claim.Situation.NextAssessmentAt.Equal(now) {
		t.Fatalf("fixture invariant: claim.Situation.NextAssessmentAt = %v must be <= now = %v (the row was due)", claim.Situation.NextAssessmentAt, now)
	}

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	commit.NextAssessmentAt = now.Add(5 * time.Minute)
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	sit := getSituationByID(t, st, sitID)
	if !sit.NextAssessmentAt.Equal(commit.NextAssessmentAt) {
		t.Fatalf("next_assessment_at = %v, want the proposed future checkpoint %v (must not stay pinned to the stale claim-time due value)", sit.NextAssessmentAt, commit.NextAssessmentAt)
	}
}

func TestCommitControllerCommitsAuthoritativeAttemptAndProjection(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-real", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	sit := getSituationByID(t, st, sitID)
	if sit.LeaseOwner != nil {
		t.Fatalf("lease_owner = %v, want cleared after commit", sit.LeaseOwner)
	}
	if sit.Lifecycle != situationmodel.LifecycleActive || sit.Attention != situationmodel.AttentionObserve {
		t.Fatalf("lifecycle/attention = %s/%s, want active/observe", sit.Lifecycle, sit.Attention)
	}

	var currentAssessmentID, basisHash, materialHash sql.NullString
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT current_assessment_id, current_assessment_basis_hash, current_material_fact_hash FROM situations WHERE id = ?`, sitID).
		Scan(&currentAssessmentID, &basisHash, &materialHash); err != nil {
		t.Fatalf("read current assessment projection: %v", err)
	}
	if !currentAssessmentID.Valid || currentAssessmentID.String != commit.Attempt.ID {
		t.Fatalf("current_assessment_id = %v, want %s", currentAssessmentID, commit.Attempt.ID)
	}
	if basisHash.String != commit.AssessmentBasisHash || materialHash.String != commit.MaterialFactHash {
		t.Fatalf("current hashes = %s/%s, want %s/%s", basisHash.String, materialHash.String, commit.AssessmentBasisHash, commit.MaterialFactHash)
	}

	var status string
	if err := st.db.QueryRowContext(context.Background(), `SELECT status FROM situation_assessment_attempts WHERE id = ?`, commit.Attempt.ID).Scan(&status); err != nil {
		t.Fatalf("read inserted attempt: %v", err)
	}
	if status != "authoritative" {
		t.Fatalf("status = %q, want authoritative", status)
	}
}

func TestCommitControllerReplayWithSameStaleClaimFailsClosedNeverDoubleApplies(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-idempotent", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)
	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)

	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	// A caller that could not observe the first commit's own success (e.g.
	// a crash between tx.Commit() returning and the result reaching
	// Reconcile) and retries with the EXACT SAME now-stale claim must never
	// silently double-apply: the first commit already cleared the lease, so
	// this fails closed with ErrSituationLeaseLost rather than either
	// re-succeeding or corrupting the already-committed row.
	err := st.CommitController(context.Background(), claim, commit)
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("replay with stale claim err = %v, want ErrSituationLeaseLost", err)
	}

	// The projection from the FIRST commit must still stand, untouched.
	var status string
	if err := st.db.QueryRowContext(context.Background(), `SELECT status FROM situation_assessment_attempts WHERE id = ?`, commit.Attempt.ID).Scan(&status); err != nil {
		t.Fatalf("read attempt after replay attempt: %v", err)
	}
	if status != "authoritative" {
		t.Fatalf("status = %q, want authoritative (unchanged by the rejected replay)", status)
	}
}

func TestCommitControllerSubtractsOnlyClaimedDueReasonsPreservingConcurrentOnes(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-due-reasons", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if len(claim.Situation.DueReasons) == 0 {
		t.Fatal("fixture must claim at least one due reason")
	}

	// Between claim and commit, a concurrent input adds a new due reason and
	// an earlier checkpoint — simulated directly via mergeSituationDueReasonTx
	// and a manual next_assessment_at pull-forward, without touching the
	// claim's own consumed set or its lease (a real concurrent
	// ApplySituationInput would also clear the lease, which this test
	// deliberately avoids so CommitController's OWN fence still passes —
	// the due-reasons/checkpoint survival behavior is what this test
	// isolates, not the lease-loss case TestCommitControllerFencesOn* below
	// already covers).
	ctx := context.Background()
	if err := mergeSituationDueReasonTx2(t, st, sitID, situationmodel.DueOperatorJudgment); err != nil {
		t.Fatalf("merge concurrent due reason: %v", err)
	}
	earlierCheckpoint := now.Add(-time.Minute)
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET next_assessment_at = ? WHERE id = ?`, canonicalTime(earlierCheckpoint), sitID); err != nil {
		t.Fatalf("pull checkpoint earlier: %v", err)
	}

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	commit.ConsumedDueReasons = claim.Situation.DueReasons
	commit.NextAssessmentAt = now.Add(time.Hour) // proposed LATER than the concurrently-persisted earlier checkpoint.

	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	sit := getSituationByID(t, st, sitID)
	foundConcurrent := false
	for _, r := range sit.DueReasons {
		if r == situationmodel.DueOperatorJudgment {
			foundConcurrent = true
		}
		for _, consumed := range claim.Situation.DueReasons {
			if r == consumed {
				t.Fatalf("claimed due reason %q survived; must have been subtracted", r)
			}
		}
	}
	if !foundConcurrent {
		t.Fatal("concurrently-added due reason must survive the commit")
	}
	if !sit.NextAssessmentAt.Equal(earlierCheckpoint) {
		t.Fatalf("next_assessment_at = %v, want the earlier concurrently-persisted checkpoint %v preserved", sit.NextAssessmentAt, earlierCheckpoint)
	}
}

// mergeSituationDueReasonTx2 is a test-local wrapper calling the package's
// own mergeSituationDueReasonTx via a fresh transaction (that function is
// tx-scoped, unexported, and otherwise only reachable from inside another
// store method).
func mergeSituationDueReasonTx2(t *testing.T, st *Store, situationID string, reason situationmodel.DueReason) error {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := mergeSituationDueReasonTx(ctx, tx, situationID, reason, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func TestCommitControllerFailsClosedOnConcurrentInputVersionBump(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-commit-concurrent-input", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	// A concurrent Situation input applies (a second Incident/delivery
	// joining the same group), bumping input_version and clearing the lease
	// — exactly ApplySituationInput's own joinSituationTx behavior.
	newSituationForGroupSecondMember(t, st, "group-commit-concurrent-input", now)

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	err := st.CommitController(context.Background(), claim, commit)
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("stale claim commit err = %v, want ErrSituationLeaseLost (lease cleared by the concurrent input)", err)
	}

	// The newer input's own due reason remains due — nothing from the
	// failed commit clobbered it.
	sit := getSituationByID(t, st, sitID)
	if sit.InputVersion <= claim.Situation.InputVersion {
		t.Fatalf("input_version = %d, want > claimed %d", sit.InputVersion, claim.Situation.InputVersion)
	}
	if len(sit.DueReasons) == 0 {
		t.Fatal("the newer input's own due reason must remain due")
	}
}

// newSituationForGroupSecondMember attaches one more fresh Incident/delivery
// to groupKey's existing nonterminal Situation via a real
// insertIncidentAndInput + ApplySituationInput round trip — simulating a
// concurrent Situation input landing between claim and commit.
func newSituationForGroupSecondMember(t *testing.T, st *Store, groupKey string, now time.Time) {
	t.Helper()
	incID, inputID := "inc2-"+groupKey, "input2-"+groupKey
	insertIncidentAndInput(t, st, incID, inputID, groupKey, now.Add(time.Minute))
	claim := claimOneInput(t, st, "concurrent:"+groupKey, now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("apply concurrent situation input for group %s: %v", groupKey, err)
	}
}

// ----------------------------------------------------------------------
// BeginControllerAttempt
// ----------------------------------------------------------------------

func TestControllerAttemptFirstCallStartsAtOne(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-begin-attempt", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	retryEpoch, workAttempt, err := st.BeginControllerAttempt(context.Background(), claim, "sha256:material-x", now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt: %v", err)
	}
	if retryEpoch != 0 {
		t.Fatalf("retryEpoch = %d, want 0", retryEpoch)
	}
	if workAttempt != 1 {
		t.Fatalf("workAttempt = %d, want 1", workAttempt)
	}
}

// beginAttemptThenCommitProjectionOnly simulates one full Reconcile cycle's
// worth of durable state advancement for these BeginControllerAttempt
// tests: BeginControllerAttempt (the real call under test), then a MINIMAL
// projection-only commit (Attempt zero value — no new authoritative row,
// exactly a "still working this input" cycle) that persists
// current_material_fact_hash and leaves the Situation immediately due again
// (NextAssessmentAt=now) so the test's next round can reclaim it. Mirrors
// how a real Reconcile cycle always pairs BeginControllerAttempt with
// exactly one later CommitController call — see BeginControllerAttempt's
// own doc comment on why current_material_fact_hash is read-only there.
func beginAttemptThenCommitProjectionOnly(t *testing.T, st *Store, claim situation.Claim, materialFactHash string, now time.Time) (retryEpoch, workAttempt int) {
	t.Helper()
	retryEpoch, workAttempt, err := st.BeginControllerAttempt(context.Background(), claim, materialFactHash, now)
	if err != nil {
		t.Fatalf("BeginControllerAttempt: %v", err)
	}
	commit := situation.ControllerCommit{
		MaterialFactHash: materialFactHash, Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionObserve,
		NextAssessmentAt: now,
	}
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("projection-only commit: %v", err)
	}
	return retryEpoch, workAttempt
}

func TestControllerAttemptSameBasisIncrementsUpToFiveThenExhausts(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-begin-attempt-exhaust", now)

	for want := 1; want <= 5; want++ {
		claim := claimSituation(t, st, sitID, "controller-a", now)
		_, got := beginAttemptThenCommitProjectionOnly(t, st, claim, "sha256:material-y", now)
		if got != want {
			t.Fatalf("attempt %d: workAttempt = %d, want %d", want, got, want)
		}
	}

	claim := claimSituation(t, st, sitID, "controller-a", now)
	_, _, err := st.BeginControllerAttempt(context.Background(), claim, "sha256:material-y", now)
	if !errors.Is(err, situation.ErrControllerAttemptsExhausted) {
		t.Fatalf("6th attempt err = %v, want ErrControllerAttemptsExhausted", err)
	}

	// Never dispatch call 11: repeated exhausted calls never advance past 5
	// or reset silently.
	_, _, err = st.BeginControllerAttempt(context.Background(), claim, "sha256:material-y", now)
	if !errors.Is(err, situation.ErrControllerAttemptsExhausted) {
		t.Fatalf("7th attempt err = %v, want ErrControllerAttemptsExhausted (must stay exhausted)", err)
	}
}

func TestControllerAttemptNewMaterialHashResetsToOne(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-begin-attempt-reset", now)

	claim := claimSituation(t, st, sitID, "controller-a", now)
	if _, workAttempt := beginAttemptThenCommitProjectionOnly(t, st, claim, "sha256:material-a", now); workAttempt != 1 {
		t.Fatalf("first attempt workAttempt = %d, want 1", workAttempt)
	}

	reclaim := claimSituation(t, st, sitID, "controller-b", now)
	if _, workAttempt := beginAttemptThenCommitProjectionOnly(t, st, reclaim, "sha256:material-a", now); workAttempt != 2 {
		t.Fatalf("same-hash continuation workAttempt = %d, want 2", workAttempt)
	}

	reclaim2 := claimSituation(t, st, sitID, "controller-c", now)
	if _, workAttempt := beginAttemptThenCommitProjectionOnly(t, st, reclaim2, "sha256:material-b", now); workAttempt != 1 {
		t.Fatalf("new-hash reset workAttempt = %d, want 1", workAttempt)
	}
}

// ----------------------------------------------------------------------
// LastTrustworthyAssessment
// ----------------------------------------------------------------------

func TestLastTrustworthyAssessmentReturnsNilWhenNoneExists(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-last-trustworthy-none", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	got, err := st.LastTrustworthyAssessment(context.Background(), claim)
	if err != nil {
		t.Fatalf("LastTrustworthyAssessment: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v, want nil", got)
	}
}

func TestLastTrustworthyAssessmentSkipsFallback(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-last-trustworthy-fallback", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	commit.Attempt.Derivation = situationmodel.DerivationDeterministicFallback
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("commit fallback: %v", err)
	}

	got, err := st.LastTrustworthyAssessment(context.Background(), claim)
	if err != nil {
		t.Fatalf("LastTrustworthyAssessment: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v, want nil (a fallback is never a trustworthy source)", got)
	}
}

func TestLastTrustworthyAssessmentFindsModelValidated(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-last-trustworthy-found", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	call := callFixture(uuid.NewString(), sitID, claim.Situation.InputVersion, 1, 1, now)
	if err := st.RecordAssessmentCall(context.Background(), claim, call); err != nil {
		t.Fatalf("record assessment call: %v", err)
	}

	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now)
	commit.Attempt.Derivation = situationmodel.DerivationModelValidated
	commit.Attempt.CallID = &call.ID // model_validated requires a linked call_id (migration 0015's own CHECK).
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("commit model_validated: %v", err)
	}

	got, err := st.LastTrustworthyAssessment(context.Background(), claim)
	if err != nil {
		t.Fatalf("LastTrustworthyAssessment: %v", err)
	}
	if got == nil || got.ID != commit.Attempt.ID {
		t.Fatalf("got = %+v, want the model_validated attempt %s", got, commit.Attempt.ID)
	}
}

// ----------------------------------------------------------------------
// ClaimControllerWork / ExtendControllerLease / ReleaseControllerWork
// ----------------------------------------------------------------------

func TestClaimControllerWorkReturnsFencedClaims(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-claim-work", now)

	claims, err := st.ClaimControllerWork(context.Background(), "worker-1", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("ClaimControllerWork: %v", err)
	}
	found := false
	for _, c := range claims {
		if c.Situation.ID == sitID {
			found = true
			if c.ClaimOwner != "worker-1" || c.ClaimToken <= 0 {
				t.Fatalf("claim = %+v, want owner=worker-1 and a positive claim token", c)
			}
		}
	}
	if !found {
		t.Fatalf("situation %s not among %d claimed controller work items", sitID, len(claims))
	}
}

func TestExtendControllerLeaseRenewsAndFencesOnStaleToken(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-extend-lease", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if err := st.ExtendControllerLease(context.Background(), claim, now.Add(time.Minute), time.Minute); err != nil {
		t.Fatalf("ExtendControllerLease: %v", err)
	}

	stale := claim
	stale.ClaimToken = claim.ClaimToken + 1000
	err := st.ExtendControllerLease(context.Background(), stale, now.Add(2*time.Minute), time.Minute)
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("extend with stale token err = %v, want ErrSituationLeaseLost", err)
	}
}

func TestReleaseControllerWorkReleasesLease(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-release-work", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if err := st.ReleaseControllerWork(context.Background(), claim, now, nil, nil); err != nil {
		t.Fatalf("ReleaseControllerWork: %v", err)
	}
	sit := getSituationByID(t, st, sitID)
	if sit.LeaseOwner != nil {
		t.Fatalf("lease_owner = %v, want nil after release", sit.LeaseOwner)
	}
}

// TestReleaseControllerWorkWithBackoffPushesCheckpointForward proves Finding
// I2's store-level fix: releasing with a non-nil retryAt clears the lease AND
// pushes next_assessment_at/retry_at forward and records errorClass, so the
// row is not instantly re-claimable — without this, a persistently-failing
// Situation would spin ControllerWorker.Drain at 100% CPU.
func TestReleaseControllerWorkWithBackoffPushesCheckpointForward(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-release-work-backoff", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	if !claim.Situation.NextAssessmentAt.Before(now) && !claim.Situation.NextAssessmentAt.Equal(now) {
		t.Fatalf("fixture invariant: claim.Situation.NextAssessmentAt = %v must be <= now = %v (the row was due)", claim.Situation.NextAssessmentAt, now)
	}

	retryAt := now.Add(30 * time.Second)
	errClass := "controller_reconcile_failed"
	if err := st.ReleaseControllerWork(context.Background(), claim, now, &retryAt, &errClass); err != nil {
		t.Fatalf("ReleaseControllerWork with backoff: %v", err)
	}

	sit := getSituationByID(t, st, sitID)
	if sit.LeaseOwner != nil {
		t.Fatalf("lease_owner = %v, want nil after release", sit.LeaseOwner)
	}
	if sit.RetryAt == nil || !sit.RetryAt.Equal(retryAt) {
		t.Fatalf("retry_at = %v, want %v", sit.RetryAt, retryAt)
	}
	if sit.LastErrorClass == nil || *sit.LastErrorClass != errClass {
		t.Fatalf("last_error_class = %v, want %q", sit.LastErrorClass, errClass)
	}
	if !sit.NextAssessmentAt.Equal(retryAt) {
		t.Fatalf("next_assessment_at = %v, want the pushed-forward backoff checkpoint %v (must not stay instantly due)", sit.NextAssessmentAt, retryAt)
	}
}

// TestReleaseControllerWorkWithBackoffPreservesConcurrentlyEarlierCheckpoint
// proves the backoff push never clobbers a genuinely earlier, concurrently
// persisted next_assessment_at (e.g. a fresh material input landing between
// claim and this release wants to be reprocessed SOONER, not later) — the
// same min-against-a-detected-concurrent-write rule CommitController's own
// next_assessment_at computation uses.
func TestReleaseControllerWorkWithBackoffPreservesConcurrentlyEarlierCheckpoint(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-release-work-concurrent", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	earlierCheckpoint := now.Add(-time.Minute)
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET next_assessment_at = ? WHERE id = ?`, canonicalTime(earlierCheckpoint), sitID); err != nil {
		t.Fatalf("pull checkpoint earlier (simulate a concurrent write): %v", err)
	}

	retryAt := now.Add(30 * time.Second) // proposed LATER than the concurrently-persisted earlier checkpoint.
	errClass := "controller_reconcile_failed"
	if err := st.ReleaseControllerWork(context.Background(), claim, now, &retryAt, &errClass); err != nil {
		t.Fatalf("ReleaseControllerWork with backoff: %v", err)
	}

	sit := getSituationByID(t, st, sitID)
	if !sit.NextAssessmentAt.Equal(earlierCheckpoint) {
		t.Fatalf("next_assessment_at = %v, want the earlier concurrently-persisted checkpoint %v preserved", sit.NextAssessmentAt, earlierCheckpoint)
	}
}

// ----------------------------------------------------------------------
// WakeDependencyRecoveredSituations
// ----------------------------------------------------------------------

//nolint:unparam // generation is a general fixture parameter; every current test happens to use 1.
func parkSituationTx(t *testing.T, st *Store, situationID, reason string, generation int64, now time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET controller_parked_at = ?, controller_parked_reason = ?,
			controller_work_attempts = 5, last_consumed_recovery_generation = ?, updated_at = ?
		WHERE id = ?`, canonicalTime(now), reason, generation, canonicalTime(now), situationID); err != nil {
		t.Fatalf("park situation %s: %v", situationID, err)
	}
}

func TestWakeDependencyRecoveredSituationsResetsExactlyDependencyParks(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	depParked := newSituationForGroup(t, st, "group-wake-dependency", now)
	parkSituationTx(t, st, depParked, situation.ParkedReasonDependency, 1, now)

	policyParked := newSituationForGroup(t, st, "group-wake-policy", now)
	parkSituationTx(t, st, policyParked, situation.ParkedReasonPolicyRejected, 1, now)

	woken, err := st.WakeDependencyRecoveredSituations(context.Background(), 2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("WakeDependencyRecoveredSituations: %v", err)
	}
	if woken != 1 {
		t.Fatalf("woken = %d, want 1", woken)
	}

	dep := getSituationByID(t, st, depParked)
	var retryEpoch, workAttempts int
	var parkedReason sql.NullString
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT controller_retry_epoch, controller_work_attempts, controller_parked_reason FROM situations WHERE id = ?`, depParked).
		Scan(&retryEpoch, &workAttempts, &parkedReason); err != nil {
		t.Fatalf("read woken situation: %v", err)
	}
	if retryEpoch != 1 {
		t.Fatalf("retry_epoch = %d, want 1", retryEpoch)
	}
	if workAttempts != 0 {
		t.Fatalf("work_attempts = %d, want 0 (reset)", workAttempts)
	}
	if parkedReason.Valid {
		t.Fatalf("parked_reason = %v, want cleared", parkedReason)
	}
	found := false
	for _, r := range dep.DueReasons {
		if r == situationmodel.DueRetry {
			found = true
		}
	}
	if !found {
		t.Fatal("retry_due must be merged into due_reasons")
	}

	// Policy park is never re-armed by dependency recovery.
	var policyParkedReason sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `SELECT controller_parked_reason FROM situations WHERE id = ?`, policyParked).Scan(&policyParkedReason); err != nil {
		t.Fatalf("read untouched policy park: %v", err)
	}
	if !policyParkedReason.Valid || policyParkedReason.String != situation.ParkedReasonPolicyRejected {
		t.Fatalf("policy park reason = %v, want unchanged %q", policyParkedReason, situation.ParkedReasonPolicyRejected)
	}
}

func TestWakeDependencyRecoveredSituationsRepeatedPollsInSameGenerationDoNotReset(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-wake-repeated", now)
	parkSituationTx(t, st, sitID, situation.ParkedReasonDependency, 1, now)

	first, err := st.WakeDependencyRecoveredSituations(context.Background(), 2, now)
	if err != nil || first != 1 {
		t.Fatalf("first wake = %d, %v, want 1, nil", first, err)
	}

	// Simulate a fresh work-bearing attempt already in progress for the
	// newly-opened epoch.
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET controller_work_attempts = 3 WHERE id = ?`, sitID); err != nil {
		t.Fatalf("simulate in-progress attempt: %v", err)
	}

	second, err := st.WakeDependencyRecoveredSituations(context.Background(), 2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("second wake: %v", err)
	}
	if second != 0 {
		t.Fatalf("second wake in the SAME generation = %d, want 0 (must not reopen)", second)
	}

	var workAttempts int
	if err := st.db.QueryRowContext(context.Background(), `SELECT controller_work_attempts FROM situations WHERE id = ?`, sitID).Scan(&workAttempts); err != nil {
		t.Fatalf("read work attempts: %v", err)
	}
	if workAttempts != 3 {
		t.Fatalf("work_attempts = %d, want unchanged 3 (repeated poll in same generation must not reset counters)", workAttempts)
	}
}

// ----------------------------------------------------------------------
// Bounded views (situation_views_test.go covers GetSituationControllerView
// directly; this file's coverage stays scoped to situation_controller.go).
// ----------------------------------------------------------------------
