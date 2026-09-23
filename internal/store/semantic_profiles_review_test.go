// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// signatureKeyOf reads deliveryID's attached signature key, failing the test
// when the delivery has no mapping.
func signatureKeyOf(t *testing.T, st *Store, deliveryID string) string {
	t.Helper()
	key, _, _, found := getDeliverySignature(t, st, deliveryID)
	if !found {
		t.Fatalf("delivery %s has no semantic signature mapping", deliveryID)
	}
	return key
}

// correctProfileForSignature lands one operator correction for signatureKey
// at expectedVersion, enqueueing exactly one head-change outbox row.
func correctProfileForSignature(t *testing.T, st *Store, signatureKey string, expectedVersion int, now time.Time) {
	t.Helper()
	correction := profilemodel.Correction{
		Signature: signatureKey, ExpectedVersion: expectedVersion,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:review",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err != nil {
		t.Fatalf("CorrectSemanticProfile (expected version %d): %v", expectedVersion, err)
	}
}

// TestDeliverSemanticProfileChangesBumpsInputVersionExactlyOnce (F8): one
// head-change delivery advances the follower's input_version exactly once
// — a replayed fan-out call finds the (change, situation) delivery already
// recorded and bumps nothing — while a genuinely NEW head change bumps
// again.
func TestDeliverSemanticProfileChangesBumpsInputVersionExactlyOnce(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	deliveryID, situationID := signatureDeliveryFixture(t, st, "bump", "group-bump", now)
	key := signatureKeyOf(t, st, deliveryID)
	before := getSituationByID(t, st, situationID).InputVersion

	correctProfileForSignature(t, st, key, 0, now)
	if n, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100); err != nil || n != 1 {
		t.Fatalf("first fan-out = (%d, %v), want (1, nil)", n, err)
	}
	after := getSituationByID(t, st, situationID)
	if after.InputVersion != before+1 {
		t.Fatalf("input_version after fan-out = %d, want %d (bumped exactly once)", after.InputVersion, before+1)
	}
	if !hasDueReason(after.DueReasons, situationmodel.DueSemanticProfileChanged) {
		t.Fatal("expected the semantic_profile_changed due reason to be merged")
	}

	// Replay: nothing left for this change, and no second bump.
	if n, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100); err != nil || n != 0 {
		t.Fatalf("replayed fan-out = (%d, %v), want (0, nil)", n, err)
	}
	if got := getSituationByID(t, st, situationID).InputVersion; got != before+1 {
		t.Fatalf("input_version after replay = %d, want unchanged %d", got, before+1)
	}

	// A NEW head change is a new invalidation.
	correctProfileForSignature(t, st, key, 1, now.Add(time.Minute))
	if n, err := st.DeliverSemanticProfileChanges(context.Background(), now.Add(time.Minute), 100); err != nil || n != 1 {
		t.Fatalf("second change fan-out = (%d, %v), want (1, nil)", n, err)
	}
	if got := getSituationByID(t, st, situationID).InputVersion; got != before+2 {
		t.Fatalf("input_version after second change = %d, want %d", got, before+2)
	}
}

// TestDeliverSemanticProfileChangesFencesStaleControllerCommit (F8): a
// controller that claimed the follower BEFORE the head change froze the
// old profile basis; the fan-out must invalidate that frozen input so its
// CommitController fails closed rather than committing the stale basis
// and consuming the semantic_profile_changed wake.
func TestDeliverSemanticProfileChangesFencesStaleControllerCommit(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	deliveryID, situationID := signatureDeliveryFixture(t, st, "fence", "group-fence", now)
	key := signatureKeyOf(t, st, deliveryID)

	claim := claimSituation(t, st, situationID, "controller-stale", now.Add(2*time.Minute))

	correctProfileForSignature(t, st, key, 0, now.Add(3*time.Minute))
	if n, err := st.DeliverSemanticProfileChanges(context.Background(), now.Add(3*time.Minute), 100); err != nil || n != 1 {
		t.Fatalf("fan-out = (%d, %v), want (1, nil)", n, err)
	}

	commit := basicControllerCommit(situationID, claim.Situation.InputVersion, now.Add(4*time.Minute))
	err := st.CommitController(context.Background(), claim, commit)
	if !errors.Is(err, situationmodel.ErrSituationLeaseLost) && !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("stale commit err = %v, want ErrSituationLeaseLost or ErrSituationVersionConflict (the frozen profile basis is invalid)", err)
	}
	sit := getSituationByID(t, st, situationID)
	if sit.InputVersion != claim.Situation.InputVersion+1 {
		t.Fatalf("input_version = %d, want %d", sit.InputVersion, claim.Situation.InputVersion+1)
	}
	if !hasDueReason(sit.DueReasons, situationmodel.DueSemanticProfileChanged) {
		t.Fatal("the semantic_profile_changed wake must survive the rejected stale commit")
	}
}

// ----------------------------------------------------------------------
// Plan 4 review round 1 — durable semantic-profile inference fixes.
// ----------------------------------------------------------------------

// exhaustJobByFinalReservation claims signatureKey's pending job and spends
// every reserved call without ever completing one, until the reservation
// itself marks the job exhausted — the "crash after the final reservation"
// shape, reproduced through the real claim/reserve surface.
func exhaustJobByFinalReservation(t *testing.T, st *Store, now time.Time) profilemodel.JobClaim {
	t.Helper()
	ctx := context.Background()
	claim, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-exhaust", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}
	for i := 0; i < defaultSemanticProfileMaxAttempts; i++ {
		if _, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now); err != nil {
			t.Fatalf("reserve %d: %v", i+1, err)
		}
	}
	if _, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now); !errors.Is(err, ErrSemanticInferenceAttemptsExhausted) {
		t.Fatalf("final reserve: got %v, want ErrSemanticInferenceAttemptsExhausted", err)
	}
	if status, _ := getJobStatus(t, st, claim.JobID); status != profilemodel.JobStateExhausted {
		t.Fatalf("status = %q, want exhausted", status)
	}
	return claim
}

// TestClaimSemanticInferenceJobReclaimsLeaseExpiredAfterStartup (F13): a
// job whose worker died AFTER startup (so RecoverSemanticInference never
// sees it) is reclaimed by the next ordinary claim once its lease expires —
// by another owner, with a fresh fencing token — while a still-live lease
// is left untouched.
func TestClaimSemanticInferenceJobReclaimsLeaseExpiredAfterStartup(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	seedPendingInferenceJob(t, st, "job-died-late", "sig:died-late", 3, nil, now)

	first, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-a", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("first claim: found=%v err=%v", found, err)
	}
	// worker-a never completes. Before the lease expires nobody else can
	// claim it.
	if _, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-b", now.Add(30*time.Second), time.Minute); err != nil || found {
		t.Fatalf("claim under a live lease = (found=%v, %v), want (false, nil)", found, err)
	}

	// Lease expired: an ordinary claim by another owner reclaims it — no
	// RecoverSemanticInference call in between.
	second, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim after lease expiry: found=%v err=%v", found, err)
	}
	if second.JobID != first.JobID {
		t.Fatalf("reclaimed job = %s, want %s", second.JobID, first.JobID)
	}
	if second.Owner != "worker-b" || second.Token <= first.Token {
		t.Fatalf("reclaim = owner %q token %d, want worker-b with a token above %d", second.Owner, second.Token, first.Token)
	}
	// The original holder is fenced out.
	if _, _, err := st.ReserveSemanticInferenceCall(ctx, first.JobID, first.Owner, first.Token, now.Add(2*time.Minute)); !errors.Is(err, profilemodel.ErrLeaseLost) {
		t.Fatalf("stale holder reserve err = %v, want ErrLeaseLost", err)
	}
}

func TestClaimSemanticInferenceJobKeepsLeaseUntilFractionalExpiry(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-lease-ns", "sig:lease-ns", 3, nil, now)
	first, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-a", now, time.Nanosecond)
	if err != nil || !found {
		t.Fatalf("first claim: found=%v err=%v", found, err)
	}
	if _, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-b", now, time.Minute); err != nil || found {
		t.Fatalf("lease reclaimed before expiry: found=%v err=%v", found, err)
	}
	second, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-b", now.Add(time.Nanosecond), time.Minute)
	if err != nil || !found || second.JobID != first.JobID || second.Token <= first.Token {
		t.Fatalf("lease not reclaimed at expiry: found=%v first=%+v second=%+v err=%v", found, first, second, err)
	}
}

// TestClaimSemanticInferenceJobExhaustsFinalReservationCrashOnReclaim
// (F13): a lease that expires after the job's LAST reserved call is
// recovered as exhausted by the claim path — exactly RecoverSemanticInference's
// own final-reservation rule — never handed out as pending again.
func TestClaimSemanticInferenceJobExhaustsFinalReservationCrashOnReclaim(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	seedPendingInferenceJob(t, st, "job-final-crash", "sig:final-crash", 1, nil, now)

	claim, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-a", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}
	if _, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now); err != nil {
		t.Fatalf("reserve the only attempt: %v", err)
	}
	// Crash: no completion; the lease expires.
	_, found, err = st.ClaimSemanticInferenceJob(ctx, "worker-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || found {
		t.Fatalf("claim after a final-reservation crash = (found=%v, %v), want (false, nil): nothing claimable", found, err)
	}
	status, ownerSet := getJobStatus(t, st, claim.JobID)
	if status != profilemodel.JobStateExhausted || ownerSet {
		t.Fatalf("status = %q ownerSet=%v, want exhausted with the lease released", status, ownerSet)
	}
}

// semanticJobRow is the bounded job-row projection the review tests below
// assert on.
type semanticJobRow struct {
	status             string
	attempt            int
	attemptBudget      int
	rearmedGeneration  int64
	errorClass         sql.NullString
	retryAt            sql.NullString
	ownerSet           bool
	frozenInputDigest  string
	maxAttemptsFrozen  int
	signatureKeyOfRow  string
	expectedHeadVerion int
}

func readSemanticJobRow(t *testing.T, st *Store, jobID string) semanticJobRow {
	t.Helper()
	var r semanticJobRow
	var owner sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT status, attempt, attempt_budget, rearmed_generation, error_class, retry_at, owner,
		       frozen_input_digest, max_attempts, signature_key, expected_head_version
		FROM semantic_profile_inference_jobs WHERE id = ?`, jobID).
		Scan(&r.status, &r.attempt, &r.attemptBudget, &r.rearmedGeneration, &r.errorClass, &r.retryAt, &owner,
			&r.frozenInputDigest, &r.maxAttemptsFrozen, &r.signatureKeyOfRow, &r.expectedHeadVerion); err != nil {
		t.Fatalf("read job %s: %v", jobID, err)
	}
	r.ownerSet = owner.Valid
	return r
}

// completeOneSemanticAttempt claims the one due job as owner, reserves one
// call, and completes it with outcome through the real dispatch surface.
func completeOneSemanticAttempt(t *testing.T, st *Store, owner string, now time.Time, outcome string) profilemodel.JobClaim {
	t.Helper()
	ctx := context.Background()
	claim, found, err := st.ClaimSemanticInferenceJob(ctx, owner, now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim as %s: found=%v err=%v", owner, found, err)
	}
	callID, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("reserve as %s: %v", owner, err)
	}
	result := profilemodel.InferenceResult{Outcome: outcome, RequestStarted: "unknown", PromptVersion: profilemodel.PromptVersion}
	if outcome == profilemodel.InferenceOutcomeAccepted {
		result.Profile = &profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		}
		result.RequestStarted = "true"
	}
	retryAt := now.Add(time.Minute)
	if _, err := st.CompleteSemanticInference(ctx, callID, claim.Owner, claim.Token, result, now, &retryAt); err != nil {
		t.Fatalf("complete as %s with %s: %v", owner, outcome, err)
	}
	return claim
}

// TestCompleteSemanticInferencePersistsTypedErrorClass (F14): every
// non-accepted completion persists its closed error class on the job — a
// transport failure is dependency-class, a malformed response is
// content-class — and a healthy completion clears it.
func TestCompleteSemanticInferencePersistsTypedErrorClass(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

	seedPendingInferenceJob(t, st, "job-class-dep", "sig:class-dep", 3, nil, now)
	claim := completeOneSemanticAttempt(t, st, "worker-a", now, profilemodel.InferenceOutcomeFailed)
	if r := readSemanticJobRow(t, st, claim.JobID); !r.errorClass.Valid || r.errorClass.String != profilemodel.ErrorClassDependency {
		t.Fatalf("error_class after a transport failure = %v, want %q", r.errorClass, profilemodel.ErrorClassDependency)
	}
	completeOneSemanticAttempt(t, st, "worker-b", now.Add(2*time.Minute), profilemodel.InferenceOutcomeMalformed)
	if r := readSemanticJobRow(t, st, claim.JobID); !r.errorClass.Valid || r.errorClass.String != profilemodel.ErrorClassContent {
		t.Fatalf("error_class after a malformed response = %v, want %q", r.errorClass, profilemodel.ErrorClassContent)
	}
	completeOneSemanticAttempt(t, st, "worker-c", now.Add(4*time.Minute), profilemodel.InferenceOutcomeAccepted)
	r := readSemanticJobRow(t, st, claim.JobID)
	if r.errorClass.Valid {
		t.Fatalf("error_class after an accepted completion = %q, want cleared", r.errorClass.String)
	}
	if r.status != profilemodel.JobStateComplete {
		t.Fatalf("status = %q, want complete", r.status)
	}
}

// TestRearmDependencyExhaustedSemanticJobsOncePerHealthyGeneration (F14):
// a dependency-exhausted job re-arms exactly once per newer durable
// healthy generation — one more full max_attempts of budget, immediately
// claimable — a replay within the same generation is a no-op, and a job
// that exhausts again waits for the NEXT generation.
func TestRearmDependencyExhaustedSemanticJobsOncePerHealthyGeneration(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	seedPendingInferenceJob(t, st, "job-rearm", "sig:rearm", 1, nil, now)

	claim := completeOneSemanticAttempt(t, st, "worker-a", now, profilemodel.InferenceOutcomeFailed)
	if r := readSemanticJobRow(t, st, claim.JobID); r.status != profilemodel.JobStateExhausted {
		t.Fatalf("status after the only attempt failed = %q, want exhausted", r.status)
	}
	if _, found, err := st.ClaimSemanticInferenceJob(ctx, "worker-b", now.Add(time.Minute), time.Minute); err != nil || found {
		t.Fatalf("claim of an exhausted job = (found=%v, %v), want (false, nil)", found, err)
	}

	// Generation 0 is never a recovery.
	if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 0, now.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("rearm at generation 0 = (%d, %v), want (0, nil)", n, err)
	}

	n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 1, now.Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("rearm at generation 1 = (%d, %v), want (1, nil)", n, err)
	}
	r := readSemanticJobRow(t, st, claim.JobID)
	if r.status != profilemodel.JobStatePending || r.ownerSet || r.retryAt.Valid {
		t.Fatalf("after rearm: status=%q ownerSet=%v retryAt=%v, want pending, no owner, no retry_at", r.status, r.ownerSet, r.retryAt)
	}
	if r.attemptBudget != 2 || r.maxAttemptsFrozen != 1 || r.rearmedGeneration != 1 {
		t.Fatalf("after rearm: attempt_budget=%d max_attempts=%d rearmed_generation=%d, want 2/1/1", r.attemptBudget, r.maxAttemptsFrozen, r.rearmedGeneration)
	}

	// Replay within the same generation: nothing to do, no double budget.
	if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 1, now.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("replayed rearm at generation 1 = (%d, %v), want (0, nil)", n, err)
	}
	if r := readSemanticJobRow(t, st, claim.JobID); r.attemptBudget != 2 {
		t.Fatalf("attempt_budget after replay = %d, want unchanged 2", r.attemptBudget)
	}

	// The re-armed job is claimable and spends its one extra attempt; a
	// second dependency failure exhausts it again for THIS generation.
	claim2 := completeOneSemanticAttempt(t, st, "worker-c", now.Add(3*time.Minute), profilemodel.InferenceOutcomeFailed)
	if claim2.JobID != claim.JobID || claim2.Attempt != 1 {
		t.Fatalf("re-armed claim = job %s attempt %d, want the same job at attempt 1", claim2.JobID, claim2.Attempt)
	}
	if r := readSemanticJobRow(t, st, claim.JobID); r.status != profilemodel.JobStateExhausted || r.attempt != 2 {
		t.Fatalf("after the extra attempt failed: status=%q attempt=%d, want exhausted/2", r.status, r.attempt)
	}
	if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 1, now.Add(4*time.Minute)); err != nil || n != 0 {
		t.Fatalf("rearm again at generation 1 = (%d, %v), want (0, nil): one rearm per generation", n, err)
	}
	if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 2, now.Add(5*time.Minute)); err != nil || n != 1 {
		t.Fatalf("rearm at generation 2 = (%d, %v), want (1, nil)", n, err)
	}
	if r := readSemanticJobRow(t, st, claim.JobID); r.attemptBudget != 3 || r.rearmedGeneration != 2 || r.status != profilemodel.JobStatePending {
		t.Fatalf("after generation 2: attempt_budget=%d rearmed_generation=%d status=%q, want 3/2/pending", r.attemptBudget, r.rearmedGeneration, r.status)
	}
}

// TestRearmDependencyExhaustedSemanticJobsNeverTouchesContentExhaustion
// (F14): a job exhausted on malformed responses is content-class — the
// provider recovering is no evidence its answers will parse — so no
// healthy generation ever re-arms it.
func TestRearmDependencyExhaustedSemanticJobsNeverTouchesContentExhaustion(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	seedPendingInferenceJob(t, st, "job-content", "sig:content", 1, nil, now)
	claim := completeOneSemanticAttempt(t, st, "worker-a", now, profilemodel.InferenceOutcomeMalformed)

	for gen := int64(1); gen <= 3; gen++ {
		if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, gen, now.Add(time.Duration(gen)*time.Minute)); err != nil || n != 0 {
			t.Fatalf("rearm at generation %d = (%d, %v), want (0, nil) for content exhaustion", gen, n, err)
		}
	}
	r := readSemanticJobRow(t, st, claim.JobID)
	if r.status != profilemodel.JobStateExhausted || r.attemptBudget != 1 || r.rearmedGeneration != 0 {
		t.Fatalf("content-exhausted job = status %q budget %d rearmed_generation %d, want exhausted/1/0 (untouched)", r.status, r.attemptBudget, r.rearmedGeneration)
	}
	if !r.errorClass.Valid || r.errorClass.String != profilemodel.ErrorClassContent {
		t.Fatalf("error_class = %v, want %q", r.errorClass, profilemodel.ErrorClassContent)
	}
}

// TestRearmDependencyExhaustedSemanticJobsSkipsSignatureWithHead (F14): a
// dependency-exhausted job whose signature meanwhile gained a head (an
// operator correction) has nothing left to infer: it is stamped as
// considered for the generation, never re-armed into a stale call.
func TestRearmDependencyExhaustedSemanticJobsSkipsSignatureWithHead(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	seedPendingInferenceJob(t, st, "job-headed", "sig:headed", 1, nil, now)
	claim := completeOneSemanticAttempt(t, st, "worker-a", now, profilemodel.InferenceOutcomeFailed)
	correctProfileForSignature(t, st, "sig:headed", 0, now.Add(time.Minute))

	if n, err := st.RearmDependencyExhaustedSemanticJobs(ctx, 4, now.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("rearm with a head present = (%d, %v), want (0, nil)", n, err)
	}
	r := readSemanticJobRow(t, st, claim.JobID)
	if r.status != profilemodel.JobStateExhausted || r.attemptBudget != 1 {
		t.Fatalf("job with a head = status %q budget %d, want exhausted/1", r.status, r.attemptBudget)
	}
	if r.rearmedGeneration != 4 {
		t.Fatalf("rearmed_generation = %d, want 4 (considered once, never rescanned for this generation)", r.rearmedGeneration)
	}
}

// oversizeKeyDelivery builds one delivery carrying a label KEY one character
// past MaxSignatureKeyChars — signature material BuildSignature refuses
// permanently.
func oversizeKeyDelivery(id string, now time.Time) DeliveryInput {
	del := deliveryFixture(id, "fp-"+id, now)
	del.Alert.Labels[strings.Repeat("k", profilemodel.MaxSignatureKeyChars+1)] = "secret-value-never-persisted"
	return del
}

func countSignatureMisses(t *testing.T, st *Store, deliveryID string) (n int, reason string) {
	t.Helper()
	var r sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*), MAX(reason) FROM delivery_semantic_signature_misses WHERE delivery_id = ?`, deliveryID).Scan(&n, &r); err != nil {
		t.Fatalf("count misses for %s: %v", deliveryID, err)
	}
	return n, r.String
}

// TestBackfillActiveSemanticMappingsSettlesUnsupportedSignatureOnce (F22):
// a delivery whose signature cannot be built (a 257-character label key)
// is selected exactly once, durably recorded as a miss with a bounded
// reason class, and never reselected — two further backfill calls return
// 0, so a caller's drain loop terminates.
func TestBackfillActiveSemanticMappingsSettlesUnsupportedSignatureOnce(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	_, _ = signatureDeliveryFixture(t, st, "miss-seed", "group-miss", now)
	deliveryID := "delivery-miss-unattached"
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{oversizeKeyDelivery(deliveryID, now)}); err != nil {
		t.Fatalf("accept oversize-key delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		"inc-miss-seed", deliveryID, canonicalTime(now)); err != nil {
		t.Fatalf("attach unattached delivery to incident: %v", err)
	}

	first, err := st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	if first != 1 {
		t.Fatalf("first backfill settled = %d, want 1 (the miss is durable progress)", first)
	}
	if _, _, _, found := getDeliverySignature(t, st, deliveryID); found {
		t.Fatal("an unsupported signature must never produce a mapping row")
	}
	n, reason := countSignatureMisses(t, st, deliveryID)
	if n != 1 || reason != semanticprofile.SignatureMissKeyTooLong {
		t.Fatalf("misses = %d reason %q, want 1 with the bounded class %q", n, reason, semanticprofile.SignatureMissKeyTooLong)
	}
	if strings.Contains(reason, "secret-value") || strings.Contains(reason, "kkkk") {
		t.Fatalf("miss reason %q leaks label content", reason)
	}

	for i := 2; i <= 3; i++ {
		n, err := st.BackfillActiveSemanticMappings(ctx, now.Add(time.Duration(i)*time.Minute), 100)
		if err != nil {
			t.Fatalf("backfill call %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("backfill call %d settled = %d, want 0: a recorded miss is never reselected", i, n)
		}
	}
	if n, _ := countSignatureMisses(t, st, deliveryID); n != 1 {
		t.Fatalf("miss rows = %d, want exactly 1", n)
	}
}

// TestApplySituationInputRecordsUnsupportedSignatureMiss (F22, ingress
// half): the same unsupported delivery arriving through the real
// ApplySituationInput applies cleanly, records its miss, and is not picked
// up by the backfill afterwards.
func TestApplySituationInputRecordsUnsupportedSignatureMiss(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	deliveryID := "delivery-miss-ingress"
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{oversizeKeyDelivery(deliveryID, now)}); err != nil {
		t.Fatalf("accept oversize-key delivery: %v", err)
	}
	insertIncidentAndDeliveryInput(t, st, "inc-miss-ingress", "input-miss-ingress", "group-miss-ingress", deliveryID, now)
	claim := claimOneInput(t, st, "seed:miss-ingress", now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input with an unsupported signature: %v", err)
	}
	if n, reason := countSignatureMisses(t, st, deliveryID); n != 1 || reason != semanticprofile.SignatureMissKeyTooLong {
		t.Fatalf("misses after ingress = %d reason %q, want 1/%q", n, reason, semanticprofile.SignatureMissKeyTooLong)
	}
	if n, err := st.BackfillActiveSemanticMappings(ctx, now.Add(time.Minute), 100); err != nil || n != 0 {
		t.Fatalf("backfill after an ingress miss = (%d, %v), want (0, nil)", n, err)
	}
}

// TestApplySituationInputReusesExhaustedIdenticalJob (F6): once a
// signature's job is exhausted, the next delivery under the SAME signature
// and the SAME frozen semantic input must apply cleanly and reuse that job
// — never collide with UNIQUE(signature_key, frozen_input_digest) and roll
// back the owning Situation's own input application. The exhausted job
// stays exhausted: nothing here re-arms it.
func TestApplySituationInputReusesExhaustedIdenticalJob(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

	firstDelivery, _ := signatureDeliveryFixture(t, st, "exh-a", "group-exh-a", now)
	key, _, _, found := getDeliverySignature(t, st, firstDelivery)
	if !found {
		t.Fatal("expected a signature mapping for the first delivery")
	}
	claim := exhaustJobByFinalReservation(t, st, now)
	if claim.Signature != key {
		t.Fatalf("exhausted job signature = %q, want %q", claim.Signature, key)
	}

	// Same proven signal identity, same label/annotation schema: identical
	// signature AND identical frozen input digest.
	secondDelivery, _ := signatureDeliveryFixture(t, st, "exh-b", "group-exh-b", now.Add(time.Minute))
	key2, _, _, found := getDeliverySignature(t, st, secondDelivery)
	if !found || key2 != key {
		t.Fatalf("second delivery signature = %q found=%v, want the shared %q", key2, found, key)
	}
	if n := countInferenceJobs(t, st, key); n != 1 {
		t.Fatalf("job count = %d, want exactly 1 (the exhausted job is reused, never re-inserted)", n)
	}
	if status, _ := getJobStatus(t, st, claim.JobID); status != profilemodel.JobStateExhausted {
		t.Fatalf("status = %q, want the exhausted job left exhausted", status)
	}
}

// TestApplySituationInputMapsButNeverAdmitsUnderTerminalOwner (F27): a
// delivery resolved late against an Incident whose owning Situation already
// terminalized gets its immutable signature mapping — the delivery is real
// — but no missing-profile inference job is ever queued for it, since no
// nonterminal Situation could consume the profile.
func TestApplySituationInputMapsButNeverAdmitsUnderTerminalOwner(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	_, situationID := signatureDeliveryFixture(t, st, "term-seed", "group-term", now)
	terminalizeSituation(t, st, situationID, now.Add(time.Minute))

	// A late delivery under a DIFFERENT signature, attached to the same
	// Incident, so ApplySituationInput resolves the same (terminal) owner.
	deliveryID := "delivery-term-late"
	del := deliveryFixture(deliveryID, "fp-term-late", now.Add(2*time.Minute))
	del.Source = "zabbix"
	sigID, sigVersion := "item:late-under-terminal", "v7"
	del.SourceProvenance.SignalID = &sigID
	del.SourceProvenance.SignalVersion = &sigVersion
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept late delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		"inc-term-seed", deliveryID, canonicalTime(now.Add(2*time.Minute))); err != nil {
		t.Fatalf("attach late delivery to incident: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES ('input-term-late', 'idem:input-term-late', 'inc-term-seed', ?, 'membership_changed', 'group-term', ?, 'pending')`,
		deliveryID, canonicalTime(now.Add(2*time.Minute))); err != nil {
		t.Fatalf("insert late situation input: %v", err)
	}
	claim := claimOneInput(t, st, "seed:term-late", now.Add(3*time.Minute))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply late situation input under a terminal owner: %v", err)
	}

	key, _, _, found := getDeliverySignature(t, st, deliveryID)
	if !found {
		t.Fatal("expected the late delivery to be mapped: the delivery is real and immutable regardless of its owner's lifecycle")
	}
	if n := countInferenceJobs(t, st, key); n != 0 {
		t.Fatalf("job count = %d, want 0: a terminal-only attachment must never queue inference", n)
	}
}
