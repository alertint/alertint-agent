// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"testing"
	"time"

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
