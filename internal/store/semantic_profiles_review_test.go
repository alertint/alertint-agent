// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

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
