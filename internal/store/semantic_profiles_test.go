// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// signatureDeliveryFixture builds one accepted delivery under groupKey with
// a proven (signal_id, signal_version) pair — the signal_version provenance
// mode — and attaches it to a fresh Situation via the real
// ApplySituationInput path, returning that Situation's id.
func signatureDeliveryFixture(t *testing.T, st *Store, id, groupKey string, now time.Time) (deliveryID, situationID string) {
	t.Helper()
	ctx := context.Background()
	deliveryID = "delivery-" + id
	del := deliveryFixture(deliveryID, "fp-"+id, now)
	del.Source = "zabbix"
	sigID, sigVersion := "item:123", "v2"
	del.SourceProvenance.SignalID = &sigID
	del.SourceProvenance.SignalVersion = &sigVersion
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery %s: %v", deliveryID, err)
	}

	incID, inputID := "inc-"+id, "input-"+id
	insertIncidentAndDeliveryInput(t, st, incID, inputID, groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "seed:"+id, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input for delivery %s: %v", deliveryID, err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&situationID); err != nil {
		t.Fatalf("find situation for group %s: %v", groupKey, err)
	}
	return deliveryID, situationID
}

func getDeliverySignature(t *testing.T, st *Store, deliveryID string) (key, mode string, advisoryOnly bool, found bool) {
	t.Helper()
	var advisory int
	err := st.db.QueryRowContext(context.Background(), `
		SELECT signature_key, mode, advisory_only FROM delivery_semantic_signatures WHERE delivery_id = ?`,
		deliveryID).Scan(&key, &mode, &advisory)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, false
	}
	if err != nil {
		t.Fatalf("read delivery semantic signature for %s: %v", deliveryID, err)
	}
	return key, mode, advisory == 1, true
}

func countInferenceJobs(t *testing.T, st *Store, signatureKey string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM semantic_profile_inference_jobs WHERE signature_key = ?`, signatureKey).Scan(&n); err != nil {
		t.Fatalf("count inference jobs for %s: %v", signatureKey, err)
	}
	return n
}

func TestApplySituationInputAttachesDeliverySemanticSignatureAndCreatesJob(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

	deliveryID, _ := signatureDeliveryFixture(t, st, "a", "group-sig-a", now)

	key, mode, advisoryOnly, found := getDeliverySignature(t, st, deliveryID)
	if !found {
		t.Fatal("expected a delivery_semantic_signatures row after ApplySituationInput")
	}
	if mode != profilemodel.SignatureModeSignalVersion {
		t.Fatalf("mode = %q, want %q (proven signal id + version)", mode, profilemodel.SignatureModeSignalVersion)
	}
	if advisoryOnly {
		t.Fatal("a proven signal_id+version signature must not be advisory_only")
	}
	if countInferenceJobs(t, st, key) != 1 {
		t.Fatalf("expected exactly one pending inference job for a brand-new signature")
	}
	var status string
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT status FROM semantic_profile_inference_jobs WHERE signature_key = ?`, key).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != profilemodel.JobStatePending {
		t.Fatalf("status = %q, want pending", status)
	}
}

// TestManyDeliveriesSharingOneSignatureCreateExactlyOneJob covers plan.md's
// literal "200 deliveries sharing one signature" acceptance bullet: every
// delivery gets its own immutable mapping row, but only the FIRST ever
// attachment for a brand-new signature creates an inference job — the
// partial live-job unique index (and this function's own existence check)
// prevent any of the other 199 from creating a duplicate.
func TestManyDeliveriesSharingOneSignatureCreateExactlyOneJob(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	const n = 200

	var signatureKey string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("many-%03d", i)
		deliveryID := "delivery-" + id
		del := deliveryFixture(deliveryID, "fp-"+id, now)
		del.Source = "zabbix"
		sigID, sigVersion := "item:shared", "v9"
		del.SourceProvenance.SignalID = &sigID
		del.SourceProvenance.SignalVersion = &sigVersion
		if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{del}); err != nil {
			t.Fatalf("accept delivery %s: %v", deliveryID, err)
		}
		groupKey := "group-many-" + id
		incID, inputID := "inc-"+id, "input-"+id
		insertIncidentAndDeliveryInput(t, st, incID, inputID, groupKey, deliveryID, now)
		claim := claimOneInput(t, st, "seed:"+id, now)
		if err := st.ApplySituationInput(context.Background(), claim); err != nil {
			t.Fatalf("apply situation input for delivery %s: %v", deliveryID, err)
		}
		key, _, _, found := getDeliverySignature(t, st, deliveryID)
		if !found {
			t.Fatalf("delivery %s: expected a signature mapping", deliveryID)
		}
		if signatureKey == "" {
			signatureKey = key
		} else if key != signatureKey {
			t.Fatalf("delivery %s: signature %q, want the same shared %q", deliveryID, key, signatureKey)
		}
	}

	var mappingCount int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM delivery_semantic_signatures WHERE signature_key = ?`, signatureKey).Scan(&mappingCount); err != nil {
		t.Fatalf("count mappings: %v", err)
	}
	if mappingCount != n {
		t.Fatalf("mapping count = %d, want %d", mappingCount, n)
	}
	if got := countInferenceJobs(t, st, signatureKey); got != 1 {
		t.Fatalf("job count for shared signature = %d, want exactly 1", got)
	}
}

func TestAttachDeliverySemanticSignatureAbsentSourceVersionKeepsIDOnlyMode(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	deliveryID := "delivery-id-only"
	del := deliveryFixture(deliveryID, "fp-id-only", now)
	del.Source = "zabbix"
	sigID := "item:456"
	del.SourceProvenance.SignalID = &sigID // no SignalVersion: absent, not fabricated.
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	groupKey := "group-id-only"
	insertIncidentAndDeliveryInput(t, st, "inc-id-only", "input-id-only", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "seed:id-only", now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}

	_, mode, advisoryOnly, found := getDeliverySignature(t, st, deliveryID)
	if !found {
		t.Fatal("expected a signature mapping")
	}
	if mode != profilemodel.SignatureModeSignalIDOnly {
		t.Fatalf("mode = %q, want %q", mode, profilemodel.SignatureModeSignalIDOnly)
	}
	if advisoryOnly {
		t.Fatal("a proven signal id alone must not be advisory_only")
	}
}

func TestAttachDeliverySemanticSignatureFallbackIsAdvisoryOnly(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	deliveryID := "delivery-fallback"
	del := deliveryFixture(deliveryID, "fp-fallback", now) // alertmanager, no proven signal id.
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	groupKey := "group-fallback"
	insertIncidentAndDeliveryInput(t, st, "inc-fallback", "input-fallback", groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "seed:fallback", now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}

	_, mode, advisoryOnly, found := getDeliverySignature(t, st, deliveryID)
	if !found {
		t.Fatal("expected a signature mapping")
	}
	if mode != profilemodel.SignatureModeFallback {
		t.Fatalf("mode = %q, want %q", mode, profilemodel.SignatureModeFallback)
	}
	if !advisoryOnly {
		t.Fatal("a fallback signature must report advisory_only")
	}
}

func TestBackfillActiveSemanticMappingsCoversMissingMembers(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// A delivery that never went through ApplySituationInput's own attach
	// step: attached directly to the incident's own delivery ownership table
	// (bypassing ApplySituationInput entirely for this second delivery — the
	// same shape a crash between insertDeliveryTx and the signature attach,
	// or an upgrade from a pre-Plan-4-Task-7 database, would leave behind),
	// so delivery_semantic_signatures never gets a row for it at all.
	seedDeliveryID := "delivery-backfill-seed"
	seed := deliveryFixture(seedDeliveryID, "fp-backfill-seed", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{seed}); err != nil {
		t.Fatalf("accept seed delivery: %v", err)
	}
	groupKey := "group-backfill"
	incID, inputID := "inc-backfill", "input-backfill"
	insertIncidentAndDeliveryInput(t, st, incID, inputID, groupKey, seedDeliveryID, now)
	claim := claimOneInput(t, st, "seed:backfill", now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}

	deliveryID := "delivery-backfill-unattached"
	del := deliveryFixture(deliveryID, "fp-backfill-unattached", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incID, deliveryID, canonicalTime(now)); err != nil {
		t.Fatalf("attach unattached delivery to incident: %v", err)
	}

	n, err := st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		t.Fatalf("BackfillActiveSemanticMappings: %v", err)
	}
	if n != 1 {
		t.Fatalf("backfilled = %d, want 1", n)
	}
	if _, _, _, found := getDeliverySignature(t, st, deliveryID); !found {
		t.Fatal("expected the backfill to attach a signature mapping")
	}

	// Idempotent: a second call finds nothing left to do.
	n2, err := st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		t.Fatalf("BackfillActiveSemanticMappings (second call): %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second backfill = %d, want 0", n2)
	}
}

func TestBackfillActiveSemanticMappingsSkipsTerminalFollowers(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	incID := "inc-terminal"
	seedDeliveryID := "delivery-terminal-seed"
	seed := deliveryFixture(seedDeliveryID, "fp-terminal-seed", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{seed}); err != nil {
		t.Fatalf("accept seed delivery: %v", err)
	}
	groupKey := "group-terminal"
	insertIncidentAndDeliveryInput(t, st, incID, "input-terminal", groupKey, seedDeliveryID, now)
	claim := claimOneInput(t, st, "seed:terminal", now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}

	deliveryID := "delivery-terminal-unattached"
	del := deliveryFixture(deliveryID, "fp-terminal-unattached", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incID, deliveryID, canonicalTime(now)); err != nil {
		t.Fatalf("attach unattached delivery to incident: %v", err)
	}

	var situationID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&situationID); err != nil {
		t.Fatalf("find situation: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle = 'closed_unknown', terminal_at = ?, terminal_reason = 'observation_deadline'
		WHERE id = ?`, canonicalTime(now), situationID); err != nil {
		t.Fatalf("terminalize situation: %v", err)
	}

	n, err := st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		t.Fatalf("BackfillActiveSemanticMappings: %v", err)
	}
	if n != 0 {
		t.Fatalf("backfilled = %d, want 0: a terminal-only member must not be queued for inference", n)
	}
	if _, _, _, found := getDeliverySignature(t, st, deliveryID); found {
		t.Fatal("a terminal-only delivery must not gain a lazily-queued mapping via the active backfill path")
	}
}

// seedRunningInferenceJob inserts one 'running' semantic_profile_inference_jobs
// row directly, with the given attempt/maxAttempts and a lease that expired
// leaseAge before now — simulating a worker that crashed mid-attempt,
// without needing the Task 8 claim/reserve dispatch surface this test
// predates.
func seedRunningInferenceJob(t *testing.T, st *Store, id, signatureKey string, attempt, maxAttempts int, now time.Time, leaseAge time.Duration) {
	t.Helper()
	leaseExpiresAt := canonicalTime(now.Add(-leaseAge))
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO semantic_profile_inference_jobs (
			id, signature_key, frozen_input_json, frozen_input_digest, expected_head_version,
			status, attempt, max_attempts, owner, token, lease_expires_at, created_at
		) VALUES (?, ?, '{}', ?, 0, 'running', ?, ?, 'owner-a', 1, ?, ?)`,
		id, signatureKey, "digest-"+id, attempt, maxAttempts, leaseExpiresAt, canonicalTime(now)); err != nil {
		t.Fatalf("seed running inference job %s: %v", id, err)
	}
}

func getJobStatus(t *testing.T, st *Store, id string) (status string, ownerSet bool) {
	t.Helper()
	var owner sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT status, owner FROM semantic_profile_inference_jobs WHERE id = ?`, id).Scan(&status, &owner); err != nil {
		t.Fatalf("read job %s status: %v", id, err)
	}
	return status, owner.Valid
}

func TestRecoverSemanticInferenceReturnsStrandedRunningJobToPending(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedRunningInferenceJob(t, st, "job-recoverable", "sig:recoverable", 1, 3, now, time.Hour)

	n, err := st.RecoverSemanticInference(context.Background(), now)
	if err != nil {
		t.Fatalf("RecoverSemanticInference: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	status, ownerSet := getJobStatus(t, st, "job-recoverable")
	if status != profilemodel.JobStatePending {
		t.Fatalf("status = %q, want pending", status)
	}
	if ownerSet {
		t.Fatal("a recovered job must have its owner cleared")
	}
}

func TestRecoverSemanticInferenceMarksFinalAttemptCrashAsExhausted(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	// attempt already equals max_attempts: the crash happened on the FINAL
	// reservation — spec.md: "recovered as exhausted even if no outcome
	// committed."
	seedRunningInferenceJob(t, st, "job-exhausted", "sig:exhausted", 3, 3, now, time.Hour)

	n, err := st.RecoverSemanticInference(context.Background(), now)
	if err != nil {
		t.Fatalf("RecoverSemanticInference: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	status, _ := getJobStatus(t, st, "job-exhausted")
	if status != profilemodel.JobStateExhausted {
		t.Fatalf("status = %q, want exhausted", status)
	}
}

func TestRecoverSemanticInferenceLeavesLiveLeaseUntouched(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	// Lease expires in the FUTURE relative to now: still live, not stranded.
	seedRunningInferenceJob(t, st, "job-live", "sig:live", 1, 3, now, -time.Hour)

	n, err := st.RecoverSemanticInference(context.Background(), now)
	if err != nil {
		t.Fatalf("RecoverSemanticInference: %v", err)
	}
	if n != 0 {
		t.Fatalf("recovered = %d, want 0", n)
	}
	status, ownerSet := getJobStatus(t, st, "job-live")
	if status != "running" || !ownerSet {
		t.Fatalf("status = %q ownerSet=%v, want an untouched live running job", status, ownerSet)
	}
}

// ----------------------------------------------------------------------
// Job claim / call reservation / completion dispatch surface — Task 7's own
// persistence for the worker Task 8 builds. Mirrors Task 2's
// BeginPreparation/ReserveObservationRequest/CommitObservationRun split.
// ----------------------------------------------------------------------

func seedPendingInferenceJob(t *testing.T, st *Store, id, signatureKey string, maxAttempts int, retryAt *time.Time, now time.Time) {
	t.Helper()
	var retryAtStr any
	if retryAt != nil {
		retryAtStr = canonicalTime(*retryAt)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO semantic_profile_inference_jobs (
			id, signature_key, frozen_input_json, frozen_input_digest, expected_head_version,
			status, attempt, max_attempts, retry_at, created_at
		) VALUES (?, ?, '{}', ?, 0, 'pending', 0, ?, ?, ?)`,
		id, signatureKey, "digest-"+id, maxAttempts, retryAtStr, canonicalTime(now)); err != nil {
		t.Fatalf("seed pending inference job %s: %v", id, err)
	}
}

func TestClaimSemanticInferenceJobClaimsOneDuePendingJob(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-due", "sig:due", 3, nil, now)

	claim, found, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("ClaimSemanticInferenceJob: %v", err)
	}
	if !found {
		t.Fatal("expected a due pending job to be claimed")
	}
	if claim.JobID != "job-due" || claim.Signature != "sig:due" || claim.Owner != "worker-a" {
		t.Fatalf("claim = %+v, want job-due/sig:due/worker-a", claim)
	}
	if claim.Attempt != 0 {
		t.Fatalf("claim.Attempt = %d, want 0 (claiming does not spend a call)", claim.Attempt)
	}
	status, ownerSet := getJobStatus(t, st, "job-due")
	if status != "running" || !ownerSet {
		t.Fatalf("status = %q ownerSet=%v, want running with an owner", status, ownerSet)
	}
}

func TestClaimSemanticInferenceJobSkipsJobsNotYetDue(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	seedPendingInferenceJob(t, st, "job-not-due", "sig:not-due", 3, &future, now)

	_, found, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("ClaimSemanticInferenceJob: %v", err)
	}
	if found {
		t.Fatal("a job whose retry_at is still in the future must not be claimed")
	}
}

func TestClaimSemanticInferenceJobReturnsFalseWhenNoneDue(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	_, found, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("ClaimSemanticInferenceJob: %v", err)
	}
	if found {
		t.Fatal("expected no job to be claimed from an empty table")
	}
}

func TestReserveSemanticInferenceCallSpendsExactlyOneAttemptPerCall(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-reserve", "sig:reserve", 2, nil, now)
	claim, found, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}

	callID1, attempt1, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if attempt1 != 1 {
		t.Fatalf("first attempt = %d, want 1", attempt1)
	}
	callID2, attempt2, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if attempt2 != 2 {
		t.Fatalf("second attempt = %d, want 2", attempt2)
	}
	if callID1 == callID2 {
		t.Fatal("each reservation must get its own immutable call id")
	}

	// max_attempts is 2: a third reservation must be refused.
	if _, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now); !errors.Is(err, ErrSemanticInferenceAttemptsExhausted) {
		t.Fatalf("third reserve: got %v, want ErrSemanticInferenceAttemptsExhausted", err)
	}
	status, _ := getJobStatus(t, st, claim.JobID)
	if status != profilemodel.JobStateExhausted {
		t.Fatalf("status after exhausting reserve = %q, want exhausted", status)
	}
}

func TestReserveSemanticInferenceCallRejectsStaleClaim(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-stale", "sig:stale", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token+1, now); !errors.Is(err, profilemodel.ErrLeaseLost) {
		t.Fatalf("wrong token: got %v, want ErrLeaseLost", err)
	}
}

func TestLoadProfileGuidanceForDeliveriesReturnsCurrentHeadsOnly(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	deliveryID, _ := signatureDeliveryFixture(t, st, "guidance-a", "group-guidance-a", now)
	var signatureKey string
	if err := st.db.QueryRowContext(ctx, `SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, deliveryID).Scan(&signatureKey); err != nil {
		t.Fatalf("read signature key: %v", err)
	}

	// A second delivery with no signature mapping at all, and a third under
	// a signature that has never received a head: neither should produce
	// guidance.
	unmappedDeliveryID := "delivery-guidance-unmapped"
	del := deliveryFixture(unmappedDeliveryID, "fp-guidance-unmapped", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{del}); err != nil {
		t.Fatalf("accept unmapped delivery: %v", err)
	}

	guidance, versionIDs, err := st.LoadProfileGuidanceForDeliveries(ctx, []string{deliveryID, unmappedDeliveryID})
	if err != nil {
		t.Fatalf("LoadProfileGuidanceForDeliveries (no head yet): %v", err)
	}
	if len(guidance) != 0 || len(versionIDs) != 0 {
		t.Fatalf("guidance = %+v versionIDs = %v, want none before any correction/inference exists", guidance, versionIDs)
	}

	correction := profilemodel.Correction{
		Signature: signatureKey,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
			UsefulCapabilities: []string{"prometheus_query", "loki_query"},
		},
		Confirm: true, AssertedBy: "operator:guidance",
	}
	v1, err := st.CorrectSemanticProfile(ctx, correction, now)
	if err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}

	guidance, versionIDs, err = st.LoadProfileGuidanceForDeliveries(ctx, []string{deliveryID, unmappedDeliveryID})
	if err != nil {
		t.Fatalf("LoadProfileGuidanceForDeliveries: %v", err)
	}
	if len(guidance) != 1 {
		t.Fatalf("guidance = %+v, want exactly 1 entry (the unmapped delivery contributes none)", guidance)
	}
	g := guidance[0]
	if g.SignatureKey != signatureKey || g.VersionID != v1.ID || g.HorizonTier != "hours" {
		t.Fatalf("guidance[0] = %+v, want signature=%s version=%s horizon=hours", g, signatureKey, v1.ID)
	}
	if len(g.UsefulCapabilities) != 2 {
		t.Fatalf("useful_capabilities = %v, want 2 entries", g.UsefulCapabilities)
	}
	if len(g.CandidateScope) != 1 || g.CandidateScope[0] != "service" {
		t.Fatalf("candidate_scope = %v, want [service]", g.CandidateScope)
	}
	if len(versionIDs) != 1 || versionIDs[0] != v1.ID {
		t.Fatalf("versionIDs = %v, want [%s]", versionIDs, v1.ID)
	}
}

func TestLoadProfileGuidanceForDeliveriesDedupesSharedSignature(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	d1, _ := signatureDeliveryFixture(t, st, "guidance-shared-a", "group-guidance-shared-a", now)
	d2, _ := signatureDeliveryFixture(t, st, "guidance-shared-b", "group-guidance-shared-b", now)
	var sig1, sig2 string
	if err := st.db.QueryRowContext(ctx, `SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, d1).Scan(&sig1); err != nil {
		t.Fatalf("read signature 1: %v", err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, d2).Scan(&sig2); err != nil {
		t.Fatalf("read signature 2: %v", err)
	}
	if sig1 != sig2 {
		t.Fatalf("fixture invariant: expected both deliveries to share one signature (same proven signal id/version), got %q and %q", sig1, sig2)
	}

	correction := profilemodel.Correction{
		Signature: sig1,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "minutes",
		},
		Confirm: true, AssertedBy: "operator:guidance-shared",
	}
	if _, err := st.CorrectSemanticProfile(ctx, correction, now); err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}

	guidance, _, err := st.LoadProfileGuidanceForDeliveries(ctx, []string{d1, d2})
	if err != nil {
		t.Fatalf("LoadProfileGuidanceForDeliveries: %v", err)
	}
	if len(guidance) != 1 {
		t.Fatalf("guidance = %+v, want exactly 1 deduped entry for the shared signature", guidance)
	}
}

func TestExtendSemanticInferenceJobLeaseExtendsLiveClaim(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-heartbeat", "sig:heartbeat", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	later := now.Add(30 * time.Second)
	if err := st.ExtendSemanticInferenceJobLease(context.Background(), claim.JobID, claim.Owner, claim.Token, later, time.Minute); err != nil {
		t.Fatalf("ExtendSemanticInferenceJobLease: %v", err)
	}
	var leaseExpiresAt string
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT lease_expires_at FROM semantic_profile_inference_jobs WHERE id = ?`, claim.JobID).Scan(&leaseExpiresAt); err != nil {
		t.Fatalf("read lease: %v", err)
	}
	if leaseExpiresAt != canonicalTime(later.Add(time.Minute)) {
		t.Fatalf("lease_expires_at = %q, want %q", leaseExpiresAt, canonicalTime(later.Add(time.Minute)))
	}
}

func TestExtendSemanticInferenceJobLeaseRejectsStaleClaim(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-heartbeat-stale", "sig:heartbeat-stale", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := st.ExtendSemanticInferenceJobLease(context.Background(), claim.JobID, claim.Owner, claim.Token+1, now, time.Minute); !errors.Is(err, profilemodel.ErrLeaseLost) {
		t.Fatalf("wrong token: got %v, want ErrLeaseLost", err)
	}
}

func TestCompleteSemanticInferenceAcceptedCreatesVersionAndHead(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-accept", "sig:accept", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	callID, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	profile := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
		CandidateScope: []string{"service"}, HorizonTier: "hours",
	}
	result := profilemodel.InferenceResult{
		Profile: &profile, Outcome: profilemodel.InferenceOutcomeAccepted, RequestStarted: "true",
		Provider: "anthropic", Model: "claude", UsageInputTokens: 100, UsageOutputTokens: 20,
		PromptVersion: profilemodel.PromptVersion,
	}
	if err := st.CompleteSemanticInference(context.Background(), callID, claim.Owner, claim.Token, result, now, nil); err != nil {
		t.Fatalf("CompleteSemanticInference: %v", err)
	}

	var headVersion int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, claim.Signature).Scan(&headVersion); err != nil {
		t.Fatalf("read head: %v", err)
	}
	if headVersion != 1 {
		t.Fatalf("head version = %d, want 1", headVersion)
	}
	status, _ := getJobStatus(t, st, claim.JobID)
	if status != profilemodel.JobStateComplete {
		t.Fatalf("job status = %q, want complete", status)
	}
	var outcome string
	if err := st.db.QueryRowContext(context.Background(), `SELECT outcome FROM semantic_profile_call_outcomes WHERE call_id = ?`, callID).Scan(&outcome); err != nil {
		t.Fatalf("read call outcome: %v", err)
	}
	if outcome != profilemodel.InferenceOutcomeAccepted {
		t.Fatalf("outcome = %q, want accepted", outcome)
	}
}

// TestCompleteSemanticInferenceLateAcceptedAfterCorrectionRecordsStale
// proves spec.md's "A late inference commits only if the expected head is
// still absent" / "A correction or winning inference makes it stale-complete,
// without replacing that head": an operator correction races ahead of the
// still-in-flight inference job for the SAME signature; when the job's
// result finally arrives, the store must record it as stale, create no
// version, and never touch the head the correction already set.
func TestCompleteSemanticInferenceLateAcceptedAfterCorrectionRecordsStale(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-late", "sig:late", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	callID, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	correction := profilemodel.Correction{
		Signature: claim.Signature,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:racer",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err != nil {
		t.Fatalf("racing correction: %v", err)
	}

	profile := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "cause",
		CandidateScope: []string{"service"}, HorizonTier: "minutes",
	}
	result := profilemodel.InferenceResult{Profile: &profile, Outcome: profilemodel.InferenceOutcomeAccepted, RequestStarted: "true"}
	if err := st.CompleteSemanticInference(context.Background(), callID, claim.Owner, claim.Token, result, now, nil); err != nil {
		t.Fatalf("CompleteSemanticInference: %v", err)
	}

	var outcome string
	if err := st.db.QueryRowContext(context.Background(), `SELECT outcome FROM semantic_profile_call_outcomes WHERE call_id = ?`, callID).Scan(&outcome); err != nil {
		t.Fatalf("read call outcome: %v", err)
	}
	if outcome != profilemodel.InferenceOutcomeStale {
		t.Fatalf("outcome = %q, want stale (the correction already won)", outcome)
	}
	var headVersion int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, claim.Signature).Scan(&headVersion); err != nil {
		t.Fatalf("read head: %v", err)
	}
	if headVersion != 1 {
		t.Fatalf("head version = %d, want 1 (the correction's own version, never replaced)", headVersion)
	}
	var versionCount int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM semantic_profile_versions WHERE signature_key = ?`, claim.Signature).Scan(&versionCount); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if versionCount != 1 {
		t.Fatalf("version count = %d, want 1 (the stale inference must not create a second version)", versionCount)
	}
}

func TestCompleteSemanticInferenceRejectedRetriesUntilExhausted(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-rejected", "sig:rejected", 2, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	callID, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	retryAt := now.Add(time.Minute)
	result := profilemodel.InferenceResult{Outcome: profilemodel.InferenceOutcomeMalformed, RequestStarted: "true"}
	if err := st.CompleteSemanticInference(context.Background(), callID, claim.Owner, claim.Token, result, now, &retryAt); err != nil {
		t.Fatalf("CompleteSemanticInference: %v", err)
	}
	status, ownerSet := getJobStatus(t, st, claim.JobID)
	if status != profilemodel.JobStatePending || ownerSet {
		t.Fatalf("status = %q ownerSet=%v, want pending with the lease released (one attempt remains)", status, ownerSet)
	}

	// Second attempt also fails, and max_attempts (2) is now spent.
	claim2, found, err := st.ClaimSemanticInferenceJob(context.Background(), "worker-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || !found {
		t.Fatalf("re-claim: found=%v err=%v", found, err)
	}
	callID2, _, err := st.ReserveSemanticInferenceCall(context.Background(), claim2.JobID, claim2.Owner, claim2.Token, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if err := st.CompleteSemanticInference(context.Background(), callID2, claim2.Owner, claim2.Token, result, now.Add(2*time.Minute), nil); err != nil {
		t.Fatalf("second CompleteSemanticInference: %v", err)
	}
	status2, _ := getJobStatus(t, st, claim2.JobID)
	if status2 != profilemodel.JobStateExhausted {
		t.Fatalf("status = %q, want exhausted after spending both attempts", status2)
	}
}

// ----------------------------------------------------------------------
// Head-change fan-out — Task 7's own "profile wakes".
// ----------------------------------------------------------------------

func situationDueReasons(t *testing.T, st *Store, situationID string) []situationmodel.DueReason {
	t.Helper()
	var dueReasonsJSON string
	if err := st.db.QueryRowContext(context.Background(), `SELECT due_reasons_json FROM situations WHERE id = ?`, situationID).Scan(&dueReasonsJSON); err != nil {
		t.Fatalf("read due reasons for %s: %v", situationID, err)
	}
	var reasons []situationmodel.DueReason
	if err := json.Unmarshal([]byte(dueReasonsJSON), &reasons); err != nil {
		t.Fatalf("unmarshal due reasons for %s: %v", situationID, err)
	}
	return reasons
}

func hasDueReason(reasons []situationmodel.DueReason, want situationmodel.DueReason) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func TestDeliverSemanticProfileChangesWakesMatchingNonterminalSituation(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	_, situationID := signatureDeliveryFixture(t, st, "wake-a", "group-wake-a", now)
	var signatureKey string
	if err := st.db.QueryRowContext(context.Background(), `SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, "delivery-wake-a").Scan(&signatureKey); err != nil {
		t.Fatalf("read signature key: %v", err)
	}

	correction := profilemodel.Correction{
		Signature: signatureKey,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:wake",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}

	n, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("DeliverSemanticProfileChanges: %v", err)
	}
	if n != 1 {
		t.Fatalf("delivered = %d, want 1", n)
	}
	if !hasDueReason(situationDueReasons(t, st, situationID), situationmodel.DueSemanticProfileChanged) {
		t.Fatal("expected the semantic_profile_changed due reason to be merged")
	}
	var deliveryCount int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM semantic_profile_change_deliveries WHERE situation_id = ?`, situationID).Scan(&deliveryCount); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if deliveryCount != 1 {
		t.Fatalf("delivery rows = %d, want 1", deliveryCount)
	}
	var acknowledged int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT acknowledged FROM semantic_profile_changes WHERE signature_key = ?`, signatureKey).Scan(&acknowledged); err != nil {
		t.Fatalf("read acknowledged: %v", err)
	}
	if acknowledged != 1 {
		t.Fatal("a single-page fan-out must acknowledge the change once exhausted")
	}

	// Idempotent: a second call finds nothing left to do.
	n2, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("DeliverSemanticProfileChanges (second call): %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second delivery = %d, want 0", n2)
	}
}

func TestDeliverSemanticProfileChangesSkipsTerminalSituations(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	_, situationID := signatureDeliveryFixture(t, st, "wake-terminal", "group-wake-terminal", now)
	var signatureKey string
	if err := st.db.QueryRowContext(context.Background(), `SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, "delivery-wake-terminal").Scan(&signatureKey); err != nil {
		t.Fatalf("read signature key: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET lifecycle = 'closed_unknown', terminal_at = ?, terminal_reason = 'observation_deadline'
		WHERE id = ?`, canonicalTime(now), situationID); err != nil {
		t.Fatalf("terminalize situation: %v", err)
	}

	correction := profilemodel.Correction{
		Signature: signatureKey,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:wake",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}

	n, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("DeliverSemanticProfileChanges: %v", err)
	}
	if n != 0 {
		t.Fatalf("delivered = %d, want 0: a terminal Situation must never be woken", n)
	}
}

// TestDeliverSemanticProfileChangesResumesCursorAcrossBatches covers
// plan.md's "150 active Situation followers" and "100-row fan-out cursor
// resume" acceptance bullets together: more matching Situations than one
// page (100), delivered across two calls, with an outbox row acknowledged
// only once its cursor has actually exhausted every match.
func TestDeliverSemanticProfileChangesResumesCursorAcrossBatches(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	const n = 150

	var signatureKey string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("follower-%03d", i)
		deliveryID := "delivery-" + id
		del := deliveryFixture(deliveryID, "fp-"+id, now)
		del.Source = "zabbix"
		sigID, sigVersion := "item:followers", "v1"
		del.SourceProvenance.SignalID = &sigID
		del.SourceProvenance.SignalVersion = &sigVersion
		if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{del}); err != nil {
			t.Fatalf("accept delivery %s: %v", deliveryID, err)
		}
		groupKey := "group-follower-" + id
		insertIncidentAndDeliveryInput(t, st, "inc-"+id, "input-"+id, groupKey, deliveryID, now)
		claim := claimOneInput(t, st, "seed:"+id, now)
		if err := st.ApplySituationInput(context.Background(), claim); err != nil {
			t.Fatalf("apply situation input for delivery %s: %v", deliveryID, err)
		}
		if signatureKey == "" {
			if err := st.db.QueryRowContext(context.Background(), `
				SELECT signature_key FROM delivery_semantic_signatures WHERE delivery_id = ?`, deliveryID).Scan(&signatureKey); err != nil {
				t.Fatalf("read signature key: %v", err)
			}
		}
	}

	correction := profilemodel.Correction{
		Signature: signatureKey,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:followers",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}

	first, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("DeliverSemanticProfileChanges (first): %v", err)
	}
	if first != 100 {
		t.Fatalf("first batch delivered = %d, want 100", first)
	}
	var acknowledgedAfterFirst int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT acknowledged FROM semantic_profile_changes WHERE signature_key = ?`, signatureKey).Scan(&acknowledgedAfterFirst); err != nil {
		t.Fatalf("read acknowledged after first batch: %v", err)
	}
	if acknowledgedAfterFirst != 0 {
		t.Fatal("a partial page must not acknowledge the change yet")
	}

	second, err := st.DeliverSemanticProfileChanges(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("DeliverSemanticProfileChanges (second): %v", err)
	}
	if second != n-100 {
		t.Fatalf("second batch delivered = %d, want %d", second, n-100)
	}
	var acknowledgedAfterSecond int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT acknowledged FROM semantic_profile_changes WHERE signature_key = ?`, signatureKey).Scan(&acknowledgedAfterSecond); err != nil {
		t.Fatalf("read acknowledged after second batch: %v", err)
	}
	if acknowledgedAfterSecond != 1 {
		t.Fatal("the cursor exhausted every matching Situation on the second page: expected acknowledged=1")
	}

	var totalDeliveries int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM semantic_profile_change_deliveries WHERE change_id IN (
			SELECT id FROM semantic_profile_changes WHERE signature_key = ?)`, signatureKey).Scan(&totalDeliveries); err != nil {
		t.Fatalf("count total deliveries: %v", err)
	}
	if totalDeliveries != n {
		t.Fatalf("total deliveries = %d, want %d", totalDeliveries, n)
	}
}

func TestCorrectSemanticProfileCreatesHeadAndRejectsStaleExpectedVersion(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()

	correction := profilemodel.Correction{
		Signature: "zabbix:advisory:sha256:test-signature",
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
			UsefulCapabilities: []string{"prometheus_query"},
		},
		Confirm: true, AssertedBy: "operator:test",
	}
	v1, err := st.CorrectSemanticProfile(ctx, correction, now)
	if err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}
	if v1.Version != 1 {
		t.Fatalf("version = %d, want 1", v1.Version)
	}
	if v1.Origin != profilemodel.OriginCorrection || v1.AssertedBy != "operator:test" {
		t.Fatalf("v1 = %+v, want origin=correction assertedBy=operator:test", v1)
	}

	// ExpectedVersion still 0: stale now that the head is 1.
	if _, err := st.CorrectSemanticProfile(ctx, correction, now); !errors.Is(err, profilemodel.ErrVersionConflict) {
		t.Fatalf("stale correction: got %v, want ErrVersionConflict", err)
	}

	correction.ExpectedVersion = 1
	v2, err := st.CorrectSemanticProfile(ctx, correction, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("CorrectSemanticProfile (v2): %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("version = %d, want 2 (correcting to equivalent content still versions)", v2.Version)
	}

	var versionCount int
	if err := st.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM semantic_profile_versions WHERE signature_key = ?`, correction.Signature).Scan(&versionCount); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if versionCount != 2 {
		t.Fatalf("version rows = %d, want 2 (versions are immutable, never overwritten)", versionCount)
	}
}

func TestCorrectSemanticProfileRejectsInvalidProfile(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	correction := profilemodel.Correction{
		Signature: "zabbix:advisory:sha256:invalid",
		Profile:   profilemodel.Profile{}, // missing required fields.
		Confirm:   true, AssertedBy: "operator:test",
	}
	if _, err := st.CorrectSemanticProfile(context.Background(), correction, now); err == nil {
		t.Fatal("expected validation to reject an empty profile")
	}
	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM semantic_profile_heads`).Scan(&count); err != nil {
		t.Fatalf("count heads: %v", err)
	}
	if count != 0 {
		t.Fatal("a rejected correction must not create a head")
	}
}

func TestCorrectSemanticProfileEnqueuesChangeForFanOut(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	correction := profilemodel.Correction{
		Signature: "zabbix:advisory:sha256:fanout",
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:test",
	}
	v1, err := st.CorrectSemanticProfile(context.Background(), correction, now)
	if err != nil {
		t.Fatalf("CorrectSemanticProfile: %v", err)
	}
	var changeCount int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM semantic_profile_changes WHERE signature_key = ? AND version_id = ?`,
		correction.Signature, v1.ID).Scan(&changeCount); err != nil {
		t.Fatalf("count changes: %v", err)
	}
	if changeCount != 1 {
		t.Fatalf("change outbox rows = %d, want 1", changeCount)
	}
}

// ----------------------------------------------------------------------
// GetSemanticProfile / ListSituationSemanticSignatures: Task 9's
// alertint_get_semantic_profile MCP read surface.
// ----------------------------------------------------------------------

func TestGetSemanticProfileUnknownSignatureReturnsEmptyHistory(t *testing.T) {
	st := newTestStore(t)
	history, err := st.GetSemanticProfile(context.Background(), "no:such:signature", "", 20)
	if err != nil {
		t.Fatalf("GetSemanticProfile: %v", err)
	}
	if history.Current != nil {
		t.Fatalf("Current = %+v, want nil for an unknown signature", history.Current)
	}
	if len(history.Versions) != 0 {
		t.Fatalf("Versions = %+v, want empty", history.Versions)
	}
	if history.Job != nil {
		t.Fatalf("Job = %+v, want nil", history.Job)
	}
	if history.NextCursor != "" {
		t.Fatalf("NextCursor = %q, want empty", history.NextCursor)
	}
}

func TestGetSemanticProfileReturnsCurrentHeadAndVersionHistoryNewestFirst(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	sig := "zabbix:advisory:sha256:history"
	base := profilemodel.Correction{
		Signature: sig,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:test",
	}
	if _, err := st.CorrectSemanticProfile(ctx, base, now); err != nil {
		t.Fatalf("correction v1: %v", err)
	}
	base.ExpectedVersion = 1
	if _, err := st.CorrectSemanticProfile(ctx, base, now.Add(time.Minute)); err != nil {
		t.Fatalf("correction v2: %v", err)
	}
	base.ExpectedVersion = 2
	if _, err := st.CorrectSemanticProfile(ctx, base, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("correction v3: %v", err)
	}

	history, err := st.GetSemanticProfile(ctx, sig, "", 20)
	if err != nil {
		t.Fatalf("GetSemanticProfile: %v", err)
	}
	if history.Current == nil || history.Current.Version != 3 {
		t.Fatalf("Current = %+v, want version 3", history.Current)
	}
	if len(history.Versions) != 3 {
		t.Fatalf("Versions = %+v, want 3 entries", history.Versions)
	}
	for i, want := range []int{3, 2, 1} {
		if history.Versions[i].Version != want {
			t.Fatalf("Versions[%d].Version = %d, want %d (newest first)", i, history.Versions[i].Version, want)
		}
	}
	if history.NextCursor != "" {
		t.Fatalf("NextCursor = %q, want empty (page holds every version)", history.NextCursor)
	}
	if history.Job != nil {
		t.Fatalf("Job = %+v, want nil (a correction has no inference job)", history.Job)
	}
}

func TestGetSemanticProfilePaginatesVersionsWithCursor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	sig := "zabbix:advisory:sha256:paged"
	base := profilemodel.Correction{
		Signature: sig,
		Profile: profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
		},
		Confirm: true, AssertedBy: "operator:test",
	}
	if _, err := st.CorrectSemanticProfile(ctx, base, now); err != nil {
		t.Fatalf("correction v1: %v", err)
	}
	base.ExpectedVersion = 1
	if _, err := st.CorrectSemanticProfile(ctx, base, now.Add(time.Minute)); err != nil {
		t.Fatalf("correction v2: %v", err)
	}
	base.ExpectedVersion = 2
	if _, err := st.CorrectSemanticProfile(ctx, base, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("correction v3: %v", err)
	}

	page1, err := st.GetSemanticProfile(ctx, sig, "", 1)
	if err != nil {
		t.Fatalf("GetSemanticProfile page1: %v", err)
	}
	if len(page1.Versions) != 1 || page1.Versions[0].Version != 3 || page1.NextCursor == "" {
		t.Fatalf("page1 = %+v, want [3] with a next cursor", page1)
	}

	page2, err := st.GetSemanticProfile(ctx, sig, page1.NextCursor, 1)
	if err != nil {
		t.Fatalf("GetSemanticProfile page2: %v", err)
	}
	if len(page2.Versions) != 1 || page2.Versions[0].Version != 2 || page2.NextCursor == "" {
		t.Fatalf("page2 = %+v, want [2] with a next cursor", page2)
	}

	page3, err := st.GetSemanticProfile(ctx, sig, page2.NextCursor, 1)
	if err != nil {
		t.Fatalf("GetSemanticProfile page3: %v", err)
	}
	if len(page3.Versions) != 1 || page3.Versions[0].Version != 1 || page3.NextCursor != "" {
		t.Fatalf("page3 = %+v, want [1] with no next cursor (last page)", page3)
	}
}

func TestGetSemanticProfileReportsLiveJobState(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	seedPendingInferenceJob(t, st, "job-live", "zabbix:advisory:sha256:live", 3, nil, now)

	history, err := st.GetSemanticProfile(context.Background(), "zabbix:advisory:sha256:live", "", 20)
	if err != nil {
		t.Fatalf("GetSemanticProfile: %v", err)
	}
	if history.Current != nil {
		t.Fatalf("Current = %+v, want nil (no version has ever been committed)", history.Current)
	}
	if history.Job == nil || history.Job.Status != profilemodel.JobStatePending {
		t.Fatalf("Job = %+v, want a live pending job", history.Job)
	}
}

func TestListSituationSemanticSignaturesReturnsDistinctKeysAcrossDeliveries(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)
	_, situationID := signatureDeliveryFixture(t, st, "sig-list-1", "grp-sig-list", now)

	second := deliveryFixture("delivery-sig-list-2", "fp-sig-list-2", now)
	second.Source = "zabbix"
	sigID2, sigVersion2 := "item:999", "v7"
	second.SourceProvenance.SignalID = &sigID2
	second.SourceProvenance.SignalVersion = &sigVersion2
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{second}); err != nil {
		t.Fatalf("accept second delivery: %v", err)
	}
	// Attach the second delivery to the SAME already-ready incident
	// insertIncidentAndDeliveryInput's own InsertIncident/MarkIncidentReady
	// steps must not repeat (the incident row and its ready state already
	// exist from signatureDeliveryFixture above).
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		"inc-sig-list-1", "delivery-sig-list-2", canonicalTime(now)); err != nil {
		t.Fatalf("link second delivery: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'membership_changed', ?, ?, 'pending')`,
		"input-sig-list-2", "idem:input-sig-list-2", "inc-sig-list-1", "delivery-sig-list-2", "grp-sig-list", canonicalTime(now)); err != nil {
		t.Fatalf("insert second situation input: %v", err)
	}
	claim := claimOneInput(t, st, "seed:sig-list-2", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("apply second situation input: %v", err)
	}

	keys, err := st.ListSituationSemanticSignatures(context.Background(), situationID)
	if err != nil {
		t.Fatalf("ListSituationSemanticSignatures: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want 2 distinct signatures", keys)
	}
}
