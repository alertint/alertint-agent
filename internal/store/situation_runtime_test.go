// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func mustJSONFixture(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testRuntime(t *testing.T, s *Store, now time.Time) *SituationRuntime {
	t.Helper()
	return NewSituationRuntime(s,
		func(key string) string { return "cmid:" + key },
		func(d AlertDelivery) string { return "signature:" + d.Source },
		func() time.Time { return now },
		SituationRuntimePolicy{MinSeverity: situationmodel.PriorityLow, HorizonTier: situation.HorizonHours},
	)
}

// seedRuntimeSituation accepts one delivery, correlates it onto an Incident,
// applies the Situation input, and returns the claimed aggregate.
func seedRuntimeSituation(t *testing.T, s *Store, suffix, severity, status string, now time.Time) situation.Claim {
	t.Helper()
	ctx := context.Background()
	incidentID := "inc-" + suffix
	deliveryID := "delivery-" + suffix
	groupKey := "host=" + suffix
	seedIncident(t, s, incidentID, groupKey, "ready", now)
	if _, err := s.AcceptDeliveries(ctx, []DeliveryInput{{
		ID: deliveryID,
		Alert: Alert{
			ID: "alert-" + suffix, Fingerprint: "fp-" + suffix, Status: status,
			Labels:      map[string]string{"severity": severity, "alertname": "DiskFull"},
			Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now,
		},
		Source: "alertmanager", SourceEpisodeKey: "episode-" + suffix,
		StartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, ResolvedAtBasis: situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: groupKey, PayloadDigest: "sha256:" + suffix,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incidentID, deliveryID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	in := SituationInput{
		ID: "input-" + suffix, IdempotencyKey: "delivery:" + deliveryID, IncidentID: incidentID,
		DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: groupKey, OccurredAt: now,
	}
	seedSituationInput(t, s, in, "claimed", "input-worker", now.Add(time.Minute))
	if _, err := s.ApplySituationInput(ctx, claimedSituationInputForTest(in, "input-worker")); err != nil {
		t.Fatal(err)
	}
	claims, err := s.ClaimDueSituations(ctx, "reconciler", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	return situation.Claim{Situation: claims[0].Situation, ClaimOwner: claims[0].ClaimOwner, ClaimToken: claims[0].ClaimToken}
}

func TestSituationRuntimeRecoversEveryExpiredLease(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "leases", "warning", "firing", now)
	_ = claim

	// Expire the Situation claim and hand-craft an expired dispatch/input lease.
	if _, err := s.DB().Exec(`UPDATE situations SET lease_expires_at = ?`, canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE alert_delivery_dispatches SET status='claimed', lease_owner='gone', lease_expires_at=?`,
		canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE situation_input_outbox SET status='claimed', applied_at=NULL, lease_owner='gone', lease_expires_at=?`,
		canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}

	recovered, err := testRuntime(t, s, now).RecoverExpiredLeases(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.AlertDispatches != 1 || recovered.SituationInputs != 1 || recovered.Situations != 1 {
		t.Fatalf("recovered=%+v", recovered)
	}
	var owner *string
	if err := s.DB().QueryRow(`SELECT lease_owner FROM situations LIMIT 1`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != nil {
		t.Fatalf("situation lease owner=%q, want released", *owner)
	}
}

func TestSituationRuntimeReconstructsOneSituationPerGroupWithoutPublishing(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	// Two unrepresented active Incidents share an exact group key; a third has
	// its own. This is the pre-0011 upgrade shape.
	seedIncident(t, s, "legacy-a", "host=legacy", "analyzed", now.Add(-2*time.Hour))
	seedIncident(t, s, "legacy-b", "host=legacy", "ready", now.Add(-time.Hour))
	seedIncident(t, s, "legacy-c", "host=other", "collecting", now.Add(-30*time.Minute))
	seedIncident(t, s, "legacy-done", "host=closed", "resolved", now.Add(-time.Hour))

	runtime := testRuntime(t, s, now)
	report, err := situation.NewReconstructor(runtime, func() time.Time { return now }).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Reconstructed != 2 || report.AttachedIncidents != 3 {
		t.Fatalf("report=%+v", report)
	}

	sits, err := s.ListSituations(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(sits) != 2 {
		t.Fatalf("situations=%d, want one per exact group", len(sits))
	}
	for _, sit := range sits {
		if sit.InputVersion != 1 {
			t.Fatalf("%s input_version=%d, want the reconstruction seed", sit.ID, sit.InputVersion)
		}
		if len(sit.DueReasons) != 1 || sit.DueReasons[0] != situationmodel.DueUpgradeReconstruction {
			t.Fatalf("%s due reasons=%v", sit.ID, sit.DueReasons)
		}
		if sit.PublicHandle != nil {
			t.Fatalf("%s minted a public handle during reconstruction", sit.ID)
		}
		if !sit.NextAssessmentAt.Equal(now) {
			t.Fatalf("%s next assessment=%s, want scheduled immediately", sit.ID, sit.NextAssessmentAt)
		}
	}

	var intents int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("upgrade pokes=%d; a restart alone must never publish", intents)
	}

	// Idempotent across restarts: the durable attachment leaves nothing to do.
	second, err := situation.NewReconstructor(runtime, func() time.Time { return now }).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Reconstructed != 0 || second.AttachedIncidents != 0 {
		t.Fatalf("second run=%+v", second)
	}
}

func TestSituationRuntimeDerivesConfirmedSymptomStateEvidence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "critical", "critical", "firing", now)

	in, incidentID, err := testRuntime(t, s, now).LoadReconciliationInput(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if incidentID != "inc-critical" {
		t.Fatalf("primary incident=%q", incidentID)
	}
	if len(in.Facts) != 1 || in.Facts[0].Kind != "symptom_state" {
		t.Fatalf("facts=%+v", in.Facts)
	}
	if in.Facts[0].InputVersion != claim.Situation.InputVersion {
		t.Fatalf("fact input version=%d, want %d", in.Facts[0].InputVersion, claim.Situation.InputVersion)
	}

	in.Now = now
	snap, err := situation.BuildSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, reason := range snap.EligibleReasons {
		if reason.Code == "critical_anchor" {
			found = true
		}
	}
	if !found {
		t.Fatalf("eligible reasons=%+v, want a deterministic critical anchor", snap.EligibleReasons)
	}
	if floor := situation.ApplyAttentionFloors(situationmodel.AttentionObserve, snap, snap.EligibleReasons); floor != situationmodel.AttentionUrgent {
		t.Fatalf("floor=%q, want urgent without any model call", floor)
	}
}

func TestSituationRuntimeTerminalUncertaintyUsesTierAwareDeadline(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "deadline", "warning", "firing", now)

	// Fresh observation: no terminal uncertainty at all.
	in, _, err := testRuntime(t, s, now).LoadReconciliationInput(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if in.TerminalUncertainty != nil {
		t.Fatalf("terminal uncertainty=%+v while lifecycle truth is fresh", in.TerminalUncertainty)
	}

	// Past the tier deadline (hours -> 24h) it becomes a crossed deadline with
	// the most precise reason: an unresolved delivery means resolution_missing
	// outranks generic observation_deadline.
	late := now.Add(situation.LifecycleDeadline(situation.HorizonHours) + time.Minute)
	in, _, err = testRuntime(t, s, late).LoadReconciliationInput(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if in.TerminalUncertainty == nil || !in.TerminalUncertainty.DeadlineCrossed {
		t.Fatalf("terminal uncertainty=%+v past deadline", in.TerminalUncertainty)
	}
	if in.TerminalUncertainty.Reason != situationmodel.TerminalReasonResolutionMissing {
		t.Fatalf("reason=%q", in.TerminalUncertainty.Reason)
	}

	// Just before the deadline nothing is crossed — proving the two-hour
	// CloseUnknown floor is not doing this work.
	early := now.Add(situation.LifecycleDeadline(situation.HorizonHours) - time.Minute)
	in, _, err = testRuntime(t, s, early).LoadReconciliationInput(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if in.TerminalUncertainty != nil {
		t.Fatalf("terminal uncertainty=%+v before the tier deadline", in.TerminalUncertainty)
	}
}

func TestSituationRuntimeCommitsIntentsAtomicallyAndMintsHandle(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "publish", "critical", "firing", now)
	runtime := testRuntime(t, s, now)

	nextUpdate := now.Add(time.Minute)
	action := "confirm bounded evidence"
	assessment := situationmodel.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: situationmodel.PersistenceUnknown,
		Impact: situationmodel.ImpactUnknown, Novelty: situationmodel.NoveltyInsufficientHistory,
		Causality: situationmodel.CausalityUnknown, Attention: situationmodel.AttentionUrgent,
		Lifecycle: situationmodel.LifecycleActive, EvidenceQuality: situationmodel.EvidenceQualityDegraded,
		SufficientReason: &situationmodel.SufficientReason{
			CandidateID: "critical_anchor", Code: "critical_anchor",
			Summary: "active critical severity", EvidenceRefs: []string{"delivery:delivery-publish"},
		},
		ActionContract: situationmodel.ActionContract{
			NextActor: situationmodel.NextActorAlertint, ActionStatus: situationmodel.ActionStatusPlanned,
			AlertintAction: &action, NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed"},
		},
		ProposedCadence: situationmodel.CadenceFast,
	}
	attempt := situation.AssessmentAttempt{
		ID: "attempt-publish", Sequence: 1, InputVersion: claim.Situation.InputVersion, FactHash: "hash-publish",
		Actor: situation.AssessmentActorDeterministic, Status: situation.AttemptStatusAuthoritative,
		TriggerReasons: []string{"incident_created"}, SnapshotDigest: "hash-publish",
		Validated: mustJSONFixture(t, assessment), CreatedAt: now, CompletedAt: &now,
	}
	tr := situationmodel.Transition{
		ID: "transition-publish", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionUrgent,
		Assessment: &assessment, ActionContract: assessment.ActionContract, Reason: "incident_created", CreatedAt: now,
	}
	if err := runtime.CommitAuthoritative(ctx, claim, attempt, tr); err != nil {
		t.Fatal(err)
	}

	intents, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].Kind != situationmodel.NotificationSituationRootCreate {
		t.Fatalf("intents=%+v", intents)
	}
	if !intents[0].MainChannelPoke || intents[0].Status != situationmodel.NotificationPending {
		t.Fatalf("intent=%+v", intents[0])
	}
	if intents[0].ClientMessageID != "cmid:"+intents[0].IdempotencyKey {
		t.Fatalf("client message id=%q", intents[0].ClientMessageID)
	}

	published, err := s.GetSituation(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if published.CurrentAssessmentID == nil || *published.CurrentAssessmentID != "attempt-publish" {
		t.Fatalf("current assessment=%v", published.CurrentAssessmentID)
	}
	if published.PublicHandle == nil || !strings.Contains(*published.PublicHandle, "publish") {
		t.Fatalf("public handle=%v, want a handle minted with the promised root", published.PublicHandle)
	}
	if !published.NextAssessmentAt.Equal(nextUpdate) {
		t.Fatalf("next assessment=%s, want the published next_update_at", published.NextAssessmentAt)
	}
}

func TestSituationRuntimeSilentTransitionLeavesNoSlackTrace(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "silent", "warning", "firing", now)
	runtime := testRuntime(t, s, now)

	nextUpdate := now.Add(5 * time.Minute)
	assessment := situationmodel.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: situationmodel.PersistenceUnknown,
		Impact: situationmodel.ImpactUnknown, Novelty: situationmodel.NoveltyInsufficientHistory,
		Causality: situationmodel.CausalityUnknown, Attention: situationmodel.AttentionObserve,
		Lifecycle: situationmodel.LifecycleActive, EvidenceQuality: situationmodel.EvidenceQualityInsufficient,
		ActionContract: situationmodel.ActionContract{
			NextActor: situationmodel.NextActorNone, ActionStatus: situationmodel.ActionStatusWaiting, NextUpdateAt: &nextUpdate,
		},
		ProposedCadence: situationmodel.CadenceNormal,
	}
	attempt := situation.AssessmentAttempt{
		ID: "attempt-silent", Sequence: 1, InputVersion: claim.Situation.InputVersion, FactHash: "hash-silent",
		Actor: situation.AssessmentActorDeterministic, Status: situation.AttemptStatusAuthoritative,
		TriggerReasons: []string{"incident_created"}, SnapshotDigest: "hash-silent",
		Validated: mustJSONFixture(t, assessment), CreatedAt: now, CompletedAt: &now,
	}
	tr := situationmodel.Transition{
		ID: "transition-silent", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionObserve,
		Assessment: &assessment, ActionContract: assessment.ActionContract, Reason: "incident_created", CreatedAt: now,
	}
	if err := runtime.CommitAuthoritative(ctx, claim, attempt, tr); err != nil {
		t.Fatal(err)
	}
	intents, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 0 {
		t.Fatalf("intents=%+v; a Situation with no sufficient reason leaves no Slack trace", intents)
	}
	silent, err := s.GetSituation(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if silent.PublicHandle != nil {
		t.Fatalf("silent situation minted handle %q", *silent.PublicHandle)
	}
}

func TestSituationRuntimeStaleCommitIsReportedAsStaleInput(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "stale", "warning", "firing", now)
	runtime := testRuntime(t, s, now)

	// New input arrived after the reconciliation read its version.
	if _, err := s.DB().Exec(`UPDATE situations SET input_version = input_version + 1 WHERE id = ?`, claim.Situation.ID); err != nil {
		t.Fatal(err)
	}
	nextUpdate := now.Add(time.Minute)
	assessment := situationmodel.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: situationmodel.PersistenceUnknown,
		Impact: situationmodel.ImpactUnknown, Novelty: situationmodel.NoveltyInsufficientHistory,
		Causality: situationmodel.CausalityUnknown, Attention: situationmodel.AttentionObserve,
		Lifecycle: situationmodel.LifecycleActive, EvidenceQuality: situationmodel.EvidenceQualityInsufficient,
		ActionContract: situationmodel.ActionContract{
			NextActor: situationmodel.NextActorNone, ActionStatus: situationmodel.ActionStatusWaiting, NextUpdateAt: &nextUpdate,
		},
		ProposedCadence: situationmodel.CadenceNormal,
	}
	attempt := situation.AssessmentAttempt{
		ID: "attempt-stale", Sequence: 1, InputVersion: claim.Situation.InputVersion, FactHash: "hash-stale",
		Actor: situation.AssessmentActorDeterministic, Status: situation.AttemptStatusAuthoritative,
		TriggerReasons: []string{"incident_created"}, SnapshotDigest: "hash-stale",
		Validated: mustJSONFixture(t, assessment), CreatedAt: now, CompletedAt: &now,
	}
	tr := situationmodel.Transition{
		ID: "transition-stale", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionObserve,
		Assessment: &assessment, ActionContract: assessment.ActionContract, CreatedAt: now,
	}
	err := runtime.CommitAuthoritative(ctx, claim, attempt, tr)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("err=%v, want the controller's stale-input signal", err)
	}
}

func TestSituationRuntimeCompleteSchedulesAClaimThatCommittedNothing(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "idle", "warning", "firing", now)
	runtime := testRuntime(t, s, now)

	next := now.Add(5 * time.Minute)
	if err := runtime.CompleteSituation(ctx, situation.DueClaim{
		SituationID: claim.Situation.ID, ClaimOwner: claim.ClaimOwner, ClaimToken: claim.ClaimToken,
	}, next); err != nil {
		t.Fatal(err)
	}
	completed, err := s.GetSituation(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.LeaseOwner != nil {
		t.Fatalf("lease owner=%q, want released", *completed.LeaseOwner)
	}
	if !completed.NextAssessmentAt.Equal(next) {
		t.Fatalf("next assessment=%s, want %s", completed.NextAssessmentAt, next)
	}
	// Re-claiming immediately must find nothing: the aggregate is no longer due.
	claims, err := s.ClaimDueSituations(ctx, "reconciler", now, time.Minute, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %d situations right after completion; the pool would spin", len(claims))
	}
}

func TestSituationRuntimeLoadsReadOnlySnapshotWithoutWriting(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "readonly", "critical", "firing", now)
	// Release the claim: an MCP caller never holds the reconciliation lease.
	if _, err := s.DB().Exec(`UPDATE situations SET lease_owner = NULL, lease_expires_at = NULL WHERE id = ?`, claim.Situation.ID); err != nil {
		t.Fatal(err)
	}
	sit, err := s.GetSituation(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}

	in, _, err := testRuntime(t, s, now).LoadReconciliationInput(ctx, situation.Claim{Situation: sit})
	if err != nil {
		t.Fatalf("lease-free load failed: %v", err)
	}
	if len(in.Facts) != 1 || in.Facts[0].Kind != "symptom_state" {
		t.Fatalf("facts=%+v; a read-only load still sees the deterministic ledger evidence", in.Facts)
	}
	var persisted int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM situation_facts`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("persisted %d facts from a lease-free read", persisted)
	}

	in.Now = now
	if _, err := situation.BuildSnapshot(in); err != nil {
		t.Fatalf("read-only snapshot: %v", err)
	}
}

func TestStoreCheckWritableReportsRealWriteCapability(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CheckWritable(ctx); err != nil {
		t.Fatalf("CheckWritable on a healthy store = %v, want nil", err)
	}
	// A closed store cannot take the write lock, so the probe reports the
	// failure rather than replaying a cached verdict.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckWritable(ctx); err == nil {
		t.Fatal("CheckWritable on a closed store reported writable")
	}
}

func TestSituationRuntimeReleaseToleratesAnAlreadyReleasedClaim(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "contended", "warning", "firing", now)
	runtime := testRuntime(t, s, now)

	due := situation.DueClaim{SituationID: claim.Situation.ID, ClaimOwner: claim.ClaimOwner, ClaimToken: claim.ClaimToken}
	if err := runtime.ReleaseSituation(ctx, due, "boom", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Releasing a claim that is already gone reached the same end state, so it
	// must not report a failure a caller would read as a storage outage.
	if err := runtime.ReleaseSituation(ctx, due, "boom", now.Add(time.Minute)); err != nil {
		t.Fatalf("second release = %v, want nil (routine lease contention is not a failure)", err)
	}
}

// testRuntimeWithFloor is testRuntime with an explicit outward min_severity
// floor, so a test can exercise what the operator floor withholds.
func testRuntimeWithFloor(t *testing.T, s *Store, now time.Time, floor situationmodel.InterruptionPriority) *SituationRuntime {
	t.Helper()
	return NewSituationRuntime(s,
		func(key string) string { return "cmid:" + key },
		func(d AlertDelivery) string { return "signature:" + d.Source },
		func() time.Time { return now },
		SituationRuntimePolicy{MinSeverity: floor, HorizonTier: situation.HorizonHours},
	)
}

// reclaimRuntimeSituation takes the reconciliation lease again after a commit
// released it — the ordinary "next due pass" a worker performs.
func reclaimRuntimeSituation(t *testing.T, s *Store, now time.Time) situation.Claim {
	t.Helper()
	claims, err := s.ClaimDueSituations(context.Background(), "reconciler", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("reclaim=%+v err=%v", claims, err)
	}
	return situation.Claim{Situation: claims[0].Situation, ClaimOwner: claims[0].ClaimOwner, ClaimToken: claims[0].ClaimToken}
}

// mediumFloorAssessment carries a sufficient reason (so a first publication is
// planned at all) whose deterministic Interruption priority is `medium` —
// below a `high` operator floor.
func mediumFloorAssessment(nextUpdate time.Time) situationmodel.Assessment {
	return situationmodel.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: situationmodel.PersistenceUnknown,
		Impact: situationmodel.ImpactUnknown, Novelty: situationmodel.NoveltyInsufficientHistory,
		Causality: situationmodel.CausalityUnknown, Attention: situationmodel.AttentionInvestigate,
		Lifecycle: situationmodel.LifecycleActive, EvidenceQuality: situationmodel.EvidenceQualityComplete,
		SufficientReason: &situationmodel.SufficientReason{
			CandidateID: "confirmed_severe_impact", Code: "confirmed_severe_impact",
			Summary: "confirmed severe impact", EvidenceRefs: []string{"delivery:delivery-floor"},
		},
		ActionContract: situationmodel.ActionContract{
			NextActor: situationmodel.NextActorAlertint, ActionStatus: situationmodel.ActionStatusPlanned,
			NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed"},
		},
		ProposedCadence: situationmodel.CadenceNormal,
	}
}

// criticalFloorAssessment is the deterministic critical anchor — the priority
// the binding constraint says always passes the outward floor.
func criticalFloorAssessment(nextUpdate time.Time) situationmodel.Assessment {
	assessment := mediumFloorAssessment(nextUpdate)
	assessment.Attention = situationmodel.AttentionUrgent
	assessment.SufficientReason = &situationmodel.SufficientReason{
		CandidateID: "critical_anchor", Code: "critical_anchor",
		Summary: "active critical severity", EvidenceRefs: []string{"delivery:delivery-floor"},
	}
	assessment.ProposedCadence = situationmodel.CadenceFast
	return assessment
}

func floorAttempt(t *testing.T, claim situation.Claim, id string, sequence int, assessment situationmodel.Assessment, now time.Time) situation.AssessmentAttempt {
	t.Helper()
	return situation.AssessmentAttempt{
		ID: id, Sequence: sequence, InputVersion: claim.Situation.InputVersion, FactHash: "hash-" + id,
		Actor: situation.AssessmentActorDeterministic, Status: situation.AttemptStatusAuthoritative,
		TriggerReasons: []string{"incident_created"}, SnapshotDigest: "hash-" + id,
		Validated: mustJSONFixture(t, assessment), CreatedAt: now, CompletedAt: &now,
	}
}

func floorTransition(claim situation.Claim, id string, assessment situationmodel.Assessment, now time.Time) situationmodel.Transition {
	return situationmodel.Transition{
		ID: id, SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Lifecycle: assessment.Lifecycle, Attention: assessment.Attention,
		Assessment: &assessment, ActionContract: assessment.ActionContract, Reason: "incident_created", CreatedAt: now,
	}
}

func situationRootCreateRow(t *testing.T, s *Store, situationID string) situationmodel.NotificationIntent {
	t.Helper()
	intents, err := s.SituationNotifications(context.Background(), situationID)
	if err != nil {
		t.Fatal(err)
	}
	var found []situationmodel.NotificationIntent
	for _, intent := range intents {
		if intent.Kind == situationmodel.NotificationSituationRootCreate {
			found = append(found, intent)
		}
	}
	if len(found) != 1 {
		t.Fatalf("root creates=%d, want exactly one for the Situation's whole life: %+v", len(found), intents)
	}
	return found[0]
}

// TestSituationRuntimeWithheldRootReactivatesWhenTheFloorIsCrossed proves a
// Situation whose FIRST publication the operator floor withheld can still
// publish its one root when a later transition crosses the deterministic
// critical floor. The withheld row permanently reserves the Situation's only
// root_create (notification_intents_one_root_create_idx), so before this fix
// every later transition planned a root EDIT against a root that was never
// posted — the deliverer answered "situation root is not published yet"
// forever and the critical poke was lost, violating "`critical` always
// passes".
func TestSituationRuntimeWithheldRootReactivatesWhenTheFloorIsCrossed(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "floor", "warning", "firing", now)
	runtime := testRuntimeWithFloor(t, s, now, situationmodel.PriorityHigh)

	firstUpdate := now.Add(time.Minute)
	quiet := mediumFloorAssessment(firstUpdate)
	if err := runtime.CommitAuthoritative(ctx, claim,
		floorAttempt(t, claim, "attempt-floor-1", 1, quiet, now),
		floorTransition(claim, "transition-floor-1", quiet, now)); err != nil {
		t.Fatal(err)
	}
	withheld := situationRootCreateRow(t, s, claim.Situation.ID)
	if withheld.Status != situationmodel.NotificationWithheldByOperatorSlackFloor {
		t.Fatalf("first publication status=%q, want the operator floor to withhold it", withheld.Status)
	}

	// The Situation escalates to the deterministic critical anchor.
	later := now.Add(2 * time.Minute)
	reclaimed := reclaimRuntimeSituation(t, s, later)
	escalated := criticalFloorAssessment(later.Add(time.Minute))
	if err := testRuntimeWithFloor(t, s, later, situationmodel.PriorityHigh).CommitAuthoritative(ctx, reclaimed,
		floorAttempt(t, reclaimed, "attempt-floor-2", 2, escalated, later),
		floorTransition(reclaimed, "transition-floor-2", escalated, later)); err != nil {
		t.Fatal(err)
	}

	intents, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 {
		t.Fatalf("intents=%+v; the reactivated root is the whole publication — no edit against an unpublished root", intents)
	}
	root := intents[0]
	if root.Kind != situationmodel.NotificationSituationRootCreate || root.Status != situationmodel.NotificationPending {
		t.Fatalf("root=%+v, want the reserved root create returned to pending", root)
	}
	if root.InterruptionPriority == nil || *root.InterruptionPriority != situationmodel.PriorityCritical {
		t.Fatalf("interruption priority=%v, want the critical priority that cleared the floor", root.InterruptionPriority)
	}
	if !root.MainChannelPoke {
		t.Fatal("reactivated root is not a main-channel poke; the critical escalation would never interrupt")
	}
	// Identity must stay exactly as first planned: the reserved row IS the
	// Situation's one root, and its client_msg_id is what keeps a Slack retry
	// of the post idempotent.
	if root.ID != withheld.ID || root.IdempotencyKey != withheld.IdempotencyKey || root.ClientMessageID != withheld.ClientMessageID {
		t.Fatalf("reactivated root identity drifted: %+v vs %+v", root, withheld)
	}
}

// TestSituationRuntimeWithheldRootStaysWithheldBelowTheFloor is the negative
// half: a later transition that still ranks below the operator floor must
// neither publish the reserved root nor plan an undeliverable edit against it.
func TestSituationRuntimeWithheldRootStaysWithheldBelowTheFloor(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "floor", "warning", "firing", now)
	runtime := testRuntimeWithFloor(t, s, now, situationmodel.PriorityHigh)

	quiet := mediumFloorAssessment(now.Add(time.Minute))
	if err := runtime.CommitAuthoritative(ctx, claim,
		floorAttempt(t, claim, "attempt-quiet-1", 1, quiet, now),
		floorTransition(claim, "transition-quiet-1", quiet, now)); err != nil {
		t.Fatal(err)
	}
	first := situationRootCreateRow(t, s, claim.Situation.ID)

	later := now.Add(2 * time.Minute)
	reclaimed := reclaimRuntimeSituation(t, s, later)
	stillQuiet := mediumFloorAssessment(later.Add(time.Minute))
	if err := testRuntimeWithFloor(t, s, later, situationmodel.PriorityHigh).CommitAuthoritative(ctx, reclaimed,
		floorAttempt(t, reclaimed, "attempt-quiet-2", 2, stillQuiet, later),
		floorTransition(reclaimed, "transition-quiet-2", stillQuiet, later)); err != nil {
		t.Fatal(err)
	}

	intents, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 {
		t.Fatalf("intents=%+v; a still-withheld Situation gains no Slack effect at all", intents)
	}
	if intents[0].ID != first.ID || intents[0].Status != situationmodel.NotificationWithheldByOperatorSlackFloor {
		t.Fatalf("root=%+v, want the same row still withheld", intents[0])
	}
}

// TestSituationRuntimeAuthoritativeCommitIsAtomicAcrossTheAttemptBoundary is
// the crash-boundary proof for CommitAuthoritative: the authoritative attempt
// and the transition it authorizes are ONE transaction. A rollback anywhere in
// that transaction must leave no orphan authoritative attempt, because
// LastTrustedAssessment would read the orphan back as the covering decision
// and — with evidence_quality 'complete' — the B+ covered-hash gate would then
// suppress every later pass on an unchanged material hash, so the promised
// transition (urgent poke included) would never commit at all.
func TestSituationRuntimeAuthoritativeCommitIsAtomicAcrossTheAttemptBoundary(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	ctx := context.Background()
	claim := seedRuntimeSituation(t, s, "atomic", "critical", "firing", now)
	runtime := testRuntime(t, s, now)

	nextUpdate := now.Add(time.Minute)
	assessment := criticalFloorAssessment(nextUpdate)
	attempt := floorAttempt(t, claim, "attempt-atomic", 1, assessment, now)

	// An active transition with no next_update_at fails inside the commit
	// transaction, after the attempt insert — the exact crash boundary the
	// two-transaction version could not survive.
	doomed := floorTransition(claim, "transition-atomic", assessment, now)
	doomed.ActionContract.NextUpdateAt = nil
	if err := runtime.CommitAuthoritative(ctx, claim, attempt, doomed); err == nil {
		t.Fatal("expected the invalid transition to fail the commit")
	}

	var attempts int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE id = ?`, "attempt-atomic").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("orphan authoritative attempts=%d; the rolled-back transition left a durable attempt behind", attempts)
	}
	trusted, prior, err := runtime.LastTrustedAssessment(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Trustworthy || prior != nil || trusted.Sequence != 0 {
		t.Fatalf("trusted=%+v prior=%+v; an orphan attempt would cover the hash and suppress every later pass", trusted, prior)
	}
	intents, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 0 {
		t.Fatalf("intents=%+v, want none from a rolled-back commit", intents)
	}

	// "Restart": the same reconciliation runs again and commits for real.
	if err := runtime.CommitAuthoritative(ctx, claim, attempt, floorTransition(claim, "transition-atomic", assessment, now)); err != nil {
		t.Fatalf("post-restart commit: %v", err)
	}
	committed, err := s.GetSituation(ctx, claim.Situation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if committed.CurrentAssessmentID == nil || *committed.CurrentAssessmentID != "attempt-atomic" {
		t.Fatalf("current assessment=%v, want the retried attempt", committed.CurrentAssessmentID)
	}
	if !committed.NextAssessmentAt.Equal(nextUpdate) {
		t.Fatalf("next assessment=%s, want %s", committed.NextAssessmentAt, nextUpdate)
	}
	root := situationRootCreateRow(t, s, claim.Situation.ID)
	if root.Status != situationmodel.NotificationPending {
		t.Fatalf("root=%+v, want the promised poke pending after the retry", root)
	}
}
