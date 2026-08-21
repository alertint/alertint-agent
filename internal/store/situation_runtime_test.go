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
