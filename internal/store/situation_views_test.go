// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestListSituationsIncludesSilentAndTerminal(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-silent", "host=silent-1", "", situationmodel.LifecycleActive, now)
	insertSituationFixture(t, s, "s-terminal", "host=terminal-1", "terminal-handle", situationmodel.LifecycleClosedUnknown, now)

	got, err := s.ListSituations(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, sit := range got {
		ids[sit.ID] = true
	}
	if !ids["s-silent"] || !ids["s-terminal"] {
		t.Fatalf("list=%+v, want both silent and terminal situations", ids)
	}
}

func TestGetSituationResolvesByIDOrHandle(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-handle-1", "host=db-1", "Db-Prod-Cpu", situationmodel.LifecycleActive, now)

	byID, err := s.GetSituation(context.Background(), "s-handle-1")
	if err != nil {
		t.Fatal(err)
	}
	if byID.ID != "s-handle-1" {
		t.Fatalf("byID=%+v", byID)
	}

	byHandle, err := s.GetSituation(context.Background(), "db-prod-cpu")
	if err != nil {
		t.Fatal(err)
	}
	if byHandle.ID != "s-handle-1" {
		t.Fatalf("byHandle=%+v, want case-insensitive handle resolution", byHandle)
	}

	if _, err := s.GetSituation(context.Background(), "does-not-exist"); err != ErrNotFound {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
}

func TestAnalysisStatesDefaultsMissingRowsToNotRequested(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES ('inc-with-gate', 'g1', 'ready', ?, ?, ?, 1, ?, ?)`, canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO incident_analysis_state (incident_id, status, decision_reason, updated_at)
		VALUES ('inc-with-gate', 'complete', 'l1_attempt_completed', ?)`, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}

	states, err := s.AnalysisStates(ctx, []string{"inc-with-gate", "inc-no-gate-row"})
	if err != nil {
		t.Fatal(err)
	}
	if states["inc-with-gate"].Status != "complete" {
		t.Fatalf("with-gate=%+v", states["inc-with-gate"])
	}
	if states["inc-no-gate-row"].Status != "not_requested" {
		t.Fatalf("no-gate-row=%+v, want not_requested default", states["inc-no-gate-row"])
	}
}

func TestSituationMemberIncidentsReturnsAttachedIncidentsInOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-members", "host=db-1", "", situationmodel.LifecycleActive, now)
	for i, id := range []string{"inc-a", "inc-b"} {
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, 'host=db-1', 'ready', ?, ?, ?, 1, ?, ?)`, id, canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
		attachedAt := now.Add(time.Duration(i) * time.Minute)
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES ('s-members', ?, ?)`,
			id, canonicalTime(attachedAt)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SituationMemberIncidents(ctx, "s-members")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "inc-a" || got[1].ID != "inc-b" {
		t.Fatalf("members=%+v", got)
	}
}

func TestSituationDetailViewsReturnFactsRunsAttemptsAndNotifications(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-detail", "host=db-3", "", situationmodel.LifecycleActive, now)
	claims, err := s.ClaimDueSituations(ctx, "worker-1", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	claim := claims[0]

	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityZabbixProblemHistory, Scope: map[string]string{"host": "db-3"},
		Parameters: json.RawMessage(`{}`), Start: now.Add(-time.Hour), End: now, Limit: 10, Why: "compare",
	}
	run := ObservationRun{
		ID: "run-detail", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		ProposedPlan: plan, ValidatedPlan: plan, Capability: plan.Capability,
		Status: observationmodel.ResultStatusConfirmedValue, ObservedAt: now, Freshness: observationmodel.FreshnessFresh,
		Digest: "digest-1", SourceCallCost: 1, CreatedAt: now,
	}
	if err := s.AppendObservationRun(ctx, claim, run); err != nil {
		t.Fatalf("append run: %v", err)
	}
	fact := observationmodel.Fact{
		ID: "fact-detail", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Kind: "problem_history", Subject: "db-3", Value: json.RawMessage(`{"episodes":1}`),
		SourceCapability: plan.Capability, ObservedAt: now, Freshness: observationmodel.FreshnessFresh,
		ResultStatus: observationmodel.ResultStatusConfirmedValue, Digest: "fact-digest-1",
		EvidenceRefs: []string{"zabbix:event:1"}, Material: true,
	}
	if err := s.AppendSituationFacts(ctx, claim, []observationmodel.Fact{fact}); err != nil {
		t.Fatalf("append facts: %v", err)
	}
	attempt := AssessmentAttempt{
		ID: "attempt-detail", SituationID: claim.Situation.ID, Sequence: 1, InputVersion: claim.Situation.InputVersion,
		FactHash: "facts-v1", Actor: AssessmentActorLLM, Status: AssessmentStatusAuthoritative,
		TriggerReasons: []string{"new_symptom"}, SnapshotDigest: "snap-1",
		Validated: json.RawMessage(`{"attention":"investigate"}`), ValidationAdjustments: json.RawMessage(`[]`),
		CreatedAt: now, CompletedAt: &now,
	}
	if err := s.AppendAssessmentAttempt(ctx, claim, attempt); err != nil {
		t.Fatalf("append attempt: %v", err)
	}
	priority := situationmodel.PriorityMedium
	situationID := claim.Situation.ID
	if err := s.CreateNotificationIntent(ctx, situationmodel.NotificationIntent{
		ID: "notify-detail", IdempotencyKey: "k-detail", SubjectKind: situationmodel.NotificationSubjectSituation,
		SubjectID: situationID, SituationID: &situationID, Kind: situationmodel.NotificationSituationRootCreate,
		MainChannelPoke: true, InterruptionPriority: &priority, Status: situationmodel.NotificationPending,
		ClientMessageID: "client-detail", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	runs, err := s.SituationObservationRuns(ctx, claim.Situation.ID)
	if err != nil || len(runs) != 1 || runs[0].ID != "run-detail" {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	facts, err := s.SituationFacts(ctx, claim.Situation.ID)
	if err != nil || len(facts) != 1 || facts[0].ID != "fact-detail" || !facts[0].Material {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	attempts, err := s.SituationAssessmentAttempts(ctx, claim.Situation.ID)
	if err != nil || len(attempts) != 1 || attempts[0].ID != "attempt-detail" || attempts[0].Status != AssessmentStatusAuthoritative {
		t.Fatalf("attempts=%+v err=%v", attempts, err)
	}
	notifications, err := s.SituationNotifications(ctx, claim.Situation.ID)
	if err != nil || len(notifications) != 1 || notifications[0].ID != "notify-detail" {
		t.Fatalf("notifications=%+v err=%v", notifications, err)
	}
}

func TestSituationRootCoordinatesAbsentUntilFirstPublication(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-root-coords", "host=db-4", "", situationmodel.LifecycleActive, now)

	_, _, ok, err := s.SituationRootCoordinates(context.Background(), "s-root-coords")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no root coordinates before first publication")
	}
}
