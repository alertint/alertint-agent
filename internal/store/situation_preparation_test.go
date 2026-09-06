// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

func testPlan(now time.Time) observationmodel.Plan {
	return observationmodel.Plan{
		Capability: observationmodel.CapabilityPrometheusQuery, Phase: observationmodel.PhaseAssessment,
		Scope: observationmodel.Scope{GroupKey: "service=checkout", Source: "alertmanager",
			SubjectID: "signal-a", Labels: map[string]string{"service": "checkout"}},
		Parameters: []byte(`{"expression":"up{service=\"checkout\"}"}`),
		Start:      now.Add(-time.Minute), End: now, EligibleAt: now,
		Limit: 20, MaxRequests: 2, Purpose: "corroborate_member",
	}
}

func TestPreparationReservesOnlyItsConfiguredRequestBudget(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-budget", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, cycle.Draft.Plans[0].ID, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, cycle.Draft.Plans[0].ID, now); !errors.Is(err, observationmodel.ErrBudgetExhausted) {
		t.Fatalf("third reservation: %v", err)
	}
}

func TestBeginPreparationRetryReturnsFrozenDraft(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-retry", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)

	first, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}

	// A later retry with a DIFFERENT recomputed draft (different anchor,
	// different config digest, different window) must return the ORIGINAL
	// frozen cycle unchanged — spec.md: "Retry uses those exact values even
	// if the wall clock ... has changed."
	later := now.Add(10 * time.Minute)
	changedPlan := testPlan(later)
	second, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: later, ConfigDigest: "cfg-2-different", Plans: []observationmodel.Plan{changedPlan}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("retry opened a different cycle: %s != %s", second.ID, first.ID)
	}
	if second.Draft.ConfigDigest != "cfg-1" {
		t.Fatalf("retry did not preserve frozen config digest: got %q", second.Draft.ConfigDigest)
	}
	if !second.Draft.Anchor.Equal(now) {
		t.Fatalf("retry did not preserve frozen anchor: got %v want %v", second.Draft.Anchor, now)
	}
	if second.Draft.Plans[0].ID != first.Draft.Plans[0].ID {
		t.Fatal("retry produced a different plan identity for the same frozen cycle")
	}
}

func TestBeginPreparationStaleClaimRejected(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-stale", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken + 1000} // wrong token
	p := testPlan(now)
	_, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err == nil {
		t.Fatal("expected stale-claim rejection")
	}
}

func TestReserveObservationRequestReopenSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-reopen", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)
	p.MaxRequests = 6 // plan-own cap must not undercut the cycle cap this test exercises
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, cycle.Draft.Plans[0].ID, now); err != nil {
		t.Fatal(err)
	}

	// "Reopen" by loading the exact same cycle again (simulating a restart
	// that recovers the open cycle from disk): the prior reservation must
	// still count against the budget.
	reloaded, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ID != cycle.ID {
		t.Fatal("reopen created a new cycle instead of loading the existing one")
	}
	for i := 0; i < 5; i++ {
		if _, err := st.ReserveObservationRequest(ctx, f, reloaded.ID, reloaded.Draft.Plans[0].ID, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ReserveObservationRequest(ctx, f, reloaded.ID, reloaded.Draft.Plans[0].ID, now); !errors.Is(err, observationmodel.ErrBudgetExhausted) {
		t.Fatalf("7th reservation across reopen: %v", err)
	}
}

func TestCommitObservationRunIdempotentReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-run", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	planID := cycle.Draft.Plans[0].ID
	if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, planID, now); err != nil {
		t.Fatal(err)
	}

	run := observationmodel.Run{
		ID: "run:test:1", CycleID: cycle.ID, PlanID: planID,
		Status:   observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: p.Start, End: p.End, Complete: true, Returned: 1},
		Facts: []observationmodel.Fact{{
			ID: "fact:test:1", RunID: "run:test:1", Kind: "metric_summary", Subject: "signal-a",
			Digest: "d1", SchemaVersion: 2, Value: []byte(`{"up":1}`),
			ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh,
			ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour), Material: true,
		}},
		ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := st.CommitObservationRun(ctx, f, run, now); err != nil {
		t.Fatal(err)
	}
	// Identical replay under a valid claim is a no-op success.
	if err := st.CommitObservationRun(ctx, f, run, now); err != nil {
		t.Fatalf("identical replay must succeed: %v", err)
	}
	// Conflicting content under the same ID fails.
	conflicting := run
	conflicting.Facts = []observationmodel.Fact{{
		ID: "fact:test:1", RunID: "run:test:1", Kind: "metric_summary", Subject: "signal-a",
		Digest: "d1", SchemaVersion: 2, Value: []byte(`{"up":0}`),
		ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh,
		ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour), Material: true,
	}}
	if err := st.CommitObservationRun(ctx, f, conflicting, now); !errors.Is(err, observationmodel.ErrConflictingReplay) {
		t.Fatalf("conflicting replay: %v", err)
	}
}

func TestCommitObservationRunStaleClaimRejected(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-run-stale", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	planID := cycle.Draft.Plans[0].ID
	if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, planID, now); err != nil {
		t.Fatal(err)
	}

	stale := f
	stale.Token = f.Token + 1000
	run := observationmodel.Run{
		ID: "run:test:2", CycleID: cycle.ID, PlanID: planID,
		Status:     observationmodel.ResultConfirmedEmpty,
		Coverage:   observationmodel.Coverage{Start: p.Start, End: p.End, Complete: true},
		ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := st.CommitObservationRun(ctx, stale, run, now); err == nil {
		t.Fatal("expected stale-claim rejection for run commit")
	}
}

func TestListObservationRunsPagination(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-list", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}

	plans := make([]observationmodel.Plan, 3)
	for i := range plans {
		p := testPlan(now)
		p.Scope.SubjectID += string(rune('a' + i))
		plans[i] = p
	}
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: plans}, 6)
	if err != nil {
		t.Fatal(err)
	}
	for i, dp := range cycle.Draft.Plans {
		if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, dp.ID, now); err != nil {
			t.Fatal(err)
		}
		run := observationmodel.Run{
			ID: "run:list:" + dp.ID, CycleID: cycle.ID, PlanID: dp.ID,
			Status:     observationmodel.ResultConfirmedEmpty,
			Coverage:   observationmodel.Coverage{Start: now, End: now, Complete: true},
			ObservedAt: now.Add(time.Duration(i) * time.Second), ExpiresAt: now.Add(24 * time.Hour),
		}
		if err := st.CommitObservationRun(ctx, f, run, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	page1, cursor, err := st.ListObservationRuns(ctx, id, "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1))
	}
	if cursor == "" {
		t.Fatal("expected a non-empty cursor for a partial page")
	}
	page2, cursor2, err := st.ListObservationRuns(ctx, id, "", cursor, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(page2))
	}
	if cursor2 != "" {
		t.Fatalf("expected empty cursor at the end of the list, got %q", cursor2)
	}
}

func TestPruneUnusedObservationDetailsExactBoundary(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=checkout", now)
	claim := claimSituation(t, st, id, "p4-prune", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	p := testPlan(now)
	cycle, err := st.BeginPreparation(ctx, f,
		observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-1", Plans: []observationmodel.Plan{p}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	planID := cycle.Draft.Plans[0].ID
	if _, err := st.ReserveObservationRequest(ctx, f, cycle.ID, planID, now); err != nil {
		t.Fatal(err)
	}
	run := observationmodel.Run{
		ID: "run:prune:1", CycleID: cycle.ID, PlanID: planID,
		Status:   observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: p.Start, End: p.End, Complete: true, Returned: 1},
		Facts: []observationmodel.Fact{{
			ID: "fact:prune:1", RunID: "run:prune:1", Kind: "metric_summary", Subject: "signal-a",
			Digest: "d1", SchemaVersion: 2, Value: []byte(`{"up":1}`),
			ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh,
			ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour), Material: true,
		}},
		ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := st.CommitObservationRun(ctx, f, run, now); err != nil {
		t.Fatal(err)
	}
	// Simulate the cycle having since sealed and been superseded by a later
	// one (sealPreparationCycleTx/BeginPreparation's own reference-lifecycle
	// transitions are covered by their own tests) so this run is genuinely
	// "unused" and its ten-day clock is the only thing gating expiry.
	if _, err := st.DB().ExecContext(ctx, `UPDATE situation_observation_references SET superseded = 1 WHERE run_id = ?`, run.ID); err != nil {
		t.Fatal(err)
	}

	// Before the ten-day boundary: nothing is eligible.
	beforeBoundary := now.Add(10*24*time.Hour - time.Second)
	n, err := st.PruneUnusedObservationDetails(ctx, beforeBoundary, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("pruned %d runs before the ten-day boundary, want 0", n)
	}

	// At/after the exact ten-day boundary from the run's completion time,
	// unused (unreferenced) detail becomes eligible.
	atBoundary := now.Add(10 * 24 * time.Hour)
	n, err = st.PruneUnusedObservationDetails(ctx, atBoundary, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d runs at the ten-day boundary, want 1", n)
	}

	runs, _, err := st.ListObservationRuns(ctx, id, "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 archived run, got %d", len(runs))
	}
	if runs[0].DetailState != observationmodel.DetailStateExpired {
		t.Fatalf("detail_state = %q, want expired", runs[0].DetailState)
	}
	if len(runs[0].Run.Facts) != 0 {
		t.Fatal("expired run must not expose fact values through the archive read")
	}
	// Immutable identity/accounting survive expiry.
	if runs[0].Run.ID != run.ID {
		t.Fatal("run identity must survive detail expiry")
	}
}
