// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"errors"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

type fakePreparationStore struct {
	hasRun       map[string]bool
	reservations int
	completions  int
	committed    []model.Run
	reserveErr   error
}

func (f *fakePreparationStore) ReserveObservationRequest(ctx context.Context, fence model.Fence, cycleID, planID string, now time.Time) (model.RequestReservation, error) {
	if f.reserveErr != nil {
		return model.RequestReservation{}, f.reserveErr
	}
	f.reservations++
	return model.RequestReservation{ID: "req", CycleID: cycleID, PlanID: planID, Ordinal: f.reservations, ReservedAt: now}, nil
}

func (f *fakePreparationStore) CompleteObservationRequest(ctx context.Context, outcome model.RequestOutcome) error {
	f.completions++
	return nil
}

func (f *fakePreparationStore) CommitObservationRun(ctx context.Context, fence model.Fence, run model.Run, now time.Time) error {
	f.committed = append(f.committed, run)
	return nil
}

func (f *fakePreparationStore) HasObservationRun(ctx context.Context, planID string) (bool, error) {
	return f.hasRun[planID], nil
}

type fakeExecutor struct {
	run   model.Run
	err   error
	calls int
}

func (f *fakeExecutor) Execute(ctx context.Context, plan model.Plan, recorder RequestRecorder) (model.Run, error) {
	f.calls++
	if f.err != nil {
		return model.Run{}, f.err
	}
	if _, err := recorder.BeforeRequest(ctx); err != nil {
		return model.Run{}, err
	}
	_ = recorder.AfterRequest(ctx, model.RequestOutcome{ReservationID: "req", RequestStarted: model.RequestStartedTrue, Code: "ok", CompletedAt: time.Now().UTC()})
	return f.run, nil
}

func testCycle(plans ...model.Plan) model.Cycle {
	return model.Cycle{ID: "cycle-1", Draft: model.CycleDraft{Plans: plans}}
}

func TestRunPhaseExecutesAndCommitsPlans(t *testing.T) {
	plan := model.Plan{ID: "plan-1", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment}
	store := &fakePreparationStore{hasRun: map[string]bool{}}
	exec := &fakeExecutor{run: model.Run{ID: "run-1", CycleID: "cycle-1", PlanID: "plan-1", Status: model.ResultConfirmedEmpty}}
	r := NewRunner(store, map[model.Capability]Executor{model.CapabilityPrometheusQuery: exec}, nil)

	if err := r.RunPhase(context.Background(), model.Fence{}, testCycle(plan), model.PhaseAssessment); err != nil {
		t.Fatal(err)
	}
	if exec.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", exec.calls)
	}
	if store.reservations != 1 || store.completions != 1 {
		t.Fatalf("reservations=%d completions=%d, want 1/1", store.reservations, store.completions)
	}
	if len(store.committed) != 1 || store.committed[0].ID != "run-1" {
		t.Fatalf("committed = %+v, want run-1", store.committed)
	}
}

func TestRunPhaseSkipsAlreadyExecutedPlans(t *testing.T) {
	plan := model.Plan{ID: "plan-1", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment}
	store := &fakePreparationStore{hasRun: map[string]bool{"plan-1": true}}
	exec := &fakeExecutor{}
	r := NewRunner(store, map[model.Capability]Executor{model.CapabilityPrometheusQuery: exec}, nil)

	if err := r.RunPhase(context.Background(), model.Fence{}, testCycle(plan), model.PhaseAssessment); err != nil {
		t.Fatal(err)
	}
	if exec.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 (plan already has a run)", exec.calls)
	}
}

func TestRunPhaseUnresolvedCapabilityNoExecutorNoIO(t *testing.T) {
	plan := model.Plan{ID: "plan-1", CycleID: "cycle-1", Capability: model.CapabilitySentryIssues, Phase: model.PhaseAssessment, Start: time.Now(), End: time.Now()}
	store := &fakePreparationStore{hasRun: map[string]bool{}}
	r := NewRunner(store, map[model.Capability]Executor{}, nil) // no executors registered

	if err := r.RunPhase(context.Background(), model.Fence{}, testCycle(plan), model.PhaseAssessment); err != nil {
		t.Fatal(err)
	}
	if store.reservations != 0 {
		t.Fatalf("reservations = %d, want 0 (no I/O for an unresolvable capability)", store.reservations)
	}
	if len(store.committed) != 1 || store.committed[0].Status != model.ResultVocabularyUnresolved {
		t.Fatalf("committed = %+v, want one vocabulary_unresolved run", store.committed)
	}
}

func TestRunPhaseExecutorFailureCommitsFailedRunAndContinues(t *testing.T) {
	failing := model.Plan{ID: "plan-fail", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment, Start: time.Now(), End: time.Now()}
	ok := model.Plan{ID: "plan-ok", CycleID: "cycle-1", Capability: model.CapabilityLokiQuery, Phase: model.PhaseAssessment}
	store := &fakePreparationStore{hasRun: map[string]bool{}}
	failExec := &fakeExecutor{err: errors.New("boom")}
	okExec := &fakeExecutor{run: model.Run{ID: "run-ok", CycleID: "cycle-1", PlanID: "plan-ok", Status: model.ResultConfirmedEmpty}}
	r := NewRunner(store, map[model.Capability]Executor{
		model.CapabilityPrometheusQuery: failExec,
		model.CapabilityLokiQuery:       okExec,
	}, nil)

	if err := r.RunPhase(context.Background(), model.Fence{}, testCycle(failing, ok), model.PhaseAssessment); err != nil {
		t.Fatal(err)
	}
	if len(store.committed) != 2 {
		t.Fatalf("committed = %d runs, want 2 (one failed, one ok)", len(store.committed))
	}
	foundFailed, foundOK := false, false
	for _, run := range store.committed {
		if run.PlanID == "plan-fail" && run.Status == model.ResultFailed {
			foundFailed = true
		}
		if run.PlanID == "plan-ok" && run.Status == model.ResultConfirmedEmpty {
			foundOK = true
		}
	}
	if !foundFailed || !foundOK {
		t.Fatalf("expected both a failed run and the ok run, got %+v", store.committed)
	}
}

func TestRunPhaseOnlyRunsMatchingPhase(t *testing.T) {
	lifecyclePlan := model.Plan{ID: "plan-lc", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseLifecycle}
	assessmentPlan := model.Plan{ID: "plan-as", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment}
	store := &fakePreparationStore{hasRun: map[string]bool{}}
	exec := &fakeExecutor{run: model.Run{ID: "run-lc", CycleID: "cycle-1", PlanID: "plan-lc", Status: model.ResultConfirmedEmpty}}
	r := NewRunner(store, map[model.Capability]Executor{model.CapabilityPrometheusQuery: exec}, nil)

	if err := r.RunPhase(context.Background(), model.Fence{}, testCycle(lifecyclePlan, assessmentPlan), model.PhaseLifecycle); err != nil {
		t.Fatal(err)
	}
	if exec.calls != 1 {
		t.Fatalf("executor calls = %d, want 1 (only the lifecycle-phase plan)", exec.calls)
	}
}
