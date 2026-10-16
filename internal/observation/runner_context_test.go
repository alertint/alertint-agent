// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"errors"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

type localContextExecutor struct {
	beforeRead func()
	readErr    error
}

func (e *localContextExecutor) Execute(ctx context.Context, plan model.Plan, _ RequestRecorder) (model.Run, error) {
	if e.beforeRead != nil {
		e.beforeRead()
	}
	e.readErr = ctx.Err()
	if e.readErr != nil {
		return model.Run{}, e.readErr
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID,
		Status: model.ResultConfirmedEmpty, Coverage: model.Coverage{Complete: true},
	}, nil
}

type contextPreparationStore struct{ fakePreparationStore }

func (s *contextPreparationStore) CommitObservationRun(ctx context.Context, fence model.Fence, run model.Run, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.fakePreparationStore.CommitObservationRun(ctx, fence, run, now)
}

func TestRunPhaseBoundedLocalReadSurvivesExpiredIOWall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ioCtx, ioCancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer ioCancel()
	plan := model.Plan{ID: "local", CycleID: "cycle-1", Capability: model.CapabilityChangeEvents, Phase: model.PhaseAssessment, Tier: model.TierLocal}
	st := &contextPreparationStore{}
	exec := &localContextExecutor{}
	runner := NewRunner(st, map[model.Capability]Executor{model.CapabilityChangeEvents: exec}, nil)

	if err := runner.RunPhaseBounded(ctx, ioCtx, model.Fence{}, testCycle(plan), model.PhaseAssessment); err != nil {
		t.Fatal(err)
	}
	if len(st.committed) != 1 || st.committed[0].Status != model.ResultConfirmedEmpty || !st.committed[0].Coverage.Complete {
		t.Fatalf("committed = %+v, want complete local observation despite expired I/O wall", st.committed)
	}
	if st.reservations != 0 || st.completions != 0 {
		t.Fatal("local read spent a physical request reservation")
	}
}

func TestRunPhaseBoundedLocalReadStopsOnControllerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plan := model.Plan{ID: "local", CycleID: "cycle-1", Capability: model.CapabilityChangeEvents, Phase: model.PhaseAssessment, Tier: model.TierLocal}
	st := &contextPreparationStore{}
	exec := &localContextExecutor{beforeRead: cancel}
	runner := NewRunner(st, map[model.Capability]Executor{model.CapabilityChangeEvents: exec}, nil)

	err := runner.RunPhaseBounded(ctx, context.Background(), model.Fence{}, testCycle(plan), model.PhaseAssessment)
	if !errors.Is(exec.readErr, context.Canceled) {
		t.Fatalf("local execution error = %v, want controller cancellation", exec.readErr)
	}
	if !errors.Is(err, context.Canceled) || len(st.committed) != 0 {
		t.Fatalf("err = %v, committed = %+v, want canceled controller and no commit", err, st.committed)
	}
}

func TestRunPhaseBoundedExternalPlansRemainWithheldAfterIOWall(t *testing.T) {
	for _, tier := range []string{model.TierTimeSensitive, model.TierOptional, model.TierRoutine} {
		t.Run(tier, func(t *testing.T) {
			ctx := context.Background()
			ioCtx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			defer cancel()
			plan := model.Plan{ID: "external", CycleID: "cycle-1", Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment, Tier: tier}
			st := &contextPreparationStore{}
			runner := NewRunner(st, map[model.Capability]Executor{model.CapabilityPrometheusQuery: &fakeExecutor{}}, nil)
			if err := runner.RunPhaseBounded(ctx, ioCtx, model.Fence{}, testCycle(plan), model.PhaseAssessment); err != nil {
				t.Fatal(err)
			}
			if len(st.committed) != 1 || st.committed[0].Status != model.ResultWithheldByBudget {
				t.Fatalf("committed = %+v, want withheld external observation", st.committed)
			}
			codes := st.committed[0].LimitationCodes
			if len(codes) != 1 || codes[0] != LimitationWallExhausted || st.reservations != 0 || st.completions != 0 {
				t.Fatalf("codes = %v, reservations = %d, completions = %d", codes, st.reservations, st.completions)
			}
		})
	}
}
