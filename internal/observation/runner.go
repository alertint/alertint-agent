// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/trace"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// RequestRecorder brackets exactly one physical HTTP/RPC dispatch: a
// connector calls BeforeRequest immediately before issuing the request
// (consuming a durable reservation) and AfterRequest immediately after
// classifying its outcome. A context-scoped recorder — never a shared
// package-level one — keeps a connector's retries/secondary lookups each
// individually accounted for.
type RequestRecorder interface {
	BeforeRequest(ctx context.Context) (model.RequestReservation, error)
	AfterRequest(ctx context.Context, outcome model.RequestOutcome) error
}

// Executor runs one frozen Plan to completion, using recorder to account
// for every physical request the underlying connector actually makes
// (including retries and secondary lookups). It returns a fully-formed Run
// ready for CommitObservationRun — never partial state the runner must
// finish assembling.
type Executor interface {
	Execute(ctx context.Context, plan model.Plan, recorder RequestRecorder) (model.Run, error)
}

// PreparationStore is the narrow persistence boundary Runner depends on —
// the subset of internal/store's Task 2 API surface RunPhase actually
// calls. *store.Store structurally satisfies it.
type PreparationStore interface {
	ReserveObservationRequest(ctx context.Context, f model.Fence, cycleID, planID string, now time.Time) (model.RequestReservation, error)
	CompleteObservationRequest(ctx context.Context, outcome model.RequestOutcome) error
	CommitObservationRun(ctx context.Context, f model.Fence, run model.Run, now time.Time) error
	HasObservationRun(ctx context.Context, planID string) (bool, error)
}

// Runner executes a frozen cycle's plans for one phase, reusing any plan
// that already has a committed run (a retry within the same open cycle)
// and executing only the missing ones.
type Runner struct {
	store     PreparationStore
	executors map[model.Capability]Executor
	clock     func() time.Time
}

// NewRunner constructs a Runner. clock defaults to the UTC wall clock when
// nil.
func NewRunner(store PreparationStore, executors map[model.Capability]Executor, clock func() time.Time) *Runner {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Runner{store: store, executors: executors, clock: clock}
}

// RunPhase executes every plan in cycle.Draft.Plans whose Phase matches
// phase and that has no committed run yet. A capability with no registered
// executor never performs I/O — it commits a vocabulary_unresolved run
// instead, exactly the honest-state spec.md requires for an unresolvable
// capability. A per-plan execution error is durable evidence limitation
// (a failed run), never propagated as a hard RunPhase error — the runner
// must complete every OTHER plan in the phase regardless of one plan's
// failure.
func (r *Runner) RunPhase(ctx context.Context, f model.Fence, cycle model.Cycle, phase model.Phase) error {
	for _, p := range cycle.Draft.Plans {
		if p.Phase != phase {
			continue
		}
		done, err := r.store.HasObservationRun(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("observation: check existing run for plan %s: %w", p.ID, err)
		}
		if done {
			continue
		}

		run := r.runOne(ctx, f, cycle, p)
		if err := r.store.CommitObservationRun(ctx, f, run, r.clock()); err != nil {
			return fmt.Errorf("observation: commit run for plan %s: %w", p.ID, err)
		}
	}
	return nil
}

func (r *Runner) runOne(ctx context.Context, f model.Fence, cycle model.Cycle, p model.Plan) model.Run {
	executor, ok := r.executors[p.Capability]
	if !ok {
		return unresolvedRun(p, r.clock())
	}

	// One span per plan dispatch, wrapping only the out-of-transaction
	// connector I/O — nothing durable happens inside it.
	ctx, span := tracer().Start(ctx, SpanObservationRun, trace.WithAttributes(
		AttrCycleID.String(cycle.ID), AttrPlanID.String(p.ID),
		AttrCapability.String(string(p.Capability)), AttrPhase.String(string(p.Phase)),
	))
	defer span.End()

	recorder := &reservingRecorder{store: r.store, fence: f, cycleID: cycle.ID, planID: p.ID, clock: r.clock}
	run, err := executor.Execute(ctx, p, recorder)
	if err != nil {
		span.SetAttributes(AttrResultClass.String(string(model.ResultFailed)))
		return failedRun(p, r.clock())
	}
	span.SetAttributes(AttrResultClass.String(string(run.Status)))
	return run
}

func unresolvedRun(p model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: model.ResultVocabularyUnresolved,
		Coverage:        model.Coverage{Start: p.Start, End: p.End, Complete: false},
		LimitationCodes: []string{"capability_unresolved"},
		ObservedAt:      now, ExpiresAt: now.Add(model.MaxWindowHoursMetricsLogs * time.Hour),
	}
}

func failedRun(p model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: model.ResultFailed,
		Coverage:        model.Coverage{Start: p.Start, End: p.End, Complete: false},
		LimitationCodes: []string{"execution_failed"},
		ObservedAt:      now, ExpiresAt: now.Add(model.MaxWindowHoursMetricsLogs * time.Hour),
	}
}

// reservingRecorder is the production RequestRecorder: every reservation
// and outcome goes straight through to the durable store, under this
// runner invocation's exact fence/cycle/plan identity.
type reservingRecorder struct {
	store           PreparationStore
	fence           model.Fence
	cycleID, planID string
	clock           func() time.Time
}

func (rr *reservingRecorder) BeforeRequest(ctx context.Context) (model.RequestReservation, error) {
	return rr.store.ReserveObservationRequest(ctx, rr.fence, rr.cycleID, rr.planID, rr.clock())
}

func (rr *reservingRecorder) AfterRequest(ctx context.Context, outcome model.RequestOutcome) error {
	return rr.store.CompleteObservationRequest(ctx, outcome)
}
