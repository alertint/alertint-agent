// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"fmt"
	"sort"
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
	// LoadObservationRun reads one committed run (facts included while its
	// detail is retained) — the source a reuse plan projects from.
	LoadObservationRun(ctx context.Context, runID string) (model.RunRecord, bool, error)
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

// Limitation codes the runner itself stamps onto runs it never dispatched.
const (
	LimitationWallExhausted = "preparation_wall_exhausted"
	LimitationReuseExpired  = "reuse_expired"
	LimitationReuseMissing  = "reuse_missing"
)

// RunPhase executes every plan of phase under a single context used for
// both connector I/O and persistence — the pre-review shape, kept for
// callers that own no separate preparation wall.
func (r *Runner) RunPhase(ctx context.Context, f model.Fence, cycle model.Cycle, phase model.Phase) error {
	return r.RunPhaseBounded(ctx, ctx, f, cycle, phase)
}

// RunPhaseBounded executes every plan in cycle.Draft.Plans whose Phase
// matches phase and that has no committed run yet, in fairness-tier order
// (local, time-sensitive, optional, routine, reuse). ioCtx bounds connector
// I/O only (the preparation wall); ctx bounds persistence (the still-live
// controller claim), so a source that exhausts the wall still leaves
// durable, honest evidence: every remaining plan commits as
// withheld_by_budget with LimitationWallExhausted and the controller keeps
// its own commit. While the cycle's protected optional plan is still
// pending, time-sensitive work runs under ioCtx shortened by the frozen
// optional wall so it cannot starve the protected turn.
//
// A capability with no registered executor never performs I/O — it commits
// a vocabulary_unresolved run instead. A per-plan execution error is
// durable evidence limitation (a failed run), never propagated as a hard
// RunPhase error — the runner must complete every OTHER plan in the phase
// regardless of one plan's failure.
func (r *Runner) RunPhaseBounded(ctx, ioCtx context.Context, f model.Fence, cycle model.Cycle, phase model.Phase) error {
	plans := make([]model.Plan, 0, len(cycle.Draft.Plans))
	for _, p := range cycle.Draft.Plans {
		if p.Phase == phase {
			plans = append(plans, p)
		}
	}
	sort.SliceStable(plans, func(i, j int) bool {
		ri, rj := tierRank(plans[i].Tier), tierRank(plans[j].Tier)
		if ri != rj {
			return ri < rj
		}
		return plans[i].ID < plans[j].ID
	})

	optionalPending := false
	for _, p := range plans {
		if p.Tier == model.TierOptional {
			optionalPending = true
		}
	}
	optionalWall := time.Duration(cycle.Draft.Allocation.OptionalWallMilliseconds) * time.Millisecond

	for _, p := range plans {
		done, err := r.store.HasObservationRun(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("observation: check existing run for plan %s: %w", p.ID, err)
		}
		if done {
			if p.Tier == model.TierOptional {
				optionalPending = false
			}
			continue
		}

		var run model.Run
		switch {
		case p.Tier == model.TierReuse:
			run, err = r.reuseRun(ctx, p)
			if err != nil {
				return err
			}
		case p.Tier != model.TierLocal && ioCtx.Err() != nil:
			run = withheldByWallRun(p, r.clock())
		default:
			planCtx := ioCtx
			var cancel context.CancelFunc
			if optionalPending && p.Tier == model.TierTimeSensitive && optionalWall > 0 {
				if deadline, ok := ioCtx.Deadline(); ok {
					planCtx, cancel = context.WithDeadline(ioCtx, deadline.Add(-optionalWall))
				}
			}
			run = r.runOne(ctx, planCtx, f, cycle, p)
			if cancel != nil {
				cancel()
			}
		}
		if p.Tier == model.TierOptional {
			optionalPending = false
		}
		if err := r.store.CommitObservationRun(ctx, f, run, r.clock()); err != nil {
			return fmt.Errorf("observation: commit run for plan %s: %w", p.ID, err)
		}
	}
	return nil
}

// runOne dispatches p through its executor: connector I/O under ioCtx,
// every durable reservation/outcome under ctx.
func (r *Runner) runOne(ctx, ioCtx context.Context, f model.Fence, cycle model.Cycle, p model.Plan) model.Run {
	executor, ok := r.executors[p.Capability]
	if !ok {
		return unresolvedRun(p, r.clock())
	}

	// One span per plan dispatch, wrapping only the out-of-transaction
	// connector I/O — nothing durable happens inside it.
	ioCtx, span := tracer().Start(ioCtx, SpanObservationRun, trace.WithAttributes(
		AttrCycleID.String(cycle.ID), AttrPlanID.String(p.ID),
		AttrCapability.String(string(p.Capability)), AttrPhase.String(string(p.Phase)),
	))
	defer span.End()

	recorder := &reservingRecorder{store: r.store, persistCtx: ctx, fence: f, cycleID: cycle.ID, planID: p.ID, clock: r.clock}
	run, err := executor.Execute(ioCtx, p, recorder)
	if err != nil {
		span.SetAttributes(AttrResultClass.String(string(model.ResultFailed)))
		return failedRun(p, r.clock())
	}
	span.SetAttributes(AttrResultClass.String(string(run.Status)))
	return run
}

// reuseRun projects p.ReuseRunID into the current cycle: no I/O, no facts
// of its own (the projection follows the source run's facts), the SOURCE
// run's coverage/status/observation/expiry preserved verbatim — except
// that a source whose evidence has already expired (ExpiresAt passed, or
// detail expired under retention) projects as stale.
func (r *Runner) reuseRun(ctx context.Context, p model.Plan) (model.Run, error) {
	now := r.clock()
	src, found, err := r.store.LoadObservationRun(ctx, p.ReuseRunID)
	if err != nil {
		return model.Run{}, fmt.Errorf("observation: load reusable run %s for plan %s: %w", p.ReuseRunID, p.ID, err)
	}
	if !found {
		return model.Run{
			ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: model.ResultUnavailable,
			Coverage:        model.Coverage{Start: p.Start, End: p.End, Complete: false},
			LimitationCodes: []string{LimitationReuseMissing},
			ObservedAt:      now, ExpiresAt: now,
		}, nil
	}
	reused := src.Run.ID
	run := model.Run{
		ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: src.Run.Status,
		Coverage:        src.Run.Coverage,
		LimitationCodes: append([]string(nil), src.Run.LimitationCodes...),
		ObservedAt:      src.Run.ObservedAt, ExpiresAt: src.Run.ExpiresAt,
		ReusedFromRunID: &reused,
	}
	if src.DetailState == model.DetailStateExpired || !now.Before(src.Run.ExpiresAt) {
		run.Status = model.ResultStale
		run.LimitationCodes = append(run.LimitationCodes, LimitationReuseExpired)
	}
	return run, nil
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

func withheldByWallRun(p model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: model.ResultWithheldByBudget,
		Coverage:        model.Coverage{Start: p.Start, End: p.End, Complete: false},
		LimitationCodes: []string{LimitationWallExhausted},
		ObservedAt:      now, ExpiresAt: now,
	}
}

// reservingRecorder is the production RequestRecorder: every reservation
// and outcome goes straight through to the durable store, under this
// runner invocation's exact fence/cycle/plan identity — and under the
// persistence context, never the connector's I/O context, so an exhausted
// preparation wall can never lose the outcome of a request that really
// happened.
type reservingRecorder struct {
	store           PreparationStore
	persistCtx      context.Context
	fence           model.Fence
	cycleID, planID string
	clock           func() time.Time
}

func (rr *reservingRecorder) BeforeRequest(context.Context) (model.RequestReservation, error) {
	return rr.store.ReserveObservationRequest(rr.persistCtx, rr.fence, rr.cycleID, rr.planID, rr.clock())
}

func (rr *reservingRecorder) AfterRequest(_ context.Context, outcome model.RequestOutcome) error {
	return rr.store.CompleteObservationRequest(rr.persistCtx, outcome)
}
