// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Durable Situation foundation runtime (Task 8)
//
// foundationRuntime owns the process-local lifecycle Tasks 6 and 7 built
// but nothing previously ran: the dispatch worker that drains the
// correlation outbox, the input worker that drains the Situation input
// outbox, and the Reconstructor that converges durable state at startup
// before either worker — or Receivers — ever runs. This slice is
// integration-only: it does not run the Situation controller, prepare
// evidence, schedule Triage policy, publish Situation Slack, or create
// operator artifacts, and the Correlator it wires alongside keeps owning
// fixed-window expiry and the existing Incident Triage schedule.
// ----------------------------------------------------------------------

// foundationRuntime bundles the durable Situation foundation's two
// background workers and its startup Reconstructor. main constructs
// exactly one per process.
type foundationRuntime struct {
	dispatch      *correlator.DispatchWorker
	inputs        *situation.InputWorker
	reconstructor *situation.Reconstructor
}

// newFoundationRuntime wires the foundation runtime against a real store
// and the already-constructed Correlator (used only as the dispatch
// worker's DeliveryApplier — the Correlator's own Start/Stop lifecycle
// stays owned by runServe, since it keeps running fixed-window expiry and
// Triage retry independent of this runtime). owner must be a non-empty,
// per-process identity; the dispatch and input workers derive their own
// lease identities from it ("<owner>:dispatch", "<owner>:input") so two
// workers from the same process can never fence each other's claims.
func newFoundationRuntime(st *store.Store, cor *correlator.Correlator, owner string, logger *slog.Logger) *foundationRuntime {
	if strings.TrimSpace(owner) == "" {
		panic("cmd/alertint: foundation runtime requires a non-empty owner")
	}
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: owner + ":dispatch"}, logger)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: owner + ":input"}, logger)
	reconstructor := situation.NewReconstructor(st, func() time.Time { return time.Now().UTC() }).WithReplay(dispatch, inputs)
	return &foundationRuntime{dispatch: dispatch, inputs: inputs, reconstructor: reconstructor}
}

// Reconstruct runs the zero-outward-effect startup pass: recover expired
// leases, drain delivery dispatches, drain Situation inputs, then
// represent unowned operational Incidents. Callers must not start
// Receivers — or anything else that accepts new inbound work — if this
// returns a non-nil error.
func (r *foundationRuntime) Reconstruct(ctx context.Context) (situation.Reconstruction, error) {
	return r.reconstructor.Run(ctx)
}

// logReconstructionReport logs one Reconstructor.Run pass's report at
// startup, then — if either fenced outbox table has permanently failed
// (dead-lettered, MaxAttempts exhausted) rows — warns loudly: a
// dead-lettered row is durably on disk but excluded from every future
// claim, and otherwise invisible without hand-written SQL
// (docs/concepts/architecture.md: "nothing is ever silently dropped").
// Factored out of runServe's own reconstruct closure to keep that
// function's branching count where it belongs — on the actual startup
// decision tree, not on how a report gets logged.
func logReconstructionReport(logger *slog.Logger, report situation.Reconstruction) {
	logger.Info("situation foundation reconstructed",
		slog.Int64("alert_dispatch_leases_recovered", report.RecoveredLeases.AlertDispatches),
		slog.Int64("situation_input_leases_recovered", report.RecoveredLeases.SituationInputs),
		slog.Int64("situation_leases_recovered", report.RecoveredLeases.Situations),
		slog.Int("deliveries_replayed", report.ReplayedDeliveries),
		slog.Int("inputs_replayed", report.ReplayedInputs),
		slog.Int("groups_represented", report.RepresentedGroups),
		slog.Int("incidents_represented", report.RepresentedIncidents),
		slog.Int("dead_lettered_dispatches", report.DeadLettered.AlertDispatches),
		slog.Int("dead_lettered_inputs", report.DeadLettered.SituationInputs),
	)
	if report.DeadLettered.AlertDispatches > 0 || report.DeadLettered.SituationInputs > 0 {
		logger.Warn("situation foundation has dead-lettered work excluded from future claims",
			slog.Int("dead_lettered_dispatches", report.DeadLettered.AlertDispatches),
			slog.Int("dead_lettered_inputs", report.DeadLettered.SituationInputs),
		)
	}
}

// runFoundationReconstruction runs one foundationRuntime.Reconstruct pass
// and logs its report — the reconstruct step of runServe's own startupSeq.
// A named function, not a closure (Task 9 fix round, Finding #3): its own
// `if err != nil` branch would otherwise count toward runServe's own
// golangci-lint gocyclo complexity purely because of Go's lexical nesting
// rules for closures, despite having nothing to do with runServe's own
// control flow — mirrors logReconstructionReport's own established
// "factored out to keep runServe's branching count where it belongs"
// convention above, extended here to the branch that convention alone could
// not itself absorb.
func runFoundationReconstruction(ctx context.Context, rt *foundationRuntime, logger *slog.Logger) error {
	report, err := rt.Reconstruct(ctx)
	if err != nil {
		return fmt.Errorf("situation foundation reconstruction: %w", err)
	}
	logReconstructionReport(logger, report)
	return nil
}

// Start launches the input worker, then the dispatch worker, each on its
// own background schedule. Call only after Reconstruct has succeeded.
func (r *foundationRuntime) Start(ctx context.Context) {
	r.inputs.Start(ctx)
	r.dispatch.Start(ctx)
}

// Stop stops the dispatch worker, then the input worker, each waiting for
// its current round to finish before the next Stop call proceeds. Call
// after Receivers have stopped accepting new inbound work, and before the
// Correlator stops — so no newly accepted work appears after the queue
// workers themselves stop.
func (r *foundationRuntime) Stop(ctx context.Context) error {
	var errs []error
	if err := r.dispatch.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("dispatch worker stop: %w", err))
	}
	if err := r.inputs.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("input worker stop: %w", err))
	}
	return errors.Join(errs...)
}

// Drain runs the input worker's, then the dispatch worker's, due work to
// quiescence (repeat until a round handles zero items, or ctx is done) —
// the same order Start already uses — and reports how many items the two
// handled in total, so foundationStopSequence's drain loop can tell a
// productive round from an idle one. It runs in every round of that loop,
// both before the controller/Triage drain (delivery and Situation-input
// work already queued) and after it (the fresh situation_input_outbox rows
// a controller commit or Triage completion just produced, while this
// runtime's own workers are STILL running); anything still queued when ctx
// expires simply waits, durably, for the next startup's reconstruction
// pass. Bounded by ctx; a ctx deadline mid-drain is not itself an error
// worth surfacing to the caller — only a genuine store error is.
func (r *foundationRuntime) Drain(ctx context.Context) (int, error) {
	handled := 0
	n, err := r.inputs.Drain(ctx)
	handled += n
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return handled, fmt.Errorf("input worker drain: %w", err)
	}
	n, err = r.dispatch.Drain(ctx)
	handled += n
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return handled, fmt.Errorf("dispatch worker drain: %w", err)
	}
	return handled, nil
}

// WakeDispatch nudges the dispatch worker to run another round immediately
// instead of waiting for its next interval tick. Wired as the wake
// callback ingress.NewAlertReceiver/NewZabbixReceiver call once a durable
// delivery commits — a latency optimization only: the dispatch worker
// polls its durable queue regardless of any wake, so a dropped or
// never-arriving wake never loses work, only adds up to one interval's
// worth of latency.
func (r *foundationRuntime) WakeDispatch() {
	r.dispatch.Wake()
}

// ----------------------------------------------------------------------
// Startup/shutdown ordering
//
// foundationSequence and foundationStopSequence exist so the exact
// process-wide startup and shutdown order this plan requires — spanning
// reconstruction, the Correlator, both foundation workers, and Receivers,
// none of which foundationRuntime alone owns — is expressed once, as pure
// composition, and is directly unit-testable with plain closures instead
// of only being provable by reading runServe's control flow.
// ----------------------------------------------------------------------

// foundationSequence composes reconstruction, the Task 9 controller
// recovery/backfill pass, Correlator start, worker start, the Task 9
// controller/Triage worker start, and Receiver start in the exact order
// this plan's startup invariant requires: reconstruct -> Triage migration
// backfill + interrupted Assessment-call/Triage-attempt recovery +
// startup-horizon enforcement -> start the Correlator -> start the
// foundation workers (input, then dispatch — foundationRuntime.Start's own
// order) -> start the Situation controller and Acute Triage workers ->
// start Receivers. run stops at the first failure, so a reconstruction
// error, a controller recovery/backfill error, or a Correlator start
// failure prevents Receivers, and everything after it, from ever starting.
// startWorkers is always the real process's foundationRuntime.Start: main
// wires it as exactly rt.Start, never as separate per-worker closures, so
// the order guarantee foundationRuntime.Start/Stop's own tests prove is the
// order the real process actually executes.
//
// backfillAndRecoverControllerWork and startControllerWorkers are Task 9
// additions; both may be left nil (a foundationSequence with no Plan 2
// controller runtime composed in at all — the existing Plan-1-only tests in
// this file's own tracedFoundationSequence helper exercise this), in which
// case run behaves exactly as it did before Task 9. The real production
// wiring (runServe) always sets both.
type foundationSequence struct {
	reconstruct                      func(ctx context.Context) error
	backfillAndRecoverControllerWork func(ctx context.Context) error
	startCorrelator                  func(ctx context.Context) error
	startWorkers                     func(ctx context.Context)
	startControllerWorkers           func(ctx context.Context)
	startReceivers                   func() error
}

func (f foundationSequence) run(ctx context.Context) error {
	if err := f.reconstruct(ctx); err != nil {
		return err
	}
	if f.backfillAndRecoverControllerWork != nil {
		if err := f.backfillAndRecoverControllerWork(ctx); err != nil {
			return err
		}
	}
	if err := f.startCorrelator(ctx); err != nil {
		return err
	}
	f.startWorkers(ctx)
	if f.startControllerWorkers != nil {
		f.startControllerWorkers(ctx)
	}
	return f.startReceivers()
}

// foundationStopSequence composes the shutdown mirror of
// foundationSequence, in the exact order plan.md Task 9 requires: stop
// Receivers; stop/flush the Correlator's fixed-window production; drain the
// foundation delivery/Situation-input work; drain due controller/Triage
// work AND its resulting inputs to quiescence; then stop the workers
// (controller/Triage first, then the foundation's dispatch/input pair).
//
// Receivers stopping first means no new inbound work can be durably
// accepted. The Correlator stopping SECOND — before any drain — is what
// makes the drain below reach a real quiescent state: its fixed-window
// ticker is the one remaining producer of fresh durable work (an expiring
// window commits a ready Incident, an awaiting_decision Triage row, and a
// Situation input together), so leaving it running until the end let a
// window expire after the controller drain had already finished and
// strand that work for the next startup's recovery. Stopping it here
// leaves any still-collecting window exactly where startup's own recovery
// re-arms it; no ready transition is lost, it is merely deferred. The
// Correlator's ApplyDelivery path (the dispatch worker's DeliveryApplier)
// is a synchronous call that needs no running Correlator loop, so the
// foundation drain that follows is unaffected.
//
// Draining is a loop, not a fixed pair of passes, because the two halves
// feed each other: an applied Situation input makes a Situation due, a
// controller commit or Triage completion appends fresh Situation inputs.
// Each round drains the foundation (input worker, then dispatch worker)
// and then the controller/Triage workers; the loop ends on the first
// round that handles zero items in both, on a drain error, on ctx expiry,
// or at maxShutdownDrainRounds (a defensive bound against a pathological
// ping-pong — whatever remains is durable and recoverable at next
// startup, spec.md's own "leave remaining durable work recoverable").
// Workers stop only after that, so nothing durably queued goes unclaimed
// mid-drain. run collects every stop error with errors.Join rather than
// stopping early, since every later stage must still get a chance to shut
// down even if an earlier one failed. stopWorkers is always the real
// process's foundationRuntime.Stop: main wires it as exactly rt.Stop, never
// as separate per-worker closures, so
// TestFoundationRuntimeStopsDispatchBeforeInputs proves the order the real
// process actually executes.
//
// drainControllerWork, drainFoundationWork, and stopControllerWorkers are
// Task 9 additions; all three may be left nil (no Plan 2 controller runtime
// composed in at all), in which case no drain loop runs and the sequence
// degrades to Receivers -> Correlator -> workers. The real production
// wiring (runServe) always sets all three.
type foundationStopSequence struct {
	stopReceivers         func() error
	stopCorrelator        func()
	drainFoundationWork   func(ctx context.Context) (int, error)
	drainControllerWork   func(ctx context.Context) (int, error)
	stopControllerWorkers func(ctx context.Context) error
	stopWorkers           func(ctx context.Context) error
}

// maxShutdownDrainRounds bounds foundationStopSequence's drain loop.
const maxShutdownDrainRounds = 8

func (f foundationStopSequence) run(ctx context.Context) error {
	var errs []error
	if err := f.stopReceivers(); err != nil {
		errs = append(errs, err)
	}
	f.stopCorrelator()
	if err := f.drainToQuiescence(ctx); err != nil {
		errs = append(errs, err)
	}
	if f.stopControllerWorkers != nil {
		if err := f.stopControllerWorkers(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := f.stopWorkers(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// drainToQuiescence runs the foundation-then-controller drain rounds
// described on foundationStopSequence until a round handles nothing.
func (f foundationStopSequence) drainToQuiescence(ctx context.Context) error {
	if f.drainFoundationWork == nil && f.drainControllerWork == nil {
		return nil
	}
	for round := 0; round < maxShutdownDrainRounds; round++ {
		if ctx.Err() != nil {
			return nil
		}
		handled := 0
		if f.drainFoundationWork != nil {
			n, err := f.drainFoundationWork(ctx)
			if err != nil {
				return err
			}
			handled += n
		}
		if f.drainControllerWork != nil {
			n, err := f.drainControllerWork(ctx)
			if err != nil {
				return err
			}
			handled += n
		}
		if handled == 0 {
			return nil
		}
	}
	return nil
}
