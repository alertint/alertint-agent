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

// foundationSequence composes reconstruction, Correlator start, worker
// start, and Receiver start in the exact order this plan's startup
// invariant requires: reconstruct -> start the Correlator -> start the
// foundation workers (input, then dispatch — foundationRuntime.Start's own
// order) -> start Receivers. run stops at the first failure, so a
// reconstruction error — or a Correlator start failure — prevents
// Receivers, and everything after it, from ever starting. startWorkers is
// always the real process's foundationRuntime.Start: main wires it as
// exactly rt.Start, never as separate per-worker closures, so the order
// guarantee foundationRuntime.Start/Stop's own tests prove is the order
// the real process actually executes.
type foundationSequence struct {
	reconstruct     func(ctx context.Context) error
	startCorrelator func(ctx context.Context) error
	startWorkers    func(ctx context.Context)
	startReceivers  func() error
}

func (f foundationSequence) run(ctx context.Context) error {
	if err := f.reconstruct(ctx); err != nil {
		return err
	}
	if err := f.startCorrelator(ctx); err != nil {
		return err
	}
	f.startWorkers(ctx)
	return f.startReceivers()
}

// foundationStopSequence composes the shutdown mirror of
// foundationSequence: stop Receivers, then the foundation workers
// (dispatch, then input — foundationRuntime.Stop's own order), then the
// Correlator. Receivers stopping first means no new inbound work can be
// durably accepted; the workers stopping next means nothing already
// durably queued goes unclaimed mid-drain; the Correlator stopping last
// means it keeps serving its own fixed-window expiry and Triage retry
// schedule for exactly as long as anything upstream could still be
// handing it work. run collects every stop error with errors.Join rather
// than stopping early, since every later stage must still get a chance to
// shut down even if an earlier one failed. stopWorkers is always the real
// process's foundationRuntime.Stop: main wires it as exactly rt.Stop,
// never as separate per-worker closures, so
// TestFoundationRuntimeStopsDispatchBeforeInputs proves the order the
// real process actually executes.
type foundationStopSequence struct {
	stopReceivers  func() error
	stopWorkers    func(ctx context.Context) error
	stopCorrelator func()
}

func (f foundationStopSequence) run(ctx context.Context) error {
	var errs []error
	if err := f.stopReceivers(); err != nil {
		errs = append(errs, err)
	}
	if err := f.stopWorkers(ctx); err != nil {
		errs = append(errs, err)
	}
	f.stopCorrelator()
	return errors.Join(errs...)
}
