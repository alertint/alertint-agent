// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// foundationSequence: startup ordering
// ----------------------------------------------------------------------

// tracer is a mutex-protected string slice every fake in this file appends
// to, so tests can assert an exact global call order across independent
// fakes without any other synchronization.
type tracer struct {
	mu    sync.Mutex
	trace []string
}

func (t *tracer) add(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.trace = append(t.trace, s)
}

func (t *tracer) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.trace))
	copy(out, t.trace)
	return out
}

func assertTrace(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("trace = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trace = %v, want %v", got, want)
		}
	}
}

// tracedFoundationSequence builds a foundationSequence whose every phase
// succeeds and appends its own name to tr, in call order — including Task
// 9's own two additional phases (backfillAndRecoverControllerWork,
// startControllerWorkers), so this file's own order-proving tests exercise
// the full six-phase sequence the plan's startup order actually specifies,
// not just the four Plan 1 phases.
func tracedFoundationSequence(tr *tracer) foundationSequence {
	return foundationSequence{
		reconstruct: func(context.Context) error {
			tr.add("recover_leases")
			tr.add("drain_deliveries")
			tr.add("drain_inputs")
			tr.add("reconstruct_incidents")
			return nil
		},
		backfillAndRecoverControllerWork: func(context.Context) error {
			tr.add("triage_migration_backfill")
			tr.add("recover_interrupted_assessment_calls")
			tr.add("recover_interrupted_triage_attempts")
			tr.add("enforce_triage_startup_horizon")
			return nil
		},
		startCorrelator: func(context.Context) error {
			tr.add("start_correlator")
			return nil
		},
		startWorkers: func(context.Context) {
			tr.add("start_input_worker")
			tr.add("start_dispatch_worker")
		},
		startControllerWorkers: func(context.Context) {
			tr.add("start_controller_worker")
			tr.add("start_triage_worker")
		},
		startReceivers: func() error {
			tr.add("start_receivers")
			return nil
		},
	}
}

// TestFoundationSequenceOrdersEveryPhase pins the exact startup order this
// plan requires: recover expired leases, drain delivery dispatches, drain
// Situation inputs, represent unowned operational Incidents (all four
// folded into one "reconstruct" phase, exactly as situation.Reconstructor.Run
// sequences them — see internal/situation/reconstruct_test.go for that
// phase's own order proof against a real Reconstructor), then start the
// Correlator, the input worker, the dispatch worker, and finally Receivers.
func TestFoundationSequenceOrdersEveryPhase(t *testing.T) {
	tr := &tracer{}
	seq := tracedFoundationSequence(tr)

	if err := seq.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := []string{
		"recover_leases",
		"drain_deliveries",
		"drain_inputs",
		"reconstruct_incidents",
		"triage_migration_backfill",
		"recover_interrupted_assessment_calls",
		"recover_interrupted_triage_attempts",
		"enforce_triage_startup_horizon",
		"start_correlator",
		"start_input_worker",
		"start_dispatch_worker",
		"start_controller_worker",
		"start_triage_worker",
		"start_receivers",
	}
	assertTrace(t, tr.snapshot(), want)
}

// TestFoundationSequenceReconstructionErrorPreventsReceiversStarting proves
// a failed reconstruction stops the sequence before the Correlator, the
// workers, or Receivers ever start — a restart must never begin accepting
// new inbound work on top of an unconverged database.
func TestFoundationSequenceReconstructionErrorPreventsReceiversStarting(t *testing.T) {
	tr := &tracer{}
	seq := tracedFoundationSequence(tr)
	wantErr := errors.New("reconstruction failed")
	seq.reconstruct = func(context.Context) error {
		tr.add("recover_leases")
		return wantErr
	}

	err := seq.run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("run err = %v, want %v", err, wantErr)
	}
	assertTrace(t, tr.snapshot(), []string{"recover_leases"})
}

// TestFoundationSequenceCorrelatorStartErrorPreventsReceiversStarting mirrors
// the reconstruction-failure case one phase later: the Correlator failing
// to start must also prevent every worker and Receivers from starting.
func TestFoundationSequenceCorrelatorStartErrorPreventsReceiversStarting(t *testing.T) {
	tr := &tracer{}
	seq := tracedFoundationSequence(tr)
	wantErr := errors.New("correlator start failed")
	seq.startCorrelator = func(context.Context) error {
		tr.add("start_correlator")
		return wantErr
	}

	err := seq.run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("run err = %v, want %v", err, wantErr)
	}
	want := []string{
		"recover_leases", "drain_deliveries", "drain_inputs", "reconstruct_incidents",
		"triage_migration_backfill", "recover_interrupted_assessment_calls",
		"recover_interrupted_triage_attempts", "enforce_triage_startup_horizon",
		"start_correlator",
	}
	assertTrace(t, tr.snapshot(), want)
}

// TestFoundationSequenceControllerRecoveryErrorPreventsReceiversStarting
// proves Task 9's own recovery/backfill phase (Triage migration backfill,
// interrupted Assessment-call/Triage-attempt recovery, startup-horizon
// enforcement) is just as gating as reconstruction itself: an error there
// must prevent the Correlator, every worker, and Receivers from ever
// starting — the whole reason it runs between reconstruction and
// Correlator start, never concurrently with anything that could claim
// controller/Triage work.
func TestFoundationSequenceControllerRecoveryErrorPreventsReceiversStarting(t *testing.T) {
	tr := &tracer{}
	seq := tracedFoundationSequence(tr)
	wantErr := errors.New("controller recovery failed")
	seq.backfillAndRecoverControllerWork = func(context.Context) error {
		tr.add("triage_migration_backfill")
		return wantErr
	}

	err := seq.run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("run err = %v, want %v", err, wantErr)
	}
	want := []string{"recover_leases", "drain_deliveries", "drain_inputs", "reconstruct_incidents", "triage_migration_backfill"}
	assertTrace(t, tr.snapshot(), want)
}

// ----------------------------------------------------------------------
// foundationStopSequence: shutdown ordering
// ----------------------------------------------------------------------

// TestFoundationStopSequenceOrdersAllSixPhases pins the full Task 9 shutdown
// order: Receivers; drain controller/Triage work; drain foundation
// dispatch/input work; stop the controller/Triage workers; stop the
// foundation dispatch/input workers; stop the Correlator.
func TestFoundationStopSequenceOrdersAllSixPhases(t *testing.T) {
	tr := &tracer{}
	seq := foundationStopSequence{
		stopReceivers: func() error {
			tr.add("stop_receivers")
			return nil
		},
		drainControllerWork: func(context.Context) error {
			tr.add("drain_controller_work")
			return nil
		},
		drainFoundationWork: func(context.Context) error {
			tr.add("drain_foundation_work")
			return nil
		},
		stopControllerWorkers: func(context.Context) error {
			tr.add("stop_triage_worker")
			tr.add("stop_controller_worker")
			return nil
		},
		stopWorkers: func(context.Context) error {
			tr.add("stop_dispatch_worker")
			tr.add("stop_input_worker")
			return nil
		},
		stopCorrelator: func() {
			tr.add("stop_correlator")
		},
	}

	if err := seq.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{
		"stop_receivers", "drain_controller_work", "drain_foundation_work",
		"stop_triage_worker", "stop_controller_worker",
		"stop_dispatch_worker", "stop_input_worker", "stop_correlator",
	}
	assertTrace(t, tr.snapshot(), want)
}

// TestFoundationStopSequenceOrdersEveryPhase pins the exact shutdown order
// this plan requires: Receivers, then the dispatch worker, then the input
// worker, then the Correlator — so no newly accepted work appears after
// the queue workers themselves stop.
func TestFoundationStopSequenceOrdersEveryPhase(t *testing.T) {
	tr := &tracer{}
	seq := foundationStopSequence{
		stopReceivers: func() error {
			tr.add("stop_receivers")
			return nil
		},
		stopWorkers: func(context.Context) error {
			tr.add("stop_dispatch_worker")
			tr.add("stop_input_worker")
			return nil
		},
		stopCorrelator: func() {
			tr.add("stop_correlator")
		},
	}

	if err := seq.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{"stop_receivers", "stop_dispatch_worker", "stop_input_worker", "stop_correlator"}
	assertTrace(t, tr.snapshot(), want)
}

// TestFoundationStopSequenceRunsEveryPhaseDespiteEarlierFailures proves an
// earlier stop failure never skips a later one — every subsystem gets a
// chance to shut down cleanly regardless of what came before it — and that
// every failure is still surfaced, joined, to the caller.
func TestFoundationStopSequenceRunsEveryPhaseDespiteEarlierFailures(t *testing.T) {
	tr := &tracer{}
	receiversErr := errors.New("receivers shutdown failed")
	dispatchErr := errors.New("dispatch stop failed")
	seq := foundationStopSequence{
		stopReceivers: func() error {
			tr.add("stop_receivers")
			return receiversErr
		},
		stopWorkers: func(context.Context) error {
			tr.add("stop_dispatch_worker")
			tr.add("stop_input_worker")
			return dispatchErr
		},
		stopCorrelator: func() {
			tr.add("stop_correlator")
		},
	}

	err := seq.run(context.Background())
	if !errors.Is(err, receiversErr) || !errors.Is(err, dispatchErr) {
		t.Fatalf("run err = %v, want it to join both receiversErr and dispatchErr", err)
	}
	want := []string{"stop_receivers", "stop_dispatch_worker", "stop_input_worker", "stop_correlator"}
	assertTrace(t, tr.snapshot(), want)
}

// ----------------------------------------------------------------------
// foundationRuntime: construction and lease-identity derivation
// ----------------------------------------------------------------------

func newTestFoundationStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "foundation.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestFoundationRuntimeDrainOnEmptyStoreIsANoOp proves foundationRuntime.
// Drain (Task 9) runs cleanly against a real, empty store — nothing due, so
// both workers' Drain calls return immediately with zero handled.
func TestFoundationRuntimeDrainOnEmptyStoreIsANoOp(t *testing.T) {
	st := newTestFoundationStore(t)
	cor := correlator.New(correlator.Config{}, st, nil, nil)
	rt := newFoundationRuntime(st, cor, "test-owner", slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}

func TestNewFoundationRuntimePanicsOnEmptyOwner(t *testing.T) {
	st := newTestFoundationStore(t)
	cor := correlator.New(correlator.Config{}, st, nil, nil)
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for an empty owner")
		}
	}()
	newFoundationRuntime(st, cor, "  ", slog.Default())
}

// ----------------------------------------------------------------------
// foundationRuntime.WakeDispatch: a Receiver POST can wake dispatch after
// workers start
// ----------------------------------------------------------------------

// fakeDispatchStore is a scriptable correlator.DispatchStore. Every claim
// call signals on claimed (non-blocking, coalesced) so tests can observe a
// claim round happened without polling.
type fakeDispatchStore struct {
	claimed chan struct{}
}

func newFakeDispatchStore() *fakeDispatchStore {
	return &fakeDispatchStore{claimed: make(chan struct{}, 64)}
}

func (f *fakeDispatchStore) ClaimAlertDispatches(context.Context, string, time.Time, time.Duration, int) ([]store.AlertDispatch, error) {
	f.claimed <- struct{}{}
	return nil, nil
}

func (f *fakeDispatchStore) RetryAlertDispatch(context.Context, store.AlertDispatch, string, time.Time, bool) error {
	return nil
}

type nopDeliveryApplier struct{}

func (nopDeliveryApplier) ApplyDelivery(context.Context, store.AlertDispatch) error { return nil }

// TestFoundationRuntimeWakeDispatchTriggersAnImmediateRound proves
// WakeDispatch reaches the dispatch worker: after Start's own immediate
// round settles, a long interval means no further round would happen on
// its own — but WakeDispatch still produces one promptly, exactly the path
// a Receiver's POST-triggered wake (ingress.NewAlertReceiver/
// NewZabbixReceiver's wake callback) exercises once workers are running.
func TestFoundationRuntimeWakeDispatchTriggersAnImmediateRound(t *testing.T) {
	dispatchStore := newFakeDispatchStore()
	dispatch := correlator.NewDispatchWorker(dispatchStore, nopDeliveryApplier{}, correlator.WorkerConfig{
		Owner:    "test:dispatch",
		Interval: time.Hour, // long enough that only Start's immediate round and an explicit Wake could plausibly land within this test's timeout
	}, nil)
	rt := &foundationRuntime{dispatch: dispatch}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// This test is scoped to the dispatch worker and WakeDispatch, so start
	// only the dispatch worker directly — rt.Start would also start
	// r.inputs, which this fixture deliberately leaves nil.
	dispatch.Start(ctx)

	waitForClaim(t, dispatchStore.claimed, "Start's immediate round")

	rt.WakeDispatch()
	waitForClaim(t, dispatchStore.claimed, "WakeDispatch's round")
}

func waitForClaim(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// ----------------------------------------------------------------------
// foundationRuntime.Stop: dispatch stops before inputs
// ----------------------------------------------------------------------

// blockingDispatchStore's ClaimAlertDispatches signals it was entered, then
// blocks until told to proceed — used to hold DispatchWorker.Stop in
// flight so the test can observe whether InputWorker has been stopped yet.
type blockingDispatchStore struct {
	entered chan struct{}
	proceed chan struct{}
}

func (f *blockingDispatchStore) ClaimAlertDispatches(context.Context, string, time.Time, time.Duration, int) ([]store.AlertDispatch, error) {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.proceed
	return nil, nil
}

func (f *blockingDispatchStore) RetryAlertDispatch(context.Context, store.AlertDispatch, string, time.Time, bool) error {
	return nil
}

// countingInputStore counts every claim call, so a test can observe
// whether InputWorker's background loop is still ticking.
type countingInputStore struct {
	mu     sync.Mutex
	claims int
}

func (f *countingInputStore) ClaimSituationInputs(context.Context, string, time.Time, time.Duration, int) ([]store.SituationClaim, error) {
	f.mu.Lock()
	f.claims++
	f.mu.Unlock()
	return nil, nil
}

func (f *countingInputStore) ApplySituationInput(context.Context, store.SituationClaim) error {
	return nil
}

func (f *countingInputStore) RetrySituationInput(context.Context, store.SituationClaim, string, time.Time, bool) error {
	return nil
}

func (f *countingInputStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claims
}

// TestFoundationRuntimeStopsDispatchBeforeInputs proves foundationRuntime.Stop
// really does block on the dispatch worker before it ever touches the input
// worker: while a slow dispatch stop is in flight, the input worker's
// background loop is demonstrably still ticking; only once dispatch's stop
// is allowed to finish does the input worker's claim count stop growing.
func TestFoundationRuntimeStopsDispatchBeforeInputs(t *testing.T) {
	dispatchStore := &blockingDispatchStore{entered: make(chan struct{}, 1), proceed: make(chan struct{})}
	dispatch := correlator.NewDispatchWorker(dispatchStore, nopDeliveryApplier{}, correlator.WorkerConfig{
		Owner:    "test:dispatch",
		Interval: time.Hour,
	}, nil)

	inputStore := &countingInputStore{}
	inputs := situation.NewInputWorker(inputStore, situation.WorkerConfig{
		Owner:    "test:input",
		Interval: 5 * time.Millisecond,
	}, nil)

	rt := &foundationRuntime{dispatch: dispatch, inputs: inputs}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.Start(ctx)

	// Wait for dispatch's immediate round to enter its (now blocking) claim
	// call, and for inputs to have ticked at least once.
	select {
	case <-dispatchStore.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch worker never entered its claim call")
	}
	waitForCount(t, inputStore, 1)

	stopDone := make(chan error, 1)
	go func() { stopDone <- rt.Stop(context.Background()) }()

	// While dispatch.Stop is still blocked mid-round, the input worker must
	// not have been told to stop yet — prove it by observing its claim
	// count keep growing during this window.
	before := inputStore.count()
	time.Sleep(50 * time.Millisecond)
	after := inputStore.count()
	if after <= before {
		t.Fatalf("input worker claim count did not grow while dispatch.Stop was in flight (before=%d after=%d) — Stop must not have reached inputs.Stop yet at this point", before, after)
	}
	select {
	case err := <-stopDone:
		t.Fatalf("Stop returned (%v) before dispatch's in-flight claim was released", err)
	default:
	}

	// Release dispatch's in-flight claim so Stop can finish.
	close(dispatchStore.proceed)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop never returned after dispatch's claim was released")
	}

	// Now that Stop has returned, the input worker must have actually
	// stopped: its claim count no longer grows.
	stable := inputStore.count()
	time.Sleep(30 * time.Millisecond)
	if inputStore.count() != stable {
		t.Fatalf("input worker kept claiming after Stop returned (%d -> %d)", stable, inputStore.count())
	}
}

func waitForCount(t *testing.T, c *countingInputStore, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("input worker claim count never reached %d (got %d)", want, c.count())
}
