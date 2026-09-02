// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 8: ControllerWorker — polls due Situations, claims a bounded batch,
// and runs Controller.Reconcile on each with a fenced lease heartbeat. This
// mirrors input_worker.go/triage_worker.go's own claim/heartbeat/wake/drain
// shape closely, with two differences those workers do not need: a
// configurable internal worker-goroutine pool (situations.workers) so a
// batch's Reconcile calls run concurrently, and a global L2 dispatch
// semaphore (situations.llm_concurrency) bounding concurrent provider calls
// across every Situation this worker is reconciling at once.
// ----------------------------------------------------------------------

// ControllerWorkStore is the narrow claim/lease surface ControllerWorker
// depends on — distinct from ControllerStore (Reconcile's own dependency,
// held inside the *Controller this worker drives): *store.Store satisfies
// both via different method-set slices, the same "narrow interface per
// consumer" shape TriageAttemptStore/TriageScheduleLister already use.
type ControllerWorkStore interface {
	ClaimControllerWork(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]Claim, error)
	ExtendControllerLease(ctx context.Context, claim Claim, now time.Time, lease time.Duration) error
	ReleaseControllerWork(ctx context.Context, claim Claim, now time.Time) error
}

// DependencyRecoveryWaker is the narrow "wake dependency-parked Situations
// for a newer recovered outage generation" primitive ControllerWorker calls
// before each claim poll (spec.md's retry/parking section): "Before each
// controller claim poll, call an idempotent Store primitive that reads
// installation LLM health and wakes dependency-parked Situations..."
// internal/llmhealth (installation LLM health) cannot be imported from
// internal/situation — llmhealth imports internal/store, which imports
// internal/situation, so the reverse import here would cycle (the same
// constraint assessment.go's own top-of-file note documents for
// ClassifyL2Outcome). This interface is the seam a caller OUTSIDE this
// package (Task 9's runtime wiring) implements, combining
// internal/llmhealth.Tracker.Snapshot().OutageGeneration (once healthy)
// with store.WakeDependencyRecoveredSituations. Nil disables it (e.g.
// tests, or a build that has not wired LLM health at all) — RunOnce simply
// skips the pre-poll wake step.
type DependencyRecoveryWaker interface {
	WakeDependencyRecoveredSituations(ctx context.Context, now time.Time) (int, error)
}

// ControllerWorkerConfig controls ControllerWorker's claim lease, heartbeat,
// schedule, batch size, internal concurrency, and L2 dispatch semaphore.
// Zero-valued fields fall back to the documented defaults, mirroring every
// other worker config in this package.
type ControllerWorkerConfig struct {
	// Owner identifies this worker instance to the store's lease fencing.
	// Required — there is no default.
	Owner string

	// Lease is how long a claimed Situation is held before another worker
	// (or this worker's own next poll) may reclaim it as expired. Default
	// 300s (config.SituationsConfig.LeaseSeconds's own default).
	Lease time.Duration

	// Heartbeat is how often a claimed Situation's lease is renewed while
	// Reconcile is still running. Default 30s
	// (config.SituationsConfig.HeartbeatSeconds's own default) — well
	// under Lease so a heartbeat miss or two never loses the lease
	// mid-reconciliation.
	Heartbeat time.Duration

	// Interval is how often Start's background loop wakes on its own,
	// absent an explicit Wake(). Default 1s
	// (config.SituationsConfig.ReconcilePollSeconds's own default).
	Interval time.Duration

	// Batch bounds how many due Situations one RunOnce call claims.
	// Default 16.
	Batch int

	// Workers bounds how many claimed Situations RunOnce reconciles
	// concurrently. Default 2 (config.SituationsConfig.Workers's own
	// default).
	Workers int

	// L2Concurrency bounds how many CompleteOnce calls may run at once
	// across every concurrently-reconciling Situation this worker drives —
	// the "global L2 semaphore." Default 2
	// (config.SituationsConfig.LLMConcurrency's own default).
	L2Concurrency int

	// Now is the clock RunOnce/heartbeat read. Default: the UTC wall clock.
	Now func() time.Time
}

const (
	defaultControllerWorkerLease         = 300 * time.Second
	defaultControllerWorkerHeartbeat     = 30 * time.Second
	defaultControllerWorkerInterval      = time.Second
	defaultControllerWorkerBatch         = 16
	defaultControllerWorkerWorkers       = 2
	defaultControllerWorkerL2Concurrency = 2
)

func (c ControllerWorkerConfig) withDefaults() ControllerWorkerConfig {
	if c.Lease <= 0 {
		c.Lease = defaultControllerWorkerLease
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = defaultControllerWorkerHeartbeat
	}
	if c.Interval <= 0 {
		c.Interval = defaultControllerWorkerInterval
	}
	if c.Batch <= 0 {
		c.Batch = defaultControllerWorkerBatch
	}
	if c.Workers <= 0 {
		c.Workers = defaultControllerWorkerWorkers
	}
	if c.L2Concurrency <= 0 {
		c.L2Concurrency = defaultControllerWorkerL2Concurrency
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return c
}

// semaphoreAssessmentClient wraps an AssessmentClient with a bounded
// concurrent-call semaphore — ControllerWorker's own "global L2 semaphore":
// at most the configured L2Concurrency CompleteOnce calls run at once
// across every Situation this worker is concurrently reconciling,
// regardless of how many of its Workers goroutines are active. Blocks
// (never drops or errors early) until a slot frees or ctx is done.
type semaphoreAssessmentClient struct {
	inner AssessmentClient
	sem   chan struct{}
}

func newSemaphoreAssessmentClient(inner AssessmentClient, concurrency int) *semaphoreAssessmentClient {
	return &semaphoreAssessmentClient{inner: inner, sem: make(chan struct{}, concurrency)}
}

func (c *semaphoreAssessmentClient) CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return llm.OneShotCompletion{}, ctx.Err()
	}
	defer func() { <-c.sem }()
	return c.inner.CompleteOnce(ctx, systemPrompt, prompt, requiredKeys)
}

// ControllerWorker polls due Situations (ControllerWorkStore.
// ClaimControllerWork), claims a bounded batch, and runs Controller.
// Reconcile on each with a fenced lease heartbeat — up to Workers of them
// concurrently, all sharing one global L2 dispatch semaphore. It is safe
// for exactly one Start/Stop lifecycle; RunOnce and Drain may additionally
// be called directly (tests, or a one-shot CLI drain) without ever calling
// Start.
type ControllerWorker struct {
	store      ControllerWorkStore
	controller *Controller
	cfg        ControllerWorkerConfig
	logger     *slog.Logger
	waker      DependencyRecoveryWaker

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
}

// SetDependencyRecoveryWaker wires the pre-poll dependency-recovery wake
// step (see DependencyRecoveryWaker's own doc comment). Optional: nil (the
// default — no call to NewControllerWorker sets one) leaves it disabled.
// Not safe to call concurrently with Start/RunOnce; call it once, right
// after construction, before starting the worker.
func (w *ControllerWorker) SetDependencyRecoveryWaker(waker DependencyRecoveryWaker) {
	w.waker = waker
}

// NewControllerWorker constructs a ControllerWorker. It builds its own
// *Controller internally (via NewController) so it can wrap client in the
// global L2 semaphore before Reconcile ever sees it — workStore is the
// worker's own claim/lease surface, controllerStore is Reconcile's; a
// concrete *store.Store satisfies both and is typically passed for each.
// Passing nil for auditSink disables audit; nil for logger falls back to
// slog.Default(); nil for clock falls back to the UTC wall clock, used for
// both the worker's own scheduling and the Controller it builds.
func NewControllerWorker(
	workStore ControllerWorkStore, controllerStore ControllerStore, client AssessmentClient,
	controllerCfg ControllerConfig, cfg ControllerWorkerConfig, clock Clock, auditSink AuditSink, logger *slog.Logger,
) *ControllerWorker {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	wrapped := newSemaphoreAssessmentClient(client, cfg.L2Concurrency)
	controller := NewController(controllerStore, wrapped, controllerCfg, clock, auditSink, logger)
	return &ControllerWorker{
		store:      workStore,
		controller: controller,
		cfg:        cfg,
		logger:     logger,
		wakeCh:     make(chan struct{}, 1),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// detachedControllerWorkerContext returns a short-lived context independent
// of the (possibly already-canceled) reconcile context, for a heartbeat
// extend or a post-failure release — the same pattern triage_worker.go's
// own detachedWriteContext uses.
func detachedControllerWorkerContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// RunOnce claims at most cfg.Batch due Situations and reconciles them, up
// to cfg.Workers concurrently. It returns how many it claimed and
// attempted (regardless of each one's ultimate outcome — a single
// Situation's failure never aborts the rest of the batch). Before claiming,
// if a DependencyRecoveryWaker is wired, it calls it once — a failure there
// is logged and never blocks the claim poll itself (the wake step is a
// best-effort optimization: a Situation it fails to wake this round simply
// waits for the next).
func (w *ControllerWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.cfg.Now()
	if w.waker != nil {
		if n, err := w.waker.WakeDependencyRecoveredSituations(ctx, now); err != nil {
			w.logger.Warn("situation: controller worker: dependency-recovery wake failed", "err", err)
		} else if n > 0 {
			w.logger.Info("situation: controller worker: woke dependency-parked situations", "count", n)
		}
	}
	claims, err := w.store.ClaimControllerWork(ctx, w.cfg.Owner, now, w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: controller worker: claim controller work: %w", err)
	}
	if len(claims) == 0 {
		return 0, nil
	}

	sem := make(chan struct{}, w.cfg.Workers)
	var wg sync.WaitGroup
	var handled atomic.Int64
	for _, claim := range claims {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return int(handled.Load()), ctx.Err()
		}
		wg.Add(1)
		go func(claim Claim) {
			defer wg.Done()
			defer func() { <-sem }()
			w.processOne(ctx, claim)
			handled.Add(1)
		}(claim)
	}
	wg.Wait()
	return int(handled.Load()), nil
}

// Drain runs RunOnce repeatedly until a round handles zero items (the due
// schedule is caught up) or a round returns an error.
func (w *ControllerWorker) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := w.RunOnce(ctx)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

// Start launches the background loop and returns immediately. It runs one
// Drain pass right away, then blocks until the next of: cfg.Interval
// elapsing, an explicit Wake(), or shutdown (ctx or Stop). A dropped Wake()
// is harmless: due rows poll again on the next tick regardless. Safe to
// call at most once per ControllerWorker; later calls are no-ops.
func (w *ControllerWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() { go w.run(ctx) })
}

func (w *ControllerWorker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if _, err := w.Drain(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: controller worker: drain", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
	}
}

// Wake nudges the background loop to run another round immediately instead
// of waiting for the next interval tick. Never blocks: a Wake() arriving
// while one is already pending is silently coalesced into it.
func (w *ControllerWorker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit after its current round and
// waits for it to finish, or returns ctx's error if ctx is done first.
func (w *ControllerWorker) Stop(ctx context.Context) error {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	select {
	case <-w.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// processOne runs claim's Reconcile cycle with a fenced lease heartbeat. On
// any Reconcile failure it releases the lease early — CommitController's
// own successful commit already clears it; a failure before ever reaching
// CommitController (or CommitController's own fenced rejection) otherwise
// leaves the lease held until it expires on its own, needlessly delaying
// the next attempt.
func (w *ControllerWorker) processOne(ctx context.Context, claim Claim) {
	reconcileCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var leaseLost atomic.Bool
	hbDone := make(chan struct{})
	go w.heartbeatLoop(reconcileCtx, cancel, claim, &leaseLost, hbDone)

	err := w.controller.Reconcile(reconcileCtx, claim)

	cancel()
	<-hbDone

	if leaseLost.Load() {
		w.logger.Warn("situation: controller worker: lease lost mid-reconcile; abandoning",
			"situation_id", claim.Situation.ID)
		return
	}
	if err != nil {
		w.logger.Warn("situation: controller worker: reconcile failed", "situation_id", claim.Situation.ID, "err", err)
		releaseCtx, releaseCancel := detachedControllerWorkerContext()
		defer releaseCancel()
		if rerr := w.store.ReleaseControllerWork(releaseCtx, claim, w.cfg.Now()); rerr != nil && !errors.Is(rerr, model.ErrSituationLeaseLost) {
			w.logger.Error("situation: controller worker: release after failed reconcile failed",
				"situation_id", claim.Situation.ID, "err", rerr)
		}
	}
}

// heartbeatLoop renews claim's lease every cfg.Heartbeat until ctx is done.
// If a renewal ever fails, it marks leaseLost and cancels cancel so the
// in-flight Reconcile call is abandoned rather than allowed to keep
// running (and later commit) under a lease it no longer holds.
func (w *ControllerWorker) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, claim Claim, leaseLost *atomic.Bool, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(w.cfg.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			extendCtx, extendCancel := detachedControllerWorkerContext()
			err := w.store.ExtendControllerLease(extendCtx, claim, w.cfg.Now(), w.cfg.Lease)
			extendCancel()
			if err != nil {
				w.logger.Warn("situation: controller worker: heartbeat lease extend failed; canceling reconcile",
					"situation_id", claim.Situation.ID, "err", err)
				leaseLost.Store(true)
				cancel()
				return
			}
		}
	}
}
