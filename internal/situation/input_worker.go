// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Durable situation input drain (Task 7)
//
// InputWorker claims durably queued Situation inputs (Store.ClaimSituationInputs)
// and applies each one through Store.ApplySituationInput, one claim at a
// time. Nothing runs this worker yet — a later task wires it into the
// process runtime.
//
// This mirrors internal/correlator.DispatchWorker deliberately closely: same
// claim/apply/retry/backoff/wake/drain shape, a separately-defined
// WorkerConfig (not shared across the package boundary — see this plan's
// pre-flight conflict scan), applied here to situation_input_outbox instead
// of alert_delivery_dispatches.
// ----------------------------------------------------------------------

// InputStore is the narrow slice of *store.Store this worker depends on. It
// exists so InputWorker can be tested against a fake instead of a real
// database. Unlike DispatchWorker (which separates its store from its
// *Correlator applier), claim/apply/retry for a Situation input all live on
// *store.Store itself, so one interface covers the whole dependency.
type InputStore interface {
	ClaimSituationInputs(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]store.SituationClaim, error)
	ApplySituationInput(ctx context.Context, claim store.SituationClaim) error
	RetrySituationInput(ctx context.Context, claim store.SituationClaim, class string, retryAt time.Time, terminal bool) error
}

// WorkerConfig controls InputWorker's claim lease, schedule, batch size,
// retry ceiling, and clock. Zero-valued fields fall back to the defaults
// documented on each constant below; NewInputWorker applies them. This is a
// separate type from correlator.WorkerConfig — same shape, deliberately
// duplicated per package, not shared across the package boundary.
type WorkerConfig struct {
	// Owner identifies this worker instance to Store.ClaimSituationInputs /
	// RetrySituationInput's lease fencing. Required — there is no default.
	Owner string

	// Lease is how long a claimed input is held before another worker may
	// reclaim it as expired. Default 60s.
	Lease time.Duration

	// Interval is how often Start's background loop wakes on its own, absent
	// an explicit Wake(). Default 2s.
	Interval time.Duration

	// Batch bounds how many inputs one RunOnce call claims. Default 16.
	Batch int

	// MaxAttempts is the attempt count (inclusive) at which a still-failing
	// claim is marked terminally failed instead of scheduled for another
	// retry. Default 8.
	MaxAttempts int

	// Now is the clock RunOnce reads for both the claim's "now" and for
	// computing a retry's due time. Default: the UTC wall clock.
	Now func() time.Time
}

const (
	defaultWorkerLease       = 60 * time.Second
	defaultWorkerInterval    = 2 * time.Second
	defaultWorkerBatch       = 16
	defaultWorkerMaxAttempts = 8
)

func (c WorkerConfig) withDefaults() WorkerConfig {
	if c.Lease <= 0 {
		c.Lease = defaultWorkerLease
	}
	if c.Interval <= 0 {
		c.Interval = defaultWorkerInterval
	}
	if c.Batch <= 0 {
		c.Batch = defaultWorkerBatch
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultWorkerMaxAttempts
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return c
}

// InputWorker drains the durable situation_input_outbox: claim a bounded
// batch, apply each claim sequentially, and classify any failure into a
// scheduled retry or a terminal dead letter. It is safe for exactly one
// Start/Stop lifecycle; RunOnce and Drain may additionally be called
// directly (e.g. by tests, or a one-shot CLI drain) without ever calling
// Start.
type InputWorker struct {
	store  InputStore
	cfg    WorkerConfig
	logger *slog.Logger

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
}

// NewInputWorker creates an InputWorker. Passing nil for logger falls back
// to slog.Default(). Call Start to run it on a schedule, or drive it
// directly with RunOnce/Drain.
func NewInputWorker(store InputStore, cfg WorkerConfig, logger *slog.Logger) *InputWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &InputWorker{
		store:  store,
		cfg:    cfg.withDefaults(),
		logger: logger,
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// inputRetryBase and inputRetryCap define the exponential backoff schedule
// for a claim that failed with a transient (non-terminal) error: 1s, 2s,
// 4s, ... doubling with each attempt, capped at five minutes so a
// long-stuck dependency does not push a retry arbitrarily far out.
const (
	inputRetryBase = time.Second
	inputRetryCap  = 5 * time.Minute
)

// inputRetryBackoff returns the delay before a failed claim's next attempt,
// given the attempt number that just failed (1-based, as AttemptCount
// already reads after Store.ClaimSituationInputs increments it). It never
// returns zero and never exceeds inputRetryCap, guarding against the shift
// overflowing for a very large attempt count.
func inputRetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 32 { // 1s<<31 already exceeds the cap many times over
		return inputRetryCap
	}
	d := inputRetryBase * time.Duration(uint64(1)<<uint(attempt-1))
	if d <= 0 || d > inputRetryCap {
		return inputRetryCap
	}
	return d
}

// inputErrorClass maps an ApplySituationInput failure to the stable
// lowercase identifier RetrySituationInput persists, and whether it is
// terminal. store.ErrNotFound (the referenced Incident, or a delivery it
// claims to own, genuinely does not exist) is a permanent local dead
// letter — no amount of retrying changes that; anything else is treated as
// a transient dependency failure worth retrying, including
// store.ErrSituationVersionConflict (a defensive compare-and-swap this
// store does not expect to actually lose under its single-writer model, but
// which is not itself proof the input can never apply).
func inputErrorClass(err error) (class string, terminal bool) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "invalid_input", true
	default:
		return "transient", false
	}
}

// RunOnce claims at most cfg.Batch due situation inputs and applies them
// sequentially, returning how many it handled (committed, terminally
// failed, or scheduled for retry). A claim whose ApplySituationInput call
// fails with context cancellation or store.ErrSituationLeaseLost is neither
// counted nor written back — RunOnce stops the round immediately and
// returns that error, since continuing to claim or apply more work under a
// cancelled context or a lease that already moved on cannot succeed. Any
// other per-claim failure is classified, written back via
// Store.RetrySituationInput, and RunOnce continues to the next claim
// regardless — a single input's outcome, terminal or not, is never grounds
// to abandon the rest of the batch.
func (w *InputWorker) RunOnce(ctx context.Context) (int, error) {
	claims, err := w.store.ClaimSituationInputs(ctx, w.cfg.Owner, w.cfg.Now(), w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: claim situation inputs: %w", err)
	}

	handled := 0
	for _, claim := range claims {
		stop, err := w.applyOne(ctx, claim)
		if stop {
			return handled, err
		}
		handled++
	}
	return handled, nil
}

// applyOne applies one claimed input and, on failure, classifies and writes
// back its retry/terminal outcome. stop is true only for context
// cancellation or a lost lease — cases where RunOnce must not keep claiming
// or applying further work, and must not attempt to rewrite this claim (the
// lease already moved on, or the caller is shutting down).
func (w *InputWorker) applyOne(ctx context.Context, claim store.SituationClaim) (stop bool, err error) {
	applyErr := w.store.ApplySituationInput(ctx, claim)
	if applyErr == nil {
		return false, nil
	}

	if errors.Is(applyErr, context.Canceled) || errors.Is(applyErr, context.DeadlineExceeded) || errors.Is(applyErr, store.ErrSituationLeaseLost) {
		w.logger.Warn("situation: input worker round stopped",
			"input_id", claim.ID, "attempt", claim.AttemptCount, "err", applyErr)
		return true, applyErr
	}

	class, terminal := inputErrorClass(applyErr)
	if !terminal && claim.AttemptCount >= w.cfg.MaxAttempts {
		terminal = true
	}

	retryAt := w.cfg.Now()
	if !terminal {
		retryAt = retryAt.Add(inputRetryBackoff(claim.AttemptCount))
	}

	if rerr := w.store.RetrySituationInput(ctx, claim, class, retryAt, terminal); rerr != nil {
		// The write-back itself lost the race (e.g. another worker's lease
		// already reclaimed this row): nothing more this call can do about
		// it, so log and move on to the rest of the batch rather than
		// abandoning it.
		w.logger.Error("situation: input retry write-back failed",
			"input_id", claim.ID, "attempt", claim.AttemptCount, "class", class, "err", rerr)
		return false, nil
	}

	w.logger.Warn("situation: input apply failed",
		"input_id", claim.ID, "attempt", claim.AttemptCount, "class", class, "terminal", terminal, "err", applyErr)
	return false, nil
}

// Drain runs RunOnce repeatedly until a round handles zero items (the
// outbox is caught up) or a round returns an error. It returns the total
// handled across every round.
func (w *InputWorker) Drain(ctx context.Context) (int, error) {
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
// elapsing, an explicit Wake(), or shutdown (ctx or Stop). It is safe to
// call at most once per InputWorker; later calls are no-ops.
func (w *InputWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		go w.run(ctx)
	})
}

func (w *InputWorker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if _, err := w.Drain(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: input worker drain", "err", err)
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
// of waiting for the next interval tick. It never blocks: the wake channel
// has room for exactly one pending wake, so a Wake() arriving while one is
// already pending is silently coalesced into it.
func (w *InputWorker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit after its current round and
// waits for it to finish. It returns nil once the loop has drained, or
// ctx's error if ctx is done first — the loop keeps running in that case,
// and a later Stop call (or the original ctx passed to Start) still
// controls its eventual shutdown.
func (w *InputWorker) Stop(ctx context.Context) error {
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
