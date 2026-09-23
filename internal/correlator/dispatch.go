// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

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
// Durable correlation dispatch drain (Task 6)
//
// DispatchWorker claims durably queued alert deliveries (Task 3's
// Store.ClaimAlertDispatches) and applies each one through Task 5's
// Correlator.ApplyDelivery, one claim at a time. Nothing runs this worker
// yet — a later task wires it into the process runtime.
// ----------------------------------------------------------------------

// DispatchStore is the narrow slice of *store.Store this worker depends on.
// It exists so DispatchWorker can be tested against a fake instead of a real
// database, and so this package never couples to *store.Store directly.
type DispatchStore interface {
	ClaimAlertDispatches(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]store.AlertDispatch, error)
	RetryAlertDispatch(ctx context.Context, claim store.AlertDispatch, class string, retryAt time.Time, terminal bool) error
}

// DeliveryApplier is the narrow slice of *Correlator this worker depends on.
// *Correlator satisfies it directly via ApplyDelivery.
type DeliveryApplier interface {
	ApplyDelivery(ctx context.Context, claim store.AlertDispatch) error
}

// WorkerConfig controls DispatchWorker's claim lease, schedule, batch size,
// retry ceiling, and clock. Zero-valued fields fall back to the defaults
// documented on each constant below; NewDispatchWorker applies them.
type WorkerConfig struct {
	// Owner identifies this worker instance to Store.ClaimAlertDispatches /
	// RetryAlertDispatch's lease fencing. Required — there is no default.
	Owner string

	// Lease is how long a claimed dispatch is held before another worker may
	// reclaim it as expired. Default 60s.
	Lease time.Duration

	// Interval is how often Start's background loop wakes on its own, absent
	// an explicit Wake(). Default 2s.
	Interval time.Duration

	// Batch bounds how many dispatches one RunOnce call claims. Default 16.
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

// DispatchWorker drains the durable correlation outbox: claim a bounded
// batch, apply each claim sequentially, and classify any failure into a
// scheduled retry or a terminal dead letter. It is safe for exactly one
// Start/Stop lifecycle; RunOnce and Drain may additionally be called
// directly (e.g. by tests, or a one-shot CLI drain) without ever calling
// Start.
type DispatchWorker struct {
	store   DispatchStore
	applier DeliveryApplier
	cfg     WorkerConfig
	logger  *slog.Logger

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
}

// NewDispatchWorker creates a DispatchWorker. Passing nil for logger falls
// back to slog.Default(). Call Start to run it on a schedule, or drive it
// directly with RunOnce/Drain.
func NewDispatchWorker(st DispatchStore, applier DeliveryApplier, cfg WorkerConfig, logger *slog.Logger) *DispatchWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &DispatchWorker{
		store:   st,
		applier: applier,
		cfg:     cfg.withDefaults(),
		logger:  logger,
		wakeCh:  make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// dispatchRetryBase and dispatchRetryCap define the exponential backoff
// schedule for a claim that failed with a transient (non-terminal) error:
// 1s, 2s, 4s, ... doubling with each attempt, capped at five minutes so a
// long-stuck dependency does not push a retry arbitrarily far out.
const (
	dispatchRetryBase = time.Second
	dispatchRetryCap  = 5 * time.Minute
)

// dispatchRetryBackoff returns the delay before a failed claim's next
// attempt, given the attempt number that just failed (1-based, as
// AttemptCount already reads after Store.ClaimAlertDispatches increments
// it). It never returns zero and never exceeds dispatchRetryCap, guarding
// against the shift overflowing for a very large attempt count.
func dispatchRetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 32 { // 1s<<31 already exceeds the cap many times over
		return dispatchRetryCap
	}
	d := dispatchRetryBase * time.Duration(uint64(1)<<uint(attempt-1)) // #nosec G115 -- attempt is capped <= 32 immediately above, so 1<<(attempt-1) never exceeds 2^31, far below int64's range
	if d <= 0 || d > dispatchRetryCap {
		return dispatchRetryCap
	}
	return d
}

// dispatchErrorClass maps an ApplyDelivery failure to the stable lowercase
// identifier RetryAlertDispatch persists, and whether it is terminal. This
// switch is meant to stay exhaustive over every error ApplyDelivery
// documents: ErrInvalidDelivery and store.ErrNotFound are permanent local
// dead letters (the delivery itself can never satisfy the correlation
// contract, no amount of retrying changes that); anything else is treated
// as a transient dependency failure worth retrying.
func dispatchErrorClass(err error) (class string, terminal bool) {
	switch {
	case errors.Is(err, ErrInvalidDelivery), errors.Is(err, store.ErrNotFound):
		return "invalid_delivery", true
	default:
		return "transient", false
	}
}

// RunOnce claims at most cfg.Batch due dispatches and applies them
// sequentially, returning how many it handled (committed, terminally
// failed, or scheduled for retry). A claim whose ApplyDelivery call fails
// with context cancellation or store.ErrAlertDispatchLeaseLost is neither
// counted nor written back — RunOnce stops the round immediately and
// returns that error, since continuing to claim or apply more work under a
// cancelled context or a lease that already moved on cannot succeed. Any
// other per-claim failure is classified, written back via
// Store.RetryAlertDispatch, and RunOnce continues to the next claim
// regardless — a single delivery's outcome, terminal or not, is never
// grounds to abandon the rest of the batch.
func (w *DispatchWorker) RunOnce(ctx context.Context) (int, error) {
	claims, err := w.store.ClaimAlertDispatches(ctx, w.cfg.Owner, w.cfg.Now(), w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("correlator: claim alert dispatches: %w", err)
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

// applyOne applies one claimed dispatch and, on failure, classifies and
// writes back its retry/terminal outcome. stop is true only for context
// cancellation or a lost lease — cases where RunOnce must not keep claiming
// or applying further work, and must not attempt to rewrite this claim
// (the lease already moved on, or the caller is shutting down).
func (w *DispatchWorker) applyOne(ctx context.Context, claim store.AlertDispatch) (stop bool, err error) {
	applyErr := w.applier.ApplyDelivery(ctx, claim)
	if applyErr == nil {
		return false, nil
	}

	if errors.Is(applyErr, context.Canceled) || errors.Is(applyErr, context.DeadlineExceeded) || errors.Is(applyErr, store.ErrAlertDispatchLeaseLost) {
		w.logger.Warn("correlator: dispatch worker round stopped",
			"delivery_id", claim.Delivery.ID, "attempt", claim.AttemptCount, "err", applyErr)
		return true, applyErr
	}

	class, terminal := dispatchErrorClass(applyErr)
	if !terminal && claim.AttemptCount >= w.cfg.MaxAttempts {
		terminal = true
	}

	retryAt := w.cfg.Now()
	if !terminal {
		retryAt = retryAt.Add(dispatchRetryBackoff(claim.AttemptCount))
	}

	if rerr := w.store.RetryAlertDispatch(ctx, claim, class, retryAt, terminal); rerr != nil {
		// The write-back itself lost the race (e.g. another worker's lease
		// already reclaimed this row): nothing more this call can do about
		// it, so log and move on to the rest of the batch rather than
		// abandoning it.
		w.logger.Error("correlator: dispatch retry write-back failed",
			"delivery_id", claim.Delivery.ID, "attempt", claim.AttemptCount, "class", class, "err", rerr)
		return false, nil
	}

	w.logger.Warn("correlator: dispatch delivery failed",
		"delivery_id", claim.Delivery.ID, "attempt", claim.AttemptCount, "class", class, "terminal", terminal, "err", applyErr)
	return false, nil
}

// Drain runs RunOnce repeatedly until a round handles zero items (the
// outbox is caught up) or a round returns an error. It returns the total
// handled across every round.
func (w *DispatchWorker) Drain(ctx context.Context) (int, error) {
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
// call at most once per DispatchWorker; later calls are no-ops.
func (w *DispatchWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		go w.run(ctx)
	})
}

func (w *DispatchWorker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if _, err := w.Drain(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("correlator: dispatch worker drain", "err", err)
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
func (w *DispatchWorker) Wake() {
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
func (w *DispatchWorker) Stop(ctx context.Context) error {
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
