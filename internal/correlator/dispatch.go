// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// ErrInvalidDelivery classifies a durably accepted row that cannot satisfy
// the correlation contract. It is a permanent local dead letter rather than a
// retryable dependency failure.
var ErrInvalidDelivery = errors.New("correlator: invalid delivery")

// RetryPolicy bounds durable dispatch retries. Jitter is injectable for
// deterministic tests; nil applies full jitter in [50%, 150%).
type RetryPolicy struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxAttempts    int
	Jitter         func(time.Duration) time.Duration
}

func (p RetryPolicy) defaults() RetryPolicy {
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = time.Second
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = 5 * time.Minute
	}
	if p.MaxBackoff < p.InitialBackoff {
		p.MaxBackoff = p.InitialBackoff
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 8
	}
	return p
}

func (p RetryPolicy) backoff(attempt int) time.Duration {
	p = p.defaults()
	delay := p.InitialBackoff
	for i := 1; i < attempt && delay < p.MaxBackoff; i++ {
		if delay > p.MaxBackoff/2 {
			delay = p.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > p.MaxBackoff {
		delay = p.MaxBackoff
	}
	if p.Jitter != nil {
		return p.Jitter(delay)
	}
	return delay/2 + time.Duration(rand.Int64N(int64(delay)))
}

// DispatchWorkerConfig configures one durable correlation worker.
type DispatchWorkerConfig struct {
	Owner        string
	Lease        time.Duration
	PollInterval time.Duration
	BatchSize    int
	Retry        RetryPolicy
}

// DispatchWorker polls and leases immutable Alert deliveries. Wake is a
// latency optimization only; polling remains the correctness mechanism.
type DispatchWorker struct {
	store      *store.Store
	correlator *Correlator
	owner      string
	lease      time.Duration
	retry      RetryPolicy
	wake       chan struct{}
	poll       time.Duration
	batchSize  int
	logger     *slog.Logger

	now   func() time.Time
	apply func(context.Context, store.AlertDelivery) error

	runMu    sync.Mutex
	stateMu  sync.Mutex
	started  bool
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewDispatchWorker constructs a durable worker. Runtime wiring is deferred to
// the hard cutover; tests and recovery code may call RunOnce directly.
func NewDispatchWorker(st *store.Store, cor *Correlator, cfg DispatchWorkerConfig, logger *slog.Logger) *DispatchWorker {
	if cfg.Owner == "" {
		cfg.Owner = "correlator-dispatch"
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 30 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 32
	}
	if logger == nil {
		logger = slog.Default()
	}
	w := &DispatchWorker{
		store: st, correlator: cor, owner: cfg.Owner, lease: cfg.Lease,
		retry: cfg.Retry.defaults(), wake: make(chan struct{}, 1), poll: cfg.PollInterval,
		batchSize: cfg.BatchSize, logger: logger, now: func() time.Time { return time.Now().UTC() },
		stopCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
	w.apply = cor.ApplyDelivery
	return w
}

// Start launches polling and returns immediately. Calling Start more than once
// is a no-op.
func (w *DispatchWorker) Start(ctx context.Context) {
	w.stateMu.Lock()
	if w.started {
		w.stateMu.Unlock()
		return
	}
	w.started = true
	w.stateMu.Unlock()
	go w.loop(ctx)
}

// Stop terminates a started worker and waits for its current RunOnce call.
func (w *DispatchWorker) Stop() {
	w.stateMu.Lock()
	started := w.started
	w.stateMu.Unlock()
	if !started {
		return
	}
	w.stopOnce.Do(func() { close(w.stopCh) })
	<-w.doneCh
}

// Wake requests an early poll without carrying any authoritative work in
// memory.
func (w *DispatchWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *DispatchWorker) loop(ctx context.Context) {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		if err := w.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("correlator: dispatch run", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-w.wake:
		case <-ticker.C:
		}
	}
}

// RunOnce claims one bounded batch, applies each immutable delivery, and only
// marks the dispatch applied after the correlation transaction has committed.
func (w *DispatchWorker) RunOnce(ctx context.Context) error {
	w.runMu.Lock()
	defer w.runMu.Unlock()

	now := w.now().UTC()
	claims, err := w.store.ClaimAlertDispatches(ctx, w.owner, now, w.lease, w.batchSize)
	if err != nil {
		return fmt.Errorf("correlator: claim alert dispatches: %w", err)
	}
	var runErr error
	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			return errors.Join(runErr, err)
		}
		if err := w.apply(ctx, claim.Delivery); err != nil {
			class, terminal := classifyDispatchError(err, claim.AttemptCount, w.retry.MaxAttempts)
			retryAt := w.now().UTC().Add(w.retry.backoff(claim.AttemptCount))
			if retryErr := w.store.RetryAlertDispatch(ctx, claim, class, retryAt, terminal); retryErr != nil {
				runErr = errors.Join(runErr, fmt.Errorf("correlator: persist dispatch failure for %s: %w", claim.Delivery.ID, retryErr))
			} else {
				runErr = errors.Join(runErr, fmt.Errorf("correlator: apply delivery %s: %w", claim.Delivery.ID, err))
			}
			continue
		}
		if err := w.store.MarkAlertDispatchApplied(ctx, claim, w.now().UTC()); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("correlator: acknowledge delivery %s: %w", claim.Delivery.ID, err))
		}
	}
	return runErr
}

func classifyDispatchError(err error, attempt, maxAttempts int) (class string, terminal bool) {
	switch {
	case errors.Is(err, ErrInvalidDelivery), errors.Is(err, store.ErrNotFound):
		return "invalid_delivery", true
	case attempt >= maxAttempts:
		return "retry_exhausted", true
	default:
		return "correlation_retryable", false
	}
}
