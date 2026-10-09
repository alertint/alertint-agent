// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// Queue is the durable independent ntfy delivery ledger implemented by store.Store.
type Queue interface {
	ClaimNTFY(ctx context.Context, owner string, now time.Time, lease time.Duration) ([]Claim, error)
	FinishNTFY(ctx context.Context, claim Claim, status string, reason string, retryAt time.Time, now time.Time) error
}

type AuditSink interface {
	Append(ctx context.Context, component string, kind string, data any) error
}

// Worker sends one freshly claimed head at a time. A thirty-second lease
// covers a ten-second request; no database transaction spans an HTTP call.
type Worker struct {
	queue  Queue
	client *Client
	owner  string
	logger *slog.Logger
	audit  AuditSink
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewWorker(queue Queue, client *Client, owner string, logger *slog.Logger, audit AuditSink) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{queue: queue, client: client, owner: owner, logger: logger, audit: audit}
}

func (w *Worker) Start(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return
	}
	ctx, w.cancel = context.WithCancel(ctx)
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := w.Round(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
				w.logger.Error("ntfy delivery worker failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) Round(ctx context.Context, now time.Time) error {
	claims, err := w.queue.ClaimNTFY(ctx, w.owner, now, 30*time.Second)
	if err != nil {
		return err
	}
	for _, claim := range claims {
		err = w.client.Send(ctx, claim.Destination, claim.Message)
		completed := time.Now().UTC()
		status, reason, retryAt := deliveryOutcome(err, claim.Attempts, completed)
		// Shutdown cancellation must not strand all remaining claims until lease expiry.
		ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		ackErr := w.queue.FinishNTFY(ackCtx, claim, status, reason, retryAt, completed)
		if ackErr == nil {
			w.logOutcome(claim, status, reason)
			if w.audit != nil {
				if auditErr := w.audit.Append(ackCtx, "ntfy", "situation.ntfy."+status, map[string]any{"notification_id": claim.ID, "reason": reason}); auditErr != nil {
					w.logger.Warn("ntfy delivery audit failed", "error", auditErr)
				}
			}
		}
		cancel()
		if ackErr != nil && !errors.Is(ackErr, ErrClaimLost) {
			return ackErr
		}
	}
	return nil
}

func (w *Worker) logOutcome(c Claim, status, reason string) {
	if status == "delivered" {
		w.logger.Info("ntfy notified", "notification", c.ID)
		return
	}
	w.logger.Warn("ntfy delivery unavailable; notification retained", "notification", c.ID, "status", status, "reason", reason)
}

func deliveryOutcome(err error, attempts int, now time.Time) (string, string, time.Time) {
	if err == nil {
		return "delivered", "", now
	}
	var failure *DeliveryError
	delay := min(5*time.Second*time.Duration(1<<min(max(attempts-1, 0), 6)), 5*time.Minute)
	delay += time.Duration(rand.Int64N(int64(delay/5) + 1)) // #nosec G404 -- retry jitter scatters timing; it does not generate secrets.
	reason := "ntfy_unavailable"
	if errors.As(err, &failure) {
		if failure.Blocked {
			return "blocked", "ntfy_configuration_rejected", now
		}
		if failure.Status == 429 {
			reason = "ntfy_rate_limited"
		}
		delay = max(delay, failure.RetryAfter)
	}
	return "pending", reason, now.Add(delay)
}
