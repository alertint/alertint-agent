// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestDispatchWorkerPersistsRetryWithBackoff(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	acceptDispatchDelivery(t, st, "delivery-retry", "fp-retry", "firing", now)
	cor := New(Config{}, st, NopIncidentSink{}, nil)
	w := NewDispatchWorker(st, cor, DispatchWorkerConfig{
		Owner: "retry-worker", Lease: time.Minute,
		Retry: RetryPolicy{InitialBackoff: 10 * time.Second, MaxBackoff: time.Minute, MaxAttempts: 3, Jitter: func(d time.Duration) time.Duration { return d }},
	}, nil)
	w.now = func() time.Time { return now }
	w.apply = func(context.Context, store.AlertDelivery) error { return errors.New("temporary database contention") }

	if err := w.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce error=nil, want retryable processing error")
	}
	var status, class, retryAt string
	if err := st.DB().QueryRow(`SELECT status, last_error_class, retry_at FROM alert_delivery_dispatches WHERE delivery_id = 'delivery-retry'`).Scan(&status, &class, &retryAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || class != "correlation_retryable" || retryAt != now.Add(10*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("retry state=(%q,%q,%q)", status, class, retryAt)
	}
}

func TestDispatchWorkerDeadLettersPermanentError(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	acceptDispatchDelivery(t, st, "delivery-failed", "fp-failed", "firing", now)
	cor := New(Config{}, st, NopIncidentSink{}, nil)
	w := NewDispatchWorker(st, cor, DispatchWorkerConfig{Owner: "failed-worker", Lease: time.Minute}, nil)
	w.now = func() time.Time { return now }
	w.apply = func(context.Context, store.AlertDelivery) error { return ErrInvalidDelivery }

	if err := w.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce error=nil, want permanent processing error")
	}
	var status, class string
	var retryAt any
	if err := st.DB().QueryRow(`SELECT status, last_error_class, retry_at FROM alert_delivery_dispatches WHERE delivery_id = 'delivery-failed'`).Scan(&status, &class, &retryAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || class != "invalid_delivery" || retryAt != nil {
		t.Fatalf("failed state=(%q,%q,%v)", status, class, retryAt)
	}
}

func TestDispatchWorkerWakeOnlyReducesPollingLatency(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
	cor := New(Config{}, st, NopIncidentSink{}, nil)
	w := NewDispatchWorker(st, cor, DispatchWorkerConfig{
		Owner: "wake-worker", Lease: time.Minute, PollInterval: time.Hour,
	}, nil)
	w.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	acceptDispatchDelivery(t, st, "delivery-wake", "fp-wake", "firing", now)
	w.Wake()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		if err := st.DB().QueryRow(`SELECT status FROM alert_delivery_dispatches WHERE delivery_id = 'delivery-wake'`).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "applied" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("woken worker did not apply durable delivery")
}
