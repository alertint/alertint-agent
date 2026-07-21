// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
)

type fakeUsage struct{ in, out int }

// TestCallWithRetry_RetryableThenSuccess: a RetryableError is retried and the
// eventual success returns the last attempt's raw and usage.
func TestCallWithRetry_RetryableThenSuccess(t *testing.T) {
	calls := 0
	raw, usage, err := llm.CallWithRetry(context.Background(), slog.Default(), 2, time.Millisecond,
		func(ctx context.Context) (json.RawMessage, fakeUsage, error) {
			calls++
			if calls < 3 {
				return nil, fakeUsage{}, &llm.RetryableError{StatusCode: http.StatusServiceUnavailable}
			}
			return json.RawMessage(`{"ok":1}`), fakeUsage{in: 5, out: 7}, nil
		})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
	if string(raw) != `{"ok":1}` || usage != (fakeUsage{in: 5, out: 7}) {
		t.Errorf("raw = %s, usage = %+v", raw, usage)
	}
}

// TestCallWithRetry_NonRetryableReturnsImmediately: any other error stops the
// loop on the first attempt with zero usage.
func TestCallWithRetry_NonRetryableReturnsImmediately(t *testing.T) {
	calls := 0
	wantErr := errors.New("llm: api error: HTTP 400")
	_, usage, err := llm.CallWithRetry(context.Background(), slog.Default(), 2, time.Millisecond,
		func(ctx context.Context) (json.RawMessage, fakeUsage, error) {
			calls++
			return nil, fakeUsage{in: 9}, wantErr
		})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
	if usage != (fakeUsage{}) {
		t.Errorf("usage = %+v, want zero on error", usage)
	}
}

// TestCallWithRetry_ExhaustedReturnsLastError: retries stop after maxRetries
// and the last retryable error surfaces.
func TestCallWithRetry_ExhaustedReturnsLastError(t *testing.T) {
	calls := 0
	_, _, err := llm.CallWithRetry(context.Background(), slog.Default(), 2, time.Millisecond,
		func(ctx context.Context) (json.RawMessage, fakeUsage, error) {
			calls++
			return nil, fakeUsage{}, &llm.RetryableError{StatusCode: http.StatusTooManyRequests}
		})
	var retryErr *llm.RetryableError
	if !errors.As(err, &retryErr) || retryErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want RetryableError 429", err)
	}
	if calls != 3 { // initial attempt + 2 retries
		t.Errorf("calls = %d, want 3", calls)
	}
}

// TestCallWithRetry_CancelDuringBackoff: a context cancelled while the loop
// sleeps between attempts aborts the wait with ctx.Err, not another attempt.
func TestCallWithRetry_CancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, _, err = llm.CallWithRetry(ctx, slog.Default(), 2, time.Hour,
			func(ctx context.Context) (json.RawMessage, fakeUsage, error) {
				calls++
				cancel() // cancel once the loop is guaranteed to enter the backoff sleep
				return nil, fakeUsage{}, &llm.RetryableError{StatusCode: http.StatusServiceUnavailable}
			})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CallWithRetry did not return after cancel during backoff")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no attempt after cancel)", calls)
	}
}
