// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// fixedClock is a deterministic WorkerConfig.Now for tests that must not
// depend on wall-clock timing.
func fixedClock() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

// dispatchStoreSpy fakes DispatchStore. claims is popped (returned once,
// then cleared) by ClaimAlertDispatches unless claimFn is set, which lets a
// test script a multi-round claim sequence (e.g. for Drain). Every
// RetryAlertDispatch call overwrites the retry* fields with its arguments,
// which is enough for the single-claim-per-round tests in this file.
type dispatchStoreSpy struct {
	mu sync.Mutex

	claims   []store.AlertDispatch
	claimFn  func(call int) ([]store.AlertDispatch, error)
	claimErr error

	claimCalls int

	retryCalled   bool
	retryClaim    store.AlertDispatch
	retryClass    string
	retryAt       time.Time
	retryTerminal bool
	retryErr      error
}

func (s *dispatchStoreSpy) ClaimAlertDispatches(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) ([]store.AlertDispatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimCalls++
	if s.claimFn != nil {
		return s.claimFn(s.claimCalls)
	}
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	out := s.claims
	s.claims = nil
	return out, nil
}

func (s *dispatchStoreSpy) RetryAlertDispatch(_ context.Context, claim store.AlertDispatch, class string, retryAt time.Time, terminal bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryCalled = true
	s.retryClaim = claim
	s.retryClass = class
	s.retryAt = retryAt
	s.retryTerminal = terminal
	return s.retryErr
}

func (s *dispatchStoreSpy) setClaims(claims []store.AlertDispatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims = claims
}

// deliveryApplierFunc fakes DeliveryApplier from a plain function.
type deliveryApplierFunc func(context.Context, store.AlertDispatch) error

func (f deliveryApplierFunc) ApplyDelivery(ctx context.Context, claim store.AlertDispatch) error {
	return f(ctx, claim)
}

func dispatchClaim(id string, attempt int) store.AlertDispatch {
	return store.AlertDispatch{Delivery: store.AlertDelivery{ID: id}, AttemptCount: attempt}
}

// ----------------------------------------------------------------------
// RunOnce classification
// ----------------------------------------------------------------------

func TestDispatchWorkerRetriesTransientFailure(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{{Delivery: store.AlertDelivery{ID: "d1"}, AttemptCount: 1}}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error { return errors.New("temporary") })
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)
	if handled, err := w.RunOnce(context.Background()); err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if st.retryClass != "transient" || st.retryTerminal {
		t.Fatalf("retry = %+v", st)
	}
}

func TestDispatchWorkerSuccessNeedsNoCompletionCall(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error { return nil })
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if st.retryCalled {
		t.Fatalf("RetryAlertDispatch must not be called on success: %+v", st)
	}
}

func TestDispatchWorkerInvalidDeliveryTerminatesWithoutRetry(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return ErrInvalidDelivery
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if !st.retryCalled || st.retryClass != "invalid_delivery" || !st.retryTerminal {
		t.Fatalf("retry = %+v, want terminal invalid_delivery", st)
	}
}

func TestDispatchWorkerNotFoundTerminatesWithoutRetry(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return store.ErrNotFound
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if !st.retryCalled || st.retryClass != "invalid_delivery" || !st.retryTerminal {
		t.Fatalf("retry = %+v, want terminal invalid_delivery", st)
	}
}

func TestDispatchWorkerContextCancellationSkipsRetryWrite(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return context.Canceled
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if st.retryCalled {
		t.Fatalf("RetryAlertDispatch must not be called on cancellation: %+v", st)
	}
}

func TestDispatchWorkerLeaseLostSkipsRetryWrite(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return store.ErrAlertDispatchLeaseLost
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if !errors.Is(err, store.ErrAlertDispatchLeaseLost) {
		t.Fatalf("err = %v, want ErrAlertDispatchLeaseLost", err)
	}
	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if st.retryCalled {
		t.Fatalf("RetryAlertDispatch must not be called when the lease is lost: %+v", st)
	}
}

func TestDispatchWorkerEighthFailedClaimBecomesTerminal(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 8)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return errors.New("still failing")
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !st.retryCalled || !st.retryTerminal || st.retryClass != "transient" {
		t.Fatalf("retry = %+v, want terminal transient at max attempts", st)
	}
}

func TestDispatchWorkerSeventhFailedClaimStaysRetryable(t *testing.T) {
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 7)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return errors.New("still failing")
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !st.retryCalled || st.retryTerminal {
		t.Fatalf("retry = %+v, want non-terminal below max attempts", st)
	}
}

func TestDispatchWorkerBackoffGrowsExponentially(t *testing.T) {
	now := fixedClock()
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return errors.New("boom")
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	first := st.retryAt.Sub(now)

	st.setClaims([]store.AlertDispatch{dispatchClaim("d1", 2)})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	second := st.retryAt.Sub(now)

	if first <= 0 || second <= first {
		t.Fatalf("backoff did not grow: attempt1=%v attempt2=%v", first, second)
	}
}

func TestDispatchWorkerBackoffCappedAtFiveMinutes(t *testing.T) {
	now := fixedClock()
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 10)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		return errors.New("boom")
	})
	// MaxAttempts raised so attempt 10 is still eligible for a scheduled
	// retry (not yet forced terminal) and the cap itself is what's under test.
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", MaxAttempts: 20, Now: fixedClock}, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.retryTerminal {
		t.Fatalf("retry unexpectedly terminal: %+v", st)
	}
	if got := st.retryAt.Sub(now); got != 5*time.Minute {
		t.Fatalf("retryAt = %v, want capped at 5m", got)
	}
}

// ----------------------------------------------------------------------
// Batch claim size and RunOnce plumbing
// ----------------------------------------------------------------------

func TestDispatchWorkerRunOnceReportsClaimError(t *testing.T) {
	wantErr := errors.New("claim boom")
	st := &dispatchStoreSpy{claimErr: wantErr}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error { return nil })
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if handled != 0 || !errors.Is(err, wantErr) {
		t.Fatalf("run = %d, %v, want 0, %v", handled, err, wantErr)
	}
}

// ----------------------------------------------------------------------
// Drain
// ----------------------------------------------------------------------

func TestDispatchWorkerDrainContinuesUntilZero(t *testing.T) {
	var applyCalls []string
	rounds := [][]store.AlertDispatch{
		{dispatchClaim("d1", 1), dispatchClaim("d2", 1)},
		{dispatchClaim("d3", 1)},
		{},
	}
	st := &dispatchStoreSpy{
		claimFn: func(call int) ([]store.AlertDispatch, error) {
			if call-1 < len(rounds) {
				return rounds[call-1], nil
			}
			return nil, nil
		},
	}
	applier := deliveryApplierFunc(func(_ context.Context, claim store.AlertDispatch) error {
		applyCalls = append(applyCalls, claim.Delivery.ID)
		return nil
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if handled != 3 {
		t.Fatalf("handled = %d, want 3", handled)
	}
	if len(applyCalls) != 3 {
		t.Fatalf("applyCalls = %v, want 3 deliveries applied", applyCalls)
	}
	if st.claimCalls != 3 {
		t.Fatalf("claimCalls = %d, want 3 (stops after the empty round)", st.claimCalls)
	}
}

func TestDispatchWorkerDrainStopsImmediatelyWhenNoWork(t *testing.T) {
	st := &dispatchStoreSpy{}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error { return nil })
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.Drain(context.Background())
	if err != nil || handled != 0 {
		t.Fatalf("drain = %d, %v, want 0, nil", handled, err)
	}
	if st.claimCalls != 1 {
		t.Fatalf("claimCalls = %d, want exactly 1", st.claimCalls)
	}
}

// ----------------------------------------------------------------------
// Wake / Start / Stop lifecycle
// ----------------------------------------------------------------------

func TestDispatchWorkerWakeIsNonBlocking(t *testing.T) {
	w := NewDispatchWorker(&dispatchStoreSpy{}, deliveryApplierFunc(func(context.Context, store.AlertDispatch) error { return nil }), WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	done := make(chan struct{})
	go func() {
		w.Wake()
		w.Wake()
		w.Wake()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake blocked")
	}
}

func TestDispatchWorkerStartRunsImmediatelyAndWakeTriggersAnotherRound(t *testing.T) {
	appliedCh := make(chan string, 4)
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(_ context.Context, claim store.AlertDispatch) error {
		appliedCh <- claim.Delivery.ID
		return nil
	})
	// A long interval means only Start's initial round and the explicit Wake
	// can produce activity within this test's timeout — never the ticker.
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	select {
	case id := <-appliedCh:
		if id != "d1" {
			t.Fatalf("applied %q, want d1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the initial round")
	}

	st.setClaims([]store.AlertDispatch{dispatchClaim("d2", 1)})
	w.Wake()

	select {
	case id := <-appliedCh:
		if id != "d2" {
			t.Fatalf("applied %q, want d2", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the woken round")
	}

	if err := w.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestDispatchWorkerStopWaitsForActiveRound(t *testing.T) {
	var applied int32
	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&applied, 1)
		return nil
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)

	w.Start(context.Background())
	if err := w.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := atomic.LoadInt32(&applied); got != 1 {
		t.Fatalf("applied = %d, want 1 (Stop must wait for the active round)", got)
	}
}

func TestDispatchWorkerStopRespectsShutdownDeadline(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	st := &dispatchStoreSpy{claims: []store.AlertDispatch{dispatchClaim("d1", 1)}}
	applier := deliveryApplierFunc(func(context.Context, store.AlertDispatch) error {
		<-block
		return nil
	})
	w := NewDispatchWorker(st, applier, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)
	w.Start(context.Background())

	stopCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := w.Stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop = %v, want context.DeadlineExceeded", err)
	}
}
