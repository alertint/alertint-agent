// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

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

// inputStoreSpy fakes InputStore. claims is popped (returned once, then
// cleared) by ClaimSituationInputs unless claimFn is set, which lets a test
// script a multi-round claim sequence (e.g. for Drain). Every
// RetrySituationInput call overwrites the retry* fields with its arguments,
// which is enough for the single-claim-per-round tests in this file.
type inputStoreSpy struct {
	mu sync.Mutex

	claims   []store.SituationClaim
	claimFn  func(call int) ([]store.SituationClaim, error)
	claimErr error

	claimCalls int

	applyFn func(claim store.SituationClaim) error

	retryCalled   bool
	retryClaim    store.SituationClaim
	retryClass    string
	retryAt       time.Time
	retryTerminal bool
	retryErr      error
}

func (s *inputStoreSpy) ClaimSituationInputs(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) ([]store.SituationClaim, error) {
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

func (s *inputStoreSpy) ApplySituationInput(_ context.Context, claim store.SituationClaim) error {
	if s.applyFn != nil {
		return s.applyFn(claim)
	}
	return nil
}

func (s *inputStoreSpy) RetrySituationInput(_ context.Context, claim store.SituationClaim, class string, retryAt time.Time, terminal bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryCalled = true
	s.retryClaim = claim
	s.retryClass = class
	s.retryAt = retryAt
	s.retryTerminal = terminal
	return s.retryErr
}

func (s *inputStoreSpy) setClaims(claims []store.SituationClaim) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims = claims
}

func inputClaim(id string, attempt int) store.SituationClaim {
	c := store.SituationClaim{AttemptCount: attempt}
	c.ID = id
	return c
}

// ----------------------------------------------------------------------
// RunOnce classification
// ----------------------------------------------------------------------

func TestInputWorkerRetriesTransientFailure(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}, applyFn: func(store.SituationClaim) error { return errors.New("temporary") }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)
	if handled, err := w.RunOnce(context.Background()); err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if st.retryClass != "transient" || st.retryTerminal {
		t.Fatalf("retry = %+v", st)
	}
}

func TestInputWorkerSuccessNeedsNoCompletionCall(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if st.retryCalled {
		t.Fatalf("RetrySituationInput must not be called on success: %+v", st)
	}
}

func TestInputWorkerNotFoundTerminatesWithoutRetry(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}, applyFn: func(store.SituationClaim) error { return store.ErrNotFound }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if err != nil || handled != 1 {
		t.Fatalf("run = %d, %v", handled, err)
	}
	if !st.retryCalled || st.retryClass != "invalid_input" || !st.retryTerminal {
		t.Fatalf("retry = %+v, want terminal invalid_input", st)
	}
}

func TestInputWorkerContextCancellationSkipsRetryWrite(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}, applyFn: func(store.SituationClaim) error { return context.Canceled }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if st.retryCalled {
		t.Fatalf("RetrySituationInput must not be called on cancellation: %+v", st)
	}
}

func TestInputWorkerLeaseLostSkipsRetryWrite(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}, applyFn: func(store.SituationClaim) error { return store.ErrSituationLeaseLost }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if !errors.Is(err, store.ErrSituationLeaseLost) {
		t.Fatalf("err = %v, want ErrSituationLeaseLost", err)
	}
	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if st.retryCalled {
		t.Fatalf("RetrySituationInput must not be called when the lease is lost: %+v", st)
	}
}

func TestInputWorkerEighthFailedClaimBecomesTerminal(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 8)}, applyFn: func(store.SituationClaim) error { return errors.New("still failing") }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !st.retryCalled || !st.retryTerminal || st.retryClass != "transient" {
		t.Fatalf("retry = %+v, want terminal transient at max attempts", st)
	}
}

func TestInputWorkerSeventhFailedClaimStaysRetryable(t *testing.T) {
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 7)}, applyFn: func(store.SituationClaim) error { return errors.New("still failing") }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !st.retryCalled || st.retryTerminal {
		t.Fatalf("retry = %+v, want non-terminal below max attempts", st)
	}
}

func TestInputWorkerBackoffGrowsExponentially(t *testing.T) {
	now := fixedClock()
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 1)}, applyFn: func(store.SituationClaim) error { return errors.New("boom") }}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	first := st.retryAt.Sub(now)

	st.setClaims([]store.SituationClaim{inputClaim("i1", 2)})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	second := st.retryAt.Sub(now)

	if first <= 0 || second <= first {
		t.Fatalf("backoff did not grow: attempt1=%v attempt2=%v", first, second)
	}
}

func TestInputWorkerBackoffCappedAtFiveMinutes(t *testing.T) {
	now := fixedClock()
	st := &inputStoreSpy{claims: []store.SituationClaim{inputClaim("i1", 10)}, applyFn: func(store.SituationClaim) error { return errors.New("boom") }}
	// MaxAttempts raised so attempt 10 is still eligible for a scheduled
	// retry (not yet forced terminal) and the cap itself is what's under test.
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", MaxAttempts: 20, Now: fixedClock}, nil)

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

func TestInputWorkerRunOnceReportsClaimError(t *testing.T) {
	wantErr := errors.New("claim boom")
	st := &inputStoreSpy{claimErr: wantErr}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.RunOnce(context.Background())
	if handled != 0 || !errors.Is(err, wantErr) {
		t.Fatalf("run = %d, %v, want 0, %v", handled, err, wantErr)
	}
}

// ----------------------------------------------------------------------
// Drain
// ----------------------------------------------------------------------

func TestInputWorkerDrainContinuesUntilZero(t *testing.T) {
	var applyCalls []string
	rounds := [][]store.SituationClaim{
		{inputClaim("i1", 1), inputClaim("i2", 1)},
		{inputClaim("i3", 1)},
		{},
	}
	st := &inputStoreSpy{
		claimFn: func(call int) ([]store.SituationClaim, error) {
			if call-1 < len(rounds) {
				return rounds[call-1], nil
			}
			return nil, nil
		},
		applyFn: func(claim store.SituationClaim) error {
			applyCalls = append(applyCalls, claim.ID)
			return nil
		},
	}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

	handled, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if handled != 3 {
		t.Fatalf("handled = %d, want 3", handled)
	}
	if len(applyCalls) != 3 {
		t.Fatalf("applyCalls = %v, want 3 inputs applied", applyCalls)
	}
	if st.claimCalls != 3 {
		t.Fatalf("claimCalls = %d, want 3 (stops after the empty round)", st.claimCalls)
	}
}

func TestInputWorkerDrainStopsImmediatelyWhenNoWork(t *testing.T) {
	st := &inputStoreSpy{}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

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

func TestInputWorkerWakeIsNonBlocking(t *testing.T) {
	w := NewInputWorker(&inputStoreSpy{}, WorkerConfig{Owner: "worker-a", Now: fixedClock}, nil)

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

func TestInputWorkerStartRunsImmediatelyAndWakeTriggersAnotherRound(t *testing.T) {
	appliedCh := make(chan string, 4)
	st := &inputStoreSpy{
		claims: []store.SituationClaim{inputClaim("i1", 1)},
		applyFn: func(claim store.SituationClaim) error {
			appliedCh <- claim.ID
			return nil
		},
	}
	// A long interval means only Start's initial round and the explicit Wake
	// can produce activity within this test's timeout — never the ticker.
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	select {
	case id := <-appliedCh:
		if id != "i1" {
			t.Fatalf("applied %q, want i1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the initial round")
	}

	st.setClaims([]store.SituationClaim{inputClaim("i2", 1)})
	w.Wake()

	select {
	case id := <-appliedCh:
		if id != "i2" {
			t.Fatalf("applied %q, want i2", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the woken round")
	}

	if err := w.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestInputWorkerStopWaitsForActiveRound(t *testing.T) {
	var applied int32
	st := &inputStoreSpy{
		claims: []store.SituationClaim{inputClaim("i1", 1)},
		applyFn: func(store.SituationClaim) error {
			time.Sleep(30 * time.Millisecond)
			atomic.AddInt32(&applied, 1)
			return nil
		},
	}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)

	w.Start(context.Background())
	if err := w.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := atomic.LoadInt32(&applied); got != 1 {
		t.Fatalf("applied = %d, want 1 (Stop must wait for the active round)", got)
	}
}

func TestInputWorkerStopRespectsShutdownDeadline(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	st := &inputStoreSpy{
		claims: []store.SituationClaim{inputClaim("i1", 1)},
		applyFn: func(store.SituationClaim) error {
			<-block
			return nil
		},
	}
	w := NewInputWorker(st, WorkerConfig{Owner: "worker-a", Interval: time.Hour, Now: fixedClock}, nil)
	w.Start(context.Background())

	stopCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := w.Stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop = %v, want context.DeadlineExceeded", err)
	}
}
