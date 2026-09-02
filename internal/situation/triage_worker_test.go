// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// --------------------------------------------------------------------------
// Fakes. TriageWorker's dependencies are narrow, situation-native
// interfaces (no internal/store import — see triage_worker.go's own header
// comment), so these fakes need no real database at all.
// --------------------------------------------------------------------------

type completeCall struct {
	attemptID, incidentID string
	finding               situation.TriageFindingInput
}

type backoffCall struct {
	attemptID, incidentID string
	nextAt                time.Time
	code, detail          string
}

type exhaustCall struct {
	attemptID, incidentID string
	code, detail          string
}

type fakeStore struct {
	mu sync.Mutex

	claimFn    func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error)
	extendFn   func(ctx context.Context, attemptID, incidentID, owner string, now time.Time, lease time.Duration) error
	completeFn func(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error)
	recoverFn  func(ctx context.Context, now time.Time) (int, error)

	extendCalls   int
	completeCalls []completeCall
	backoffCalls  []backoffCall
	exhaustCalls  []exhaustCall
	recoverCalls  int
}

func (f *fakeStore) ClaimIncidentTriageAttempt(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
	if f.claimFn != nil {
		return f.claimFn(ctx, incidentID, owner, now, lease)
	}
	return situation.TriageAttemptClaim{}, model.ErrNotFound
}

func (f *fakeStore) ExtendIncidentTriageLease(ctx context.Context, attemptID, incidentID, owner string, now time.Time, lease time.Duration) error {
	f.mu.Lock()
	f.extendCalls++
	f.mu.Unlock()
	if f.extendFn != nil {
		return f.extendFn(ctx, attemptID, incidentID, owner, now, lease)
	}
	return nil
}

func (f *fakeStore) CompleteIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
	f.mu.Lock()
	f.completeCalls = append(f.completeCalls, completeCall{attemptID, incidentID, finding})
	f.mu.Unlock()
	if f.completeFn != nil {
		return f.completeFn(ctx, attemptID, incidentID, finding, now)
	}
	return situation.TriageCompletionSuccess, nil
}

func (f *fakeStore) BackoffIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, nextAt time.Time, code, detail string, now time.Time) error {
	f.mu.Lock()
	f.backoffCalls = append(f.backoffCalls, backoffCall{attemptID, incidentID, nextAt, code, detail})
	f.mu.Unlock()
	return nil
}

func (f *fakeStore) ExhaustIncidentTriageAttempt(ctx context.Context, attemptID, incidentID, code, detail string, now time.Time) error {
	f.mu.Lock()
	f.exhaustCalls = append(f.exhaustCalls, exhaustCall{attemptID, incidentID, code, detail})
	f.mu.Unlock()
	return nil
}

func (f *fakeStore) RecoverExpiredIncidentTriageAttempts(ctx context.Context, now time.Time) (int, error) {
	f.mu.Lock()
	f.recoverCalls++
	f.mu.Unlock()
	if f.recoverFn != nil {
		return f.recoverFn(ctx, now)
	}
	return 0, nil
}

func (f *fakeStore) snapshot() (extendCalls int, complete []completeCall, backoff []backoffCall, exhaust []exhaustCall, recoverCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.extendCalls, append([]completeCall(nil), f.completeCalls...), append([]backoffCall(nil), f.backoffCalls...), append([]exhaustCall(nil), f.exhaustCalls...), f.recoverCalls
}

type fakeLister struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (f *fakeLister) ListDueIncidentTriage(ctx context.Context, now time.Time) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...), f.err
}

func (f *fakeLister) setIDs(ids []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids = ids
}

type fakeAnalyzer struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error)
}

func (f *fakeAnalyzer) Analyze(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, claim)
	}
	return situation.AcuteResult{IncidentID: claim.IncidentID}, nil
}

func (f *fakeAnalyzer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeAfterCommit struct {
	mu    sync.Mutex
	calls int
	last  situation.AcuteResult
	fn    func(ctx context.Context, result situation.AcuteResult) error
}

func (f *fakeAfterCommit) AfterCommit(ctx context.Context, result situation.AcuteResult) error {
	f.mu.Lock()
	f.calls++
	f.last = result
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, result)
	}
	return nil
}

func (f *fakeAfterCommit) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func testClaim(incidentID string, attemptNumber int) situation.TriageAttemptClaim {
	return situation.TriageAttemptClaim{
		AttemptID:            "attempt-" + incidentID,
		IncidentID:           incidentID,
		AttemptNumber:        attemptNumber,
		SituationID:          "sit-1",
		DecisionInputVersion: 1,
		MembershipDigest:     "sha256:membership",
		IncidentInputDigest:  "sha256:input",
		MemberDeliveryIDs:    []string{"delivery-1"},
		StartedAt:            time.Now().UTC(),
		LeaseOwner:           "owner-1",
		LeaseExpiresAt:       time.Now().UTC().Add(time.Minute),
		ClaimToken:           1,
	}
}

func newWorker(store *fakeStore, lister *fakeLister, analyzer *fakeAnalyzer, after *fakeAfterCommit, cfg situation.TriageWorkerConfig) *situation.TriageWorker {
	if cfg.Owner == "" {
		cfg.Owner = "test-owner"
	}
	var ac situation.AfterCommitter
	if after != nil {
		ac = after
	}
	return situation.NewTriageWorker(store, lister, analyzer, ac, cfg, nil)
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestTriageWorker_CurrentCompatibleSuccess: claim -> Analyze -> Complete
// (success) -> AfterCommit, exactly once each.
func TestTriageWorker_CurrentCompatibleSuccess(t *testing.T) {
	claim := testClaim("inc-1", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-1"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{
			IncidentID: c.IncidentID, Summary: "s", RootCause: "r", Confidence: 0.5,
			OutputJSON: []byte(`{"x":1}`), EnrichmentJSON: "", EvidencePackDigest: "sha256:pack",
		}, nil
	}}
	after := &fakeAfterCommit{}
	w := newWorker(store, lister, analyzer, after, situation.TriageWorkerConfig{})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1", n)
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 1 {
		t.Fatalf("complete calls = %d, want 1", len(complete))
	}
	if complete[0].finding.RootCause != "r" || complete[0].finding.EvidencePackDigest != "sha256:pack" {
		t.Errorf("finding = %+v, want RootCause=r EvidencePackDigest=sha256:pack", complete[0].finding)
	}
	if len(backoff) != 0 || len(exhaust) != 0 {
		t.Fatalf("backoff/exhaust calls = %d/%d, want 0/0", len(backoff), len(exhaust))
	}
	if after.callCount() != 1 {
		t.Fatalf("AfterCommit calls = %d, want 1", after.callCount())
	}
	if after.last.RootCause != "r" {
		t.Errorf("AfterCommit result.RootCause = %q, want r", after.last.RootCause)
	}
}

// TestTriageWorker_StaleMembership: a stale_membership completion must NOT
// trigger AfterCommit (spec.md: no post-commit effect on a stale attempt).
func TestTriageWorker_StaleMembership(t *testing.T) {
	claim := testClaim("inc-2", 1)
	store := &fakeStore{
		claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
			return claim, nil
		},
		completeFn: func(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
			return situation.TriageCompletionStaleMembership, nil
		},
	}
	lister := &fakeLister{ids: []string{"inc-2"}}
	analyzer := &fakeAnalyzer{}
	after := &fakeAfterCommit{}
	w := newWorker(store, lister, analyzer, after, situation.TriageWorkerConfig{})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if after.callCount() != 0 {
		t.Fatalf("AfterCommit calls = %d, want 0 (stale completion)", after.callCount())
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 1 || len(backoff) != 0 || len(exhaust) != 0 {
		t.Fatalf("complete/backoff/exhaust = %d/%d/%d, want 1/0/0", len(complete), len(backoff), len(exhaust))
	}
}

// TestTriageWorker_StaleIncidentInput mirrors the membership case for the
// other stale outcome.
func TestTriageWorker_StaleIncidentInput(t *testing.T) {
	claim := testClaim("inc-3", 1)
	store := &fakeStore{
		claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
			return claim, nil
		},
		completeFn: func(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
			return situation.TriageCompletionStaleIncidentInput, nil
		},
	}
	lister := &fakeLister{ids: []string{"inc-3"}}
	after := &fakeAfterCommit{}
	w := newWorker(store, lister, &fakeAnalyzer{}, after, situation.TriageWorkerConfig{})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if after.callCount() != 0 {
		t.Fatalf("AfterCommit calls = %d, want 0 (stale completion)", after.callCount())
	}
}

// TestTriageWorker_CleanSkip: Analyze returning situation.ErrCleanSkip must
// close the attempt via ExhaustIncidentTriageAttempt with a distinct
// "clean_skip" code — never Complete, never Backoff.
func TestTriageWorker_CleanSkip(t *testing.T) {
	claim := testClaim("inc-4", 2)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-4"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, situation.ErrCleanSkip
	}}
	after := &fakeAfterCommit{}
	w := newWorker(store, lister, analyzer, after, situation.TriageWorkerConfig{})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 0 || len(backoff) != 0 {
		t.Fatalf("complete/backoff = %d/%d, want 0/0", len(complete), len(backoff))
	}
	if len(exhaust) != 1 {
		t.Fatalf("exhaust calls = %d, want 1", len(exhaust))
	}
	if exhaust[0].code != "clean_skip" {
		t.Errorf("exhaust code = %q, want clean_skip", exhaust[0].code)
	}
	if after.callCount() != 0 {
		t.Fatalf("AfterCommit calls = %d, want 0 (clean skip)", after.callCount())
	}
}

// TestTriageWorker_RetryableProviderFailure: a plain analysis error on an
// attempt below the ceiling backs off (never exhausts).
func TestTriageWorker_RetryableProviderFailure(t *testing.T) {
	claim := testClaim("inc-5", 2) // 2nd of 5 attempts
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-5"}}
	wantErr := errors.New("provider unavailable")
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, wantErr
	}}
	now := time.Now().UTC()
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{Now: func() time.Time { return now }})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 0 || len(exhaust) != 0 {
		t.Fatalf("complete/exhaust = %d/%d, want 0/0", len(complete), len(exhaust))
	}
	if len(backoff) != 1 {
		t.Fatalf("backoff calls = %d, want 1", len(backoff))
	}
	if backoff[0].code == "" {
		t.Error("backoff code must not be empty")
	}
	if !backoff[0].nextAt.After(now) {
		t.Errorf("backoff nextAt = %v, want after %v", backoff[0].nextAt, now)
	}
}

// TestTriageWorker_FifthAttemptExhaustion: a failure on the final (5th, the
// configured MaxAttempts) attempt closes the schedule terminally instead of
// scheduling a 6th.
func TestTriageWorker_FifthAttemptExhaustion(t *testing.T) {
	claim := testClaim("inc-6", 5)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-6"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, errors.New("still failing")
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{MaxAttempts: 5})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 0 || len(backoff) != 0 {
		t.Fatalf("complete/backoff = %d/%d, want 0/0", len(complete), len(backoff))
	}
	if len(exhaust) != 1 {
		t.Fatalf("exhaust calls = %d, want 1", len(exhaust))
	}
}

// TestTriageWorker_Heartbeat: a slow Analyze call gets its lease extended
// more than once while it runs, at roughly the configured heartbeat cadence
// (well under the lease).
func TestTriageWorker_Heartbeat(t *testing.T) {
	claim := testClaim("inc-7", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-7"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		time.Sleep(120 * time.Millisecond)
		return situation.AcuteResult{IncidentID: c.IncidentID}, nil
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{
		Heartbeat: 20 * time.Millisecond,
		Lease:     time.Minute,
	})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	extendCalls, complete, _, _, _ := store.snapshot()
	if extendCalls < 2 {
		t.Fatalf("heartbeat extend calls = %d, want >= 2 for a 120ms analysis at a 20ms heartbeat", extendCalls)
	}
	if len(complete) != 1 {
		t.Fatalf("complete calls = %d, want 1 (heartbeat must not itself complete the attempt)", len(complete))
	}
}

// TestTriageWorker_LeaseLoss: when a heartbeat extend fails, the worker
// cancels the in-flight Analyze call and abandons the attempt — it must
// never complete/backoff/exhaust a stale attempt whose lease moved on.
func TestTriageWorker_LeaseLoss(t *testing.T) {
	claim := testClaim("inc-8", 1)
	analyzeCanceled := make(chan struct{})
	store := &fakeStore{
		claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
			return claim, nil
		},
		extendFn: func(ctx context.Context, attemptID, incidentID, owner string, now time.Time, lease time.Duration) error {
			return situation.ErrTriageAttemptLeaseLost
		},
	}
	lister := &fakeLister{ids: []string{"inc-8"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		<-ctx.Done()
		close(analyzeCanceled)
		return situation.AcuteResult{}, ctx.Err()
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{
		Heartbeat: 10 * time.Millisecond,
		Lease:     time.Minute,
	})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1 (claim was taken even though abandoned)", n)
	}
	select {
	case <-analyzeCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Analyze's context was never canceled after lease loss")
	}
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 0 || len(backoff) != 0 || len(exhaust) != 0 {
		t.Fatalf("complete/backoff/exhaust = %d/%d/%d, want 0/0/0 (abandoned stale attempt)", len(complete), len(backoff), len(exhaust))
	}
}

// TestTriageWorker_Cancellation: canceling RunOnce's own context propagates
// into Analyze; the resulting failure still gets a durable, classified
// write-back (via a context independent of the canceled one) rather than
// being silently dropped.
func TestTriageWorker_Cancellation(t *testing.T) {
	claim := testClaim("inc-9", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-9"}}
	ctx, cancel := context.WithCancel(context.Background())
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		cancel()
		<-ctx.Done()
		return situation.AcuteResult{}, ctx.Err()
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	_, _ = w.RunOnce(ctx) // may return the ctx error from a later loop check; the single processOne call still completes
	_, complete, backoff, exhaust, _ := store.snapshot()
	if len(complete) != 0 || len(exhaust) != 0 {
		t.Fatalf("complete/exhaust = %d/%d, want 0/0", len(complete), len(exhaust))
	}
	if len(backoff) != 1 {
		t.Fatalf("backoff calls = %d, want 1 (canceled attempt still recorded)", len(backoff))
	}
	if backoff[0].code != "canceled" {
		t.Errorf("backoff code = %q, want canceled", backoff[0].code)
	}
}

// TestTriageWorker_PostCommitFailureIsBestEffort: AfterCommit failing after
// a successful completion must not fail RunOnce or the attempt — the
// durable Finding already committed.
func TestTriageWorker_PostCommitFailureIsBestEffort(t *testing.T) {
	claim := testClaim("inc-10", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-10"}}
	analyzer := &fakeAnalyzer{}
	after := &fakeAfterCommit{fn: func(ctx context.Context, result situation.AcuteResult) error {
		return errors.New("notify unreachable")
	}}
	w := newWorker(store, lister, analyzer, after, situation.TriageWorkerConfig{})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v (post-commit failure must be swallowed)", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1", n)
	}
	if after.callCount() != 1 {
		t.Fatalf("AfterCommit calls = %d, want 1", after.callCount())
	}
}

// TestTriageWorker_CrashRecovery: every RunOnce recovers expired in-flight
// attempts before claiming new work.
func TestTriageWorker_CrashRecovery(t *testing.T) {
	store := &fakeStore{recoverFn: func(ctx context.Context, now time.Time) (int, error) { return 2, nil }}
	lister := &fakeLister{}
	w := newWorker(store, lister, &fakeAnalyzer{}, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	_, _, _, _, recoverCalls := store.snapshot()
	if recoverCalls != 1 {
		t.Fatalf("recover calls = %d, want 1", recoverCalls)
	}
}

// TestTriageWorker_CommittedAttemptNeverAnalyzedAgain: once an attempt
// commits, a stale listing that still names the same incident must not
// trigger a second Analyze call — the worker never analyzes without first
// taking a fresh claim, and a raced-away claim (model.ErrNotFound, as the
// real store returns once a schedule row is gone) is not analyzed at all.
func TestTriageWorker_CommittedAttemptNeverAnalyzedAgain(t *testing.T) {
	claim := testClaim("inc-11", 1)
	claimed := false
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		if !claimed {
			claimed = true
			return claim, nil
		}
		return situation.TriageAttemptClaim{}, model.ErrNotFound
	}}
	lister := &fakeLister{ids: []string{"inc-11"}}
	analyzer := &fakeAnalyzer{}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	n1, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}
	if n1 != 1 {
		t.Fatalf("handled 1 = %d, want 1", n1)
	}
	// Stale listing still names inc-11 (as if a poll raced the schedule's
	// own deletion of the row); the second claim attempt must fail closed —
	// mirroring the pre-Plan-2 dispatch chain's own
	// TestTriageRetrySkipsIncidentThatLeftReady: an incident whose schedule
	// already resolved (deleted, in this new system's case) is never
	// re-dispatched.
	n2, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("handled 2 = %d, want 0 (raced-away claim is not counted as handled)", n2)
	}
	if analyzer.callCount() != 1 {
		t.Fatalf("Analyze calls = %d, want 1 (never re-analyzed after commit)", analyzer.callCount())
	}
}

// TestTriageWorker_ClaimNotDueIsBenign: ClaimIncidentTriageAttempt returning
// ErrTriageAttemptNotDue (the listing ran slightly ahead of the claim's own
// due check) must not analyze, error, or log at error level — a normal,
// expected race.
func TestTriageWorker_ClaimNotDueIsBenign(t *testing.T) {
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return situation.TriageAttemptClaim{}, situation.ErrTriageAttemptNotDue
	}}
	lister := &fakeLister{ids: []string{"inc-not-due"}}
	analyzer := &fakeAnalyzer{}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("handled = %d, want 0", n)
	}
	if analyzer.callCount() != 0 {
		t.Fatalf("Analyze calls = %d, want 0", analyzer.callCount())
	}
}

// TestTriageWorker_ClaimNotDecidedIsBenign: ClaimIncidentTriageAttempt
// returning ErrTriageAttemptNotDecided (a migrated legacy row whose
// controller decision backfill has not run yet, per Task 6) must not
// analyze or fail RunOnce — just skip and move on.
func TestTriageWorker_ClaimNotDecidedIsBenign(t *testing.T) {
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return situation.TriageAttemptClaim{}, situation.ErrTriageAttemptNotDecided
	}}
	lister := &fakeLister{ids: []string{"inc-not-decided"}}
	analyzer := &fakeAnalyzer{}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("handled = %d, want 0", n)
	}
	if analyzer.callCount() != 0 {
		t.Fatalf("Analyze calls = %d, want 0", analyzer.callCount())
	}
}

// TestTriageWorker_BatchLimit proves RunOnce claims at most cfg.Batch due
// incidents per round.
func TestTriageWorker_BatchLimit(t *testing.T) {
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return testClaim(incidentID, 1), nil
	}}
	lister := &fakeLister{ids: []string{"a", "b", "c", "d", "e"}}
	analyzer := &fakeAnalyzer{}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{Batch: 2})

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Fatalf("handled = %d, want 2 (batch limit)", n)
	}
}

// TestTriageWorker_StartWakeStop exercises the background loop lifecycle.
func TestTriageWorker_StartWakeStop(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		mu.Lock()
		defer mu.Unlock()
		if seen[incidentID] {
			return situation.TriageAttemptClaim{}, model.ErrNotFound
		}
		seen[incidentID] = true
		return testClaim(incidentID, 1), nil
	}}
	lister := &fakeLister{ids: []string{"inc-loop"}}
	analyzer := &fakeAnalyzer{}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{Interval: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Wake()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && analyzer.callCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if analyzer.callCount() == 0 {
		t.Fatal("Start/Wake never triggered a claim/analyze")
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
