// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// --------------------------------------------------------------------------
// Fakes specific to ControllerWorker tests. fakeControllerStore (defined in
// controller_test.go, same package) already satisfies both ControllerStore
// and ControllerWorkStore.
// --------------------------------------------------------------------------

// ctClaimFor builds a fully-fenced situation.Claim for a Situation whose
// deterministic urgent floor (critical severity) is the simplest fixture for
// worker-level tests that care about claim/heartbeat/concurrency behavior,
// not Assessment content — its Reconcile cycle still dispatches (or falls
// back) exactly once per Finding I3's ruling (no prior trustworthy
// Assessment exists), not zero times.
func ctClaimFor(id, owner string, token int64) situation.Claim {
	sit := ctBaseSituation()
	sit.ID = id
	owner2 := owner
	sit.LeaseOwner = &owner2
	sit.ClaimToken = token
	return situation.Claim{Situation: sit, ClaimOwner: owner, ClaimToken: token}
}

func ctFloorSnapshotInput() situation.SnapshotInput {
	in := ctBaseSnapshotInput()
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "critical")}
	return in
}

type fakeWaker struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, now time.Time) (int, error)
}

func (f *fakeWaker) WakeDependencyRecoveredSituations(ctx context.Context, now time.Time) (int, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, now)
	}
	return 0, nil
}

func (f *fakeWaker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newWorkerConfig(owner string) situation.ControllerWorkerConfig {
	return situation.ControllerWorkerConfig{
		Owner: owner, Lease: time.Minute, Interval: 5 * time.Millisecond,
	}
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

func TestControllerWorkerRunOnceClaimsAndReconciles(t *testing.T) {
	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-w1", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
	}
	client := &fakeAssessmentClient{}
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1", n)
	}
	if len(store.snapshotCommits()) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.snapshotCommits()))
	}
	// Finding I3: a deterministic floor no longer short-circuits L2 dispatch
	// (ctFloorSnapshotInput has no prior trustworthy Assessment) — this
	// cycle dispatches exactly once, falling back to DeterministicFallback
	// since fakeAssessmentClient has no scripted response.
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1", client.calls)
	}
}

// TestControllerWorkerSetInferenceLimiterGatesL2ThroughSharedPool proves
// Plan 4 Task 8's own "factor the current L2-only semaphore into the
// shared L0/L2 limiter" wiring actually takes effect: with a
// capacity-1 llm.InferenceLimiter's one slot already held by an external
// (Profile-priority) acquisition, a ControllerWorker wired to that SAME
// limiter via SetInferenceLimiter must have its own L2 dispatch BLOCK
// waiting for it — proving the call genuinely went through the shared pool
// rather than the worker's own private per-instance semaphore (which would
// let it through immediately, unaffected by an external acquisition it has
// never heard of).
func TestControllerWorkerSetInferenceLimiterGatesL2ThroughSharedPool(t *testing.T) {
	limiter := llm.NewInferenceLimiter(1)
	release, err := limiter.Acquire(context.Background(), llm.InferenceProfile)
	if err != nil {
		t.Fatalf("pre-acquire the shared limiter's one slot: %v", err)
	}
	defer release()

	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-limited", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: in, beginWorkAttempt: 1,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
	}
	client := &fakeAssessmentClient{}
	cfg := newWorkerConfig("worker-a")
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{AttemptWall: 50 * time.Millisecond}, cfg, nil, nil, nil)
	w.SetInferenceLimiter(limiter)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// The controller's own AttemptWall (50ms) expired while L2 dispatch was
	// still blocked waiting for the shared limiter's one slot (held by this
	// test the entire time) — CompleteOnce was therefore never actually
	// invoked; RunOnce absorbs the resulting reconcile failure (its own
	// per-Situation error handling, not propagated as a RunOnce error).
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0 (still blocked on the shared limiter)", client.calls)
	}
}

// TestControllerWorkerSetEvidencePreparerWiresThroughToReconcile proves
// Plan 4 Task 9's own preparer pass-through: cmd/alertint only ever holds a
// *ControllerWorker, never the *Controller it builds internally, so
// SetEvidencePreparer must reach the same Controller.SetEvidencePreparer
// seam Task 6's own controller_test.go already proves in isolation.
func TestControllerWorkerSetEvidencePreparerWiresThroughToReconcile(t *testing.T) {
	in := ctBaseSnapshotInput()
	claim := ctClaimFor("situation-preparer", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: in, beginWorkAttempt: 1,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
	}
	client := &fakeAssessmentClient{}
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)
	preparer := &fakeEvidencePreparer{}
	w.SetEvidencePreparer(preparer)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(preparer.calls) == 0 {
		t.Fatal("expected the wired preparer to be invoked during Reconcile")
	}
}

func TestControllerWorkerRunOnceRespectsBoundedBatch(t *testing.T) {
	store := &fakeControllerStore{
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			if limit != 7 {
				t.Errorf("claim limit = %d, want configured batch 7", limit)
			}
			return nil, nil
		},
	}
	client := &fakeAssessmentClient{}
	cfg := newWorkerConfig("worker-a")
	cfg.Batch = 7
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}

// TestControllerWorkerTwoWorkersClaimDisjointSituations proves two
// independent ControllerWorker instances, each backed by its own claim
// function returning disjoint Situation sets (the shape a real database's
// atomic UPDATE...RETURNING claim guarantees), never process the same
// Situation and each commits exactly its own share.
func TestControllerWorkerTwoWorkersClaimDisjointSituations(t *testing.T) {
	inA, inB := ctFloorSnapshotInput(), ctFloorSnapshotInput()
	claimA := ctClaimFor("situation-a", "worker-a", 1)
	claimB := ctClaimFor("situation-b", "worker-b", 1)

	storeA := &fakeControllerStore{
		loadInput: inA,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claimA}, nil
		},
	}
	storeB := &fakeControllerStore{
		loadInput: inB,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claimB}, nil
		},
	}

	wA := situation.NewControllerWorker(storeA, storeA, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)
	wB := situation.NewControllerWorker(storeB, storeB, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-b"), nil, nil, nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = wA.RunOnce(context.Background()) }()
	go func() { defer wg.Done(); _, _ = wB.RunOnce(context.Background()) }()
	wg.Wait()

	commitsA, commitsB := storeA.snapshotCommits(), storeB.snapshotCommits()
	if len(commitsA) != 1 || len(commitsB) != 1 {
		t.Fatalf("commits A/B = %d/%d, want 1/1 (disjoint, each processes only its own claim)", len(commitsA), len(commitsB))
	}
}

func TestControllerWorkerHeartbeatExtendsLeaseDuringSlowReconcile(t *testing.T) {
	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-slow", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		commitFn: func(situation.ControllerCommit) error {
			time.Sleep(120 * time.Millisecond)
			return nil
		},
	}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 20 * time.Millisecond
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, cfg, nil, nil, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := store.snapshotExtendCalls(); got < 2 {
		t.Fatalf("heartbeat extend calls = %d, want >= 2 for a 120ms reconcile at a 20ms heartbeat", got)
	}
}

func TestControllerWorkerLeaseLossCancelsReconcileAndAbandonsWithoutRelease(t *testing.T) {
	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-leaselost", "worker-a", 1)
	commitCanceled := make(chan struct{})
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendErr: model.ErrSituationLeaseLost,
		commitFn: func(situation.ControllerCommit) error {
			// Never actually reached in this scenario (see below); present
			// only so a bug that DOES reach it fails loudly instead of
			// hanging.
			close(commitCanceled)
			return nil
		},
	}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	// A client whose CompleteOnce blocks on the REAL context Reconcile
	// passed it, until that context is canceled by the heartbeat's own
	// lease-loss abandon path — this Situation has no deterministic floor
	// (non-critical severity), so Reconcile must dispatch L2 work and
	// therefore actually calls CompleteOnce, giving the heartbeat loss a
	// real in-flight call to cancel.
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}

	in2 := ctBaseSnapshotInput() // non-critical: no deterministic floor, forces L2 dispatch.
	store.loadInput = in2
	store.beginWorkAttempt = 1

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, logger)

	done := make(chan struct{})
	go func() {
		_, _ = w.RunOnce(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunOnce never returned after lease loss")
	}

	select {
	case <-commitCanceled:
		t.Fatal("CommitController must never be reached after the lease was lost mid-reconcile")
	case <-time.After(50 * time.Millisecond):
	}
	if len(store.snapshotReleaseCalls()) != 0 {
		t.Fatal("a lease already lost mid-reconcile must not be independently released — the abandon path owns it")
	}
	lines := jsonLogLines(t, &buf)
	reconciles := linesWithMsg(lines, "situation: controller reconcile")
	if len(reconciles) != 1 || reconciles[0]["result_class"] != "superseded" {
		t.Fatalf("reconcile lines = %v, want one superseded result", reconciles)
	}
	for _, line := range lines {
		if line["level"] == "WARN" {
			t.Fatalf("superseded heartbeat emitted warning: %v", line)
		}
	}
}

func TestControllerWorkerPreemptCancelsOnlyMatchingClaim(t *testing.T) {
	claim := ctClaimFor("situation-preempt", "worker-a", 7)
	expires := time.Now().UTC().Add(time.Minute)
	claim.Situation.LeaseExpiresAt = &expires
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
	}
	inCall := make(chan struct{})
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		close(inCall)
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}
	var logs bytes.Buffer
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil,
		slog.New(slog.NewJSONHandler(&logs, nil)))
	done := make(chan error, 1)
	go func() {
		_, err := w.RunOnce(context.Background())
		done <- err
	}()
	select {
	case <-inCall:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not reach L2")
	}

	w.Preempt(claim.Situation.ID, claim.ClaimToken+1)
	w.Preempt("unknown-situation", claim.ClaimToken)
	select {
	case err := <-done:
		t.Fatalf("stale or unknown preempt ended reconcile: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	w.Preempt(claim.Situation.ID, claim.ClaimToken)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("matching preempt did not cancel blocked reconcile promptly")
	}
	if calls := store.snapshotReleaseCalls(); len(calls) != 0 {
		t.Fatalf("release after preempt = %+v, want none", calls)
	}
	if got := linesWithMsg(jsonLogLines(t, &logs), "situation: controller reconcile"); len(got) != 1 || got[0]["result_class"] != "superseded" {
		t.Fatalf("reconcile result = %v, want one superseded", got)
	}
	if n := reflect.ValueOf(w).Elem().FieldByName("inflight").Len(); n != 0 {
		t.Fatalf("in-flight registry after RunOnce = %d, want empty", n)
	}
}

func TestControllerWorkerSupersededCommitDoesNotRelease(t *testing.T) {
	claim := ctClaimFor("situation-superseded", "worker-a", 1)
	expires := time.Now().UTC().Add(time.Minute)
	claim.Situation.LeaseExpiresAt = &expires
	store := &fakeControllerStore{
		loadInput: ctFloorSnapshotInput(), commitErr: model.ErrSituationLeaseLost,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, logger)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := store.snapshotReleaseCalls(); len(got) != 0 {
		t.Fatalf("release calls = %+v, want none for a lost claim", got)
	}
	lines := jsonLogLines(t, &buf)
	if got := linesWithMsg(lines, "situation: controller worker: reconcile failed"); len(got) != 0 {
		t.Fatalf("failure warnings = %v, want none", got)
	}
	if got := linesWithMsg(lines, "situation: controller reconcile"); len(got) != 1 || got[0]["result_class"] != "superseded" {
		t.Fatalf("reconcile lines = %v, want one superseded result", got)
	}
}

func TestControllerWorkerHeartbeatRetriesTransientExtendError(t *testing.T) {
	claim := ctClaimFor("situation-retry", "worker-a", 1)
	expires := time.Now().UTC().Add(300 * time.Millisecond)
	claim.Situation.LeaseExpiresAt = &expires
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendFn: func(_ context.Context, call int) error {
			if call == 1 {
				return errors.New("database is locked")
			}
			return nil
		},
	}
	accepted := acceptedResponse(t)
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		select {
		case <-time.After(70 * time.Millisecond):
			return accepted()
		case <-ctx.Done():
			return llm.OneShotCompletion{}, ctx.Err()
		}
	}}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	cfg.Lease = 300 * time.Millisecond
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := len(store.snapshotCommits()); got != 1 {
		t.Fatalf("commits = %d, want one after transient extend failure", got)
	}
	if got := store.snapshotExtendCalls(); got < 2 {
		t.Fatalf("extends = %d, want retry", got)
	}
	if got := store.snapshotReleaseCalls(); len(got) != 0 {
		t.Fatalf("release calls = %+v, want none", got)
	}
}

func TestControllerWorkerHeartbeatCancelsBeforeLeaseLapses(t *testing.T) {
	claim := ctClaimFor("situation-unconfirmed", "worker-a", 1)
	expires := time.Now().UTC().Add(50 * time.Millisecond)
	claim.Situation.LeaseExpiresAt = &expires
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendErr: errors.New("database is locked"),
	}
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	cfg.Lease = 50 * time.Millisecond
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunOnce stopped on parent deadline: %v", ctx.Err())
	}
	lines := linesWithMsg(jsonLogLines(t, &buf), "situation: controller reconcile")
	if len(lines) != 1 || lines[0]["result_class"] == "committed" || lines[0]["result_class"] == "superseded" {
		t.Fatalf("reconcile lines = %v, want a real failure", lines)
	}
	if got := store.snapshotExtendCalls(); got < 2 {
		t.Fatalf("extends = %d, want retry before cancellation", got)
	}
	releases := store.snapshotReleaseCalls()
	if len(releases) != 1 || releases[0].RetryAt == nil {
		t.Fatalf("release calls = %+v, want one with backoff", releases)
	}
}

func TestControllerWorkerHeartbeatWithoutLeaseExpiryHasNoRetryBudget(t *testing.T) {
	claim := ctClaimFor("situation-no-expiry", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendErr: errors.New("database is locked"),
	}
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunOnce stopped on parent deadline: %v", ctx.Err())
	}
	if got := store.snapshotExtendCalls(); got != 1 {
		t.Fatalf("extends = %d, want cancellation on first failure without expiry", got)
	}
	if got := store.snapshotReleaseCalls(); len(got) != 1 {
		t.Fatalf("release calls = %+v, want one", got)
	}
}

func TestControllerWorkerHeartbeatBatchWaitedClaimHasReducedBudget(t *testing.T) {
	claim := ctClaimFor("situation-waited", "worker-a", 1)
	expires := time.Now().UTC().Add(15 * time.Millisecond)
	claim.Situation.LeaseExpiresAt = &expires
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendErr: errors.New("database is locked"),
	}
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunOnce stopped on parent deadline: %v", ctx.Err())
	}
	if got := store.snapshotExtendCalls(); got != 1 {
		t.Fatalf("extends = %d, want one failed renewal for waited claim", got)
	}
	if got := store.snapshotReleaseCalls(); len(got) != 1 {
		t.Fatalf("release calls = %+v, want one", got)
	}
}

func TestControllerWorkerHeartbeatExtendBoundedByRemainingLease(t *testing.T) {
	type renewalContextKey struct{}
	claim := ctClaimFor("situation-bound", "worker-a", 1)
	expires := time.Now().UTC().Add(50 * time.Millisecond)
	claim.Situation.LeaseExpiresAt = &expires
	var sawDeadline time.Time
	var sawContextValue any
	store := &fakeControllerStore{
		loadInput: ctBaseSnapshotInput(), beginWorkAttempt: 1,
		claimFn: func(context.Context, string, time.Time, time.Duration, int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		extendFn: func(ctx context.Context, _ int) error {
			sawDeadline, _ = ctx.Deadline()
			sawContextValue = ctx.Value(renewalContextKey{})
			<-ctx.Done()
			return ctx.Err()
		},
	}
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	}}
	cfg := newWorkerConfig("worker-a")
	cfg.Heartbeat = 10 * time.Millisecond
	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), renewalContextKey{}, "trace-context"), 2*time.Second)
	defer cancel()
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunOnce stopped on parent deadline: %v", ctx.Err())
	}
	if sawDeadline.IsZero() || sawDeadline.After(expires) {
		t.Fatalf("extend deadline = %v, want no later than lease expiry %v", sawDeadline, expires)
	}
	if sawContextValue != "trace-context" {
		t.Fatalf("extend context value = %v, want trace-context", sawContextValue)
	}
}

func TestControllerWorkerReleasesOnReconcileFailure(t *testing.T) {
	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-fail", "worker-a", 1)
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return []situation.Claim{claim}, nil
		},
		commitErr: errors.New("commit failed"),
	}
	cfg := newWorkerConfig("worker-a")
	fixedNow := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return fixedNow }
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	audit := &fakeAuditSink{}
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, cfg, nil, audit, logger)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	releases := store.snapshotReleaseCalls()
	if len(releases) != 1 || releases[0].Claim.Situation.ID != claim.Situation.ID {
		t.Fatalf("release calls = %+v, want exactly one release of %s", releases, claim.Situation.ID)
	}
	// Finding I2: the release must carry a bounded backoff, not an instant
	// re-claim — a persistently-failing Situation would otherwise spin
	// Drain at 100% CPU (see TestControllerWorkerDrainTerminatesWhenReconcileAlwaysFails).
	if releases[0].RetryAt == nil {
		t.Fatal("release after a failed Reconcile must carry a backoff RetryAt, not release with no checkpoint pushed forward")
	}
	if !releases[0].RetryAt.After(fixedNow) {
		t.Fatalf("release RetryAt = %v, want strictly after now = %v", releases[0].RetryAt, fixedNow)
	}
	if releases[0].ErrorClass == nil || *releases[0].ErrorClass == "" {
		t.Fatal("release after a failed Reconcile must record a bounded error class")
	}
	if !audit.has("situation.controller.commit_failed") {
		t.Fatalf("audit kinds = %v, want commit_failed for a genuine store failure", audit.kinds)
	}
	if got := linesWithMsg(jsonLogLines(t, &buf), "situation: controller commit failed"); len(got) != 1 || got[0]["level"] != "WARN" {
		t.Fatalf("commit failure lines = %v, want one WARN", got)
	}
}

// TestControllerWorkerDrainTerminatesWhenReconcileAlwaysFails proves Finding
// I2's core claim: a persistently-failing Situation does not spin Drain
// forever. claimFn simulates a real store's own "next_assessment_at <= now"
// due filter — after the first (failing) round, it only returns the
// Situation again if the recorded release carried no backoff, mirroring
// exactly what a real ClaimDueSituations would do once processOne's release
// has pushed next_assessment_at into the future.
func TestControllerWorkerDrainTerminatesWhenReconcileAlwaysFails(t *testing.T) {
	in := ctFloorSnapshotInput()
	claim := ctClaimFor("situation-alwaysfail", "worker-a", 1)

	var store *fakeControllerStore
	rounds := 0
	store = &fakeControllerStore{
		loadInput: in,
		commitErr: errors.New("commit always fails"),
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			rounds++
			if rounds == 1 {
				return []situation.Claim{claim}, nil
			}
			// Read store.releaseCalls directly (not via snapshotReleaseCalls,
			// which would re-lock store.mu — this closure already runs while
			// ClaimControllerWork holds it): no concurrent writer can be
			// touching it right now either way, since Drain's rounds are
			// strictly sequential (RunOnce fully completes, including every
			// release, before the next round's claim call runs).
			if len(store.releaseCalls) == 0 || store.releaseCalls[len(store.releaseCalls)-1].RetryAt == nil {
				t.Fatalf("round %d: claiming again without a recorded backoff from the prior round's release", rounds)
			}
			// A real store would see next_assessment_at pushed into the
			// future by the backoff and simply not return this row again.
			return nil, nil
		},
	}
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)

	total, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if total != 1 {
		t.Fatalf("Drain total = %d, want 1 (bounded — must not spin reclaiming the same always-failing situation)", total)
	}
	if rounds != 2 {
		t.Fatalf("claim rounds = %d, want 2 (one failing round, one empty round that stops Drain)", rounds)
	}
}

func TestControllerWorkerDrainProcessesOnlyWorkDueNow(t *testing.T) {
	in := ctFloorSnapshotInput()
	var round int
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			round++
			switch round {
			case 1:
				return []situation.Claim{ctClaimFor("situation-d1", "worker-a", 1)}, nil
			case 2:
				return []situation.Claim{ctClaimFor("situation-d2", "worker-a", 1)}, nil
			default:
				return nil, nil // caught up: nothing else due now.
			}
		},
	}
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)

	total, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if total != 2 {
		t.Fatalf("Drain total = %d, want 2", total)
	}
	if round != 3 {
		t.Fatalf("claim rounds = %d, want 3 (two due rounds plus the empty round that stops Drain)", round)
	}
}

func TestControllerWorkerStartWakeStop(t *testing.T) {
	in := ctFloorSnapshotInput()
	var claimed atomic.Int32
	var claimedThisRound atomic.Bool
	store := &fakeControllerStore{
		loadInput: in,
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			// One claim per Drain round (Start's initial pass, and each
			// Wake()), then empty — so Drain terminates and run()'s select
			// reaches stopCh/ticker/wakeCh instead of looping forever.
			if claimedThisRound.Swap(true) {
				claimedThisRound.Store(false) // reset for the next Drain round (next tick/Wake).
				return nil, nil
			}
			n := claimed.Add(1)
			return []situation.Claim{ctClaimFor("situation-swp", "worker-a", int64(n))}, nil
		},
	}
	cfg := newWorkerConfig("worker-a")
	cfg.Interval = time.Hour // only Wake()/the initial Drain should trigger rounds within this test's timeout.
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, cfg, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	waitForAtLeast(t, claimed.Load, 1, time.Second)
	w.Wake()
	waitForAtLeast(t, claimed.Load, 2, time.Second)

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestControllerWorkerDependencyRecoveryWakerCalledBeforeClaim(t *testing.T) {
	store := &fakeControllerStore{
		claimFn: func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
			return nil, nil
		},
	}
	waker := &fakeWaker{}
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, newWorkerConfig("worker-a"), nil, nil, nil)
	w.SetDependencyRecoveryWaker(waker)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if waker.callCount() != 1 {
		t.Fatalf("waker calls = %d, want 1", waker.callCount())
	}
}

// waitForAtLeast polls get() until it reaches at least want or timeout
// elapses.
func waitForAtLeast(t *testing.T, get func() int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if get() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("value never reached %d within %v (got %d)", want, timeout, get())
}
