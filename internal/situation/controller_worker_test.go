// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
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
		extendErr: errors.New("lease lost"),
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

	w := situation.NewControllerWorker(store, store, client, situation.ControllerConfig{}, cfg, nil, nil, nil)

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
	w := situation.NewControllerWorker(store, store, &fakeAssessmentClient{}, situation.ControllerConfig{}, cfg, nil, nil, nil)

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
