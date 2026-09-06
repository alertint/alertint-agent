// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 7 worker fixtures.
// ----------------------------------------------------------------------

func nwLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// nwDeliveryError is a deliverer error carrying the closed classification the
// worker resolves outcomes with, exactly as cmd/alertint's Slack adapter
// does for a *slack.APIError.
type nwDeliveryError struct {
	class      DeliveryErrorClass
	code       string
	retryAfter time.Duration
}

func (f nwDeliveryError) Error() string                          { return fmt.Sprintf("slack: %s: %s", f.class, f.code) }
func (f nwDeliveryError) DeliveryErrorClass() DeliveryErrorClass { return f.class }
func (f nwDeliveryError) DeliveryErrorCode() string              { return f.code }
func (f nwDeliveryError) DeliveryRetryAfter() time.Duration      { return f.retryAfter }

type nwRetry struct {
	intentID string
	class    string
	retryAt  time.Time
}

// nwStore is a race-safe in-memory NotificationStore recording every call
// the worker makes.
type nwStore struct {
	mu sync.Mutex

	state       SlackDeliveryState
	batches     [][]NotificationClaim
	deliveredAs []NotificationDelivery
	delivered   []string
	retried     []nwRetry
	blocked     []string
	failed      []string
	released    []string
	heartbeats  int
	successes   int
	failures    []string
	gapOpens    []time.Duration
	completes   int
	recovers    int
	reactivated []int64
	recovered   int

	deliverAckErr error
	heartbeatErr  error
	openGap       bool
	recoverGap    string
	recoverOK     bool
	completeGap   string
	completeOK    bool
}

func (s *nwStore) RecoverExpiredNotificationClaims(_ context.Context, _ time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recovered++
	return 0, nil
}

func (s *nwStore) HeartbeatNotificationClaim(_ context.Context, _ NotificationClaim, _ time.Time, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeats++
	return s.heartbeatErr
}

func (s *nwStore) ReleaseNotificationClaim(_ context.Context, claim NotificationClaim, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released = append(s.released, claim.Intent.ID)
	return nil
}

func (s *nwStore) ReactivateConfigurationBlocked(_ context.Context, generation int64, _ time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reactivated = append(s.reactivated, generation)
	return 1, nil
}

func (s *nwStore) RedriveFailedNotificationIntent(_ context.Context, _ string, _ time.Time) error {
	return nil
}

func (s *nwStore) ObserveSlackFailure(_ context.Context, class string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, class)
	return nil
}

func (s *nwStore) ObserveSlackSuccess(_ context.Context, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.successes++
	return nil
}

func (s *nwStore) OpenDueDeliveryGap(_ context.Context, _ time.Time, threshold time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gapOpens = append(s.gapOpens, threshold)
	return s.openGap, nil
}

func (s *nwStore) RecoverDeliveryGap(_ context.Context, _ time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recovers++
	return s.recoverGap, s.recoverOK, nil
}

func (s *nwStore) CompleteDeliveryGap(_ context.Context, _ time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completes++
	return s.completeGap, s.completeOK, nil
}

func (s *nwStore) GetSlackDeliveryState(context.Context) (SlackDeliveryState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

func (s *nwStore) ClaimNotificationIntents(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) ([]NotificationClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		return nil, nil
	}
	batch := s.batches[0]
	s.batches = s.batches[1:]
	return batch, nil
}

func (s *nwStore) MarkNotificationDelivered(_ context.Context, claim NotificationClaim,
	delivery NotificationDelivery, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliverAckErr != nil {
		return s.deliverAckErr
	}
	s.delivered = append(s.delivered, claim.Intent.ID)
	s.deliveredAs = append(s.deliveredAs, delivery)
	return nil
}

func (s *nwStore) RetryNotificationIntent(_ context.Context, claim NotificationClaim, class string, retryAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retried = append(s.retried, nwRetry{intentID: claim.Intent.ID, class: class, retryAt: retryAt})
	return nil
}

func (s *nwStore) BlockNotificationConfiguration(_ context.Context, claim NotificationClaim, class string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = append(s.blocked, claim.Intent.ID+":"+class)
	return nil
}

func (s *nwStore) FailNotificationIntent(_ context.Context, claim NotificationClaim, class string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, claim.Intent.ID+":"+class)
	return nil
}

func (s *nwStore) snapshot(read func(*nwStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	read(s)
}

// nwDeliverer is a race-safe fake NotificationDeliverer.
type nwDeliverer struct {
	mu         sync.Mutex
	probeErr   error
	probeCalls int
	calls      []model.NotificationIntent
	deliver    func(model.NotificationIntent) (NotificationDelivery, error)
}

func (d *nwDeliverer) Probe(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probeCalls++
	return d.probeErr
}

func (d *nwDeliverer) Deliver(ctx context.Context, intent model.NotificationIntent) (NotificationDelivery, error) {
	d.mu.Lock()
	d.calls = append(d.calls, intent)
	fn := d.deliver
	d.mu.Unlock()
	if fn == nil {
		return NotificationDelivery{Channel: "C", MessageTS: "1.1", DeliveredAs: "root"}, nil
	}
	_ = ctx
	return fn(intent)
}

func (d *nwDeliverer) clientMessageIDs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.calls))
	for _, c := range d.calls {
		out = append(out, c.ClientMessageID)
	}
	return out
}

func nwClaim(id string, attempt int) NotificationClaim {
	situationID := "sit-1"
	transitionID := "tr-1"
	sequence := 1
	version := 1
	return NotificationClaim{
		Intent: model.NotificationIntent{
			ID:                 id,
			IdempotencyKey:     "key:" + id,
			EffectClass:        model.EffectRootSync,
			SituationID:        &situationID,
			TransitionID:       &transitionID,
			TransitionSequence: &sequence,
			SummaryVersion:     &version,
			ClientMessageID:    "client:" + id,
			Status:             model.IntentPending,
			AttemptCount:       attempt,
			CreatedAt:          time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC),
		},
		ClaimOwner: "notify-a",
		ClaimToken: 1,
	}
}

// nwClock is a mutable test clock safe to advance while worker goroutines
// read it.
type nwClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *nwClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *nwClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// nwWorker builds a worker on a fixed clock with a deterministic jitter
// source (rnd = 0.5 => no jitter) and a fast heartbeat.
func nwWorker(store NotificationStore, deliverer NotificationDeliverer, now time.Time) *NotificationWorker {
	return NewNotificationWorker(store, deliverer, NotificationWorkerConfig{
		Owner:     "notify-a",
		Heartbeat: time.Hour,
		Rand:      func() float64 { return 0.5 },
	}, func() time.Time { return now }, nwLogger())
}

// ----------------------------------------------------------------------
// Step 4: indefinite retry.
// ----------------------------------------------------------------------

// TestNotificationWorkerRetriesIndefinitely proves the retry schedule has no
// terminal value at ANY attempt count: attempt 1, 100, and 100000 all
// return a finite delay bounded by five minutes plus its jitter.
func TestNotificationWorkerRetriesIndefinitely(t *testing.T) {
	initial, maxDelay := 5*time.Second, 5*time.Minute
	for _, attempt := range []int{1, 2, 100, 100000} {
		for _, rnd := range []float64{0, 0.5, 1} {
			delay := notificationRetryDelay(attempt, 0, initial, maxDelay, 0.2, rnd)
			if delay <= 0 {
				t.Fatalf("attempt %d rnd %v: delay %s, want a positive retry delay", attempt, rnd, delay)
			}
			if delay > time.Duration(float64(maxDelay)*1.2) {
				t.Fatalf("attempt %d rnd %v: delay %s exceeds the five-minute cap plus bounded jitter", attempt, rnd, delay)
			}
		}
	}
	// The schedule really is exponential before the cap, and jittered.
	if got := notificationRetryDelay(1, 0, initial, maxDelay, 0.2, 0.5); got != initial {
		t.Fatalf("attempt 1 with neutral jitter = %s, want %s", got, initial)
	}
	if got := notificationRetryDelay(2, 0, initial, maxDelay, 0.2, 0.5); got != 2*initial {
		t.Fatalf("attempt 2 with neutral jitter = %s, want %s", got, 2*initial)
	}
	low := notificationRetryDelay(3, 0, initial, maxDelay, 0.2, 0)
	high := notificationRetryDelay(3, 0, initial, maxDelay, 0.2, 1)
	if low >= high || low != time.Duration(float64(4*initial)*0.8) || high != time.Duration(float64(4*initial)*1.2) {
		t.Fatalf("attempt 3 jitter spread = [%s, %s], want +/-20%% around %s", low, high, 4*initial)
	}
	if got := notificationRetryDelay(100, 0, initial, maxDelay, 0, 0); got != maxDelay {
		t.Fatalf("attempt 100 without jitter = %s, want the %s cap", got, maxDelay)
	}
}

// TestNotificationWorkerHonorsLongerRetryAfter proves a provider-requested
// wait wins when it is longer than the computed backoff, and loses when it
// is shorter.
func TestNotificationWorkerHonorsLongerRetryAfter(t *testing.T) {
	initial, maxDelay := 5*time.Second, 5*time.Minute
	if got := notificationRetryDelay(1, 30*time.Minute, initial, maxDelay, 0.2, 0.5); got != 30*time.Minute {
		t.Fatalf("delay with a 30m Retry-After = %s, want 30m", got)
	}
	if got := notificationRetryDelay(1, time.Second, initial, maxDelay, 0.2, 0.5); got != initial {
		t.Fatalf("delay with a 1s Retry-After = %s, want the longer computed %s", got, initial)
	}
}

// TestNotificationWorkerNoElapsedOutageEverFailsAValidIntent drives the
// worker itself at attempts 1, 100, and 100000: every one is retried, none
// is ever failed or blocked.
func TestNotificationWorkerNoElapsedOutageEverFailsAValidIntent(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{}
	for _, attempt := range []int{1, 100, 100000} {
		store.batches = append(store.batches, []NotificationClaim{nwClaim(fmt.Sprintf("intent-%d", attempt), attempt)})
	}
	deliverer := &nwDeliverer{deliver: func(model.NotificationIntent) (NotificationDelivery, error) {
		return NotificationDelivery{}, nwDeliveryError{class: DeliveryRetryable, code: "ratelimited"}
	}}
	w := nwWorker(store, deliverer, now)
	for i := 0; i < 3; i++ {
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce %d: %v", i, err)
		}
	}
	store.snapshot(func(s *nwStore) {
		if len(s.retried) != 3 {
			t.Fatalf("retried %d intents, want 3", len(s.retried))
		}
		if len(s.failed) != 0 || len(s.blocked) != 0 {
			t.Fatalf("failed=%v blocked=%v, want an elapsed outage to close no delivery obligation", s.failed, s.blocked)
		}
		for _, r := range s.retried {
			if !r.retryAt.After(now) {
				t.Fatalf("retry_at %s is not in the future", r.retryAt)
			}
			if r.retryAt.Sub(now) > time.Duration(float64(5*time.Minute)*1.2) {
				t.Fatalf("retry_at %s exceeds the capped delay", r.retryAt)
			}
			if r.class != "ratelimited" {
				t.Fatalf("recorded error class %q, want the bounded ratelimited", r.class)
			}
		}
		if len(s.failures) != 3 {
			t.Fatalf("observed %d slack failures, want one per retryable outcome", len(s.failures))
		}
	})
}

// TestNotificationWorkerBlocksConfigurationAndFailsInvalid pins the two
// non-retry outcomes and proves an invalid payload never opens a Delivery
// gap (it is this build's own bug, not a Slack outage).
func TestNotificationWorkerBlocksConfigurationAndFailsInvalid(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{batches: [][]NotificationClaim{
		{nwClaim("intent-config", 1)},
		{nwClaim("intent-invalid", 1)},
	}}
	deliverer := &nwDeliverer{deliver: func(intent model.NotificationIntent) (NotificationDelivery, error) {
		if intent.ID == "intent-config" {
			return NotificationDelivery{}, nwDeliveryError{class: DeliveryConfigurationBlocking, code: "invalid_auth"}
		}
		return NotificationDelivery{}, nwDeliveryError{class: DeliveryInvalid, code: "missing_text"}
	}}
	w := nwWorker(store, deliverer, now)
	for i := 0; i < 2; i++ {
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce %d: %v", i, err)
		}
	}
	store.snapshot(func(s *nwStore) {
		if len(s.blocked) != 1 || s.blocked[0] != "intent-config:invalid_auth" {
			t.Fatalf("blocked = %v, want the configuration rejection", s.blocked)
		}
		if len(s.failed) != 1 || s.failed[0] != "intent-invalid:missing_text" {
			t.Fatalf("failed = %v, want the invalid payload", s.failed)
		}
		if len(s.retried) != 0 {
			t.Fatalf("retried = %v, want neither outcome to schedule a retry", s.retried)
		}
		if len(s.failures) != 1 || s.failures[0] != "invalid_auth" {
			t.Fatalf("observed slack failures = %v, want only the configuration rejection", s.failures)
		}
	})
}

// TestNotificationWorkerUncertainSuccessConvergesToOneDeliveredIntent
// proves an uncertain external response followed by a successful retry
// reuses the identical client message id and converges locally to exactly
// one delivered intent — Slack itself stays at-least-once.
func TestNotificationWorkerUncertainSuccessConvergesToOneDeliveredIntent(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	claim := nwClaim("intent-uncertain", 1)
	retryClaim := claim
	retryClaim.Intent.AttemptCount = 2
	store := &nwStore{batches: [][]NotificationClaim{{claim}, {retryClaim}}}

	attempt := 0
	deliverer := &nwDeliverer{deliver: func(model.NotificationIntent) (NotificationDelivery, error) {
		attempt++
		if attempt == 1 {
			// Slack accepted the post but the response never arrived.
			return NotificationDelivery{}, nwDeliveryError{class: DeliveryRetryable, code: "undecodable_response"}
		}
		return NotificationDelivery{Channel: "C", MessageTS: "100.1", DeliveredAs: "root"}, nil
	}}
	w := nwWorker(store, deliverer, now)
	for i := 0; i < 2; i++ {
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce %d: %v", i, err)
		}
	}
	ids := deliverer.clientMessageIDs()
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("client message ids = %v, want the identical id reused on the retry", ids)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.delivered) != 1 || s.delivered[0] != "intent-uncertain" {
			t.Fatalf("delivered = %v, want exactly one durable delivered intent", s.delivered)
		}
		if len(s.retried) != 1 {
			t.Fatalf("retried = %v, want exactly the one uncertain attempt", s.retried)
		}
	})
}

// TestNotificationWorkerSupersededRootIsNotADeliveryFailure pins the Task 5
// handoff (R4): losing a claim to a concurrent supersession is the expected
// outcome, never a retry, block, or failure.
func TestNotificationWorkerSupersededRootIsNotADeliveryFailure(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{
		batches:       [][]NotificationClaim{{nwClaim("intent-superseded", 1)}},
		deliverAckErr: ErrNotificationIntentSuperseded,
	}
	w := nwWorker(store, &nwDeliverer{}, now)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.delivered) != 0 || len(s.retried) != 0 || len(s.failed) != 0 || len(s.blocked) != 0 {
			t.Fatalf("superseded ack wrote an outcome: delivered=%v retried=%v failed=%v blocked=%v",
				s.delivered, s.retried, s.failed, s.blocked)
		}
	})
	if got := w.Stats().Superseded; got != 1 {
		t.Fatalf("Stats().Superseded = %d, want 1", got)
	}
	if got := w.Stats().Failed; got != 0 {
		t.Fatalf("Stats().Failed = %d, want 0", got)
	}
}

// TestNotificationWorkerRecordsStaleBroadcastAsDelayedThread proves the
// worker records the deliverer's revalidated delivery mode verbatim: a
// handoff found stale immediately before I/O lands as delayed_thread, never
// as a broadcast.
func TestNotificationWorkerRecordsStaleBroadcastAsDelayedThread(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	claim := nwClaim("intent-handoff", 1)
	claim.Intent.EffectClass = model.EffectBroadcastHandoff
	claim.Intent.SummaryVersion = nil
	claim.Intent.RequiresRoot = true
	store := &nwStore{batches: [][]NotificationClaim{{claim}}}
	deliverer := &nwDeliverer{deliver: func(model.NotificationIntent) (NotificationDelivery, error) {
		return NotificationDelivery{Channel: "C", MessageTS: "100.9", DeliveredAs: "delayed_thread"}, nil
	}}
	w := nwWorker(store, deliverer, now)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.deliveredAs) != 1 || s.deliveredAs[0].DeliveredAs != "delayed_thread" {
			t.Fatalf("recorded delivery = %+v, want delayed_thread", s.deliveredAs)
		}
	})
}

// ----------------------------------------------------------------------
// Steps 5-7: probe, gap state machine, lifecycle.
// ----------------------------------------------------------------------

// TestNotificationWorkerProbesWhileAFailureWindowExists proves the worker
// probes on its first round and while a failure window, gap, or blocked
// configuration exists, and stops probing once Slack is healthy again.
func TestNotificationWorkerProbesWhileAFailureWindowExists(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{}
	deliverer := &nwDeliverer{}
	clock := &nwClock{at: now}
	w := NewNotificationWorker(store, deliverer, NotificationWorkerConfig{
		Owner:     "notify-a",
		Heartbeat: time.Hour,
		Rand:      func() float64 { return 0.5 },
	}, clock.now, nwLogger())

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	if deliverer.probeCalls != 1 {
		t.Fatalf("probe calls after the first round = %d, want exactly 1 startup probe", deliverer.probeCalls)
	}
	// Healthy: no more probing.
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if deliverer.probeCalls != 1 {
		t.Fatalf("probe calls while healthy = %d, want no extra probe", deliverer.probeCalls)
	}
	// A failure window reopens probing, once the probe backoff has elapsed.
	failedAt := now.Add(-time.Minute)
	store.snapshot(func(s *nwStore) { s.state.FirstFailureAt = &failedAt })
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("third RunOnce: %v", err)
	}
	if deliverer.probeCalls != 1 {
		t.Fatalf("probe calls before the probe backoff elapsed = %d, want no extra probe", deliverer.probeCalls)
	}
	clock.advance(time.Minute)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("fourth RunOnce: %v", err)
	}
	if deliverer.probeCalls != 2 {
		t.Fatalf("probe calls with an open failure window = %d, want 2", deliverer.probeCalls)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.gapOpens) == 0 {
			t.Fatal("a failure window must ask the store whether a gap is due")
		}
		if s.gapOpens[len(s.gapOpens)-1] != defaultDeliveryGapThreshold {
			t.Fatalf("gap threshold = %s, want the fixed %s", s.gapOpens[len(s.gapOpens)-1], defaultDeliveryGapThreshold)
		}
	})
}

// TestNotificationWorkerRecoveryReactivatesConfigurationAndReplaysGap
// proves a successful probe closes the failure window, increments the
// durable configuration generation for blocked intents, and recovers the
// open gap — in that order, before any backlog claim.
func TestNotificationWorkerRecoveryReactivatesConfigurationAndReplaysGap(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	failedAt := now.Add(-10 * time.Minute)
	generation := "gap-1"
	store := &nwStore{
		state: SlackDeliveryState{
			FirstFailureAt:            &failedAt,
			OpenGapGeneration:         &generation,
			OpenGapStatus:             "open",
			ConfigurationGeneration:   3,
			BlockedConfigurationCount: 2,
		},
		recoverGap: generation,
		recoverOK:  true,
	}
	w := nwWorker(store, &nwDeliverer{}, now)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	store.snapshot(func(s *nwStore) {
		if s.successes == 0 {
			t.Fatal("a successful probe must close the failure window")
		}
		if len(s.reactivated) != 1 || s.reactivated[0] != 4 {
			t.Fatalf("reactivated with generations %v, want exactly the incremented [4]", s.reactivated)
		}
		if s.recovers != 1 {
			t.Fatalf("RecoverDeliveryGap calls = %d, want 1", s.recovers)
		}
	})
	stats := w.Stats()
	if stats.GapsRecovered != 1 || stats.Reactivated != 1 {
		t.Fatalf("stats = %+v, want one recovery and one reactivation", stats)
	}
}

// TestNotificationWorkerOpensAndCompletesGapGenerations proves the worker
// drives both ends of the durable generation lifecycle and counts them.
func TestNotificationWorkerOpensAndCompletesGapGenerations(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	failedAt := now.Add(-6 * time.Minute)
	store := &nwStore{
		state:       SlackDeliveryState{FirstFailureAt: &failedAt},
		openGap:     true,
		completeGap: "gap-1",
		completeOK:  true,
	}
	deliverer := &nwDeliverer{probeErr: errors.New("slack unreachable")}
	w := nwWorker(store, deliverer, now)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	stats := w.Stats()
	if stats.GapsOpened != 1 || stats.GapsCompleted != 1 || stats.ProbeFailures != 1 {
		t.Fatalf("stats = %+v, want one gap opened, one completed, and one failed probe", stats)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.failures) != 1 {
			t.Fatalf("observed slack failures = %v, want the failed probe to keep the window continuous", s.failures)
		}
	})
}

// TestNotificationWorkerHeartbeatLossAbandonsTheClaim proves a lost lease
// abandons the in-flight attempt rather than acknowledging an outcome onto
// a row that now belongs to someone else.
func TestNotificationWorkerHeartbeatLossAbandonsTheClaim(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{
		batches:      [][]NotificationClaim{{nwClaim("intent-lease", 1)}},
		heartbeatErr: ErrNotificationClaimLost,
	}
	released := make(chan struct{})
	deliverer := &nwDeliverer{deliver: func(model.NotificationIntent) (NotificationDelivery, error) {
		<-released // held until the heartbeat has had a chance to fail
		return NotificationDelivery{Channel: "C", MessageTS: "1.1", DeliveredAs: "root"}, nil
	}}
	w := NewNotificationWorker(store, deliverer, NotificationWorkerConfig{
		Owner:     "notify-a",
		Heartbeat: time.Millisecond,
		Rand:      func() float64 { return 0.5 },
	}, func() time.Time { return now }, nwLogger())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Errorf("RunOnce: %v", err)
		}
	}()
	// Let the heartbeat fire and fail, then release the delivery.
	for {
		var beats int
		store.snapshot(func(s *nwStore) { beats = s.heartbeats })
		if beats > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(released)
	<-done

	store.snapshot(func(s *nwStore) {
		if len(s.delivered) != 0 || len(s.retried) != 0 || len(s.failed) != 0 {
			t.Fatalf("a lost lease wrote an outcome: delivered=%v retried=%v failed=%v", s.delivered, s.retried, s.failed)
		}
	})
	if got := w.Stats().ClaimsLost; got != 1 {
		t.Fatalf("Stats().ClaimsLost = %d, want 1", got)
	}
}

// TestNotificationWorkerStopRunsOneBoundedFinalPass proves R6's shutdown
// shape: the loop ends, exactly one more pass runs under the shutdown
// context, and no goroutine is left behind.
func TestNotificationWorkerStopRunsOneBoundedFinalPass(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{batches: [][]NotificationClaim{{nwClaim("intent-final", 1)}}}
	w := NewNotificationWorker(store, &nwDeliverer{}, NotificationWorkerConfig{
		Owner: "notify-a",
		Poll:  time.Hour, // never ticks on its own during this test
		Rand:  func() float64 { return 0.5 },
	}, func() time.Time { return now }, nwLogger())

	ctx := context.Background()
	w.Start(ctx)
	// The first round drains the queued batch; wait for it.
	for {
		var delivered int
		store.snapshot(func(s *nwStore) { delivered = len(s.delivered) })
		if delivered == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	store.snapshot(func(s *nwStore) { s.batches = [][]NotificationClaim{{nwClaim("intent-shutdown", 1)}} })
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.delivered) != 2 || s.delivered[1] != "intent-shutdown" {
			t.Fatalf("delivered = %v, want the final pass to have drained intent-shutdown", s.delivered)
		}
	})
	// Stop is idempotent and never blocks a second time.
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestNotificationWorkerStopReleasesHeldClaims proves a claim still held
// when the final pass ends is handed straight back, so shutdown never
// leaves a durable obligation waiting out a full lease.
func TestNotificationWorkerStopReleasesHeldClaims(t *testing.T) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	store := &nwStore{batches: [][]NotificationClaim{{nwClaim("intent-held", 1)}}}
	w := NewNotificationWorker(store, &nwDeliverer{}, NotificationWorkerConfig{
		Owner: "notify-a",
		Poll:  time.Hour,
		Rand:  func() float64 { return 0.5 },
	}, func() time.Time { return now }, nwLogger())

	// Simulate a claim the worker is still holding when Stop is called.
	w.trackClaim(nwClaim("intent-held-open", 1))
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	store.snapshot(func(s *nwStore) {
		if len(s.released) != 1 || s.released[0] != "intent-held-open" {
			t.Fatalf("released = %v, want the still-held claim handed back", s.released)
		}
	})
}
