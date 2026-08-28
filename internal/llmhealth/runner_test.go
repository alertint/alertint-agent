// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
)

type fakeProber struct {
	calls atomic.Int32
	res   llm.ProbeResult
	block chan struct{}
}

func (p *fakeProber) Probe(ctx context.Context) llm.ProbeResult {
	p.calls.Add(1)
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
		}
	}
	return p.res
}

func TestStepProbesOnlyWhenIdleAndDue(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"}}
	r := llmhealth.NewRunner(tr, pr, nil, nil)
	r.Step(context.Background(), c.now())
	if pr.calls.Load() != 0 {
		t.Fatal("probed at boot")
	}
	c.add(5 * time.Minute)
	r.Step(context.Background(), c.now())
	r.Step(context.Background(), c.now())
	if pr.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (once per minute)", pr.calls.Load())
	}
	obs := tr.Begin(llmhealth.CapabilityTriageDraft, "i")
	c.add(time.Minute)
	r.Step(context.Background(), c.now())
	if pr.calls.Load() != 1 {
		t.Fatal("probed while a call was in flight")
	}
	obs.Finish(nil)
	c.add(time.Minute)
	r.Step(context.Background(), c.now())
	if pr.calls.Load() != 1 {
		t.Fatal("probed before idle interval elapsed after a real call")
	}
}

func TestStepDeliversBeforeProbing(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &fakePub{}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	r.Step(context.Background(), c.now())
	if pub.postCount() != 1 {
		t.Fatalf("posts = %v", pub.posts)
	}
}

func TestRunWakesOnKick(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &fakePub{}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	llmhealth.SetRunnerTickForTest(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	r.Step(context.Background(), c.now())                      // root delivered
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil) // kick → recovery edit without waiting an hour
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pub.updateCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if pub.updateCount() != 1 {
		t.Fatalf("recovery edit not delivered on kick: %v", pub.updates)
	}
	cancel()
	<-done
}

// TestStartJoinsInFlightPostOnShutdown pins the lifecycle side of the
// detached POST: the done channel Start returns closes only after a POST in
// flight at cancellation has returned and its coordinates were persisted, so
// the owner can keep the store open until then instead of exiting with the
// durable marker stuck at "indeterminate".
func TestStartJoinsInFlightPostOnShutdown(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &blockingPub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	llmhealth.SetRunnerTickForTest(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // transition → buffered kick
	c.add(5 * time.Minute)
	done := r.Start(ctx) // consumes the kick: root due → POST

	<-pub.started // past the fence, POST in flight
	cancel()
	select {
	case <-done:
		t.Fatal("runner reported done while its POST was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(pub.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not finish after the POST returned")
	}
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryDelivered || rec.SlackTS == "" {
		t.Fatalf("durable slack_delivery = %q ts = %q; the joined POST's coordinates must be persisted before done closes", rec.SlackDelivery, rec.SlackTS)
	}
}

// TestDrainTimeoutCoversWorstCaseChain pins the derivation: after the post
// fence a shutdown may still have to wait for the detached POST, the
// post-result audit and persist, and — when an idle probe was due in the
// same step — the probe's own persist and audit. On top of that a real call
// can recover while the POST is in flight: the recovery holds the tracker
// lock across two audits and a persist, and the returning POST then adopts
// the stale root with one more audit and persist. Each is individually
// bounded; the drain window must cover all of them with margin.
func TestDrainTimeoutCoversWorstCaseChain(t *testing.T) {
	// One step's tail past the post fence (detached POST, its audit+persist,
	// a due probe's persist+audit, a recovery holding the lock across two
	// audits and a persist, the stale-root adoption audit+persist) PLUS the
	// final delivery pass Stop runs against the settled state: one whole
	// Deliver phase (deliveryBudget) and its last result's audit+persist.
	chain := llmhealth.DeliveryTimeoutForTest() + 9*llmhealth.PersistTimeoutForTest() +
		llmhealth.DeliveryBudgetForTest() + 2*llmhealth.PersistTimeoutForTest()
	if got := llmhealth.DrainTimeout(); got <= chain {
		t.Fatalf("DrainTimeout = %v, must exceed the worst-case chain %v", got, chain)
	}
}

// slowAudit holds every Append until its bounded context expires, so each
// audit stage costs the full persistTimeout. started (optional) is closed on
// the first Append.
type slowAudit struct {
	started chan struct{}
	// startedAt is the 1-based Append call that closes started (0 = first).
	startedAt int
	once      sync.Once

	mu     sync.Mutex
	calls  int
	events []string
}

func (a *slowAudit) Append(ctx context.Context, _, event string, _ any) error {
	a.mu.Lock()
	a.calls++
	a.events = append(a.events, event)
	n := a.calls
	a.mu.Unlock()
	if a.started != nil && n >= a.startedAt {
		a.once.Do(func() { close(a.started) })
	}
	<-ctx.Done()
	return ctx.Err()
}

func (a *slowAudit) seen(event string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e == event {
			return true
		}
	}
	return false
}

// delayedPub answers the POST only just inside deliveryTimeout.
type delayedPub struct {
	fakePub

	delay   time.Duration
	started chan struct{}
	once    sync.Once
}

func (p *delayedPub) PostSystemMessage(ctx context.Context, text string) (string, string, error) {
	p.once.Do(func() { close(p.started) })
	time.Sleep(p.delay)
	return p.fakePub.PostSystemMessage(ctx, text)
}

// TestStartDrainsWorstCaseChainWithinDrainTimeout runs the maximum-duration
// shutdown path with the bounds shrunk: a POST that takes almost the whole
// deliveryTimeout, audit appends that each burn a full persistTimeout, and
// an idle probe due in the same step. The runner must still finish inside
// DrainTimeout with the root's coordinates durable. (The store is concrete,
// so persist latency itself is not injectable here; its bound is covered by
// the derivation test above.)
func TestStartDrainsWorstCaseChainWithinDrainTimeout(t *testing.T) {
	restore := llmhealth.SetTimeoutsForTest(200*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	t.Cleanup(restore)
	llmhealth.SetRunnerTickForTest(time.Hour)

	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := &clock{t: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, Auditor: &slowAudit{}, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub := &delayedPub{delay: 150 * time.Millisecond, started: make(chan struct{})}
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeFailed, Err: context.Canceled}}
	r := llmhealth.NewRunner(tr, pr, pub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // transition → buffered kick
	c.add(5 * time.Minute)                                        // root due and probe due
	done := r.Start(ctx)

	<-pub.started
	cancel()
	start := time.Now()
	select {
	case <-done:
	case <-time.After(llmhealth.DrainTimeout()):
		t.Fatalf("runner still draining after DrainTimeout %v", llmhealth.DrainTimeout())
	}
	t.Logf("drained in %v of %v", time.Since(start), llmhealth.DrainTimeout())
	if pr.calls.Load() != 1 {
		t.Fatalf("probe calls = %d; the worst case includes the probe stage", pr.calls.Load())
	}
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryDelivered || rec.SlackTS == "" {
		t.Fatalf("durable slack_delivery = %q ts = %q", rec.SlackDelivery, rec.SlackTS)
	}
}

// TestStartDrainsRecoveryRacingPostWithinDrainTimeout combines the
// "recovery during an in-flight post" scenario with shutdown and slow
// audits: the real call recovers while the detached POST is out (holding the
// lock across its own audits and persist), the POST then returns into the
// adoption path (one more audit and persist), and all of it must still land
// inside DrainTimeout — the adopted root's coordinates durable, so the next
// process can edit it to recovered instead of leaving it saying
// "unavailable" forever.
func TestStartDrainsRecoveryRacingPostWithinDrainTimeout(t *testing.T) {
	restore := llmhealth.SetTimeoutsForTest(200*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	t.Cleanup(restore)
	llmhealth.SetRunnerTickForTest(time.Hour)

	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := &clock{t: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
	// The initial failing observation below is audit #1; the recovery's
	// first audit under the lock is #2 — that is the one the test waits on.
	audit := &slowAudit{started: make(chan struct{}), startedAt: 2}
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, Auditor: audit, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub := &blockingPub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // transition → buffered kick
	c.add(5 * time.Minute)
	done := r.Start(ctx)

	<-pub.started
	recovered := make(chan struct{})
	go func() {
		defer close(recovered)
		tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil) // recovery while the POST is in flight
	}()
	<-audit.started // recovery now holds the tracker lock in its first slow audit
	cancel()
	close(pub.release) // the POST returns into a contended lock, then adopts the root
	start := time.Now()
	select {
	case <-done:
	case <-time.After(llmhealth.DrainTimeout()):
		t.Fatalf("runner still draining after DrainTimeout %v", llmhealth.DrainTimeout())
	}
	<-recovered
	t.Logf("drained in %v of %v", time.Since(start), llmhealth.DrainTimeout())
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryRecoveryPending || rec.SlackTS == "" {
		t.Fatalf("durable slack_delivery = %q ts = %q; the root posted during recovery must be adopted durably before done closes", rec.SlackDelivery, rec.SlackTS)
	}
	// Distinguishes stale-root adoption (recovery won the lock first) from an
	// ordinary delivered-root recovery, which ends in the same durable state.
	if !audit.seen("llm.health.slack_adopted") {
		t.Fatalf("no llm.health.slack_adopted audit: the POST did not return into a recovery that already held the lock; events=%v", audit.events)
	}
}

// TestStaleProbeFailureDiscardedAfterRealSuccessRacesIt covers the TOCTOU gap
// between ProbeDue() (checks inFlight == 0, releases the lock) and the probe
// HTTP call actually starting: a real call can begin — and succeed — while
// the probe is still in flight. The probe's later-arriving failure must not
// override that fresher, stronger real-success signal (H2's "probe success
// cannot erase a real inference failure" cuts both ways: a stale probe
// failure must not erase a real inference success either).
func TestStaleProbeFailureDiscardedAfterRealSuccessRacesIt(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/v1/models/m", Err: err503}, block: make(chan struct{})}
	r := llmhealth.NewRunner(tr, pr, nil, nil)
	c.add(5 * time.Minute)

	done := make(chan struct{})
	go func() {
		r.Step(context.Background(), c.now())
		close(done)
	}()
	for pr.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	// A real call races in and succeeds while the probe above is still blocked.
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)

	close(pr.block)
	<-done

	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("a stale probe failure must not override a real success that raced it: %+v", s)
	}
}

// TestStaleProbeFailureDiscardedWhenRealCallBeginsDuringIt covers the
// remaining interleaving: the real call BEGINS after ProbeDue decided but is
// still in flight when the probe fails. The probe's failure is stale the
// moment a real call starts — that call's own Finish is the authoritative
// signal about reachability — so the probe must not mark the installation
// unavailable in the window before the real call completes.
func TestStaleProbeFailureDiscardedWhenRealCallBeginsDuringIt(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/v1/models/m", Err: err503}, block: make(chan struct{})}
	r := llmhealth.NewRunner(tr, pr, nil, nil)
	c.add(5 * time.Minute)

	done := make(chan struct{})
	go func() {
		r.Step(context.Background(), c.now())
		close(done)
	}()
	for pr.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	// A real call begins while the probe is blocked — and is still in flight
	// when the probe's failure lands.
	obs := tr.Begin(llmhealth.CapabilityTriageDraft, "i")
	close(pr.block)
	<-done

	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("a probe failure that raced a real call's start must not mark the installation unavailable: %+v", s)
	}
	obs.Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("after the racing real call succeeds: %+v", s)
	}
}

// stalledPub accepts the connection and never answers: PostSystemMessage /
// UpdateSystemMessage return only when ctx is done, the way a Slack request
// against a stalled endpoint would with no client timeout.
type stalledPub struct{ calls atomic.Int32 }

func (p *stalledPub) PostSystemMessage(ctx context.Context, _ string) (string, string, error) {
	p.calls.Add(1)
	<-ctx.Done()
	return "", "", fmt.Errorf("post: %w", ctx.Err())
}

func (p *stalledPub) UpdateSystemMessage(ctx context.Context, _, _, _ string) error {
	p.calls.Add(1)
	<-ctx.Done()
	return fmt.Errorf("update: %w", ctx.Err())
}

// TestStalledSlackDeliveryDoesNotBlockProbe pins that one stalled Slack
// request cannot stop the single Runner: Step bounds every Publisher call
// with its own timeout, returns, and still runs the idle probe that is due —
// otherwise an idle LLM recovery would stay reported as unavailable for as
// long as Slack keeps the connection open.
func TestStalledSlackDeliveryDoesNotBlockProbe(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &stalledPub{}
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"}}
	r := llmhealth.NewRunner(tr, pr, pub, nil)
	llmhealth.SetDeliveryTimeoutForTest(20 * time.Millisecond)
	t.Cleanup(func() { llmhealth.SetDeliveryTimeoutForTest(15 * time.Second) })

	// A probe-driven outage: the LLM went away while idle, and only the next
	// idle probe can bring it back.
	c.add(5 * time.Minute)
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Err: err503})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("%+v", s)
	}
	c.add(5 * time.Minute) // broadcast_after reached; the next probe is due

	done := make(chan struct{})
	go func() {
		r.Step(context.Background(), c.now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Step did not return while Slack stalled; the Runner is wedged")
	}
	if pub.calls.Load() != 1 {
		t.Fatalf("slack calls = %d", pub.calls.Load())
	}
	if pr.calls.Load() != 1 {
		t.Fatal("the due idle probe did not run after the stalled Slack call")
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("probe success must still recover the installation: %+v", s)
	}
}

// TestLateRootBacklogCannotStarveProbe pins that the whole Slack delivery
// phase of one Step is budgeted, not just each call: N stalled late-root
// edits must not cost N × deliveryTimeout before the due probe runs.
func TestLateRootBacklogCannotStarveProbe(t *testing.T) {
	_, st, c, _ := newTracker(t)
	rec, caps, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		rec.LateRoots = append(rec.LateRoots, store.LLMLateRoot{Channel: "C1", TS: fmt.Sprintf("1.%d", i), DownForMS: 60000})
	}
	if err := st.SaveLLMHealth(context.Background(), rec, caps); err != nil {
		t.Fatal(err)
	}
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub := &stalledPub{}
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"}}
	r := llmhealth.NewRunner(tr, pr, pub, nil)
	llmhealth.SetDeliveryTimeoutForTest(100 * time.Millisecond)
	llmhealth.SetDeliveryBudgetForTest(150 * time.Millisecond)
	t.Cleanup(func() {
		llmhealth.SetDeliveryTimeoutForTest(15 * time.Second)
		llmhealth.SetDeliveryBudgetForTest(45 * time.Second)
	})
	c.add(5 * time.Minute)

	start := time.Now()
	r.Step(context.Background(), c.now())
	if el := time.Since(start); el > 400*time.Millisecond {
		t.Fatalf("Step took %v: the late-root backlog was drained call by call instead of within one budget", el)
	}
	if pr.calls.Load() != 1 {
		t.Fatal("the due idle probe did not run")
	}
	if calls := pub.calls.Load(); calls >= 5 {
		t.Fatalf("slack calls = %d; the budget did not cut the backlog short", calls)
	}
}

// poisonedPub stalls every update of one specific root ts and answers all
// others at once, so one bad late root can be placed at the head of the queue.
type poisonedPub struct {
	stallTS string
	mu      sync.Mutex
	edited  []string
}

func (p *poisonedPub) PostSystemMessage(_ context.Context, _ string) (string, string, error) {
	return "", "", errors.New("unexpected post")
}

func (p *poisonedPub) UpdateSystemMessage(ctx context.Context, _, ts, _ string) error {
	if ts == p.stallTS {
		<-ctx.Done()
		return fmt.Errorf("update: %w", ctx.Err())
	}
	p.mu.Lock()
	p.edited = append(p.edited, ts)
	p.mu.Unlock()
	return nil
}

// TestLateRootRetriesAreFair pins that a late root whose edit keeps failing
// cannot shadow the roots queued behind it: a budget that admits about one
// edit per Step must still reach every other root within a few Steps, or a
// stale "LLM unavailable" root would stand in the channel indefinitely because
// of an unrelated one ahead of it in the queue.
func TestLateRootRetriesAreFair(t *testing.T) {
	_, st, c, _ := newTracker(t)
	rec, caps, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec.LateRoots = []store.LLMLateRoot{
		{Channel: "C1", TS: "poison", DownForMS: 60000},
		{Channel: "C1", TS: "1.1", DownForMS: 60000},
		{Channel: "C1", TS: "1.2", DownForMS: 60000},
	}
	if err := st.SaveLLMHealth(context.Background(), rec, caps); err != nil {
		t.Fatal(err)
	}
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub := &poisonedPub{stallTS: "poison"}
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"}}
	r := llmhealth.NewRunner(tr, pr, pub, nil)
	// The stalled edit alone spends the whole budget: exactly one attempt
	// per Step, so whichever root is at the head is the only one tried.
	llmhealth.SetDeliveryTimeoutForTest(50 * time.Millisecond)
	llmhealth.SetDeliveryBudgetForTest(40 * time.Millisecond)
	t.Cleanup(func() {
		llmhealth.SetDeliveryTimeoutForTest(15 * time.Second)
		llmhealth.SetDeliveryBudgetForTest(45 * time.Second)
	})

	for i := 0; i < 4; i++ {
		r.Step(context.Background(), c.now())
		c.add(time.Second)
	}
	pub.mu.Lock()
	edited := append([]string(nil), pub.edited...)
	pub.mu.Unlock()
	if len(edited) != 2 {
		t.Fatalf("edited late roots after 4 steps = %v; the poisoned head starved the queue", edited)
	}
	rec, _, err = st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.LateRoots) != 1 || rec.LateRoots[0].TS != "poison" {
		t.Fatalf("durable late roots = %+v; only the poisoned root should remain", rec.LateRoots)
	}
}

func TestProbeTimeoutIsBounded(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeFailed, Err: context.DeadlineExceeded}, block: make(chan struct{})}
	r := llmhealth.NewRunner(tr, pr, nil, nil)
	llmhealth.SetProbeTimeoutForTest(20 * time.Millisecond)
	c.add(5 * time.Minute)
	start := time.Now()
	r.Step(context.Background(), c.now())
	if time.Since(start) > time.Second {
		t.Fatal("probe not bounded by timeout")
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonTimeout {
		t.Fatalf("%+v", s)
	}
}

// TestStopPostsRootThatBecameDueWithoutAKick: the broadcast window elapses
// after the last kick was consumed (the failing observation was not yet 5m
// old when the runner stepped on it). No producer will kick again; only a
// tick would. Stop must still acknowledge the settled state — post the
// episode's root — before the runner exits, not leave it for a restart.
func TestStopPostsRootThatBecameDueWithoutAKick(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &fakePub{}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	llmhealth.SetRunnerTickForTest(time.Hour)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	<-tr.Kick()                           // the kick the loop would have taken…
	r.Step(context.Background(), c.now()) // …and the step it would have run: not due yet
	done := r.Start(context.Background())
	c.add(5 * time.Minute) // now due; nothing will kick again
	r.Stop()
	select {
	case <-done:
	case <-time.After(llmhealth.DrainTimeout()):
		t.Fatal("runner did not stop within DrainTimeout")
	}
	if pub.postCount() != 1 {
		t.Fatalf("root posts at Stop = %d, want 1: the due root must be acknowledged before exit", pub.postCount())
	}
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryDelivered || rec.SlackTS == "" {
		t.Fatalf("durable slack_delivery = %q ts = %q after Stop", rec.SlackDelivery, rec.SlackTS)
	}
}

// TestStopAcknowledgesRecoveryRacingStop is the reported interleaving: the
// last producer recovers (kick buffered) and the owner stops the runner in
// the same instant. A cancel-and-join runner may select the stop first and
// exit with the root still saying "unavailable". Stop must deliver the
// recovery edit whichever branch the select takes.
func TestStopAcknowledgesRecoveryRacingStop(t *testing.T) {
	for i := 0; i < 20; i++ {
		tr, st, c, _ := newTracker(t)
		pub := &fakePub{}
		r := llmhealth.NewRunner(tr, nil, pub, nil)
		llmhealth.SetRunnerTickForTest(time.Hour)
		tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
		c.add(5 * time.Minute)
		r.Step(context.Background(), c.now()) // root delivered; the kick was consumed by nobody: drain it
		select {
		case <-tr.Kick():
		default:
		}
		tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil) // final transition → kick buffered
		r.Stop()                                                   // and the stop: both ready when the loop first selects
		done := r.Start(context.Background())
		select {
		case <-done:
		case <-time.After(llmhealth.DrainTimeout()):
			t.Fatal("runner did not stop within DrainTimeout")
		}
		rec, _, err := st.GetLLMHealth(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if pub.updateCount() != 1 || rec.SlackDelivery != llmhealth.DeliveryRecovered {
			t.Fatalf("run %d: recovery edits = %d, durable slack_delivery = %q; the final transition was not acknowledged before exit", i, pub.updateCount(), rec.SlackDelivery)
		}
	}
}

// cutPub blocks the first update until its ctx ends and reports how it
// ended; later calls answer at once.
type cutPub struct {
	fakePub

	firstErr chan error
	once     sync.Once
}

func (p *cutPub) UpdateSystemMessage(ctx context.Context, channel, ts, text string) error {
	var first bool
	p.once.Do(func() { first = true })
	if first {
		<-ctx.Done()
		p.firstErr <- ctx.Err()
		return ctx.Err()
	}
	return p.fakePub.UpdateSystemMessage(ctx, channel, ts, text)
}

// TestStopCutsTheStepInProgress: the runner's own ctx is never canceled by
// the owner (Stop is the shutdown path), so Stop itself must cut the step
// that is running — otherwise a stalled edit or a slow probe in that step
// keeps running to its own bound before the final pass even starts, past
// what DrainTimeout accounts for. The cut is observable as context.Canceled
// (not DeadlineExceeded) on the stalled call, and the final pass then
// retries it on a live ctx.
func TestStopCutsTheStepInProgress(t *testing.T) {
	restore := llmhealth.SetTimeoutsForTest(2*time.Second, 100*time.Millisecond, 100*time.Millisecond)
	t.Cleanup(restore)
	tr, st, c, _ := newTracker(t)
	pub := &cutPub{firstErr: make(chan error, 1)}
	r := llmhealth.NewRunner(tr, nil, pub, nil)
	llmhealth.SetRunnerTickForTest(time.Hour)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	<-tr.Kick()
	c.add(5 * time.Minute)
	r.Step(context.Background(), c.now()) // root delivered
	done := r.Start(context.Background())
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil) // kick → step → recovery edit stalls in cutPub
	time.Sleep(50 * time.Millisecond)                          // let the step reach the stalled edit
	start := time.Now()
	r.Stop()
	select {
	case err := <-pub.firstErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stalled edit ended with %v after %v; Stop must cut the step in progress, not wait out its bound", err, time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled edit never ended")
	}
	select {
	case <-done:
	case <-time.After(llmhealth.DrainTimeout()):
		t.Fatal("runner did not stop within DrainTimeout")
	}
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pub.updateCount() != 1 || rec.SlackDelivery != llmhealth.DeliveryRecovered {
		t.Fatalf("final pass: edits landed = %d, durable slack_delivery = %q; want the cut edit retried and recovered", pub.updateCount(), rec.SlackDelivery)
	}
}
