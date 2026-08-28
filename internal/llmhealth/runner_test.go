// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"fmt"
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
