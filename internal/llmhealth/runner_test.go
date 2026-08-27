// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
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
