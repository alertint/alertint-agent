// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
)

func TestEndToEndOutageEpisode(t *testing.T) {
	tr, _, c, a := newTracker(t)
	pub := &fakePub{}
	pr := &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/v1/models/m", Err: err503}}
	r := llmhealth.NewRunner(tr, pr, pub, nil)

	// 1. Real Call-1 failures across three incidents; idle probe must not run while calls are in flight.
	for _, id := range []string{"a", "b", "c"} {
		obs := tr.Begin(llmhealth.CapabilityTriageDraft, id)
		r.Step(context.Background(), c.now())
		obs.Finish(err503)
		c.add(30 * time.Second)
	}
	if pr.calls.Load() != 0 {
		t.Fatal("probe ran while calls were in flight / not idle")
	}
	// 2. Five minutes unhealthy → one root.
	c.add(4 * time.Minute)
	r.Step(context.Background(), c.now())
	if pub.postCount() != 1 {
		t.Fatalf("posts = %v", pub.posts)
	}
	// 3. Idle → probe runs (once per minute) and keeps state unavailable; it never posts a second root.
	c.add(5 * time.Minute)
	r.Step(context.Background(), c.now())
	c.add(30 * time.Second)
	r.Step(context.Background(), c.now())
	if pr.calls.Load() != 1 || pub.postCount() != 1 {
		t.Fatalf("probe calls=%d posts=%d", pr.calls.Load(), pub.postCount())
	}
	// 4. Probe success alone does not clear the inference failure.
	pr.res = llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/v1/models/m"}
	c.add(time.Minute)
	r.Step(context.Background(), c.now())
	if tr.Snapshot().State != llmhealth.StateUnavailable || pub.updateCount() != 0 {
		t.Fatal("probe success must not recover an inference outage")
	}
	// 5. Real Call-1 success → recovery edit in place, once.
	tr.Begin(llmhealth.CapabilityTriageDraft, "d").Finish(nil)
	r.Step(context.Background(), c.now())
	r.Step(context.Background(), c.now())
	if pub.updateCount() != 1 || pub.postCount() != 1 {
		t.Fatalf("updates=%v posts=%v", pub.updates, pub.posts)
	}
	// 6. Audit trail carries codes only.
	for _, p := range a.payloads {
		for k, v := range p {
			if s, ok := v.(string); ok && (strings.Contains(s, "sk-") || k == "prompt" || k == "body") {
				t.Fatalf("audit leaked %s=%v", k, v)
			}
		}
	}
}

func TestConcurrentObservationsRace(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	r := llmhealth.NewRunner(tr, &fakeProber{res: llm.ProbeResult{Outcome: llm.ProbeOK}}, &fakePub{}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cap := llmhealth.CapabilityTriageDraft
			if i%3 == 0 {
				cap = llmhealth.CapabilityMemoryClassifier
			}
			obs := tr.Begin(cap, fmt.Sprintf("inc-%d", i))
			if i%2 == 0 {
				obs.Finish(err503)
			} else {
				obs.Finish(nil)
			}
			_ = tr.Snapshot()
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			r.Step(context.Background(), c.now())
		}
	}()
	wg.Wait()
	if tr.Snapshot().InFlight != 0 {
		t.Fatal("in-flight counter drifted")
	}
}
