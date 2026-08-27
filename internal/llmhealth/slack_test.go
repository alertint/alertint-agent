// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llmhealth"
)

type fakePub struct {
	mu                   sync.Mutex
	posts, updates       []string
	failPost, failUpdate bool
}

func (p *fakePub) PostSystemMessage(_ context.Context, text string) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failPost {
		return "", "", errors.New("slack: ratelimited")
	}
	p.posts = append(p.posts, text)
	return "C1", "171.1", nil
}

func (p *fakePub) UpdateSystemMessage(_ context.Context, channel, ts, text string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failUpdate {
		return errors.New("slack: message_not_found")
	}
	if channel != "C1" || ts != "171.1" {
		return errors.New("wrong coordinates")
	}
	p.updates = append(p.updates, text)
	return nil
}

func (p *fakePub) postCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.posts)
}

func (p *fakePub) updateCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.updates)
}

func TestRenderCopyContract(t *testing.T) {
	if got := llmhealth.RenderOutage(llmhealth.StateUnavailable, 5*time.Minute); got != "⚠️ AlertINT system · LLM unavailable for 5m. New Incident triage is retrying; correlation may be delayed." {
		t.Fatalf("%q", got)
	}
	if got := llmhealth.RenderOutage(llmhealth.StateDegraded, 5*time.Minute); got != "⚠️ AlertINT system · LLM degraded for 5m. Verification re-judgment is failing; draft Findings continue with reduced confidence." {
		t.Fatalf("%q", got)
	}
	if got := llmhealth.RenderRecovery(12 * time.Minute); got != "✅ AlertINT system · LLM recovered after 12m. Pending triage retries continue automatically." {
		t.Fatalf("%q", got)
	}
	for d, want := range map[time.Duration]string{30 * time.Second: "<1m", 5 * time.Minute: "5m", 90 * time.Minute: "1h 30m", 2 * time.Hour: "2h"} {
		if got := llmhealth.FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestOneRootPerEpisodeAndInPlaceRecovery(t *testing.T) {
	tr, _, c, a := newTracker(t)
	pub := &fakePub{}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(4 * time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 0 {
		t.Fatal("must not post before broadcast_after")
	}
	c.add(time.Minute)
	tr.Deliver(context.Background(), pub)
	tr.Deliver(context.Background(), pub)                         // repeated cadence: still one root
	tr.Begin(llmhealth.CapabilityTriageDraft, "j").Finish(err503) // repeated observation: still one root
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 1 || pub.posts[0] != llmhealth.RenderOutage(llmhealth.StateUnavailable, 5*time.Minute) {
		t.Fatalf("posts = %v", pub.posts)
	}
	c.add(7 * time.Minute)
	tr.Begin(llmhealth.CapabilityTriageDraft, "k").Finish(nil)
	tr.Deliver(context.Background(), pub)
	if pub.updateCount() != 1 || pub.updates[0] != llmhealth.RenderRecovery(12*time.Minute) || pub.postCount() != 1 {
		t.Fatalf("updates = %v posts = %v", pub.updates, pub.posts)
	}
	tr.Deliver(context.Background(), pub) // idempotent after recovered
	if pub.updateCount() != 1 {
		t.Fatal("recovery edit repeated")
	}
	found := 0
	for _, k := range a.kinds {
		if k == "llm.health.slack_posted" || k == "llm.health.slack_updated" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
}

func TestDegradedToUnavailableEditsSameRoot(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &fakePub{}
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	tr.Begin(llmhealth.CapabilityTriageDraft, "j").Finish(err503)
	c.add(time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 1 || pub.updateCount() != 1 || pub.updates[0] != llmhealth.RenderOutage(llmhealth.StateUnavailable, 6*time.Minute) {
		t.Fatalf("posts=%v updates=%v", pub.posts, pub.updates)
	}
}

func TestDeliveryFailureRetriesWithoutDuplicate(t *testing.T) {
	tr, _, c, a := newTracker(t)
	pub := &fakePub{failPost: true}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 0 || tr.Snapshot().State != llmhealth.StateUnavailable {
		t.Fatal("failed post must not be recorded")
	}
	pub.failPost = false
	c.add(time.Minute)
	tr.Deliver(context.Background(), pub) // Slack recovered while LLM still down: deliver the CURRENT outage
	if pub.postCount() != 1 || pub.posts[0] != llmhealth.RenderOutage(llmhealth.StateUnavailable, 6*time.Minute) {
		t.Fatalf("posts = %v", pub.posts)
	}
	failed := 0
	for _, k := range a.kinds {
		if k == "llm.health.slack_failed" {
			failed++
		}
	}
	if failed != 2 {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
}

func TestRecoveryBeforeFirstDeliveryIsSuppressed(t *testing.T) {
	tr, _, c, a := newTracker(t)
	pub := &fakePub{failPost: true}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(6 * time.Minute)
	tr.Deliver(context.Background(), pub) // pending
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	pub.failPost = false
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 0 || pub.updateCount() != 0 {
		t.Fatalf("stale outage/recovery pair must be suppressed: posts=%v updates=%v", pub.posts, pub.updates)
	}
	suppressed := false
	for _, k := range a.kinds {
		suppressed = suppressed || k == "llm.health.slack_suppressed"
	}
	if !suppressed {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
}

func TestRecoveryEditFailureRetries(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &fakePub{}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	pub.failUpdate = true
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	tr.Deliver(context.Background(), pub)
	pub.failUpdate = false
	tr.Deliver(context.Background(), pub)
	if pub.updateCount() != 1 {
		t.Fatalf("updates = %v", pub.updates)
	}
}

func TestSlackCoordinatesSurviveRestart(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &fakePub{}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	tr2.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	tr2.Deliver(context.Background(), pub)
	if pub.postCount() != 1 || pub.updateCount() != 1 {
		t.Fatalf("after restart posts=%v updates=%v", pub.posts, pub.updates)
	}
}

func TestNilPublisherKeepsLocalHistoryOnly(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(6 * time.Minute)
	tr.Deliver(context.Background(), nil)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("%+v", s)
	}
}
