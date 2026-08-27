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

// TestFailedPostDeliveryStatePersists covers the gap where a failed
// PostSystemMessage set SlackDelivery = DeliveryPending in memory but
// returned before persist(), so the durable llm_health row never reflected
// the attempt: after a restart it would look exactly like "none" (no attempt
// ever happened) rather than "pending" (one already failed) — durable state
// and the audit trail must agree.
func TestFailedPostDeliveryStatePersists(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &fakePub{failPost: true}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)

	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryPending {
		t.Fatalf("durable slack_delivery = %q, want %q", rec.SlackDelivery, llmhealth.DeliveryPending)
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

// blockingPub wraps fakePub and blocks inside PostSystemMessage until
// release is closed, signaling started once the call has begun — lets a test
// pin down state exactly while a post is in flight.
type blockingPub struct {
	*fakePub

	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingPub) PostSystemMessage(ctx context.Context, text string) (string, string, error) {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return p.fakePub.PostSystemMessage(ctx, text)
}

// TestRecoveryDuringInFlightPostDiscardsStaleResult covers the race where the
// LLM recovers while a PostSystemMessage HTTP call for the just-ended outage
// is still in flight: the outage generation must be fenced at recovery too
// (not only when a new outage starts), so the late-arriving success is
// discarded — never resurrected as a "delivered" root nothing will ever edit.
func TestRecoveryDuringInFlightPostDiscardsStaleResult(t *testing.T) {
	tr, _, c, a := newTracker(t)
	pub := &blockingPub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}

	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)

	done := make(chan struct{})
	go func() {
		tr.Deliver(context.Background(), pub)
		close(done)
	}()
	<-pub.started

	// Recover while the post above is still blocked in flight.
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)

	close(pub.release)
	<-done

	posted, suppressed := false, false
	for _, k := range a.kinds {
		posted = posted || k == "llm.health.slack_posted"
		suppressed = suppressed || k == "llm.health.slack_suppressed"
	}
	if posted {
		t.Fatal("a delivery result computed before recovery must not be applied after it")
	}
	if !suppressed {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
}

// blockingUpdatePub wraps fakePub and blocks inside UpdateSystemMessage until
// release is closed, signaling started once the call has begun — mirrors
// blockingPub but for the edit call instead of the initial post.
type blockingUpdatePub struct {
	*fakePub

	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingUpdatePub) UpdateSystemMessage(ctx context.Context, channel, ts, text string) error {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return p.fakePub.UpdateSystemMessage(ctx, channel, ts, text)
}

// TestNewOutageWhileRecoveryEditInFlightDoesNotStealItsGeneration covers the
// race where a SECOND outage begins while the FIRST episode's recovery edit
// (UpdateSystemMessage) is still in flight. SlackGeneration must be an
// independently monotonic fence: if entering the new outage merely copies
// OutageGeneration (which the recovery increment may have already raced
// ahead of), the two can coincide again, so the stale recovery-edit result
// passes the staleness check and marks the brand-new, never-posted episode
// "recovered" — permanently silencing its own root.
func TestNewOutageWhileRecoveryEditInFlightDoesNotStealItsGeneration(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &blockingUpdatePub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}

	// Episode 1: outage, broadcast (root posts immediately, not blocked), recover.
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)

	// The recovery edit starts and blocks.
	done := make(chan struct{})
	go func() {
		tr.Deliver(context.Background(), pub)
		close(done)
	}()
	<-pub.started

	// Episode 2 begins while the episode-1 recovery edit above is still in flight.
	tr.Begin(llmhealth.CapabilityTriageDraft, "j").Finish(err503)

	close(pub.release)
	<-done

	// Episode 2 must still be able to post its own root once broadcastAfter
	// elapses — it must not come out of the gate already marked "recovered".
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 2 {
		t.Fatalf("second episode's root was never posted (its generation was stolen by a stale recovery edit): posts=%v", pub.posts)
	}
}
