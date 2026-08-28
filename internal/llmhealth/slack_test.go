// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
)

type fakePub struct {
	mu                   sync.Mutex
	posts, updates       []string
	failPost, failUpdate bool
	failPostErr          error // when non-nil, PostSystemMessage returns exactly this
}

func (p *fakePub) PostSystemMessage(_ context.Context, text string) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failPostErr != nil {
		return "", "", p.failPostErr
	}
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

// TestRecoveryDuringInFlightPostReconcilesStaleRoot covers the race where
// the LLM recovers while a PostSystemMessage HTTP call for the just-ended
// outage is still in flight. The generation fence correctly stops the stale
// result from being applied as a live "delivered" root — but the POST DID
// succeed, so Slack now shows an outage root. Discarding the coordinates
// would leave that root saying "unavailable" forever; instead the tracker
// must adopt them and edit the root to the recovery copy, so the final
// visible message is the truth.
func TestRecoveryDuringInFlightPostReconcilesStaleRoot(t *testing.T) {
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

	suppressed := false
	for _, k := range a.kinds {
		suppressed = suppressed || k == "llm.health.slack_suppressed"
	}
	if !suppressed {
		t.Fatalf("recovery before a confirmed delivery must still audit as suppressed: %v", a.kinds)
	}

	// The next step must reconcile the root Slack actually shows.
	tr.Deliver(context.Background(), pub)
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.posts) != 1 || len(pub.updates) != 1 {
		t.Fatalf("posts=%v updates=%v; want the one stale root edited exactly once", pub.posts, pub.updates)
	}
	if want := llmhealth.RenderRecovery(5 * time.Minute); pub.updates[0] != want {
		t.Fatalf("final visible message = %q, want %q", pub.updates[0], want)
	}
}

// TestLateRootFromPreviousEpisodeGetsItsOwnRecoveryEdit covers the rarer
// variant: recovery AND a new outage both happen while the first episode's
// POST is in flight. Outage episodes are separate histories (CONTEXT.md):
// the late episode-1 root gets episode-1's recovery edit, and episode 2
// keeps its own independent delivery state — it must not become visible
// through the old root before satisfying broadcast_after, and it posts its
// own root once it does. Two roots across two episodes is correct.
func TestLateRootFromPreviousEpisodeGetsItsOwnRecoveryEdit(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	pub := &blockingPub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}

	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)

	done := make(chan struct{})
	go func() {
		tr.Deliver(context.Background(), pub)
		close(done)
	}()
	<-pub.started
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)    // episode 1 recovers (down 5m)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // episode 2 begins
	close(pub.release)
	<-done

	// Immediately: the late root is edited to episode 1's recovery; episode 2
	// has not been unhealthy for broadcast_after, so nothing new is posted.
	tr.Deliver(context.Background(), pub)
	pub.mu.Lock()
	if len(pub.posts) != 1 || len(pub.updates) != 1 || pub.updates[0] != llmhealth.RenderRecovery(5*time.Minute) {
		pub.mu.Unlock()
		t.Fatalf("posts=%v updates=%v; want the late root edited to episode 1's recovery and no early root for episode 2", pub.posts, pub.updates)
	}
	pub.mu.Unlock()
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("episode 2 must still be an outage: %+v", s)
	}

	// Episode 2 sustains: it gets its own root, then its own recovery edit.
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 2 {
		t.Fatalf("posts = %v; episode 2 must post its own root once sustained", pub.posts)
	}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	tr.Deliver(context.Background(), pub)
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.updates) != 2 || pub.updates[1] != llmhealth.RenderRecovery(5*time.Minute) {
		t.Fatalf("updates = %v; episode 2's root must get episode 2's recovery edit", pub.updates)
	}
}

// TestLateRootSurvivesTwoRecoveriesDuringItsPost pins that recovery metadata
// stays associated with EVERY generation that has a POST outstanding, not
// just the newest closed episode: if episode 1's POST is still blocked while
// episode 1 recovers (down 5m), episode 2 begins and ALSO recovers (down 2m),
// the returning episode-1 root must still be edited to episode 1's own
// recovery — never orphaned as a standing false outage, and never given
// episode 2's duration.
func TestLateRootSurvivesTwoRecoveriesDuringItsPost(t *testing.T) {
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
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)    // episode 1 recovers (down 5m)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // episode 2 begins
	c.add(2 * time.Minute)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil) // episode 2 recovers (down 2m)
	close(pub.release)
	<-done

	tr.Deliver(context.Background(), pub)
	for _, k := range a.kinds {
		if k == "llm.health.slack_orphaned" {
			t.Fatalf("episode 1's root was orphaned: %v", a.kinds)
		}
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.posts) != 1 || len(pub.updates) != 1 || pub.updates[0] != llmhealth.RenderRecovery(5*time.Minute) {
		t.Fatalf("posts=%v updates=%v; want the late root edited to episode 1's own 5m recovery", pub.posts, pub.updates)
	}
}

// TestPendingLateRootEditSurvivesRestart pins that a late root awaiting its
// recovery edit is durable: if the process dies after adopting the root but
// before (or while) editing it, the restarted tracker still edits it —
// otherwise a false outage root stands in the channel forever, against the
// cross-restart recovery-edit contract.
func TestPendingLateRootEditSurvivesRestart(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &blockingPub{fakePub: &fakePub{failUpdate: true}, started: make(chan struct{}), release: make(chan struct{})}

	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	done := make(chan struct{})
	go func() {
		tr.Deliver(context.Background(), pub)
		close(done)
	}()
	<-pub.started
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)    // episode 1 recovers (down 5m)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503) // episode 2 begins
	close(pub.release)
	<-done // the late root is adopted; its recovery edit (failUpdate) has not landed

	// "Crash" here: a fresh tracker from the durable state alone, a working Slack.
	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub2 := &fakePub{}
	tr2.Deliver(context.Background(), pub2)
	pub2.mu.Lock()
	if len(pub2.posts) != 0 || len(pub2.updates) != 1 || pub2.updates[0] != llmhealth.RenderRecovery(5*time.Minute) {
		pub2.mu.Unlock()
		t.Fatalf("after restart posts=%v updates=%v; want only the pending late root edited to its recovery", pub2.posts, pub2.updates)
	}
	pub2.mu.Unlock()

	// Edited once; a further step (and another restart) must not edit it again.
	tr2.Deliver(context.Background(), pub2)
	tr3, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	tr3.Deliver(context.Background(), pub2)
	if pub2.updateCount() != 1 {
		t.Fatalf("updates = %v; the late edit must be done exactly once", pub2.updates)
	}
}

// TestPostIsNotAttemptedWhenWriteAheadMarkerFails pins that the "durable
// before POST" guarantee depends on the write actually committing: if the
// indeterminate marker cannot be persisted, the POST must not happen (Slack
// could accept a root that a restarted process would never know about, and
// would post again). Once the store is back, delivery proceeds normally.
func TestPostIsNotAttemptedWhenWriteAheadMarkerFails(t *testing.T) {
	path := t.TempDir() + "/health.db"
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
	opts := llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute}
	tr, err := llmhealth.New(context.Background(), st, opts)
	if err != nil {
		t.Fatal(err)
	}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)

	// The store goes away before delivery: the marker write fails.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	pub := &fakePub{}
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 0 {
		t.Fatalf("posted %v without a committed write-ahead marker", pub.posts)
	}

	// Store back (as after a restart): the outage is still undelivered and
	// delivery proceeds exactly once.
	st2, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	tr2, err := llmhealth.New(context.Background(), st2, opts)
	if err != nil {
		t.Fatal(err)
	}
	tr2.Deliver(context.Background(), pub)
	if pub.postCount() != 1 {
		t.Fatalf("posts = %v after the store returned", pub.posts)
	}
}

// TestIndeterminatePostIsNeverRetried pins the one-root contract against a
// POST whose outcome is unknown (transport failure after the request may
// have been accepted): without a Slack lookup there is no way to know
// whether a root exists, so the tracker must not post again — a possibly
// missing message is recoverable from logs/audit//health, a duplicate root
// is not.
func TestIndeterminatePostIsNeverRetried(t *testing.T) {
	tr, st, c, a := newTracker(t)
	pub := &fakePub{failPostErr: fmt.Errorf("channel C1: post system message: %w", llmhealth.ErrDeliveryIndeterminate)}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)
	tr.Deliver(context.Background(), pub)

	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryIndeterminate {
		t.Fatalf("durable slack_delivery = %q, want %q", rec.SlackDelivery, llmhealth.DeliveryIndeterminate)
	}
	pub.failPostErr = nil
	c.add(time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 0 {
		t.Fatalf("posts = %v; an indeterminate post must never be retried", pub.posts)
	}
	seen := false
	for _, k := range a.kinds {
		seen = seen || k == "llm.health.slack_indeterminate"
	}
	if !seen {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
}

// ctxAwarePub behaves like the real Slack publisher on a canceled context:
// the transport fails before anything is sent, and — unable to tell that
// apart from a failure after sending — the publisher marks it indeterminate.
type ctxAwarePub struct{ fakePub }

func (p *ctxAwarePub) PostSystemMessage(ctx context.Context, text string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("channel C1: post system message: %w: %w", llmhealth.ErrDeliveryIndeterminate, err)
	}
	return p.fakePub.PostSystemMessage(ctx, text)
}

// TestPreCanceledDeliveryDoesNotSilenceEpisode pins that a Deliver whose ctx
// is already canceled — shutdown racing a queued tick or kick — never commits
// the "post started" marker: no request could have left, so nothing is
// indeterminate, and the episode's one root is still posted by the next live
// step (in this process or the next) instead of being suppressed for good.
func TestPreCanceledDeliveryDoesNotSilenceEpisode(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &ctxAwarePub{}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tr.Deliver(canceled, pub)

	if pub.postCount() != 0 {
		t.Fatalf("posts = %v; nothing may be posted on a canceled context", pub.posts)
	}
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery == llmhealth.DeliveryIndeterminate {
		t.Fatalf("durable slack_delivery = %q after a pre-canceled delivery; the episode is silenced for good", rec.SlackDelivery)
	}

	c.add(time.Minute)
	tr.Deliver(context.Background(), pub)
	if pub.postCount() != 1 {
		t.Fatalf("posts = %v; the live step must post the episode's root exactly once", pub.posts)
	}
}

// TestCrashBetweenPostAndPersistDoesNotRepost pins the durable side of the
// same contract: the "a post is in flight" marker is persisted BEFORE the
// HTTP call, so a process that dies between Slack accepting the message and
// the coordinates being written comes back knowing a root may exist and does
// not post a second one.
func TestCrashBetweenPostAndPersistDoesNotRepost(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	pub := &blockingPub{fakePub: &fakePub{}, started: make(chan struct{}), release: make(chan struct{})}
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	c.add(5 * time.Minute)

	done := make(chan struct{})
	go func() {
		tr.Deliver(context.Background(), pub)
		close(done)
	}()
	<-pub.started

	// "Crash" here: a fresh tracker from the durable state alone.
	rec, _, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.SlackDelivery != llmhealth.DeliveryIndeterminate {
		t.Fatalf("durable slack_delivery while a post is in flight = %q, want %q", rec.SlackDelivery, llmhealth.DeliveryIndeterminate)
	}
	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub2 := &fakePub{}
	c.add(time.Minute)
	tr2.Deliver(context.Background(), pub2)
	if pub2.postCount() != 0 {
		t.Fatalf("restarted tracker posted %v; a root may already exist", pub2.posts)
	}

	close(pub.release)
	<-done
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
