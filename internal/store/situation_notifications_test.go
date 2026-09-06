// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 7 fixtures. Every helper is prefixed `sn` (situation
// notifications) so it never collides with Task 5's `sh` history fixtures
// living in the same package.
// ----------------------------------------------------------------------

const snOwner = "notify-a"

// snCommit runs one real fenced controller commit against sitID and returns
// it. A nil prior means "the Situation's first cycle" (its root has never
// been published); a non-nil prior continues that history with a materially
// changed Operator contract, which is what makes the second cycle produce a
// new root projection plus its own immutable journal entry.
func snCommit(t *testing.T, st *Store, sitID string, prior *situation.ControllerCommit, now time.Time) situation.ControllerCommit {
	t.Helper()
	contract := shRunningTriageContract(now.Add(time.Minute))
	if prior != nil {
		contract = shOperatorContract(now.Add(time.Minute))
	}
	return snCommitWith(t, st, sitID, prior, contract, now)
}

// snCommitWith is snCommit with an explicit Operator contract, so a test can
// choose whether a cycle qualifies as a main-channel poke (an
// OperatorActionRequired appearing for the first time is PokeOperatorHandoff;
// handing the next move back to AlertINT is material but PokeNone).
func snCommitWith(t *testing.T, st *Store, sitID string, prior *situation.ControllerCommit,
	contract situationmodel.ActionContract, now time.Time) situation.ControllerCommit {
	t.Helper()
	if prior != nil {
		shMakeDue(t, st, sitID, now.Add(-time.Minute))
	}
	claim := claimSituation(t, st, sitID, "controller-a", now)
	cycle := shPrepare(t, claim, contract, situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	if prior != nil {
		last := prior.History.Transitions[len(prior.History.Transitions)-1]
		cycle.Change.PriorTransition = &last
		cycle.Change.PriorSummary = prior.History.Summary
		cycle.Publish.PriorTransition = &last
		cycle.Publish.RootPublished = true
	}
	commit := shDerive(t, cycle)
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	return commit
}

// snCommitBelowFloor is snCommit's second-cycle form with an operator Slack
// floor high enough to withhold the poke: the poked Transition then carries
// BOTH a durably withheld broadcast_handoff and the quiet thread_append the
// floor never suppresses (Task 4's `3ab73d6`).
func snCommitBelowFloor(t *testing.T, st *Store, sitID string, prior situation.ControllerCommit,
	now time.Time) situation.ControllerCommit {
	t.Helper()
	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim := claimSituation(t, st, sitID, "controller-a", now)
	cycle := shPrepare(t, claim, shOperatorContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	last := prior.History.Transitions[len(prior.History.Transitions)-1]
	cycle.Change.PriorTransition = &last
	cycle.Change.PriorSummary = prior.History.Summary
	cycle.Publish.PriorTransition = &last
	cycle.Publish.RootPublished = true
	cycle.Publish.SlackFloor = situationmodel.InterruptionCritical
	// The shared fixture anchors every conclusion on the deterministic
	// critical floor, which always passes any floor. Swap in an ordinary
	// Sufficient reason so this poke derives `high` and the operator's
	// critical floor can actually withhold it.
	concl := *cycle.Change.Projection.Assessment
	concl.SufficientReasonCode = "duration_outlier"
	cycle.Change.Projection.Assessment = &concl
	commit := shDerive(t, cycle)
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	return commit
}

// snSeedOneCycle creates a Situation with exactly one committed cycle: a
// pending root_sync plus one immutable thread_append at sequence 1.
func snSeedOneCycle(t *testing.T, st *Store, group string, now time.Time) (string, situation.ControllerCommit) {
	t.Helper()
	sitID := newSituationForGroup(t, st, group, now)
	return sitID, snCommit(t, st, sitID, nil, now)
}

func snIntent(t *testing.T, st *Store, id string) situationmodel.NotificationIntent {
	t.Helper()
	intent, err := st.GetNotificationIntent(context.Background(), id)
	if err != nil {
		t.Fatalf("GetNotificationIntent(%s): %v", id, err)
	}
	return intent
}

// snDeliver acknowledges claim as delivered with plausible coordinates.
func snDeliver(t *testing.T, st *Store, claim situation.NotificationClaim, ts string, now time.Time) {
	t.Helper()
	as := "thread"
	if claim.Intent.EffectClass == situationmodel.EffectRootSync {
		as = "root"
	}
	if err := st.MarkNotificationDelivered(context.Background(), claim,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: ts, DeliveredAs: as}, now); err != nil {
		t.Fatalf("MarkNotificationDelivered(%s): %v", claim.Intent.ID, err)
	}
}

// snClaimOne claims exactly one intent and fails the test when the claim
// returns anything other than one row.
func snClaimOne(t *testing.T, st *Store, now time.Time) situation.NotificationClaim {
	t.Helper()
	claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, now, 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed %d intents, want exactly 1", len(claims))
	}
	return claims[0]
}

func snClasses(claims []situation.NotificationClaim) []string {
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		out = append(out, string(c.Intent.EffectClass))
	}
	return out
}

// ----------------------------------------------------------------------
// Step 1: claim ordering, fencing, heartbeat, release, recovery.
// ----------------------------------------------------------------------

// TestNotificationClaimFencesOwnerTokenAndLease proves the three fences:
// a claim is exclusive while its lease holds, the claim token increases
// monotonically on every (re)claim, and an expired lease is reclaimable by
// a different owner — whose new token fences the old holder out.
func TestNotificationClaimFencesOwnerTokenAndLease(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, _ = snSeedOneCycle(t, st, "group-claim-fence", now)

	first := snClaimOne(t, st, now)
	if first.ClaimOwner != snOwner || first.ClaimToken < 1 {
		t.Fatalf("first claim = %+v, want owner %q and a positive token", first, snOwner)
	}

	// While the lease holds no other owner may take the same head.
	others, err := st.ClaimNotificationIntents(ctx, "notify-b", now.Add(time.Second), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("second ClaimNotificationIntents: %v", err)
	}
	for _, c := range others {
		if c.Intent.ID == first.Intent.ID {
			t.Fatalf("intent %s was claimed twice under a live lease", c.Intent.ID)
		}
	}

	// After the lease expires the row is reclaimable, with a higher token.
	expired := now.Add(6 * time.Minute)
	reclaimed, err := st.ClaimNotificationIntents(ctx, "notify-b", expired, 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].Intent.ID != first.Intent.ID {
		t.Fatalf("reclaimed = %v, want the one expired intent %s", snClasses(reclaimed), first.Intent.ID)
	}
	if reclaimed[0].ClaimToken <= first.ClaimToken {
		t.Fatalf("reclaimed token %d must exceed the expired holder's %d", reclaimed[0].ClaimToken, first.ClaimToken)
	}

	// The original holder is now fenced out of every acknowledgement.
	if err := st.MarkNotificationDelivered(ctx, first,
		situation.NotificationDelivery{Channel: "C", MessageTS: "1.1", DeliveredAs: "root"}, expired); !errors.Is(err, ErrNotificationClaimLost) {
		t.Fatalf("stale delivered ack = %v, want ErrNotificationClaimLost", err)
	}
	if got := snIntent(t, st, first.Intent.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("intent status after a stale ack = %q, want unchanged pending", got.Status)
	}
}

// TestNotificationClaimOrdersRootBeforeJournalThenBySequence pins the
// per-Situation queue: the coalescible root projection first, then the
// immutable journal in Transition-sequence order, exactly one head at a
// time so a later entry can never pass an earlier one.
func TestNotificationClaimOrdersRootBeforeJournalThenBySequence(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-claim-order", now)
	_ = snCommit(t, st, sitID, &first, now.Add(time.Minute))

	// The head is the current root projection, even though sequence 1's
	// journal entry is older.
	root := snClaimOne(t, st, now.Add(2*time.Minute))
	if root.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("head effect class = %q, want root_sync", root.Intent.EffectClass)
	}
	snDeliver(t, st, root, "100.1", now.Add(2*time.Minute))

	// Now the immutable journal drains in sequence order, one at a time.
	seen := []int{}
	for i := 0; i < 4; i++ {
		at := now.Add(time.Duration(3+i) * time.Minute)
		claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, at, 5*time.Minute, 25)
		if err != nil {
			t.Fatalf("claim round %d: %v", i, err)
		}
		if len(claims) == 0 {
			break
		}
		if len(claims) != 1 {
			t.Fatalf("claim round %d returned %d intents, want at most the one Situation head", i, len(claims))
		}
		c := claims[0]
		if c.Intent.TransitionSequence == nil {
			t.Fatalf("journal claim %s has no transition sequence", c.Intent.ID)
		}
		seen = append(seen, *c.Intent.TransitionSequence)
		snDeliver(t, st, c, "20"+string(rune('0'+i))+".1", at)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			t.Fatalf("journal delivered out of Transition-sequence order: %v", seen)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("expected at least both journal entries to drain, got %v", seen)
	}
}

// TestNotificationClaimWaitsForDurableRoot proves a reply is not claimable
// — and so consumes no delivery attempt — until the Situation's root
// coordinates are durably published.
func TestNotificationClaimWaitsForDurableRoot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, commit := snSeedOneCycle(t, st, "group-claim-root-dep", now)
	thread := shIntentOfClass(t, commit.History.Intents, situationmodel.EffectThreadAppend)

	// Block the root out of the queue so the reply is the only candidate.
	root := snClaimOne(t, st, now)
	if root.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("head = %q, want root_sync", root.Intent.EffectClass)
	}
	if err := st.RetryNotificationIntent(ctx, root, "ratelimited", now.Add(time.Hour)); err != nil {
		t.Fatalf("RetryNotificationIntent: %v", err)
	}

	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(time.Minute), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %v while the root is undelivered, want nothing", snClasses(claims))
	}
	if got := snIntent(t, st, thread.ID); got.AttemptCount != 0 {
		t.Fatalf("root-dependent reply attempt_count = %d, want 0 (it never became claimable)", got.AttemptCount)
	}
	if _, _, ok, err := st.GetSituationRootCoordinates(ctx, sitID); err != nil || ok {
		t.Fatalf("GetSituationRootCoordinates before delivery = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

// TestNotificationClaimHonorsRetryScheduleWithoutReordering proves a later
// journal entry cannot pass an earlier pending one that is merely waiting
// out its retry delay.
func TestNotificationClaimHonorsRetryScheduleWithoutReordering(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-claim-retry-order", now)
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))

	root := snClaimOne(t, st, now.Add(2*time.Minute))
	snDeliver(t, st, root, "100.1", now.Add(2*time.Minute))

	earlier := snClaimOne(t, st, now.Add(3*time.Minute))
	if got := *earlier.Intent.TransitionSequence; got != 1 {
		t.Fatalf("first journal head sequence = %d, want 1", got)
	}
	if err := st.RetryNotificationIntent(ctx, earlier, "ratelimited", now.Add(time.Hour)); err != nil {
		t.Fatalf("RetryNotificationIntent: %v", err)
	}
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(4*time.Minute), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %v while sequence 1 waits out its retry, want nothing", snClasses(claims))
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND status = 'pending'`, sitID); n < 2 {
		t.Fatalf("pending intents = %d, want the held-back journal entries of both cycles", n)
	}
	_ = second
}

// TestNotificationClaimRespectsBatchLimit proves the limit bounds one claim
// round across Situations.
func TestNotificationClaimRespectsBatchLimit(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		snSeedOneCycle(t, st, "group-claim-batch-"+string(rune('a'+i)), now)
	}
	claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, now, 5*time.Minute, 2)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("claimed %d intents with limit 2, want 2", len(claims))
	}
}

// TestNotificationClaimRecoversAbandonedClaims proves a crashed worker's
// expired lease is swept back to unclaimed and is then reclaimable.
func TestNotificationClaimRecoversAbandonedClaims(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, _ = snSeedOneCycle(t, st, "group-claim-abandoned", now)

	claim := snClaimOne(t, st, now)
	if n, err := st.RecoverExpiredNotificationClaims(ctx, now.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("RecoverExpiredNotificationClaims before expiry = (%d, %v), want (0, nil)", n, err)
	}
	n, err := st.RecoverExpiredNotificationClaims(ctx, now.Add(6*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("RecoverExpiredNotificationClaims after expiry = (%d, %v), want (1, nil)", n, err)
	}
	recovered := snIntent(t, st, claim.Intent.ID)
	if recovered.ClaimOwner != nil || recovered.LeaseExpiresAt != nil {
		t.Fatalf("recovered intent still holds a claim: %+v", recovered)
	}
	if recovered.Status != situationmodel.IntentPending {
		t.Fatalf("recovered intent status = %q, want pending", recovered.Status)
	}
	if err := st.HeartbeatNotificationClaim(ctx, claim, now.Add(7*time.Minute), 5*time.Minute); !errors.Is(err, ErrNotificationClaimLost) {
		t.Fatalf("heartbeat after recovery = %v, want ErrNotificationClaimLost", err)
	}
}

// ----------------------------------------------------------------------
// Step 1: acknowledgement transitions.
// ----------------------------------------------------------------------

// TestNotificationAckDeliveredWritesRootCoordinates proves root coordinates
// land only when the matching fenced root delivery is acknowledged, and
// that the acknowledgement unblocks the Situation's dependent history.
func TestNotificationAckDeliveredWritesRootCoordinates(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, _ := snSeedOneCycle(t, st, "group-ack-root", now)

	root := snClaimOne(t, st, now)
	snDeliver(t, st, root, "100.1", now)

	channel, ts, ok, err := st.GetSituationRootCoordinates(ctx, sitID)
	if err != nil || !ok || channel != "C-sit" || ts != "100.1" {
		t.Fatalf("root coordinates = (%q,%q,%v,%v), want (C-sit,100.1,true,nil)", channel, ts, ok, err)
	}
	stored := snIntent(t, st, root.Intent.ID)
	if stored.Status != situationmodel.IntentDelivered || stored.DeliveredAt == nil ||
		stored.Channel == nil || stored.MessageTS == nil || stored.DeliveredAs == nil {
		t.Fatalf("delivered intent = %+v, want a complete delivered record", stored)
	}
	if stored.ClaimOwner != nil || stored.LeaseExpiresAt != nil {
		t.Fatalf("delivered intent still holds a claim: %+v", stored)
	}
	next := snClaimOne(t, st, now.Add(time.Second))
	if next.Intent.EffectClass != situationmodel.EffectThreadAppend {
		t.Fatalf("next claim = %q, want the now-unblocked thread_append", next.Intent.EffectClass)
	}
}

// TestNotificationAckStaleAcknowledgementChangesZeroRows walks every
// acknowledgement with a claim whose token has moved on and proves each one
// changes nothing.
func TestNotificationAckStaleAcknowledgementChangesZeroRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, _ = snSeedOneCycle(t, st, "group-ack-stale", now)

	claim := snClaimOne(t, st, now)
	stale := claim
	stale.ClaimToken = claim.ClaimToken + 41

	acks := map[string]func() error{
		"delivered": func() error {
			return st.MarkNotificationDelivered(ctx, stale,
				situation.NotificationDelivery{Channel: "C", MessageTS: "9.9", DeliveredAs: "root"}, now)
		},
		"retry":     func() error { return st.RetryNotificationIntent(ctx, stale, "ratelimited", now.Add(time.Minute)) },
		"blocked":   func() error { return st.BlockNotificationConfiguration(ctx, stale, "invalid_auth", now) },
		"failed":    func() error { return st.FailNotificationIntent(ctx, stale, "invalid_payload", now) },
		"heartbeat": func() error { return st.HeartbeatNotificationClaim(ctx, stale, now, 5*time.Minute) },
		"release":   func() error { return st.ReleaseNotificationClaim(ctx, stale, now) },
	}
	before := snIntent(t, st, claim.Intent.ID)
	for name, ack := range acks {
		if err := ack(); !errors.Is(err, ErrNotificationClaimLost) {
			t.Fatalf("stale %s ack = %v, want ErrNotificationClaimLost", name, err)
		}
		after := snIntent(t, st, claim.Intent.ID)
		if after.Status != before.Status || after.AttemptCount != before.AttemptCount ||
			after.ClaimToken != before.ClaimToken {
			t.Fatalf("stale %s ack changed durable state: %+v -> %+v", name, before, after)
		}
	}
}

// TestNotificationAckHeartbeatAndReleaseKeepTheIntentClaimable proves a
// heartbeat moves the lease deadline without changing status, and a clean
// release hands the row straight back.
func TestNotificationAckHeartbeatAndReleaseKeepTheIntentClaimable(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, _ = snSeedOneCycle(t, st, "group-ack-heartbeat", now)

	claim := snClaimOne(t, st, now)
	if err := st.HeartbeatNotificationClaim(ctx, claim, now.Add(30*time.Second), 5*time.Minute); err != nil {
		t.Fatalf("HeartbeatNotificationClaim: %v", err)
	}
	beat := snIntent(t, st, claim.Intent.ID)
	if beat.Status != situationmodel.IntentPending || beat.LeaseExpiresAt == nil ||
		!beat.LeaseExpiresAt.After(now.Add(5*time.Minute)) {
		t.Fatalf("heartbeat left %+v, want pending with an extended lease", beat)
	}
	if err := st.ReleaseNotificationClaim(ctx, claim, now.Add(time.Minute)); err != nil {
		t.Fatalf("ReleaseNotificationClaim: %v", err)
	}
	released := snIntent(t, st, claim.Intent.ID)
	if released.ClaimOwner != nil || released.LeaseExpiresAt != nil || released.Status != situationmodel.IntentPending {
		t.Fatalf("released intent = %+v, want pending and unclaimed", released)
	}
	again := snClaimOne(t, st, now.Add(2*time.Minute))
	if again.Intent.ID != claim.Intent.ID {
		t.Fatalf("reclaimed %s, want the released %s", again.Intent.ID, claim.Intent.ID)
	}
}

// TestNotificationAckRetryBlockAndFailPreserveAttempts pins the three
// non-delivery outcomes: retry keeps the intent pending with a due time,
// configuration blocking is durable with no retry time, and failure is
// terminal-until-redriven. None of them ever resets the attempt count.
func TestNotificationAckRetryBlockAndFailPreserveAttempts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, _ = snSeedOneCycle(t, st, "group-ack-outcomes", now)

	first := snClaimOne(t, st, now)
	if first.Intent.AttemptCount != 1 {
		t.Fatalf("first claim attempt_count = %d, want 1", first.Intent.AttemptCount)
	}
	if err := st.RetryNotificationIntent(ctx, first, "ratelimited", now.Add(5*time.Second)); err != nil {
		t.Fatalf("RetryNotificationIntent: %v", err)
	}
	retried := snIntent(t, st, first.Intent.ID)
	if retried.Status != situationmodel.IntentPending || retried.RetryAt == nil || retried.AttemptCount != 1 {
		t.Fatalf("retried intent = %+v, want pending with retry_at and attempt_count 1", retried)
	}
	if retried.LastErrorClass == nil || *retried.LastErrorClass != "ratelimited" {
		t.Fatalf("retried last_error_class = %v, want ratelimited", retried.LastErrorClass)
	}

	second := snClaimOne(t, st, now.Add(10*time.Second))
	if second.Intent.AttemptCount != 2 {
		t.Fatalf("second claim attempt_count = %d, want 2", second.Intent.AttemptCount)
	}
	if err := st.BlockNotificationConfiguration(ctx, second, "invalid_auth", now.Add(10*time.Second)); err != nil {
		t.Fatalf("BlockNotificationConfiguration: %v", err)
	}
	blocked := snIntent(t, st, second.Intent.ID)
	if blocked.Status != situationmodel.IntentBlockedConfiguration || blocked.AttemptCount != 2 ||
		blocked.RetryAt != nil || blocked.ClaimOwner != nil {
		t.Fatalf("blocked intent = %+v, want durable blocked_configuration keeping attempts", blocked)
	}
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(time.Hour), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	for _, c := range claims {
		if c.Intent.ID == second.Intent.ID {
			t.Fatal("a blocked_configuration intent must not be claimable")
		}
	}

	// Reactivate, then prove an invalid payload fails terminally.
	if n, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("ReactivateConfigurationBlocked = (%d, %v), want (1, nil)", n, err)
	}
	third := snClaimOne(t, st, now.Add(2*time.Hour))
	if third.Intent.AttemptCount != 3 {
		t.Fatalf("post-reactivation attempt_count = %d, want the preserved 3", third.Intent.AttemptCount)
	}
	if err := st.FailNotificationIntent(ctx, third, "invalid_payload", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("FailNotificationIntent: %v", err)
	}
	failed := snIntent(t, st, third.Intent.ID)
	if failed.Status != situationmodel.IntentFailed || failed.RetryAt != nil || failed.AttemptCount != 3 {
		t.Fatalf("failed intent = %+v, want failed with no retry time and attempts preserved", failed)
	}
}

// TestNotificationAckRedrivenRootReleasesDependentHistory pins the spec's
// "a failed root never causes later effects to dead-letter in a chain":
// the dependents wait, and become claimable once the same root is explicitly
// redriven and delivered.
func TestNotificationAckRedrivenRootReleasesDependentHistory(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, commit := snSeedOneCycle(t, st, "group-ack-redrive", now)
	thread := shIntentOfClass(t, commit.History.Intents, situationmodel.EffectThreadAppend)

	root := snClaimOne(t, st, now)
	if err := st.FailNotificationIntent(ctx, root, "invalid_payload", now); err != nil {
		t.Fatalf("FailNotificationIntent: %v", err)
	}
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(time.Minute), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %v behind a failed root, want nothing (dependents wait, never dead-letter)", snClasses(claims))
	}
	if got := snIntent(t, st, thread.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("dependent journal entry status = %q, want an untouched pending", got.Status)
	}

	if err := st.RedriveFailedNotificationIntent(ctx, root.Intent.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("RedriveFailedNotificationIntent: %v", err)
	}
	redriven := snClaimOne(t, st, now.Add(3*time.Minute))
	if redriven.Intent.ID != root.Intent.ID || redriven.Intent.AttemptCount != 2 {
		t.Fatalf("redriven claim = %+v, want the same root with its attempts preserved", redriven.Intent)
	}
	snDeliver(t, st, redriven, "100.1", now.Add(3*time.Minute))

	released := snClaimOne(t, st, now.Add(4*time.Minute))
	if released.Intent.ID != thread.ID {
		t.Fatalf("post-redrive claim = %s, want the previously blocked journal entry %s", released.Intent.ID, thread.ID)
	}
}

// ----------------------------------------------------------------------
// Step 2: supersession and revalidation.
// ----------------------------------------------------------------------

// TestNotificationSupersessionTakesTheClaimFromAnInFlightRootSync is the
// Task 5 handoff (R4): a concurrent authoritative commit may supersede the
// exact root projection this worker is mid-flight on. The acknowledgement
// must be refused, distinguishably, without corrupting anything.
func TestNotificationSupersessionTakesTheClaimFromAnInFlightRootSync(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-supersede-inflight", now)

	claim := snClaimOne(t, st, now)
	if claim.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("head = %q, want root_sync", claim.Intent.EffectClass)
	}

	// A concurrent controller commit supersedes exactly this projection.
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))

	superseded := snIntent(t, st, claim.Intent.ID)
	if superseded.Status != situationmodel.IntentSuperseded {
		t.Fatalf("in-flight root status = %q, want superseded", superseded.Status)
	}
	if superseded.ClaimOwner != nil || superseded.LeaseExpiresAt != nil {
		t.Fatalf("superseded root still carries a claim: %+v", superseded)
	}

	err := st.MarkNotificationDelivered(ctx, claim,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "100.1", DeliveredAs: "root"}, now.Add(2*time.Minute))
	if !errors.Is(err, ErrNotificationIntentSuperseded) {
		t.Fatalf("delivered ack on a superseded root = %v, want ErrNotificationIntentSuperseded", err)
	}
	after := snIntent(t, st, claim.Intent.ID)
	if after.Status != situationmodel.IntentSuperseded || after.DeliveredAt != nil {
		t.Fatalf("superseded root after its ack = %+v, want the row itself untouched", after)
	}
	// The post Slack accepted IS the Situation's root: its coordinates are
	// kept so the replacement edits it rather than posting a second one
	// (review round 1, R1-F3).
	if _, ts, ok, err := st.GetSituationRootCoordinates(ctx, sitID); err != nil || !ok || ts != "100.1" {
		t.Fatalf("root coordinates after the superseded first post's ack = (ok=%v, ts=%q, err=%v), want (true, 100.1, nil)", ok, ts, err)
	}

	// The replacement projection is the claimable head, and its own
	// delivery edits that same root.
	next := snClaimOne(t, st, now.Add(3*time.Minute))
	replacement := shIntentOfClass(t, second.History.Intents, situationmodel.EffectRootSync)
	if next.Intent.ID != replacement.ID {
		t.Fatalf("next head = %s, want the replacement root %s", next.Intent.ID, replacement.ID)
	}
	snDeliver(t, st, next, "100.1", now.Add(3*time.Minute))
}

// TestNotificationSupersessionLeavesImmutableEntriesAndOtherEpisodes proves
// a newer root projection coalesces only the older root of its own
// Situation: immutable journal entries and other Situations' pending work
// are untouched.
func TestNotificationSupersessionLeavesImmutableEntriesAndOtherEpisodes(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-supersede-scope", now)
	otherID, otherCommit := snSeedOneCycle(t, st, "group-supersede-other", now)

	firstThread := shIntentOfClass(t, first.History.Intents, situationmodel.EffectThreadAppend)
	otherRoot := shIntentOfClass(t, otherCommit.History.Intents, situationmodel.EffectRootSync)

	_ = snCommit(t, st, sitID, &first, now.Add(time.Minute))

	if got := snIntent(t, st, firstThread.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("immutable journal entry status = %q, want pending (never superseded)", got.Status)
	}
	if got := snIntent(t, st, otherRoot.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("other Situation's root status = %q, want an untouched pending", got.Status)
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE status = 'superseded'`); n != 1 {
		t.Fatalf("superseded rows = %d, want exactly the one replaced root projection", n)
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND status = 'superseded'`, otherID); n != 0 {
		t.Fatalf("other Situation had %d superseded intents, want 0", n)
	}
}

// TestNotificationSupersessionRecordsDelayedThreadDelivery pins the durable
// half of the stale-handoff rule: a revalidated-stale broadcast is recorded
// as a delayed_thread delivery, never as a broadcast.
func TestNotificationSupersessionRecordsDelayedThreadDelivery(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	_, commit := snSeedOneCycle(t, st, "group-supersede-delayed", now)
	thread := shIntentOfClass(t, commit.History.Intents, situationmodel.EffectThreadAppend)

	root := snClaimOne(t, st, now)
	snDeliver(t, st, root, "100.1", now)
	entry := snClaimOne(t, st, now.Add(time.Second))
	if entry.Intent.ID != thread.ID {
		t.Fatalf("claimed %s, want the journal entry %s", entry.Intent.ID, thread.ID)
	}
	if err := st.MarkNotificationDelivered(ctx, entry,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "100.2", DeliveredAs: "delayed_thread"},
		now.Add(time.Second)); err != nil {
		t.Fatalf("MarkNotificationDelivered(delayed_thread): %v", err)
	}
	stored := snIntent(t, st, thread.ID)
	if stored.DeliveredAs == nil || *stored.DeliveredAs != "delayed_thread" {
		t.Fatalf("delivered_as = %v, want delayed_thread", stored.DeliveredAs)
	}
	// A journal delivery never rewrites the Situation's root coordinates.
	_, ts, ok, err := st.GetSituationRootCoordinates(ctx, *stored.SituationID)
	if err != nil || !ok || ts != "100.1" {
		t.Fatalf("root coordinates = (%q,%v,%v), want the root's own 100.1", ts, ok, err)
	}
}

// TestNotificationClaimNeverClaimsAFloorWithheldEffect pins the one shape
// where a Transition still carries two intents after Task 4's `3ab73d6`: a
// poke below the operator's Slack floor keeps a durably withheld
// broadcast_handoff AND the quiet thread_append the floor never suppresses.
// The withheld decision must never become claimable — only the quiet entry
// is ever delivered — and the withheld row must not shadow it in its own
// Situation's queue.
func TestNotificationClaimNeverClaimsAFloorWithheldEffect(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-claim-withheld", now)
	second := snCommitBelowFloor(t, st, sitID, first, now.Add(time.Minute))

	withheld := shIntentOfClass(t, second.History.Intents, situationmodel.EffectBroadcastHandoff)
	if withheld.Status != situationmodel.IntentWithheld {
		t.Fatalf("broadcast below the Slack floor has status %q, want withheld_by_operator_slack_floor", withheld.Status)
	}
	quiet := shIntentOfClass(t, second.History.Intents, situationmodel.EffectThreadAppend)
	if quiet.TransitionSequence == nil || withheld.TransitionSequence == nil ||
		*quiet.TransitionSequence != *withheld.TransitionSequence {
		t.Fatalf("the withheld broadcast and its quiet entry must share one Transition sequence: %v vs %v",
			withheld.TransitionSequence, quiet.TransitionSequence)
	}

	// Drain the Situation, proving the withheld row is never handed out and
	// never blocks the queue behind it.
	claimed := []string{}
	for round := 0; round < 6; round++ {
		at := now.Add(time.Duration(2+round) * time.Minute)
		claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, at, 5*time.Minute, 25)
		if err != nil {
			t.Fatalf("claim round %d: %v", round, err)
		}
		if len(claims) == 0 {
			break
		}
		for i, c := range claims {
			if c.Intent.ID == withheld.ID {
				t.Fatal("a withheld_by_operator_slack_floor intent was claimed")
			}
			claimed = append(claimed, c.Intent.ID)
			snDeliver(t, st, c, "30"+string(rune('0'+round))+"."+string(rune('0'+i)), at)
		}
	}
	var sawQuiet bool
	for _, id := range claimed {
		if id == quiet.ID {
			sawQuiet = true
		}
	}
	if !sawQuiet {
		t.Fatalf("claimed %v, want the quiet journal entry %s to have been delivered", claimed, quiet.ID)
	}
	if got := snIntent(t, st, withheld.ID); got.Status != situationmodel.IntentWithheld || got.AttemptCount != 0 {
		t.Fatalf("withheld intent = %+v, want an untouched durable decision with no attempts", got)
	}
}

// TestNotificationClaimOrdersJournalBySequenceAcrossEffectClasses is the
// regression for a claim order that ranked effect class ABOVE Transition
// sequence: every thread_append then sorted ahead of every
// broadcast_handoff, so an older poke could be delivered after newer quiet
// entries. spec.md's ordering is "immutable journal replies deliver in
// Transition-sequence order" — the only class ordering it requires is that
// the root projection precede its replies.
//
// The fixture is deliberately the one shape the earlier ordering tests did
// not have: a broadcast_handoff at a LOWER sequence than a pending
// thread_append.
func TestNotificationClaimOrdersJournalBySequenceAcrossEffectClasses(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-claim-class-order", now)
	// Cycle 2 hands the next move to an operator: a poke, so its journal
	// entry is a broadcast_handoff at sequence 2.
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))
	// Cycle 3 takes the next move back: material, but PokeNone, so its
	// journal entry is a quiet thread_append at sequence 3.
	_ = snCommitWith(t, st, sitID, &second, shRunningTriageContract(now.Add(3*time.Minute)), now.Add(2*time.Minute))

	root := snClaimOne(t, st, now.Add(4*time.Minute))
	if root.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("head = %q, want the root projection first", root.Intent.EffectClass)
	}
	snDeliver(t, st, root, "100.1", now.Add(4*time.Minute))

	type entry struct {
		sequence int
		class    string
	}
	got := []entry{}
	for round := 0; round < 5; round++ {
		at := now.Add(time.Duration(5+round) * time.Minute)
		claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, at, 5*time.Minute, 25)
		if err != nil {
			t.Fatalf("claim round %d: %v", round, err)
		}
		if len(claims) == 0 {
			break
		}
		c := claims[0]
		got = append(got, entry{sequence: *c.Intent.TransitionSequence, class: string(c.Intent.EffectClass)})
		snDeliver(t, st, c, "10"+string(rune('0'+round))+".2", at)
	}
	want := []entry{
		{sequence: 1, class: "thread_append"},
		{sequence: 2, class: "broadcast_handoff"},
		{sequence: 3, class: "thread_append"},
	}
	if len(got) != len(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivered %v, want %v — the immutable journal must drain in Transition-sequence order, "+
				"never with every quiet entry ahead of an older broadcast", got, want)
		}
	}
	_ = sitID
}

// TestNotificationAckReactivationKeepsOnePendingRootProjection is the
// regression for a reactivation that returned EVERY blocked intent to
// pending in one statement: when a Situation had both a blocked root_sync
// and a newer pending one, that violated migration 0018's
// notification_intents_root_sync_pending_idx, rolled the whole transaction
// back, and left the configuration generation unadvanced — so nothing
// reactivated for any Situation, permanently.
//
// Case A: the newest projection is already pending. It renders the current
// state, so the older blocked one is a resolved outcome (migration 0018's
// own words) and stays blocked; reactivation must still succeed for
// everything else.
func TestNotificationAckReactivationKeepsOnePendingRootProjection(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-ack-reactivate-newer", now)
	firstRoot := shIntentOfClass(t, first.History.Intents, situationmodel.EffectRootSync)

	blocked := snClaimOne(t, st, now)
	if blocked.Intent.ID != firstRoot.ID {
		t.Fatalf("claimed %s, want the first root %s", blocked.Intent.ID, firstRoot.ID)
	}
	if err := st.BlockNotificationConfiguration(ctx, blocked, "channel_not_found", now); err != nil {
		t.Fatalf("BlockNotificationConfiguration: %v", err)
	}
	// A later material commit inserts a NEW root projection and supersedes
	// the blocked one at commit: an obsolete root is never left holding
	// its Situation's queue.
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))
	secondRoot := shIntentOfClass(t, second.History.Intents, situationmodel.EffectRootSync)
	if older := snIntent(t, st, firstRoot.ID); older.Status != situationmodel.IntentSuperseded ||
		older.ReplacementIntentID == nil || *older.ReplacementIntentID != secondRoot.ID {
		t.Fatalf("blocked root after a newer commit = %q (replacement %v), want superseded by %s",
			older.Status, older.ReplacementIntentID, secondRoot.ID)
	}

	n, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ReactivateConfigurationBlocked with a newer pending root: %v", err)
	}
	if n != 0 {
		t.Fatalf("reactivated %d root projections, want 0 — the newer pending one already renders current state", n)
	}
	if got := snIntent(t, st, secondRoot.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("newer root status = %q, want pending", got.Status)
	}
	if got := snIntent(t, st, firstRoot.ID); got.Status == situationmodel.IntentPending {
		t.Fatal("the superseded blocked root must not be returned to pending")
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`,
		sitID); n != 1 {
		t.Fatalf("pending root projections = %d, want exactly 1", n)
	}
	// The configuration generation really advanced, so the whole
	// reactivation transaction committed.
	if state := snState(t, st); state.ConfigurationGeneration != 1 {
		t.Fatalf("configuration generation = %d, want the advanced 1", state.ConfigurationGeneration)
	}
}

// Case B: every live root projection for the Situation is blocked. The
// newest is the one corrected configuration should deliver; the older ones
// are coalesced into it, exactly as a newer projection always coalesces an
// older one.
func TestNotificationAckReactivationCoalescesOlderBlockedRootProjections(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-ack-reactivate-both", now)
	firstRoot := shIntentOfClass(t, first.History.Intents, situationmodel.EffectRootSync)

	blocked := snClaimOne(t, st, now)
	if err := st.BlockNotificationConfiguration(ctx, blocked, "channel_not_found", now); err != nil {
		t.Fatalf("BlockNotificationConfiguration: %v", err)
	}
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))
	secondRoot := shIntentOfClass(t, second.History.Intents, situationmodel.EffectRootSync)
	blockedAgain := snClaimOne(t, st, now.Add(2*time.Minute))
	if blockedAgain.Intent.ID != secondRoot.ID {
		t.Fatalf("claimed %s, want the second root %s", blockedAgain.Intent.ID, secondRoot.ID)
	}
	if err := st.BlockNotificationConfiguration(ctx, blockedAgain, "channel_not_found", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("BlockNotificationConfiguration: %v", err)
	}

	n, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("ReactivateConfigurationBlocked with two blocked roots: %v", err)
	}
	if n < 1 {
		t.Fatalf("reactivated %d intents, want at least the newest root projection", n)
	}
	if got := snIntent(t, st, secondRoot.ID); got.Status != situationmodel.IntentPending {
		t.Fatalf("newest root status = %q, want pending", got.Status)
	}
	older := snIntent(t, st, firstRoot.ID)
	if older.Status != situationmodel.IntentSuperseded {
		t.Fatalf("older root status = %q, want superseded by the newest projection", older.Status)
	}
	if older.ReplacementIntentID == nil || *older.ReplacementIntentID != secondRoot.ID {
		t.Fatalf("older root replacement = %v, want %q", older.ReplacementIntentID, secondRoot.ID)
	}
	if older.SupersessionReason == nil || *older.SupersessionReason == "" {
		t.Fatal("a superseded root projection must record why")
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`,
		sitID); n != 1 {
		t.Fatalf("pending root projections = %d, want exactly 1", n)
	}
	// The reactivated root really is claimable and deliverable.
	claim := snClaimOne(t, st, now.Add(4*time.Minute))
	if claim.Intent.ID != secondRoot.ID {
		t.Fatalf("claimed %s after reactivation, want the reactivated root %s", claim.Intent.ID, secondRoot.ID)
	}
}

// TestNotificationAckFailedRootIsSupersededByANewerProjection proves a
// failed root projection is not a permanent blocker: the next commit's
// projection supersedes it at commit and is itself claimable at the head
// of the queue (a failed row holds the queue until then — see
// TestNotificationClaimBlockedRootEditHoldsItsHandoff), so a later valid
// projection repairs the Situation with no operator redrive. The
// superseded row is then no longer failed and cannot be redriven — the
// obligation lives in its replacement.
func TestNotificationAckFailedRootIsSupersededByANewerProjection(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-ack-redrive-newer", now)
	firstRoot := shIntentOfClass(t, first.History.Intents, situationmodel.EffectRootSync)

	failed := snClaimOne(t, st, now)
	if err := st.FailNotificationIntent(ctx, failed, "invalid_payload", now); err != nil {
		t.Fatalf("FailNotificationIntent: %v", err)
	}
	// The failed root holds the queue: its dependent journal entry is not
	// claimable behind it.
	if claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(30*time.Second), time.Minute, 25); err != nil || len(claims) != 0 {
		t.Fatalf("claimed %v behind a failed root (err=%v), want nothing", snClasses(claims), err)
	}
	second := snCommit(t, st, sitID, &first, now.Add(time.Minute))
	secondRoot := shIntentOfClass(t, second.History.Intents, situationmodel.EffectRootSync)

	older := snIntent(t, st, firstRoot.ID)
	if older.Status != situationmodel.IntentSuperseded || older.ReplacementIntentID == nil || *older.ReplacementIntentID != secondRoot.ID {
		t.Fatalf("failed root after a newer commit = %q (replacement %v), want superseded by %s",
			older.Status, older.ReplacementIntentID, secondRoot.ID)
	}
	if err := st.RedriveFailedNotificationIntent(ctx, firstRoot.ID, now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("redrive of a superseded root = %v, want ErrNotFound: it is no longer failed", err)
	}
	claim := snClaimOne(t, st, now.Add(2*time.Minute))
	if claim.Intent.ID != secondRoot.ID {
		t.Fatalf("claimed %s, want the replacement root %s at the head of the queue", claim.Intent.ID, secondRoot.ID)
	}
}

// TestCommitWithheldRootRetiresThePendingRootItReplaces proves migration
// 0018's "one live root projection per Situation" survives a replacement
// the operator's Slack floor withheld. Superseding only when the newer
// projection is itself deliverable would leave the older, now-stale one
// pending forever: it claims ahead of every reply its Situation owns, fails
// its pre-I/O summary-version check on every attempt, and nothing ever
// supersedes it — stranding the Situation's whole later history behind a
// root that can never deliver.
func TestCommitWithheldRootRetiresThePendingRootItReplaces(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-withheld-root", now)
	queued := shIntentOfClass(t, first.History.Intents, situationmodel.EffectRootSync)
	if queued.Status != situationmodel.IntentPending {
		t.Fatalf("seeded root projection has status %q, want pending", queued.Status)
	}

	// A second cycle whose first publication falls below the operator's
	// floor. The publication context is supplied directly here, so this
	// exercises the LEDGER's own invariant rather than the planner's.
	later := now.Add(10 * time.Minute)
	shMakeDue(t, st, sitID, later.Add(-time.Minute))
	claim := claimSituation(t, st, sitID, "controller-a", later)
	cycle := shPrepare(t, claim, shOperatorContract(later.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, later)
	last := first.History.Transitions[len(first.History.Transitions)-1]
	cycle.Change.PriorTransition = &last
	cycle.Change.PriorSummary = first.History.Summary
	cycle.Publish.PriorTransition = &last
	cycle.Publish.SlackFloor = situationmodel.InterruptionCritical
	concl := *cycle.Change.Projection.Assessment
	concl.SufficientReasonCode = "duration_outlier"
	cycle.Change.Projection.Assessment = &concl

	commit := shDerive(t, cycle)
	withheld := shIntentOfClass(t, commit.History.Intents, situationmodel.EffectRootSync)
	if withheld.Status != situationmodel.IntentWithheld {
		t.Fatalf("replacement root projection has status %q, want withheld_by_operator_slack_floor", withheld.Status)
	}
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	retired := snIntent(t, st, queued.ID)
	if retired.Status != situationmodel.IntentSuperseded {
		t.Fatalf("the replaced root projection has status %q, want superseded", retired.Status)
	}
	if retired.ReplacementIntentID == nil || *retired.ReplacementIntentID != withheld.ID {
		t.Fatalf("replacement_intent_id = %v, want the withheld replacement %s", retired.ReplacementIntentID, withheld.ID)
	}
	if retired.SupersessionReason == nil || *retired.SupersessionReason == "" {
		t.Fatal("a superseded root projection must record why")
	}
	if retired.ClaimOwner != nil || retired.LeaseExpiresAt != nil || retired.RetryAt != nil {
		t.Fatalf("a superseded root projection keeps no claim or retry state: %+v", retired)
	}

	var pending int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM notification_intents
		WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`, sitID).Scan(&pending); err != nil {
		t.Fatalf("count pending root projections: %v", err)
	}
	if pending != 0 {
		t.Fatalf("%d root projection(s) still pending behind a withheld replacement", pending)
	}
}

// ----------------------------------------------------------------------
// In-flight supersession keeps a successful first post (review round 1,
// R1-F3).
// ----------------------------------------------------------------------

func TestMarkNotificationDeliveredSupersededFirstPostKeepsCoordinates(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	id, first := snSeedOneCycle(t, st, "review-inflight-post", now)
	posted := snClaimOne(t, st, now)
	if posted.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("claimed %s, want the first root projection", posted.Intent.EffectClass)
	}
	// Slack accepts the first post, but another controller commit replaces
	// its projection before the success response is acknowledged.
	snCommit(t, st, id, &first, now.Add(time.Second))
	err := st.MarkNotificationDelivered(ctx, posted,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "100.1", DeliveredAs: "root"}, now.Add(2*time.Second))
	if !errors.Is(err, ErrNotificationIntentSuperseded) {
		t.Fatalf("ack error = %v, want ErrNotificationIntentSuperseded: the row itself stays superseded", err)
	}
	_, ts, ok, readErr := st.GetSituationRootCoordinates(ctx, id)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !ok || ts != "100.1" {
		t.Fatalf("successful first post lost coordinates after supersession: published=%v ts=%q; the replacement would post a second root", ok, ts)
	}
	if got := snIntent(t, st, posted.Intent.ID).Status; got != situationmodel.IntentSuperseded {
		t.Fatalf("superseded row status = %s, want superseded (never delivered)", got)
	}
	// The replacement projection now edits that root: it is claimable and
	// its delivery lands on the same coordinates.
	replacement := snClaimOne(t, st, now.Add(3*time.Second))
	if replacement.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("claimed %s, want the replacement root projection", replacement.Intent.EffectClass)
	}
	snDeliver(t, st, replacement, "100.1", now.Add(4*time.Second))
	if _, ts, _, err := st.GetSituationRootCoordinates(ctx, id); err != nil || ts != "100.1" {
		t.Fatalf("root coordinates = %q (err=%v) after the replacement delivered, want the first post's 100.1", ts, err)
	}
}

func TestMarkNotificationDeliveredSupersededAckFromAStaleHolderWritesNothing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	id, first := snSeedOneCycle(t, st, "review-stale-holder", now)
	stale := snClaimOne(t, st, now)
	// The stale holder's five-minute lease expires and a second worker
	// reclaims the same projection (a new claim token); only then is it
	// superseded.
	if _, err := st.RecoverExpiredNotificationClaims(ctx, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	fresh := snClaimOne(t, st, now.Add(6*time.Minute))
	if fresh.ClaimToken == stale.ClaimToken {
		t.Fatal("fixture: the reclaim did not advance the claim token")
	}
	snCommit(t, st, id, &first, now.Add(7*time.Minute))
	err := st.MarkNotificationDelivered(ctx, stale,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "77.7", DeliveredAs: "root"}, now.Add(8*time.Minute))
	if !errors.Is(err, ErrNotificationIntentSuperseded) {
		t.Fatalf("ack error = %v, want ErrNotificationIntentSuperseded", err)
	}
	if _, _, ok, _ := st.GetSituationRootCoordinates(ctx, id); ok {
		t.Fatal("a stale holder's acknowledgement wrote root coordinates; only the last claim holder may")
	}
}

func TestMarkNotificationDeliveredSupersededEditNeverMovesTheRoot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	id, first := snSeedOneCycle(t, st, "review-superseded-edit", now)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now)
	snDeliver(t, st, snClaimOne(t, st, now), "100.2", now)
	second := snCommit(t, st, id, &first, now.Add(time.Minute))
	edit := snClaimOne(t, st, now.Add(time.Minute))
	if edit.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("claimed %s, want the root edit", edit.Intent.EffectClass)
	}
	// A third material commit (the contract hands the next move back to
	// AlertINT) replaces the claimed edit's projection mid-flight.
	snCommitWith(t, st, id, &second, shRunningTriageContract(now.Add(3*time.Minute)), now.Add(2*time.Minute))
	err := st.MarkNotificationDelivered(ctx, edit,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "100.1", DeliveredAs: "root"}, now.Add(3*time.Minute))
	if !errors.Is(err, ErrNotificationIntentSuperseded) {
		t.Fatalf("ack error = %v, want ErrNotificationIntentSuperseded", err)
	}
	if _, ts, _, _ := st.GetSituationRootCoordinates(ctx, id); ts != "100.1" {
		t.Fatalf("root coordinates = %q, want the original 100.1: an edit never re-anchors a root", ts)
	}
}

// ----------------------------------------------------------------------
// Blocked and failed effects hold the queue (review round 1, R1-F2).
// ----------------------------------------------------------------------

func TestNotificationClaimBlockedRootEditHoldsItsHandoff(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	id, first := snSeedOneCycle(t, st, "review-blocked-edit", now)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now)
	snDeliver(t, st, snClaimOne(t, st, now), "100.2", now)
	now = now.Add(time.Minute)
	snCommit(t, st, id, &first, now)
	root := snClaimOne(t, st, now)
	if root.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatal("expected root edit")
	}
	if err := st.BlockNotificationConfiguration(ctx, root, "missing_scope", now); err != nil {
		t.Fatal(err)
	}
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now, time.Minute, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %v before its blocked root edit was delivered: an existing timestamp proves a root exists, not that this projection reached it", snClasses(claims))
	}
	// Corrected configuration returns the edit to pending; it delivers
	// FIRST, and only then is the handoff claimable.
	if _, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	edit := snClaimOne(t, st, now.Add(time.Minute))
	if edit.Intent.ID != root.Intent.ID {
		t.Fatalf("claimed %s after reactivation, want the reactivated root edit %s", edit.Intent.ID, root.Intent.ID)
	}
	snDeliver(t, st, edit, "100.1", now.Add(time.Minute))
	handoff := snClaimOne(t, st, now.Add(2*time.Minute))
	if handoff.Intent.EffectClass != situationmodel.EffectBroadcastHandoff {
		t.Fatalf("claimed %s after the root edit delivered, want the handoff", handoff.Intent.EffectClass)
	}
}

func TestNotificationClaimBlockedReplyHoldsLaterHistoryInOrder(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	id, first := snSeedOneCycle(t, st, "review-blocked-reply", now)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now) // root
	reply1 := snClaimOne(t, st, now)                       // journal entry #1
	if reply1.Intent.EffectClass != situationmodel.EffectThreadAppend {
		t.Fatalf("claimed %s, want the first journal entry", reply1.Intent.EffectClass)
	}
	if err := st.BlockNotificationConfiguration(ctx, reply1, "channel_not_found", now); err != nil {
		t.Fatal(err)
	}
	// A later commit (an operator handoff) adds a root edit and a newer
	// journal effect. The root edit is claimable (root projections come
	// first); the newer effect is not, because the blocked older entry
	// holds the queue.
	now = now.Add(time.Minute)
	snCommit(t, st, id, &first, now)
	edit := snClaimOne(t, st, now)
	if edit.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("claimed %s, want the root edit", edit.Intent.EffectClass)
	}
	snDeliver(t, st, edit, "100.1", now)
	if claims, err := st.ClaimNotificationIntents(ctx, snOwner, now, time.Minute, 25); err != nil || len(claims) != 0 {
		t.Fatalf("claimed %v behind a blocked older journal entry (err=%v); reactivation must never deliver newer history before older", snClasses(claims), err)
	}
	if _, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(time.Minute), 5*time.Minute, 25)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claimed %d after reactivation (err=%v), want the older entry:%s", len(claims), err, snDump(t, st))
	}
	older := claims[0]
	if older.Intent.ID != reply1.Intent.ID {
		t.Fatalf("claimed %s after reactivation, want the older entry %s first", older.Intent.ID, reply1.Intent.ID)
	}
	snDeliver(t, st, older, "100.3", now.Add(time.Minute))
	newer := snClaimOne(t, st, now.Add(2*time.Minute))
	if newer.Intent.EffectClass == situationmodel.EffectRootSync || *newer.Intent.TransitionSequence <= *reply1.Intent.TransitionSequence {
		t.Fatalf("claimed %s #%d after the older entry delivered, want the newer journal effect",
			newer.Intent.EffectClass, *newer.Intent.TransitionSequence)
	}
}

// snDump renders every notification intent as one line per row, for
// failure messages.
func snDump(t *testing.T, st *Store) string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), `
		SELECT id, effect_class, status, COALESCE(transition_sequence, 0), COALESCE(retry_at, ''), COALESCE(claim_owner, ''),
		       COALESCE(last_error_class, ''), requires_root
		FROM notification_intents ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("dump intents: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out strings.Builder
	for rows.Next() {
		var id, class, status, retryAt, owner, errClass string
		var seq, requiresRoot int
		if err := rows.Scan(&id, &class, &status, &seq, &retryAt, &owner, &errClass, &requiresRoot); err != nil {
			t.Fatalf("scan intent: %v", err)
		}
		fmt.Fprintf(&out, "\n  %s class=%s status=%s seq=%d retry_at=%q owner=%q err=%q requires_root=%d",
			id[:8], class, status, seq, retryAt, owner, errClass, requiresRoot)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate intents: %v", err)
	}
	return out.String()
}

// ----------------------------------------------------------------------
// The claim poll never scans resolved history (review round 2, R2-F3).
// ----------------------------------------------------------------------

func TestNotificationClaimQueryUsesTheLiveIndex(t *testing.T) {
	st := newTestStore(t)
	rows, err := st.db.QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+notificationClaimRankingQuery,
		"2026-09-06T10:00:00Z", "2026-09-06T10:00:00Z", 25)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if strings.Contains(detail, "SCAN ni") {
			t.Errorf("claim poll scans notification history rather than an index restricted to live statuses: %s", detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "notification_intents_live_idx") {
		t.Fatalf("claim poll does not use notification_intents_live_idx:\n%s", strings.Join(plan, "\n"))
	}
}

// ----------------------------------------------------------------------
// Reactivation coalesces older live roots whatever the keeper's status
// (review round 2, R2-F4).
// ----------------------------------------------------------------------

func TestNotificationReactivationRetiresAnOlderBlockedRootBehindADeliveredOne(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reactivate-delivered.db")
	blockedRootID, deliveredRootID := seedMigration19SupersedeFixture(t, path)
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	n, err := st.ReactivateConfigurationBlocked(ctx, 1, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("reactivated %d root projections, want 0: the delivered newer projection is the root on screen", n)
	}
	older := snIntent(t, st, blockedRootID)
	if older.Status != situationmodel.IntentSuperseded || older.ReplacementIntentID == nil || *older.ReplacementIntentID != deliveredRootID {
		t.Fatalf("pre-upgrade blocked root after reactivation = %q (replacement %v), want superseded by the delivered %s: an obsolete root must never be revived",
			older.Status, older.ReplacementIntentID, deliveredRootID)
	}
	if got := snIntent(t, st, deliveredRootID); got.Status != situationmodel.IntentDelivered || got.MessageTS == nil {
		t.Fatalf("delivered root after reactivation = %+v, want its delivered outcome untouched", got)
	}
}
