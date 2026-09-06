// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 7, Steps 5-6: the durable Delivery-gap lifecycle.
// ----------------------------------------------------------------------

const snGapThreshold = 5 * time.Minute

func snState(t *testing.T, st *Store) situation.SlackDeliveryState {
	t.Helper()
	state, err := st.GetSlackDeliveryState(context.Background())
	if err != nil {
		t.Fatalf("GetSlackDeliveryState: %v", err)
	}
	return state
}

func snFail(t *testing.T, st *Store, at time.Time) {
	t.Helper()
	if err := st.ObserveSlackFailure(context.Background(), "ratelimited", at); err != nil {
		t.Fatalf("ObserveSlackFailure: %v", err)
	}
}

// TestDeliveryGapFirstFailureOpensOneContinuousWindow proves the first
// retryable failure stores first_failure_at, later failures leave that
// instant alone (the window is continuous, not sliding), and the durable
// warning marker is stamped exactly once.
func TestDeliveryGapFirstFailureOpensOneContinuousWindow(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)

	if got := snState(t, st); got.FirstFailureAt != nil {
		t.Fatalf("fresh delivery state first_failure_at = %v, want nil", got.FirstFailureAt)
	}
	snFail(t, st, now)
	first := snState(t, st)
	if first.FirstFailureAt == nil || !first.FirstFailureAt.Equal(now) {
		t.Fatalf("first_failure_at = %v, want %s", first.FirstFailureAt, now)
	}
	if first.LastWarningAt == nil || !first.LastWarningAt.Equal(now) {
		t.Fatalf("last_warning_at = %v, want the one bounded first-failure warning at %s", first.LastWarningAt, now)
	}
	snFail(t, st, now.Add(time.Minute))
	again := snState(t, st)
	if !again.FirstFailureAt.Equal(now) {
		t.Fatalf("first_failure_at moved to %v; the window must stay anchored at %s", again.FirstFailureAt, now)
	}
}

// TestDeliveryGapDoesNotOpenBeforeFiveContinuousMinutes pins the exact
// threshold: 4m59s of continuous failure is still an ordinary delay.
func TestDeliveryGapDoesNotOpenBeforeFiveContinuousMinutes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snFail(t, st, now)

	opened, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold-time.Second), snGapThreshold)
	if err != nil || opened {
		t.Fatalf("OpenDueDeliveryGap at 4m59s = (%v, %v), want (false, nil)", opened, err)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM slack_delivery_gaps`); n != 0 {
		t.Fatalf("gap generations before the threshold = %d, want 0", n)
	}
	opened, err = st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold)
	if err != nil || !opened {
		t.Fatalf("OpenDueDeliveryGap at exactly 5m = (%v, %v), want (true, nil)", opened, err)
	}
	// Idempotent: a second call while the same generation is open opens none.
	opened, err = st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold+time.Minute), snGapThreshold)
	if err != nil || opened {
		t.Fatalf("second OpenDueDeliveryGap = (%v, %v), want (false, nil)", opened, err)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM slack_delivery_gaps`); n != 1 {
		t.Fatalf("gap generations = %d, want exactly 1", n)
	}
}

// TestDeliveryGapSuccessResetsTheOrdinaryFailureWindow proves an
// intervening success makes the next failure start a fresh window, so
// intermittent failures never accumulate into a gap.
func TestDeliveryGapSuccessResetsTheOrdinaryFailureWindow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)

	snFail(t, st, now)
	if err := st.ObserveSlackSuccess(ctx, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("ObserveSlackSuccess: %v", err)
	}
	cleared := snState(t, st)
	if cleared.FirstFailureAt != nil {
		t.Fatalf("first_failure_at after a success = %v, want nil", cleared.FirstFailureAt)
	}
	if cleared.LastSuccessAt == nil || !cleared.LastSuccessAt.Equal(now.Add(4*time.Minute)) {
		t.Fatalf("last_success_at = %v, want the success instant", cleared.LastSuccessAt)
	}
	snFail(t, st, now.Add(4*time.Minute+time.Second))
	opened, err := st.OpenDueDeliveryGap(ctx, now.Add(8*time.Minute), snGapThreshold)
	if err != nil || opened {
		t.Fatalf("OpenDueDeliveryGap 4m into the second window = (%v, %v), want (false, nil)", opened, err)
	}
}

// TestDeliveryGapOpenRecordsAffectedBacklog proves the generation records
// the delayed backlog it is opening over, and that its rendering facts read
// back through GetDeliveryGap.
func TestDeliveryGapOpenRecordsAffectedBacklog(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snSeedOneCycle(t, st, "group-gap-open-a", now)
	snSeedOneCycle(t, st, "group-gap-open-b", now)

	snFail(t, st, now)
	if opened, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold); err != nil || !opened {
		t.Fatalf("OpenDueDeliveryGap = (%v, %v), want (true, nil)", opened, err)
	}
	state := snState(t, st)
	if state.OpenGapGeneration == nil || state.OpenGapStatus != "open" {
		t.Fatalf("delivery state = %+v, want an open gap generation", state)
	}
	gap, err := st.GetDeliveryGap(ctx, *state.OpenGapGeneration)
	if err != nil {
		t.Fatalf("GetDeliveryGap: %v", err)
	}
	if !gap.OpenedAt.Equal(now) {
		t.Fatalf("gap opened_at = %s, want the first failure instant %s", gap.OpenedAt, now)
	}
	if gap.AffectedSituationCount != 2 {
		t.Fatalf("affected situation count = %d, want 2", gap.AffectedSituationCount)
	}
	if gap.DelayedEffectCount < 4 {
		t.Fatalf("delayed effect count = %d, want every pending intent of both Situations", gap.DelayedEffectCount)
	}
	// While a gap is open nothing at all is claimable: Slack is down and
	// the recovery notice must precede the backlog.
	claims, err := st.ClaimNotificationIntents(ctx, snOwner, now.Add(snGapThreshold), 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("claimed %v inside an open gap, want nothing", snClasses(claims))
	}
}

// TestDeliveryGapRecoveryCreatesOneNoticeAheadOfTheBacklog proves recovery
// moves the generation to replaying, creates exactly one
// installation_gap_recovery intent, and blocks every backlog claim until
// that notice is delivered.
func TestDeliveryGapRecoveryCreatesOneNoticeAheadOfTheBacklog(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snSeedOneCycle(t, st, "group-gap-recover", now)

	snFail(t, st, now)
	if _, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold); err != nil {
		t.Fatalf("OpenDueDeliveryGap: %v", err)
	}
	recoveredAt := now.Add(7 * time.Minute)
	generation, ok, err := st.RecoverDeliveryGap(ctx, recoveredAt)
	if err != nil || !ok || generation == "" {
		t.Fatalf("RecoverDeliveryGap = (%q, %v, %v), want a recovered generation", generation, ok, err)
	}
	// Idempotent: nothing left to recover.
	if _, again, err := st.RecoverDeliveryGap(ctx, recoveredAt.Add(time.Minute)); err != nil || again {
		t.Fatalf("second RecoverDeliveryGap = (%v, %v), want (false, nil)", again, err)
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE effect_class = 'installation_gap_recovery'`); n != 1 {
		t.Fatalf("recovery notices = %d, want exactly 1 per generation", n)
	}

	notice := snClaimOne(t, st, recoveredAt.Add(time.Second))
	if notice.Intent.EffectClass != situationmodel.EffectInstallationGapRecovery {
		t.Fatalf("claim while replaying = %q, want only the recovery notice", notice.Intent.EffectClass)
	}
	if notice.Intent.GapGeneration == nil || *notice.Intent.GapGeneration != generation {
		t.Fatalf("recovery notice gap generation = %v, want %q", notice.Intent.GapGeneration, generation)
	}
	if err := st.MarkNotificationDelivered(ctx, notice,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "70.7", DeliveredAs: "system"},
		recoveredAt.Add(time.Second)); err != nil {
		t.Fatalf("MarkNotificationDelivered(notice): %v", err)
	}

	backlog := snClaimOne(t, st, recoveredAt.Add(2*time.Second))
	if backlog.Intent.EffectClass != situationmodel.EffectRootSync {
		t.Fatalf("post-notice claim = %q, want the Situation's latest root projection", backlog.Intent.EffectClass)
	}
}

// TestDeliveryGapReplayCompletesOnlyWhenTheBacklogDrains proves the
// generation stays replaying until nothing replayable remains, and that
// work created after recovery never holds it open.
func TestDeliveryGapReplayCompletesOnlyWhenTheBacklogDrains(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, first := snSeedOneCycle(t, st, "group-gap-replay", now)

	snFail(t, st, now)
	if _, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold); err != nil {
		t.Fatalf("OpenDueDeliveryGap: %v", err)
	}
	recoveredAt := now.Add(7 * time.Minute)
	generation, _, err := st.RecoverDeliveryGap(ctx, recoveredAt)
	if err != nil {
		t.Fatalf("RecoverDeliveryGap: %v", err)
	}

	at := recoveredAt
	for round := 0; round < 6; round++ {
		at = at.Add(time.Second)
		claims, err := st.ClaimNotificationIntents(ctx, snOwner, at, 5*time.Minute, 25)
		if err != nil {
			t.Fatalf("claim round %d: %v", round, err)
		}
		if len(claims) == 0 {
			break
		}
		// Work is still outstanding, so the generation may not complete.
		if _, done, err := st.CompleteDeliveryGap(ctx, at); err != nil {
			t.Fatalf("CompleteDeliveryGap: %v", err)
		} else if done {
			t.Fatalf("generation completed while %d replayable intents were still in flight", len(claims))
		}
		for i, c := range claims {
			snDeliver(t, st, c, "10"+string(rune('0'+round))+"."+string(rune('0'+i)), at)
		}
	}

	completed, done, err := st.CompleteDeliveryGap(ctx, at.Add(time.Minute))
	if err != nil || !done || completed != generation {
		t.Fatalf("CompleteDeliveryGap with a drained backlog = (%q, %v, %v), want (%q, true, nil)",
			completed, done, err, generation)
	}
	var status string
	if err := st.db.QueryRowContext(ctx, `SELECT status FROM slack_delivery_gaps WHERE id = ?`, generation).
		Scan(&status); err != nil {
		t.Fatalf("read gap status: %v", err)
	}
	if status != "complete" {
		t.Fatalf("gap status = %q, want complete", status)
	}
	if state := snState(t, st); state.OpenGapGeneration != nil {
		t.Fatalf("delivery state still names gap %v after completion", state.OpenGapGeneration)
	}
	// New work committed after recovery is ordinary delivery, not replay.
	_ = snCommit(t, st, sitID, &first, at.Add(2*time.Minute))
	if _, done, err := st.CompleteDeliveryGap(ctx, at.Add(3*time.Minute)); err != nil || done {
		t.Fatalf("CompleteDeliveryGap after completion = (%v, %v), want (false, nil)", done, err)
	}
}

// TestDeliveryGapReplaySecondOutageStartsADistinctGeneration proves a
// failure during replay does not reuse or reopen the first generation: it
// needs its own continuous five-minute window and gets its own identity.
func TestDeliveryGapReplaySecondOutageStartsADistinctGeneration(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snSeedOneCycle(t, st, "group-gap-second", now)

	snFail(t, st, now)
	if _, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold); err != nil {
		t.Fatalf("OpenDueDeliveryGap: %v", err)
	}
	firstGeneration, _, err := st.RecoverDeliveryGap(ctx, now.Add(7*time.Minute))
	if err != nil {
		t.Fatalf("RecoverDeliveryGap: %v", err)
	}
	// The recovery notice lands: a real delivery success closes the first
	// outage's window.
	if err := st.ObserveSlackSuccess(ctx, now.Add(7*time.Minute+30*time.Second)); err != nil {
		t.Fatalf("ObserveSlackSuccess: %v", err)
	}

	// Slack fails again mid-replay.
	secondWindow := now.Add(8 * time.Minute)
	snFail(t, st, secondWindow)
	if opened, err := st.OpenDueDeliveryGap(ctx, secondWindow.Add(snGapThreshold-time.Second), snGapThreshold); err != nil || opened {
		t.Fatalf("second gap before its own five minutes = (%v, %v), want (false, nil)", opened, err)
	}
	opened, err := st.OpenDueDeliveryGap(ctx, secondWindow.Add(snGapThreshold), snGapThreshold)
	if err != nil || !opened {
		t.Fatalf("second gap at its own five minutes = (%v, %v), want (true, nil)", opened, err)
	}
	state := snState(t, st)
	if state.OpenGapGeneration == nil || *state.OpenGapGeneration == firstGeneration {
		t.Fatalf("open gap generation = %v, want a distinct generation from %q", state.OpenGapGeneration, firstGeneration)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM slack_delivery_gaps`); n != 2 {
		t.Fatalf("gap generations = %d, want 2 distinct ones", n)
	}
}

// TestDeliveryGapRecoveryKeepsTheFailureWindowUntilAWriteLands proves a
// readiness probe's recovery does not close the failure window: while the
// recovery notice keeps failing, the same outage keeps naming the same
// generation and no second one opens (review round 1, R1-F4).
func TestDeliveryGapRecoveryKeepsTheFailureWindowUntilAWriteLands(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snSeedOneCycle(t, st, "group-gap-keep-window", now)

	snFail(t, st, now)
	if _, err := st.OpenDueDeliveryGap(ctx, now.Add(snGapThreshold), snGapThreshold); err != nil {
		t.Fatalf("OpenDueDeliveryGap: %v", err)
	}
	if _, ok, err := st.RecoverDeliveryGap(ctx, now.Add(7*time.Minute)); err != nil || !ok {
		t.Fatalf("RecoverDeliveryGap = (%v, %v), want recovered", ok, err)
	}
	state := snState(t, st)
	if state.FirstFailureAt == nil || !state.FirstFailureAt.Equal(now) {
		t.Fatalf("first_failure_at after recovery = %v, want the original anchor %s: a token probe is not a delivery success", state.FirstFailureAt, now)
	}
	if state.OpenGapStatus != "replaying" {
		t.Fatalf("gap status after recovery = %q, want replaying", state.OpenGapStatus)
	}
	// The notice keeps failing for well over five more minutes: same
	// outage, same generation, no second one.
	snFail(t, st, now.Add(8*time.Minute))
	snFail(t, st, now.Add(14*time.Minute))
	if opened, err := st.OpenDueDeliveryGap(ctx, now.Add(15*time.Minute), snGapThreshold); err != nil || opened {
		t.Fatalf("OpenDueDeliveryGap while the recovered outage continues = (%v, %v), want (false, nil)", opened, err)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM slack_delivery_gaps`); n != 1 {
		t.Fatalf("gap generations = %d, want exactly 1 for one continuous outage", n)
	}
	// The notice finally lands; the window closes and a LATER failure
	// starts a fresh window of its own.
	if err := st.ObserveSlackSuccess(ctx, now.Add(16*time.Minute)); err != nil {
		t.Fatalf("ObserveSlackSuccess: %v", err)
	}
	if snState(t, st).FirstFailureAt != nil {
		t.Fatal("a delivery success must close the failure window")
	}
	snFail(t, st, now.Add(17*time.Minute))
	if opened, err := st.OpenDueDeliveryGap(ctx, now.Add(17*time.Minute+snGapThreshold), snGapThreshold); err != nil || !opened {
		t.Fatalf("OpenDueDeliveryGap for a second outage after a real success = (%v, %v), want (true, nil)", opened, err)
	}
}

// TestDeliveryGapConfigurationGenerationReactivatesBlockedIntents proves
// corrected startup configuration increments the durable configuration
// generation and returns blocked intents to pending exactly once.
func TestDeliveryGapConfigurationGenerationReactivatesBlockedIntents(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	snSeedOneCycle(t, st, "group-gap-config", now)

	claim := snClaimOne(t, st, now)
	if err := st.BlockNotificationConfiguration(ctx, claim, "invalid_auth", now); err != nil {
		t.Fatalf("BlockNotificationConfiguration: %v", err)
	}
	state := snState(t, st)
	if state.BlockedConfigurationCount != 1 {
		t.Fatalf("blocked configuration count = %d, want 1", state.BlockedConfigurationCount)
	}
	if state.ConfigurationGeneration != 0 {
		t.Fatalf("initial configuration generation = %d, want 0", state.ConfigurationGeneration)
	}

	n, err := st.ReactivateConfigurationBlocked(ctx, state.ConfigurationGeneration+1, now.Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("ReactivateConfigurationBlocked = (%d, %v), want (1, nil)", n, err)
	}
	bumped := snState(t, st)
	if bumped.ConfigurationGeneration != 1 || bumped.BlockedConfigurationCount != 0 {
		t.Fatalf("delivery state after reactivation = %+v, want generation 1 and no blocked intents", bumped)
	}
	// Replaying the same generation is a no-op, so a restart loop can never
	// reactivate the same correction twice.
	if n, err := st.ReactivateConfigurationBlocked(ctx, 1, now.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("replayed ReactivateConfigurationBlocked = (%d, %v), want (0, nil)", n, err)
	}
	reactivated := snIntent(t, st, claim.Intent.ID)
	if reactivated.Status != situationmodel.IntentPending || reactivated.AttemptCount != 1 {
		t.Fatalf("reactivated intent = %+v, want pending with its attempts preserved", reactivated)
	}
}
