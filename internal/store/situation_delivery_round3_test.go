// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-3 repair regressions (lead review round 2, 2026-09-09, R2),
// against the real SQLite store, the real derivation/planner, the real
// fenced CommitController transaction and the real claim/acknowledge
// surface.
//
// A delivered obstacle whose clearance is still queued left the operator's
// standing state ambiguous: the delivered fold said "limited", the owed
// fold said nothing, and unioning the two hid a genuine recurrence behind
// a correction that had not been sent yet. The ordered fold over both is
// what the eligibility rule needs.
// ----------------------------------------------------------------------

// b5r3Drain delivers every intent currently claimable, root first, exactly
// as an ordinary worker round would.
func b5r3Drain(t *testing.T, st *Store, now time.Time) int {
	t.Helper()
	claims, err := st.ClaimNotificationIntents(context.Background(), snOwner, now, 5*time.Minute, 25)
	if err != nil {
		t.Fatalf("ClaimNotificationIntents: %v", err)
	}
	for _, c := range claims {
		snDeliver(t, st, c, "100.1", now.Add(time.Second))
	}
	return len(claims)
}

// b5r3DrainAll repeats a worker round until nothing is claimable — a reply
// only becomes claimable once its root has been delivered.
func b5r3DrainAll(t *testing.T, st *Store, now time.Time) {
	t.Helper()
	for i := 0; i < 5; i++ {
		if b5r3Drain(t, st, now.Add(time.Duration(i)*2*time.Second)) == 0 {
			return
		}
	}
	t.Fatal("delivery backlog did not drain in five worker rounds")
}

// b5r3Limited is the briefing that records an unavailable member analysis.
func b5r3Limited() *model.OperatorBriefing {
	b := b5r2Brief()
	b.Unavailable = 1
	return b
}

// R2/1: appearance delivered, clearance still owed, obstacle recorded
// again. The recurrence is real: an ordinary ordered drain would otherwise
// end on the clearance and leave the operator believing coverage is whole.
func TestB5RecurringObstacleBehindAnOwedClearanceStillEarnsAReply(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r3-recurrence", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	obstacle := osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r3Limited(), true)
	if n := b5r2PendingReplies(t, st, id, obstacle.ID); n != 1 {
		t.Fatalf("fixture: the obstacle earned %d replies, want 1", n)
	}
	b5r3DrainAll(t, st, now.Add(70*time.Second))

	cleared := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if n := b5r2PendingReplies(t, st, id, cleared.ID); n != 1 {
		t.Fatalf("fixture: the clearance must be owed and undelivered, got %d pending replies", n)
	}

	again := osCycle(t, st, id, now.Add(3*time.Minute), osMonitoringContract(now.Add(4*time.Minute)),
		model.LifecycleActive, b5r3Limited(), true)
	if n := b5r2PendingReplies(t, st, id, again.ID); n != 1 {
		t.Fatalf("the recurring obstacle earned %d replies; the owed clearance would be the operator's last word", n)
	}
}

// R2/2: the durable representation itself. What the operator HAS been told
// and what they will be looking at once the queue drains are two different
// answers, and only the second decides eligibility.
func TestB5CommunicatedAndStandingHistoryAreDistinct(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r3-standing", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))
	osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r3Limited(), true)
	b5r3DrainAll(t, st, now.Add(70*time.Second))

	delivered := b5r2History(t, st, id)
	if !containsUnavailable(delivered.CommunicatedLimitationCodes) ||
		!containsUnavailable(delivered.ProjectedLimitationCodes) {
		t.Fatalf("a delivered obstacle with nothing queued against it is both communicated and standing: %+v", delivered)
	}

	osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)

	owed := b5r2History(t, st, id)
	if !containsUnavailable(owed.CommunicatedLimitationCodes) {
		t.Fatalf("the delivered obstacle is still what the operator has actually been told: %+v", owed)
	}
	if containsUnavailable(owed.ProjectedLimitationCodes) {
		t.Fatalf("a queued clearance must cancel the delivered appearance in the standing state: %+v", owed)
	}
}

// R2/3, restart: the standing state is derived from durable rows alone, so
// a process restart between the owed clearance and the recurrence changes
// nothing.
func TestB5StandingHistorySurvivesARestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "b5r3-restart.db")

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id := newSituationForGroup(t, st, "b5r3-restart", now)
	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))
	osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r3Limited(), true)
	b5r3DrainAll(t, st, now.Add(70*time.Second))
	osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	h := b5r2History(t, reopened, id)
	if containsUnavailable(h.ProjectedLimitationCodes) {
		t.Fatalf("the owed clearance was forgotten across the restart: %+v", h)
	}
	again := osCycle(t, reopened, id, now.Add(3*time.Minute), osMonitoringContract(now.Add(4*time.Minute)),
		model.LifecycleActive, b5r3Limited(), true)
	if n := b5r2PendingReplies(t, reopened, id, again.ID); n != 1 {
		t.Fatalf("after the restart the recurring obstacle earned %d replies, want 1", n)
	}
}

// R2/4, the action boundary through the same durable path: a delivered
// operator request whose withdrawal is already queued leaves no standing
// request, so a further withdrawal corrects nothing — while the request
// being required again is always news.
func TestB5OwedWithdrawalLeavesNoStandingRequest(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r3-action", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	required := osCycle(t, st, id, now.Add(time.Minute), shOperatorContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if !b5r3HasActionCandidate(required, false) {
		t.Fatalf("fixture: the operator request produced no action candidate: %+v", required.Projection.OperatorDelta)
	}
	b5r3DrainAll(t, st, now.Add(70*time.Second))

	withdrawn := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if !b5r3HasActionCandidate(withdrawn, true) {
		t.Fatalf("fixture: dropping the operator request produced no withdrawal candidate: %+v", withdrawn.Projection.OperatorDelta)
	}
	if n := b5r2PendingReplies(t, st, id, withdrawn.ID); n != 1 {
		t.Fatalf("fixture: the withdrawal must be owed and undelivered, got %d pending replies", n)
	}

	h := b5r2History(t, st, id)
	if h.CommunicatedAction == nil {
		t.Fatalf("the delivered request is still what the operator has been told: %+v", h)
	}
	if h.ProjectedAction != nil {
		t.Fatalf("a queued withdrawal must leave no standing request: %+v", h)
	}
	// The real predicate against that real history: nothing left to correct.
	action := model.OperatorActionInvestigateSituation
	second := []model.MaterialCandidate{{Kind: model.CandidateActionChanged,
		Action: &model.ActionFacts{Action: action, Withdrawn: true}}}
	if got := situation.ReplyEligible(second, h, true); len(got) != 0 {
		t.Fatalf("a second withdrawal was planned against an already-withdrawn request: %+v", got)
	}

	// Requiring the action again is new information either way.
	reintroduced := osCycle(t, st, id, now.Add(3*time.Minute), shOperatorContract(now.Add(4*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if n := b5r2PendingReplies(t, st, id, reintroduced.ID); n != 1 {
		t.Fatalf("the renewed operator request earned %d replies, want 1", n)
	}
}

func b5r3HasActionCandidate(tr model.Transition, withdrawn bool) bool {
	d := tr.Projection.OperatorDelta
	if d == nil {
		return false
	}
	for _, c := range d.Candidates {
		if c.Kind == model.CandidateActionChanged && c.Action != nil && c.Action.Withdrawn == withdrawn {
			return true
		}
	}
	return false
}
