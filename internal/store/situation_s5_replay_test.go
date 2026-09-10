// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B6 (deterministic acceptance, S5-01/S5-02): the canonical slide-5 R3
// seven-event drill, reproduced against the real SQLite store, the real
// derivation/planner and the real fenced CommitController transaction —
// the same real-store boundary every B5 round validated its design
// against. Event facts and illustrative target text are taken directly
// from replay/replayTargets in the frozen canonical HTML (03-situation-
// history-slack-ownership/2026-09-07-situation-state-map.html, SHA-256
// 60c255596f9e7fc96f616a30216edd35afc76ec8c3dba48793c816a06be28fbd):
//
//  1. 15:09:09 First root arrives            — Active 4/4 firing, no reply
//  2. 15:10:33 Investigation starts           — one earned assurance reply
//  3. 15:10:58 Finding published              — one earned finding reply
//  4. 15:11:29 One of four clears             — one earned members-changed reply
//  5. 15:13:29 Quiet status checks            — root refresh only, no reply
//  6. 15:13:58 All four clear                 — one earned all-clear reply
//  7. 15:15:59 Recovery confirmed             — one earned terminal-end reply
//
// S5-02's "stays at four" claim is tested as two independent variants of
// event 2: TestS5ReplayRedundantFirstRootStaysAtFour (the root is not
// published until execution has already started, so the root itself
// conveys it) and TestS5ReplayFindingOvertakesUndeliveredStartStaysAtFour
// (the assurance is queued but not yet delivered when the finding
// commits, so the SAME fenced transaction supersedes it). The delivered
// variant (TestS5ReplayDeliveredAssuranceReachesFive) is the illustrative
// target row 2 explicitly calls out: "This adds one reply only under
// those conditions; it was not posted in R3."
//
// §7 (status-check fallback): the illustrative target's bracketed
// "update by [recorded update deadline]" copy is the explicitly NOT-
// implemented `update-delayed` promise (spec.md, integration-contract.md
// §7); this suite asserts the real rendered status-check wording never
// contains "update by" anywhere in the sequence, mirroring
// cmd/alertint's TestSituationSlackE2ENeverRendersAnUnsupportedUpdatePromise.
// ----------------------------------------------------------------------

const (
	s5PodCrashLooping = "PodCrashLooping"
	s5LatencyP99      = "LatencyP99"
	s5HighErrorRate   = "HighErrorRate"
	s5QueueBacklog    = "QueueBacklog"
)

// s5FourFiring is the R3 root cause group: four alerts, all firing. IDs
// are the stable identity briefingAlertDelta diffs on — Name alone is a
// display detail, not the comparison key.
func s5FourFiring() []model.BriefingAlert {
	return []model.BriefingAlert{
		{ID: "a1", Name: s5PodCrashLooping, State: "firing"},
		{ID: "a2", Name: s5LatencyP99, State: "firing"},
		{ID: "a3", Name: s5HighErrorRate, State: "firing"},
		{ID: "a4", Name: s5QueueBacklog, State: "firing"},
	}
}

// s5Event1 is the awaiting root: no work has started yet.
func s5Event1() *model.OperatorBriefing {
	return &model.OperatorBriefing{Scope: "checkout", Alerts: s5FourFiring(), Firing: 4, Total: 4}
}

// s5Event2 records that the bounded investigation actually claimed and
// started against all four recorded alerts — the frozen investigation
// input names slide 4's "running" edge requires, never a Situation total.
func s5Event2() *model.OperatorBriefing {
	b := s5Event1()
	b.Work = model.WorkProjection{
		ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
		InvestigatedAlertIDs: []string{"a1", "a2", "a3", "a4"},
		InvestigatedNames:    []string{s5PodCrashLooping, s5LatencyP99, s5HighErrorRate, s5QueueBacklog},
		InvestigatedCount:    4, InvestigatedCountKnown: true,
	}
	return b
}

// s5Event3 is the accepted finding; the investigation has nothing else
// outstanding, so Work settles at the same commit (R3: "current":"Monitoring").
func s5Event3() *model.OperatorBriefing {
	b := s5Event2()
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{
		IncidentID: "i-checkout", Summary: "pod crash -> error spike -> queue backlog",
		Findings: []string{"Pod restarts precede the error-rate spike", "Queue backlog follows the error spike"},
	}}
	return b
}

// s5Event4 is the recorded partial recovery: QueueBacklog resolved, the
// other three remain firing. The retained finding is unchanged.
func s5Event4() *model.OperatorBriefing {
	b := s5Event3()
	b.Alerts = []model.BriefingAlert{
		{ID: "a1", Name: s5PodCrashLooping, State: "firing"},
		{ID: "a2", Name: s5LatencyP99, State: "firing"},
		{ID: "a3", Name: s5HighErrorRate, State: "firing"},
		{ID: "a4", Name: s5QueueBacklog, State: "resolved"},
	}
	b.Firing, b.Resolved, b.Total = 3, 1, 4
	return b
}

// s5Event5 is byte-for-byte identical to event 4: only the root's status-
// checkpoint deadline moves. No candidate compares checkpoint times, so
// this earns nothing.
func s5Event5() *model.OperatorBriefing { return s5Event4() }

// s5Event6 is the recorded all-clear: every monitored alert has resolved.
func s5Event6(grace time.Time) *model.OperatorBriefing {
	b := s5Event4()
	b.Alerts = []model.BriefingAlert{
		{ID: "a1", Name: s5PodCrashLooping, State: "resolved"}, {ID: "a2", Name: s5LatencyP99, State: "resolved"},
		{ID: "a3", Name: s5HighErrorRate, State: "resolved"}, {ID: "a4", Name: s5QueueBacklog, State: "resolved"},
	}
	b.Firing, b.Resolved = 0, 4
	b.Work.SourceGraceUntil = timePtrValue(grace)
	return b
}

// s5Event7 is the terminal recovery: identical facts to event 6, the
// terminal-end candidate comes from the Lifecycle transition itself.
func s5Event7(grace time.Time) *model.OperatorBriefing { return s5Event6(grace) }

// s5DeliverPending claims and delivers every currently pending intent
// until the queue is empty. The claim ranking serializes one Situation's
// queue head at a time (root before reply, matching production order:
// "the current root goes out ahead of the older reply"), so this loops
// rather than claiming once with a large limit.
func s5DeliverPending(t *testing.T, st *Store, now time.Time) int {
	t.Helper()
	total := 0
	for i := 0; i < 25; i++ {
		claims, err := st.ClaimNotificationIntents(context.Background(), "s5-deliver", now, 5*time.Minute, 25)
		if err != nil {
			t.Fatalf("ClaimNotificationIntents: %v", err)
		}
		if len(claims) == 0 {
			return total
		}
		for _, c := range claims {
			ts := "s5." + c.Intent.ID
			as := "thread"
			if c.Intent.EffectClass == model.EffectRootSync {
				as = "root"
			}
			if err := st.MarkNotificationDelivered(context.Background(), c,
				situation.NotificationDelivery{Channel: "C-s5", MessageTS: ts, DeliveredAs: as},
				now.Add(time.Duration(total+1)*time.Millisecond)); err != nil {
				t.Fatalf("MarkNotificationDelivered(%s): %v", c.Intent.ID, err)
			}
			total++
		}
	}
	t.Fatalf("delivery queue did not drain within 25 rounds")
	return total
}

// s5TotalDeliveredReplies counts every thread_append/broadcast_handoff
// intent this Situation has ever delivered, across the whole run.
func s5TotalDeliveredReplies(t *testing.T, st *Store, situationID string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM notification_intents
		WHERE situation_id = ? AND effect_class IN ('thread_append','broadcast_handoff') AND status = 'delivered'`,
		situationID).Scan(&n); err != nil {
		t.Fatalf("count delivered replies: %v", err)
	}
	return n
}

// s5RecoveryCycle is osCycle plus one field osCycle's shared signature has
// no room for: the Situation's own recovery_observed_at, required by the
// situations table's lifecycle CHECK constraint from LifecycleRecoveryPending
// onward. A local variant, not a change to the osCycle every other B5 test
// depends on.
func s5RecoveryCycle(t *testing.T, st *Store, sitID string, now time.Time, contract model.ActionContract,
	lifecycle model.Lifecycle, briefing *model.OperatorBriefing, recoveryObservedAt time.Time) model.Transition {
	t.Helper()
	ctx := context.Background()
	shMakeDue(t, st, sitID, now.Add(-time.Second))
	claim := claimSituation(t, st, sitID, osOwner, now)
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	cycle := shPrepare(t, claim, contract, lifecycle, model.AttentionObserve, now)
	cycle.Change.PriorTransition = in.PriorTransition
	cycle.Change.PriorSummary = in.CurrentSummary
	cycle.Change.Projection.Briefing = briefing
	cycle.Publish.RootPublished = true
	cycle.Publish.DeliveredHistory = in.DeliveredHistory
	if in.PriorTransition != nil {
		cycle.Publish.PriorTransition = in.PriorTransition
	}
	// basicControllerCommit/shPrepare never populate RecoveryObservedAt or
	// GraceUntil — only lifecycleResolution (the real controller's own
	// derivation, bypassed by this fixture) does. The situations table
	// CHECK requires both non-nil together from recovery_pending through
	// recovered, and requires RecoveryObservedAt in the reused grace
	// window on the briefing itself.
	cycle.Commit.RecoveryObservedAt = timePtrValue(recoveryObservedAt)
	if briefing.Work.SourceGraceUntil != nil {
		cycle.Commit.GraceUntil = briefing.Work.SourceGraceUntil
	} else {
		cycle.Commit.GraceUntil = timePtrValue(recoveryObservedAt.Add(20 * time.Minute))
	}
	commit := shDerive(t, cycle)
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	if commit.History == nil || len(commit.History.Transitions) != 1 {
		t.Fatalf("expected exactly one committed transition, got %+v", commit.History)
	}
	stored, err := st.GetSituationTransition(ctx, commit.History.Transitions[0].ID)
	if err != nil {
		t.Fatalf("GetSituationTransition: %v", err)
	}
	return stored
}

// s5QuietCycle attempts one real controller cycle for sitID with
// content byte-identical to the current committed state, and reports
// whether selectControllerReason found anything materially due to
// commit — the real "does a bare clock tick alone earn a Transition"
// answer, rather than assuming one.
func s5QuietCycle(t *testing.T, st *Store, sitID string, now time.Time, contract model.ActionContract,
	lifecycle model.Lifecycle, briefing *model.OperatorBriefing) (committed bool) {
	t.Helper()
	ctx := context.Background()
	shMakeDue(t, st, sitID, now.Add(-time.Second))
	claim := claimSituation(t, st, sitID, osOwner, now)
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	cycle := shPrepare(t, claim, contract, lifecycle, model.AttentionObserve, now)
	cycle.Change.PriorTransition = in.PriorTransition
	cycle.Change.PriorSummary = in.CurrentSummary
	cycle.Change.Projection.Briefing = briefing
	cycle.Publish.RootPublished = true
	cycle.Publish.DeliveredHistory = in.DeliveredHistory
	if in.PriorTransition != nil {
		cycle.Publish.PriorTransition = in.PriorTransition
	}
	commit := shDerive(t, cycle)
	if len(commit.History.Transitions) == 0 {
		// Release the lease this claim took: a real controller cycle that
		// decides there is nothing to commit does not hold the Situation
		// for its full lease duration, and the next event in this replay
		// is well inside that window.
		if _, err := st.db.ExecContext(ctx, `UPDATE situations SET lease_owner = NULL, lease_expires_at = NULL WHERE id = ?`, sitID); err != nil {
			t.Fatalf("release quiet-cycle lease: %v", err)
		}
		return false
	}
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	return true
}

// s5EventKinds is the same OperatorDelta.Candidates reader b5r4Kinds uses.
func s5EventKinds(tr model.Transition) map[model.CandidateKind]bool {
	out := map[model.CandidateKind]bool{}
	if d := tr.Projection.OperatorDelta; d != nil {
		for _, c := range d.Candidates {
			out[c.Kind] = true
		}
	}
	return out
}

// ----------------------------------------------------------------------
// Variant 1: the awaiting root is published first; execution starts
// after it and its assurance is delivered before the finding arrives.
// Illustrative target row 2's "adds one reply" case — five replies total.
// ----------------------------------------------------------------------

func TestS5ReplayDeliveredAssuranceReachesFive(t *testing.T) {
	st := newTestStore(t)
	base := time.Date(2026, 9, 10, 15, 9, 9, 0, time.UTC)
	id := newSituationForGroup(t, st, "s5-replay-delivered", base)
	grace := base.Add(20 * time.Minute)

	// Event 1 — 15:09:09 first root arrives; no work, no reply.
	ev1 := osCycle(t, st, id, base, osMonitoringContract(base.Add(90*time.Second)), model.LifecycleActive, s5Event1(), false)
	if n := s5DeliverPending(t, st, base.Add(time.Second)); n != 1 {
		t.Fatalf("event 1 delivered %d intents, want exactly the root", n)
	}
	if got := s5EventKinds(ev1); len(got) != 0 {
		t.Fatalf("event 1 (first root) recorded candidates, want none: %+v", got)
	}

	// Event 2 — 15:10:33 investigation starts against the existing root.
	t2 := time.Date(2026, 9, 10, 15, 10, 33, 0, time.UTC)
	ev2 := osCycle(t, st, id, t2, shRunningTriageContract(t2.Add(2*time.Minute)), model.LifecycleActive, s5Event2(), true)
	if !s5EventKinds(ev2)[model.CandidateFirstExecutionAssurance] {
		t.Fatalf("event 2 recorded no first-execution assurance: %+v", ev2.Projection.OperatorDelta)
	}
	if n := s5DeliverPending(t, st, t2.Add(time.Second)); n != 2 {
		t.Fatalf("event 2 delivered %d intents, want root + one assurance reply", n)
	}
	for _, c := range ev2.Projection.OperatorDelta.Candidates {
		if c.Kind != model.CandidateFirstExecutionAssurance {
			continue
		}
		if len(c.Members.NowFiring) != 4 || c.Members.FiringCount != 4 || !c.Members.CountKnown {
			t.Fatalf("event 2 assurance investigated names/count = %+v, want the 4 frozen investigation inputs", c.Members)
		}
	}

	// Event 3 — 15:10:58 the finding is published; the assurance already
	// reached the operator, so it is not superseded, only satisfied.
	t3 := time.Date(2026, 9, 10, 15, 10, 58, 0, time.UTC)
	ev3 := osCycle(t, st, id, t3, osMonitoringContract(t3.Add(2*time.Minute)), model.LifecycleActive, s5Event3(), true)
	if !s5EventKinds(ev3)[model.CandidateUsefulFinding] {
		t.Fatalf("event 3 recorded no useful finding: %+v", ev3.Projection.OperatorDelta)
	}
	if n := s5DeliverPending(t, st, t3.Add(time.Second)); n != 2 {
		t.Fatalf("event 3 delivered %d intents, want root + one finding reply", n)
	}

	// Event 4 — 15:11:29 QueueBacklog clears; three remain firing.
	t4 := time.Date(2026, 9, 10, 15, 11, 29, 0, time.UTC)
	ev4 := osCycle(t, st, id, t4, osMonitoringContract(t4.Add(2*time.Minute)), model.LifecycleActive, s5Event4(), true)
	kinds4 := s5EventKinds(ev4)
	if !kinds4[model.CandidateMembersChanged] {
		t.Fatalf("event 4 recorded no members-changed candidate: %+v", ev4.Projection.OperatorDelta)
	}
	for _, c := range ev4.Projection.OperatorDelta.Candidates {
		if c.Kind != model.CandidateMembersChanged {
			continue
		}
		if len(c.Members.Cleared) != 1 || c.Members.Cleared[0] != s5QueueBacklog {
			t.Fatalf("event 4 cleared names = %v, want [%s]", c.Members.Cleared, s5QueueBacklog)
		}
		if len(c.Members.StillFiring) != 3 {
			t.Fatalf("event 4 still-firing names = %v, want 3 names", c.Members.StillFiring)
		}
	}
	if n := s5DeliverPending(t, st, t4.Add(time.Second)); n != 2 {
		t.Fatalf("event 4 delivered %d intents, want root + one members-changed reply", n)
	}

	// Event 5 — 15:13:29 a quiet status-checkpoint tick: the briefing is
	// byte-identical to event 4, so selectControllerReason finds nothing
	// materially due and commits no Transition at all — quieter than the
	// illustrative target's "root deadlines refreshed" text claims (a
	// real gap between illustrative copy and the minimal implementation:
	// this release does not re-stamp an unchanged root's checkpoint on a
	// bare clock tick with no other input; nothing to correct here since
	// nothing was invented on Slack, but worth recording precisely).
	t5 := time.Date(2026, 9, 10, 15, 13, 29, 0, time.UTC)
	if committed := s5QuietCycle(t, st, id, t5, osMonitoringContract(t5.Add(2*time.Minute)), model.LifecycleActive, s5Event5()); committed {
		t.Fatalf("event 5 (quiet, unchanged checkpoint) committed a Transition; want none")
	}
	if n := s5DeliverPending(t, st, t5.Add(time.Second)); n != 0 {
		t.Fatalf("event 5 delivered %d intents, want none: nothing was queued", n)
	}

	// Event 6 — 15:13:58 all four resolve; RecoveryPending / all-clear.
	t6 := time.Date(2026, 9, 10, 15, 13, 58, 0, time.UTC)
	ev6 := s5RecoveryCycle(t, st, id, t6, osMonitoringContract(t6.Add(2*time.Minute)), model.LifecycleRecoveryPending, s5Event6(grace), t6)
	if !s5EventKinds(ev6)[model.CandidateAllClear] {
		t.Fatalf("event 6 recorded no all-clear candidate: %+v", ev6.Projection.OperatorDelta)
	}
	if n := s5DeliverPending(t, st, t6.Add(time.Second)); n != 2 {
		t.Fatalf("event 6 delivered %d intents, want root + one all-clear reply", n)
	}

	// Event 7 — 15:15:59 recovery confirmed; terminal.
	t7 := time.Date(2026, 9, 10, 15, 15, 59, 0, time.UTC)
	ev7 := s5RecoveryCycle(t, st, id, t7, osTerminalContract(), model.LifecycleRecovered, s5Event7(grace), t6)
	kinds7 := s5EventKinds(ev7)
	if !kinds7[model.CandidateTerminalEnd] {
		t.Fatalf("event 7 recorded no terminal-end candidate: %+v", ev7.Projection.OperatorDelta)
	}
	for _, c := range ev7.Projection.OperatorDelta.Candidates {
		if c.Kind == model.CandidateTerminalEnd && c.Next.Kind != model.NextStepWorkEnded {
			t.Fatalf("recovered terminal end next-step kind = %s, want work_ended (not tracking_ended: recovery IS confirmed)", c.Next.Kind)
		}
	}
	if n := s5DeliverPending(t, st, t7.Add(time.Second)); n != 2 {
		t.Fatalf("event 7 delivered %d intents, want root + one terminal reply", n)
	}

	// §7: the illustrative target's bracketed "update by [...]" copy on
	// events 2 and 3 is the explicitly NOT-implemented promise
	// (spec.md/integration-contract.md §7, the `update-delayed` example).
	// internal/store cannot render Slack text directly (internal/notify/
	// slack imports internal/store; a test-only import would cycle), so
	// this is proved at the renderer boundary instead, by the existing
	// cmd/alertint TestSituationSlackE2ENeverRendersAnUnsupportedUpdatePromise
	// scanning every root/reply this same store ever produces for real —
	// see the Slide self-check for that cross-reference.

	// S5-02: five earned replies total when the assurance was delivered —
	// the four R3 historically recorded (finding, partial recovery,
	// all-clear, recovered) plus the assurance the target adds.
	if got := s5TotalDeliveredReplies(t, st, id); got != 5 {
		t.Fatalf("total delivered replies = %d, want 5 (assurance, finding, partial recovery, all-clear, recovered)", got)
	}
}

// ----------------------------------------------------------------------
// Variant 2: publication is delayed until AFTER execution has already
// started (the "first-root-running" Slack example). The very first root
// already conveys it, so no separate assurance reply is ever queued.
// Illustrative target: "stays at four ... when that assurance is
// redundant."
// ----------------------------------------------------------------------

func TestS5ReplayRedundantFirstRootStaysAtFour(t *testing.T) {
	st := newTestStore(t)
	base := time.Date(2026, 9, 10, 15, 10, 33, 0, time.UTC)
	id := newSituationForGroup(t, st, "s5-replay-redundant", base)
	grace := base.Add(20 * time.Minute)

	// The first-ever transition already shows execution running: no prior
	// Transition exists to diff against, so MaterialCandidates records no
	// candidates at all for it and the root alone conveys the state.
	ev1 := osCycle(t, st, id, base, shRunningTriageContract(base.Add(2*time.Minute)), model.LifecycleActive, s5Event2(), false)
	if got := s5EventKinds(ev1); len(got) != 0 {
		t.Fatalf("first-ever transition (root conveys execution) recorded candidates, want none: %+v", got)
	}
	if n := s5DeliverPending(t, st, base.Add(time.Second)); n != 1 {
		t.Fatalf("first publication delivered %d intents, want only the root, no assurance reply", n)
	}

	t3 := base.Add(25 * time.Second)
	osCycle(t, st, id, t3, osMonitoringContract(t3.Add(2*time.Minute)), model.LifecycleActive, s5Event3(), true)
	s5DeliverPending(t, st, t3.Add(time.Second))

	t4 := t3.Add(31 * time.Second)
	osCycle(t, st, id, t4, osMonitoringContract(t4.Add(2*time.Minute)), model.LifecycleActive, s5Event4(), true)
	s5DeliverPending(t, st, t4.Add(time.Second))

	t6 := t4.Add(2 * time.Minute)
	s5RecoveryCycle(t, st, id, t6, osMonitoringContract(t6.Add(2*time.Minute)), model.LifecycleRecoveryPending, s5Event6(grace), t6)
	s5DeliverPending(t, st, t6.Add(time.Second))

	t7 := t6.Add(2 * time.Minute)
	s5RecoveryCycle(t, st, id, t7, osTerminalContract(), model.LifecycleRecovered, s5Event7(grace), t6)
	s5DeliverPending(t, st, t7.Add(time.Second))

	if got := s5TotalDeliveredReplies(t, st, id); got != 4 {
		t.Fatalf("total delivered replies = %d, want 4 (no assurance: the first root already conveyed it)", got)
	}
}

// ----------------------------------------------------------------------
// Variant 3: the finding arrives while the assurance is still queued and
// undelivered — the SAME fenced CommitController transaction supersedes
// it (§5.3). Illustrative target: "stays at four ... when that assurance
// is ... superseded" (the "finding-supersedes-start" Slack example).
// ----------------------------------------------------------------------

func TestS5ReplayFindingOvertakesUndeliveredStartStaysAtFour(t *testing.T) {
	st := newTestStore(t)
	base := time.Date(2026, 9, 10, 15, 9, 9, 0, time.UTC)
	id := newSituationForGroup(t, st, "s5-replay-overtaken", base)
	grace := base.Add(20 * time.Minute)

	osCycle(t, st, id, base, osMonitoringContract(base.Add(90*time.Second)), model.LifecycleActive, s5Event1(), false)
	s5DeliverPending(t, st, base.Add(time.Second))

	t2 := time.Date(2026, 9, 10, 15, 10, 33, 0, time.UTC)
	assurance := osCycle(t, st, id, t2, shRunningTriageContract(t2.Add(2*time.Minute)), model.LifecycleActive, s5Event2(), true)
	if !s5EventKinds(assurance)[model.CandidateFirstExecutionAssurance] {
		t.Fatalf("event 2 recorded no first-execution assurance: %+v", assurance.Projection.OperatorDelta)
	}
	// Deliberately do NOT deliver event 2's root/reply yet: the finding
	// must overtake an assurance that is still pending, not one already
	// on the operator's screen.
	if info := osIntentDetail(t, st, id, assurance.Sequence); info.Status != "pending" {
		t.Fatalf("assurance reply status before the finding = %s, want pending", info.Status)
	}

	t3 := time.Date(2026, 9, 10, 15, 10, 58, 0, time.UTC)
	osCycle(t, st, id, t3, osMonitoringContract(t3.Add(2*time.Minute)), model.LifecycleActive, s5Event3(), true)

	overtaken := osIntentDetail(t, st, id, assurance.Sequence)
	if overtaken.Status != "superseded" {
		t.Fatalf("assurance reply status after the finding = %s, want superseded", overtaken.Status)
	}
	if overtaken.Reason != "superseded_by_finding" {
		t.Fatalf("supersession_reason = %q, want superseded_by_finding", overtaken.Reason)
	}

	// Event 2's own root_sync is ALSO superseded here, not just its reply:
	// an undelivered root card is always replaced by a fresher one rather
	// than posting two edits back to back, so only event 3's root and
	// finding reply remain claimable — no stale root edit ever reaches
	// Slack, and the superseded assurance never becomes deliverable.
	if got := osIntentDetail(t, st, id, assurance.Sequence); got.Status != "superseded" {
		t.Fatalf("event 2 reply status = %s, want superseded", got.Status)
	}
	if n := s5DeliverPending(t, st, t3.Add(time.Second)); n != 2 {
		t.Fatalf("post-overtake drain delivered %d intents, want event-3's root + finding reply only", n)
	}

	t4 := t3.Add(31 * time.Second)
	osCycle(t, st, id, t4, osMonitoringContract(t4.Add(2*time.Minute)), model.LifecycleActive, s5Event4(), true)
	s5DeliverPending(t, st, t4.Add(time.Second))

	t6 := t4.Add(2 * time.Minute)
	s5RecoveryCycle(t, st, id, t6, osMonitoringContract(t6.Add(2*time.Minute)), model.LifecycleRecoveryPending, s5Event6(grace), t6)
	s5DeliverPending(t, st, t6.Add(time.Second))

	t7 := t6.Add(2 * time.Minute)
	s5RecoveryCycle(t, st, id, t7, osTerminalContract(), model.LifecycleRecovered, s5Event7(grace), t6)
	s5DeliverPending(t, st, t7.Add(time.Second))

	if got := s5TotalDeliveredReplies(t, st, id); got != 4 {
		t.Fatalf("total delivered replies = %d, want 4 (the superseded assurance never counts as delivered)", got)
	}
}
