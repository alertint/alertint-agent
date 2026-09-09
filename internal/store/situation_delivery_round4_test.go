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
// B5 round-4 repair regressions (lead review round 3, 2026-09-09, R1),
// against the real SQLite store, the real derivation and planner, the real
// fenced CommitController transaction, the real claim surface and the real
// delivery-time GetCommunicatedHistory/ReplyEligible pair.
//
// §5.3 retires a PURELY transient start assurance at commit time. A row
// that also carries a material scope change is not disposable, so it
// survives and is delivered later — by which time the work may have moved
// past starting. The scope change is still owed; the assurance is not.
// ----------------------------------------------------------------------

// b5r4Mixed commits one reply row carrying both the transient start
// assurance and a material scope change.
func b5r4Mixed() *model.OperatorBriefing {
	b := b5r2Executing()
	b.Scope = "checkout + payments"
	return b
}

// b5r4Settled is the same Situation once the investigation has produced a
// finding and its work has ended.
func b5r4Settled() *model.OperatorBriefing {
	b := b5r2Finding()
	b.Scope = "checkout + payments"
	b.Work.Phase = model.WorkPhaseSettled
	return b
}

func b5r4Kinds(tr model.Transition) map[model.CandidateKind]bool {
	out := map[model.CandidateKind]bool{}
	if d := tr.Projection.OperatorDelta; d != nil {
		for _, c := range d.Candidates {
			out[c.Kind] = true
		}
	}
	return out
}

// b5r4MixedStart publishes and delivers the awaiting root, then commits the
// mixed start row, checking the fixture really is mixed.
func b5r4MixedStart(t *testing.T, st *Store, id string, now time.Time) model.Transition {
	t.Helper()
	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))
	start := osCycle(t, st, id, now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r4Mixed(), true)
	kinds := b5r4Kinds(start)
	if !kinds[model.CandidateFirstExecutionAssurance] || !kinds[model.CandidateMembersChanged] {
		t.Fatalf("fixture: the start row must carry the assurance AND the scope change: %+v", start.Projection.OperatorDelta)
	}
	if n := b5r2PendingReplies(t, st, id, start.ID); n != 1 {
		t.Fatalf("fixture: the mixed start row earned %d replies, want 1", n)
	}
	return start
}

// b5r4Selection runs the exact delivery-time pair the deliverer runs for
// tr: the bounded durable history read, then the real eligibility
// predicate.
func b5r4Selection(t *testing.T, st *Store, id string, tr model.Transition) (situation.DeliveredHistory, map[model.CandidateKind]bool) {
	t.Helper()
	h, err := st.GetCommunicatedHistory(context.Background(), id, tr.Sequence)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	out := map[model.CandidateKind]bool{}
	for _, c := range situation.ReplyEligible(tr.Projection.OperatorDelta.Candidates, h, true) {
		out[c.Kind] = true
	}
	return h, out
}

// R1/1: the retained mixed row is delivered after a useful finding has been
// committed and the current root delivered. Its scope change is still owed;
// its start assurance has been overtaken.
func TestB5RetainedMixedRowDropsItsOvertakenAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-mixed-selection", now)

	start := b5r4MixedStart(t, st, id, now)
	finding := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r4Settled(), true)
	if !b5r4Kinds(finding)[model.CandidateUsefulFinding] {
		t.Fatalf("fixture: the settled cycle recorded no useful finding: %+v", finding.Projection.OperatorDelta)
	}
	if got := osIntentDetail(t, st, id, start.Sequence).Status; got == "superseded" {
		t.Fatalf("the whole mixed row was superseded, losing its material scope history: %s", got)
	}

	// Production order: the current root goes out ahead of the older reply.
	root := snClaimOne(t, st, now.Add(130*time.Second))
	if root.Intent.EffectClass != model.EffectRootSync {
		t.Fatalf("expected the current root at the queue head, got %+v", root.Intent)
	}
	snDeliver(t, st, root, "100.1", now.Add(131*time.Second))
	mixed := snClaimOne(t, st, now.Add(132*time.Second))
	if mixed.Intent.TransitionID == nil || *mixed.Intent.TransitionID != start.ID {
		t.Fatalf("expected the retained mixed row next, got %+v", mixed.Intent)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if !h.AssuranceSuperseded {
		t.Errorf("later settled work with a finding did not overtake the start assurance: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("the retained mixed row still selects a start assurance the work has moved past")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("the row's material scope change was lost with its stale assurance")
	}
}

// R1/2, negative control: a later material reply that is NOT a finding, an
// inconclusive completion or a terminal end overtakes nothing. The
// assurance is still the operator's first word about the work.
func TestB5AssuranceSurvivesALaterNonOvertakingReply(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-not-overtaken", now)

	start := b5r4MixedStart(t, st, id, now)
	wider := b5r2Executing()
	wider.Scope = "checkout + payments + search"
	later := osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, wider, true)
	if n := b5r2PendingReplies(t, st, id, later.ID); n != 1 {
		t.Fatalf("fixture: the later scope change earned %d replies, want 1", n)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if h.AssuranceSuperseded {
		t.Fatalf("a later scope change was treated as overtaking the assurance: %+v", h)
	}
	if !selected[model.CandidateFirstExecutionAssurance] || !selected[model.CandidateMembersChanged] {
		t.Fatalf("the mixed row lost a fact nothing had overtaken: %+v", selected)
	}
}

// R1/3: the Situation's terminal end overtakes a retained assurance too —
// the same vocabulary §5.3 supersedes a transient row for.
func TestB5TerminalEndOvertakesARetainedAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-terminal", now)

	start := b5r4MixedStart(t, st, id, now)
	end := osCycle(t, st, id, now.Add(2*time.Minute), osTerminalContract(),
		model.LifecycleClosedUnknown, b5r4Mixed(), true)
	if !b5r4Kinds(end)[model.CandidateTerminalEnd] {
		t.Fatalf("fixture: the terminal cycle recorded no terminal end: %+v", end.Projection.OperatorDelta)
	}
	if n := b5r2PendingReplies(t, st, id, end.ID); n != 1 {
		t.Fatalf("fixture: the terminal end earned %d replies, want 1", n)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if !h.AssuranceSuperseded {
		t.Errorf("a terminal end did not overtake the start assurance: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("a closed Situation's retained row still says the investigation is starting")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("the row's material scope change was lost with its stale assurance")
	}
}

// b5r4RestartSelection commits the retained mixed start, then one later
// overtaking cycle, closes the file-backed store and reopens it, and
// returns the delivery-time answer the deliverer would get after the
// restart. Every input is a durable row: nothing is carried in memory.
func b5r4RestartSelection(t *testing.T, group string, later *model.OperatorBriefing) (situation.DeliveredHistory, map[model.CandidateKind]bool) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), group+".db")

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id := newSituationForGroup(t, st, group, now)
	start := b5r4MixedStart(t, st, id, now)
	osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, later, true)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return b5r4Selection(t, reopened, id, start)
}

// R1/4, restart: the answer is derived from durable rows alone, so a
// process restart between the finding and the delayed delivery changes
// nothing.
func TestB5OvertakenAssuranceSurvivesARestart(t *testing.T) {
	h, selected := b5r4RestartSelection(t, "b5r4-restart", b5r4Settled())
	if !h.AssuranceSuperseded {
		t.Errorf("the overtaking finding was forgotten across the restart: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("after the restart the retained row published a stale start assurance")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("after the restart the row's material scope change was lost")
	}
}

// R1/5: present assurance relevance must not corrupt historical ordering.
// The limitation and action folds stay bounded strictly BELOW the reply's
// own sequence, so an owed clearance is never cancelled by its own effect.
func TestB5HistoricalOrderingStaysBoundedBelowTheReply(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-bound", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))
	limited := b5r2Brief()
	limited.Unavailable = 1
	obstacle := osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, limited, true)
	cleared := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	if n := b5r2PendingReplies(t, st, id, obstacle.ID) + b5r2PendingReplies(t, st, id, cleared.ID); n != 2 {
		t.Fatalf("fixture: both the obstacle and its clearance must be owed, got %d pending replies", n)
	}

	_, selected := b5r4Selection(t, st, id, cleared)
	if !selected[model.CandidateAbilityChanged] {
		t.Fatal("the owed clearance was cancelled by its own effect; the historical fold lost its lower bound")
	}
	_, first := b5r4Selection(t, st, id, obstacle)
	if !first[model.CandidateAbilityChanged] {
		t.Fatal("the owed obstacle was rewritten by the correction queued behind it")
	}
}

// R1/6: the forward read is FORWARD. A finding already behind this reply
// has not overtaken it — the operator has still never been told the work
// started, and that is the one message this candidate exists to send.
func TestB5AnEarlierFindingDoesNotOvertakeALaterAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-earlier-finding", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	early := b5r2Brief()
	early.Analyses = []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deploy broke checkout",
		Findings: []string{"Errors began after deploy"}}}
	found := osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, early, true)
	if !b5r4Kinds(found)[model.CandidateUsefulFinding] {
		t.Fatalf("fixture: the early cycle recorded no useful finding: %+v", found.Projection.OperatorDelta)
	}

	start := osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r4Mixed(), true)
	if !b5r4Kinds(start)[model.CandidateFirstExecutionAssurance] {
		t.Fatalf("fixture: the start row recorded no assurance: %+v", start.Projection.OperatorDelta)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if h.AssuranceSuperseded {
		t.Fatalf("a finding recorded BEFORE the assurance was treated as overtaking it: %+v", h)
	}
	if !selected[model.CandidateFirstExecutionAssurance] {
		t.Fatal("the operator was never told the work started: an earlier finding suppressed the assurance behind it")
	}
}

// R1/7: plan time is a different question and is left alone. The unbounded
// history the planner reads has no reply to look forward from, so it never
// reports an overtaken assurance.
func TestB5PlanTimeHistoryNeverReportsAnOvertakenAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r4-plan-time", now)

	b5r4MixedStart(t, st, id, now)
	osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r4Settled(), true)

	if h := b5r2History(t, st, id); h.AssuranceSuperseded {
		t.Fatalf("the plan-time read answered a delivery-time question: %+v", h)
	}
}
