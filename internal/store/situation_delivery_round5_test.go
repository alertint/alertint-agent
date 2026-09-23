// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-5 regressions (lead review round 4, 2026-09-10, R1), against
// the real store, derivation, planner and fenced commit.
//
// Round 4 proved the settled-finding and terminal-end shapes. The lead's
// assessment names two more the forward read must answer, and one claim it
// must never make: a finding is not proof that aggregate work has ended.
// ----------------------------------------------------------------------

// b5r5Exhausted is the same Situation once its automatic work has ended
// without a useful finding — the honest inconclusive end.
func b5r5Exhausted() *model.OperatorBriefing {
	b := b5r4Mixed()
	b.Work.Phase = model.WorkPhaseExhausted
	return b
}

// b5r5FindingWithWorkRunning records a useful finding while another member
// schedule is still executing: the finding is real, the work is not over.
func b5r5FindingWithWorkRunning() *model.OperatorBriefing {
	b := b5r2Finding()
	b.Scope = "checkout + payments"
	b.Work.Phase = model.WorkPhaseExecuting
	b.Work.RemainingIncidents = 2
	return b
}

// R1/1: an inconclusive completion is the investigation's own end, so it
// overtakes a start assurance exactly as a useful finding does — the
// vocabulary §5.3 already shares with commit-time supersession.
func TestB5InconclusiveCompletionOvertakesARetainedAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r5-inconclusive", now)

	start := b5r4MixedStart(t, st, id, now)
	ended := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r5Exhausted(), true)
	if !b5r4Kinds(ended)[model.CandidateInconclusiveCompletion] {
		t.Fatalf("fixture: the ended cycle recorded no inconclusive completion: %+v", ended.Projection.OperatorDelta)
	}
	if n := b5r2PendingReplies(t, st, id, ended.ID); n != 1 {
		t.Fatalf("fixture: the inconclusive completion earned %d replies, want 1", n)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if !h.AssuranceSuperseded {
		t.Errorf("an investigation that ended without a finding did not overtake the start assurance: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("the retained row still says the investigation is starting after it ended")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("the row's material scope change was lost with its stale assurance")
	}
}

// R1/2: a finding can coexist with work that is still running. The start
// assurance is still overtaken — the operator has the finding, so
// "investigating" is no longer the news — but nothing here may be read as
// the aggregate work having finished.
func TestB5AFindingOvertakesTheStartWhileOtherWorkStillRuns(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r5-finding-with-work", now)

	start := b5r4MixedStart(t, st, id, now)
	finding := osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r5FindingWithWorkRunning(), true)
	if !b5r4Kinds(finding)[model.CandidateUsefulFinding] {
		t.Fatalf("fixture: the cycle recorded no useful finding: %+v", finding.Projection.OperatorDelta)
	}
	if w := finding.Projection.Briefing.Work; w.Phase != model.WorkPhaseExecuting || w.RemainingIncidents != 2 {
		t.Fatalf("fixture: aggregate work must still be running: %+v", w)
	}

	h, selected := b5r4Selection(t, st, id, start)
	if !h.AssuranceSuperseded {
		t.Errorf("a useful finding did not overtake the start assurance: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("the retained row still leads with a start the finding has moved past")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("the row's material scope change was lost with its stale assurance")
	}
	// The recorded work facts are untouched: supersession is a delivery
	// answer about one message, never a claim that the work is over.
	if w := finding.Projection.Briefing.Work; w.Phase != model.WorkPhaseExecuting || w.RemainingIncidents != 2 {
		t.Fatalf("the finding rewrote the recorded aggregate work: %+v", w)
	}
}

// R1/3, restart: the new overtaking shape is derived from durable rows
// alone, so a process restart between the inconclusive end and the delayed
// delivery changes neither the answer nor what the reply may say.
func TestB5InconclusiveSupersessionSurvivesARestart(t *testing.T) {
	h, selected := b5r4RestartSelection(t, "b5r5-restart", b5r5Exhausted())
	if !h.AssuranceSuperseded {
		t.Errorf("the inconclusive end was forgotten across the restart: %+v", h)
	}
	if selected[model.CandidateFirstExecutionAssurance] {
		t.Error("after the restart the retained row published a stale start assurance")
	}
	if !selected[model.CandidateMembersChanged] {
		t.Error("after the restart the row's material scope change was lost")
	}
}
