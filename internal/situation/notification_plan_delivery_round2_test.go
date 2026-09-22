// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-2 repair regressions (lead review 2026-09-09, R4/R5).
//
// R4: the canonical slide-4 gate is "Initial publication has no duplicate
// reply" (gate node), "Never echo the first root into its thread" (root
// node), "or no earlier root" (quiet-path edge) and "existing root"
// (reply-path edge). The first root renders the CURRENT truth, so nothing
// in the commit that publishes it is owed a thread echo — not only the
// first-execution assurance.
//
// R5: delivered-only history strands a correction. An obstacle queued
// during a delivery gap is still OWED to the operator; a clearance planned
// while that reply is pending must survive, or the stale obstacle publishes
// later with nothing to correct it.
// ----------------------------------------------------------------------

// rdCandidateTransition clones the known-valid baseline Transition and
// gives it one arbitrary candidate list, so a planner test can vary the
// kind without rebuilding a full B2/B3 derivation.
func rdCandidateTransition(t *testing.T, kind model.JournalKind, cands ...model.MaterialCandidate) model.Transition {
	t.Helper()
	tr := hsFirst(t)
	tr.JournalKind = kind
	tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: cands}
	return tr
}

func rdFinding() model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateUsefulFinding,
		Finding: &model.FindingFacts{IncidentID: "i", Hypothesis: "Deploy broke checkout", Observations: []string{"Errors began after deploy"}}}
}

func rdLimitation(code string, cleared bool) model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateAbilityChanged,
		Limitation: &model.LimitationFacts{Code: code, Cleared: cleared}}
}

func rdAction(a model.OperatorAction, withdrawn bool) model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateActionChanged,
		Action: &model.ActionFacts{Action: a, Introduced: !withdrawn, Withdrawn: withdrawn}}
}

// R4/1: no candidate kind earns a reply while this commit is itself the
// first root publication — the terminal case the lead's probe names, and
// the material finding/member cases that share the rule.
func TestReplyEligibleFirstPublicationEarnsNoReplyForAnyKind(t *testing.T) {
	cands := []model.MaterialCandidate{
		{Kind: model.CandidateTerminalEnd},
		rdFinding(),
		{Kind: model.CandidateMembersChanged, Members: &model.MemberFacts{NowFiring: []string{"a"}, FiringCount: 1, Total: 1}},
		rdLimitation(model.LimitationInvestigationUnavailable, false),
	}
	if got := ReplyEligible(cands, DeliveredHistory{}, false); len(got) != 0 {
		t.Fatalf("initial publication must have no duplicate reply, got %v", rdKinds(got))
	}
	if got := ReplyEligible(cands, DeliveredHistory{}, true); len(got) != len(cands) {
		t.Fatalf("an existing root must still earn every material reply, got %v", rdKinds(got))
	}
}

// R4/2: the same rule through the real planner — a delayed FIRST root that
// is already terminal publishes the current terminal overview and queues no
// terminal thread echo beside it.
func TestPlanNotificationIntentsFirstTerminalRootQueuesNoEcho(t *testing.T) {
	c := hsChange(t)
	tr := rdCandidateTransition(t, model.JournalClosedUnknown, model.MaterialCandidate{Kind: model.CandidateTerminalEnd})
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum)
	in.RootPublished = false
	in.RootPublicationOwed = true // an earlier root projection is still owed: publication was already earned
	got := hsPlan(t, in)
	if n := len(hsReplyIntents(got)); n != 0 {
		t.Fatalf("a delayed first terminal root also queued %d thread echoes: %+v", n, hsReplyIntents(got))
	}
	if len(hsIntentsOfClass(got, model.EffectRootSync)) != 1 {
		t.Fatalf("the current terminal overview must still be planned: %+v", got)
	}
}

// R4/3: the symptoms-only legacy fallback obeys the same first-publication
// rule — it must not smuggle an initial echo past the candidate gate.
func TestReplyEligibleTransitionFirstPublicationIgnoresSymptomsFallback(t *testing.T) {
	c := hsChange(t)
	tr := rdCandidateTransition(t, model.JournalInvestigationChanged)
	tr.Projection.Briefing.Symptoms = []string{"checkout 5xx"}
	prior := rdCandidateTransition(t, model.JournalInvestigationChanged)
	prior.Projection.Briefing.Symptoms = []string{"latency"}
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum)
	in.PriorTransition = &prior

	in.RootPublished = true
	if !replyEligibleTransition(in, tr) {
		t.Fatal("a real symptom change under an existing root must still earn its reply")
	}
	in.RootPublished, in.RootPublicationOwed = false, true
	if replyEligibleTransition(in, tr) {
		t.Fatal("initial publication has no duplicate reply, symptoms fallback included")
	}
}

// R4/4 (negative control for the fallback the lead declined to ratify
// blanket): identical symptoms and no candidate is quiet, published root or
// not — prose alone never earns a reply.
func TestReplyEligibleTransitionProseOnlyChangeStaysQuiet(t *testing.T) {
	c := hsChange(t)
	tr := rdCandidateTransition(t, model.JournalInvestigationChanged)
	tr.Projection.Briefing.Symptoms = []string{"checkout 5xx"}
	tr.Projection.Briefing.Scope = "checkout service"
	prior := rdCandidateTransition(t, model.JournalInvestigationChanged)
	prior.Projection.Briefing.Symptoms = []string{"checkout 5xx"}
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum)
	in.PriorTransition = &prior
	if replyEligibleTransition(in, tr) {
		t.Fatal("a rewording with no candidate and unchanged symptoms must stay quiet")
	}
}

// R5/1: a clearance stays eligible while its obstacle is still OWED to the
// operator. Delivered-only history dropped it as an "unreported transient"
// and left the pending obstacle to publish later, uncorrected.
func TestReplyEligibleOwedObstacleKeepsItsClearance(t *testing.T) {
	clearing := []model.MaterialCandidate{rdLimitation(model.LimitationInvestigationUnavailable, true)}

	if got := ReplyEligible(clearing, DeliveredHistory{}, true); len(got) != 0 {
		t.Fatalf("a genuinely unreported transient obstacle has nothing to correct: %v", rdKinds(got))
	}
	// An obstacle that is owed but not yet delivered is standing: nothing
	// queued behind it clears it.
	owed := DeliveredHistory{ProjectedLimitationCodes: []string{model.LimitationInvestigationUnavailable}}
	if got := ReplyEligible(clearing, owed, true); len(got) != 1 {
		t.Fatalf("an obstacle still owed to the operator must keep its correction: %v", rdKinds(got))
	}
}

// R5/2: the same boundary for a duplicate appearance — an obstacle already
// queued must not be replanned as new while it waits.
func TestReplyEligibleOwedObstacleSuppressesADuplicateAppearance(t *testing.T) {
	appearing := []model.MaterialCandidate{rdLimitation(model.LimitationInvestigationUnavailable, false)}
	owed := DeliveredHistory{ProjectedLimitationCodes: []string{model.LimitationInvestigationUnavailable}}
	if got := ReplyEligible(appearing, owed, true); len(got) != 0 {
		t.Fatalf("an obstacle already queued must not be replanned as new: %v", rdKinds(got))
	}
}

// R5/3: the analogous action race the lead inspected but did not probe — a
// withdrawal must survive while the request that introduced it is still
// owed, or the operator is later asked to do something already withdrawn.
func TestReplyEligibleOwedActionKeepsItsWithdrawal(t *testing.T) {
	withdrawal := []model.MaterialCandidate{rdAction(model.OperatorActionInvestigateSituation, true)}
	if got := ReplyEligible(withdrawal, DeliveredHistory{}, true); len(got) != 0 {
		t.Fatalf("nothing was ever requested, so nothing is withdrawn: %v", rdKinds(got))
	}
	action := model.OperatorActionInvestigateSituation
	owed := DeliveredHistory{ProjectedAction: &action}
	if got := ReplyEligible(withdrawal, owed, true); len(got) != 1 {
		t.Fatalf("a request still owed to the operator must keep its withdrawal: %v", rdKinds(got))
	}
}
