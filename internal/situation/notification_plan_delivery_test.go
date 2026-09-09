// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 (earned delivery / communicated history): ReplyEligible is the pure
// DeliveredHistory-aware filter that replaces operatorReplyWarranted for
// briefing-bearing transitions (B0 integration contract §4/§5). It never
// re-derives materiality (B3 already decided a candidate belongs in the
// list); it only decides whether the OPERATOR has already effectively been
// told, so nothing here re-checks structural-fact inequality.
// ----------------------------------------------------------------------

func rdKinds(cands []model.MaterialCandidate) []model.CandidateKind {
	out := make([]model.CandidateKind, len(cands))
	for i, c := range cands {
		out[i] = c.Kind
	}
	return out
}

func rdEqualKinds(t *testing.T, got []model.MaterialCandidate, want ...model.CandidateKind) {
	t.Helper()
	gk := rdKinds(got)
	if len(gk) != len(want) {
		t.Fatalf("ReplyEligible kinds = %v, want %v", gk, want)
	}
	for i := range want {
		if gk[i] != want[i] {
			t.Fatalf("ReplyEligible kinds = %v, want %v", gk, want)
		}
	}
}

// 1/2/3: the first-execution assurance is conveyed by the fresh root itself
// when no root exists yet (spec.md "If the first root already conveys this
// assurance, do not echo it"); once a root already exists, it earns its one
// reply — unless DeliveredHistory already shows it conveyed (idempotency:
// MaterialCandidates only ever emits this candidate once, but a replayed or
// re-processed cycle must not double-plan it).
func TestReplyEligibleFirstExecutionAssurance(t *testing.T) {
	assurance := model.MaterialCandidate{
		Kind:    model.CandidateFirstExecutionAssurance,
		Members: &model.MemberFacts{NowFiring: []string{"a"}, FiringCount: 1, CountKnown: true, Total: 1},
		Next:    model.NextStepFacts{Kind: model.NextStepStatusCheck},
	}
	cands := []model.MaterialCandidate{assurance}

	if got := ReplyEligible(cands, DeliveredHistory{}, false); len(got) != 0 {
		t.Fatalf("unpublished root must convey the assurance itself, want no reply: %v", got)
	}
	if got := ReplyEligible(cands, DeliveredHistory{}, true); len(got) != 1 {
		t.Fatalf("published root + fresh candidate must earn one reply: %v", got)
	}
	if got := ReplyEligible(cands, DeliveredHistory{AssuranceConveyed: true}, true); len(got) != 0 {
		t.Fatalf("already-conveyed assurance must not be replanned: %v", got)
	}
}

// 4/5/6: structural material facts B3 already decided (finding, inconclusive
// completion, member/lifecycle-edge facts, terminal end) are never gated by
// delivery history — they are always eligible.
func TestReplyEligibleUnconditionalKinds(t *testing.T) {
	for _, kind := range []model.CandidateKind{
		model.CandidateUsefulFinding, model.CandidateInconclusiveCompletion,
		model.CandidateMembersChanged, model.CandidateAllClear, model.CandidateRefire,
		model.CandidateTerminalEnd,
	} {
		cands := []model.MaterialCandidate{{Kind: kind}}
		got := ReplyEligible(cands, DeliveredHistory{}, false)
		if len(got) != 1 || got[0].Kind != kind {
			t.Errorf("%s must always be eligible regardless of history, got %v", kind, got)
		}
	}
}

// 7/8: a NEWLY appearing limitation is eligible unless it is already (still)
// communicated — defensive idempotency, since MaterialCandidates only fires
// a fresh appearance on a genuine prior!=current diff.
func TestReplyEligibleAbilityChangedAppearing(t *testing.T) {
	cand := model.MaterialCandidate{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: "evidence_source_unavailable", Cleared: false}}

	got := ReplyEligible([]model.MaterialCandidate{cand}, DeliveredHistory{}, true)
	if len(got) != 1 {
		t.Fatalf("a never-communicated limitation appearing must be eligible: %v", got)
	}
	got = ReplyEligible([]model.MaterialCandidate{cand}, DeliveredHistory{CommunicatedLimitationCodes: []string{"evidence_source_unavailable"}}, true)
	if len(got) != 0 {
		t.Fatalf("an already-communicated appearance must not be replanned: %v", got)
	}
}

// 9/10: a limitation CLEARING is useful history only if the obstacle was
// actually reported in the first place (plan.md item 4: "Unreported
// transient obstacle restoration is not useful history").
func TestReplyEligibleAbilityChangedClearing(t *testing.T) {
	cand := model.MaterialCandidate{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: "evidence_source_unavailable", Cleared: true}}

	got := ReplyEligible([]model.MaterialCandidate{cand}, DeliveredHistory{CommunicatedLimitationCodes: []string{"evidence_source_unavailable"}}, true)
	if len(got) != 1 {
		t.Fatalf("clearing a communicated limitation must be eligible: %v", got)
	}
	got = ReplyEligible([]model.MaterialCandidate{cand}, DeliveredHistory{}, true)
	if len(got) != 0 {
		t.Fatalf("clearing a NEVER-communicated limitation must not be eligible: %v", got)
	}
	// A distinct simultaneous limitation's own communicated state must not
	// leak into this one (spec.md "Distinct simultaneous limitations remain
	// independent").
	got = ReplyEligible([]model.MaterialCandidate{cand}, DeliveredHistory{CommunicatedLimitationCodes: []string{"other_code"}}, true)
	if len(got) != 0 {
		t.Fatalf("an unrelated communicated code must not clear this one: %v", got)
	}
}

// 11/12/13/14: withdrawing a recorded operator action is honest only if
// that action was actually communicated; introducing or revising one is
// always new information.
func TestReplyEligibleActionChanged(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	withdrawn := model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Withdrawn: true, Action: action}}
	introduced := model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Introduced: true, Action: action}}
	revised := model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Revised: true, Action: action}}

	if got := ReplyEligible([]model.MaterialCandidate{withdrawn}, DeliveredHistory{}, true); len(got) != 0 {
		t.Fatalf("withdrawing a never-communicated action must not be eligible: %v", got)
	}
	if got := ReplyEligible([]model.MaterialCandidate{withdrawn}, DeliveredHistory{CommunicatedAction: &action}, true); len(got) != 1 {
		t.Fatalf("withdrawing a communicated action must be eligible: %v", got)
	}
	if got := ReplyEligible([]model.MaterialCandidate{introduced}, DeliveredHistory{}, true); len(got) != 1 {
		t.Fatalf("introducing an action is always eligible: %v", got)
	}
	if got := ReplyEligible([]model.MaterialCandidate{revised}, DeliveredHistory{}, true); len(got) != 1 {
		t.Fatalf("revising an action is always eligible: %v", got)
	}
}

// 15: a mixed commit keeps only the eligible candidates, in their original
// order — B4 renders every survivor from the one persisted list.
func TestReplyEligibleMixedListPreservesOrder(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	cands := []model.MaterialCandidate{
		{Kind: model.CandidateFirstExecutionAssurance, Members: &model.MemberFacts{FiringCount: 1, CountKnown: true}},
		{Kind: model.CandidateUsefulFinding, Finding: &model.FindingFacts{Hypothesis: "x"}},
		{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: "c", Cleared: true}}, // never communicated -> dropped
		{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Withdrawn: true, Action: action}},   // never communicated -> dropped
		{Kind: model.CandidateTerminalEnd, Next: model.NextStepFacts{Kind: model.NextStepWorkEnded}},
	}
	got := ReplyEligible(cands, DeliveredHistory{}, true)
	rdEqualKinds(t, got, model.CandidateFirstExecutionAssurance, model.CandidateUsefulFinding, model.CandidateTerminalEnd)
}

// 16: no candidates in, none out, no panic.
func TestReplyEligibleEmpty(t *testing.T) {
	if got := ReplyEligible(nil, DeliveredHistory{}, true); len(got) != 0 {
		t.Fatalf("empty input must produce empty output: %v", got)
	}
}

// ----------------------------------------------------------------------
// End-to-end wiring: PlanNotificationIntents/selectPoke actually read
// in.DeliveredHistory/in.RootPublished through replyEligibleTransition, not
// just ReplyEligible in isolation.
// ----------------------------------------------------------------------

// rdAssuranceTransition clones a known-valid baseline Transition and turns
// it into a briefing-bearing investigation_started assurance carrying
// exactly one first_execution_assurance candidate — the minimal fixture
// PlanNotificationIntents' wiring test needs. Transition.Validate() does not
// descend into Projection.Briefing/OperatorDelta, so this is a valid
// Transition without going through the full B2/B3 derivation.
func rdAssuranceTransition(t *testing.T) model.Transition {
	t.Helper()
	tr := hsFirst(t)
	tr.JournalKind = model.JournalInvestigationStarted
	tr.Reason = model.ReasonInvestigationStarted
	tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
		Work: model.WorkProjection{ExecutionStarted: true}}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind:    model.CandidateFirstExecutionAssurance,
		Members: &model.MemberFacts{NowFiring: []string{"checkout-error-rate"}, FiringCount: 1, CountKnown: true, Total: 1},
		Next:    model.NextStepFacts{Kind: model.NextStepStatusCheck},
	}}}
	return tr
}

func TestPlanNotificationIntentsSuppressesAssuranceWhenRootNotYetPublished(t *testing.T) {
	c := hsChange(t)
	tr := rdAssuranceTransition(t)
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum)
	in.RootPublished = false // this commit's own first root publication conveys it
	got := hsPlan(t, in)
	if len(hsReplyIntents(got)) != 0 {
		t.Fatalf("an unpublished root's own first post must convey the assurance, want no reply intents: %+v", hsReplyIntents(got))
	}
	if len(hsIntentsOfClass(got, model.EffectRootSync)) != 1 {
		t.Fatalf("must still plan the root itself: %+v", got)
	}
}

func TestPlanNotificationIntentsAssuranceEarnsAReplyOnceRootExists(t *testing.T) {
	c := hsChange(t)
	tr := rdAssuranceTransition(t)
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum) // hsPub defaults RootPublished=true
	got := hsPlan(t, in)
	replies := hsReplyIntents(got)
	if len(replies) != 1 {
		t.Fatalf("an already-published root's fresh assurance must earn exactly one reply: %+v", replies)
	}
}

func TestPlanNotificationIntentsSuppressesAlreadyConveyedAssurance(t *testing.T) {
	c := hsChange(t)
	tr := rdAssuranceTransition(t)
	sum, err := ProjectEpisode(nil, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	in := hsPub(c, []model.Transition{tr}, sum)
	in.DeliveredHistory = DeliveredHistory{AssuranceConveyed: true}
	got := hsPlan(t, in)
	if len(hsReplyIntents(got)) != 0 {
		t.Fatalf("an already-conveyed assurance must not be replanned: %+v", hsReplyIntents(got))
	}
}
