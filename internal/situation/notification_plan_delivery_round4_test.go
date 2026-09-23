// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-4 repair regressions (lead review round 3, 2026-09-09, R1).
//
// A reply row that carries the start assurance BESIDE material member or
// scope history is not disposable, so §5.3's commit-time supersession
// leaves it alone and it is still delivered later. By then the work may
// have visibly moved past merely starting — a finding, an inconclusive
// completion, the Situation's terminal end — and "Investigating …" is a
// stale statement about the present, not history worth keeping.
//
// The assurance is therefore the one candidate whose eligibility asks a
// FORWARD question. Limitation and action ordering stays bounded below the
// reply's own sequence: a later correction may not rewrite what an earlier
// message was allowed to say.
// ----------------------------------------------------------------------

// rd4Assurance is the transient first-execution assurance candidate.
func rd4Assurance() model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateFirstExecutionAssurance,
		Members: &model.MemberFacts{FiringCount: 1, Total: 1, CountKnown: true}}
}

// rd4Scope is the material scope change that rides the same row and keeps
// it alive.
func rd4Scope() model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateMembersChanged,
		Members: &model.MemberFacts{FiringCount: 1, Total: 1,
			PreviousScope: "checkout", Scope: "checkout + payments"}}
}

func rd4Kinds(cands []model.MaterialCandidate) map[model.CandidateKind]bool {
	out := map[model.CandidateKind]bool{}
	for _, c := range cands {
		out[c.Kind] = true
	}
	return out
}

// R1/1: the assurance is dropped once something has overtaken it, and the
// row's own material scope change is delivered exactly as before.
func TestReplyEligibleOvertakenAssuranceIsDroppedFromAMixedRow(t *testing.T) {
	h := DeliveredHistory{AssuranceSuperseded: true}
	got := rd4Kinds(ReplyEligible([]model.MaterialCandidate{rd4Assurance(), rd4Scope()}, h, true))
	if got[model.CandidateFirstExecutionAssurance] {
		t.Error("a start assurance overtaken by later work was still selected")
	}
	if !got[model.CandidateMembersChanged] {
		t.Error("suppressing the stale assurance also erased the row's material scope change")
	}
}

// R1/2, negative control: nothing has overtaken it and the operator has not
// seen it, so the assurance still posts. The rule is a supersession, not a
// blanket suppression.
func TestReplyEligibleAssuranceStandsUntilSomethingOvertakesIt(t *testing.T) {
	got := rd4Kinds(ReplyEligible([]model.MaterialCandidate{rd4Assurance(), rd4Scope()}, DeliveredHistory{}, true))
	if !got[model.CandidateFirstExecutionAssurance] || !got[model.CandidateMembersChanged] {
		t.Fatalf("an unovertaken start assurance was suppressed: %+v", got)
	}
}

// R1/3: the two questions stay apart. Present assurance relevance must not
// touch the historical limitation and action ordering that rides the same
// reply — a clearance for a standing obstacle is still owed.
func TestReplyEligibleOvertakenAssuranceLeavesHistoricalFactsAlone(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	h := DeliveredHistory{
		AssuranceSuperseded:      true,
		ProjectedLimitationCodes: []string{model.LimitationInvestigationUnavailable},
		ProjectedAction:          &action,
	}
	got := rd4Kinds(ReplyEligible([]model.MaterialCandidate{
		rd4Assurance(), rd4Limitation(), rd4Withdrawal()}, h, true))
	if got[model.CandidateFirstExecutionAssurance] {
		t.Error("the overtaken assurance survived")
	}
	if !got[model.CandidateAbilityChanged] {
		t.Error("the clearance for a standing obstacle was dropped with the stale assurance")
	}
	if !got[model.CandidateActionChanged] {
		t.Error("the withdrawal of a standing request was dropped with the stale assurance")
	}
}

// R1/4: an assurance the operator has already SEEN stays quiet whether or
// not anything overtook it — the older duplicate rule is unchanged.
func TestReplyEligibleConveyedAssuranceStaysQuietWithoutSupersession(t *testing.T) {
	h := DeliveredHistory{AssuranceConveyed: true}
	if got := rd4Kinds(ReplyEligible([]model.MaterialCandidate{rd4Assurance()}, h, true)); got[model.CandidateFirstExecutionAssurance] {
		t.Fatal("an assurance the operator already saw was announced again")
	}
}

func rd4Limitation() model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateAbilityChanged,
		Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable, Cleared: true}}
}

func rd4Withdrawal() model.MaterialCandidate {
	action := model.OperatorActionInvestigateSituation
	return model.MaterialCandidate{Kind: model.CandidateActionChanged,
		Action: &model.ActionFacts{Action: action, Withdrawn: true}}
}
