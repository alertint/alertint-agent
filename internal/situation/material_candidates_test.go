// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// candidateKinds is a small assertion helper: the set of Kinds MaterialCandidates
// returned, in order, for readable failure messages.
func candidateKinds(cands []model.MaterialCandidate) []model.CandidateKind {
	out := make([]model.CandidateKind, len(cands))
	for i, c := range cands {
		out[i] = c.Kind
	}
	return out
}

func hasCandidate(cands []model.MaterialCandidate, kind model.CandidateKind) *model.MaterialCandidate {
	for i := range cands {
		if cands[i].Kind == kind {
			return &cands[i]
		}
	}
	return nil
}

func mcTransition(lifecycle model.Lifecycle, briefing *model.OperatorBriefing) model.Transition {
	return model.Transition{Lifecycle: lifecycle, Projection: model.ProjectionFacts{Briefing: briefing}}
}

// MaterialCandidates(nil, tr) must return no candidates: there is no delta
// without a baseline, and the first root conveys itself without an echo.
func TestMaterialCandidatesNilPriorIsSilent(t *testing.T) {
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1})
	if got := MaterialCandidates(nil, tr); len(got) != 0 {
		t.Fatalf("nil prior must yield no candidates, got %v", candidateKinds(got))
	}
}

// S4-10: an authoritative all-clear (Active -> Recovery pending) is a
// candidate carrying the actual grace deadline, never an invented one.
func TestMaterialCandidatesAllClearCarriesGraceDeadline(t *testing.T) {
	grace := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 1,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "firing"}},
	})
	tr := mcTransition(model.LifecycleRecoveryPending, &model.OperatorBriefing{
		Firing: 0, Total: 1,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "resolved"}},
		Work:   model.WorkProjection{SourceGraceUntil: &grace},
	})
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateAllClear)
	if c == nil {
		t.Fatalf("expected all_clear candidate, got %v", candidateKinds(cands))
	}
	if c.Next.Kind != model.NextStepGraceDeadline || c.Next.At == nil || !c.Next.At.Equal(grace) {
		t.Fatalf("all_clear must carry the actual grace deadline: %+v", c.Next)
	}
	if c.Members == nil || len(c.Members.Cleared) != 1 || c.Members.Cleared[0] != "CheckoutErrors" {
		t.Fatalf("all_clear must name the cleared member: %+v", c.Members)
	}
	if hasCandidate(cands, model.CandidateRefire) != nil || hasCandidate(cands, model.CandidateMembersChanged) != nil {
		t.Fatalf("all_clear must not also fire refire/members_changed: %v", candidateKinds(cands))
	}
}

// S4-10: a refire during recovery confirmation names what refired and the
// actual next step — never an invented triage dispatch.
func TestMaterialCandidatesRefireNamesSourceChange(t *testing.T) {
	prior := mcTransition(model.LifecycleRecoveryPending, &model.OperatorBriefing{
		Firing: 0, Total: 1,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "resolved"}},
	})
	checkpoint := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 1,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "firing"}},
		Work:   model.WorkProjection{StatusCheckpointAt: &checkpoint},
	})
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateRefire)
	if c == nil {
		t.Fatalf("expected refire candidate, got %v", candidateKinds(cands))
	}
	if c.Members == nil || len(c.Members.NowFiring) != 1 || c.Members.NowFiring[0] != "CheckoutErrors" {
		t.Fatalf("refire must name what refired: %+v", c.Members)
	}
	if c.Next.Kind != model.NextStepStatusCheck || c.Next.At == nil || !c.Next.At.Equal(checkpoint) {
		t.Fatalf("refire must carry the actual next step, not an invented dispatch: %+v", c.Next)
	}
}

// S4-06: a scope/membership change while the Situation stays Active names
// cleared/now-firing/still-firing members without inferring a common cause.
func TestMaterialCandidatesMembersChangedNamesWithoutCommonCause(t *testing.T) {
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 1,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "firing"}},
	})
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 2,
		Alerts: []model.BriefingAlert{{ID: "a", Name: "CheckoutErrors", State: "firing"}, {ID: "b", Name: "PaymentLatency", State: "firing"}},
	})
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateMembersChanged)
	if c == nil {
		t.Fatalf("expected members_changed candidate, got %v", candidateKinds(cands))
	}
	if c.Members == nil || len(c.Members.NowFiring) != 1 || c.Members.NowFiring[0] != "PaymentLatency" {
		t.Fatalf("expected the newly firing member named: %+v", c.Members)
	}
	if len(c.Members.StillFiring) != 2 {
		t.Fatalf("still-firing must list every currently firing member: %+v", c.Members)
	}

	// Silence: an unrelated cycle with no alert delta must not repeat it.
	quiet := MaterialCandidates(&tr, tr)
	if hasCandidate(quiet, model.CandidateMembersChanged) != nil {
		t.Fatalf("an unchanged member set must stay quiet: %v", candidateKinds(quiet))
	}
}

// S4-05: the aggregate work disposition newly reaching Exhausted earns one
// inconclusive_completion candidate — never repeated on a following quiet
// cycle that stays Exhausted.
func TestMaterialCandidatesInconclusiveCompletionFiresOnceOnExhaustion(t *testing.T) {
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true},
	})
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{
		Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseExhausted, ExecutionStarted: true},
	})
	cands := MaterialCandidates(&prior, tr)
	if hasCandidate(cands, model.CandidateInconclusiveCompletion) == nil {
		t.Fatalf("expected inconclusive_completion candidate, got %v", candidateKinds(cands))
	}
	quiet := MaterialCandidates(&tr, tr)
	if hasCandidate(quiet, model.CandidateInconclusiveCompletion) != nil {
		t.Fatalf("a repeated exhausted cycle must stay quiet: %v", candidateKinds(quiet))
	}
}

// S4-07/§5 raw fact: an investigation ability newly blocking or newly
// clearing is a candidate; an unchanged blocked cycle stays quiet.
func TestMaterialCandidatesAbilityChangedTracksBlockAndClear(t *testing.T) {
	blockedStatus := model.AlertINTStatusBlocked
	waitReason := model.WaitReason("assessment_parked")
	blockedContract := model.ActionContract{AlertINTStatus: &blockedStatus, WaitReason: &waitReason}
	waitingStatus := model.AlertINTStatusWaiting
	openContract := model.ActionContract{AlertINTStatus: &waitingStatus}

	prior := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: openContract, Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Firing: 1, Total: 1}}}
	tr := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: blockedContract, Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Firing: 1, Total: 1}}}
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateAbilityChanged)
	if c == nil || c.Limitation == nil || c.Limitation.Cleared || c.Limitation.Code != "assessment_parked" {
		t.Fatalf("expected a newly-blocked ability candidate with its code: %+v", c)
	}

	quiet := MaterialCandidates(&tr, tr)
	if hasCandidate(quiet, model.CandidateAbilityChanged) != nil {
		t.Fatalf("a repeated blocked cycle must stay quiet: %v", candidateKinds(quiet))
	}

	cleared := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: openContract, Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Firing: 1, Total: 1}}}
	clearCands := MaterialCandidates(&tr, cleared)
	c2 := hasCandidate(clearCands, model.CandidateAbilityChanged)
	if c2 == nil || c2.Limitation == nil || !c2.Limitation.Cleared {
		t.Fatalf("expected a cleared ability candidate: %+v", c2)
	}
}

// S4-09: introduce/revise/withdraw are distinguished, never collapsed into
// one undifferentiated "changed" fact.
func TestMaterialCandidatesActionChangedDistinguishesIntroduceAndWithdraw(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	noAction := model.ActionContract{}
	withAction := model.ActionContract{OperatorActionRequired: &action}

	prior := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: noAction, Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Firing: 1, Total: 1}}}
	tr := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: withAction, Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Firing: 1, Total: 1}}}
	introduced := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateActionChanged)
	if introduced == nil || introduced.Action == nil || !introduced.Action.Introduced || introduced.Action.Withdrawn {
		t.Fatalf("expected an introduced action candidate: %+v", introduced)
	}

	withdrawn := hasCandidate(MaterialCandidates(&tr, prior), model.CandidateActionChanged)
	if withdrawn == nil || withdrawn.Action == nil || !withdrawn.Action.Withdrawn || withdrawn.Action.Introduced {
		t.Fatalf("expected a withdrawn action candidate: %+v", withdrawn)
	}

	quiet := MaterialCandidates(&tr, tr)
	if hasCandidate(quiet, model.CandidateActionChanged) != nil {
		t.Fatalf("an unchanged action must stay quiet: %v", candidateKinds(quiet))
	}
}

// B0 integration contract §4: Work.ExecutionStarted's false->true edge is
// the first_execution_assurance candidate — emitted exactly once, never
// re-emitted on a later commit while execution continues.
func TestMaterialCandidatesFirstExecutionAssuranceFiresOnceOnTheEdge(t *testing.T) {
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseQueued}})
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true, InvestigatedNames: []string{"CheckoutErrors"}}})
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateFirstExecutionAssurance)
	if c == nil || c.Members == nil || len(c.Members.NowFiring) != 1 || c.Members.NowFiring[0] != "CheckoutErrors" {
		t.Fatalf("expected a first_execution_assurance candidate naming the actual investigated alerts: %+v", c)
	}
	quiet := MaterialCandidates(&tr, tr)
	if hasCandidate(quiet, model.CandidateFirstExecutionAssurance) != nil {
		t.Fatalf("execution continuing must not re-emit the assurance: %v", candidateKinds(quiet))
	}
}

// Terminal outcomes carry the actual, distinct next step: Recovered work
// has ended; Closed unknown's tracking has ended without confirmation.
func TestMaterialCandidatesTerminalEndDistinguishesRecoveredAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		lifecycle model.Lifecycle
		want      model.NextStepKind
	}{
		{model.LifecycleRecovered, model.NextStepWorkEnded},
		{model.LifecycleClosedUnknown, model.NextStepTrackingEnded},
	} {
		prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Firing: 1, Total: 1})
		tr := mcTransition(tc.lifecycle, &model.OperatorBriefing{Firing: 0, Total: 1})
		c := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateTerminalEnd)
		if c == nil || c.Next.Kind != tc.want {
			t.Fatalf("%s: expected terminal_end with next step %s, got %+v", tc.lifecycle, tc.want, c)
		}
	}
}
