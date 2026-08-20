// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestApplyAttentionFloorsUsesExactlyFourUrgentCodes(t *testing.T) {
	for _, code := range []string{"critical_anchor", "confirmed_severe_impact", "expanding_blast_radius", "urgent_policy"} {
		reason := model.ReasonCandidate{Code: code, DeterministicFloor: true}
		if got := ApplyAttentionFloors(model.AttentionObserve, []model.ReasonCandidate{reason}); got != model.AttentionUrgent {
			t.Fatalf("%s attention = %s", code, got)
		}
	}
	for _, code := range []string{"duration_outlier", "novel_symptom", "envelope_violation", "operator_judgment_needed", "terminal_uncertainty", "invented"} {
		reason := model.ReasonCandidate{Code: code, DeterministicFloor: true}
		if got := ApplyAttentionFloors(model.AttentionInvestigate, []model.ReasonCandidate{reason}); got != model.AttentionInvestigate {
			t.Fatalf("%s gained an urgent floor: %s", code, got)
		}
	}
	if got := ApplyAttentionFloors(model.AttentionInvestigate, []model.ReasonCandidate{{Code: "critical_anchor"}}); got != model.AttentionInvestigate {
		t.Fatalf("unmarked candidate gained an urgent floor: %s", got)
	}
}

func TestDeriveInterruptionPriorityUsesDeterministicLadder(t *testing.T) {
	operatorAction := "restart database"
	judgment := "identify owning team"
	empty := ""
	cases := []struct {
		name       string
		assessment model.Assessment
		want       model.InterruptionPriority
	}{
		{"critical anchor", assessmentFor(model.ReasonCandidate{Code: "critical_anchor"}, model.AttentionUrgent, model.NextActorAlertint), model.PriorityCritical},
		{"urgent", assessmentFor(model.ReasonCandidate{Code: "confirmed_severe_impact"}, model.AttentionUrgent, model.NextActorAlertint), model.PriorityHigh},
		{"operator action", model.Assessment{Attention: model.AttentionInvestigate, ActionContract: model.ActionContract{NextActor: model.NextActorOperator, OperatorActionRequired: &operatorAction}}, model.PriorityHigh},
		{"operator judgment", model.Assessment{Attention: model.AttentionInvestigate, ActionContract: model.ActionContract{NextActor: model.NextActorOperator, OperatorJudgmentRequested: &judgment}}, model.PriorityHigh},
		{"terminal uncertainty", assessmentFor(model.ReasonCandidate{Code: "terminal_uncertainty"}, model.AttentionInvestigate, model.NextActorNone), model.PriorityHigh},
		{"alertint investigates", assessmentFor(model.ReasonCandidate{Code: "duration_outlier"}, model.AttentionInvestigate, model.NextActorAlertint), model.PriorityMedium},
		{"observe", model.Assessment{Attention: model.AttentionObserve, ActionContract: model.ActionContract{NextActor: model.NextActorNone}}, model.PriorityLow},
		{"operator actor without requested work", model.Assessment{Attention: model.AttentionInvestigate, ActionContract: model.ActionContract{NextActor: model.NextActorOperator}}, model.PriorityLow},
		{"empty operator fields", model.Assessment{Attention: model.AttentionInvestigate, ActionContract: model.ActionContract{NextActor: model.NextActorOperator, OperatorActionRequired: &empty, OperatorJudgmentRequested: &empty}}, model.PriorityLow},
		{"off ladder", model.Assessment{Attention: model.Attention("panic"), ActionContract: model.ActionContract{NextActor: model.NextActor("model")}}, model.PriorityLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveInterruptionPriority(tc.assessment); got != tc.want {
				t.Fatalf("priority = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCriticalPriorityRequiresUnquietedCriticalReason(t *testing.T) {
	a := assessmentFor(model.ReasonCandidate{Code: "critical_anchor"}, model.AttentionInvestigate, model.NextActorAlertint)
	if got := DeriveInterruptionPriority(a); got != model.PriorityMedium {
		t.Fatalf("quieted critical priority = %s", got)
	}
}

func assessmentFor(reason model.ReasonCandidate, attention model.Attention, actor model.NextActor) model.Assessment {
	return model.Assessment{
		Attention:        attention,
		SufficientReason: &model.SufficientReason{Code: reason.Code, CandidateID: reason.ID, EvidenceRefs: append([]string(nil), reason.EvidenceRefs...)},
		ActionContract:   model.ActionContract{NextActor: actor},
	}
}
