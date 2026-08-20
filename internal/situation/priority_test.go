// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestApplyAttentionFloorsUsesExactlyFourUrgentCodes(t *testing.T) {
	snapshot := sampleSnapshot()
	for _, code := range []string{"critical_anchor", "confirmed_severe_impact", "expanding_blast_radius", "urgent_policy"} {
		snapshot = snapshotForFloor(code)
		reason := requireReason(t, EligibleReasons(snapshot), code)
		if got := applyAttentionFloorsAgainstSnapshot(model.AttentionObserve, snapshot, []model.ReasonCandidate{reason}); got != model.AttentionUrgent {
			t.Fatalf("%s attention = %s", code, got)
		}
	}
	for _, code := range []string{"duration_outlier", "novel_symptom", "envelope_violation", "operator_judgment_needed", "terminal_uncertainty", "invented"} {
		reason := model.ReasonCandidate{Code: code, DeterministicFloor: true}
		if got := applyAttentionFloorsAgainstSnapshot(model.AttentionInvestigate, snapshot, []model.ReasonCandidate{reason}); got != model.AttentionInvestigate {
			t.Fatalf("%s gained an urgent floor: %s", code, got)
		}
	}
	if got := applyAttentionFloorsAgainstSnapshot(model.AttentionInvestigate, snapshot, []model.ReasonCandidate{{Code: "critical_anchor"}}); got != model.AttentionInvestigate {
		t.Fatalf("unmarked candidate gained an urgent floor: %s", got)
	}
}

func TestApplyAttentionFloorsRejectsFabricatedCatalogCandidate(t *testing.T) {
	snapshot := sampleSnapshot()
	fabricated := newCandidate("critical_anchor", "active_source_severity_critical", []string{"delivery:invented"}, true)
	if got := applyAttentionFloorsAgainstSnapshot(model.AttentionObserve, snapshot, []model.ReasonCandidate{fabricated}); got != model.AttentionObserve {
		t.Fatalf("fabricated candidate granted urgent attention: %s", got)
	}
}

func applyAttentionFloorsAgainstSnapshot(proposed model.Attention, snapshot Snapshot, reasons []model.ReasonCandidate) model.Attention {
	return ApplyAttentionFloors(proposed, snapshot, reasons)
}

func snapshotForFloor(code string) Snapshot {
	s := sampleSnapshot()
	switch code {
	case "critical_anchor":
		s.Symptoms = []Symptom{{ID: "critical", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", EvidenceRefs: []string{"delivery:critical"}}}
	case "confirmed_severe_impact":
		s.Impact = []ImpactFact{{Kind: "availability", Severity: "severe", Confirmed: true, EvidenceRefs: []string{"fact:availability"}}}
	case "expanding_blast_radius":
		s.BlastRadius = &BlastRadius{Previous: 1, Current: 3, UrgentBoundary: 2, EvidenceRefs: []string{"fact:scope-before", "fact:scope-now"}}
	case "urgent_policy":
		s.UrgentPolicies = []UrgentPolicy{{ID: "policy:1", Active: true, Scoped: true, EvidenceRefs: []string{"policy:1"}}}
	}
	return s
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
