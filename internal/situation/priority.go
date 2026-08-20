// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ApplyAttentionFloors promotes only candidates that exactly match a fresh
// deterministic catalog evaluation of snapshot. Caller-authored candidates
// carry no floor authority.
func ApplyAttentionFloors(proposed model.Attention, snapshot Snapshot, reasons []model.ReasonCandidate) model.Attention {
	eligible := EligibleReasons(snapshot)
	for _, supplied := range reasons {
		if _, ok := urgentFloorCodes[supplied.Code]; !ok {
			continue
		}
		for _, expected := range eligible {
			if reasonCandidatesEqual(expected, supplied) && expected.DeterministicFloor {
				return model.AttentionUrgent
			}
		}
	}
	return proposed
}

func reasonCandidatesEqual(left, right model.ReasonCandidate) bool {
	if left.ID != right.ID || left.CatalogVersion != right.CatalogVersion || left.PredicateVersion != right.PredicateVersion ||
		left.Code != right.Code || left.PredicateResult != right.PredicateResult || left.DeterministicFloor != right.DeterministicFloor {
		return false
	}
	leftRefs := canonicalStrings(left.EvidenceRefs)
	rightRefs := canonicalStrings(right.EvidenceRefs)
	if len(leftRefs) != len(rightRefs) {
		return false
	}
	for i := range leftRefs {
		if leftRefs[i] != rightRefs[i] {
			return false
		}
	}
	return true
}

// DeriveInterruptionPriority implements the fixed Situation publication
// ladder. The outward min_severity compatibility floor is applied later when a
// main-channel intent is created.
func DeriveInterruptionPriority(assessment model.Assessment) model.InterruptionPriority {
	if assessment.Attention == model.AttentionUrgent && assessment.SufficientReason != nil && assessment.SufficientReason.Code == "critical_anchor" {
		return model.PriorityCritical
	}
	if assessment.Attention == model.AttentionUrgent || nonempty(assessment.ActionContract.OperatorJudgmentRequested) ||
		nonempty(assessment.ActionContract.OperatorActionRequired) ||
		assessment.SufficientReason != nil && assessment.SufficientReason.Code == "terminal_uncertainty" {
		return model.PriorityHigh
	}
	if assessment.Attention == model.AttentionInvestigate && assessment.ActionContract.NextActor == model.NextActorAlertint {
		return model.PriorityMedium
	}
	return model.PriorityLow
}

func nonempty(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}
