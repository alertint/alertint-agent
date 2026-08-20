// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ApplyAttentionFloors promotes only the four closed deterministic anchors.
// All other candidate codes remain advisory to validated L2 assessment.
func ApplyAttentionFloors(proposed model.Attention, reasons []model.ReasonCandidate) model.Attention {
	for _, reason := range reasons {
		if _, ok := urgentFloorCodes[reason.Code]; ok && reason.DeterministicFloor {
			return model.AttentionUrgent
		}
	}
	return proposed
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
