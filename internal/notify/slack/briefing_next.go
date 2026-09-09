// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// The deadline promises a controller check, not a retry of a particular probe.
// RetryAt is separately frozen from the work schedule. No model prose or wall
// clock enters this mapping; historical replies use their recorded event time.
func briefingNextStep(t model.Transition, b *model.OperatorBriefing, deadline *time.Time, now time.Time) string {
	if t.Lifecycle == model.LifecycleRecovered {
		return "Recovery confirmed after the observation period; monitoring for this episode has ended."
	}
	if t.Lifecycle == model.LifecycleClosedUnknown {
		return "Recovery could not be confirmed; tracking for this Situation has ended. No automatic retry or resumption is scheduled."
	}
	step := briefingWork(t.ActionContract, b, now)
	if deadline == nil {
		deadline = t.ActionContract.NextUpdateAt
	}
	if deadline != nil {
		// S4-08: this is a status checkpoint, never a reply promise — a check
		// may happen quietly, with no guaranteed reply. RenderDeadline's
		// "update by"/"update overdue" wording is reserved for an actual
		// enforceable notification commitment (the legacy root's own
		// ContractDeadlineAt line, contractAndDeadlineBlock); using it here
		// would claim a promise nothing in this minimal implementation
		// enforces.
		step += " Next status check: " + SlackDateToken(*deadline, "{time}") + "."
	} else {
		step += " Next status check is not scheduled."
	}
	return step
}

func briefingWork(c model.ActionContract, b *model.OperatorBriefing, now time.Time) string {
	if c.AlertINTStatus != nil {
		switch *c.AlertINTStatus {
		case model.AlertINTStatusBlocked:
			return "Automatic work is blocked. No automatic retry is scheduled." + briefingResumeTriggers(c)
		case model.AlertINTStatusExhausted:
			return "Automatic attempts are exhausted. No automatic retry is scheduled." + briefingResumeTriggers(c)
		case model.AlertINTStatusComplete:
			return "The current work is complete; its next action is not specified."
		case model.AlertINTStatusPlanned, model.AlertINTStatusRunning, model.AlertINTStatusWaiting:
			// These states need the specific action below.
		}
	}
	if c.AlertINTAction == nil || c.AlertINTStatus == nil {
		return "Automatic work is not recorded; no retry can be promised."
	}
	switch *c.AlertINTAction {
	case model.AlertINTActionRunAcuteTriage:
		if *c.AlertINTStatus == model.AlertINTStatusRunning {
			return "Investigating."
		}
		if *c.AlertINTStatus == model.AlertINTStatusPlanned {
			return "Investigation is queued; it has not started yet."
		}
		if c.WaitReason != nil && *c.WaitReason == model.WaitReasonAcuteTriageBackoff {
			return briefingRetry("Investigation", b.RetryAt, now)
		}
		return "Investigation is waiting; no retry time is recorded."
	case model.AlertINTActionRetrySituationAssessment:
		if *c.AlertINTStatus == model.AlertINTStatusRunning {
			return "Reassessing the situation, not rerunning verification checks."
		}
		if *c.AlertINTStatus == model.AlertINTStatusPlanned {
			return "Assessment is queued; it has not started yet."
		}
		if c.WaitReason != nil && *c.WaitReason == model.WaitReasonAssessmentRetry {
			return briefingRetry("Assessment", b.RetryAt, now)
		}
		return "Assessment is waiting; no retry time is recorded."
	case model.AlertINTActionVerifyRecovery:
		return "Watching for sustained recovery; the next check will reassess whether alerts remain clear."
	case model.AlertINTActionMonitorSituation:
		step := "Monitoring alert changes."
		if briefingHasUncertainty(b) {
			step += " No verification retry is recorded."
		}
		return step
	}
	return "Automatic work is not recognized; no retry can be promised."
}

func briefingRetry(work string, at *time.Time, now time.Time) string {
	if at == nil {
		return work + " is waiting in back-off; retry time is unavailable."
	}
	if !at.After(now) {
		return work + " retry is due; start is not yet confirmed (scheduled for " + SlackDateToken(*at, "{time}") + ")."
	}
	return work + " retry scheduled for " + SlackDateToken(*at, "{time}") + "."
}

func briefingResumeTriggers(c model.ActionContract) string {
	var triggers []string
	seen := map[model.NextUpdateOn]bool{}
	for _, event := range c.NextUpdateOn {
		if seen[event] {
			continue
		}
		seen[event] = true
		// Only these triggers can unblock work; a routine cadence tick is
		// a status check, not permission to retry a parked request.
		switch event {
		case model.NextUpdateOnMaterialInput:
			triggers = append(triggers, "new evidence arrives")
		case model.NextUpdateOnDependencyRecovery:
			triggers = append(triggers, "the evidence source recovers")
		case model.NextUpdateOnSourceResolution, model.NextUpdateOnSourceRefire, model.NextUpdateOnTriageOutcome,
			model.NextUpdateOnAssessmentRetryDue, model.NextUpdateOnRecoveryGraceExpired, model.NextUpdateOnLifecycleObservationDeadline:
			// Not a promise to resume blocked work.
		}
	}
	if len(triggers) == 0 {
		return ""
	}
	return " Reconsidering when " + strings.Join(triggers, " or ") + "."
}

func briefingHasUncertainty(b *model.OperatorBriefing) bool {
	if b.Failed > 0 || b.Unavailable > 0 {
		return true
	}
	for _, a := range b.Analyses {
		if a.Verification != "supported" || a.VerificationGaps > 0 || a.VerificationLimit != "" {
			return true
		}
	}
	return false
}

func briefingNames(names []string) string {
	var clean []string
	for i, name := range names {
		if i == 8 {
			clean = append(clean, "…")
			break
		}
		clean = append(clean, briefingText(name, 180))
	}
	return strings.Join(clean, ", ")
}

func briefingRemainingAlerts(b *model.OperatorBriefing) []string {
	var firing, unknown []string
	for _, a := range b.Alerts {
		switch a.State {
		case "firing":
			firing = append(firing, a.Name)
		case "unknown":
			unknown = append(unknown, a.Name)
		}
	}
	var lines []string
	if len(firing) > 0 {
		lines = append(lines, "*Still firing:* "+briefingNames(firing))
	}
	if len(unknown) > 0 {
		lines = append(lines, "*State unknown:* "+briefingNames(unknown))
	}
	if len(b.Alerts) == 0 && (b.Firing > 0 || b.Unknown > 0) {
		lines = append(lines, "Alert names were not captured in this update; details via MCP.")
	}
	if b.AlertsOmitted > 0 {
		lines = append(lines, fmt.Sprintf("%d additional alerts not listed; full list via MCP.", b.AlertsOmitted))
	}
	return lines
}
