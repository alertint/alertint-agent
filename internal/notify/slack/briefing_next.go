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
			return "Investigating" + briefingExecutionScope(b)
		}
		if *c.AlertINTStatus == model.AlertINTStatusPlanned {
			return "Investigation is queued; it has not started yet." + briefingQueuedEligibility(b.Work, now)
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
		step := "Watching for sustained recovery"
		if grace := b.Work.SourceGraceUntil; grace != nil {
			// The recovery grace deadline is its OWN recorded time, distinct
			// from the status checkpoint briefingNextStep appends below
			// (canonical "recovery-with-work": "confirm recovery through
			// [recorded grace deadline]; investigation status check at
			// [recorded checkpoint]").
			step += " through " + SlackDateToken(*grace, "{time}") + "."
		} else {
			step += "; the next check will reassess whether alerts remain clear."
		}
		if outstanding := briefingOutstandingWork(b, now); outstanding != "" {
			step += " " + outstanding
		}
		return step
	case model.AlertINTActionMonitorSituation:
		step := "Monitoring alert changes."
		if briefingHasUncertainty(b) {
			step += " No verification retry is recorded."
		}
		return step
	}
	return "Automatic work is not recognized; no retry can be promised."
}

// briefingOutstandingWork discloses investigation that is still outstanding
// while the Situation's own orientation has moved elsewhere (canonical
// slide 4 "Confirming recovery": "Disclose any investigation still running
// separately", and the "recovery-with-work" example's "One investigation is
// still running"). Recovery confirmation is about the monitored alerts
// alone; hiding live execution behind it told the operator the episode was
// quieter than the recorded work says (R3 repair, lead review 2026-09-09).
// Every branch reads one recorded Work fact: nothing here claims work
// finished, and nothing invents a new work loop.
//
// Phase and RemainingIncidents answer two different questions and neither
// may be read as the other (R4 repair, lead review round 2, 2026-09-09):
// aggregateWorkPhase reports the highest-priority phase any member schedule
// is in, while RemainingIncidents counts EVERY schedule with outstanding
// automatic work — awaiting_decision, queued, executing and retry_wait
// alike (B0 §3; BuildWorkProjection). One executing schedule beside two
// waiting ones is phase executing with three outstanding, so the count
// proves how much work remains, never how much of it is running.
func briefingOutstandingWork(b *model.OperatorBriefing, now time.Time) string {
	w := b.Work
	switch w.Phase {
	case model.WorkPhaseExecuting:
		if w.RemainingIncidents == 1 {
			return "One investigation is still running."
		}
		return "An investigation is still running." + briefingOutstandingTotal(w)
	case model.WorkPhaseRetryWait:
		if at := w.RetryEligibleAt; at != nil {
			// RetryEligibleAt is the EARLIEST recorded retry across the
			// member schedules, so it dates one retry, not all of them.
			if w.RemainingIncidents == 1 {
				return "One investigation retry is eligible at " + SlackDateToken(*at, "{time}") + "."
			}
			return "The earliest investigation retry is eligible at " + SlackDateToken(*at, "{time}") + "." + briefingOutstandingTotal(w)
		}
		if w.RemainingIncidents == 1 {
			return "One investigation is waiting in back-off; no retry time is recorded."
		}
		return "An investigation is waiting in back-off; no retry time is recorded." + briefingOutstandingTotal(w)
	case model.WorkPhaseQueued:
		return "Investigation work is still outstanding; it has not started yet." +
			briefingQueuedEligibility(w, now) + briefingOutstandingTotal(w)
	case model.WorkPhaseAwaitingDecision:
		// No decision has been committed yet, so no schedule carries a
		// readiness time to state — awaiting a decision is not queued work.
		return "Investigation work is still outstanding; it has not started yet." + briefingOutstandingTotal(w)
	case model.WorkPhaseCollecting, model.WorkPhaseSettled, model.WorkPhaseExhausted, model.WorkPhaseNone:
		// No outstanding automatic work to disclose. A legacy projection
		// (Phase "") falls through to the same silence: unknown work is not
		// a claim that work is running.
	}
	return ""
}

// briefingOutstandingTotal states the recorded outstanding-work aggregate
// when it proves more work than the phase sentence already did. A count of
// one is already carried by that sentence, and a zero count is an
// unpopulated legacy projection rather than a recorded absence.
func briefingOutstandingTotal(w model.WorkProjection) string {
	if w.RemainingIncidents > 1 {
		return fmt.Sprintf(" In total, %d member investigations have outstanding work.", w.RemainingIncidents)
	}
	return ""
}

// briefingExecutionScope names what the running investigation actually took
// as input (canonical slide 4 "first-root-running": "Investigating
// [recorded count] alerts for [recorded scope]: [alert names]"). It reads
// only the Work projection's own frozen claim-time provenance. A projection
// that recorded neither a count nor names is legacy: it says nothing extra
// rather than asserting an unknown that was never a recorded fact.
func briefingExecutionScope(b *model.OperatorBriefing) string {
	w := b.Work
	if !w.InvestigatedCountKnown && len(w.InvestigatedNames) == 0 {
		return "."
	}
	return briefingInputScope(w.InvestigatedCountKnown, w.InvestigatedCount, w.InvestigatedNames, briefingScope(b))
}

// briefingInputScope renders one investigation's recorded input as a
// sentence ending, so a caller writes "Investigating" + this. It is the one
// place the count/name rule lives, shared by the root's Work projection and
// by a first_execution_assurance candidate's own MemberFacts.
//
// countKnown is the ONLY authority for stating a number (B0 §3
// InvestigatedCountKnown / §4 MemberFacts.CountKnown, lead decision B,
// round 2): Situation.Total, the firing count and the separately bounded
// name list's length are three different numbers, and none of them may
// stand in for an unrecorded count. The names are bounded on their own, so
// a name list shorter than a known count is introduced with "including",
// never as the complete input (canonical row 576: "Count the actual
// investigation inputs, not every Situation member or only the still-firing
// members").
func briefingInputScope(countKnown bool, count int, names []string, scope string) string {
	switch {
	case countKnown && len(names) > 0:
		joiner := ": "
		if count > len(names) {
			joiner = ", including "
		}
		return " " + briefingAlertCount(count) + " for " + scope + joiner + briefingNames(names) + "."
	case countKnown:
		return " " + briefingAlertCount(count) + " for " + scope + "."
	case len(names) > 0:
		return " " + scope + ": " + briefingNames(names) + "; the complete investigated alert count is not recorded."
	}
	return " " + scope + "."
}

func briefingAlertCount(n int) string {
	if n == 1 {
		return "1 alert"
	}
	return fmt.Sprintf("%d alerts", n)
}

// briefingQueuedEligibility states what the record actually says about when
// queued work becomes claimable (slide 2 minimal: "queued analysis, with a
// known readiness/due time or actual waiting reason"; the queued example's
// "eligible after [recorded readiness/due condition]"). Eligibility is the
// moment a worker MAY claim the request, never a scheduled execution time
// and never evidence that execution began, so no branch here promises a
// start (G1 repair, lead final review 2026-09-10).
//
// An unknown projection stays silent: a transition predating
// QueuedEligibilityKnown recorded no eligibility at all, and reading its
// missing time as "eligible now" would invent the fact slide 2 asks for.
func briefingQueuedEligibility(w model.WorkProjection, now time.Time) string {
	if !w.QueuedEligibilityKnown {
		return ""
	}
	at := w.QueuedEligibleAt
	if at == nil {
		// The contract reads "planned" for an awaiting-decision schedule as
		// well as a queued one (deriveAlertINTBranch collapses both), and an
		// undecided schedule has no readiness time to state — that IS its
		// waiting reason. Otherwise the schedule is queued but records no
		// time, and briefingNextStep's status checkpoint carries the timing.
		if w.Phase == model.WorkPhaseAwaitingDecision {
			return " No investigation decision is committed yet, so it has no readiness time."
		}
		return " No readiness time is recorded for it."
	}
	if at.After(now) {
		return " It becomes eligible after " + SlackDateToken(*at, "{time}") + "; eligibility is not an execution guarantee."
	}
	// "As of" covers both a schedule that became claimable earlier and one
	// this very commit authorized, whose recorded eligibility is this
	// transition's own instant.
	return " It is eligible for a claim as of " + SlackDateToken(*at, "{time}") + "; eligibility is not an execution guarantee."
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

// briefingAlertInventory renders the current alert inventory.
// memberNamesStated is true when a member candidate already listed the
// recorded names from its own facts: the firing list must not be printed
// twice, and "names were not captured" would contradict names the reply
// just gave. The unknown-state and omitted-alert lines are the briefing's
// own display bounds and stay visible either way.
func briefingAlertInventory(b *model.OperatorBriefing, memberNamesStated bool) []string {
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
	if !memberNamesStated && len(firing) > 0 {
		lines = append(lines, "*Still firing:* "+briefingNames(firing))
	}
	if len(unknown) > 0 {
		lines = append(lines, "*State unknown:* "+briefingNames(unknown))
	}
	if !memberNamesStated && len(b.Alerts) == 0 && (b.Firing > 0 || b.Unknown > 0) {
		lines = append(lines, "Alert names were not captured in this update; details via MCP.")
	}
	if b.AlertsOmitted > 0 {
		lines = append(lines, fmt.Sprintf("%d additional alerts not listed; full list via MCP.", b.AlertsOmitted))
	}
	return lines
}
