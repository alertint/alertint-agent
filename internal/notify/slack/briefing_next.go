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
	// S1-05/S4-08 (§63): the recovery-pending lifecycle and outstanding
	// investigation coexist, and only presentation can say both.
	// deriveAlertINTBranch ranks EVERY triage phase and both Assessment
	// retry phases above its own recovery-pending case, and
	// ControllerState.TriagePhase is aggregateTriagePhase over the same
	// member schedules BuildWorkProjection reduces — so a Situation
	// confirming recovery while any work is outstanding always derives a
	// work contract, and the branch that states the persisted grace
	// deadline is unreachable for it. The deadline is a lifecycle fact,
	// recorded on the transition that observed clearance and carried on the
	// projection independently of which action the contract selected; it
	// was reaching no operator at all in that state (canonical
	// "recovery-with-work": "Recovery grace and investigation coexist.
	// Lifecycle sets orientation; activity describes remaining work").
	//
	// The composition adds a clause; it changes no contract, decides no
	// work and reorders no schedule. The work sentence below it is still
	// the contract's own recorded truth, the status checkpoint still keeps
	// its own clause, and a nil grace states no deadline rather than
	// inventing one. A terminal lifecycle returned above, so nothing here
	// can reopen an ended episode; a delivery-time superseded execution
	// replaces this whole string in briefingJournalPresented, so a
	// historical row gains no current promise from it either.
	if t.Lifecycle == model.LifecycleRecoveryPending && !briefingRecoveryWatched(t.ActionContract) {
		step = briefingRecoveryWatch(b.Work) + " " + step
	}
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
			// deriveAlertINTBranch collapses an undecided schedule and a
			// committed-but-unclaimed one into the same "planned" contract
			// status, so the populated Work phase — never the contract
			// alone — decides which of the two this actually is (P2-1
			// repair, lead review of the final repairs, 2026-09-10).
			// Calling an undecided schedule queued asserted a request
			// nothing had committed, and the eligibility clause then
			// contradicted that first sentence in the same breath.
			if b.Work.Phase == model.WorkPhaseAwaitingDecision {
				return briefingAwaitingDecision
			}
			return "Investigation is queued" + briefingQueuedNotStarted(b.Work) +
				briefingQueuedEligibility(b.Work, now) + briefingRecordedRetry(b.Work, now)
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
		step := briefingRecoveryWatch(b.Work)
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
// briefingRecoveryWatch states the observation the recovery-pending
// lifecycle actually is, and the persisted deadline it runs to. The grace
// deadline is its OWN recorded time, distinct from the status checkpoint
// briefingNextStep appends and from every work time beside it (canonical
// "recovery-with-work": "confirm recovery through [recorded grace deadline];
// investigation status check at [recorded checkpoint]").
//
// A nil deadline says only what the record says: the observation is running
// and the next check reassesses whether the alerts are still clear. Reading
// a missing grace as an expiry, or borrowing the checkpoint for it, would
// invent the one fact this sentence exists to state.
func briefingRecoveryWatch(w model.WorkProjection) string {
	const watching = "Watching for sustained recovery"
	if grace := w.SourceGraceUntil; grace != nil {
		return watching + " through " + SlackDateToken(*grace, "{time}") + "."
	}
	return watching + "; the next check will reassess whether alerts remain clear."
}

// briefingRecoveryWatched reports whether briefingWork's own verify_recovery
// branch already stated the watch above, which is the one case where
// composing it again would report a single recorded fact twice.
func briefingRecoveryWatched(c model.ActionContract) bool {
	if c.AlertINTAction == nil || c.AlertINTStatus == nil || *c.AlertINTAction != model.AlertINTActionVerifyRecovery {
		return false
	}
	switch *c.AlertINTStatus {
	case model.AlertINTStatusPlanned, model.AlertINTStatusRunning, model.AlertINTStatusWaiting:
		return true
	case model.AlertINTStatusBlocked, model.AlertINTStatusExhausted, model.AlertINTStatusComplete:
		// briefingWork returns for these before the verify_recovery branch:
		// they report an obstacle or an end, and state no watch of their own.
	}
	return false
}

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
			// The waiting SCHEDULE is a triage back-off — this aggregate
			// phase proves that much — but the TIME is not necessarily its
			// own: RetryEligibleAt is the earliest of the member back-offs
			// AND the committed Assessment-level retry
			// (CommittedOperatorBriefing's overlay), and the projection
			// records nothing that separates the two. Calling it an
			// investigation retry asserted an owner the record cannot name
			// (§63 correction), so the phase keeps its attribution and the
			// instant loses one. Being the EARLIEST of several, it still
			// dates ONE retry rather than all of them.
			if w.RemainingIncidents == 1 {
				return "One investigation is waiting in back-off. " + briefingRetryEligibility("A recorded retry", *at, now)
			}
			return "An investigation is waiting in back-off. " +
				briefingRetryEligibility("The earliest recorded retry", *at, now) + briefingOutstandingTotal(w)
		}
		if w.RemainingIncidents == 1 {
			return "One investigation is waiting in back-off; no retry time is recorded."
		}
		return "An investigation is waiting in back-off; no retry time is recorded." + briefingOutstandingTotal(w)
	case model.WorkPhaseQueued:
		return "Investigation work is still outstanding" + briefingQueuedNotStarted(w) +
			briefingQueuedEligibility(w, now) + briefingRecordedRetry(w, now) + briefingOutstandingTotal(w)
	case model.WorkPhaseAwaitingDecision:
		// Queued outranks awaiting_decision in aggregateWorkPhase, so this
		// aggregate phase proves EVERY remaining schedule is undecided: the
		// shared sentence is true of all of them, and none of them carries a
		// readiness time to state. Reporting only "not started" withheld the
		// one fact slide 4 asks this surface for — the actual wait (P2-2
		// repair, lead review of the final repairs, 2026-09-10).
		return "Investigation work is still outstanding. " + briefingAwaitingDecision + briefingOutstandingTotal(w)
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

// briefingAwaitingDecision is the one sentence both work surfaces use for a
// ready Incident whose Triage schedule holds no committed request yet
// (WorkPhaseAwaitingDecision). It states a recorded waiting reason, not a
// queued request and not a promise that a decision is imminent: the
// controller commits one when it next re-decides on this Situation's own
// facts, which the status checkpoint beside this sentence already dates.
const briefingAwaitingDecision = "Awaiting an investigation decision; no request is committed yet."

// briefingQueuedNotStarted closes the queued sentence on both work
// surfaces, and states that nothing has started ONLY when the projection
// records no claimed attempt anywhere in this Situation.
//
// aggregateWorkPhase ranks a queued schedule above retry_wait once some
// OTHER member schedule has executed, so an aggregate phase of queued
// covers two different records: nothing in this Situation has ever run, and
// one schedule is queued beside another that already claimed an attempt and
// fell into back-off. The shared "it has not started yet" was false of the
// second, denying execution the immutable attempts ledger recorded (repair,
// lead renderer review 2026-09-10, contract §59).
//
// ExecutionStarted is a PAST fact, so it may only withdraw the denial, never
// assert that work is running now. Nothing needs to be added in its place:
// executing outranks queued in that same aggregation, so this phase already
// proves no member schedule is currently in flight, and the eligibility
// clause and outstanding total that follow still carry the actual wait.
func briefingQueuedNotStarted(w model.WorkProjection) string {
	if w.ExecutionStarted {
		return "."
	}
	return "; it has not started yet."
}

// briefingRecordedRetry discloses the retry the record actually holds beside
// queued work (canonical slide 2 minimal, backoff node: the root must carry a
// "Specific limitation and retry eligibility time, if recorded", and "Wait
// until recorded retry eligibility ... Status checkpoint is separate").
//
// aggregateWorkPhase ranks a queued schedule ABOVE retry_wait once some other
// member schedule has executed, and only the retry_wait branch ever read
// RetryEligibleAt — so in exactly the mixed record the previous repair
// described, the back-off schedule's own recorded retry time was dropped from
// both work surfaces while the queued readiness time beside it displayed
// (repair, lead mixed-work review 2026-09-10, contract §61).
//
// The clause is deliberately unattributed. RetryEligibleAt is the earliest of
// the member triage back-offs AND the committed Assessment-level retry
// (CommittedOperatorBriefing overlays situations.retry_at onto it), and the
// projection records nothing that separates the two here, so calling this an
// investigation retry would assert provenance nothing proves — that same
// node's "Distinguish assessment retries from acute-triage retries" read
// honestly rather than guessed. Being the EARLIEST of several, it dates ONE
// retry: the indefinite article keeps it from speaking for every outstanding
// schedule, and no count of retries and no incident identity is claimed.
//
// Eligibility is when a retry MAY be claimed, never a promise that one runs
// then and never evidence that anything is running now — executing outranks
// queued in that same aggregation, so this phase still proves no member
// schedule is in flight. The queued readiness time, the recovery grace
// deadline and the status checkpoint each keep their own clause. A nil time
// stays silent: no back-off schedule and no assessment recorded a retry, and
// the queued clause already carries this phase's actual wait.
func briefingRecordedRetry(w model.WorkProjection, now time.Time) string {
	if w.RetryEligibleAt == nil {
		return ""
	}
	return " " + briefingRetryEligibility("A separately recorded retry", *w.RetryEligibleAt, now)
}

// briefingRetryEligibility states one recorded retry eligibility in the
// tense the recorded instant actually supports, and leaves it unattributed:
// eligibility is when a retry MAY be claimed, so a future instant is a
// wait and a passed one is a fact, and neither is a promise that anything
// runs then. subject carries only how many retries the caller's own
// aggregate proves it speaks for — never whose retry it is, which
// Work.RetryEligibleAt does not record.
func briefingRetryEligibility(subject string, at, now time.Time) string {
	when := SlackDateToken(at, "{time}")
	if at.After(now) {
		return subject + " becomes eligible after " + when + "."
	}
	return subject + " is eligible as of " + when + "."
}

// briefingQueuedEligibility states what the record actually says about when
// queued work becomes claimable (slide 2 minimal: "queued analysis, with a
// known readiness/due time or actual waiting reason"; the queued example's
// "eligible after [recorded readiness/due condition]"). Eligibility is the
// moment a worker MAY claim the request, never a scheduled execution time
// and never evidence that execution began, so no branch here promises a
// start (G1 repair, lead final review 2026-09-10).
//
// QueuedEligibleAt is the EARLIEST recorded eligibility across the queued
// member schedules, so beside more than one outstanding investigation it
// dates ONE of them and never the aggregate — the same rule
// briefingOutstandingWork already applies to RetryEligibleAt. An
// unqualified "it" there read as the moment all outstanding work becomes
// eligible, which the record never said (P2-3 repair, lead review of the
// final repairs, 2026-09-10). RemainingIncidents is the honest
// discriminator even though it counts every outstanding schedule rather
// than only the queued ones: above one, this sentence must not speak for
// the whole count, and the qualified wording claims exactly one queued
// schedule, which a non-nil earliest time proves.
//
// An unknown projection stays silent: a transition predating
// QueuedEligibilityKnown recorded no eligibility at all, and reading its
// missing time as "eligible now" would invent the fact slide 2 asks for.
// An undecided schedule never reaches here — briefingAwaitingDecision is
// its whole sentence — so nil here means a queued schedule that records no
// time, and briefingNextStep's status checkpoint carries the timing.
func briefingQueuedEligibility(w model.WorkProjection, now time.Time) string {
	if !w.QueuedEligibilityKnown {
		return ""
	}
	multiple := w.RemainingIncidents > 1
	at := w.QueuedEligibleAt
	if at == nil {
		if multiple {
			return " No readiness time is recorded for any queued investigation."
		}
		return " No readiness time is recorded for it."
	}
	// "As of" covers both a schedule that became claimable earlier and one
	// this very commit authorized, whose recorded eligibility is this
	// transition's own instant.
	when := SlackDateToken(*at, "{time}")
	const notAPromise = "; eligibility is not an execution guarantee."
	switch {
	case multiple && at.After(now):
		return " The earliest queued investigation becomes eligible after " + when + notAPromise
	case multiple:
		return " At least one queued investigation is eligible for a claim as of " + when + notAPromise
	case at.After(now):
		return " It becomes eligible after " + when + notAPromise
	}
	return " It is eligible for a claim as of " + when + notAPromise
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
