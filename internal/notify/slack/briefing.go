// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	slacklib "github.com/slack-go/slack"
)

// Untrusted selected prose cannot introduce mentions, links, new lines or
// mrkdwn delimiters. Escape before composing our own trusted Slack markup.
func briefingText(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		s = boundedRunes(s, limit) + "…"
	}
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "*", "∗", "_", "＿", "`", "'", "~", "∼").Replace(s)
	if len(s) > limit {
		s = boundedRunes(s, limit)
		// Keep an escaped entity whole at the truncation boundary.
		if amp := strings.LastIndex(s, "&"); amp > strings.LastIndex(s, ";") {
			s = s[:amp]
		}
		s += "…"
	}
	return s
}

func briefingScope(b *model.OperatorBriefing) string {
	scope := b.DisplayScope
	if scope == "" {
		scope = b.Scope
	}
	return briefingText(scope, 100)
}

// Reuse persisted finding titles, always qualified, without a new model call.
// Before analysis, source symptom names provide the descriptive fallback.
func briefingSubject(b *model.OperatorBriefing) string {
	for _, a := range b.Analyses {
		if strings.TrimSpace(a.Title) != "" {
			return "Hypothesis: " + briefingText(a.Title, 140)
		}
	}
	var symptoms []string
	for _, symptom := range b.Symptoms {
		if strings.TrimSpace(symptom) != "" && symptom != "…" {
			symptoms = append(symptoms, symptom)
		}
		if len(symptoms) == 2 {
			break
		}
	}
	if len(symptoms) > 0 {
		return briefingText(strings.Join(symptoms, ", "), 140)
	}
	return ""
}

func briefingTitleContext(b *model.OperatorBriefing) string {
	context := briefingScope(b)
	if subject := briefingSubject(b); subject != "" {
		context += " — " + subject
	}
	return context
}

// One color communicates overall status; phase styling remains bold-only.
func briefingStatus(t model.Transition) (marker, label string) {
	switch {
	case t.Lifecycle == model.LifecycleRecovered:
		return "🟢", "Recovered"
	case t.Lifecycle == model.LifecycleClosedUnknown:
		return "🔴", "Recovery unconfirmed"
	case t.Attention == model.AttentionUrgent:
		return "🔴", "Urgent"
	case t.Attention == model.AttentionInvestigate || operatorWorkBlocked(t.ActionContract) || t.ActionContract.OperatorActionRequired != nil:
		return "🔴", "Needs investigation"
	case t.Lifecycle == model.LifecycleRecoveryPending:
		return "🔵", "Confirming recovery"
	default:
		return "🔵", "Monitoring"
	}
}

func briefingState(b *model.OperatorBriefing) string {
	if b.Total == 0 {
		return "Current alert state unavailable"
	}
	if b.Firing == 0 && b.Unknown == 0 {
		return fmt.Sprintf("%d alerts resolved", b.Total)
	}
	s := fmt.Sprintf("%d/%d alerts firing", b.Firing, b.Total)
	if b.Resolved > 0 {
		s += fmt.Sprintf(" · %d resolved", b.Resolved)
	}
	if b.Unknown > 0 {
		s += fmt.Sprintf(" · %d unobserved", b.Unknown)
	}
	return s
}

func briefingImpact(t model.Transition) string {
	if a := t.Projection.Assessment; a != nil {
		switch a.Impact {
		case model.ImpactConfirmed:
			return "Confirmed impact"
		case model.ImpactSuspected:
			return "Suspected impact"
		case model.ImpactNoneObserved, model.ImpactUnknown:
			return "Impact unknown"
		}
	}
	return "Impact unknown"
}

func briefingAnalysis(b *model.OperatorBriefing, detailed bool) string {
	var lines []string
	if len(b.Analyses) == 0 {
		if !detailed && len(b.Symptoms) > 0 {
			lines = append(lines, "*Alerts:* "+briefingSymptoms(b.Symptoms))
		}
		lines = append(lines, "No completed analysis available; cause remains unconfirmed.")
	}
	limit := 1
	if detailed {
		limit = 3
	}
	for i, a := range b.Analyses {
		if i >= limit {
			break
		}
		if i > 0 {
			lines = append(lines, "")
		}
		if detailed {
			lines = append(lines, briefingEvidence(a)...)
		} else {
			lines = append(lines, briefingFinding(a, b.Historical)...)
		}
		if a.AnalyzedAt != nil {
			lines = append(lines, "Finding at "+SlackDateToken(*a.AnalyzedAt, "{date_short} {time}"))
		} else if detailed {
			lines = append(lines, "Analysis time unavailable.")
		}
	}
	if b.Failed > 0 {
		lines = append(lines, fmt.Sprintf("Analysis failed for %d incident(s); coverage incomplete.", b.Failed))
	}
	if b.Pending > 0 {
		lines = append(lines, fmt.Sprintf("%d incident(s) still awaiting analysis.", b.Pending))
	}
	if b.Unavailable > 0 {
		lines = append(lines, fmt.Sprintf("Analysis unavailable for %d incident(s); not scheduled for these incidents.", b.Unavailable))
	}
	if b.AnalysisCount > limit {
		lines = append(lines, fmt.Sprintf("Showing %d of %d completed analyses; full detail via MCP.", limit, b.AnalysisCount))
	}
	return strings.Join(lines, "\n")
}

func briefingInterpretation(a model.IncidentAnalysis) string {
	if a.Summary != "" {
		return a.Summary
	}
	return a.Title
}

func briefingEvidence(a model.IncidentAnalysis) []string {
	lines := []string{"*Observed*"}
	for j, f := range a.Findings {
		if j == 3 {
			break
		}
		lines = append(lines, "• "+briefingText(f, 300))
	}
	if len(a.Findings) == 0 {
		lines = []string{"*Observed:* No supporting observations were recorded; this does not establish that the service is healthy."}
	}
	return append(lines, "*Interpretation:* "+briefingText(briefingInterpretation(a), 300), "*Still unknown:* "+briefingUncertainty(a))
}

func briefingFinding(a model.IncidentAnalysis, historical bool) []string {
	label := "*Likely cause:*"
	if a.Stale && !historical {
		label = "*Earlier hypothesis:*"
	}
	lines := []string{label + " " + briefingText(briefingInterpretation(a), 240)}
	if len(a.Findings) > 0 {
		lines = append(lines, "*Supporting observations:* "+briefingText(a.Findings[0], 180))
	}
	qualification := "Hypothesis; not a confirmed cause."
	if a.Verification != "supported" || a.VerificationGaps > 0 || a.VerificationLimit != "" {
		qualification = "Verification limited; cause unconfirmed."
	}
	// S3-03 (B0 integration contract §4): a newer alert delivery arriving
	// after analysis (Stale) alone does not invalidate the hypothesis — the
	// "Earlier hypothesis" label above and the analyzed-at date already say
	// this finding predates the newest observation, honestly, without
	// claiming its relevance is reduced.
	return append(lines, qualification)
}

func briefingUncertainty(a model.IncidentAnalysis) string {
	parts := []string{"Causality remains unproven."}
	if a.Verification == "supported" {
		parts = append(parts, "Verification supports the hypothesis.")
	}
	if a.Verification == "revised" {
		parts = append(parts, "Verification revised the hypothesis.")
	}
	if a.Verification == "" {
		parts = append(parts, "verification not recorded.")
	}
	if a.Verification == "degraded" {
		parts = append(parts, "verification is incomplete.")
	}
	if a.VerificationLimit != "" {
		parts = append(parts, briefingVerificationLimit(a.VerificationLimit)+".")
	}
	if a.VerificationGaps > 0 {
		parts = append(parts, fmt.Sprintf("%d verification checks unavailable or invalid.", a.VerificationGaps))
	}
	// S3-03: a Stale flip (a newer alert delivery, or a missing analysis
	// time) is not itself evidence against the hypothesis — say nothing
	// here rather than invent an invalidation claim from the timestamp.
	return strings.Join(parts, " ")
}

// These are the stored verifier's reason codes, not free-form public prose.
// Unknown reasons remain explicit limitations without exposing internal detail.
func briefingVerificationLimit(reason string) string {
	switch reason {
	case "verification_source_unavailable":
		return "verification source unavailable"
	case "llm_call_failed":
		return "verification review could not complete"
	case "llm_response_invalid":
		return "verification review returned an unusable response"
	default:
		return "verification limitation recorded; details unavailable"
	}
}

// briefingAction renders the operator Action line from the RECORDED
// operator contract alone (canonical slide 4 thread contract: "Add a
// concrete Action: only when the operator contract requires one"; the
// "Required operator action changes" row: "Introduce, revise or explicitly
// withdraw the concrete request... do not leave obsolete instructions
// uncorrected").
//
// Firing counts, raised attention and a blocked or exhausted automatic
// status are AlertINT's own facts about its OWN work. None of them is a
// human request, and deriving one from them put an on-call ask nobody
// recorded in front of an operator — including on the canonical
// "investigation:exhausted" example, whose assumption is explicitly "no
// separate human action requested" (R4 repair, lead review 2026-09-09).
// The line itself stays present in every state; only its content changed,
// so absence of a request is stated rather than left ambiguous.
//
// Interface limit reported with this repair: model.OperatorAction is a
// closed single-value enum (investigate_situation) carrying no affected
// source or alert, so the canonical "action-required" example's concrete
// naming ("check [affected source] for missing lifecycle updates for
// [affected alert]") cannot be rendered from recorded facts. The recorded
// request is stated as recorded; nothing is invented to fill that gap.
func briefingAction(b *model.OperatorBriefing, t model.Transition) string {
	scope := briefingScope(b)
	if a := t.ActionContract.OperatorActionRequired; a != nil {
		return "On-call: " + briefingRequestSubject(*a, scope) + " via MCP and check current service health."
	}
	if withdrawn, action := briefingWithdrawnAction(t); withdrawn {
		return "None required from on-call; the earlier request to " + briefingRequestSubject(action, scope) + " is no longer needed."
	}
	switch {
	case t.Lifecycle == model.LifecycleClosedUnknown:
		return "None required from on-call; recovery could not be confirmed."
	case b.Total == 0:
		return "None required from on-call; the current alert state is unavailable."
	case b.Firing == 0 && b.Unknown == 0:
		return "None required from on-call; alerts resolved."
	}
	// The generic close: true in every remaining state, and — unlike a
	// work-status claim — it cannot contradict an exhausted or blocked
	// schedule described elsewhere in the same message.
	return "None required from on-call; no operator action is recorded."
}

// briefingRequestSubject names one recorded OperatorAction code in operator
// words. Unrecognized codes stay deliberately unspecific rather than
// inventing a task the contract never recorded.
func briefingRequestSubject(a model.OperatorAction, scope string) string {
	if a == model.OperatorActionInvestigateSituation {
		return "investigate " + scope
	}
	return "act on " + scope
}

// briefingWithdrawnAction reports the recorded withdrawal of an earlier
// operator request (B0 §4 ActionFacts.Withdrawn). B3 emits the structural
// fact; B5 decides whether the withdrawal is actually delivered. Rendering
// it here is what keeps an obsolete instruction from standing uncorrected.
func briefingWithdrawnAction(t model.Transition) (bool, model.OperatorAction) {
	d := t.Projection.OperatorDelta
	if d == nil {
		return false, ""
	}
	for _, c := range d.Candidates {
		if c.Kind == model.CandidateActionChanged && c.Action != nil && c.Action.Withdrawn {
			return true, c.Action.Action
		}
	}
	return false, ""
}

func operatorWorkBlocked(c model.ActionContract) bool {
	return c.AlertINTStatus != nil && (*c.AlertINTStatus == model.AlertINTStatusBlocked || *c.AlertINTStatus == model.AlertINTStatusExhausted)
}

func renderBriefingRoot(in SituationRootInput) RenderedMessage {
	b := in.Summary.Briefing
	t := in.SourceTransition
	orientation := situation.DeriveOrientation(in.Summary, t)
	marker, label := briefingStatus(t)
	title := drillPrefix(t.Drill) + marker + " *" + label + " · " + briefingTitleContext(b) + "*"
	phase := renderOrientationChain(orientation)
	status := briefingState(b) + " · " + briefingImpact(t)
	if b.Critical > 0 {
		status += fmt.Sprintf(" · %d active critical alert(s)", b.Critical)
	}
	activity := "*AlertINT:* " + briefingNextStep(t, b, in.ContractDeadlineAt, in.Now)
	action := "*Action:* " + briefingAction(b, t)
	analysis := briefingAnalysis(b, false)
	lines := []string{title, phase, status, analysis, activity, action}
	blocks := []slacklib.Block{sectionBlock(title), contextBlock(phase), contextBlock(status), sectionBlock(analysis), sectionBlock(activity + "\n" + action)}
	if len(in.Summary.RecordedOperatorContext) > 0 {
		note := "Recorded context: " + briefingText(in.Summary.RecordedOperatorContext[len(in.Summary.RecordedOperatorContext)-1], 160)
		lines = append(lines, note)
		blocks = append(blocks, contextBlock(note))
	}
	if t.Lifecycle.Terminal() {
		line := durationPeakLine(in.Summary)
		lines = append(lines, line)
		blocks = append(blocks, contextBlock(line))
	}
	footer := briefingFooter(in.Summary)
	lines = append(lines, footer)
	blocks = append(blocks, sectionBlock(footer))
	return RenderedMessage{Text: strings.Join(lines, "\n"), Blocks: blocks}
}

func briefingFooter(s model.EpisodeSummary) string {
	handle := s.PublicHandle
	if handle == "" {
		handle = s.SituationID
	}
	return "Investigate via MCP\nget situation " + briefingText(handle, 200) + " using alertint"
}

func briefingJournal(t model.Transition) (string, string) {
	b := t.Projection.Briefing
	headline := "Update"
	switch t.Lifecycle {
	case model.LifecycleRecoveryPending:
		headline = "Recovery observed"
	case model.LifecycleRecovered:
		headline = "Recovered"
	case model.LifecycleClosedUnknown:
		headline = "Recovery unconfirmed"
	case model.LifecycleActive:
		// Keep the active update heading.
	}
	var lines []string
	selected := *b
	if d := t.Projection.OperatorDelta; d != nil {
		selected.Analyses = d.Analyses
		selected.AnalysisCount = len(d.Analyses)
		// Availability changes are explained once by the delta, not repeated
		// as a copy of the root's current work inventory.
		selected.Failed, selected.Pending, selected.Unavailable = 0, 0, 0
		lines = append(lines, briefingDeltaLines(d, b)...)
		// A useful finding reported as a candidate alone still headlines as
		// evidence: the overview-driven branch below cannot see it, because
		// the bounded Analyses list is exactly what it fell outside of.
		if t.Lifecycle == model.LifecycleActive && briefingHasCandidateFinding(d) {
			headline = "Evidence update"
		}
		if t.Lifecycle == model.LifecycleActive && d.StateChanged && b.Firing < d.PreviousFiring && b.Firing > 0 {
			headline = "Partial recovery · " + briefingState(b)
		}
	}
	if len(selected.Analyses) > 0 || t.Projection.OperatorDelta == nil {
		if t.Lifecycle == model.LifecycleActive {
			headline = "Evidence update"
		}
		lines = append(lines, briefingAnalysis(&selected, true))
	}
	if t.Reason == model.ReasonOperatorArtifactRecorded {
		headline = briefingText(t.Journal.AttributedActor, 120) + ": " + briefingText(t.Journal.Headline, 200)
		lines = []string{briefingText(t.Journal.Detail, 1500)}
	} else {
		headline = briefingReplyTitle(headline, t, b)
	}
	marker, _ := briefingStatus(t)
	headline = marker + " " + headline
	// A reply that already carries the initial execution assurance has
	// stated the recorded count and names once; the activity line then says
	// what happens next without repeating the same scope sentence back
	// (canonical "Keep the attention cost bounded"). The root is the
	// opposite case: it carries no assurance line, so its activity line is
	// where the recorded execution scope belongs.
	activity := b
	if t.Projection.OperatorDelta != nil && briefingAssuranceLine(t.Projection.OperatorDelta, b) != "" {
		trimmed := *b
		trimmed.Work.InvestigatedNames = nil
		trimmed.Work.InvestigatedCount, trimmed.Work.InvestigatedCountKnown = 0, false
		activity = &trimmed
	}
	lines = append(lines, "*AlertINT:* "+briefingNextStep(t, activity, t.ActionContract.NextUpdateAt, t.CreatedAt), "*Action:* "+briefingAction(b, t))
	// Each bounded delta/evidence group gets its own section. Combining long
	// alert names with evidence must not truncate the hypothesis qualification.
	detail := strings.Join(lines, "\n\n")
	return headline, detail
}

func briefingReplyTitle(headline string, t model.Transition, b *model.OperatorBriefing) string {
	d := t.Projection.OperatorDelta
	if t.Lifecycle == model.LifecycleActive && d != nil &&
		d.StateChanged && b.Firing < d.PreviousFiring && b.Firing > 0 && len(d.ClearedAlerts) > 0 {
		cleared := briefingText(d.ClearedAlerts[0], 100)
		if len(d.ClearedAlerts) > 1 {
			cleared += fmt.Sprintf(" and %d more", len(d.ClearedAlerts)-1)
		}
		partial := "Partial recovery · " + cleared + " cleared · " + briefingState(b)
		if len(d.Analyses) > 0 {
			selected := *b
			selected.Analyses = d.Analyses
			partial += " · Evidence update — " + briefingSubject(&selected)
		}
		return partial
	}
	// Evidence replies use the newly selected finding, not an older root title.
	if t.Lifecycle == model.LifecycleActive && d != nil && len(d.Analyses) > 0 {
		selected := *b
		selected.Analyses = d.Analyses
		return headline + " · " + briefingTitleContext(&selected)
	}
	return headline + " · " + briefingTitleContext(b)
}

func briefingDeltaLines(d *model.OperatorDelta, b *model.OperatorBriefing) []string {
	var lines []string
	if d.StateChanged {
		lines = append(lines, fmt.Sprintf("%d/%d → %d/%d alerts firing.", d.PreviousFiring, d.PreviousTotal, b.Firing, b.Total))
		if len(d.ClearedAlerts) > 0 {
			lines = append(lines, "*Cleared:* "+briefingNames(d.ClearedAlerts))
		}
		if len(d.NewFiringAlerts) > 0 {
			lines = append(lines, "*Now firing:* "+briefingNames(d.NewFiringAlerts))
		}
		lines = append(lines, briefingRemainingAlerts(b)...)
	}
	if d.ScopeChanged {
		lines = append(lines, "Affected scope changed from "+briefingText(d.PreviousScope, 140)+" to "+briefingText(b.Scope, 140)+".")
	}
	if d.SymptomsChanged {
		lines = append(lines, "Observed symptoms: "+briefingSymptoms(d.PreviousSymptoms)+" → "+briefingSymptoms(b.Symptoms)+"; reassess the affected service.")
	}
	if d.AttentionIncreased {
		lines = append(lines, "Urgency increased; review current service impact now.")
	}
	// Every line below is driven by the delta's own structured Candidates
	// first and falls back to the legacy boolean only when no candidate of
	// that kind rode this delta. B3 emits candidate-ONLY events by design
	// (an out-of-overview finding, a completion with no aggregate failure
	// count behind it, a cleared obstacle that has no legacy boolean at
	// all), so gating them on the old flags dropped the fact entirely
	// (R1 repair, lead review 2026-09-09).
	if line := briefingAbilityChangeLine(d, b); line != "" {
		lines = append(lines, line)
	}
	if line := briefingActionChangeLine(d); line != "" {
		lines = append(lines, line)
	}
	lines = append(lines, briefingInconclusiveLines(d)...)
	lines = append(lines, briefingCandidateFindingLines(d)...)
	if line := briefingAssuranceLine(d, b); line != "" {
		lines = append(lines, line)
	}
	return lines
}

// briefingAbilityChangeLine states the operational consequence of a
// recorded investigation-ability change (S4-07, canonical "capability-lost"
// and "capability-restored": "Explain operational consequences and recorded
// retry eligibility — not internal error noise"). A CLEARED obstacle has no
// legacy delta boolean of its own — AbilityLost only ever marks a loss — so
// before this repair a restored capability rendered nothing at all.
//
// The candidate carries a closed limitation CODE, never an evidence-source
// name, so no source is named here. A cleared obstacle is also not proof
// that execution resumed: the line reports the obstacle only, and the work
// facts elsewhere in the reply say what is actually running.
func briefingAbilityChangeLine(d *model.OperatorDelta, b *model.OperatorBriefing) string {
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateAbilityChanged || c.Limitation == nil {
			continue
		}
		obstacle := briefingLimitationObstacle(c.Limitation.Code)
		line := "Investigation limited by " + obstacle + ": that evidence could not be retrieved, so the analysis remains incomplete."
		if c.Limitation.Cleared {
			line = "Investigation limitation cleared: " + obstacle + " no longer applies, and that evidence is available again."
		}
		if next := briefingCandidateNext(c.Next); next != "" {
			line += " " + next
		}
		return line
	}
	if !d.AbilityLost {
		return ""
	}
	if b.Unavailable > 0 {
		return fmt.Sprintf("Analysis unavailable for %d incident(s); not scheduled for these incidents.", b.Unavailable)
	}
	return "Automatic work cannot proceed; next steps below."
}

// briefingLimitationObstacle names one closed limitation code as the
// obstacle an operator would recognize. These are recorded wait-reason and
// limitation codes, not free prose: an unrecognized code stays explicit
// without exposing internal transport detail (canonical "capability-lost":
// "Explain effect, not low-level transport diagnostics").
func briefingLimitationObstacle(code string) string {
	switch code {
	case model.LimitationInvestigationUnavailable:
		return "unavailable analysis for some member incidents"
	case string(model.WaitReasonAcuteTriageDecision):
		return "a pending investigation decision"
	case string(model.WaitReasonAcuteTriageBackoff):
		return "an investigation back-off"
	case string(model.WaitReasonAssessmentRetry):
		return "a pending assessment retry"
	case string(model.WaitReasonAssessmentParked):
		return "a parked assessment"
	case string(model.WaitReasonSourceChange):
		return "an unsettled source state"
	case string(model.WaitReasonRecoveryGrace):
		return "the recovery grace period"
	}
	return "a recorded obstacle"
}

// briefingCandidateNext states a candidate's OWN recorded next step (B0 §4
// NextStepFacts) — a status checkpoint, a real retry or grace time, or an
// explicit end. Never a fabricated retry or completion ETA; a kind with no
// recorded time says so instead of borrowing another clock.
func briefingCandidateNext(n model.NextStepFacts) string {
	switch n.Kind {
	case model.NextStepRetryEligible:
		if n.At != nil {
			return "Next: retry eligible at " + SlackDateToken(*n.At, "{time}") + "."
		}
		return "Next: a retry is eligible; no retry time is recorded."
	case model.NextStepGraceDeadline:
		if n.At != nil {
			return "Next: confirm recovery through " + SlackDateToken(*n.At, "{time}") + "."
		}
		return "Next: confirm recovery; no grace deadline is recorded."
	case model.NextStepStatusCheck:
		if n.At != nil {
			return "Next: status check at " + SlackDateToken(*n.At, "{time}") + "."
		}
		return "Next: no status check is scheduled."
	case model.NextStepWorkEnded:
		return "Next: no further automatic work is scheduled on this schedule."
	case model.NextStepTrackingEnded:
		return "Next: tracking for this Situation has ended."
	}
	return ""
}

// briefingCandidateFindingLines renders every useful-finding candidate whose
// Incident the bounded Analyses overview does NOT already show (S4-04,
// canonical "evidence-map"/reply: "Finding, structured supporting
// observations, decision-relevant unknowns and next step"). B3 emits a
// candidate wherever an Incident's evidence structurally changed; the
// overview keeps at most model.AnalysisFindingsBound entries, so a finding
// outside it reached the renderer as a candidate alone and was dropped
// whole. An Incident carried by BOTH forms renders once, from the overview,
// so the repair adds no duplicate content.
func briefingCandidateFindingLines(d *model.OperatorDelta) []string {
	shown := make(map[string]bool, len(d.Analyses))
	for _, a := range d.Analyses {
		shown[a.IncidentID] = true
	}
	var lines []string
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateUsefulFinding || c.Finding == nil || shown[c.Finding.IncidentID] {
			continue
		}
		lines = append(lines, briefingFindingCandidateLine(c))
	}
	return lines
}

// briefingFindingCandidateLine renders one candidate finding from its own
// recorded facts. A recorded hypothesis is the finding; an absent one is not
// filled in from a title (a name is not a causal hypothesis, lead decision
// D, round 2). Missing observations are stated as missing, never as health.
func briefingFindingCandidateLine(c model.MaterialCandidate) string {
	f := c.Finding
	var parts []string
	if strings.TrimSpace(f.Hypothesis) != "" {
		parts = append(parts, "*Finding:* "+briefingText(f.Hypothesis, 240))
	}
	if len(f.Observations) > 0 {
		parts = append(parts, "*Evidence:* "+briefingText(strings.Join(f.Observations, "; "), 300))
	} else {
		parts = append(parts, "*Evidence:* No supporting observations were recorded; this does not establish that the service is healthy.")
	}
	if len(f.Unknowns) > 0 {
		parts = append(parts, "*Still unknown:* "+briefingText(strings.Join(f.Unknowns, "; "), 300))
	}
	parts = append(parts, "Hypothesis; not a confirmed cause.")
	if next := briefingCandidateNext(c.Next); next != "" {
		parts = append(parts, next)
	}
	return strings.Join(parts, "\n")
}

// briefingAssuranceLine renders the one initial execution assurance from a
// first_execution_assurance candidate's own recorded member facts (canonical
// slide 4 row 576 and the "first-root-running" example). B5 decides whether
// this assurance is actually delivered, and suppresses it when a finding
// already supersedes it; B4 only renders the facts it would carry.
func briefingAssuranceLine(d *model.OperatorDelta, b *model.OperatorBriefing) string {
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateFirstExecutionAssurance || c.Members == nil {
			continue
		}
		line := "Investigating" + briefingInputScope(c.Members.CountKnown, c.Members.FiringCount, c.Members.NowFiring, briefingScope(b))
		if next := briefingCandidateNext(c.Next); next != "" {
			line += " " + next
		}
		return line
	}
	return ""
}

// briefingInconclusiveLine renders the structured inconclusive-completion
// reply (S4-05: B0 integration contract §4) — actual checks, a
// decision-relevant unknown when one was recorded, and the honest no-retry
// next step. Falls back to the legacy-compatible generic wording when no
// structured Candidate rode this delta (an older persisted transition).
func briefingInconclusiveLine(d *model.OperatorDelta) string {
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateInconclusiveCompletion {
			continue
		}
		return briefingInconclusiveCandidateLine(c)
	}
	return "Analysis failed; coverage is incomplete."
}

// briefingInconclusiveLines renders EVERY recorded inconclusive completion,
// each keyed to its own incident/attempt identity, and falls back to the
// legacy aggregate wording only when the delta carried no candidate at all
// (an older persisted transition). Gating this on d.AnalysisFailed dropped
// a candidate-only completion whose aggregate failure count never moved
// (R1 repair, lead review 2026-09-09).
func briefingInconclusiveLines(d *model.OperatorDelta) []string {
	var lines []string
	for _, c := range d.Candidates {
		if c.Kind == model.CandidateInconclusiveCompletion {
			lines = append(lines, briefingInconclusiveCandidateLine(c))
		}
	}
	if len(lines) == 0 && d.AnalysisFailed {
		lines = append(lines, "Analysis failed; coverage is incomplete.")
	}
	return lines
}

func briefingInconclusiveCandidateLine(c model.MaterialCandidate) string {
	{
		line := "Investigation inconclusive."
		switch {
		case c.Outcome != nil && !c.Outcome.EvidenceKnown:
			// A typed exhaustion retained its result code and end time, not
			// the checks it ran: state that limit rather than inventing
			// checked sources or claiming what the evidence showed (lead
			// decision D, round 2, 2026-09-09).
			line += " The attempt ended with result " + briefingText(c.Outcome.ResultCode, 60) + "; the checks it ran were not retained, so no supporting observations can be stated."
		case c.Finding != nil && len(c.Finding.Observations) > 0:
			line += " " + briefingText(strings.Join(c.Finding.Observations, "; "), 300) + "; the available evidence did not establish a cause."
		default:
			line += " No supporting observations were recorded; the available evidence did not establish a cause."
		}
		// A recorded unknown is the decision-relevant half of an
		// inconclusive result — "checked X, still could not see Y" is what
		// makes the reply actionable. Dropping supplied Unknowns silently
		// turned a limited result into an unexplained dead end (R1 repair,
		// lead review 2026-09-09).
		if c.Finding != nil && len(c.Finding.Unknowns) > 0 {
			line += " Still unknown: " + briefingText(strings.Join(c.Finding.Unknowns, "; "), 300) + "."
		}
		return line + " " + briefingInconclusiveRetry(c.Next)
	}
}

// briefingInconclusiveRetry reads the candidate's OWN recorded next step
// rather than asserting an absence: a retry that really is eligible must not
// be denied by a fixed sentence, and every other recorded next step (a status
// check, a grace deadline, work having ended, or nothing recorded at all)
// genuinely schedules no further analysis retry.
func briefingInconclusiveRetry(next model.NextStepFacts) string {
	if next.Kind == model.NextStepRetryEligible {
		return "An investigation retry remains scheduled."
	}
	return "No further analysis retry is scheduled on this schedule."
}

// briefingActionChangeLine distinguishes an introduced, revised or
// withdrawn operator Action (S4-09: B0 integration contract §4) — a
// withdrawal explicitly corrects the earlier request rather than repeating
// the same "changed" wording for both directions. Falls back to the
// legacy-compatible generic wording when no structured Candidate rode this
// delta (an older persisted transition, before this field existed).
func briefingActionChangeLine(d *model.OperatorDelta) string {
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateActionChanged || c.Action == nil {
			continue
		}
		switch {
		case c.Action.Withdrawn:
			return "The earlier operator action request is no longer needed."
		case c.Action.Introduced:
			return "Operator action newly required; see Action below."
		case c.Action.Revised:
			return "Operator action changed; see Action below."
		}
	}
	if !d.HumanRequestChanged {
		return ""
	}
	return "Human action request changed; a recorded next actor does not confirm accepted ownership."
}

// briefingHasCandidateFinding reports whether this delta carries a
// useful-finding candidate the bounded Analyses overview does not show.
func briefingHasCandidateFinding(d *model.OperatorDelta) bool {
	return len(briefingCandidateFindingLines(d)) > 0
}

func briefingSymptoms(symptoms []string) string {
	if len(symptoms) == 0 {
		return "none recorded"
	}
	return briefingText(strings.Join(symptoms, ", "), 240)
}
