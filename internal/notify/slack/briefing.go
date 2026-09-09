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

func briefingAction(b *model.OperatorBriefing, t model.Transition) string {
	scope := briefingScope(b)
	if t.ActionContract.OperatorActionRequired != nil || operatorWorkBlocked(t.ActionContract) {
		return "On-call: investigate " + scope + " via MCP and check current service health."
	}
	// S1-04/S4-11: a closed_unknown outcome alone is not a concrete concern —
	// requesting an MCP health check here regardless of the recorded contract
	// invents a generic human-health request the canonical slide explicitly
	// forbids ("no generic MCP/human-health request without concrete
	// concern"). Only a recorded OperatorActionRequired above earns one.
	if t.Lifecycle == model.LifecycleClosedUnknown {
		return "None required from on-call; recovery could not be confirmed."
	}
	if t.Attention != model.AttentionObserve || b.Critical > 0 || b.Unknown > 0 {
		return "On-call: check current service health for " + scope + " now."
	}
	if b.Firing > 0 {
		return "On-call: assess current impact on " + scope + "."
	}
	if b.Total == 0 {
		return "On-call: check current service health for " + scope + "; alert state is unavailable."
	}
	return "None required from on-call; alerts resolved."
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
	lines = append(lines, "*AlertINT:* "+briefingNextStep(t, b, t.ActionContract.NextUpdateAt, t.CreatedAt), "*Action:* "+briefingAction(b, t))
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
	if d.AbilityLost {
		if b.Unavailable > 0 {
			lines = append(lines, fmt.Sprintf("Analysis unavailable for %d incident(s); not scheduled for these incidents.", b.Unavailable))
		} else {
			lines = append(lines, "Automatic work cannot proceed; next steps below.")
		}
	}
	if d.HumanRequestChanged {
		lines = append(lines, briefingActionChangeLine(d))
	}
	if d.AnalysisFailed {
		lines = append(lines, briefingInconclusiveLine(d))
	}
	return lines
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
	return "Analysis failed; coverage is incomplete."
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
	return "Human action request changed; a recorded next actor does not confirm accepted ownership."
}

func briefingSymptoms(symptoms []string) string {
	if len(symptoms) == 0 {
		return "none recorded"
	}
	return briefingText(strings.Join(symptoms, ", "), 240)
}
