// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"time"

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

// One color communicates overall status; phase styling remains bold-only.
func briefingStatus(t model.Transition) string {
	switch {
	case t.Lifecycle == model.LifecycleRecovered:
		return "🟢"
	case t.Lifecycle == model.LifecycleClosedUnknown:
		return "🔴"
	case t.Attention == model.AttentionUrgent:
		return "🔴"
	case t.Attention == model.AttentionInvestigate || operatorWorkBlocked(t.ActionContract) || t.ActionContract.OperatorActionRequired != nil:
		return "🔴"
	case t.Lifecycle == model.LifecycleRecoveryPending:
		return "🔵"
	default:
		return "🔵"
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

func briefingAnalysis(b *model.OperatorBriefing, detailed bool) string {
	var lines []string
	for i, alert := range b.Alerts {
		if i == 3 {
			break
		}
		if alert.SourceSummary != "" {
			label := "Source report"
			qualifier := ""
			if alert.State == "resolved" {
				label = "Historical source report"
				qualifier = " (retained annotation, not a current measurement)"
			}
			lines = append(lines, label+" ("+briefingText(alert.Name, 120)+", "+briefingText(alert.State, 20)+"): "+briefingComplete(alert.SourceSummary)+qualifier)
		}
	}
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
	interpretation := "*Interpretation:*"
	if briefingDraft(a) {
		interpretation = "*Retained draft hypothesis (not reconciled with verification results):*"
	}
	lines := []string{interpretation + " " + briefingComplete(briefingInterpretation(a))}
	if a.EvidenceSummary != "" {
		lines = append(lines, "\n*Evidence collected:* "+briefingComplete(a.EvidenceSummary))
	}
	if len(a.Observations) > 0 {
		lines = append(lines, "\n*Observed log samples:*")
		for _, f := range a.Observations {
			lines = append(lines, "• "+briefingComplete(f))
		}
	} else {
		lines = append(lines, "\n*Observed:* No supporting observations were recorded; this does not establish that the service is healthy.")
	}
	brief := a
	brief.VerificationNotes = nil
	lines = append(lines, "\n*Verification:* "+briefingUncertainty(brief))
	var empty, other []string
	for _, note := range a.VerificationNotes {
		const suffix = ": returned no data; this check establishes neither health nor failure."
		if strings.HasSuffix(note, suffix) {
			empty = append(empty, strings.TrimSuffix(note, suffix))
		} else {
			other = append(other, note)
		}
	}
	if len(empty) > 0 {
		lines = append(lines, fmt.Sprintf("\n*Checks returning no data (%d):* No data establishes neither health nor failure.", len(empty)))
		for _, note := range empty {
			lines = append(lines, "• "+briefingComplete(note))
		}
	}
	if len(other) > 0 {
		lines = append(lines, "\n*Other verification results:*")
		for _, note := range other {
			lines = append(lines, "• "+briefingComplete(note))
		}
	}
	return lines
}

func briefingFinding(a model.IncidentAnalysis, historical bool) []string {
	label := "*Hypothesis:*"
	if historical {
		label = "*Historical hypothesis:*"
	}
	if a.Stale && !historical {
		label = "*Earlier hypothesis:*"
	}
	lines := []string{label + " " + briefingText(briefingInterpretation(a), 240)}
	if len(a.Observations) > 0 {
		lines = append(lines, "*Observed log sample:* "+briefingText(a.Observations[0], 180))
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
	if a.VerificationLimit == "llm_call_failed" || a.VerificationLimit == "llm_response_invalid" || a.VerificationLimit == "budget_deferred" {
		qualification += " Retained draft; not reconciled with verification results."
	}
	lines = append(lines, qualification)
	for _, note := range a.VerificationNotes {
		lines = append(lines, briefingText(note, 500))
	}
	return lines
}

func briefingUncertainty(a model.IncidentAnalysis) string {
	parts := []string{"Causality remains unproven."}
	if a.Verification == "supported" {
		parts = append(parts, "Verification supports the hypothesis.")
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
	for _, note := range a.VerificationNotes {
		parts = append(parts, briefingText(note, 500))
	}
	return strings.Join(parts, " ")
}

// These are the stored verifier's reason codes, not free-form public prose.
// Unknown reasons remain explicit limitations without exposing internal detail.
func briefingVerificationLimit(reason string) string {
	switch reason {
	case "verification_source_unavailable":
		return "verification source unavailable"
	case "budget_deferred":
		return "verification review could not run because the configured analysis budget could not admit the request"
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
// Omit the row when there is no request or recorded withdrawal.
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
	return ""
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
	if in.Summary.Briefing.Flow != nil {
		return renderCanonicalRoot(in)
	}
	b := in.Summary.Briefing
	t := in.SourceTransition
	orientation := situation.DeriveOrientation(in.Summary, t)
	marker := briefingStatus(t)
	title := drillPrefix(t.Drill) + marker + " *" + briefingScope(b) + "*"
	phase := renderOrientationChain(orientation)
	status := briefingRootAlerts(b)
	if b.Critical > 0 {
		status += fmt.Sprintf(" · %d active critical alert(s)", b.Critical)
	}
	activity := "*AlertINT:* " + briefingNextStep(t, b, in.ContractDeadlineAt, in.Now)
	action := ""
	if request := briefingAction(b, t); request != "" {
		action = "\n*Action:* " + request
	}
	analysis := briefingRootFinding(b)
	if t.Lifecycle.Terminal() && len(b.Analyses) == 0 {
		analysis = "Analysis ended without a completed finding."
	}
	lines := []string{title, phase, status, analysis, activity + action}
	body := status
	if analysis != "" {
		body += "\n" + analysis
	}
	body += "\n" + activity + action
	blocks := []slacklib.Block{sectionBlock(title), contextBlock(phase)}
	blocks = append(blocks, briefingSections(body)...)
	if len(in.Summary.RecordedOperatorContext) > 0 {
		note := "Recorded context: " + briefingText(in.Summary.RecordedOperatorContext[len(in.Summary.RecordedOperatorContext)-1], 160)
		lines = append(lines, note)
		blocks = append(blocks, contextBlock(note))
	}
	line := briefingDuration(in.Summary.EffectiveStartedAt, in.Now)
	if t.Lifecycle.Terminal() {
		line = durationPeakLine(in.Summary)
	}
	lines = append(lines, line)
	blocks = append(blocks, contextBlock(line))
	footer := briefingFooter(in.Summary)
	lines = append(lines, footer)
	blocks = append(blocks, contextBlock(footer))
	return RenderedMessage{Text: strings.Join(lines, "\n"), Blocks: blocks}
}

func briefingFooter(s model.EpisodeSummary) string {
	handle := s.PublicHandle
	if handle == "" {
		handle = s.SituationID
	}
	return "MCP: get situation " + briefingText(handle, 200) + " using alertint"
}

// ----------------------------------------------------------------------
// Reply presentation
// ----------------------------------------------------------------------

// supersededExecutionStep replaces a reply's activity sentence when the
// automatic investigation that reply's own contract describes has already
// been overtaken.
//
// It states the one thing delivery actually established and stops. It
// names no new activity, promises no new time, and infers neither
// completion, Monitoring nor a terminal state from the supersession —
// a useful finding can coexist with another investigation that is still
// running (canonical "recovery-interrupted": "Use Investigating only if
// actual aggregate work supports it"; "recovery-with-work": "Do not claim
// investigation completion or invent a new work loop").
//
// It says nothing about the root either. The main message is refreshed by
// its own delivery, which the canonical thread gate keeps a separate
// decision ("Root can refresh without a thread post") and which may be
// queued, blocked or failed at this instant. Pointing the operator at it
// as though it were already current would replace one unverified claim
// with another (lead decisions 2026-09-10, §46/3).
const supersededExecutionStep = "This update's recorded investigation status and checkpoint have been superseded; " +
	"they are not current."

// briefingExecutionClaimed reports whether this Transition's own recorded
// contract asserts that the automatic investigation is still in flight —
// the single claim a later useful finding, inconclusive completion or
// terminal end overtakes.
//
// Every other activity sentence is left exactly as recorded. Source
// monitoring, recovery watching, a blocked or exhausted schedule and a
// terminal end are not claims about the overtaken execution, and
// suppressing them would hide current truth rather than stale truth.
func briefingExecutionClaimed(t model.Transition) bool {
	if t.Lifecycle.Terminal() {
		return false
	}
	c := t.ActionContract
	if c.AlertINTAction == nil || c.AlertINTStatus == nil || *c.AlertINTAction != model.AlertINTActionRunAcuteTriage {
		return false
	}
	switch *c.AlertINTStatus {
	case model.AlertINTStatusPlanned, model.AlertINTStatusRunning, model.AlertINTStatusWaiting:
		return true
	case model.AlertINTStatusBlocked, model.AlertINTStatusExhausted, model.AlertINTStatusComplete:
		// These already report an end or an obstacle, not work in flight.
	}
	return false
}

// SituationReplyInput is one earned reply's rendering input: the Transition
// the reply is about, plus the one thing that Transition cannot know about
// itself.
//
// ExecutionSuperseded is a PRESENTATION fact, established at delivery and
// never stored: a later Transition that earned a reply of its own recorded
// a useful finding, an inconclusive completion or the Situation's terminal
// end, so the investigation this row's contract describes is no longer
// where the work is (B5 AssuranceSuperseded; canonical slide 4 "Keep the
// attention cost bounded": "Never replay stale start messages after
// completion or closure"; slide 5 15:10:33: "Show the actual current
// contract and checkpoint").
//
// It changes one sentence and nothing else. The durable ledger row is not
// touched, no recorded fact is erased, the reply keeps every material
// change it carries, and a Transition whose contract claims no
// investigation in flight renders exactly as it always did.
type SituationReplyInput struct {
	Transition          model.Transition
	ReplyKind           model.NotificationReplyKind
	ExecutionSuperseded bool
}

// RenderSituationReply renders one earned reply: situation.go's journal
// assembly plus the presentation fact above, and nothing else. Validation,
// the fallback text, the block shape, the staleness markers and the
// recorded instant have exactly one implementation, so with that fact
// absent the two entry points are byte-identical and cannot drift (lead
// decisions 2026-09-10, §46/1).
//
// RenderSituationJournal remains the entry point for every caller with no
// delivery-time answer to give.
func RenderSituationReply(in SituationReplyInput) (RenderedMessage, error) {
	return renderJournalEntryKind(in.Transition, in.ExecutionSuperseded, string(in.ReplyKind))
}

// RenderSituationHandoff is the short channel copy of a reply broadcast.
// The complete Finding and timeline stay under the existing root.
func RenderSituationHandoff(in SituationReplyInput) (RenderedMessage, error) {
	if _, err := RenderSituationReply(in); err != nil {
		return RenderedMessage{}, err
	}
	t := in.Transition
	heading := "↪ *Update in existing Situation thread*"
	if b := t.Projection.Briefing; b != nil {
		if scope := briefingScope(b); scope != "" {
			heading += " · " + scope
		}
	}
	why := "Operator attention is needed."
	if d := t.Projection.OperatorDelta; d != nil {
		if n := len(d.NewFiringAlerts); n > 0 {
			why = fmt.Sprintf("New alerts: %d", n)
			if d.AttentionIncreased {
				why += " (urgency)"
			}
			why += "."
		} else if d.AttentionIncreased {
			why = "Urgency increased."
		}
	}
	lines := []string{heading, "*Why:* " + why}
	if action := t.ActionContract.OperatorActionRequired; action != nil {
		lines = append(lines, "*Action now:* "+sentenceAction(*action))
	} else {
		lines = append(lines, "*AlertINT:* Assessing the changed condition.")
	}
	text := strings.Join(lines, "\n")
	return RenderedMessage{Text: text, Blocks: []slacklib.Block{sectionBlock(text), contextBlock(SlackDateToken(t.Journal.OccurredAt, "{date_short} {time}"))}}, nil
}

// briefingJournal renders one reply from its Transition alone, exactly as
// that Transition recorded itself. Production reaches the body through
// renderJournalEntry; this name survives for the renderer tests that read
// the plain rendering directly.
func briefingJournal(t model.Transition) (string, string) {
	return briefingJournalPresented(t, false)
}

// briefingJournalPresented adds the one delivery-time presentation fact a
// reply cannot derive from its own row: whether the automatic execution its
// contract describes has since been overtaken. See SituationReplyInput.
func briefingJournalPresented(t model.Transition, executionSuperseded bool) (string, string) {
	if t.Projection.Briefing.Flow != nil {
		return canonicalBriefingJournal(t, "", executionSuperseded)
	}
	b := t.Projection.Briefing
	headline := ""
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
		lines = append(lines, briefingDeltaLines(d, b, t.Lifecycle.Terminal())...)
		if t.Lifecycle == model.LifecycleActive && briefingAssuranceLine(d, b) != "" {
			headline = "Investigation started"
		}
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
	marker := briefingStatus(t)
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
	step := briefingNextStep(t, activity, t.ActionContract.NextUpdateAt, t.CreatedAt)
	if executionSuperseded && briefingExecutionClaimed(t) {
		step = supersededExecutionStep
	}
	// A limitation candidate and the activity row can carry the exact same
	// current contract. Keep it once, without erasing a candidate's distinct clock.
	work := briefingWork(t.ActionContract, b, t.CreatedAt)
	duplicate := work
	if at := t.ActionContract.NextUpdateAt; at != nil {
		duplicate += " " + briefingCandidateNext(model.NextStepFacts{Kind: model.NextStepStatusCheck, At: at})
	}
	compact := lines[:0]
	for _, line := range lines {
		if line != duplicate {
			compact = append(compact, line)
		}
	}
	lines = compact
	lines = append(lines, "*AlertINT:* "+step)
	lines = append(lines, briefingDuration(t.Projection.EffectiveStartedAt, t.CreatedAt))
	if request := briefingAction(b, t); request != "" {
		lines = append(lines, "*Action:* "+request)
	}
	// Each bounded delta/evidence group gets its own section. Combining long
	// alert names with evidence must not truncate the hypothesis qualification.
	detail := strings.Join(lines, "\n\n")
	return headline, detail
}

func briefingReplyTitle(headline string, t model.Transition, b *model.OperatorBriefing) string {
	if d := t.Projection.OperatorDelta; t.Lifecycle == model.LifecycleActive && d != nil && d.StateChanged && b.Firing < d.PreviousFiring && b.Firing > 0 {
		return "Partial recovery · " + briefingState(b)
	}
	if headline == "" {
		return briefingScope(b)
	}
	return headline + " · " + briefingScope(b)
}

func briefingDuration(start, end time.Time) string {
	if start.IsZero() || end.IsZero() {
		return "*Duration:* unavailable"
	}
	elapsed := end.Sub(start).Truncate(time.Second)
	if elapsed < 0 {
		elapsed = 0
	}
	return "*Duration:* " + elapsed.String()
}

func briefingRootAlerts(b *model.OperatorBriefing) string {
	status := fmt.Sprintf("*Alerts:* %d", b.Total)
	if b.Firing == 0 && b.Unknown == 0 {
		return status + " resolved"
	}
	if b.Firing != b.Total || b.Resolved > 0 || b.Unknown > 0 {
		status += " · " + briefingState(b)
	}
	var symptoms []string
	for _, a := range b.Alerts {
		if a.State == "firing" && a.SourceSummary != "" {
			symptoms = append(symptoms, briefingText(a.SourceSummary, 160))
		}
		if len(symptoms) == 2 {
			break
		}
	}
	if len(symptoms) > 0 {
		status += " · " + strings.Join(symptoms, "; ")
	}
	return status
}

func briefingDeltaLines(d *model.OperatorDelta, b *model.OperatorBriefing, terminal ...bool) []string {
	lines := briefingMemberLines(d, b)
	if d.SymptomsChanged {
		lines = append(lines, "Observed symptoms: "+briefingSymptoms(d.PreviousSymptoms)+" → "+briefingSymptoms(b.Symptoms)+"; reassess the affected service.")
	}
	// Every line below is driven by the delta's own structured Candidates
	// first and falls back to the legacy boolean only when no candidate of
	// that kind rode this delta. B3 emits candidate-ONLY events by design
	// (an out-of-overview finding, a completion with no aggregate failure
	// count behind it, a cleared obstacle that has no legacy boolean at
	// all), so gating them on the old flags dropped the fact entirely
	// (R1 repair, lead review 2026-09-09).
	lines = append(lines, briefingAbilityChangeLines(d, b, terminal...)...)
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

// briefingMemberLines render the recorded member-alert change: which alerts
// cleared, which are newly firing, which still are, and the scope or
// urgency the change moved (S4-06, canonical "scope-expanded" and
// "recovery-interrupted" replies).
//
// The member-carrying candidates — members_changed, all_clear and refire —
// are the source when the delta carries one. Gating these lines on the
// legacy booleans dropped a candidate-only member change whole, and the
// candidate's own scope/urgency pair is the only place a change that moved
// no alert at all is recorded (R1 repair, lead review round 2,
// 2026-09-09). A production delta carries BOTH forms, so nothing here
// repeats what the candidate already stated; a fact no candidate carries
// still falls back to its legacy field individually, never all-or-nothing.
func briefingMemberLines(d *model.OperatorDelta, b *model.OperatorBriefing) []string {
	var selected []model.MaterialCandidate
	for _, c := range d.Candidates {
		switch c.Kind {
		case model.CandidateMembersChanged, model.CandidateAllClear, model.CandidateRefire:
			if c.Members != nil {
				selected = append(selected, c)
			}
		case model.CandidateFirstExecutionAssurance, model.CandidateUsefulFinding,
			model.CandidateInconclusiveCompletion, model.CandidateAbilityChanged,
			model.CandidateActionChanged, model.CandidateTerminalEnd:
			// Rendered by their own lines below. terminal_end carries no
			// member facts at all, and the assurance candidate's member
			// facts are its recorded investigation input, not a change.
		}
	}
	if len(selected) == 0 {
		return briefingLegacyMemberLines(d, b)
	}
	var lines []string
	scopeStated, urgencyStated, namesStated := false, false, false
	for i, c := range selected {
		m := c.Members
		if i == 0 {
			// One recorded state, whichever member candidate carried it:
			// every member candidate reads the same current Situation
			// counts, so a second copy would only repeat the first.
			lines = append(lines, briefingMemberStateLine(d, m))
		}
		namesStated = namesStated || len(m.Cleared)+len(m.NowFiring)+len(m.StillFiring) > 0
		if len(m.Cleared) > 0 {
			lines = append(lines, "*Cleared:* "+briefingNames(m.Cleared))
		}
		if len(m.NowFiring) > 0 {
			lines = append(lines, "*Now firing:* "+briefingNames(m.NowFiring))
		}
		if len(m.StillFiring) > 0 {
			lines = append(lines, "*Still firing:* "+briefingNames(m.StillFiring))
		}
		if m.PreviousScope != "" && m.Scope != "" {
			lines = append(lines, "Affected scope changed from "+briefingText(m.PreviousScope, 140)+" to "+briefingText(m.Scope, 140)+".")
			scopeStated = true
		}
		if m.PreviousUrgency != "" && m.Urgency != "" {
			lines = append(lines, "Urgency increased from "+briefingText(m.PreviousUrgency, 60)+" to "+briefingText(m.Urgency, 60)+"; review current service impact now.")
			urgencyStated = true
		}
	}
	// The alert inventory's remaining honesty lines are the root briefing's
	// own display bounds, not member facts: an unknown alert state and the
	// omitted-alert count stay visible whichever form carried the names.
	lines = append(lines, briefingAlertInventory(b, namesStated)...)
	if !scopeStated && d.ScopeChanged {
		lines = append(lines, "Affected scope changed from "+briefingText(d.PreviousScope, 140)+" to "+briefingText(b.Scope, 140)+".")
	}
	if !urgencyStated && d.AttentionIncreased {
		lines = append(lines, "Urgency increased; review current service impact now.")
	}
	return lines
}

// briefingMemberStateLine states the recorded alert counts, using the
// delta's own prior counts only when it actually recorded them: a
// candidate-only delta has none, and rendering its zero-valued fields as a
// prior state would invent a Situation that never existed.
func briefingMemberStateLine(d *model.OperatorDelta, m *model.MemberFacts) string {
	if d.StateChanged && d.PreviousTotal > 0 {
		return fmt.Sprintf("%d/%d → %d/%d alerts firing.", d.PreviousFiring, d.PreviousTotal, m.FiringCount, m.Total)
	}
	return fmt.Sprintf("%d/%d alerts firing.", m.FiringCount, m.Total)
}

// briefingLegacyMemberLines are the pre-candidate rendering, kept for a
// delta that carries no member candidate at all — an older persisted
// transition being replayed, or a change B3 records only as a boolean.
func briefingLegacyMemberLines(d *model.OperatorDelta, b *model.OperatorBriefing) []string {
	var lines []string
	if d.StateChanged {
		lines = append(lines, fmt.Sprintf("%d/%d → %d/%d alerts firing.", d.PreviousFiring, d.PreviousTotal, b.Firing, b.Total))
		if len(d.ClearedAlerts) > 0 {
			lines = append(lines, "*Cleared:* "+briefingNames(d.ClearedAlerts))
		}
		if len(d.NewFiringAlerts) > 0 {
			lines = append(lines, "*Now firing:* "+briefingNames(d.NewFiringAlerts))
		}
		lines = append(lines, briefingAlertInventory(b, false)...)
	}
	if d.ScopeChanged {
		lines = append(lines, "Affected scope changed from "+briefingText(d.PreviousScope, 140)+" to "+briefingText(b.Scope, 140)+".")
	}
	if d.AttentionIncreased {
		lines = append(lines, "Urgency increased; review current service impact now.")
	}
	return lines
}

// briefingAbilityChangeLines state the operational consequence of EVERY
// recorded investigation-ability change this delta carries (S4-07,
// canonical "capability-lost" and "capability-restored": "Explain
// operational consequences and recorded retry eligibility — not internal
// error noise"). A CLEARED obstacle has no legacy delta boolean of its own
// — AbilityLost only ever marks a loss — so before the first repair a
// restored capability rendered nothing at all.
//
// B3's abilityChangedCandidates emits the contract obstacle and the
// coverage aggregate as two INDEPENDENT facts that can occur in the same
// cycle and in opposite directions. Returning after the first candidate
// dropped the second one whole, so a parked assessment clearing beside a
// newly unavailable analysis reported only the good news (R2 repair, lead
// review round 2, 2026-09-09). Identical repeats of one fact still render
// once.
func briefingAbilityChangeLines(d *model.OperatorDelta, b *model.OperatorBriefing, terminal ...bool) []string {
	var lines []string
	seen := map[model.LimitationFacts]bool{}
	candidate := false
	for _, c := range d.Candidates {
		if c.Kind != model.CandidateAbilityChanged || c.Limitation == nil {
			continue
		}
		candidate = true
		if seen[*c.Limitation] {
			continue
		}
		seen[*c.Limitation] = true
		line := briefingLimitationLine(*c.Limitation)
		if c.Limitation.Cleared && (c.Next.Kind == model.NextStepTrackingEnded || (len(terminal) > 0 && terminal[0])) {
			line = "This episode ended with an investigation limitation; automatic analysis did not resume."
		} else if !c.Limitation.Cleared && c.Limitation.Code == string(model.WaitReasonAssessmentParked) && b.BlockedReason != "" {
			line = briefingBlockedReason(b)
		}
		if next := briefingCandidateNext(c.Next); next != "" {
			line += " " + next
		}
		lines = append(lines, line)
	}
	if candidate || !d.AbilityLost {
		return lines
	}
	if b.Unavailable > 0 {
		return []string{fmt.Sprintf("Analysis unavailable for %d incident(s); not scheduled for these incidents.", b.Unavailable)}
	}
	return []string{"Automatic work cannot proceed; next steps below."}
}

// briefingLimitationLine describes one recorded limitation and NOTHING
// beyond it. The recorded codes are of two kinds and neither carries an
// evidence-source identity or an execution fact:
//
//   - the coverage aggregate (LimitationInvestigationUnavailable) records
//     that some member incident's analysis is unavailable, and its
//     clearance records only that the aggregate reached zero — which the
//     B3 producer documents can also follow member removal, so it is not
//     proof that a previously unavailable analysis resumed;
//   - a contract wait reason records why automatic work cannot proceed;
//     scheduling says nothing at all about whether evidence was reachable.
//
// Canonical "capability-lost"/"capability-restored" assume an actual
// evidence-access loss and an actual resumption under existing authority.
// Asserting either from these codes fabricated a fact the model never
// recorded (R3 repair, lead review round 2, 2026-09-09); a future capability
// that really does record evidence-source access needs its own supporting
// fact before the canonical wording can be earned.
func briefingLimitationLine(l model.LimitationFacts) string {
	if l.Code == model.LimitationInvestigationUnavailable {
		if l.Cleared {
			return "Investigation coverage limitation cleared: unavailable analysis is no longer recorded for any member incident."
		}
		return "Investigation coverage limited by unavailable analysis for some member incidents: the recorded analysis for this Situation is incomplete."
	}
	obstacle := briefingLimitationObstacle(l.Code)
	if l.Cleared {
		return "Investigation limitation cleared: " + obstacle + " no longer applies."
	}
	return "Investigation limited by " + obstacle + ": automatic investigation cannot proceed while it applies."
}

// briefingLimitationObstacle names one closed contract wait reason as the
// obstacle an operator would recognize. These are recorded codes, not free
// prose: an unrecognized code stays explicit without exposing internal
// transport detail (canonical "capability-lost": "Explain effect, not
// low-level transport diagnostics"). The coverage aggregate has its own
// sentence pair above and never reaches this mapping.
func briefingLimitationObstacle(code string) string {
	switch code {
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
		parts = append(parts, "*Evidence:* Investigator-reported notes, not independently confirmed: "+briefingText(strings.Join(f.Observations, "; "), 300))
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

// Split selected evidence at line boundaries before Slack's section cap can
// discard later check results. Each selected line has its own smaller bound.
func briefingSections(text string) []slacklib.Block {
	var blocks []slacklib.Block
	var section string
	for _, line := range strings.Split(text, "\n") {
		for len(line) > 2800 {
			if section != "" {
				blocks = append(blocks, sectionBlock(section))
				section = ""
			}
			chunk := boundedRunes(line, 2800)
			if at := strings.LastIndex(chunk, " "); at > 1400 {
				chunk = chunk[:at+1]
			} else if amp := strings.LastIndex(chunk, "&"); amp > strings.LastIndex(chunk, ";") {
				chunk = chunk[:amp]
			}
			blocks = append(blocks, sectionBlock(chunk))
			line = line[len(chunk):]
		}
		if len(section)+len(line)+1 > 2800 && section != "" {
			blocks = append(blocks, sectionBlock(section))
			section = ""
		}
		if section != "" {
			section += "\n"
		}
		section += line
	}
	if section != "" {
		blocks = append(blocks, sectionBlock(section))
	}
	return blocks
}
