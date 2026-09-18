// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
	slacklib "github.com/slack-go/slack"
)

// Canonical presentation is versioned by the presence of recorded Flow facts.
// Historical transitions without them retain their original replay semantics.
func canonicalPhase(t model.Transition, b *model.OperatorBriefing) string {
	switch t.Lifecycle {
	case model.LifecycleActive:
		// Active episodes use the work phase below.
	case model.LifecycleRecovered:
		return "Recovered"
	case model.LifecycleClosedUnknown:
		return "Recovery unconfirmed"
	case model.LifecycleRecoveryPending:
		return "Confirming recovery"
	}
	switch b.Work.Phase {
	case model.WorkPhaseNone:
		return "Observed"
	case model.WorkPhaseExecuting, model.WorkPhaseRetryWait:
		return "Investigating"
	case model.WorkPhaseSettled, model.WorkPhaseExhausted:
		return "Monitoring"
	case model.WorkPhaseCollecting:
		if b.Flow.CorrelationClosesAt != nil {
			return "Correlating"
		}
	case model.WorkPhaseQueued, model.WorkPhaseAwaitingDecision:
		if b.Work.ExecutionStarted {
			return "Investigating"
		}
	}
	return "Observed"
}

func canonicalColor(t model.Transition, b *model.OperatorBriefing) string {
	if t.Lifecycle == model.LifecycleRecovered {
		return "🟢"
	}
	if b.Firing > 0 || t.Lifecycle == model.LifecycleClosedUnknown {
		return "🔴"
	}
	return "🔵"
}

func canonicalChain(phase string) string {
	phases := []string{"Observed", "Correlating", "Investigating", "Monitoring", "Confirming recovery", "Recovered"}
	if phase == "Recovery unconfirmed" {
		phases[len(phases)-1] = phase
	}
	for i, p := range phases {
		if p == phase {
			phases[i] = "*▸ " + p + "*"
		}
	}
	return strings.Join(phases, " · ")
}

func canonicalShort(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	if end := strings.Index(s, ". "); end >= 0 && end < limit {
		return s[:end+1]
	}
	return ""
}

// An accepted analysis is not automatically proof of its proposed cause.
// Without supporting verification the overview uses recorded observations.
func canonicalFinding(b *model.OperatorBriefing, assessment *model.AssessmentConclusion) (finding, title string) {
	// Situation-level causal support does not identify a particular hypothesis
	// when several analyses contribute. Keep their sourced observations instead.
	if len(b.Analyses) != 1 {
		assessment = nil
	}
	for _, a := range b.Analyses {
		// The triage response contract puts sourced observations in
		// correlation_findings and possible causes in overall_issue.
		if a.Verification == "supported" && !briefingDraft(a) {
			for _, fact := range a.Findings {
				if strings.TrimSpace(fact) == "" {
					continue
				}
				title = canonicalShort(fact, 180)
				if canonicalCauseSupported(assessment) && a.VerificationGaps == 0 {
					title = canonicalShort(strings.TrimPrefix(a.Title, "Hypothesis: "), 180)
				}
				return fact, title
			}
		}
		if canonicalCauseSupported(assessment) && a.Verification == "supported" && !briefingDraft(a) && a.VerificationGaps == 0 {
			finding = strings.TrimSpace(briefingInterpretation(a))
			title = canonicalShort(strings.TrimPrefix(a.Title, "Hypothesis: "), 180)
			if finding != "" {
				return finding, title
			}
		}
		for _, o := range a.Observations {
			if s := canonicalShort(o, 320); s != "" && canonicalDiagnostic(o) {
				return compactObservation(s), ""
			}
		}
	}
	if len(b.Analyses) > 0 {
		for _, a := range b.Alerts {
			if s := canonicalShort(a.SourceSummary, 300); s != "" {
				return "Alert reported: " + s, ""
			}
		}
	}
	return "", ""
}

func canonicalDiagnostic(s string) bool {
	s = strings.ToLower(s)
	for _, word := range []string{"error", "fail", "invalid token", "refused", "panic", "exception", "timeout", "timed out", "unavailable"} {
		if strings.Contains(s, word) {
			return true
		}
	}
	return false
}

func canonicalCauseSupported(a *model.AssessmentConclusion) bool {
	return a != nil && (a.Causality == model.CausalitySupported || a.Causality == model.CausalityOperatorConfirmed)
}

func canonicalRevisedTitle(b *model.OperatorBriefing) string {
	// Use the same completed, reconciled diagnosis as the single-analysis
	// Finding. Multiple analyses still require a scoped aggregate summary.
	if len(b.Analyses) != 1 {
		return ""
	}
	a := b.Analyses[0]
	if a.Verification != "revised" || briefingDraft(a) {
		return ""
	}
	if title := canonicalShort(strings.TrimSpace(a.Title), 180); title != "" {
		return title
	}
	return canonicalShort(a.Summary, 180)
}

func canonicalSummary(b *model.OperatorBriefing, assessment *model.AssessmentConclusion) string {
	if title := canonicalRevisedTitle(b); title != "" {
		return title
	}
	_, title := canonicalFinding(b, assessment)
	if title != "" {
		return title
	}
	for _, a := range b.Alerts {
		if summary := canonicalShort(a.SourceSummary, 180); summary != "" {
			return summary
		}
	}
	names := make([]string, 0, len(b.Alerts))
	seen := map[string]bool{}
	for _, a := range b.Alerts {
		name := strings.Split(a.Name, " · ")[0]
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	if title := canonicalShort(strings.Join(names, ", "), 180); title != "" {
		return title
	}
	return fmt.Sprintf("%d grouped alerts", b.Total)
}

func canonicalAlertName(a model.BriefingAlert) string {
	name := a.Name
	if a.Context != "" && !strings.Contains(name, a.Context) {
		name += " · " + a.Context
	}
	return name
}

func canonicalMembers(b *model.OperatorBriefing) string {
	var lines []string
	for _, a := range b.Alerts {
		symbol, state := "·", "state unavailable"
		switch a.State {
		case "firing":
			symbol, state = "🔸", "firing"
		case "resolved":
			symbol, state = "🔹", "resolved"
		}
		lines = append(lines, symbol+" "+briefingComplete(canonicalAlertName(a))+" · "+state)
	}
	if b.AlertsOmitted > 0 {
		lines = append(lines, fmt.Sprintf("%d further alert identities available via MCP.", b.AlertsOmitted))
	}
	return strings.Join(lines, "\n")
}

func canonicalElapsed(start, end time.Time) string {
	if start.IsZero() || end.IsZero() {
		return "unavailable"
	}
	d := end.Sub(start).Truncate(time.Second)
	if d < 0 {
		d = 0
	}
	s := d.String()
	if d >= time.Minute && d%time.Minute == 0 {
		s = strings.TrimSuffix(s, "0s")
	}
	return s
}

func canonicalUsage(u model.AnalysisUsage) string {
	if !u.CallsKnown {
		return ""
	}
	calls := fmt.Sprintf("%d calls", u.Calls)
	input, output := "unavailable", "unavailable"
	if u.InputTokensKnown {
		input = canonicalNumber(u.InputTokens)
	}
	if u.OutputTokensKnown {
		output = canonicalNumber(u.OutputTokens)
	}
	return "*Analysis usage:* " + calls + " · " + input + " input / " + output + " output tokens"
}

func canonicalNumber(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func canonicalTimings(t model.Transition, b *model.OperatorBriefing, start, end time.Time, root bool) []string {
	f := b.Flow
	terminal := t.Lifecycle.Terminal()
	if terminal && t.Projection.TerminalAt != nil {
		end = *t.Projection.TerminalAt
	}
	var lines []string
	if root {
		label := "Alert age"
		if terminal {
			label += " at closure"
		}
		line := "*" + label + ":* " + canonicalElapsed(start, end)
		if t.Projection.EffectiveStartedAtBasis == model.SourceTimeBasisReceiptFallback {
			line += " (receipt-time fallback)"
		}
		lines = append(lines, line)
	}
	if !terminal {
		lines = append(lines, "*Since first receipt:* "+canonicalElapsed(f.FirstReceivedAt, end))
	}
	if f.InvestigationStartedAt != nil {
		lines = append(lines, "*Investigation started:* "+canonicalElapsed(f.FirstReceivedAt, *f.InvestigationStartedAt)+" after first receipt")
	}
	if f.InvestigationCompletedAt != nil {
		line := "*Analysis completed:* " + canonicalElapsed(f.FirstReceivedAt, *f.InvestigationCompletedAt) + " after first receipt"
		if f.InvestigationStartedAt != nil {
			runtime := canonicalElapsed(*f.InvestigationStartedAt, *f.InvestigationCompletedAt)
			if f.InvestigationRuntimeSeconds != nil {
				runtime = (time.Duration(*f.InvestigationRuntimeSeconds) * time.Second).String()
			}
			line += " · *Investigation runtime:* " + runtime
		}
		lines = append(lines, line)
	}
	if terminal {
		label := "Total time from first receipt"
		if t.Lifecycle == model.LifecycleRecovered {
			label = "Total time to confirmed recovery"
		}
		lines = append(lines, "*"+label+":* "+canonicalElapsed(f.FirstReceivedAt, end)+" from first receipt")
	}
	if f.InvestigationCompletedAt != nil || terminal {
		if usage := canonicalUsage(f.AnalysisUsage); usage != "" {
			lines = append(lines, usage)
		}
	}
	return lines
}

func canonicalNext(t model.Transition, b *model.OperatorBriefing, now time.Time) string {
	if t.Lifecycle == model.LifecycleRecovered {
		return "Alerts cleared and did not fire again during the recovery observation period. Episode monitoring is complete."
	}
	if t.Lifecycle == model.LifecycleActive && b.Work.Phase == model.WorkPhaseCollecting && b.Flow.CorrelationClosesAt != nil {
		at := *b.Flow.CorrelationClosesAt
		if at.After(now) {
			return "Start investigation in ~" + canonicalElapsed(now, at) + ", around " + SlackDateToken(at, "{time_secs}") + "."
		}
		return "Correlation window closed; investigation is waiting to start."
	}
	step := briefingNextStep(t, b, t.ActionContract.NextUpdateAt, now)
	step = strings.Replace(step, "Analysis completed. Monitoring for changes.", "Monitoring alert changes.", 1)
	return compactRecoveryDeadline(step, t, b)
}

func renderCanonicalRoot(in SituationRootInput) RenderedMessage {
	b, t := in.Summary.Briefing, in.SourceTransition
	// A quiet checkpoint refreshes the selected root deadline without earning
	// a new material transition. Replies keep their historical deadline.
	t.ActionContract.NextUpdateAt = in.ContractDeadlineAt
	phase := canonicalPhase(t, b)
	title := drillPrefix(t.Drill) + canonicalColor(t, b) + " *" + phase + " · " + briefingScope(b) + " — " + briefingComplete(canonicalSummary(b, t.Projection.Assessment)) + "*"
	counts := fmt.Sprintf("*Alerts:* %d firing · %d resolved", b.Firing, b.Resolved)
	if b.Unknown > 0 {
		counts += fmt.Sprintf(" · %d unobserved", b.Unknown)
	}
	lines := []string{title, canonicalChain(phase)}
	finding, findingTitle := canonicalFinding(b, t.Projection.Assessment)
	if len(finding) > 320 {
		if short := canonicalShort(finding, 320); short != "" {
			finding = short
		} else if findingTitle != "" {
			finding = findingTitle
		} else {
			finding = ""
		}
	}
	// A completed diagnosis leads a single-analysis root even when a log
	// observation is available. Multi-analysis roots retain their scoped finding.
	if len(b.Analyses) == 1 || finding == "" || strings.HasPrefix(finding, "Alert reported: ") {
		if workingDiagnosis := canonicalWorkingDiagnosis(b); workingDiagnosis != "" {
			finding = workingDiagnosis
		}
	}
	if incomplete := canonicalIncompleteFinding(t, b); incomplete != "" {
		lines = append(lines, incomplete)
	} else if finding != "" {
		lines = append(lines, canonicalFindingLine(finding, t.Lifecycle != model.LifecycleActive))
	}
	if j := b.ExpectedJudgment; j != nil {
		lines = append(lines, "*Operator:* Expected until "+SlackDateToken(j.ValidUntil, "{time}")+" · "+briefingText(j.AssertedOperator, 120))
	}

	if !t.Lifecycle.Terminal() {
		activity := canonicalNext(t, b, in.Now)
		lines = append(lines, activity)
	}
	lines = append(lines, counts, canonicalMembers(b))
	if action := briefingAction(b, t); action != "" {
		lines = append(lines, "*Action:* "+action)
	}
	if t.Lifecycle == model.LifecycleRecovered {
		end := in.Now
		if t.Projection.TerminalAt != nil {
			end = *t.Projection.TerminalAt
		}
		lines = append(lines, "Recovery confirmed · "+canonicalElapsed(b.Flow.FirstReceivedAt, end)+" after first receipt")
	} else {
		lines = append(lines, strings.Join(canonicalTimings(t, b, in.Summary.EffectiveStartedAt, in.Now, true), "\n"))
	}
	if t.Lifecycle.Terminal() {
		lines = append(lines, canonicalMCP(in.Summary))
	}
	var blocks []slacklib.Block
	for _, line := range lines {
		if line != "" {
			blocks = append(blocks, briefingSections(line)...)
		}
	}
	return RenderedMessage{Text: strings.Join(lines, "\n\n"), Blocks: blocks}
}

func canonicalMCP(s model.EpisodeSummary) string {
	id := s.PublicHandle
	if id == "" {
		id = s.SituationID
	}
	return "*MCP:* `get situation " + briefingText(id, 200) + "`"
}

// Recovery describes alert state independently of whether an investigation
// produced a usable result. Do not replace an earlier completed analysis with
// the status of a later follow-up, or infer a particular failure from absence.
func canonicalIncompleteFinding(t model.Transition, b *model.OperatorBriefing) string {
	if !t.Lifecycle.Terminal() || (!b.Work.ExecutionStarted && b.BlockedReason == "") {
		return ""
	}
	for _, a := range b.Analyses {
		if !briefingDraft(a) {
			return ""
		}
	}
	if b.Flow.InvestigationCompletedAt != nil {
		return ""
	}
	if b.BlockedReason == "budget_deferred" {
		return "*Finding:* Investigation incomplete. The analysis budget was reached before a result was available."
	}
	return "*Finding:* Investigation incomplete. No completed analysis was available when monitoring ended."
}
