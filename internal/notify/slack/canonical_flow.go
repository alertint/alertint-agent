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
				return s, ""
			}
		}
	}
	if len(b.Analyses) > 0 {
		for _, a := range b.Alerts {
			if s := canonicalShort(a.SourceSummary, 300); s != "" {
				return "Source reported: " + s, ""
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

func canonicalSummary(b *model.OperatorBriefing, assessment *model.AssessmentConclusion) string {
	_, title := canonicalFinding(b, assessment)
	if title != "" {
		return title
	}
	for _, a := range b.Alerts {
		if summary := canonicalShort(a.SourceSummary, 180); summary != "" {
			if b.Historical {
				return "Earlier report: " + summary
			}
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
	for _, state := range []string{"firing", "resolved", "unknown"} {
		var names []string
		for _, a := range b.Alerts {
			if a.State == state {
				names = append(names, briefingComplete(canonicalAlertName(a)))
			}
		}
		if len(names) > 0 {
			label := map[string]string{"firing": "Firing", "resolved": "Resolved", "unknown": "State unavailable"}[state]
			lines = append(lines, "*"+label+":* "+strings.Join(names, "; "))
		}
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
	return briefingNextStep(t, b, t.ActionContract.NextUpdateAt, now)
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
	lines := []string{title, canonicalChain(phase), counts, canonicalMembers(b)}
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
	if finding != "" {
		prefix := ""
		if t.Lifecycle != model.LifecycleActive {
			prefix = "During the incident: "
		}
		lines = append(lines, "*Finding:* "+prefix+briefingComplete(finding))
	} else if !t.Lifecycle.Terminal() && (b.Work.Phase == model.WorkPhaseCollecting || b.Work.Phase == model.WorkPhaseAwaitingDecision || b.Work.Phase == model.WorkPhaseQueued || b.Work.Phase == model.WorkPhaseExecuting) {
		pending := "Pending investigation."
		if b.Work.Phase == model.WorkPhaseExecuting {
			pending = "Investigation running."
		}
		lines = append(lines, "*Finding:* "+pending+"\n*Cause:* "+pending)
	}
	if !t.Lifecycle.Terminal() {
		label := "*AlertINT:* "
		if phase == "Correlating" {
			label = "*Next:* "
		}
		lines = append(lines, label+canonicalNext(t, b, in.Now))
	}
	if action := briefingAction(b, t); action != "" {
		lines = append(lines, "*Action:* "+action)
	}
	lines = append(lines, strings.Join(canonicalTimings(t, b, in.Summary.EffectiveStartedAt, in.Now, true), "\n"))
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
	return "*Further details via MCP:* `get situation " + briefingText(id, 200) + " using alertint`"
}
