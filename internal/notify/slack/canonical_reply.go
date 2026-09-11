// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func canonicalReplyKind(t model.Transition) string {
	b := t.Projection.Briefing
	if d := t.Projection.OperatorDelta; d != nil {
		if len(d.Analyses) > 0 || briefingHasCandidateFinding(d) {
			return "analysis_completed"
		}
	}
	switch t.Lifecycle {
	case model.LifecycleActive:
		// Active episodes use their work and material changes below.
	case model.LifecycleRecovered:
		return "recovered"
	case model.LifecycleRecoveryPending:
		return "recovery_observed"
	case model.LifecycleClosedUnknown:
		return "recovery_unconfirmed"
	}
	if b.Work.Phase == model.WorkPhaseCollecting {
		return "correlation_started"
	}
	if d := t.Projection.OperatorDelta; d != nil {
		if d.StateChanged && b.Firing > 0 && b.Firing < d.PreviousFiring {
			return "partial_clearance"
		}
		if briefingAssuranceLine(d, b) != "" {
			return "investigation_started"
		}
	}
	if len(b.Analyses) > 0 && t.Projection.OperatorDelta == nil {
		return "analysis_completed"
	}
	return ""
}

func canonicalSourceUnit(unit string) string {
	if unit == "" {
		return "records"
	}
	return briefingComplete(unit)
}

func canonicalSourceLines(checks []model.SourceCheck) []string {
	if len(checks) == 0 {
		return nil
	}
	lines := []string{"*Sources and check results:*"}
	for _, c := range checks {
		name := briefingComplete(c.Source)
		if c.Check != "" {
			name += " — " + briefingComplete(c.Check)
		}
		var parts []string
		if c.CallsKnown {
			parts = append(parts, fmt.Sprintf("%d calls", c.Calls))
		}
		if c.RecordsKnown {
			parts = append(parts, fmt.Sprintf("%s %s returned", canonicalNumber(c.Records), canonicalSourceUnit(c.Unit)))
		}
		switch c.Outcome {
		case model.SourceCheckConfigured:
			parts = append(parts, "configured")
		case model.SourceCheckEmpty:
			parts = append(parts, "query succeeded; 0 matches")
		case model.SourceCheckFailed:
			parts = append(parts, "failed")
		case model.SourceCheckSkipped:
			parts = append(parts, "skipped")
		case model.SourceCheckReturned:
			if !c.RecordsKnown {
				parts = append(parts, "data returned")
			}
		}
		if c.Detail != "" {
			parts = append(parts, briefingComplete(c.Detail))
		}
		lines = append(lines, "• *"+name+":* "+strings.Join(parts, " · "))
	}
	return lines
}

func canonicalAnalysisLines(b *model.OperatorBriefing, selected []model.IncidentAnalysis, assessment *model.AssessmentConclusion) []string {
	if len(b.Analyses) != 1 || len(selected) != 1 || b.Analyses[0].IncidentID != selected[0].IncidentID {
		assessment = nil
	}
	var lines []string
	for _, a := range selected {
		single := *b
		single.Analyses = []model.IncidentAnalysis{a}
		finding, _ := canonicalFinding(&single, assessment)
		// A verified causal conclusion is the lead finding, not a second
		// interpretation labelled as additional evidence. Retain its sourced
		// observations below; unsupported hypotheses never take this path.
		if canonicalCauseSupported(assessment) && a.Verification == "supported" && !briefingDraft(a) && a.VerificationGaps == 0 && strings.TrimSpace(a.Summary) != "" {
			finding = strings.TrimSpace(a.Summary)
		}
		if finding != "" {
			lines = append(lines, "*Finding:* "+briefingComplete(finding))
		}
		// The response contract separates sourced factual findings from its
		// causal hypothesis. A useful observation does not require a cause.
		if a.Verification == "supported" && !briefingDraft(a) {
			for _, f := range a.Findings {
				if strings.TrimSpace(f) != "" && strings.TrimSpace(f) != strings.TrimSpace(finding) {
					lines = append(lines, "*Supporting finding:* "+briefingComplete(f))
				}
			}
		}
		if len(a.Observations) > 0 {
			lines = append(lines, "*Supporting evidence:*")
			for _, o := range a.Observations {
				lines = append(lines, "• "+briefingComplete(o))
			}
		}
		if a.VerificationLimit != "" {
			lines = append(lines, "*Analysis result:* "+briefingVerificationLimit(a.VerificationLimit)+".")
		}
	}
	lines = append(lines, canonicalSourceLines(b.Flow.SourceChecks)...)
	// Legacy analysis envelopes may have complete named check results without
	// the new source accounting projection. Keep those results accessible.
	if len(b.Flow.SourceChecks) == 0 {
		for _, a := range selected {
			if len(a.VerificationNotes) > 0 {
				lines = append(lines, "*Verification checks:*")
				for _, n := range a.VerificationNotes {
					lines = append(lines, "• "+briefingComplete(n))
				}
			}
		}
	}
	return lines
}

func canonicalAnalysisReply(t model.Transition, b *model.OperatorBriefing) (string, []string) {
	var lines []string
	label := "Analysis completed"
	if d := t.Projection.OperatorDelta; d != nil {
		if results := briefingInconclusiveLines(d); len(results) > 0 {
			label = "Investigation ended"
			lines = append(lines, results...)
		}
	}
	selected := b.Analyses
	if d := t.Projection.OperatorDelta; d != nil && len(d.Analyses) > 0 {
		selected = d.Analyses
	}
	lines = append(lines, canonicalAnalysisLines(b, selected, t.Projection.Assessment)...)
	if d := t.Projection.OperatorDelta; d != nil {
		// Preserve useful out-of-overview candidate observations without turning
		// their unverified hypothesis into a cause.
		for _, c := range d.Candidates {
			if c.Kind != model.CandidateUsefulFinding || c.Finding == nil {
				continue
			}
			shown := false
			for _, a := range selected {
				if a.IncidentID == c.Finding.IncidentID {
					shown = true
				}
			}
			if !shown {
				for _, o := range c.Finding.Observations {
					lines = append(lines, "*Additional finding:* "+briefingComplete(o))
				}
			}
		}
	}

	return label, lines
}

func canonicalBriefingJournal(t model.Transition, kind string, executionSuperseded bool) (string, string) {
	b := t.Projection.Briefing
	if kind == "" {
		kind = canonicalReplyKind(t)
	}
	label := ""
	var lines []string
	switch kind {
	case "correlation_started":
		label = "Correlating alerts"
		if b.Flow.GroupingRule != "" {
			lines = append(lines, "*Grouping rule:* "+briefingComplete(b.Flow.GroupingRule))
		}
		if b.Flow.GroupKey != "" {
			lines = append(lines, "*Current group:* `"+briefingComplete(b.Flow.GroupKey)+"`")
		}
		lines = append(lines, "*Collected alerts:*\n"+canonicalMembers(b))
		if at := b.Flow.CorrelationClosesAt; at != nil {
			lines = append(lines, "*Correlation window:* "+canonicalElapsed(b.Flow.CorrelationOpenedAt, *at)+" · closes at "+SlackDateToken(*at, "{time_secs}"))
		}
	case "investigation_started":
		label = "Investigation started"
		if b.Work.InvestigatedCountKnown {
			lines = append(lines, fmt.Sprintf("*Investigation scope:* %d alert inputs.", b.Work.InvestigatedCount))
		}
		lines = append(lines, "*Investigated inputs:* "+canonicalInvestigationNames(b))
		if b.Flow.GroupKey != "" {
			lines = append(lines, "*Correlation:* Grouped by `"+briefingComplete(b.Flow.GroupKey)+"`.")
		}
		lines = append(lines, canonicalSourceLines(b.Flow.SourceChecks)...)
	case "analysis_completed":
		label, lines = canonicalAnalysisReply(t, b)
	case "partial_clearance":
		label = "Partial clearance"
		lines = append(lines, canonicalClearanceLines(t, b)...)
	case "recovery_observed":
		label = "Recovery observed"
		lines = append(lines, canonicalClearanceLines(t, b)...)
		lines = append(lines, fmt.Sprintf("*Remaining firing:* %d", b.Firing))
	case "recovered":
		label = "Recovered"
		period := "the recovery observation period"
		if t.Projection.RecoveryObservedAt != nil && t.Projection.GraceUntil != nil {
			period = "the " + canonicalElapsed(*t.Projection.RecoveryObservedAt, *t.Projection.GraceUntil) + " observation period"
		}
		lines = append(lines, "*Recovery confirmed:* The monitored alerts cleared and did not fire again during "+period+". Episode monitoring is complete.")
	case "recovery_unconfirmed":
		label = "Recovery unconfirmed"
	default:
		if d := t.Projection.OperatorDelta; d != nil {
			lines = append(lines, briefingDeltaLines(d, b, t.Lifecycle.Terminal())...)
		}
	}
	if t.Reason == model.ReasonOperatorArtifactRecorded {
		label = briefingComplete(t.Journal.AttributedActor) + ": " + briefingComplete(t.Journal.Headline)
		lines = []string{briefingComplete(t.Journal.Detail)}
	}
	heading := canonicalColor(t, b) + " "
	if label != "" {
		heading += label + " · "
	}
	heading += briefingScope(b)
	if kind == "analysis_completed" {
		if _, title := canonicalFinding(b, t.Projection.Assessment); title != "" {
			heading += " — " + briefingComplete(title)
		}
	}
	if kind != "recovered" {
		next := canonicalNext(t, b, t.CreatedAt)
		if executionSuperseded && briefingExecutionClaimed(t) {
			next = supersededExecutionStep
		}
		lines = append(lines, "*AlertINT:* "+next)
	}
	if request := briefingAction(b, t); request != "" {
		lines = append(lines, "*Action:* "+request)
	}
	lines = append(lines, canonicalReplyTimings(t, b, kind)...)
	if t.Lifecycle.Terminal() {
		s := model.EpisodeSummary{SituationID: t.SituationID}
		if t.Projection.PublicHandle != nil {
			s.PublicHandle = *t.Projection.PublicHandle
		}
		lines = append(lines, canonicalMCP(s))
	}
	return heading, strings.Join(lines, "\n\n")
}

func canonicalReplyTimings(t model.Transition, b *model.OperatorBriefing, kind string) []string {
	var lines []string
	switch {
	case kind == "analysis_completed":
		lines = append(lines, canonicalTimings(t, b, t.Projection.EffectiveStartedAt, t.CreatedAt, false)...)
	case t.Lifecycle.Terminal():
		end := t.CreatedAt
		if t.Projection.TerminalAt != nil {
			end = *t.Projection.TerminalAt
		}
		lines = append(lines, "*Confirmed:* "+SlackDateToken(end, "{time_secs}"), "*Total time from first receipt:* "+canonicalElapsed(b.Flow.FirstReceivedAt, end))
	default:
		lines = append(lines, "*Since first receipt:* "+canonicalElapsed(b.Flow.FirstReceivedAt, t.CreatedAt))
		if kind == "investigation_started" && b.Flow.InvestigationStartedAt != nil {
			lines = append(lines, "*Started:* "+SlackDateToken(*b.Flow.InvestigationStartedAt, "{time_secs}")+" · *Response time:* "+canonicalElapsed(b.Flow.FirstReceivedAt, *b.Flow.InvestigationStartedAt)+" from first receipt")
		}
	}
	return lines
}

func canonicalInvestigationNames(b *model.OperatorBriefing) string {
	names := make([]string, 0, len(b.Work.InvestigatedNames))
	for _, name := range b.Work.InvestigatedNames {
		names = append(names, briefingComplete(name))
	}
	if len(names) == 0 {
		return "Input names were not recorded."
	}
	return strings.Join(names, "; ")
}

func canonicalClearanceLines(t model.Transition, b *model.OperatorBriefing) []string {
	d := t.Projection.OperatorDelta
	if d == nil {
		return []string{canonicalMembers(b)}
	}
	changed := append([]string(nil), d.ClearedAlerts...)
	for _, c := range d.Candidates {
		if c.Members != nil {
			changed = append(changed, c.Members.Cleared...)
		}
	}
	if len(changed) == 0 {
		return []string{canonicalMembers(b)}
	}
	var newly, prior, firing []string
	for _, a := range b.Alerts {
		name := briefingComplete(canonicalAlertName(a))
		if a.State == "firing" {
			firing = append(firing, name)
			continue
		}
		if a.State != "resolved" {
			continue
		}
		justCleared := false
		for _, n := range changed {
			if n == a.Name || n == canonicalAlertName(a) {
				justCleared = true
				break
			}
		}
		if justCleared {
			newly = append(newly, name)
		} else {
			prior = append(prior, name)
		}
	}
	var lines []string
	for _, entry := range []struct {
		label string
		names []string
	}{{"Newly resolved", newly}, {"Already resolved", prior}, {"Still firing", firing}} {
		if len(entry.names) > 0 {
			lines = append(lines, "*"+entry.label+":* "+strings.Join(entry.names, "; "))
		}
	}
	return lines
}
