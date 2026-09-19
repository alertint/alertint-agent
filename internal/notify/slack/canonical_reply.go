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
	lines := []string{"*Checks:*"}
	// Keep compact subjects, but distinguish expressions whose differences
	// (for example thresholds) are not represented by the subject and scope.
	queries := map[string]map[string]int{}
	for _, c := range checks {
		if c.Kind != "promql" || c.QueryExpr == "" {
			continue
		}
		key := c.Source + "\x00" + canonicalCheckName(c)
		if queries[key] == nil {
			queries[key] = map[string]int{}
		}
		if queries[key][c.QueryExpr] == 0 {
			queries[key][c.QueryExpr] = len(queries[key]) + 1
		}
	}
	seen := map[string]bool{}
	for _, c := range checks {
		if c.QueryScope != "" && (c.Outcome == model.SourceCheckReturned || c.Outcome == model.SourceCheckEmpty) {
			key := c.Source + "\x00" + c.Kind + "\x00" + c.QueryScope + "\x00" + string(c.Outcome) + "\x00" + c.Detail
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		switch c.Kind {
		case "incidents_in_window":
			c.Check = "Other alerts"
			c.Detail = compactOtherAlerts(c.Detail)
		case "up_ratio":
			c.Check = "Peer health"
		}
		name := briefingComplete(c.Source)
		if c.Check != "" && c.Check != "collection" {
			checkName := canonicalCheckName(c)
			if refs := queries[c.Source+"\x00"+checkName]; c.Kind == "promql" && len(refs) > 1 {
				checkName += fmt.Sprintf(" · check %d", refs[c.QueryExpr])
			}
			name += " — " + briefingComplete(checkName)
		}
		symbol, result := compactSourceResult(c)
		lines = append(lines, symbol+" *"+name+":* "+briefingComplete(result))
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
		label := "*Finding:* "
		if diagnosis := canonicalWorkingDiagnosis(&single); diagnosis != "" {
			finding = diagnosis
		}
		if finding != "" {
			lines = append(lines, label+briefingComplete(finding))
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
		var evidence []string
		seen := map[string]bool{strings.TrimSpace(finding): true}
		for _, o := range a.Observations {
			// Routine log samples remain available through MCP; they do not explain the alert.
			o = canonicalEvidenceObservation(o)
			if o != "" && !seen[o] {
				evidence = append(evidence, "▪ "+briefingComplete(o))
				seen[o] = true
			}
		}
		if len(evidence) > 0 {
			lines = append(lines, "*Evidence:*\n"+strings.Join(evidence, "\n"))
		}
		if a.VerificationLimit != "" {
			lines = append(lines, "*Analysis result:* "+briefingVerificationLimit(a.VerificationLimit)+".")
		}
	}
	if checks := canonicalSourceLines(b.Flow.SourceChecks); len(checks) > 0 {
		lines = append(lines, strings.Join(checks, "\n"))
	}
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
			lines = append(lines, "*Correlation window:* "+canonicalElapsed(b.Flow.CorrelationOpenedAt, *at))
		}
	case "investigation_started":
		label = "Investigation started"

		if checks := canonicalSourceLines(b.Flow.SourceChecks); len(checks) > 0 {
			lines = append(lines, strings.Join(checks, "\n"))
		}
	case "analysis_completed":
		label, lines = canonicalAnalysisReply(t, b)
	case "partial_clearance":
		label = "Partial clearance"
		lines = append(lines, strings.Join(canonicalClearanceLines(t, b), "\n"))
	case "recovery_observed":
		label = "Recovery observed"
		lines = append(lines, strings.Join(canonicalClearanceLines(t, b), "\n"))
		lines = append(lines, fmt.Sprintf("*Remaining firing:* %d", b.Firing))
	case "recovered":
		label = "Recovered"
		period := "the observation period"
		if t.Projection.RecoveryObservedAt != nil && t.Projection.GraceUntil != nil {
			period = canonicalElapsed(*t.Projection.RecoveryObservedAt, *t.Projection.GraceUntil)
		}
		lines = append(lines, "Alerts stayed clear for "+period+". Monitoring ended.")
	case "recovery_unconfirmed":
		label = "Recovery unconfirmed"
	default:
		if d := t.Projection.OperatorDelta; d != nil {
			lines = append(lines, briefingDeltaLines(d, b, t.Lifecycle.Terminal())...)
		}
	}
	lines = canonicalPrependIncompleteFinding(t, b, lines)
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
		if kind == "investigation_started" && !executionSuperseded {
			next = compactInvestigationStep(next, b)
		}
		if kind == "investigation_started" && !strings.HasPrefix(next, "Investigating") {
			lines = append([]string{"*Investigated inputs:* " + canonicalInvestigationNames(b)}, lines...)
		}
		lines = append([]string{next}, lines...)
	}
	if request := briefingAction(b, t); request != "" {
		lines = append(lines, "*Action:* "+request)
	}
	lines = append(lines, strings.Join(canonicalReplyTimings(t, b, kind), "\n"))
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
		lines = append(lines, canonicalTimings(t, b, t.Projection.EffectiveStartedAt, t.CreatedAt, false, true)...)
	case t.Lifecycle.Terminal():
		end := t.CreatedAt
		if t.Projection.TerminalAt != nil {
			end = *t.Projection.TerminalAt
		}
		lines = append(lines, "*Confirmed:* "+SlackDateToken(end, "{time_secs}"))
		lines = append(lines, canonicalTimings(t, b, t.Projection.EffectiveStartedAt, end, true, true)...)
	default:
		if kind != "investigation_started" {
			lines = append(lines, "*Since first receipt:* "+canonicalElapsed(b.Flow.FirstReceivedAt, t.CreatedAt))
		}
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
		symbol, state string
		names         []string
	}{
		{"🔹", "just recovered", newly}, {"🔹", "resolved earlier", prior}, {"🔸", "firing", firing},
	} {
		for _, name := range entry.names {
			lines = append(lines, entry.symbol+" "+name+" · "+entry.state)
		}
	}
	return lines
}

func canonicalPrependIncompleteFinding(t model.Transition, b *model.OperatorBriefing, lines []string) []string {
	if incomplete := canonicalIncompleteFinding(t, b); incomplete != "" {
		return append([]string{incomplete}, lines...)
	}
	return lines
}
