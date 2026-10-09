// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Message is frozen before publication; its ID remains unchanged on retries.
type Message struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	Priority int    `json:"priority"`
}

func Render(t model.Transition, events []string, delayed bool) Message {
	return render(t, events, delayed, delayed)
}

// RenderCatchup distinguishes an outage recap from work superseded before sending.
func RenderCatchup(t model.Transition, events []string, delayed bool) Message {
	return render(t, events, true, delayed)
}

func render(t model.Transition, events []string, catchup, delayed bool) Message {
	state, icon := presentation(t, events, catchup)
	handle := t.SituationID
	if t.Projection.PublicHandle != nil && *t.Projection.PublicHandle != "" {
		handle = *t.Projection.PublicHandle
	}
	scope := ""
	if b := t.Projection.Briefing; b != nil {
		scope = b.DisplayScope
		if scope == "" {
			scope = b.Scope
		}
	}
	subject := plainText(scope, 90)
	if subject == "" {
		subject = plainText(handle, 90)
	}
	title := icon + " " + state + " · " + subject
	if delayed {
		title = "ntfy delivery resumed · " + title
	} else if catchup {
		title = "ntfy queued update · " + title
	}
	if t.Drill {
		title = "DRILL · " + title
	}
	footer := "---\nSituation: " + codeReference(handle)
	if !t.CreatedAt.IsZero() {
		footer += "  \n" + t.CreatedAt.UTC().Format("02 Jan 2006 · 15:04:05 UTC")
	}
	if t.Drill {
		footer += "  \nDRILL — test Situation."
	}
	body := messageBody{limit: 4000 - len(footer) - 100}
	renderOverview(&body, t, state, delayed, catchup)
	renderContract(&body, t)
	renderLimits(&body, t)
	if b := t.Projection.Briefing; b != nil {
		renderAnalyses(&body, b)
	}
	if !catchup {
		renderJournal(&body, t, state)
	}
	if body.omitted {
		body.parts = append(body.parts, "… More detail is available in the full Situation through MCP.")
	}
	body.parts = append(body.parts, footer)
	priority := 3
	switch situation.DeriveInterruptionPriority(t) {
	case model.InterruptionHigh:
		priority = 4
	case model.InterruptionCritical:
		priority = 5
	case model.InterruptionLow:
		priority = 2
	case model.InterruptionMedium:
	}
	if t.Lifecycle.Terminal() || catchup {
		priority = 3
	}
	return Message{ID: "ntfy:" + t.ID, Title: shorten(title, 200, "…"), Body: strings.Join(body.parts, "\n\n"), Priority: priority}
}

func renderOverview(body *messageBody, t model.Transition, state string, delayed, catchup bool) {
	var overview []string
	if b := t.Projection.Briefing; b != nil {
		if len(b.Symptoms) > 0 {
			overview = append(overview, "**"+body.text(readableName(strings.Join(b.Symptoms, " · ")), 180)+"**")
		}
		if b.Total > 0 {
			if counts := alertCounts(b); counts != "" {
				overview = append(overview, counts)
			}
		}
	}
	if state != lifecycleLabel(t.Lifecycle) {
		overview = append(overview, "**Status:** "+lifecycleLabel(t.Lifecycle))
	}
	if len(overview) > 0 {
		body.add(strings.Join(overview, "  \n"))
	}
	if delayed {
		body.add("**ntfy delivery resumed**  \nNotifications were delayed while ntfy delivery was unavailable or paused. This is the current committed Situation state.")
	} else if catchup {
		body.add("**ntfy queued update**  \nEarlier ntfy notifications were superseded before delivery. This is the current committed Situation state.")
	}
}

func alertCounts(b *model.OperatorBriefing) string {
	var counts []string
	for _, count := range []struct {
		n     int
		label string
	}{{b.Firing, "firing"}, {b.Resolved, "resolved"}, {b.Unknown, "unobserved"}} {
		if count.n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", count.n, count.label))
		}
	}
	return strings.Join(counts, " · ")
}

func renderContract(body *messageBody, t model.Transition) {
	if t.Lifecycle.Terminal() {
		return
	}
	if action := t.ActionContract.OperatorActionRequired; action != nil {
		text := "Investigate this Situation."
		if *action != model.OperatorActionInvestigateSituation {
			text = plainText(strings.ReplaceAll(string(*action), "_", " "), 200)
		}
		body.add("**Your action**  \n" + markdownText(text, 200))
	}
	var activityLines []string
	if activity := currentActivity(t.ActionContract); activity != "" {
		activityLines = append(activityLines, "**AlertINT:** "+activity)
	}
	if at := t.ActionContract.NextUpdateAt; at != nil {
		activityLines = append(activityLines, "**Next checkpoint:** "+at.UTC().Format("15:04 UTC · 02 Jan"))
	}
	if len(activityLines) > 0 {
		body.add(strings.Join(activityLines, "  \n"))
	}
}

func renderLimits(body *messageBody, t model.Transition) {
	if b := t.Projection.Briefing; b != nil {
		var limits []string
		for _, a := range b.Analyses {
			if a.VerificationLimit != "" && !slices.Contains(limits, a.VerificationLimit) {
				limits = append(limits, a.VerificationLimit)
			}
		}
		if len(limits) > 0 {
			body.add("**Uncertainty**  \n" + body.text(strings.Join(limits, "; "), 600))
		}
		if b.BlockedReason != "" {
			body.add("**Investigation limited**  \n" + body.text(strings.ReplaceAll(b.BlockedReason, "_", " "), 200))
		}
	}
	if t.Projection.Assessment != nil && len(t.Projection.Assessment.LimitationCodes) > 0 {
		body.add("**Coverage limitations**  \n" + body.text(strings.ReplaceAll(strings.Join(t.Projection.Assessment.LimitationCodes, ", "), "_", " "), 400))
	}
}

func renderJournal(body *messageBody, t model.Transition, state string) {
	if t.Reason == model.ReasonFirstAuthoritativeState && t.Projection.Briefing != nil && t.Journal.Detail == "" {
		return
	}
	// The title already names the event; avoid repeating a bare state label.
	detail := t.Journal.Detail
	if detail == "" && t.Journal.Headline != "" && t.Journal.Headline != lifecycleLabel(t.Lifecycle) && t.Journal.Headline != state {
		detail = t.Journal.Headline
	}
	if detail != "" {
		body.add("**Update**  \n" + body.text(detail, 300))
	}
}

func shorten(s string, limit int, suffix string) string {
	if len(s) <= limit {
		return s
	}
	end := limit - len(suffix)
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + suffix
}

func lifecycleLabel(lifecycle model.Lifecycle) string {
	switch lifecycle {
	case model.LifecycleActive:
		return "Active"
	case model.LifecycleRecovered:
		return "Recovered"
	case model.LifecycleClosedUnknown:
		return "Tracking ended · recovery unconfirmed"
	case model.LifecycleRecoveryPending:
		return "Recovery pending"
	}
	return "Status unavailable"
}

func presentation(t model.Transition, events []string, catchup bool) (string, string) {
	switch t.Lifecycle {
	case model.LifecycleRecovered:
		return "Recovered", "✅"
	case model.LifecycleClosedUnknown:
		return "Recovery unconfirmed", "⚠️"
	case model.LifecycleRecoveryPending:
		return "Recovery pending", "⏳"
	case model.LifecycleActive:
	}
	if t.ActionContract.OperatorActionRequired != nil {
		return "Action required", "⚠️"
	}
	if !catchup {
		for _, label := range []struct{ event, title, icon string }{
			{"priority_escalated", "Priority escalated", "🚨"},
			{"recovery_refired", "Alert firing again", "🚨"},
			{"coverage_degraded", "Coverage limited", "⚠️"},
			{"investigation_completed", "Investigation update", "🔎"},
			{"investigation_started", "Investigation started", "🔎"},
			{"coverage_restored", "Coverage restored", "🔎"},
			{"members_changed", "Scope changed", "🔎"},
			{"operator_updated", "Operator update", "💬"},
		} {
			if slices.Contains(events, label.event) {
				return label.title, label.icon
			}
		}
	}
	if p := situation.DeriveInterruptionPriority(t); p == model.InterruptionHigh || p == model.InterruptionCritical {
		return "Active", "🚨"
	}
	return "Active", "🔎"
}

func currentActivity(c model.ActionContract) string {
	if c.AlertINTAction == nil || c.AlertINTStatus == nil {
		return ""
	}
	if *c.AlertINTStatus != model.AlertINTStatusRunning {
		activity := "Automatic work"
		switch *c.AlertINTAction {
		case model.AlertINTActionRunAcuteTriage:
			activity = "Investigation"
		case model.AlertINTActionRetrySituationAssessment:
			activity = "Reassessment"
		case model.AlertINTActionMonitorSituation:
			if *c.AlertINTStatus == model.AlertINTStatusWaiting {
				return "Waiting for alert changes."
			}
			activity = "Monitoring"
		case model.AlertINTActionVerifyRecovery:
			activity = "Recovery confirmation"
		}
		return activity + " " + string(*c.AlertINTStatus) + "."
	}
	switch *c.AlertINTAction {
	case model.AlertINTActionRunAcuteTriage:
		return "Investigating this Situation."
	case model.AlertINTActionRetrySituationAssessment:
		return "Reassessing this Situation."
	case model.AlertINTActionMonitorSituation:
		return "Monitoring alert changes."
	case model.AlertINTActionVerifyRecovery:
		return "Checking for sustained recovery."
	}
	return ""
}

func renderAnalyses(body *messageBody, b *model.OperatorBriefing) {
	for i, a := range b.Analyses {
		if i == 2 {
			body.omitted = true
			break
		}
		label := "Analysis"
		if a.Stale || b.Historical {
			label = "Earlier analysis"
		}
		if a.Summary != "" {
			body.add("**" + label + "**  \n" + body.text(a.Summary, 420))
		}
		var observations []string
		for j, observation := range a.Observations {
			if j == 2 {
				body.omitted = true
				break
			}
			observations = append(observations, "- "+body.text(observation, 220))
		}
		if len(observations) > 0 {
			body.add("**Evidence**\n\n" + strings.Join(observations, "\n"))
		}
	}
}

// Limit whole blocks, reserving identity and omission text outside the budget.
// Do not cut the assembled Markdown: that can leave open emphasis or code spans.
type messageBody struct {
	parts   []string
	limit   int
	omitted bool
}

func (b *messageBody) add(s string) {
	if len(s)+2 > b.limit {
		b.omitted = true
		return
	}
	b.parts = append(b.parts, s)
	b.limit -= len(s) + 2
}

func (b *messageBody) text(s string, limit int) string {
	if len(strings.Join(strings.Fields(s), " ")) > limit {
		b.omitted = true
	}
	return markdownText(s, limit)
}

func plainText(s string, limit int) string {
	return shorten(strings.Join(strings.Fields(s), " "), limit, "…")
}

var markdownEscaper = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
	"<", "\\<", ">", "\\>", "#", "\\#", "!", "\\!", "|", "\\|",
	"(", "\\(", ")", "\\)", "{", "\\{", "}", "\\}", "+", "\\+", "-", "\\-", ".", "\\.", "~", "\\~", "=", "\\=",
)

func markdownText(s string, limit int) string {
	return markdownEscaper.Replace(plainText(s, limit))
}

var nameBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func readableName(s string) string {
	return strings.ReplaceAll(nameBoundary.ReplaceAllString(s, "$1 $2"), "_", " ")
}

func codeReference(s string) string {
	s = plainText(s, 200)
	delimiter := "`"
	for strings.Contains(s, delimiter) {
		delimiter += "`"
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return delimiter + s + delimiter
}
