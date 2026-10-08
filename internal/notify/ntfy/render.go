// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"fmt"
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
	state := "Active"
	switch t.Lifecycle {
	case model.LifecycleActive:
	case model.LifecycleRecovered:
		state = "Recovered"
	case model.LifecycleClosedUnknown:
		state = "Closed with uncertainty"
	case model.LifecycleRecoveryPending:
		state = "Recovery pending"
	}
	handle := t.SituationID
	if t.Projection.PublicHandle != nil {
		handle = *t.Projection.PublicHandle
	}
	title := state + " · " + handle
	if t.ActionContract.OperatorActionRequired != nil && !t.Lifecycle.Terminal() {
		title = "Operator action required · " + handle
	}
	if delayed {
		title = "ntfy delivery resumed · " + title
	} else if catchup {
		title = "ntfy queued update · " + title
	}
	if t.Drill {
		title = "DRILL · " + title
	}
	body := fmt.Sprintf("Situation: %s\nStatus: %s\nOccurred: %s\nEvents: %s\n", shorten(handle, 160, "…"), state, t.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), strings.Join(events, ", "))
	if t.Drill {
		body += "DRILL — test Situation.\n"
	}
	if delayed {
		body += "Notifications were delayed while ntfy delivery was unavailable or paused. This is the current committed Situation state.\n"
	} else if catchup {
		body += "Earlier ntfy notifications were superseded before delivery. This is the current committed Situation state.\n"
	}
	if !t.Lifecycle.Terminal() {
		if action := t.ActionContract.OperatorActionRequired; action != nil {
			body += "Required action: " + shorten(string(*action), 400, "…") + "\n"
		}
	}
	if b := t.Projection.Briefing; b != nil {
		body += briefingEssentials(b)
	}
	if t.Projection.Assessment != nil && len(t.Projection.Assessment.LimitationCodes) > 0 {
		body += "Coverage limitations: " + shorten(strings.Join(t.Projection.Assessment.LimitationCodes, ", "), 400, "…") + "\n"
	}
	if b := t.Projection.Briefing; b != nil {
		if len(b.Symptoms) > 0 {
			body += "Symptoms: " + strings.Join(b.Symptoms, "; ") + "\n"
		}
		for _, a := range b.Analyses {
			body += "Finding: " + a.Summary + "\n"
			if len(a.Observations) > 0 {
				body += "Observations: " + strings.Join(a.Observations, "; ") + "\n"
			}
		}
	}
	if !catchup {
		body += t.Journal.Headline + "\n" + t.Journal.Detail
	}
	priority := 3
	{
		switch situation.DeriveInterruptionPriority(t) {
		case model.InterruptionHigh:
			priority = 4
		case model.InterruptionCritical:
			priority = 5
		case model.InterruptionLow:
			priority = 2
		case model.InterruptionMedium:
		}
	}
	if t.Lifecycle.Terminal() || catchup {
		priority = 3
	}
	return Message{ID: "ntfy:" + t.ID, Title: shorten(strings.NewReplacer("\r", " ", "\n", " ").Replace(title), 200, "…"), Body: shorten(body, 4000, "\n… full Situation history is available through MCP."), Priority: priority}
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

func briefingEssentials(b *model.OperatorBriefing) string {
	body := ""
	body += "Scope: " + shorten(b.DisplayScope, 300, "…") + "\n"
	if b.DisplayScope == "" {
		body += "Source scope: " + shorten(b.Scope, 300, "…") + "\n"
	}
	// Reserve essential uncertainty before any potentially long findings.
	var uncertainty []string
	for _, a := range b.Analyses {
		if a.VerificationLimit != "" {
			uncertainty = append(uncertainty, a.VerificationLimit)
		}
	}
	if len(uncertainty) > 0 {
		body += "Uncertainty: " + shorten(strings.Join(uncertainty, "; "), 600, "…") + "\n"
	}
	if b.BlockedReason != "" {
		body += "Investigation limited: " + shorten(b.BlockedReason, 200, "…") + "\n"
	}
	return body
}
