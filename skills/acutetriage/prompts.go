// SPDX-License-Identifier: FSL-1.1-ALv2

// Package acutetriage implements the acute-triage skill (Slice 07).
// This file contains the system prompt and the evidence-pack builder.
package acutetriage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// SystemPrompt is the built-in fallback prompt, used only when no rule
// engine is wired or a pack template is missing. The shipped prompts live
// in packs/baseline/templates/ (correlated, single_alert, storm, recovery)
// and are selected per incident by the rule engine.
const SystemPrompt = `You are an expert SRE analyzing a correlated group of firing alerts.
Your task is to identify the underlying issue, determine how alerts correlate and connect,
assign severity, and rank alerts by their role in the incident.

You MUST respond with ONLY a valid JSON object — no prose, no markdown fences.
The response must conform exactly to this schema:
{
  "analysis_name":        "string (short title, ≤80 chars)",
  "overall_issue":        "string (one-sentence root-cause hypothesis)",
  "correlation_findings": ["string", ...],
  "severity":             "low|medium|high",
  "confidence":           0.0,
  "alerts": [
    {"alert_id": "uuid", "role_in_incident": "string"}
  ]
}

Rules:
- severity must be one of: "low", "medium", or "high" based on business impact and urgency.
- confidence is a float in [0.0, 1.0] reflecting how certain you are about the correlation and root cause.
- Focus on explaining HOW alerts are connected and WHY they belong to the same incident.
- Every alert_id in the input must appear exactly once in the alerts array.
- role_in_incident should be one of: primary, downstream, correlated, noise.
- If you cannot determine a role, use "unknown".
- If a "Live metrics" section is present, use those values to calibrate severity and
  confidence — actual metric values take precedence over numeric claims in annotations.
- If a "Recent logs" section has lines, use them to identify the concrete error at
  incident time — quoted log lines are stronger evidence than annotation text, and the
  lines are listed most-recent-first. If that section instead says the backend returned
  no lines or failed, treat it as a gap in evidence — do NOT infer the service is healthy
  from absent logs.
- If a "Recent changes" section is present, a deploy/config/flag change shortly
  before the incident is a prime root-cause candidate — weigh its Δ-before-incident
  timing. Absence of changes is NOT proof nothing changed (the emitter may not be wired).
- If a "Sentry issues" section is present, a NEW-in-window issue (first seen inside the
  incident window) is a prime root-cause candidate and its file:line is where to look
  first; a chronic issue (first seen before the window) is more likely a symptom than the
  cause. The affected-user count and event rate calibrate severity. A "no Sentry issues …
  in window" note is evidence the incident is likely NOT application-code-driven (e.g.
  infra/network) — it is NOT proof of health. The section is distilled, not exhaustive.`

// RequiredKeys lists the top-level keys that must be present in a valid
// LLM response. Passed to llm.Client.Complete for structural validation.
var RequiredKeys = []string{
	"analysis_name",
	"overall_issue",
	"correlation_findings",
	"severity",
	"confidence",
	"alerts",
}

// EvidencePack is the structured evidence built from an incident and its
// member alerts. It is serialized to JSON and passed as the user prompt.
type EvidencePack struct {
	IncidentID    string            `json:"incident_id"`
	GroupKey      string            `json:"group_key"`
	WindowSeconds int               `json:"window_seconds"`
	FirstAlertAt  time.Time         `json:"first_alert_at"`
	LastAlertAt   time.Time         `json:"last_alert_at"`
	AlertCount    int               `json:"alert_count"`
	SharedLabels  map[string]string `json:"shared_labels"`
	Timeline      []AlertSummary    `json:"timeline"`
}

// AlertSummary is the per-alert slice included in the evidence pack.
type AlertSummary struct {
	AlertID     string            `json:"alert_id"`
	Fingerprint string            `json:"fingerprint"`
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"starts_at"`
}

// BuildEvidencePack constructs the evidence pack from an incident and its
// member alerts. windowSeconds is taken from the correlator config.
func BuildEvidencePack(inc store.Incident, alerts []store.Alert, windowSeconds int) EvidencePack {
	timeline := make([]AlertSummary, 0, len(alerts))
	for _, a := range alerts {
		timeline = append(timeline, AlertSummary{
			AlertID:     a.ID,
			Fingerprint: a.Fingerprint,
			Status:      a.Status,
			Labels:      a.Labels,
			Annotations: a.Annotations,
			StartsAt:    a.StartsAt,
		})
	}
	// Sort by StartsAt ascending for chronological timeline.
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].StartsAt.Before(timeline[j].StartsAt)
	})

	return EvidencePack{
		IncidentID:    inc.ID,
		GroupKey:      inc.GroupKey,
		WindowSeconds: windowSeconds,
		FirstAlertAt:  inc.FirstAlertAt,
		LastAlertAt:   inc.LastAlertAt,
		AlertCount:    inc.AlertCount,
		SharedLabels:  sharedLabels(alerts),
		Timeline:      timeline,
	}
}

// UserPrompt renders the evidence pack into the user-turn message sent to the
// LLM. metrics is optional — pass nil when Prometheus is not available. logs is
// optional — pass nil when no log source is configured; when non-nil it always
// renders a "Recent logs" section (lines, or a note explaining their absence).
func UserPrompt(pack EvidencePack, packJSON string, metrics []MetricSnapshot, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"Analyze the following correlated incident.\n\nEvidence:\n%s\n\nShared labels: %s\nAlert count: %d\nWindow: %ds",
		packJSON,
		formatLabels(pack.SharedLabels),
		pack.AlertCount,
		pack.WindowSeconds,
	)
	if len(metrics) > 0 {
		b.WriteString("\n\nLive metrics (Prometheus, at incident time):")
		for _, m := range metrics {
			fmt.Fprintf(&b, "\n  %s{instance=%q} = %s", m.Metric, m.Instance, m.Value)
		}
	}
	renderLogs(&b, logs)
	renderChanges(&b, changes)
	renderSentry(&b, sentry)
	b.WriteString("\n\nRespond with JSON only.")
	return b.String()
}

// renderSentry appends the "Sentry issues" Error-source section. With issues
// they render most-relevant-first (NEW before chronic, then blast radius), each
// carrying its file:line (or culprit fallback), level, affected-user count, and
// in-window rate, plus the exception message when the toggle kept it. When the
// match set is empty the Note renders instead (so the model sees we looked and
// found nothing / the project was unknown / the backend failed). Omitted only
// when sentry is nil (disabled / unconfigured / no scope). Mirrors renderChanges.
func renderSentry(b *strings.Builder, e *SentryEnrichment) {
	if e == nil {
		return
	}
	if len(e.Issues) > 0 {
		fmt.Fprintf(b, "\n\nSentry issues (at triage time, %s, most relevant first):", scopeLabel(e.Project, e.Environment))
		for _, iss := range e.Issues {
			renderSentryIssue(b, iss)
		}
		if e.MoreCount > 0 {
			fmt.Fprintf(b, "\n  +%d more matched", e.MoreCount)
		}
		return
	}
	note := e.Note
	if note == "" {
		note = "no Sentry issues available"
	}
	fmt.Fprintf(b, "\n\nSentry issues (at triage time): %s", note)
}

// renderSentryIssue renders one distilled issue line (plus its message line when
// present): "[NEW|chronic] <type> @ <file:line|culprit> · <level> · <N> users · <rate>".
func renderSentryIssue(b *strings.Builder, iss SentryIssueView) {
	novelty := "chronic"
	if iss.New {
		novelty = "NEW"
	}
	fmt.Fprintf(b, "\n  [%s] %s", novelty, iss.ExceptionType)
	if loc := issueLocation(iss); loc != "" {
		fmt.Fprintf(b, " @ %s", loc)
	}
	if iss.Level != "" {
		fmt.Fprintf(b, " · %s", iss.Level)
	}
	fmt.Fprintf(b, " · %d users", iss.UserCount)
	if iss.RatePerMin != "" {
		fmt.Fprintf(b, " · %s", iss.RatePerMin)
	}
	if iss.Message != "" {
		fmt.Fprintf(b, "\n    %s", iss.Message)
	}
}

// issueLocation is the jump-to target for an issue: the deepest in-app file:line
// when one was recovered, else the issue culprit (a vendored/framework trace or a
// frame fetch that degraded). Empty when neither is known.
func issueLocation(iss SentryIssueView) string {
	if iss.FileLine != "" {
		return iss.FileLine
	}
	return iss.Culprit
}

// renderChanges appends the "Recent changes" section. With matched changes they
// render most-relevant-first, each carrying its Δ-before-incident hint — the
// single highest-signal fact for the LLM. When empty the Note renders instead
// (so the model sees we looked). Omitted only when changes is nil (disabled).
func renderChanges(b *strings.Builder, e *ChangeEnrichment) {
	if e == nil {
		return
	}
	if len(e.Changes) > 0 {
		b.WriteString("\n\nRecent changes (most relevant first, matched on incident labels):")
		for _, c := range e.Changes {
			fmt.Fprintf(b, "\n  %s  [%s] %s", c.DeltaBeforeIncident, c.Kind, c.Title)
			if c.Version != "" {
				fmt.Fprintf(b, " (%s)", c.Version)
			}
			if len(c.MatchedOn) > 0 {
				fmt.Fprintf(b, "  {matched: %s}", formatLabels(c.MatchedOn))
			}
			if c.Link != "" {
				fmt.Fprintf(b, "  %s", c.Link)
			}
		}
		return
	}
	note := e.Note
	if note == "" {
		note = "no recent changes available"
	}
	fmt.Fprintf(b, "\n\nRecent changes: %s", note)
}

// renderLogs appends the "Recent logs" section. When the enrichment carries
// lines they render newest-first; when it is empty (queried-empty / timeout /
// error / no-selector) the note renders instead — so the operator and the LLM
// both see that logs were attempted. The section is omitted only when logs are
// not configured (enrichment is nil).
func renderLogs(b *strings.Builder, e *LogEnrichment) {
	if e == nil {
		return
	}
	if len(e.Lines) > 0 {
		fmt.Fprintf(b, "\n\nRecent logs (%s, most recent first, around incident time):", e.Source)
		for _, ln := range e.Lines {
			fmt.Fprintf(b, "\n  %s  %s", ln.Timestamp.UTC().Format(time.RFC3339), ln.Line)
		}
		return
	}
	note := e.Note
	if note == "" {
		note = "no log lines available"
	}
	fmt.Fprintf(b, "\n\nRecent logs (%s): %s", e.Source, note)
	if e.Query != "" {
		fmt.Fprintf(b, "\n  (query: %s). Treat this as missing evidence, not as \"no errors\".", e.Query)
	} else {
		b.WriteString("\n  Treat this as missing evidence, not as \"no errors\".")
	}
}

// sharedLabels returns labels whose key AND value are identical across all
// alerts. Empty if no alerts are provided.
func sharedLabels(alerts []store.Alert) map[string]string {
	if len(alerts) == 0 {
		return map[string]string{}
	}
	shared := make(map[string]string)
	for k, v := range alerts[0].Labels {
		shared[k] = v
	}
	for _, a := range alerts[1:] {
		for k := range shared {
			if a.Labels[k] != shared[k] {
				delete(shared, k)
			}
		}
	}
	return shared
}

// formatLabels renders a label map as "k=v,k=v" sorted for determinism.
func formatLabels(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
