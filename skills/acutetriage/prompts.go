// SPDX-License-Identifier: FSL-1.1-ALv2

// Package acutetriage implements the acute-triage skill (Slice 07).
// This file contains the system prompt and the evidence-pack builder.
package acutetriage

import (
	"encoding/json"
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
- If the input contains more than 20 alerts, itemize only the 20 most significant in the
  alerts array — every "primary" and "noise" call must be among them; alerts you omit are
  recorded as "correlated" automatically. With 20 or fewer alerts, every alert_id in the
  input must appear exactly once.
- Keep prose tight: at most 6 correlation_findings, each at most 25 words; overall_issue
  stays a single sentence.
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

// maxItemizedAlerts bounds the per-alert itemization the prompts request:
// incidents larger than this get top-N itemization and the code-side
// "correlated" defaulting for the rest (skill.go, defaultUnitemizedRoles),
// keeping the response's output-token size flat at any storm size — same
// bounded-by-construction philosophy as prometheus.max_series (0.7.3). The
// literal value also appears in packs/baseline/templates/{correlated,storm,
// recovery}.md; prompts_itemize_test.go pins them together.
const maxItemizedAlerts = 20

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
// verify.Enabled gates the verification-plan instruction (R1) and, when true,
// moves the memory-verdict request out of this call and into callTwoPrompt
// (R16) — call 2 is where the model re-judges with real evidence in hand, so
// asking for a verdict here would have it judge the recalled prior against
// nothing but its own draft. verify.Enabled == false reproduces the pre-Task-5
// prompt byte-for-byte (the kill switch).
func UserPrompt(pack EvidencePack, packJSON string, metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, memory *MemoryEnrichment, verify VerificationParams) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"Analyze the following correlated incident.\n\nEvidence:\n%s\n\nShared labels: %s\nAlert count: %d\nWindow: %ds",
		packJSON,
		formatLabels(pack.SharedLabels),
		pack.AlertCount,
		pack.WindowSeconds,
	)
	renderMetrics(&b, metrics)
	renderLogs(&b, logs)
	renderChanges(&b, changes)
	renderSentry(&b, sentry)
	renderMemory(&b, memory, !verify.Enabled)
	renderEvidenceBasis(&b, metrics, logs, changes, sentry, memory != nil)
	renderVerificationInstruction(&b, verify)
	b.WriteString("\n\nRespond with JSON only.")
	return b.String()
}

// renderVerificationInstruction appends the "verification" JSON-key request
// (R1) when verification is enabled — up to verify.MaxQueries model-proposed
// disprove-queries, from a closed kind set (promql, incidents_in_window; the
// floor's up_ratio is never model-proposable). A root cause claiming
// wider-than-member-alert scope MUST include targeted queries (R7 —
// scope-inflation guard); an empty list is otherwise allowed. Silent when
// verification is disabled, so the kill switch is total, not just
// byte-identical for one fixture.
func renderVerificationInstruction(b *strings.Builder, verify VerificationParams) {
	if !verify.Enabled {
		return
	}
	fmt.Fprintf(b, "\n\n## Verification plan (required key)\n"+
		"After forming your verdict, add a \"verification\" key to your JSON, shaped exactly:\n"+
		`  "verification": {"queries": [<up to %d queries>]}`+"\n"+
		"Each query is a read-only check that could DISPROVE your root cause. Allowed kinds:\n"+
		`  {"kind":"promql","expr":"<instant PromQL>","why":"<what this would refute>"}`+"\n"+
		`  {"kind":"incidents_in_window","params":{"window_minutes":60},"why":"..."}`+"\n"+
		"A root cause claiming scope wider than the member alerts (cluster-wide, zonal, "+
		"regional, infrastructure-wide) MUST include targeted disprove-queries. An empty "+
		"list is allowed when no check would change your verdict. Two checks always run "+
		"regardless: a parent-scope up ratio and an incidents-in-window scan — do not "+
		"duplicate them.", verify.MaxQueries)
}

// callTwoPrompt builds the full continuation prompt for the second LLM call
// (R5): call 1's prompt verbatim (byte-identical prefix — the load-bearing
// property for prompt caching), the model's own draft verdict, the computed
// verification results, and a re-judge instruction. The verification results
// are computed facts and OUTRANK the draft, the evidence sections above, and
// any recalled prior hypotheses — the model is told to revise, not defend.
// The memory-verdict request (moved here from call 1 per R16 when
// verification is enabled) is appended only when a strong prior was recalled,
// so the marks it drives have a target to judge.
func callTwoPrompt(callOne string, draftRaw json.RawMessage, round *VerificationRound, memory *MemoryEnrichment) string {
	var b strings.Builder
	b.WriteString(callOne)
	b.WriteString("\n\n## Your draft verdict (your own prior output)\n")
	b.Write(draftRaw)
	renderVerificationResults(&b, round)
	b.WriteString("\n\nThese results are computed facts: they outrank the draft, the evidence " +
		"sections above, and any recalled prior hypotheses. Re-judge your draft against them. " +
		"If they contradict it, revise — do not defend the draft. A replacement hypothesis " +
		"formed now is itself unverified: keep its confidence moderate. Respond with the SAME " +
		"JSON schema as before, complete (do NOT include the \"verification\" key again).")
	if memory != nil && memory.Strong != nil {
		b.WriteString("\n\nAfter weighing the verification results, add a \"memory_verdict\" field " +
			"judging the folded prior hypothesis in the Memory section: \"confirms\", \"refutes\", " +
			"or \"silent\". Do NOT raise your confidence on the strength of the recalled hypothesis alone.")
	}
	return b.String()
}

// MaxMetadataOnlyConfidence is the confidence ceiling for findings built from
// alert metadata alone. Exported so surfaces explaining the cap (the drill
// console hint) reference the real value.
// alert labels/annotations alone (no live metrics, logs, changes, or Sentry
// issues). It appears in two places that must stay in sync: the prompt
// directive below (the model is asked to respect it) and the deterministic
// backstop in Skill.Run (which enforces it when the model doesn't).
const MaxMetadataOnlyConfidence = 0.6

// renderEvidenceBasis appends a calibration directive when NO live evidence
// (log lines, metric values, changes, or Sentry issues) was retrieved for the
// incident — i.e. the analysis rests on alert labels/annotations alone. It
// counters BUG-2: an authoritative-but-unverified finding (a confident, wrong
// causal direction) anchors the downstream AI agent on the wrong fix, so an
// annotations-only analysis must hedge and lower confidence. When any live
// evidence is present the per-section guidance already governs and this is silent.
// A section that was attempted but empty (a note, zero lines) is NOT live
// evidence — the note alone does not lift the annotations-only basis. Nor does a
// recalled memory section: recalled priors are past hypotheses, so when
// memoryPresent is true the directive says so explicitly — a recalled prior's
// confidence must not be smuggled into today's evidence-free re-fire (R18/R20).
func renderEvidenceBasis(b *strings.Builder, metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, memoryPresent bool) {
	// Call 1 renders this before any verification round exists, so it passes nil:
	// the prompt-side directive is unchanged by verification. Only the
	// deterministic post-call cap (applyEvidenceCap) sees the executed round.
	if !annotationsOnlyBasis(metrics, logs, changes, sentry, nil) {
		return
	}
	b.WriteString("\n\nEvidence basis: ANNOTATIONS ONLY — no live logs, metrics, " +
		"deploy/config changes, or Sentry errors were retrieved for this incident, so " +
		"every conclusion below rests on alert labels and annotations alone. Treat any " +
		"root-cause or causal-direction claim (which alert is primary vs downstream) as an " +
		"unverified hypothesis: prefer the \"correlated\" role over confident \"primary\"/" +
		"\"downstream\" assignments unless the ordering is self-evident from the annotations, " +
		fmt.Sprintf("and keep confidence at or below %.1f.", MaxMetadataOnlyConfidence))
	if memoryPresent {
		b.WriteString(" Any prior findings recalled in the Memory section are past " +
			"hypotheses, NOT live evidence — they do not lift this annotations-only basis " +
			"or raise the confidence ceiling.")
	}
}

// metricsDegraded reports whether metric enrichment was attempted but the
// backend was merely too slow to answer within the deadline (OutcomeDegraded) —
// a self-inflicted timeout under load, not an outage. The metric data very
// likely exists, so unlike a genuine failure or empty result it must NOT force
// the annotations-only confidence cap.
func metricsDegraded(metrics *MetricEnrichment) bool {
	return metrics != nil && metrics.Outcome == OutcomeDegraded
}

// annotationsOnlyBasis reports whether the finding rests on alert annotations
// alone — no live evidence AND no self-inflicted metric timeout to excuse the
// absence. This is the single condition that triggers the metadata-only
// confidence cap; both the prompt directive (renderEvidenceBasis) and the
// deterministic backstop (applyEvidenceCap) route through it so they never drift.
// A fetched verification up_ratio/promql observation counts as live evidence
// (verificationLive) — a real read of the infrastructure, R17 — so it lifts the
// basis too; incidents_in_window never does (own SQLite bookkeeping). ver is nil
// on the prompt side (the round has not run yet), non-nil at the post-call cap.
func annotationsOnlyBasis(metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, ver *VerificationEnrichment) bool {
	return !hasLiveEvidence(metrics, logs, changes, sentry) && !metricsDegraded(metrics) && !verificationLive(ver)
}

// hasLiveEvidence reports whether any enrichment source returned actual data
// (not just an attempted-but-empty note) for the incident.
func hasLiveEvidence(metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment) bool {
	switch {
	case metrics != nil && len(metrics.Snapshots) > 0:
		return true
	case logs != nil && len(logs.Lines) > 0:
		return true
	case changes != nil && len(changes.Changes) > 0:
		return true
	case sentry != nil && len(sentry.Issues) > 0:
		return true
	default:
		return false
	}
}

// renderMetrics appends the "Live metrics" section. When snapshots are present
// they render as metric{series} = value; when empty (queried-empty / no-selector
// / backend-failed) the note renders instead, so the model sees metrics were
// attempted — the same visibility posture logs already have. Omitted only when
// metrics are not configured (m is nil).
func renderMetrics(b *strings.Builder, m *MetricEnrichment) {
	if m == nil {
		return
	}
	if len(m.Snapshots) > 0 {
		b.WriteString("\n\nLive metrics (Prometheus, at incident time):")
		for _, s := range m.Snapshots {
			fmt.Fprintf(b, "\n  %s%s = %s", s.Metric, s.Series, s.Value)
		}
		return
	}
	note := m.Note
	if note == "" {
		note = "no metric values available"
	}
	fmt.Fprintf(b, "\n\nLive metrics (Prometheus): %s", note)
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
	renderReconciliationHeadline(b, e)
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

// renderReconciliationHeadline prepends the one neutral cross-source headline
// above the Sentry issue render. It is derived ENTIRELY from the persisted verdict
// — counts and scope only, never a Sentry-controlled string (title/message/culprit)
// — so per ADR-0011 it is a presented signal the model weighs, not a directive
// (KTD4). N (matched) and M (chronic) both read from Reconciliation, which carries
// the FULL pre-cap counts, never the truncated render, so a busy service reports
// the true count rather than a constant MaxIssues. It renders only on a conclusive
// look (Reconciliation != nil), so it is naturally inert on the degraded /
// unknown-project / disabled paths (R5/R6/R7).
func renderReconciliationHeadline(b *strings.Builder, e *SentryEnrichment) {
	if e.Reconciliation == nil {
		return
	}
	switch e.Reconciliation.Tag {
	case tagMatched:
		fmt.Fprintf(b, "\n\nSentry: %d new in-window error(s) correlated", len(e.Reconciliation.CorroboratingIssueIDs))
	case tagInfraOnly:
		b.WriteString("\n\nSentry: no new in-window errors for this scope")
		if e.Reconciliation.ChronicCount > 0 {
			fmt.Fprintf(b, " (%d chronic present)", e.Reconciliation.ChronicCount)
		}
	}
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
