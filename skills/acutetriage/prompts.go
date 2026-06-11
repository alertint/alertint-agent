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

// SystemPrompt is the fixed system prompt sent to the LLM for every
// acute-triage analysis. It instructs the model to return strict JSON
// matching ResponseSchema.
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
  confidence — actual metric values take precedence over numeric claims in annotations.`

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
// LLM. metrics is optional — pass nil when Prometheus is not available.
func UserPrompt(pack EvidencePack, packJSON string, metrics []MetricSnapshot) string {
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
	b.WriteString("\n\nRespond with JSON only.")
	return b.String()
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
