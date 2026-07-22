// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/severity"
)

// FieldError is one schema-gate failure: a field pointer, the offending value,
// and what was expected. The pointer uses dotted JSON-path notation
// (e.g. "rendered_finding.severity").
type FieldError struct {
	Field string
	Got   string
	Want  string
}

func (e FieldError) Error() string {
	return fmt.Sprintf("%s: got %q, want %s", e.Field, e.Got, e.Want)
}

// SchemaGate validates a golden's shape and value ranges. Pure function over
// the JSON; no LLM, no API key. Returns nil when the golden is well-formed.
func SchemaGate(g *Golden) []FieldError {
	var errs []FieldError

	// Top-level required keys are enforced by DisallowUnknownFields + the
	// struct's required fields; here we check semantic invariants.
	if g.SchemaVersion != SchemaVersion {
		errs = append(errs, FieldError{
			Field: "schema_version",
			Got:   fmt.Sprintf("%d", g.SchemaVersion),
			Want:  fmt.Sprintf("%d", SchemaVersion),
		})
	}
	if g.ID == "" {
		errs = append(errs, FieldError{Field: "id", Got: "", Want: "non-empty string"})
	}
	if g.CapturedAt.IsZero() {
		errs = append(errs, FieldError{Field: "captured_at", Got: "", Want: "non-zero time"})
	}
	if g.ScenarioPath == "" {
		errs = append(errs, FieldError{Field: "scenario_path", Got: "", Want: "non-empty string"})
	}

	// Incident.
	if g.Incident.ID == "" {
		errs = append(errs, FieldError{Field: "incident.id", Got: "", Want: "non-empty string"})
	}
	if g.Incident.AlertCount != len(g.Incident.Alerts) {
		errs = append(errs, FieldError{
			Field: "incident.alert_count",
			Got:   fmt.Sprintf("%d", g.Incident.AlertCount),
			Want:  fmt.Sprintf("%d (matches len(alerts))", len(g.Incident.Alerts)),
		})
	}

	// Rendered finding: parse and validate.
	var rf struct {
		AnalysisName        string  `json:"analysis_name"`
		OverallIssue        string  `json:"overall_issue"`
		CorrelationFindings []string `json:"correlation_findings"`
		Severity            string  `json:"severity"`
		Confidence          float64 `json:"confidence"`
		Alerts              []struct {
			AlertID        string `json:"alert_id"`
			RoleInIncident string `json:"role_in_incident"`
		} `json:"alerts"`
		MemoryVerdict string `json:"memory_verdict,omitempty"`
	}
	if err := jsonUnmarshal(g.RenderedFinding, &rf); err != nil {
		errs = append(errs, FieldError{
			Field: "rendered_finding",
			Got:   err.Error(),
			Want:  "valid JSON object",
		})
		return errs
	}
	if rf.AnalysisName == "" {
		errs = append(errs, FieldError{Field: "rendered_finding.analysis_name", Got: "", Want: "non-empty string"})
	}
	if rf.OverallIssue == "" {
		errs = append(errs, FieldError{Field: "rendered_finding.overall_issue", Got: "", Want: "non-empty string"})
	}
	if g.Incident.AlertCount > 1 && len(rf.CorrelationFindings) == 0 {
		errs = append(errs, FieldError{
			Field: "rendered_finding.correlation_findings",
			Got:   "[]",
			Want:  "non-empty when alert_count > 1",
		})
	}
	if severity.GateRank(rf.Severity) == 0 {
		errs = append(errs, FieldError{
			Field: "rendered_finding.severity",
			Got:   rf.Severity,
			Want:  "low|medium|high",
		})
	}
	if rf.Confidence < 0 || rf.Confidence > 1 {
		errs = append(errs, FieldError{
			Field: "rendered_finding.confidence",
			Got:   fmt.Sprintf("%f", rf.Confidence),
			Want:  "[0.0, 1.0]",
		})
	}
	if len(rf.Alerts) == 0 {
		errs = append(errs, FieldError{
			Field: "rendered_finding.alerts",
			Got:   "[]",
			Want:  "non-empty",
		})
	}
	// Every alert_id must reference a real incident alert.
	known := make(map[string]bool, len(g.Incident.Alerts))
	for _, a := range g.Incident.Alerts {
		known[a.ID] = true
	}
	for i, ao := range rf.Alerts {
		if ao.AlertID == "" {
			errs = append(errs, FieldError{
				Field: fmt.Sprintf("rendered_finding.alerts[%d].alert_id", i),
				Got:   "",
				Want:  "non-empty string",
			})
			continue
		}
		if !known[ao.AlertID] {
			errs = append(errs, FieldError{
				Field: fmt.Sprintf("rendered_finding.alerts[%d].alert_id", i),
				Got:   ao.AlertID,
				Want:  "id present in incident.alerts",
			})
		}
		if strings.TrimSpace(ao.RoleInIncident) == "" {
			errs = append(errs, FieldError{
				Field: fmt.Sprintf("rendered_finding.alerts[%d].role_in_incident", i),
				Got:   "",
				Want:  "non-empty string",
			})
		}
	}

	// Verification.
	switch g.Verification.Outcome {
	case "supported", "revised", "degraded", "":
		// "" is allowed when verification was disabled.
	default:
		errs = append(errs, FieldError{
			Field: "verification.outcome",
			Got:   g.Verification.Outcome,
			Want:  "supported|revised|degraded",
		})
	}

	// Model usage.
	if g.ModelUsage.InputTokens < 0 {
		errs = append(errs, FieldError{
			Field: "model_usage.input_tokens",
			Got:   fmt.Sprintf("%d", g.ModelUsage.InputTokens),
			Want:  ">= 0",
		})
	}
	if g.ModelUsage.OutputTokens < 0 {
		errs = append(errs, FieldError{
			Field: "model_usage.output_tokens",
			Got:   fmt.Sprintf("%d", g.ModelUsage.OutputTokens),
			Want:  ">= 0",
		})
	}
	if g.ModelUsage.LatencyMS < 0 {
		errs = append(errs, FieldError{
			Field: "model_usage.latency_ms",
			Got:   fmt.Sprintf("%d", g.ModelUsage.LatencyMS),
			Want:  ">= 0",
		})
	}
	if g.ModelUsage.CostUSD < 0 {
		errs = append(errs, FieldError{
			Field: "model_usage.cost_usd",
			Got:   fmt.Sprintf("%f", g.ModelUsage.CostUSD),
			Want:  ">= 0",
		})
	}

	return errs
}
