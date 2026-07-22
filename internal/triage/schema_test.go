// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/triage"
)

func validGolden() *triage.Golden {
	return &triage.Golden{
		SchemaVersion: triage.SchemaVersion,
		ID:            "test",
		CapturedAt:    time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC),
		ScenarioPath:  "scenarios/test.yaml",
		Incident: triage.IncidentSnapshot{
			ID:         "inc-1",
			GroupKey:   "alertname=Test",
			AlertCount: 1,
			Alerts: []triage.AlertSnapshot{{
				ID:     "a1",
				Labels: map[string]string{"alertname": "Test"},
			}},
		},
		RenderedFinding: json.RawMessage(`{
			"analysis_name": "x",
			"overall_issue": "y",
			"correlation_findings": ["z"],
			"severity": "high",
			"confidence": 0.9,
			"alerts": [{"alert_id": "a1", "role_in_incident": "correlated"}]
		}`),
		Verification: triage.VerificationSnapshot{Outcome: "supported"},
		ModelUsage:   triage.ModelUsage{Model: "test", InputTokens: 1, OutputTokens: 1, LatencyMS: 1, CostUSD: 0.01},
	}
}

func TestSchemaGate_Valid(t *testing.T) {
	if errs := triage.SchemaGate(validGolden()); len(errs) > 0 {
		t.Fatalf("expected no errors, got: %+v", errs)
	}
}

func TestSchemaGate_BadSeverity(t *testing.T) {
	g := validGolden()
	g.RenderedFinding = json.RawMessage(`{
		"analysis_name": "x",
		"overall_issue": "y",
		"correlation_findings": ["z"],
		"severity": "Page",
		"confidence": 0.9,
		"alerts": [{"alert_id": "a1", "role_in_incident": "correlated"}]
	}`)
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for bad severity")
	}
	if errs[0].Field != "rendered_finding.severity" {
		t.Fatalf("field = %q, want rendered_finding.severity", errs[0].Field)
	}
}

func TestSchemaGate_BadConfidence(t *testing.T) {
	g := validGolden()
	g.RenderedFinding = json.RawMessage(`{
		"analysis_name": "x",
		"overall_issue": "y",
		"correlation_findings": ["z"],
		"severity": "high",
		"confidence": 1.5,
		"alerts": [{"alert_id": "a1", "role_in_incident": "correlated"}]
	}`)
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for confidence > 1")
	}
}

func TestSchemaGate_AlertCountMismatch(t *testing.T) {
	g := validGolden()
	g.Incident.AlertCount = 5
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for alert_count mismatch")
	}
}

func TestSchemaGate_UnknownAlertID(t *testing.T) {
	g := validGolden()
	g.RenderedFinding = json.RawMessage(`{
		"analysis_name": "x",
		"overall_issue": "y",
		"correlation_findings": ["z"],
		"severity": "high",
		"confidence": 0.9,
		"alerts": [{"alert_id": "unknown", "role_in_incident": "correlated"}]
	}`)
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for unknown alert_id")
	}
}

func TestSchemaGate_EmptyRole(t *testing.T) {
	g := validGolden()
	g.RenderedFinding = json.RawMessage(`{
		"analysis_name": "x",
		"overall_issue": "y",
		"correlation_findings": ["z"],
		"severity": "high",
		"confidence": 0.9,
		"alerts": [{"alert_id": "a1", "role_in_incident": ""}]
	}`)
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for empty role_in_incident")
	}
}

func TestSchemaGate_BadVerificationOutcome(t *testing.T) {
	g := validGolden()
	g.Verification.Outcome = "bogus"
	errs := triage.SchemaGate(g)
	if len(errs) == 0 {
		t.Fatal("expected error for bad verification outcome")
	}
}
