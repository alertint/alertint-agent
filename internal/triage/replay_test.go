// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/triage"
)

func TestDeterminismReplay_Match(t *testing.T) {
	dir := t.TempDir()
	goldenPath := filepath.Join(dir, "storm-collapse.json")
	scenarioPath := filepath.Join("testdata", "scenarios", "storm-collapse.yaml")
	responsesPath := filepath.Join("testdata", "scenarios", "storm-collapse.responses.json")

	// Build a golden that matches what the replay will produce.
	g := &triage.Golden{
		SchemaVersion: triage.SchemaVersion,
		ID:            "storm-collapse",
		CapturedAt:    time.Now().UTC(),
		ScenarioPath:  scenarioPath,
		Incident: triage.IncidentSnapshot{
			ID:         "inc-1",
			GroupKey:   "alertname=HighErrorRate",
			AlertCount: 24,
			Alerts:     make([]triage.AlertSnapshot, 24),
		},
		RenderedFinding: json.RawMessage(`{
			"analysis_name": "Storm: shared dependency degradation",
			"overall_issue": "Alert storm across 24 services indicates a shared dependency failure.",
			"correlation_findings": [
				"24 HighErrorRate alerts across 24 distinct services within 5m",
				"Shared cluster=prod and env=prod labels indicate a common upstream cause"
			],
			"severity": "high",
			"confidence": 0.92,
			"alerts": [{"alert_id": "replay-storm-collapse-0-0", "role_in_incident": "correlated"}]
		}`),
		Verification: triage.VerificationSnapshot{Outcome: ""},
		ModelUsage:   triage.ModelUsage{Model: "scripted"},
	}
	for i := range g.Incident.Alerts {
		g.Incident.Alerts[i] = triage.AlertSnapshot{
			ID:     "PLACEHOLDER",
			Labels: map[string]string{"alertname": "HighErrorRate", "cluster": "prod", "env": "prod", "service": "PLACEHOLDER"},
		}
	}
	if err := triage.SaveGolden(goldenPath, g); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}

	loaded, err := triage.LoadGolden(goldenPath)
	if err != nil {
		t.Fatalf("LoadGolden: %v", err)
	}

	errs := triage.DeterminismReplay(loaded, scenarioPath, responsesPath)
	if len(errs) > 0 {
		t.Fatalf("replay errors: %+v", errs)
	}
}
