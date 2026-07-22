// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"path/filepath"
	"testing"

	"github.com/alertint/alertint-agent/internal/triage"
)

func TestLoadScenarioAndResponses(t *testing.T) {
	scenarioPath := filepath.Join("testdata", "scenarios", "storm-collapse.yaml")
	sc, err := triage.LoadScenario(scenarioPath)
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if sc.ID != "storm-collapse" {
		t.Fatalf("ID = %q, want storm-collapse", sc.ID)
	}
	if len(sc.Alerts) != 1 || sc.Alerts[0].Repeat != 24 {
		t.Fatalf("alerts = %+v, want one entry with repeat=24", sc.Alerts)
	}

	respPath := filepath.Join("testdata", "scenarios", "storm-collapse.responses.json")
	resps, err := triage.LoadResponses(respPath)
	if err != nil {
		t.Fatalf("LoadResponses: %v", err)
	}
	if len(resps) == 0 {
		t.Fatal("expected at least one scripted response")
	}
}
