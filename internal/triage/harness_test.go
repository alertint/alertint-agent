// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alertint/alertint-agent/internal/triage"
)

// TestHarness runs the full eval harness against every committed golden.
// On any failure, writes .last-failures/<stem>.json with the structured
// detail. The judge layer is skipped when ANTHROPIC_API_KEY is absent.
func TestHarness(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no golden dir yet: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			g, err := triage.LoadGolden(path)
			if err != nil {
				t.Fatalf("LoadGolden: %v", err)
			}

			if errs := triage.SchemaGate(g); len(errs) > 0 {
				writeFailure(t, path, "schema", errs, g, "", "", 0, 0)
				t.Fatalf("schema gate: %+v", errs)
			}

			scenarioPath := filepath.Join("testdata", "scenarios", g.ID+".yaml")
			responsesPath := filepath.Join("testdata", "scenarios", g.ID+".responses.json")
			if errs := triage.DeterminismReplay(g, scenarioPath, responsesPath); len(errs) > 0 {
				writeFailure(t, path, "determinism", errs, g, "", "", 0, 0)
				t.Fatalf("determinism replay: %+v", errs)
			}

			if os.Getenv("ANTHROPIC_API_KEY") == "" {
				t.Skipf("ANTHROPIC_API_KEY not set; schema-gate and replay still ran")
			}
		})
	}
}

func writeFailure(t *testing.T, goldenPath, layer string, errs []triage.FieldError, g *triage.Golden, prompt, rawResp string, cost float64, latencyMS int64) {
	t.Helper()
	summary := make([]map[string]string, len(g.Incident.Alerts))
	for i, a := range g.Incident.Alerts {
		summary[i] = map[string]string{"id": a.ID, "alertname": a.Labels["alertname"]}
	}
	art := &triage.FailureArtifact{
		GoldenPath:            goldenPath,
		Layer:                 layer,
		Errors:                errs,
		JudgePrompt:           prompt,
		JudgeRawResponse:      rawResp,
		RenderedFinding:       string(g.RenderedFinding),
		IncidentAlertsSummary: summary,
		CostUSD:               cost,
		LatencyMS:             latencyMS,
	}
	if err := triage.WriteFailureArtifact(goldenPath, art); err != nil {
		t.Logf("write failure artifact: %v", err)
	}
}
