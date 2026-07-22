// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/triage"
)

func TestConfigDriftGate_Match(t *testing.T) {
	dir := t.TempDir()
	goldenPath := filepath.Join(dir, "test.json")
	snap := triage.ConfigSnapshot{
		Model: "claude-sonnet-4-6", MaxTokens: 4096, TriageMinAlerts: 1,
		VerificationEnabled: true, ClassifierMode: "off", SlackMinSeverity: "low",
		RulePacks: []triage.RulePackIdentity{{Name: "baseline", Version: "0.1.0"}},
	}
	g := &triage.Golden{
		SchemaVersion: triage.SchemaVersion, ID: "test",
		CapturedAt: time.Now().UTC(), ScenarioPath: "x",
		ConfigSnapshot: snap,
	}
	if err := triage.SaveGolden(goldenPath, g); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}
	if errs := triage.ConfigDriftGate(goldenPath, snap); len(errs) > 0 {
		t.Fatalf("expected no drift, got: %+v", errs)
	}
}

func TestConfigDriftGate_ModelChanged(t *testing.T) {
	dir := t.TempDir()
	goldenPath := filepath.Join(dir, "test.json")
	snap := triage.ConfigSnapshot{Model: "claude-sonnet-4-6", MaxTokens: 4096}
	g := &triage.Golden{
		SchemaVersion: triage.SchemaVersion, ID: "test",
		CapturedAt: time.Now().UTC(), ScenarioPath: "x",
		ConfigSnapshot: snap,
	}
	if err := triage.SaveGolden(goldenPath, g); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}
	current := snap
	current.Model = "claude-sonnet-4-7"
	errs := triage.ConfigDriftGate(goldenPath, current)
	if len(errs) == 0 {
		t.Fatal("expected drift error for model change")
	}
}
