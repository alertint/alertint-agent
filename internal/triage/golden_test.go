// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/triage"
)

func TestPackageCompiles(t *testing.T) {}

func TestGoldenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "g.json")
	in := &triage.Golden{
		SchemaVersion: 1,
		ID:            "storm-collapse",
		CapturedAt:    time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC),
		ScenarioPath:  "scenarios/storm-collapse.yaml",
	}
	if err := triage.SaveGolden(path, in); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}
	out, err := triage.LoadGolden(path)
	if err != nil {
		t.Fatalf("LoadGolden: %v", err)
	}
	if out.ID != in.ID || !out.CapturedAt.Equal(in.CapturedAt) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", in, out)
	}
	if out.SchemaVersion != triage.SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", out.SchemaVersion, triage.SchemaVersion)
	}
}
