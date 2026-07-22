// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alertint/alertint-agent/internal/triage"
)

func TestWriteFailureArtifact(t *testing.T) {
	dir := t.TempDir()
	goldenPath := filepath.Join(dir, "storm-collapse.json")
	art := &triage.FailureArtifact{
		GoldenPath: goldenPath,
		Layer:      "schema",
		Errors: []triage.FieldError{
			{Field: "rendered_finding.severity", Got: "Page", Want: "low|medium|high"},
		},
		RenderedFinding: `{"severity":"Page"}`,
	}
	if err := triage.WriteFailureArtifact(goldenPath, art); err != nil {
		t.Fatalf("WriteFailureArtifact: %v", err)
	}
	written := filepath.Join(dir, ".last-failures", "storm-collapse.json")
	b, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read written artifact: %v", err)
	}
	var got triage.FailureArtifact
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("parse written artifact: %v", err)
	}
	if got.Layer != "schema" || len(got.Errors) != 1 {
		t.Fatalf("artifact mismatch: %+v", got)
	}
}
