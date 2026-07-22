// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FailureArtifact is the structured failure record written to
// .last-failures/<stem>.json. The directory is gitignored; CI uploads it as
// an artifact so reviewers see the full detail without re-running.
type FailureArtifact struct {
	GoldenPath            string              `json:"golden_path"`
	Layer                 string              `json:"layer"`
	Errors                []FieldError        `json:"errors"`
	JudgePrompt           string              `json:"judge_prompt,omitempty"`
	JudgeRawResponse      string              `json:"judge_raw_response,omitempty"`
	RenderedFinding       string              `json:"rendered_finding"`
	IncidentAlertsSummary []map[string]string `json:"incident_alerts_summary"`
	Verdict               string              `json:"verdict,omitempty"`
	ExpectedVerdict       string              `json:"expected_verdict,omitempty"`
	CostUSD               float64             `json:"cost_usd,omitempty"`
	LatencyMS             int64               `json:"latency_ms,omitempty"`
}

// WriteFailureArtifact writes the artifact to
// <goldenDir>/.last-failures/<stem>.json. The directory is created if absent.
func WriteFailureArtifact(goldenPath string, art *FailureArtifact) error {
	dir := filepath.Join(filepath.Dir(goldenPath), ".last-failures")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("triage: mkdir %s: %w", dir, err)
	}
	stem := filepath.Base(goldenPath)
	out := filepath.Join(dir, stem)
	b, err := json.MarshalIndent(art, "", "  ")
	if err != nil {
		return fmt.Errorf("triage: marshal artifact: %w", err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return fmt.Errorf("triage: write artifact %s: %w", out, err)
	}
	return nil
}
