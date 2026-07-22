// SPDX-License-Identifier: FSL-1.1-ALv2

// Package triage implements the eval harness for the acute-triage skill.
//
// The harness runs three layers against drill-captured golden traces:
//  1. Schema gate (deterministic, no API key).
//  2. Determinism replay (re-invokes the skill with scripted LLM responses).
//  3. LLM-as-judge (Haiku call, structured verdict; skipped when
//     ANTHROPIC_API_KEY is absent).
//
// Goldens are committed JSON; failures write to .last-failures/ (gitignored).
package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion is the on-disk golden format version. Bump on breaking changes.
const SchemaVersion = 1

// Golden is one captured triage trace. See the spec for the full shape.
type Golden struct {
	SchemaVersion   int                  `json:"schema_version"`
	ID              string               `json:"id"`
	CapturedAt      time.Time            `json:"captured_at"`
	ScenarioPath    string               `json:"scenario_path"`
	Incident        IncidentSnapshot     `json:"incident"`
	RenderedFinding json.RawMessage      `json:"rendered_finding"`
	Verification    VerificationSnapshot `json:"verification"`
	ModelUsage      ModelUsage           `json:"model_usage"`
	ConfigSnapshot  ConfigSnapshot       `json:"config_snapshot"`
	Judge           JudgeMeta            `json:"judge"`
}

// IncidentSnapshot is the incident context captured at golden time.
type IncidentSnapshot struct {
	ID           string            `json:"id"`
	GroupKey     string            `json:"group_key"`
	AlertCount   int               `json:"alert_count"`
	SharedLabels map[string]string `json:"shared_labels"`
	Alerts       []AlertSnapshot   `json:"alerts"`
}

// AlertSnapshot is one member alert at golden time.
type AlertSnapshot struct {
	ID          string            `json:"id"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"starts_at"`
}

// VerificationSnapshot is the verification-round outcome at golden time.
type VerificationSnapshot struct {
	Outcome         string `json:"outcome"` // supported | revised | degraded
	QueriesExecuted int    `json:"queries_executed"`
	QueriesFailed   int    `json:"queries_failed"`
}

// ModelUsage is the LLM call's token + cost record.
type ModelUsage struct {
	Model       string  `json:"model"`
	InputTokens int     `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	LatencyMS   int64   `json:"latency_ms"`
	CostUSD     float64 `json:"cost_usd"`
	PromptHash  string  `json:"prompt_hash"`
}

// ConfigSnapshot is the identity of the components that produced the finding.
// Asserted on replay; drift fails loud.
type ConfigSnapshot struct {
	Model               string             `json:"model"`
	MaxTokens           int                `json:"max_tokens"`
	SystemPromptHash    string             `json:"system_prompt_hash"`
	TriageMinAlerts     int                `json:"triage_min_alerts"`
	VerificationEnabled bool               `json:"verification_enabled"`
	ClassifierMode      string             `json:"classifier_mode"`
	SlackMinSeverity    string             `json:"slack_min_severity"`
	RulePacks           []RulePackIdentity `json:"rule_packs"`
}

// RulePackIdentity is one loaded rule pack's identity.
type RulePackIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Hash    string `json:"hash"` // sha256 of pack.yaml
}

// JudgeMeta is metadata about the judge (not the judge call itself).
type JudgeMeta struct {
	Model            string `json:"model"`
	PromptVersion    string `json:"prompt_version"`
	SystemPromptPath string `json:"system_prompt_path"`
}

// LoadGolden reads and parses a golden JSON file.
func LoadGolden(path string) (*Golden, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/QA harness reads caller-chosen paths by design
	if err != nil {
		return nil, fmt.Errorf("triage: read golden %s: %w", path, err)
	}
	var g Golden
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("triage: parse golden %s: %w", path, err)
	}
	return &g, nil
}

// SaveGolden writes a golden JSON file atomically (write to .tmp, rename).
func SaveGolden(path string, g *Golden) error {
	if g.SchemaVersion == 0 {
		g.SchemaVersion = SchemaVersion
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("triage: marshal golden: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("triage: write tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("triage: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// GoldenDir returns the directory containing a golden's path, useful for
// locating sibling .last-failures/ directories.
func GoldenDir(path string) string {
	return filepath.Dir(path)
}
