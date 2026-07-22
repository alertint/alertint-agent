// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ConfigDriftGate checks whether the golden's ConfigSnapshot matches the
// current build's configuration. Drift fails loud so reviewers know the
// golden needs regeneration. Returns nil when the snapshot matches.
func ConfigDriftGate(goldenPath string, current ConfigSnapshot) []FieldError {
	g, err := LoadGolden(goldenPath)
	if err != nil {
		return []FieldError{{Field: "golden", Got: err.Error(), Want: "loadable golden"}}
	}
	want := g.ConfigSnapshot

	var errs []FieldError
	if want.Model != current.Model {
		errs = append(errs, FieldError{
			Field: "config_snapshot.model",
			Got:   current.Model,
			Want:  want.Model,
		})
	}
	if want.MaxTokens != current.MaxTokens {
		errs = append(errs, FieldError{
			Field: "config_snapshot.max_tokens",
			Got:   fmt.Sprintf("%d", current.MaxTokens),
			Want:  fmt.Sprintf("%d", want.MaxTokens),
		})
	}
	if want.TriageMinAlerts != current.TriageMinAlerts {
		errs = append(errs, FieldError{
			Field: "config_snapshot.triage_min_alerts",
			Got:   fmt.Sprintf("%d", current.TriageMinAlerts),
			Want:  fmt.Sprintf("%d", want.TriageMinAlerts),
		})
	}
	if want.VerificationEnabled != current.VerificationEnabled {
		errs = append(errs, FieldError{
			Field: "config_snapshot.verification_enabled",
			Got:   fmt.Sprintf("%t", current.VerificationEnabled),
			Want:  fmt.Sprintf("%t", want.VerificationEnabled),
		})
	}
	if want.ClassifierMode != current.ClassifierMode {
		errs = append(errs, FieldError{
			Field: "config_snapshot.classifier_mode",
			Got:   current.ClassifierMode,
			Want:  want.ClassifierMode,
		})
	}
	if want.SlackMinSeverity != current.SlackMinSeverity {
		errs = append(errs, FieldError{
			Field: "config_snapshot.slack_min_severity",
			Got:   current.SlackMinSeverity,
			Want:  want.SlackMinSeverity,
		})
	}
	// Rule packs: compare by name+version (hash is optional).
	if !samePackSet(want.RulePacks, current.RulePacks) {
		errs = append(errs, FieldError{
			Field: "config_snapshot.rule_packs",
			Got:   packSummary(current.RulePacks),
			Want:  packSummary(want.RulePacks),
		})
	}
	return errs
}

func samePackSet(a, b []RulePackIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]string, len(a))
	bs := make([]string, len(b))
	for i, p := range a {
		as[i] = p.Name + "@" + p.Version
	}
	for i, p := range b {
		bs[i] = p.Name + "@" + p.Version
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func packSummary(packs []RulePackIdentity) string {
	parts := make([]string, len(packs))
	for i, p := range packs {
		parts[i] = p.Name + "@" + p.Version
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// HashPackFile computes a sha256 hash of a pack.yaml file for the
// ConfigSnapshot.RulePacks[].Hash field.
func HashPackFile(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/QA harness reads caller-chosen paths by design
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// HashSystemPrompt computes a sha256 hash of the system prompt string.
func HashSystemPrompt(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// GoldenPath returns the canonical path for a golden given its ID.
func GoldenPath(goldenDir, id string) string {
	return filepath.Join(goldenDir, id+".json")
}
