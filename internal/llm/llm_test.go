// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestPromptText(t *testing.T) {
	p := llm.Prompt{Prefix: "evidence", Suffix: " + continuation"}
	if got := p.Text(); got != "evidence + continuation" {
		t.Fatalf("Text() = %q", got)
	}
}

func TestValidateKeys(t *testing.T) {
	raw := json.RawMessage(`{"a":1,"b":2}`)
	if err := llm.ValidateKeys(raw, []string{"a", "b"}); err != nil {
		t.Fatalf("all keys present: %v", err)
	}
	err := llm.ValidateKeys(raw, []string{"a", "missing"})
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Fatalf("want ErrSchemaViolation, got %v", err)
	}
	if err := llm.ValidateKeys(json.RawMessage(`[1,2]`), []string{"a"}); !errors.Is(err, llm.ErrSchemaViolation) {
		t.Fatalf("non-object must be a schema violation, got %v", err)
	}
	if err := llm.ValidateKeys(raw, nil); err != nil {
		t.Fatalf("no required keys must pass: %v", err)
	}
}

func TestStripMarkdownFence(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":1}\n```": `{"a":1}`,
		"```\n{\"a\":1}\n```":     `{"a":1}`,
		`{"a":1}`:                 `{"a":1}`,
		"  {\"a\":1}  ":           `{"a":1}`,
	}
	for in, want := range cases {
		if got := llm.StripMarkdownFence(in); got != want {
			t.Errorf("StripMarkdownFence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPromptHashStable(t *testing.T) {
	a := llm.PromptHash("sys", "user")
	b := llm.PromptHash("sys", "user")
	if a != b || len(a) != 64 {
		t.Fatalf("hash unstable or wrong length: %q vs %q", a, b)
	}
	if llm.PromptHash("sysu", "ser") == a {
		t.Fatal("separator must prevent boundary collisions")
	}
}

func TestPromptOutputTokenLimit(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		perCall    int
		want       int
	}{
		{"unset keeps configured", 1024, 0, 1024},
		{"lower explicit cap wins", 1024, 512, 512},
		{"explicit cap cannot raise configured", 256, 512, 256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := llm.Prompt{MaxOutputTokens: tc.perCall}
			if got := p.OutputTokenLimit(tc.configured); got != tc.want {
				t.Fatalf("OutputTokenLimit(%d) = %d, want %d", tc.configured, got, tc.want)
			}
		})
	}
}

func TestPromptOutputLimit(t *testing.T) {
	tests := []struct {
		name        string
		configured  int
		builtin     int
		kind        llm.CallKind
		caps        llm.OutputCaps
		want        int
		wantPerCall bool
	}{
		{"no caps keeps the built-in cap", 4096, 800, llm.CallAssessment, nil, 800, true},
		{"unset everything keeps configured", 4096, 0, "", nil, 4096, false},
		{"override replaces the built-in cap", 4096, 800, llm.CallAssessment, llm.OutputCaps{llm.CallAssessment: 300}, 300, true},
		{"zero turns the cap off", 4096, 800, llm.CallAssessment, llm.OutputCaps{llm.CallAssessment: 0}, 4096, false},
		{"override cannot raise configured", 1024, 800, llm.CallAssessment, llm.OutputCaps{llm.CallAssessment: 9000}, 1024, false},
		{"other kinds are untouched", 4096, 800, llm.CallAssessment, llm.OutputCaps{llm.CallSemanticProfile: 0}, 800, true},
		{"a call without a kind ignores caps", 4096, 512, "", llm.OutputCaps{llm.CallAssessment: 0}, 512, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := llm.Prompt{MaxOutputTokens: tc.builtin, Kind: tc.kind}
			got, perCall := p.OutputLimit(tc.configured, tc.caps)
			if got != tc.want || perCall != tc.wantPerCall {
				t.Fatalf("OutputLimit(%d) = (%d, %v), want (%d, %v)", tc.configured, got, perCall, tc.want, tc.wantPerCall)
			}
		})
	}
}

func TestPromptTruncationHint(t *testing.T) {
	tests := []struct {
		name    string
		prompt  llm.Prompt
		perCall bool
		want    string
	}{
		{"configured ceiling points at llm.max_tokens", llm.Prompt{}, false, "raise llm.max_tokens"},
		{"a lifted per-call cap points at llm.max_tokens", llm.Prompt{Kind: llm.CallAssessment}, false, "raise llm.max_tokens"},
		{"a fixed per-call cap names itself", llm.Prompt{MaxOutputTokens: 128}, true, "per-call max_output_tokens"},
		{"a tunable per-call cap names its key", llm.Prompt{MaxOutputTokens: 800, Kind: llm.CallAssessment}, true,
			"per-call max_output_tokens; raise or zero llm.output_caps.assessment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.prompt.TruncationHint(tc.perCall); got != tc.want {
				t.Fatalf("TruncationHint(%v) = %q, want %q", tc.perCall, got, tc.want)
			}
		})
	}
}
