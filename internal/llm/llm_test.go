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
