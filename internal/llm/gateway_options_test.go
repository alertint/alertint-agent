// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"encoding/json"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func boolPtr(b bool) *bool { return &b }

// TestReasoningJSONShape pins the wire shape of the gateway `reasoning` object:
// only what is set is sent, and an explicit enabled: false survives omitempty.
func TestReasoningJSONShape(t *testing.T) {
	tests := []struct {
		name string
		in   llm.Reasoning
		want string
	}{
		{"effort only", llm.Reasoning{Effort: "none"}, `{"effort":"none"}`},
		{"explicit disable is kept", llm.Reasoning{Enabled: boolPtr(false)}, `{"enabled":false}`},
		{"budget and exclude", llm.Reasoning{MaxTokens: 400, Exclude: true}, `{"max_tokens":400,"exclude":true}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("json = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestRoutingJSONShape pins the wire shape of the gateway `provider` object.
func TestRoutingJSONShape(t *testing.T) {
	in := llm.Routing{Only: []string{"deepinfra"}, AllowFallbacks: boolPtr(false), Quantizations: []string{"bf16"}}
	got, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"only":["deepinfra"],"allow_fallbacks":false,"quantizations":["bf16"]}`
	if string(got) != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

func TestGatewayOptionsIsZero(t *testing.T) {
	if !(llm.Reasoning{}).IsZero() || !(llm.Routing{}).IsZero() {
		t.Fatal("empty options must be zero")
	}
	for name, zero := range map[string]bool{
		"reasoning enabled":  llm.Reasoning{Enabled: boolPtr(false)}.IsZero(),
		"reasoning effort":   llm.Reasoning{Effort: "low"}.IsZero(),
		"reasoning budget":   llm.Reasoning{MaxTokens: 1}.IsZero(),
		"reasoning exclude":  llm.Reasoning{Exclude: true}.IsZero(),
		"routing order":      llm.Routing{Order: []string{"a"}}.IsZero(),
		"routing only":       llm.Routing{Only: []string{"a"}}.IsZero(),
		"routing ignore":     llm.Routing{Ignore: []string{"a"}}.IsZero(),
		"routing fallbacks":  llm.Routing{AllowFallbacks: boolPtr(true)}.IsZero(),
		"routing quantizing": llm.Routing{Quantizations: []string{"fp8"}}.IsZero(),
	} {
		if zero {
			t.Errorf("%s: a set field must not read as zero", name)
		}
	}
}
