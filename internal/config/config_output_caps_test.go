// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestLLMOutputCapsConfig(t *testing.T) {
	if got := Defaults().LLM.OutputCaps; got != nil {
		t.Fatalf("output_caps must default to none (every built-in cap kept), got %v", got)
	}
	for _, tc := range []struct{ name, yaml, want string }{
		{"override and off", "assessment: 0\n    semantic_profile: 1200", ""},
		{"unknown kind", "assesment: 0", `llm.output_caps: unknown call kind "assesment"`},
		{"negative", "assessment: -1", "llm.output_caps.assessment (-1) must be >= 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(minimalValidYAML, "llm:\n", "llm:\n  output_caps:\n    "+tc.yaml+"\n", 1)
			cfg, err := Load(writeConfig(t, body))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Load = %v, want %s", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v, ok := cfg.LLM.OutputCaps[llm.CallAssessment]; !ok || v != 0 {
				t.Fatalf("assessment cap = (%d, %v), want an explicit 0 (cap off)", v, ok)
			}
			if got := cfg.LLM.OutputCaps[llm.CallSemanticProfile]; got != 1200 {
				t.Fatalf("semantic_profile cap = %d, want 1200", got)
			}
			if _, ok := cfg.LLM.OutputCaps[llm.CallVerificationRepair]; ok {
				t.Fatal("an unset kind must stay absent so its built-in cap applies")
			}
		})
	}
}
