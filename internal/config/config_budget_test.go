// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestLLMBudgetConfig(t *testing.T) {
	defaults := Defaults()
	if defaults.LLM.Budget.CallsPerHour != 0 || defaults.LLM.Budget.TotalTokens != 0 {
		t.Fatal("budget must default to unlimited")
	}
	for _, tc := range []struct{ name, yaml, want string }{
		{"finite", "calls_per_hour: 30\n    total_tokens: 100000", ""},
		{"negative calls", "calls_per_hour: -1", "llm.budget.calls_per_hour"},
		{"negative tokens", "total_tokens: -1", "llm.budget.total_tokens"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(minimalValidYAML, "llm:\n", "llm:\n  budget:\n    "+tc.yaml+"\n", 1)
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
			if cfg.LLM.Budget.CallsPerHour != 30 || cfg.LLM.Budget.TotalTokens != 100000 {
				t.Fatalf("budget = %+v", cfg.LLM.Budget)
			}
		})
	}
}
