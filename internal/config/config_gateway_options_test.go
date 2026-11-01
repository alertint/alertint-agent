// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

const gatewayLLMYAML = `
alertmanager:
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
llm:
  provider: openai-compatible
  base_url: https://openrouter.ai/api
`

func TestLLMGatewayOptionsConfig(t *testing.T) {
	cfg := Defaults()
	if cfg.LLM.Reasoning != nil || cfg.LLM.Routing != nil {
		t.Fatal("reasoning and routing must default to unset (nothing extra is sent)")
	}

	t.Run("valid", func(t *testing.T) {
		body := gatewayLLMYAML + "  reasoning:\n    effort: none\n  routing:\n    only: [deepinfra]\n    allow_fallbacks: false\n    quantizations: [bf16]\n"
		cfg, err := loadFrom(strings.NewReader(body), "", true)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.LLM.Reasoning == nil || cfg.LLM.Reasoning.Effort != "none" {
			t.Fatalf("reasoning = %+v", cfg.LLM.Reasoning)
		}
		r := cfg.LLM.Routing
		if r == nil || len(r.Only) != 1 || r.Only[0] != "deepinfra" || r.AllowFallbacks == nil || *r.AllowFallbacks {
			t.Fatalf("routing = %+v", r)
		}
	})

	t.Run("explicit disable is kept", func(t *testing.T) {
		cfg, err := loadFrom(strings.NewReader(gatewayLLMYAML+"  reasoning:\n    enabled: false\n"), "", true)
		if err != nil {
			t.Fatal(err)
		}
		if e := cfg.LLM.Reasoning.Enabled; e == nil || *e {
			t.Fatalf("enabled = %v, want an explicit false", e)
		}
	})

	for _, tc := range []struct{ name, extra, want string }{
		{"effort and max_tokens", "  reasoning:\n    effort: low\n    max_tokens: 400\n", "llm.reasoning.effort and llm.reasoning.max_tokens are mutually exclusive"},
		{"negative max_tokens", "  reasoning:\n    max_tokens: -1\n", "llm.reasoning.max_tokens (-1) must be >= 0"},
		{"empty reasoning", "  reasoning: {}\n", "llm.reasoning is empty"},
		{"empty routing", "  routing: {}\n", "llm.routing is empty"},
		{"blank provider slug", "  routing:\n    only: [\"\"]\n", "llm.routing.only[0] is empty"},
		{"misspelled key", "  reasoning:\n    efort: low\n", "efort"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFrom(strings.NewReader(gatewayLLMYAML+tc.extra), "", true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load = %v, want error containing %q", err, tc.want)
			}
		})
	}

	for _, tc := range []struct{ name, extra, want string }{
		{"reasoning", "  reasoning:\n    effort: low\n", `llm.reasoning is only valid for provider "openai-compatible"`},
		{"routing", "  routing:\n    only: [deepinfra]\n", `llm.routing is only valid for provider "openai-compatible"`},
	} {
		t.Run("anthropic rejects "+tc.name, func(t *testing.T) {
			body := strings.Replace(minimalValidYAML, "llm:\n", "llm:\n"+tc.extra, 1)
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
