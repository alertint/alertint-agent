// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	llmanthropic "github.com/alertint/alertint-agent/internal/llm/anthropic"
	llmopenai "github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// TestBuildLLMClient_ProviderSelectsConcreteType pins the provider switch:
// anthropic and openai-compatible each construct their own client type, never
// the other's — a swapped condition here would silently point every triage
// call at the wrong provider.
func TestBuildLLMClient_ProviderSelectsConcreteType(t *testing.T) {
	anthropicCfg := config.Defaults()
	anthropicCfg.LLM.Provider = "anthropic"
	if _, ok := buildLLMClient(&anthropicCfg, "key", nil, slog.Default()).(*llmanthropic.Client); !ok {
		t.Errorf("provider=anthropic must build *llmanthropic.Client, got %T", buildLLMClient(&anthropicCfg, "key", nil, slog.Default()))
	}

	openaiCfg := config.Defaults()
	openaiCfg.LLM.Provider = "openai-compatible"
	openaiCfg.LLM.BaseURL = "http://localhost:30000"
	if _, ok := buildLLMClient(&openaiCfg, "", nil, slog.Default()).(*llmopenai.Client); !ok {
		t.Errorf("provider=openai-compatible must build *llmopenai.Client, got %T", buildLLMClient(&openaiCfg, "", nil, slog.Default()))
	}
}

// TestBuildClassifierClient_OpenAICompatibleReusesLLMModel pins the exact
// regression this branch exists to prevent (see buildClassifierClient's own
// comment): on openai-compatible, the classifier must request cfg.LLM.Model,
// never the hardcoded Anthropic Haiku constant — a single-model local
// endpoint would 404 every classifier call otherwise, silently poisoning the
// ADR-0018 graduation evidence with fail-open "unsure" verdicts.
func TestBuildClassifierClient_OpenAICompatibleReusesLLMModel(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel, _ = body["model"].(string)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"matched\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.BaseURL = srv.URL
	cfg.LLM.Model = "qwen3-32b"
	cfg.Memory.Classifier.Mode = config.ClassifierModeShadow
	cfg.Memory.Classifier.TimeoutSeconds = 5

	client := buildClassifierClient(&cfg, "", nil, slog.Default())
	if client == nil {
		t.Fatal("buildClassifierClient must return a client when the classifier is enabled")
	}
	if _, err := client.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, []string{"verdict"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotModel != "qwen3-32b" {
		t.Errorf("classifier requested model = %q, want cfg.LLM.Model %q (not the hardcoded Haiku constant %q)",
			gotModel, cfg.LLM.Model, acutetriage.ClassifierModel)
	}
}

// TestBuildClassifierClient_DisabledReturnsNil confirms the classifier stays
// off (a true nil interface, no client constructed) regardless of provider
// when memory.classifier.mode is off — the default.
func TestBuildClassifierClient_DisabledReturnsNil(t *testing.T) {
	cfg := config.Defaults()
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.BaseURL = "http://localhost:30000"
	if client := buildClassifierClient(&cfg, "", nil, slog.Default()); client != nil {
		t.Errorf("classifier disabled (mode=off): want nil client, got %v", client)
	}
}

// TestLLMProviderIsOpenAI_CaseInsensitive matches config validation's own
// case-insensitive provider comparison.
func TestLLMProviderIsOpenAI_CaseInsensitive(t *testing.T) {
	cfg := config.Defaults()
	cfg.LLM.Provider = "OpenAI-Compatible"
	if !llmProviderIsOpenAI(&cfg) {
		t.Error("llmProviderIsOpenAI must be case-insensitive")
	}
	cfg.LLM.Provider = "anthropic"
	if llmProviderIsOpenAI(&cfg) {
		t.Error("anthropic must not be treated as openai-compatible")
	}
}
