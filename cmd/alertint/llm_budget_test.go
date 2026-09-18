// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestLLMBudgetSharedByPrimaryAndClassifier(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{}"}}],"usage":{"prompt_tokens":2,"completion_tokens":2}}`)
	}))
	defer srv.Close()
	cfg := config.Defaults()
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.BaseURL = srv.URL
	cfg.LLM.Budget = llm.BudgetLimits{CallsPerHour: 1, TotalTokens: 10000}
	cfg.Memory.Classifier.Mode = config.ClassifierModeShadow
	b := llm.NewBudget(st, cfg.LLM.Budget)
	primary := buildLLMClient(&cfg, "", nil, slog.Default(), b)
	classifier := buildClassifierClient(&cfg, "", nil, slog.Default(), b)
	if _, err := primary.Complete(context.Background(), "sys", llm.Prompt{Prefix: "triage"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := classifier.Complete(context.Background(), "sys", llm.Prompt{Prefix: "classify"}, nil); !errors.Is(err, llm.ErrBudgetExhausted) {
		t.Fatalf("classifier = %v, want shared budget exhausted", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d", calls.Load())
	}
}

func TestLLMBudgetFiniteConfigWithoutStoreFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.LLM.Budget.CallsPerHour = 1
	for _, provider := range []string{"anthropic", "openai-compatible"} {
		cfg.LLM.Provider = provider
		cfg.LLM.BaseURL = "http://provider.invalid"
		client := buildLLMClient(&cfg, "test", nil, slog.Default())
		_, err := client.Complete(context.Background(), "sys", llm.Prompt{Prefix: "test"}, nil)
		if !errors.Is(err, llm.ErrRequestNotSent) {
			t.Fatalf("%s: missing store = %v, want no dispatch", provider, err)
		}
	}
}
