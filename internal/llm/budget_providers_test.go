// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/internal/store"
)

type budgetProvider interface {
	Complete(ctx context.Context, system string, prompt llm.Prompt, requiredKeys []string) (llm.Completion, error)
	CompleteOnce(ctx context.Context, system string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error)
}

func TestBudgetProviderRetriesAndOneShotShareCeiling(t *testing.T) {
	for _, name := range []string{"anthropic", "openai"} {
		t.Run(name, func(t *testing.T) {
			st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer srv.Close()
			b := llm.NewBudget(st, llm.BudgetLimits{CallsPerHour: 2})
			var client budgetProvider
			if name == "anthropic" {
				client = anthropic.NewWithHTTPClient(anthropic.Config{Budget: b, BaseRetryDelay: time.Millisecond}, nil, nil, srv.URL)
			} else {
				client = openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Budget: b, BaseRetryDelay: time.Millisecond}, nil, nil)
			}
			if _, err := client.Complete(context.Background(), "sys", llm.Prompt{Prefix: "test"}, nil); !errors.Is(err, llm.ErrBudgetExhausted) {
				t.Fatalf("Complete = %v, want budget error on third HTTP attempt", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("HTTP attempts = %d, want 2", calls.Load())
			}
			comp, err := client.CompleteOnce(context.Background(), "sys", llm.Prompt{Prefix: "test"}, nil)
			if !errors.Is(err, llm.ErrBudgetExhausted) || comp.RequestStarted != llm.RequestStartStatusFalse {
				t.Fatalf("CompleteOnce = %+v, %v; want exhausted, request not started", comp, err)
			}
			if calls.Load() != 2 {
				t.Fatalf("one-shot bypassed budget: %d HTTP attempts", calls.Load())
			}
		})
	}
}
