// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestRequestObserverSeesRetriesBeforeBudgetRejection(t *testing.T) {
	for _, provider := range []string{"anthropic", "openai"} {
		t.Run(provider, func(t *testing.T) {
			st, err := store.Open(context.Background(), ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
			defer server.Close()
			budget := llm.NewBudget(st, llm.BudgetLimits{CallsPerHour: 2})
			var client interface {
				Complete(ctx context.Context, system string, prompt llm.Prompt, keys []string) (llm.Completion, error)
			}
			if provider == "anthropic" {
				client = anthropic.NewWithHTTPClient(anthropic.Config{Budget: budget, BaseRetryDelay: time.Millisecond}, nil, nil, server.URL)
			} else {
				client = openaicompat.New(openaicompat.Config{BaseURL: server.URL, Budget: budget, BaseRetryDelay: time.Millisecond}, nil, nil)
			}
			var observed []llm.RequestStartStatus
			ctx := llm.WithRequestObserver(context.Background(), func(_ llm.Completion, err error) { observed = append(observed, llm.ClassifyRequestStart(err)) })
			_, err = client.Complete(ctx, "system", llm.Prompt{Prefix: "test"}, nil)
			if !errors.Is(err, llm.ErrBudgetExhausted) {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(observed)
			if string(raw) != `["true","true","false"]` {
				t.Fatalf("request observations=%s", raw)
			}
		})
	}
}
