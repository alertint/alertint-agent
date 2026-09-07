// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

type budgetRoundTrip func(*http.Request) (*http.Response, error)

func (f budgetRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func budgetRequest(t *testing.T, transport http.RoundTripper) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://provider.invalid/v1/messages", strings.NewReader(`{"max_tokens":10,"system":"sys","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestBudgetCallsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "budget.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":3,"output_tokens":2}}`)), Header: make(http.Header)}, nil
	})
	b := llm.NewBudget(st, llm.BudgetLimits{CallsPerHour: 1})
	if err := budgetRequest(t, b.Transport(provider)); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	b = llm.NewBudget(st, llm.BudgetLimits{CallsPerHour: 1})
	if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrBudgetExhausted) || !errors.Is(err, llm.ErrRequestNotSent) {
		t.Fatalf("second call after restart = %v, want budget exhausted before dispatch", err)
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
}

func TestBudgetTokensIncludeCacheCreationAndRead(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	calls := 0
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":1,"output_tokens":1,"cache_creation_input_tokens":1000,"cache_read_input_tokens":1000}}`)), Header: make(http.Header)}, nil
	})
	b := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 3000})
	if err := budgetRequest(t, b.Transport(provider)); err != nil {
		t.Fatal(err)
	}
	if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrBudgetExhausted) {
		t.Fatalf("next call = %v, want cache tokens charged", err)
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
}

func TestBudgetProviderOverrunIsNotSuccess(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	b := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 3000})
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":4000,"output_tokens":2}}`)), Header: make(http.Header)}, nil
	})
	if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrBudgetExhausted) {
		t.Fatalf("provider overrun = %v, want explicit budget error", err)
	}
	if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrRequestNotSent) {
		t.Fatalf("subsequent dispatch = %v, want blocked", err)
	}
}

func TestBudgetConcurrentReservationsAcrossStoreHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	a, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	var calls atomic.Int32
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":3,"output_tokens":2}}`))}, nil
	})
	transports := []http.RoundTripper{
		llm.NewBudget(a, llm.BudgetLimits{CallsPerHour: 5}).Transport(provider),
		llm.NewBudget(b, llm.BudgetLimits{CallsPerHour: 5}).Transport(provider),
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := budgetRequest(t, transports[i%2]); err != nil && !errors.Is(err, llm.ErrBudgetExhausted) {
				t.Errorf("reservation: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 5 {
		t.Fatalf("concurrent provider calls = %d, want 5", calls.Load())
	}
}

func TestBudgetUnknownUsageRemainsBlockedAfterRestart(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		err        error
	}{
		{"missing", `{}`, 200, nil},
		{"partial", `{"usage":{"input_tokens":5}}`, 200, nil},
		{"negative", `{"usage":{"input_tokens":-1,"output_tokens":2}}`, 200, nil},
		{"null", `{"usage":{"input_tokens":null,"output_tokens":2}}`, 200, nil},
		{"malformed", `{`, 200, nil},
		{"oversized", `{"usage":{"input_tokens":1,"output_tokens":1}}` + strings.Repeat(" ", 512*1024), 200, nil},
		{"overflow", `{"usage":{"input_tokens":9223372036854775807,"output_tokens":2}}`, 200, nil},
		{"zero", `{"usage":{"input_tokens":0,"output_tokens":0}}`, 200, nil},
		{"rate limit", `{}`, 429, nil},
		{"timeout", "", 0, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "budget.db")
			st, err := store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			b := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000})
			if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrBudgetUsageUnknown) {
				t.Fatalf("unknown usage = %v", err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			b = llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 20000})
			if err := budgetRequest(t, b.Transport(provider)); !errors.Is(err, llm.ErrBudgetExhausted) {
				t.Fatalf("restart with raised limit = %v, want unresolved usage blocked", err)
			}
			if calls != 1 {
				t.Fatalf("provider calls = %d, want 1", calls)
			}
		})
	}
}

func TestBudgetUnsettledReservationSurvivesCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	b := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 2000})
	func() {
		defer func() {
			if recover() != "simulated process death" {
				t.Error("expected dispatch to simulate process death")
			}
		}()
		_ = budgetRequest(t, b.Transport(budgetRoundTrip(func(r *http.Request) (*http.Response, error) { panic("simulated process death") })))
	}()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	b = llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 2000})
	err = budgetRequest(t, b.Transport(budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		t.Error("dispatch after unresolved crash")
		return nil, errors.New("unexpected dispatch")
	})))
	if !errors.Is(err, llm.ErrBudgetExhausted) {
		t.Fatalf("restart = %v", err)
	}
}

func TestBudgetConcurrentTokensReserveOnlyRequestAllowance(t *testing.T) {
	for _, limit := range []int64{2000, 3000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "budget.db")
			st, err := store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			other, err := store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.Close() }()
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"prompt_tokens":2,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":2}}}`))}, nil
			})
			transport := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: limit}).Transport(provider)
			done := make(chan error, 1)
			go func() { done <- budgetRequest(t, transport) }()
			<-entered
			err = budgetRequest(t, llm.NewBudget(other, llm.BudgetLimits{TotalTokens: limit}).Transport(provider))
			close(release)
			firstErr := <-done
			if firstErr != nil {
				t.Fatal(firstErr)
			}
			wantCalls := int32(3)
			if limit == 2000 {
				wantCalls = 2
				if !errors.Is(err, llm.ErrBudgetExhausted) {
					t.Fatalf("overcommitted reservation = %v", err)
				}
			} else if err != nil {
				t.Fatalf("ample concurrent budget = %v, want admitted", err)
			}
			if err := budgetRequest(t, transport); err != nil {
				t.Fatalf("after refund: %v", err)
			}
			if calls.Load() != wantCalls {
				t.Fatalf("provider calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}

func TestBudgetPersistenceFailureNeverReturnsSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	b := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 2000})
	calls := 0
	err = budgetRequest(t, b.Transport(budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":1,"output_tokens":1}}`))}, nil
	})))
	if err == nil || !strings.Contains(err.Error(), "settlement failed") || errors.Is(err, llm.ErrRequestNotSent) {
		t.Fatalf("lost settlement = %v", err)
	}
	err = budgetRequest(t, b.Transport(budgetRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected dispatch") })))
	if !errors.Is(err, llm.ErrRequestNotSent) {
		t.Fatalf("closed store = %v", err)
	}
	st, err = store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	b = llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 2000})
	err = budgetRequest(t, b.Transport(budgetRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected dispatch") })))
	if !errors.Is(err, llm.ErrBudgetExhausted) {
		t.Fatalf("lost settlement must retain charge after restart: %v", err)
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
}

func TestBudgetOpenAICacheDetailsAreNotDoubleCounted(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	calls := 0
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"usage":{"prompt_tokens":1600,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":1500},"completion_tokens_details":{"reasoning_tokens":100}}}`
		if calls > 1 {
			body = `{"usage":{"prompt_tokens":1,"completion_tokens":1}}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	transport := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 3000}).Transport(provider)
	if err := budgetRequest(t, transport); err != nil {
		t.Fatal(err)
	}
	if err := budgetRequest(t, transport); err != nil {
		t.Fatalf("cached/reasoning detail tokens were charged twice: %v", err)
	}
}
