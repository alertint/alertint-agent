// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

type observedBudgetState struct {
	Calls         []time.Time      `json:"calls"`
	Tokens        int64            `json:"tokens"`
	Pending       map[string]int64 `json:"pending"`
	Unknown       bool             `json:"unknown"`
	UnknownReason string           `json:"unknown_reason"`
	UnknownAt     string           `json:"unknown_at"`
}

func readBudgetState(t *testing.T, st *store.Store) observedBudgetState {
	t.Helper()
	var state observedBudgetState
	err := st.UpdateLLMBudget(context.Background(), func(raw []byte) ([]byte, error) {
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		return raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func budgetStatusRequest(t *testing.T, transport http.RoundTripper) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://provider.invalid/v1/messages", strings.NewReader(`{"max_tokens":10}`))
	if err != nil {
		t.Fatal(err)
	}
	return transport.RoundTrip(req)
}

func TestBudgetDeclinedStatusSettlesWithoutLatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantTokens int64
	}{
		{"bad_request", 400, `{}`, 0},
		{"unauthorized", 401, `{"error":{"message":"x"}}`, 0},
		{"not_found", 404, `{}`, 0},
		{"too_large", 413, `{}`, 0},
		{"rate_limit", 429, `{}`, 0},
		{"unavailable", 503, `{}`, 0},
		{"overloaded", 529, `{}`, 0},
		{"rate_limit_with_usage", 429, `{"usage":{"input_tokens":7,"output_tokens":0}}`, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "budget.db")
			st, err := store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			provider := budgetRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				status, body := tc.status, tc.body
				if calls > 1 {
					status, body = 200, `{"usage":{"input_tokens":1,"output_tokens":1}}`
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			resp, err := budgetStatusRequest(t, llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider))
			if err != nil || resp == nil || resp.StatusCode != tc.status {
				t.Fatalf("first response = %v, %v; want status %d", resp, err, tc.status)
			}
			_ = resp.Body.Close()
			state := readBudgetState(t, st)
			if state.Unknown || state.Tokens != tc.wantTokens || len(state.Pending) != 0 || len(state.Calls) != 1 {
				t.Fatalf("settled state = %+v, want unknown=false tokens=%d pending=0 calls=1", state, tc.wantTokens)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			resp, err = budgetStatusRequest(t, llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider))
			if err != nil || resp == nil || resp.StatusCode != http.StatusOK || calls != 2 {
				t.Fatalf("after restart = %v, %v; calls=%d", resp, err, calls)
			}
			_ = resp.Body.Close()
		})
	}
}

func TestBudgetDeclinedStatusStillCountsCalls(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	calls := 0
	provider := budgetRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	transport := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000, CallsPerHour: 1}).Transport(provider)
	resp, err := budgetStatusRequest(t, transport)
	if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first call = %v, %v", resp, err)
	}
	_ = resp.Body.Close()
	resp, err = budgetStatusRequest(t, transport)
	if resp != nil {
		_ = resp.Body.Close()
	}
	var deferred *llm.BudgetDeferredError
	if resp != nil || !errors.As(err, &deferred) || deferred.RetryAt == nil || calls != 1 {
		t.Fatalf("second call = %v, %v; calls=%d", resp, err, calls)
	}
}

func TestBudgetAmbiguousStatusPassesThroughAndLatches(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"500_no_usage", 500, `{}`},
		{"500_with_usage", 500, `{"usage":{"input_tokens":7,"output_tokens":1}}`},
		{"502_no_usage", 502, `{}`},
		{"504_no_usage", 504, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "budget.db")
			st, err := store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			provider := budgetRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			resp, err := budgetStatusRequest(t, llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider))
			if err != nil || resp == nil || resp.StatusCode != tc.status {
				t.Fatalf("response = %v, %v", resp, err)
			}
			_ = resp.Body.Close()
			state := readBudgetState(t, st)
			assertAmbiguousStatusState(t, tc.name, tc.status, state)
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			resp, err = budgetStatusRequest(t, llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 20000}).Transport(provider))
			if resp != nil {
				_ = resp.Body.Close()
			}
			if tc.name == "500_with_usage" {
				if err != nil || resp == nil || resp.StatusCode != tc.status || calls != 2 {
					t.Fatalf("restart = %v, %v; calls=%d, want provider response after restart", resp, err, calls)
				}
				return
			}
			var deferred *llm.BudgetDeferredError
			if resp != nil || !errors.As(err, &deferred) || calls != 1 {
				t.Fatalf("restart = %v, %v; calls=%d", resp, err, calls)
			}
			if tc.status == 502 && (!strings.Contains(deferred.Error(), "http_502") || !strings.Contains(deferred.Error(), state.UnknownAt)) {
				t.Fatalf("deferred error = %q", deferred.Error())
			}
		})
	}
}

func assertAmbiguousStatusState(t *testing.T, name string, status int, state observedBudgetState) {
	t.Helper()
	if name == "500_with_usage" {
		if state.Tokens != 8 || state.Unknown || len(state.Pending) != 0 || state.UnknownReason != "" || state.UnknownAt != "" {
			t.Fatalf("state = %+v; want 8 settled tokens and no latch", state)
		}
		return
	}
	if !state.Unknown || state.Tokens == 0 || len(state.Pending) != 0 || state.UnknownReason != fmt.Sprintf("http_%d", status) {
		t.Fatalf("state = %+v; want status latch", state)
	}
	if status == 502 {
		if _, err := time.Parse(time.RFC3339, state.UnknownAt); err != nil {
			t.Fatalf("unknown_at = %q: %v", state.UnknownAt, err)
		}
	}
}

func TestBudgetUnknownReasonRecordsCause(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		dispatchErr error
		want        string
	}{
		{"no_usage", 200, `{}`, nil, "no_usage"},
		{"usage_overflow", 200, `{"usage":{"input_tokens":9223372036854775807,"output_tokens":2}}`, nil, "usage_overflow"},
		{"usage_field_overflow", 200, `{"usage":{"input_tokens":9223372036854775808,"output_tokens":2}}`, nil, "usage_overflow"},
		{"transport_error", 0, "", context.DeadlineExceeded, "transport_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			provider := budgetRoundTrip(func(*http.Request) (*http.Response, error) {
				if tc.dispatchErr != nil {
					return nil, tc.dispatchErr
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			resp, _ := budgetStatusRequest(t, llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider))
			if resp != nil {
				_ = resp.Body.Close()
			}
			first := readBudgetState(t, st)
			if !first.Unknown || first.UnknownReason != tc.want {
				t.Fatalf("first latch = %+v", first)
			}
			if _, err := time.Parse(time.RFC3339, first.UnknownAt); err != nil {
				t.Fatalf("unknown_at = %q: %v", first.UnknownAt, err)
			}
		})
	}
}

func TestBudgetUnknownReasonFirstCauseWins(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	entered := make(chan int, 2)
	release := []chan struct{}{make(chan struct{}), make(chan struct{})}
	provider := budgetRoundTrip(func(r *http.Request) (*http.Response, error) {
		index := 0
		if r.Header.Get("X-Case") == "second" {
			index = 1
		}
		entered <- index
		<-release[index]
		status := 502
		if index == 1 {
			status = 200
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	transport := llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider)
	call := func(label string, done chan<- error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://provider.invalid", strings.NewReader(`{"max_tokens":10}`))
		if err != nil {
			done <- err
			return
		}
		req.Header.Set("X-Case", label)
		resp, err := transport.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go call("first", firstDone)
	go call("second", secondDone)
	<-entered
	<-entered
	close(release[0])
	if err := <-firstDone; err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := readBudgetState(t, st)
	if first.UnknownReason != "http_502" {
		t.Fatalf("first cause = %+v", first)
	}
	close(release[1])
	if err := <-secondDone; !errors.Is(err, llm.ErrBudgetUsageUnknown) {
		t.Fatalf("second call: %v", err)
	}
	second := readBudgetState(t, st)
	if second.UnknownReason != first.UnknownReason || second.UnknownAt != first.UnknownAt {
		t.Fatalf("first cause overwritten: %+v -> %+v", first, second)
	}
}
