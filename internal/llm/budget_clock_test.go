// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

type clockBudgetTransport func(*http.Request) (*http.Response, error)

func (f clockBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBudgetRollingHourBoundary(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 9, 7, 10, 59, 59, 0, time.UTC)
	b := llm.NewBudget(st, llm.BudgetLimits{CallsPerHour: 1})
	llm.SetBudgetClockForTest(b, func() time.Time { return now })
	calls := 0
	transport := b.Transport(clockBudgetTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":1,"output_tokens":1}}`))}, nil
	}))
	call := func() error {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://provider.invalid", strings.NewReader(`{"max_tokens":10}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := transport.RoundTrip(r)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := call(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	err = call()
	var deferred *llm.BudgetDeferredError
	if !errors.Is(err, llm.ErrBudgetExhausted) || !errors.As(err, &deferred) || deferred.RetryAt == nil {
		t.Fatalf("new clock hour = %v, want typed rolling-hour deferral", err)
	}
	if want := now.Add(time.Hour - 2*time.Second); !deferred.RetryAt.Equal(want) {
		t.Fatalf("retry at = %v, want %v", deferred.RetryAt, want)
	}
	now = now.Add(time.Hour - 2*time.Second)
	if err := call(); err != nil {
		t.Fatalf("exactly one hour later: %v", err)
	}
	if calls != 2 {
		t.Fatalf("provider calls = %d, want 2", calls)
	}
}
