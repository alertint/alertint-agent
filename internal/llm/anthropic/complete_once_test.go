// SPDX-License-Identifier: FSL-1.1-ALv2

package anthropic_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
)

// TestCompleteOnceSuccessMakesExactlyOneRequest proves CompleteOnce spends
// no retry budget on a clean success.
func TestCompleteOnceSuccessMakesExactlyOneRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"result":"ok"}`, 1, 1))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	comp, err := c.CompleteOnce(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"result"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 HTTP request, got %d", calls.Load())
	}
	if comp.RequestStarted != llm.RequestStartStatusTrue {
		t.Fatalf("RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusTrue)
	}
}

// TestCompleteOnce429MakesExactlyOneRequest proves CompleteOnce never
// retries a rate-limit response — the hidden retry loop Complete uses for
// Acute Triage must not apply here.
func TestCompleteOnce429MakesExactlyOneRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	comp, err := c.CompleteOnce(context.Background(), "sys", llm.Prompt{Prefix: "user"}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 HTTP request on 429, got %d", calls.Load())
	}
	if comp.RequestStarted != llm.RequestStartStatusTrue {
		t.Fatalf("RequestStarted = %q, want %q (a 429 response proves execution)", comp.RequestStarted, llm.RequestStartStatusTrue)
	}
}

// TestCompleteOnce5xxMakesExactlyOneRequest proves the same for a 5xx
// response (529 overloaded, Anthropic's own retryable status).
func TestCompleteOnce5xxMakesExactlyOneRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(529)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	comp, err := c.CompleteOnce(context.Background(), "sys", llm.Prompt{Prefix: "user"}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 HTTP request on 529, got %d", calls.Load())
	}
	if comp.RequestStarted != llm.RequestStartStatusTrue {
		t.Fatalf("RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusTrue)
	}
}

// TestCompleteOnceTimeoutMakesExactlyOneRequest proves a client-side timeout
// (context deadline) never retries and is classified unknown, not true/false.
func TestCompleteOnceTimeoutMakesExactlyOneRequest(t *testing.T) {
	var calls atomic.Int32
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-block // never respond within the test's short deadline
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	c := newTestClient(t, srv.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	comp, err := c.CompleteOnce(ctx, "sys", llm.Prompt{Prefix: "user"}, nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 HTTP request on timeout, got %d", calls.Load())
	}
	if comp.RequestStarted != llm.RequestStartStatusUnknown {
		t.Fatalf("RequestStarted = %q, want %q (an ambiguous transport failure)", comp.RequestStarted, llm.RequestStartStatusUnknown)
	}
}

// TestCompleteOnceUncertainTransportMakesExactlyOneRequest proves a
// connection-level failure (server closes without responding) is also
// classified unknown and never retried.
func TestCompleteOnceUncertainTransportMakesExactlyOneRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close() // close without ever writing a response
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	comp, err := c.CompleteOnce(context.Background(), "sys", llm.Prompt{Prefix: "user"}, nil)
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
	if comp.RequestStarted != llm.RequestStartStatusUnknown {
		t.Fatalf("RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusUnknown)
	}
}

// TestCompleteExistingRetryBehaviorUnchanged proves Complete (Acute
// Triage's path) still retries 429 up to MaxRetries — CompleteOnce's
// addition must not have touched Complete's own behavior.
func TestCompleteExistingRetryBehaviorUnchanged(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"result":"ok"}`, 1, 1))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"result"})
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 total calls (2 retries + 1 success), got %d", calls.Load())
	}
}
