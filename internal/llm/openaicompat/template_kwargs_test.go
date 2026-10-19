// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
)

// Rejection bodies as the hosted APIs return them for the self-hosted
// chat_template_kwargs extension.
const (
	mistralRejection = `{"object":"error","message":{"detail":[{"type":"extra_forbidden",` +
		`"loc":["body","chat_template_kwargs"],"msg":"Extra inputs are not permitted",` +
		`"input":{"enable_thinking":false}}]},"type":"invalid_request_error"}`
	openAIRejection = `{"error":{"message":"Unrecognized request argument supplied: chat_template_kwargs",` +
		`"type":"invalid_request_error","param":null,"code":null}}`
)

// strictEndpoint rejects any request carrying chat_template_kwargs with the
// given status and body, and answers everything else successfully. It records
// whether each request carried the field, in arrival order.
type strictEndpoint struct {
	status int
	body   string

	mu      sync.Mutex
	carried []bool
}

func (s *strictEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	_, present := req["chat_template_kwargs"]
	s.mu.Lock()
	s.carried = append(s.carried, present)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if present {
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
		return
	}
	_, _ = w.Write([]byte(chatBody(`{"k":1}`, 3, 2)))
}

func (s *strictEndpoint) requests() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bool(nil), s.carried...)
}

func TestRejectedTemplateKwargsResentWithoutAndRemembered(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"mistral 422", http.StatusUnprocessableEntity, mistralRejection},
		{"openai-style 400", http.StatusBadRequest, openAIRejection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := &strictEndpoint{status: tc.status, body: tc.body}
			srv := httptest.NewServer(ep)
			defer srv.Close()
			c := newClient(srv, nil)

			comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, []string{"k"})
			if err != nil {
				t.Fatalf("first Complete: %v", err)
			}
			if string(comp.Raw) != `{"k":1}` || comp.InputTokens != 3 || comp.OutputTokens != 2 {
				t.Errorf("completion = %s in=%d out=%d, want the resend's reply and usage", comp.Raw, comp.InputTokens, comp.OutputTokens)
			}
			if got := ep.requests(); len(got) != 2 || !got[0] || got[1] {
				t.Fatalf("requests carrying the field = %v, want [true false]", got)
			}

			if _, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
				t.Fatalf("second Complete: %v", err)
			}
			if got := ep.requests(); len(got) != 3 || got[2] {
				t.Fatalf("requests carrying the field = %v, want the later call sent once without it", got)
			}
		})
	}
}

// TestCompleteOnceRejectedTemplateKwargsResendsOnce pins the one exception to
// CompleteOnce's single physical request: a request the endpoint refused for
// the field is resent once, and the dispatch reports the resend's outcome.
func TestCompleteOnceRejectedTemplateKwargsResendsOnce(t *testing.T) {
	ep := &strictEndpoint{status: http.StatusUnprocessableEntity, body: mistralRejection}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	c := newClient(srv, nil)

	comp, err := c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err != nil {
		t.Fatalf("CompleteOnce: %v", err)
	}
	if comp.RequestStarted != llm.RequestStartStatusTrue {
		t.Errorf("RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusTrue)
	}
	if got := ep.requests(); len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("requests carrying the field = %v, want [true false]", got)
	}

	if _, err := c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("second CompleteOnce: %v", err)
	}
	if got := ep.requests(); len(got) != 3 || got[2] {
		t.Fatalf("requests carrying the field = %v, want the later call sent once without it", got)
	}
}

func TestResendObservedAsSeparateRequests(t *testing.T) {
	ep := &strictEndpoint{status: http.StatusUnprocessableEntity, body: mistralRejection}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	c := newClient(srv, nil)

	var observed []error
	ctx := llm.WithRequestObserver(context.Background(), func(_ llm.Completion, err error) {
		observed = append(observed, err)
	})
	if _, err := c.Complete(ctx, "sys", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("observed %d requests, want 2 (the refused one and the resend)", len(observed))
	}
	var api *llm.APIError
	if !errors.As(observed[0], &api) || api.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("first observation = %v, want the 422 APIError", observed[0])
	}
	if observed[1] != nil {
		t.Errorf("second observation = %v, want nil", observed[1])
	}
}

func TestUnrelatedValidationErrorNotResent(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":[{"type":"missing","loc":["body","messages"]}]}`))
	}))
	defer srv.Close()
	c := newClient(srv, nil)

	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, nil)
	var api *llm.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("err = %v, want the 422 APIError", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// TestRejectionNamingUnsentFieldNotResent covers a body that names the field
// although the request never carried it: there is nothing to drop, so the
// error stands.
func TestRejectionNamingUnsentFieldNotResent(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(openAIRejection))
	}))
	defer srv.Close()
	c := openaicompat.NewForTest(openaicompat.Config{BaseURL: srv.URL, Model: "gpt-5", TimeoutSeconds: 5}, true)

	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, nil)
	var api *llm.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusBadRequest {
		t.Fatalf("err = %v, want the 400 APIError", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// TestEchoedFieldKeepsPin covers a validation error that merely echoes the
// request body, field included: the resend fails the same way, so the field
// was not the problem and later calls still carry the pin.
func TestEchoedFieldKeepsPin(t *testing.T) {
	var mu sync.Mutex
	var carried []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, present := req["chat_template_kwargs"]
		mu.Lock()
		carried = append(carried, present)
		mu.Unlock()
		echo, _ := json.Marshal(req)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":[{"type":"string_too_long","loc":["body"],"input":` + string(echo) + `}]}`))
	}))
	defer srv.Close()
	c := newClient(srv, nil)

	for i := 0; i < 2; i++ {
		_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "p"}, nil)
		var api *llm.APIError
		if !errors.As(err, &api) || api.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("call %d: err = %v, want the 422 APIError", i+1, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []bool{true, false, true, false}; fmt.Sprint(carried) != fmt.Sprint(want) {
		t.Fatalf("requests carrying the field = %v, want %v", carried, want)
	}
}

// TestInconclusiveResendKeepsPin: a rate-limited resend proves nothing about
// the field, so the pin stays on and the dispatch reports the rate limit.
func TestInconclusiveResendKeepsPin(t *testing.T) {
	var mu sync.Mutex
	var carried []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, present := req["chat_template_kwargs"]
		mu.Lock()
		carried = append(carried, present)
		mu.Unlock()
		if present {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(mistralRejection))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := newClient(srv, nil)

	for i := 0; i < 2; i++ {
		comp, err := c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, nil)
		var retry *llm.RetryableError
		if !errors.As(err, &retry) || retry.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("call %d: err = %v, want the 429 RetryableError", i+1, err)
		}
		if comp.RequestStarted != llm.RequestStartStatusTrue {
			t.Errorf("call %d: RequestStarted = %q, want %q", i+1, comp.RequestStarted, llm.RequestStartStatusTrue)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []bool{true, false, true, false}; fmt.Sprint(carried) != fmt.Sprint(want) {
		t.Fatalf("requests carrying the field = %v, want %v", carried, want)
	}
}

// memBudgetStore is an in-memory llm.BudgetStore; nextHour drops the recorded
// calls, as the rolling hour passing would.
type memBudgetStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *memBudgetStore) UpdateLLMBudget(_ context.Context, update func([]byte) ([]byte, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = []byte("{}")
	}
	next, err := update(s.data)
	if err == nil {
		s.data = next
	}
	return err
}

func (s *memBudgetStore) nextHour(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var state map[string]any
	if err := json.Unmarshal(s.data, &state); err != nil {
		t.Fatal(err)
	}
	state["calls"] = []any{}
	next, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	s.data = next
}

// TestBudgetDeclinedResendSendsNextWithoutField covers a call budget that the
// refusals use up, so every resend is declined: with one call per hour, or
// two calls racing the first refusal under two per hour. The next permitted
// request goes without the field, and once it is accepted the field stays off.
func TestBudgetDeclinedResendSendsNextWithoutField(t *testing.T) {
	for _, racers := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d per hour", racers), func(t *testing.T) {
			var mu sync.Mutex
			var carried []bool
			var refusals int
			allRefused := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				_, present := req["chat_template_kwargs"]
				mu.Lock()
				carried = append(carried, present)
				if present {
					refusals++
					if refusals == racers {
						close(allRefused)
					}
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if present {
					// Hold each refusal until every racer has sent, so
					// all of them reserve before any resend does.
					select {
					case <-allRefused:
					case <-time.After(5 * time.Second):
					}
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(mistralRejection))
					return
				}
				_, _ = w.Write([]byte(chatBody(`{"k":1}`, 3, 2)))
			}))
			defer srv.Close()
			store := &memBudgetStore{}
			var logs bytes.Buffer
			c := openaicompat.New(openaicompat.Config{
				BaseURL:        srv.URL,
				Model:          "mistral-medium-latest",
				TimeoutSeconds: 5,
				Budget:         llm.NewBudget(store, llm.BudgetLimits{CallsPerHour: racers}),
			}, nil, slog.New(slog.NewTextHandler(&logs, nil)))
			call := func() (llm.OneShotCompletion, error) {
				return c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, []string{"k"})
			}

			var wg sync.WaitGroup
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					comp, err := call()
					var api *llm.APIError
					if !errors.As(err, &api) || api.StatusCode != http.StatusUnprocessableEntity {
						t.Errorf("first hour: err = %v, want the 422 APIError", err)
					}
					if comp.RequestStarted != llm.RequestStartStatusTrue {
						t.Errorf("first hour: RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusTrue)
					}
				}()
			}
			wg.Wait()

			// Same hour: the budget is spent, nothing leaves.
			comp, err := call()
			if !errors.Is(err, llm.ErrRequestNotSent) || comp.RequestStarted != llm.RequestStartStatusFalse {
				t.Fatalf("spent hour: err = %v RequestStarted = %q, want not sent", err, comp.RequestStarted)
			}

			for hour := 1; hour <= 2; hour++ {
				store.nextHour(t)
				comp, err := call()
				if err != nil {
					t.Fatalf("hour %d: %v", hour, err)
				}
				if string(comp.Raw) != `{"k":1}` {
					t.Errorf("hour %d: Raw = %s, want the reply", hour, comp.Raw)
				}
			}
			mu.Lock()
			got := fmt.Sprint(carried)
			mu.Unlock()
			want := make([]bool, racers, racers+2)
			for i := range want {
				want[i] = true
			}
			if want = append(want, false, false); got != fmt.Sprint(want) {
				t.Fatalf("requests carrying the field = %s, want %v", got, want)
			}
			if n := strings.Count(logs.String(), "endpoint rejected chat_template_kwargs"); n != 1 {
				t.Errorf("warnings = %d, want 1:\n%s", n, logs.String())
			}
		})
	}
}
