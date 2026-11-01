// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
)

func off() *bool { b := false; return &b }

// TestReasoningAndRoutingSent verifies llm.reasoning and llm.routing reach the
// wire as the gateway's `reasoning` and `provider` objects, and that a client
// without them sends neither key.
func TestReasoningAndRoutingSent(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body = nil
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()

	plain := newClient(srv, nil)
	if _, err := plain.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"reasoning", "provider"} {
		if _, present := body[key]; present {
			t.Errorf("a client without the option must not send %q", key)
		}
	}

	tuned := newClient(srv, func(c *openaicompat.Config) {
		c.Reasoning = &llm.Reasoning{Effort: "none"}
		c.Routing = &llm.Routing{Only: []string{"deepinfra"}, AllowFallbacks: off()}
	})
	if _, err := tuned.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"effort": "none"}; !reflect.DeepEqual(body["reasoning"], want) {
		t.Errorf("reasoning = %v, want %v", body["reasoning"], want)
	}
	want := map[string]any{"only": []any{"deepinfra"}, "allow_fallbacks": false}
	if !reflect.DeepEqual(body["provider"], want) {
		t.Errorf("provider = %v, want %v", body["provider"], want)
	}
}

// TestReasoningAndRoutingSurviveTemplateKwargsResend verifies the resend that
// drops a rejected chat_template_kwargs keeps the operator's reasoning and
// routing: they are explicit opt-ins, not part of the pin that is shed.
func TestReasoningAndRoutingSurviveTemplateKwargsResend(t *testing.T) {
	var mu sync.Mutex
	var carried []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, kwargs := req["chat_template_kwargs"]
		_, reasoning := req["reasoning"]
		_, provider := req["provider"]
		mu.Lock()
		carried = append(carried, kwargs, reasoning && provider)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if kwargs {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(mistralRejection))
			return
		}
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()

	c := newClient(srv, func(c *openaicompat.Config) {
		c.Reasoning = &llm.Reasoning{Effort: "low"}
		c.Routing = &llm.Routing{Order: []string{"deepinfra"}}
	})
	if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// request 1: kwargs pin + options; request 2 (the resend): no pin, options kept.
	if want := []bool{true, true, false, true}; !reflect.DeepEqual(carried, want) {
		t.Fatalf("(carried kwargs, carried reasoning+provider) per request = %v, want %v", carried, want)
	}
}
