// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestIsHostedOpenAI(t *testing.T) {
	cases := []struct {
		baseURL string
		want    bool
	}{
		{"https://api.openai.com", true},
		{"https://API.OPENAI.COM", true},
		{"https://api.openai.com:443", true},
		{"http://localhost:30000", false},
		{"http://127.0.0.1:11434", false},
		{"https://api.openai.com.evil.example", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isHostedOpenAI(c.baseURL); got != c.want {
			t.Errorf("isHostedOpenAI(%q) = %v, want %v", c.baseURL, got, c.want)
		}
	}
}

// roundTripFunc lets the test intercept the request without a listener, so the
// client can be pointed at the real hosted-OpenAI base URL.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHostedOpenAIOmitsChatTemplateKwargs(t *testing.T) {
	var gotBody map[string]any
	c := New(Config{BaseURL: "https://api.openai.com", Model: "gpt-4.1", Thinking: true, ReasoningEffort: "low"}, nil, nil)
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		body := `{"choices":[{"message":{"content":"{\"k\":1}"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":1,"completion_tokens":1}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatal(err)
	}
	if _, present := gotBody["chat_template_kwargs"]; present {
		t.Errorf("chat_template_kwargs must be omitted for hosted OpenAI, got %v", gotBody["chat_template_kwargs"])
	}
	if _, present := gotBody["response_format"]; !present {
		t.Error("response_format must still be sent for hosted OpenAI")
	}
}

// TestResendNotSentReportsRefusedRequest covers a resend that never leaves the
// process (the budget declines it, say): the refused request did go out, so
// the call reports that rejection and stays classified as started.
func TestResendNotSentReportsRefusedRequest(t *testing.T) {
	var calls int
	c := New(Config{BaseURL: "https://api.mistral.ai", Model: "mistral-medium-latest", TimeoutSeconds: 5}, nil, nil)
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			return nil, fmt.Errorf("%w: reserve LLM budget: %w", llm.ErrRequestNotSent, llm.ErrBudgetExhausted)
		}
		body := `{"detail":[{"type":"extra_forbidden","loc":["body","chat_template_kwargs"]}]}`
		return &http.Response{
			StatusCode: http.StatusUnprocessableEntity,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	comp, err := c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, nil)
	var api *llm.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("err = %v, want the 422 APIError", err)
	}
	if errors.Is(err, llm.ErrRequestNotSent) {
		t.Errorf("err = %v must not claim the request was never sent", err)
	}
	if comp.RequestStarted != llm.RequestStartStatusTrue {
		t.Errorf("RequestStarted = %q, want %q", comp.RequestStarted, llm.RequestStartStatusTrue)
	}
	if calls != 2 {
		t.Errorf("transport calls = %d, want 2", calls)
	}
	if !c.pinChatTemplateKwargs.Load() {
		t.Error("pin must stay on: no resend was accepted, so the field is not proven to be the problem")
	}
}

// TestUnprovenPendingRejectionRestoresField: after a declined resend the next
// request goes without the field. When that one fails for another reason, the
// field is not proven to be the problem, so later requests carry it again.
func TestUnprovenPendingRejectionRestoresField(t *testing.T) {
	var carried []bool
	reply := func(status int, body string) *http.Response {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
	}
	c := New(Config{BaseURL: "https://api.mistral.ai", Model: "mistral-medium-latest", TimeoutSeconds: 5}, nil, nil)
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, present := req["chat_template_kwargs"]
		carried = append(carried, present)
		switch len(carried) {
		case 1:
			return reply(http.StatusUnprocessableEntity, `{"detail":[{"type":"extra_forbidden","loc":["body","chat_template_kwargs"]}]}`), nil
		case 2:
			return nil, fmt.Errorf("%w: reserve LLM budget: %w", llm.ErrRequestNotSent, llm.ErrBudgetExhausted)
		default:
			return reply(http.StatusBadRequest, `{"error":{"message":"invalid model"}}`), nil
		}
	})

	for i := 0; i < 3; i++ {
		_, err := c.CompleteOnce(context.Background(), "", llm.Prompt{Prefix: "p"}, nil)
		var api *llm.APIError
		if !errors.As(err, &api) {
			t.Fatalf("call %d: err = %v, want an APIError", i+1, err)
		}
	}
	// Refused, declined resend; next call without the field (400); then the
	// field again.
	if want := []bool{true, false, false, true}; fmt.Sprint(carried) != fmt.Sprint(want) {
		t.Fatalf("requests carrying the field = %v, want %v", carried, want)
	}
	if !c.pinChatTemplateKwargs.Load() || c.pendingRejection.Load() != nil {
		t.Error("pin must stay on and nothing stay pending after an unproven request without the field")
	}
}
