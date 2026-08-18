// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
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
	c := New(Config{BaseURL: "https://api.openai.com", Model: "gpt-4.1"}, nil, nil)
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
