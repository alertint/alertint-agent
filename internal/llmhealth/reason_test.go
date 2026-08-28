// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestMarkLLMOrigin pins the LLM-origin marker Acute Triage wraps around a
// failed Complete: the marker is transparent to Classify (the wrapped error
// still classifies by its own shape), survives further fmt.Errorf %w
// wrapping, and is absent from an identically-shaped error that did not come
// through the marker — so a downstream consumer (the Correlator) can trust an
// ambiguous stdlib-shaped reason only when the marker vouches for it.
func TestMarkLLMOrigin(t *testing.T) {
	marked := fmt.Errorf("acutetriage: llm: %w", llmhealth.MarkLLMOrigin(context.DeadlineExceeded))
	if !llmhealth.IsLLMOrigin(marked) {
		t.Fatal("marked error not recognised through fmt.Errorf wrapping")
	}
	if got := llmhealth.Classify(marked); got != llmhealth.ReasonTimeout {
		t.Fatalf("Classify(marked) = %q, want timeout (the marker must be transparent)", got)
	}
	if !errors.Is(marked, context.DeadlineExceeded) {
		t.Fatal("marker must unwrap to the original error")
	}
	if llmhealth.IsLLMOrigin(fmt.Errorf("store: %w", context.DeadlineExceeded)) {
		t.Fatal("an unmarked deadline must not read as LLM-origin")
	}
	if llmhealth.IsLLMOrigin(nil) {
		t.Fatal("nil is not LLM-origin")
	}
	if llmhealth.MarkLLMOrigin(nil) != nil {
		t.Fatal("MarkLLMOrigin(nil) must stay nil so a success path needs no branch")
	}
}

func TestClassify(t *testing.T) {
	var _ net.Error = timeoutError{}
	cases := []struct {
		name string
		err  error
		want llmhealth.Reason
		cls  llmhealth.Class
	}{
		{"nil", nil, llmhealth.ReasonOK, llmhealth.ClassOK},
		{"canceled", fmt.Errorf("acutetriage: llm: %w", context.Canceled), llmhealth.ReasonCanceled, llmhealth.ClassIgnored},
		{"deadline", context.DeadlineExceeded, llmhealth.ReasonTimeout, llmhealth.ClassDependency},
		{"net timeout", &url.Error{Op: "Post", Err: timeoutError{}}, llmhealth.ReasonTimeout, llmhealth.ClassDependency},
		{"net refused", &url.Error{Op: "Post", Err: errors.New("connection refused")}, llmhealth.ReasonNetwork, llmhealth.ClassDependency},
		{"429", &llm.RetryableError{StatusCode: 429}, llmhealth.ReasonRateLimited, llmhealth.ClassDependency},
		{"529", &llm.RetryableError{StatusCode: 529}, llmhealth.ReasonProviderUnavailable, llmhealth.ClassDependency},
		{"503", &llm.RetryableError{StatusCode: 503}, llmhealth.ReasonProviderUnavailable, llmhealth.ClassDependency},
		{"401", &llm.APIError{StatusCode: 401, Message: "invalid x-api-key"}, llmhealth.ReasonAuthFailed, llmhealth.ClassDependency},
		{"403", &llm.APIError{StatusCode: 403}, llmhealth.ReasonAuthFailed, llmhealth.ClassDependency},
		{"400", &llm.APIError{StatusCode: 400, Message: "prompt too long"}, llmhealth.ReasonRequestInvalid, llmhealth.ClassContent},
		{"schema", fmt.Errorf("%w: missing keys [x]", llm.ErrSchemaViolation), llmhealth.ReasonSchemaViolation, llmhealth.ClassContent},
		{"truncated", llm.ErrResponseTruncated, llmhealth.ReasonSchemaViolation, llmhealth.ClassContent},
		{"invalid", fmt.Errorf("%w: not valid JSON", llm.ErrResponseInvalid), llmhealth.ReasonSchemaViolation, llmhealth.ClassContent},
		{"malformed typed", fmt.Errorf("%w: unexpected end", llmhealth.ErrResponseMalformed), llmhealth.ReasonResponseMalformed, llmhealth.ClassContent},
		{"unknown", errors.New("something else"), llmhealth.ReasonUnknown, llmhealth.ClassDependency},
	}
	for _, tc := range cases {
		got := llmhealth.Classify(tc.err)
		if got != tc.want || got.Class() != tc.cls {
			t.Errorf("%s: Classify = %s (%v), want %s (%v)", tc.name, got, got.Class(), tc.want, tc.cls)
		}
	}
}

func TestSafeDetailNeverLeaksProviderText(t *testing.T) {
	secret := "sk-ant-SECRET " + strings.Repeat("body", 200)
	cases := map[error]string{
		&llm.APIError{StatusCode: 401, Message: secret}:                         "HTTP 401",
		&llm.RetryableError{StatusCode: 503}:                                    "HTTP 503",
		&url.Error{Op: "Post", URL: "https://x/" + secret, Err: timeoutError{}}: "request timed out",
		fmt.Errorf("%w: missing keys [summary]", llm.ErrSchemaViolation):        "schema violation",
		fmt.Errorf("%w: %s", llmhealth.ErrResponseMalformed, secret):            "typed response malformed",
		context.DeadlineExceeded:                                                "request timed out",
	}
	for err, want := range cases {
		got := llmhealth.SafeDetail(err)
		if got != want || strings.Contains(got, "SECRET") || len(got) > 160 {
			t.Errorf("SafeDetail(%v) = %q, want %q", err, got, want)
		}
	}
}
