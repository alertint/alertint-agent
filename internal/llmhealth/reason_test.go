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

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	var _ net.Error = timeoutErr{}
	cases := []struct {
		name string
		err  error
		want llmhealth.Reason
		cls  llmhealth.Class
	}{
		{"nil", nil, llmhealth.ReasonOK, llmhealth.ClassOK},
		{"canceled", fmt.Errorf("acutetriage: llm: %w", context.Canceled), llmhealth.ReasonCanceled, llmhealth.ClassIgnored},
		{"deadline", context.DeadlineExceeded, llmhealth.ReasonTimeout, llmhealth.ClassDependency},
		{"net timeout", &url.Error{Op: "Post", Err: timeoutErr{}}, llmhealth.ReasonTimeout, llmhealth.ClassDependency},
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
		&llm.APIError{StatusCode: 401, Message: secret}:                       "HTTP 401",
		&llm.RetryableError{StatusCode: 503}:                                  "HTTP 503",
		&url.Error{Op: "Post", URL: "https://x/" + secret, Err: timeoutErr{}}: "request timed out",
		fmt.Errorf("%w: missing keys [summary]", llm.ErrSchemaViolation):      "schema violation",
		fmt.Errorf("%w: %s", llmhealth.ErrResponseMalformed, secret):          "typed response malformed",
		context.DeadlineExceeded:                                              "request timed out",
	}
	for err, want := range cases {
		got := llmhealth.SafeDetail(err)
		if got != want || strings.Contains(got, "SECRET") || len(got) > 160 {
			t.Errorf("SafeDetail(%v) = %q, want %q", err, got, want)
		}
	}
}
