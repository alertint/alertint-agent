// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestClassifyRequestStartNilIsTrue(t *testing.T) {
	if got := llm.ClassifyRequestStart(nil); got != llm.RequestStartStatusTrue {
		t.Fatalf("ClassifyRequestStart(nil) = %q, want %q", got, llm.RequestStartStatusTrue)
	}
}

func TestClassifyRequestStartNotSentIsFalse(t *testing.T) {
	err := fmt.Errorf("%w: marshal request: boom", llm.ErrRequestNotSent)
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusFalse {
		t.Fatalf("ClassifyRequestStart(ErrRequestNotSent) = %q, want %q", got, llm.RequestStartStatusFalse)
	}
}

func TestClassifyRequestStartRetryableIsTrue(t *testing.T) {
	err := &llm.RetryableError{StatusCode: 429}
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusTrue {
		t.Fatalf("ClassifyRequestStart(RetryableError) = %q, want %q", got, llm.RequestStartStatusTrue)
	}
}

func TestClassifyRequestStartAPIErrorIsTrue(t *testing.T) {
	err := &llm.APIError{StatusCode: 400}
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusTrue {
		t.Fatalf("ClassifyRequestStart(APIError) = %q, want %q", got, llm.RequestStartStatusTrue)
	}
}

func TestClassifyRequestStartResponseInvalidIsTrue(t *testing.T) {
	err := fmt.Errorf("%w: response is not valid JSON", llm.ErrResponseInvalid)
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusTrue {
		t.Fatalf("ClassifyRequestStart(ErrResponseInvalid) = %q, want %q", got, llm.RequestStartStatusTrue)
	}
}

func TestClassifyRequestStartResponseTruncatedIsTrue(t *testing.T) {
	err := fmt.Errorf("%w=100", llm.ErrResponseTruncated)
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusTrue {
		t.Fatalf("ClassifyRequestStart(ErrResponseTruncated) = %q, want %q", got, llm.RequestStartStatusTrue)
	}
}

func TestClassifyRequestStartAmbiguousTransportIsUnknown(t *testing.T) {
	// A raw network-layer failure (what an unwrapped http.Client.Do error
	// looks like) — never proves whether the request reached the provider.
	err := fmt.Errorf("llm: http: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")})
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusUnknown {
		t.Fatalf("ClassifyRequestStart(transport error) = %q, want %q", got, llm.RequestStartStatusUnknown)
	}
}

func TestClassifyRequestStartContextDeadlineIsUnknown(t *testing.T) {
	err := fmt.Errorf("llm: http: %w", context.DeadlineExceeded)
	if got := llm.ClassifyRequestStart(err); got != llm.RequestStartStatusUnknown {
		t.Fatalf("ClassifyRequestStart(deadline exceeded) = %q, want %q", got, llm.RequestStartStatusUnknown)
	}
}
