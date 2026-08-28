// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestAPIErrorString(t *testing.T) {
	if got := (&llm.APIError{StatusCode: 401}).Error(); got != "llm: api error: HTTP 401" {
		t.Fatalf("got %q", got)
	}
	if got := (&llm.APIError{StatusCode: 400, Message: "bad request"}).Error(); got != "llm: api error: HTTP 400: bad request" {
		t.Fatalf("got %q", got)
	}
	var target *llm.APIError
	wrapped := fmt.Errorf("acutetriage: llm: %w", &llm.APIError{StatusCode: 403})
	if !errors.As(wrapped, &target) || target.StatusCode != http.StatusForbidden {
		t.Fatalf("errors.As failed: %v", wrapped)
	}
}

func TestErrResponseInvalidWraps(t *testing.T) {
	err := fmt.Errorf("%w: response is not valid JSON: boom", llm.ErrResponseInvalid)
	if !errors.Is(err, llm.ErrResponseInvalid) {
		t.Fatal("want ErrResponseInvalid")
	}
}
