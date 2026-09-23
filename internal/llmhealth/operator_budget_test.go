// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"net/url"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

func TestBudgetAdmissionIsNotNetworkHealth(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://provider.invalid", Err: &llm.BudgetDeferredError{Message: "token allowance"}}
	if got := Classify(err); string(got) != "budget_deferred" || got.Class() != ClassIgnored {
		t.Fatalf("budget admission classified as %q, class %v", got, got.Class())
	}
}
