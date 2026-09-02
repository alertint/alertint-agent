// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"fmt"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/situation"
)

// Task 7 fix round, Finding #4: recreate the spirit of the 4 deleted
// internal/correlator/triage_retry_test.go tests
// (TestTriageBackoffRecordsCapabilityAwareCode,
// TestTriageBackoffRecordsResponseMalformed,
// TestTriageBackoffDoesNotMisattributeAmbiguousShapedErrors,
// TestTriageBackoffRecordsLLMOriginTimeout) directly against
// classifyAnalyzeError — the function that now computes the same
// granularity the deleted classifyTriageError used to, at Analyze's own
// error boundary. internal/situation/triage_worker_test.go separately
// proves classifyAttemptError actually trusts whatever this function
// produces (via the ClassifiedError interface) end-to-end through
// TriageWorker; these tests prove the classification decision itself is
// correct.

// TestClassifyAnalyzeError_RecordsCapabilityAwareCode pins the
// dependency-class branch: a provider-status error classifies to its
// llmhealth reason code and safe HTTP-status detail, not the generic
// fallback.
func TestClassifyAnalyzeError_RecordsCapabilityAwareCode(t *testing.T) {
	err := classifyAnalyzeError(&llm.RetryableError{StatusCode: 503})
	assertClassified(t, err, "provider_unavailable", "HTTP 503")
}

// TestClassifyAnalyzeError_RecordsResponseMalformed pins the content-class
// side: a Call-1 typed-decode failure (wrapping llmhealth.ErrResponseMalformed,
// the way analysis() in skill.go actually propagates it) classifies as
// response_malformed — the same code /health reports for that capability.
func TestClassifyAnalyzeError_RecordsResponseMalformed(t *testing.T) {
	err := fmt.Errorf("acutetriage: parse llm response: %w",
		fmt.Errorf("%w: json: cannot unmarshal string into Go struct field", llmhealth.ErrResponseMalformed))
	assertClassified(t, classifyAnalyzeError(err), "response_malformed", "typed response malformed")
}

// TestClassifyAnalyzeError_DoesNotMisattributeAmbiguousShapedErrors pins
// classifyAnalyzeError's other side: llmhealth.Classify's timeout/network/
// canceled reasons match on generic stdlib error shapes (context.
// DeadlineExceeded, a net.Error, a *url.Error) that a non-LLM failure
// inside Analyze's own call chain — a SQLite write timing out, a
// Prometheus/Zabbix/log-source fetch failing — could equally produce.
// Trusting them here would misattribute a non-LLM failure as an LLM
// dependency code, so classifyAnalyzeError falls back to the generic
// "acute_triage_failed" code for exactly these three ambiguous reasons
// when NOT marked LLM-origin.
func TestClassifyAnalyzeError_DoesNotMisattributeAmbiguousShapedErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"context deadline (e.g. a SQLite write timing out)", fmt.Errorf("store: save output: %w", context.DeadlineExceeded)},
		{"context canceled (e.g. a non-LLM fetch canceled)", fmt.Errorf("store: save output: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertClassified(t, classifyAnalyzeError(tc.err), "acute_triage_failed", "")
		})
	}
}

// TestClassifyAnalyzeError_RecordsLLMOriginTimeout pins the resolution of
// the ambiguity above: a timeout that Analyze marked as LLM-origin
// (llmhealth.MarkLLMOrigin, applied at its own Complete() boundary — see
// skill.go's "acutetriage: llm: %w" wrap) IS trustworthy, so a real Call-1
// context deadline persists its capability-aware "timeout" code instead of
// the generic fallback.
func TestClassifyAnalyzeError_RecordsLLMOriginTimeout(t *testing.T) {
	err := fmt.Errorf("acutetriage: llm: %w", llmhealth.MarkLLMOrigin(context.DeadlineExceeded))
	assertClassified(t, classifyAnalyzeError(err), "timeout", "request timed out")
}

// TestClassifyAnalyzeError_SatisfiesSituationClassifiedError proves the
// structural contract classifyAttemptError depends on: every non-nil error
// classifyAnalyzeError returns actually satisfies situation.ClassifiedError
// via a plain type assertion, exactly the way TriageWorker's own
// classifyAttemptError checks for it.
func TestClassifyAnalyzeError_SatisfiesSituationClassifiedError(t *testing.T) {
	err := classifyAnalyzeError(fmt.Errorf("boom"))
	ce, ok := err.(situation.ClassifiedError)
	if !ok {
		t.Fatalf("classifyAnalyzeError's result does not satisfy situation.ClassifiedError: %T", err)
	}
	if ce.Code() == "" {
		t.Error("Code() is empty")
	}
}

// TestClassifyAnalyzeError_NilIsNil proves the nil fast-path: Analyze never
// calls this with a nil error in production (only from a non-nil failure
// branch), but a nil-safe implementation is cheap and avoids ever wrapping
// a nil error into a non-nil one.
func TestClassifyAnalyzeError_NilIsNil(t *testing.T) {
	if err := classifyAnalyzeError(nil); err != nil {
		t.Errorf("classifyAnalyzeError(nil) = %v, want nil", err)
	}
}

func assertClassified(t *testing.T, err error, wantCode, wantDetail string) {
	t.Helper()
	ce, ok := err.(situation.ClassifiedError)
	if !ok {
		t.Fatalf("err = %T, does not satisfy situation.ClassifiedError", err)
	}
	if ce.Code() != wantCode {
		t.Errorf("Code() = %q, want %q", ce.Code(), wantCode)
	}
	if wantDetail != "" && ce.SafeDetail() != wantDetail {
		t.Errorf("SafeDetail() = %q, want %q", ce.SafeDetail(), wantDetail)
	}
}
