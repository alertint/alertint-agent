// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/situation"
)

// ----------------------------------------------------------------------
// Task 7 fix round, Finding #4: restore the pre-Plan-2 dispatch chain's own
// llmhealth-aware classifyTriageError granularity (internal/correlator/
// triage_retry.go, deleted when Task 7 removed the old Correlator dispatch
// chain), now computed at the one place Analyze's errors flow through
// instead of at the old Correlator dispatch site. TriageWorker's own
// classifyAttemptError (internal/situation/triage_worker.go) checks any
// AcuteAnalyzer failure for the optional situation.ClassifiedError
// interface before falling back to its own coarser context.*-only
// classification — classifiedAnalyzeError below satisfies that interface.
// ----------------------------------------------------------------------

// ambiguousShapedAnalyzeReasons mirrors the deleted internal/correlator/
// triage_retry.go's own ambiguousShapedReasons exactly: llmhealth.Classify
// reasons that match on a generic stdlib error shape (context.
// DeadlineExceeded, a net.Error, a *url.Error) rather than an internal/llm-
// or internal/llmhealth-specific typed value. Analyze's own error can come
// from a SQLite write timing out or a Prometheus/Zabbix/log-source fetch
// failing, not just the LLM call — these three reasons are trusted only
// when llmhealth.MarkLLMOrigin (applied at Analyze's own Complete()
// boundary, skill.go) vouches the error actually came out of the LLM call.
var ambiguousShapedAnalyzeReasons = map[llmhealth.Reason]bool{
	llmhealth.ReasonTimeout:  true,
	llmhealth.ReasonNetwork:  true,
	llmhealth.ReasonCanceled: true,
}

// classifyAnalyzeError wraps a non-nil Analyze failure (never called with
// ErrCleanSkip — that is not a failure to classify at all) in a type
// satisfying situation.ClassifiedError, always — even the "no LLM-specific
// signal at all" and "ambiguous shape, not LLM-marked" cases get an
// explicit "acute_triage_failed" code here, rather than being left for
// classifyAttemptError's own bare context.*-only fallback to (mis)classify.
// This keeps the granularity decision entirely inside this package, which
// is the only one that can see llmhealth.MarkLLMOrigin's own marking.
func classifyAnalyzeError(err error) error {
	if err == nil {
		return nil
	}
	reason := llmhealth.Classify(err)
	code := "acute_triage_failed"
	switch {
	case reason == llmhealth.ReasonUnknown:
		// No llmhealth-recognizable shape at all — generic code.
	case ambiguousShapedAnalyzeReasons[reason] && !llmhealth.IsLLMOrigin(err):
		// A stdlib-shaped timeout/network/canceled error NOT marked as
		// having come out of the LLM call (e.g. a SQLite write timing out,
		// or a non-LLM enrichment fetch failing) — trusting the reason here
		// would misattribute a non-LLM failure as an LLM dependency code.
	default:
		code = string(reason)
	}
	return &classifiedAnalyzeError{cause: err, code: code, detail: llmhealth.SafeDetail(err)}
}

// classifiedAnalyzeError satisfies situation.ClassifiedError: error plus
// Code()/SafeDetail(). It is a structural implementation — this package
// already imports internal/situation directly (AcuteResult/
// TriageAttemptClaim/AcuteAnalyzer), so there is no cycle risk in
// referencing the interface by name; it stays structural only because
// ClassifiedError itself is documented as such.
type classifiedAnalyzeError struct {
	cause  error
	code   string
	detail string
}

var _ situation.ClassifiedError = (*classifiedAnalyzeError)(nil)

func (e *classifiedAnalyzeError) Error() string      { return e.cause.Error() }
func (e *classifiedAnalyzeError) Unwrap() error      { return e.cause }
func (e *classifiedAnalyzeError) Code() string       { return e.code }
func (e *classifiedAnalyzeError) SafeDetail() string { return e.detail }
