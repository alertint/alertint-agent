// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import "context"

// ProbeOutcome is the result class of a zero-generation reachability probe.
type ProbeOutcome string

const (
	ProbeOK          ProbeOutcome = "ok"
	ProbeUnsupported ProbeOutcome = "unsupported" // safe route absent (404/405/501); never a failure
	ProbeFailed      ProbeOutcome = "failed"
)

// ProbeResult reports one probe: the exact request made (for audit/tests) and
// the outcome. Err is set only when Outcome == ProbeFailed and is one of the
// same error shapes Complete returns (*APIError, *RetryableError, transport).
type ProbeResult struct {
	Outcome    ProbeOutcome
	Method     string
	Path       string
	StatusCode int
	Err        error
}

// Prober is implemented by provider clients that can check reachability
// without generating tokens. Implementations must never POST.
type Prober interface {
	Probe(ctx context.Context) ProbeResult
}
