// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

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

// DoProbe executes a prepared GET and maps the status into a ProbeResult.
// Bodies are drained (bounded) and discarded: a probe never surfaces provider
// text. Only GET requests are accepted — the guard is what makes "no probe
// generates" a property of the type, not a convention.
func DoProbe(client *http.Client, req *http.Request, path string) ProbeResult {
	res := ProbeResult{Method: req.Method, Path: path}
	if req.Method != http.MethodGet {
		res.Outcome = ProbeFailed
		res.Err = fmt.Errorf("llm: probe must be GET, got %s", req.Method)
		return res
	}
	resp, err := client.Do(req) // #nosec G704 -- req's URL is always built by the caller from the operator-configured provider base URL (anthropicBaseURL or llm.base_url), never from request/user input
	if err != nil {
		res.Outcome = ProbeFailed
		res.Err = fmt.Errorf("llm: http: %w", err)
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.StatusCode = resp.StatusCode
	switch {
	case resp.StatusCode == http.StatusOK:
		res.Outcome = ProbeOK
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusMethodNotAllowed, resp.StatusCode == http.StatusNotImplemented:
		res.Outcome = ProbeUnsupported
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		res.Outcome = ProbeFailed
		res.Err = &RetryableError{StatusCode: resp.StatusCode}
	default:
		res.Outcome = ProbeFailed
		res.Err = &APIError{StatusCode: resp.StatusCode}
	}
	return res
}
