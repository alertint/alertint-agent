// SPDX-License-Identifier: FSL-1.1-ALv2

// Package llmhealth owns installation-level LLM dependency health: capability
// observations from real triage calls, an idle zero-generation probe, a
// durable neutral aggregate, and one Slack system message per sustained
// episode. It sits below Acute Triage and never imports the Situation package.
package llmhealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/alertint/alertint-agent/internal/llm"
)

// Capability is one distinct use the agent makes of the LLM, each with its
// own health that only its own success can clear (CONTEXT.md: LLM capability).
type Capability string

const (
	CapabilityTriageDraft         Capability = "triage_draft"
	CapabilityVerificationRejudge Capability = "verification_rejudge"
	CapabilityMemoryClassifier    Capability = "memory_classifier"
	CapabilityProbe               Capability = "probe"
)

// Reason names why one call outcome was recorded, from success through every
// distinguished failure shape.
type Reason string

const (
	ReasonOK                  Reason = "ok"
	ReasonCanceled            Reason = "canceled"
	ReasonTimeout             Reason = "timeout"
	ReasonNetwork             Reason = "network"
	ReasonRateLimited         Reason = "rate_limited"
	ReasonProviderUnavailable Reason = "provider_unavailable"
	ReasonAuthFailed          Reason = "auth_failed"
	ReasonRequestInvalid      Reason = "request_invalid"
	ReasonSchemaViolation     Reason = "schema_violation"
	ReasonResponseMalformed   Reason = "response_malformed"
	ReasonUnknown             Reason = "unknown"
)

// Class groups reasons by what they say about the dependency. Dependency-class
// failures mark a capability unhealthy at once; content-class failures may be
// one bad Incident and need corroboration (see Tracker).
type Class int

const (
	ClassOK Class = iota
	ClassIgnored
	ClassDependency
	ClassContent
)

// ErrResponseMalformed is wrapped by Acute Triage when Complete succeeded but
// the typed JSON decode of the reply failed.
var ErrResponseMalformed = errors.New("llmhealth: response malformed")

// llmOriginError marks an error as having come out of an LLM call. It is
// transparent to Classify and errors.Is/As (Unwrap exposes the original), and
// exists only so a consumer that sees a whole-invocation error (the Correlator
// sees Acute Triage's entire sink error, not just the Complete result) can
// tell an LLM timeout/network failure from an identically-shaped one raised
// by SQLite or a metrics/log-source fetch.
type llmOriginError struct{ err error }

func (e *llmOriginError) Error() string { return e.err.Error() }
func (e *llmOriginError) Unwrap() error { return e.err }

// MarkLLMOrigin wraps err as LLM-origin. nil stays nil so a success path
// needs no branch. Acute Triage applies it at its Complete boundary before
// propagating the failure.
func MarkLLMOrigin(err error) error {
	if err == nil {
		return nil
	}
	return &llmOriginError{err: err}
}

// IsLLMOrigin reports whether err (or anything it wraps) was marked by
// MarkLLMOrigin.
func IsLLMOrigin(err error) bool {
	var o *llmOriginError
	return errors.As(err, &o)
}

// Classify maps an error from an LLM call (transport, provider, schema, or
// typed-decode) onto a stable Reason. nil maps to ReasonOK.
func Classify(err error) Reason {
	if err == nil {
		return ReasonOK
	}
	if errors.Is(err, context.Canceled) {
		return ReasonCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTimeout
	}
	var retry *llm.RetryableError
	if errors.As(err, &retry) {
		if retry.StatusCode == http.StatusTooManyRequests {
			return ReasonRateLimited
		}
		return ReasonProviderUnavailable
	}
	var api *llm.APIError
	if errors.As(err, &api) {
		switch {
		case api.StatusCode == http.StatusUnauthorized || api.StatusCode == http.StatusForbidden:
			return ReasonAuthFailed
		case api.StatusCode == http.StatusTooManyRequests:
			return ReasonRateLimited
		case api.StatusCode >= http.StatusInternalServerError:
			return ReasonProviderUnavailable
		default:
			return ReasonRequestInvalid
		}
	}
	if errors.Is(err, ErrResponseMalformed) {
		return ReasonResponseMalformed
	}
	if errors.Is(err, llm.ErrSchemaViolation) || errors.Is(err, llm.ErrResponseTruncated) || errors.Is(err, llm.ErrResponseInvalid) {
		return ReasonSchemaViolation
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) {
		return ReasonNetwork
	}
	return ReasonUnknown
}

// Class reports which broad group r belongs to.
func (r Reason) Class() Class {
	switch r {
	case ReasonOK:
		return ClassOK
	case ReasonCanceled:
		return ClassIgnored
	case ReasonRequestInvalid, ReasonSchemaViolation, ReasonResponseMalformed:
		return ClassContent
	case ReasonTimeout, ReasonNetwork, ReasonRateLimited, ReasonProviderUnavailable, ReasonAuthFailed, ReasonUnknown:
		return ClassDependency
	default:
		return ClassDependency
	}
}

// SafeDetail renders a short, provider-text-free explanation from the error's
// class and HTTP status only. It is the ONLY detail string ever persisted or
// sent to Slack; err.Error() is for logs.
func SafeDetail(err error) string {
	switch Classify(err) {
	case ReasonOK:
		return ""
	case ReasonCanceled:
		return "canceled"
	case ReasonTimeout:
		return "request timed out"
	case ReasonNetwork:
		return "network error"
	case ReasonSchemaViolation:
		return "schema violation"
	case ReasonResponseMalformed:
		return "typed response malformed"
	case ReasonRateLimited, ReasonProviderUnavailable, ReasonAuthFailed, ReasonRequestInvalid, ReasonUnknown:
		// Falls through to the HTTP-status formatting below.
	}
	var retry *llm.RetryableError
	if errors.As(err, &retry) {
		return fmt.Sprintf("HTTP %d", retry.StatusCode)
	}
	var api *llm.APIError
	if errors.As(err, &api) {
		return fmt.Sprintf("HTTP %d", api.StatusCode)
	}
	return "unclassified error"
}
