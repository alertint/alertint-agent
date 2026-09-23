// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"errors"
)

// RequestStartStatus records whether a one-shot Complete call (CompleteOnce)
// proved, disproved, or left ambiguous that a physical HTTP request actually
// reached the provider. It mirrors internal/situation/model.
// ProviderRequestStarted's three-value vocabulary exactly — this package is
// the transport-neutral producer of that fact, situation/model's type is the
// persisted projection of it — but is declared independently here so
// internal/llm never imports internal/situation/model (this package sits
// below internal/situation in the dependency graph; every provider client
// already imports it).
type RequestStartStatus string

const (
	// RequestStartStatusTrue means a response — success or any non-2xx
	// status, malformed body, or truncation — proves the request physically
	// reached the provider and a reply came back.
	RequestStartStatusTrue RequestStartStatus = "true"
	// RequestStartStatusFalse means the failure is proved to have happened
	// before any physical HTTP request left the process (request-body
	// marshal or http.Request construction failed) — the call was never
	// attempted.
	RequestStartStatusFalse RequestStartStatus = "false"
	// RequestStartStatusUnknown means the underlying http.Client.Do call
	// itself failed (network error, timeout, connection reset, TLS
	// failure, ...) — genuinely ambiguous whether the request reached the
	// provider before the failure.
	RequestStartStatusUnknown RequestStartStatus = "unknown"
)

// OneShotCompletion is CompleteOnce's result: the same Completion shape
// Complete returns, plus RequestStarted — the fact a one-shot caller (Plan
// 2's Situation controller) needs to record durably on its own immutable
// attempt outcome row, since CompleteOnce never itself persists anything.
type OneShotCompletion struct {
	Completion

	RequestStarted RequestStartStatus
}

// ErrRequestNotSent marks a failure proved to have occurred before any
// physical HTTP request left the process: request-body marshaling or
// http.Request construction failed. A provider client's doRequest wraps
// exactly those two failure sites with this sentinel (and no other); every
// later failure site (the http.Client.Do round trip itself, response
// reading, decoding, or shape/schema checks) leaves it unwrapped, so
// ClassifyRequestStart can tell "never sent" apart from "sent, but the
// outcome afterward is uncertain or a real response".
var ErrRequestNotSent = errors.New("llm: request not sent")

// ClassifyRequestStart maps a CompleteOnce (or, hypothetically, Complete)
// outcome error onto the closed RequestStartStatus vocabulary a provider
// client's CompleteOnce uses to fill OneShotCompletion.RequestStarted:
//
//   - nil, a *RetryableError, a *APIError, or an error wrapping
//     ErrResponseInvalid/ErrResponseTruncated/ErrSchemaViolation all prove a
//     response — success or failure — actually came back from the provider,
//     so they map to RequestStartStatusTrue;
//   - an error wrapping ErrRequestNotSent proves the request was never
//     attempted, so it maps to RequestStartStatusFalse;
//   - anything else (in practice: the raw http.Client.Do failure a
//     doRequest leaves unwrapped) is a genuinely ambiguous transport
//     failure and maps to RequestStartStatusUnknown.
func ClassifyRequestStart(err error) RequestStartStatus {
	if err == nil {
		return RequestStartStatusTrue
	}
	if errors.Is(err, ErrRequestNotSent) {
		return RequestStartStatusFalse
	}
	var retry *RetryableError
	if errors.As(err, &retry) {
		return RequestStartStatusTrue
	}
	var api *APIError
	if errors.As(err, &api) {
		return RequestStartStatusTrue
	}
	if errors.Is(err, ErrResponseInvalid) || errors.Is(err, ErrResponseTruncated) || errors.Is(err, ErrSchemaViolation) {
		return RequestStartStatusTrue
	}
	return RequestStartStatusUnknown
}
