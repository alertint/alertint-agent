// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/logs/loki"
	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// Request outcome codes — the closed vocabulary every connector records on
// model.RequestOutcome.Code (never a provider's raw error text):
//
//   - ok: the request completed and its body was decoded within limits.
//   - transport_failure: any other network/API/decode failure.
//   - response_too_large: the DECODED body exceeded
//     model.MaxDecodedResponseBytes; the connector persists a truncated,
//     incomplete run with NO data from that response (F10).
//   - redirect_refused: the source answered 3xx; the bounded path never
//     follows it (that would be a second, unreserved physical request), so
//     the plan fails with exactly one dispatch accounted for (F19).
const (
	outcomeOK               = "ok"
	outcomeTransportFailure = "transport_failure"
	outcomeResponseTooLarge = "response_too_large"
	outcomeRedirectRefused  = "redirect_refused"
)

// Limitation codes shared across connectors (per-connector ones such as
// recovery_unknown live next to their executor).
const (
	limitationTruncated        = "truncated"
	limitationResponseTooLarge = "response_too_large"
	limitationFactBytesCapped  = "fact_bytes_capped"
)

// outcomeCode classifies one physical request's error into the closed
// outcome vocabulary above.
func outcomeCode(err error) string {
	switch {
	case err == nil:
		return outcomeOK
	case isResponseTooLarge(err):
		return outcomeResponseTooLarge
	case isRedirectRefused(err):
		return outcomeRedirectRefused
	default:
		return outcomeTransportFailure
	}
}

// isRedirectRefused reports whether err is any transport package's
// refused-redirect sentinel.
func isRedirectRefused(err error) bool {
	return errors.Is(err, prometheus.ErrRedirectRefused) ||
		errors.Is(err, loki.ErrRedirectRefused) ||
		errors.Is(err, sentry.ErrRedirectRefused) ||
		errors.Is(err, zabbix.ErrRedirectRefused)
}

// isResponseTooLarge reports whether err is any transport package's
// bounded-body sentinel. The transport packages cannot share one sentinel
// (this package imports them, never the reverse), so the shared check lives
// here.
func isResponseTooLarge(err error) bool {
	return errors.Is(err, prometheus.ErrResponseTooLarge) ||
		errors.Is(err, loki.ErrResponseTooLarge) ||
		errors.Is(err, sentry.ErrResponseTooLarge) ||
		errors.Is(err, zabbix.ErrResponseTooLarge)
}

// requestHooks builds a before/after pair bridging observation.RequestRecorder
// into the transport clients' own before()/after(started, err)
// instrumentation shape. The returned bool pointer is set true if any
// BeforeRequest call fails with model.ErrBudgetExhausted, so the caller can
// distinguish "withheld by budget" from a real transport failure after the
// client call returns.
func requestHooks(ctx context.Context, recorder observation.RequestRecorder, clock func() time.Time) (func() error, func(started bool, err error), *bool) {
	var lastReservationID string
	budgetExhausted := new(bool)
	before := func() error {
		r, err := recorder.BeforeRequest(ctx)
		if err != nil {
			if errors.Is(err, model.ErrBudgetExhausted) {
				*budgetExhausted = true
			}
			return err
		}
		lastReservationID = r.ID
		return nil
	}
	after := func(started bool, callErr error) {
		s := model.RequestStartedTrue
		if !started {
			s = model.RequestStartedFalse
		}
		_ = recorder.AfterRequest(ctx, model.RequestOutcome{
			ReservationID: lastReservationID, RequestStarted: s, Code: outcomeCode(callErr), CompletedAt: clock(),
		})
	}
	return before, after, budgetExhausted
}

// responseTooLargeRun is the honest run for a response the bounded
// transport refused to buffer: truncated, incomplete, no facts — never a
// partial decode of an over-limit body.
func responseTooLargeRun(plan model.Plan, now, expiresAt time.Time) model.Run {
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: model.ResultTruncated,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: false},
		LimitationCodes: []string{limitationResponseTooLarge},
		ObservedAt:      now, ExpiresAt: expiresAt,
	}
}

// boundedResult is one connector's normalized, already byte-capped result
// for boundedRun: the single fact's kind and value, how many source rows
// the value represents (Returned) versus were left out (Omitted), and the
// two independent reasons the run is not complete — Truncated (the source
// returned more than Plan.Limit, or reported more pages) and Capped (the
// fact value had to be shrunk to fit model.MaxFactBytes).
type boundedResult struct {
	Kind      string
	Value     []byte
	Returned  int
	Omitted   int
	Truncated bool
	Capped    bool
	// ExtraLimitations are connector-specific codes appended after the
	// shared truncated/fact_bytes_capped ones (e.g. recovery_unknown).
	ExtraLimitations []string
	ExpiresAt        time.Time
}

// boundedRun assembles the one-fact Run every external-source connector
// persists: confirmed_value / confirmed_empty when complete, truncated when
// the source or the fact-byte cap left rows out. Coverage.Complete is only
// ever true when neither applied — a hard cap is never completeness proof.
func boundedRun(plan model.Plan, now time.Time, r boundedResult) model.Run {
	status := model.ResultConfirmedEmpty
	if r.Returned > 0 {
		status = model.ResultConfirmedValue
	}
	var limitationCodes []string
	if r.Truncated {
		status = model.ResultTruncated
		limitationCodes = append(limitationCodes, limitationTruncated)
	}
	if r.Capped {
		status = model.ResultTruncated
		limitationCodes = append(limitationCodes, limitationFactBytesCapped)
	}
	limitationCodes = append(limitationCodes, r.ExtraLimitations...)

	fact := model.Fact{
		ID: factID(plan.ID, r.Kind, r.Value), RunID: "run:" + plan.ID,
		Kind: r.Kind, Subject: plan.Scope.SubjectID, Digest: digestOf(r.Value),
		SchemaVersion: model.FactSchemaVersion, Value: r.Value,
		ResultStatus: status, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: r.ExpiresAt, Material: true,
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage: model.Coverage{
			Start: plan.Start, End: plan.End, Complete: !r.Truncated && !r.Capped,
			Returned: r.Returned, Omitted: r.Omitted,
		},
		Facts:           []model.Fact{fact},
		LimitationCodes: limitationCodes,
		ObservedAt:      now, ExpiresAt: r.ExpiresAt,
	}
}

// fitFactValue finds the largest prefix n (0 <= n <= count) of a
// canonically ordered collection whose marshalled fact value fits within
// model.MaxFactBytes, and returns that value with n. marshal(n) must render
// the value with only the first n items; because a shorter prefix never
// renders longer, a binary search over n is deterministic and exact. An
// error is returned only if even the empty collection does not fit — a
// fact is never emitted above the cap.
func fitFactValue(count int, marshal func(n int) ([]byte, error)) ([]byte, int, error) {
	value, err := marshal(count)
	if err != nil {
		return nil, 0, err
	}
	if len(value) <= model.MaxFactBytes {
		return value, count, nil
	}
	lo, hi := 0, count // invariant: hi never fits; search the largest fitting n in [lo, hi)
	var best []byte
	bestN := -1
	for lo < hi {
		mid := lo + (hi-lo)/2
		v, err := marshal(mid)
		if err != nil {
			return nil, 0, err
		}
		if len(v) <= model.MaxFactBytes {
			best, bestN = v, mid
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if bestN < 0 {
		return nil, 0, fmt.Errorf("connectors: fact value exceeds %d bytes even when empty", model.MaxFactBytes)
	}
	return best, bestN, nil
}
