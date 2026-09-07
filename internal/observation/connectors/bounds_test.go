// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/logs/loki"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// capturingRecorder records every reservation and outcome so a test can
// assert exactly which closed outcome codes a connector reported.
type capturingRecorder struct {
	reservations int
	outcomes     []model.RequestOutcome
	denyAfter    int // reservations beyond this many fail with ErrBudgetExhausted (0 = unlimited)
}

func (r *capturingRecorder) BeforeRequest(ctx context.Context) (model.RequestReservation, error) {
	if r.denyAfter > 0 && r.reservations >= r.denyAfter {
		return model.RequestReservation{}, model.ErrBudgetExhausted
	}
	r.reservations++
	return model.RequestReservation{ID: "res-" + string(rune('0'+r.reservations))}, nil
}

func (r *capturingRecorder) AfterRequest(ctx context.Context, outcome model.RequestOutcome) error {
	r.outcomes = append(r.outcomes, outcome)
	return nil
}

func (r *capturingRecorder) codes() []string {
	out := make([]string, 0, len(r.outcomes))
	for _, o := range r.outcomes {
		out = append(out, o.Code)
	}
	return out
}

func TestOutcomeCodeClosedVocabulary(t *testing.T) {
	cases := map[string]error{
		outcomeOK:               nil,
		outcomeTransportFailure: errors.New("dial tcp: refused"),
		outcomeResponseTooLarge: prometheus.ErrResponseTooLarge,
	}
	for want, err := range cases {
		if got := outcomeCode(err); got != want {
			t.Fatalf("outcomeCode(%v) = %q, want %q", err, got, want)
		}
	}
	for _, err := range []error{loki.ErrResponseTooLarge, sentry.ErrResponseTooLarge, zabbix.ErrResponseTooLarge} {
		if !isResponseTooLarge(err) || outcomeCode(err) != outcomeResponseTooLarge {
			t.Fatalf("%v must classify as response_too_large", err)
		}
	}
}

func TestFitFactValueKeepsLargestFittingPrefix(t *testing.T) {
	item := strings.Repeat("x", 1000)
	marshal := func(n int) ([]byte, error) {
		items := make([]string, n)
		for i := range items {
			items[i] = item
		}
		return json.Marshal(items)
	}
	// 40 x ~1 KiB items exceed the 16 KiB cap; the fit must be the largest
	// prefix that still fits, found deterministically.
	value, kept, err := fitFactValue(40, marshal)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) > model.MaxFactBytes {
		t.Fatalf("fitted value is %d bytes, over the %d cap", len(value), model.MaxFactBytes)
	}
	if kept <= 0 || kept >= 40 {
		t.Fatalf("kept = %d, want a strict non-empty prefix", kept)
	}
	next, err := marshal(kept + 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) <= model.MaxFactBytes {
		t.Fatalf("prefix %d also fits (%d bytes): fit is not the largest", kept+1, len(next))
	}
	// Twice the same input → the same prefix (determinism).
	again, keptAgain, err := fitFactValue(40, marshal)
	if err != nil || keptAgain != kept || string(again) != string(value) {
		t.Fatalf("fit is not deterministic: kept %d vs %d", keptAgain, kept)
	}
	// Something that already fits is returned whole.
	whole, keptWhole, err := fitFactValue(3, marshal)
	if err != nil || keptWhole != 3 || len(whole) > model.MaxFactBytes {
		t.Fatalf("small collection must be kept whole: kept=%d err=%v", keptWhole, err)
	}
}

func TestFitFactValueErrorsWhenEvenEmptyDoesNotFit(t *testing.T) {
	huge := strings.Repeat("y", model.MaxFactBytes+1)
	_, _, err := fitFactValue(2, func(int) ([]byte, error) { return json.Marshal(huge) })
	if err == nil {
		t.Fatal("expected an error when no prefix fits — a fact must never exceed the cap")
	}
}

func TestBoundedRunStatusAndCoverage(t *testing.T) {
	plan := testStorePlan()
	value := []byte(`{"x":1}`)

	complete := boundedRun(plan, plan.End, boundedResult{Kind: "k", Value: value, Returned: 2})
	if complete.Status != model.ResultConfirmedValue || !complete.Coverage.Complete || len(complete.LimitationCodes) != 0 {
		t.Fatalf("complete run = %+v", complete)
	}
	empty := boundedRun(plan, plan.End, boundedResult{Kind: "k", Value: value})
	if empty.Status != model.ResultConfirmedEmpty {
		t.Fatalf("empty status = %q", empty.Status)
	}
	truncated := boundedRun(plan, plan.End, boundedResult{Kind: "k", Value: value, Returned: 2, Omitted: 1, Truncated: true})
	if truncated.Status != model.ResultTruncated || truncated.Coverage.Complete || truncated.Coverage.Omitted != 1 {
		t.Fatalf("truncated run = %+v", truncated)
	}
	if got := truncated.LimitationCodes; len(got) != 1 || got[0] != limitationTruncated {
		t.Fatalf("limitation codes = %v", got)
	}
	capped := boundedRun(plan, plan.End, boundedResult{Kind: "k", Value: value, Returned: 2, Omitted: 3, Capped: true, ExtraLimitations: []string{"recovery_unknown"}})
	if capped.Status != model.ResultTruncated || capped.Coverage.Complete {
		t.Fatalf("capped run = %+v", capped)
	}
	if got := capped.LimitationCodes; len(got) != 2 || got[0] != limitationFactBytesCapped || got[1] != "recovery_unknown" {
		t.Fatalf("limitation codes = %v", got)
	}
	if len(capped.Facts) != 1 || capped.Facts[0].ResultStatus != model.ResultTruncated {
		t.Fatalf("fact = %+v", capped.Facts)
	}
}

func TestResponseTooLargeRunCarriesNoData(t *testing.T) {
	plan := testStorePlan()
	run := responseTooLargeRun(plan, plan.End, plan.End)
	if run.Status != model.ResultTruncated || run.Coverage.Complete || len(run.Facts) != 0 {
		t.Fatalf("run = %+v", run)
	}
	if len(run.LimitationCodes) != 1 || run.LimitationCodes[0] != limitationResponseTooLarge {
		t.Fatalf("limitation codes = %v", run.LimitationCodes)
	}
}
