// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
)

func TestPrometheusExecutorSendsExactSelectorAndOverflowLimit(t *testing.T) {
	var requests atomic.Int32
	var gotQuery, gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		gotQuery = r.URL.Query().Get("query")
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()

	client := prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	e := &PrometheusExecutor{Client: client}
	plan := testStorePlan()
	plan.Capability = "prometheus_query"
	plan.Scope.Labels = map[string]string{"cluster": "lab", "service": "checkout"}
	plan.Limit = 20

	rec := &noopRecorder{}
	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("physical requests = %d, want 1", requests.Load())
	}
	if gotQuery != `{cluster="lab",service="checkout"}` {
		t.Fatalf("query = %q, unexpected selector", gotQuery)
	}
	if gotLimit != strconv.Itoa(plan.Limit+1) {
		t.Fatalf("limit = %q, want %d (overflow sentinel)", gotLimit, plan.Limit+1)
	}
	if rec.calls != 2 {
		t.Fatalf("recorder calls = %d, want 2 (before+after)", rec.calls)
	}
	if run.Status == "" {
		t.Fatal("expected a result status")
	}
}

func TestPrometheusExecutorConfirmedEmptyOnEmptyMatrix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()

	client := prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	e := &PrometheusExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_empty" {
		t.Fatalf("status = %q, want confirmed_empty", run.Status)
	}
}

func TestPrometheusExecutorTruncatesOverLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 3 series returned though the plan's limit is 2 (limit+1=3 requested).
		body := `{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"a":"1"},"values":[[1,"1"]]},
			{"metric":{"a":"2"},"values":[[1,"2"]]},
			{"metric":{"a":"3"},"values":[[1,"3"]]}
		]}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	e := &PrometheusExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	plan.Limit = 2

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "truncated" {
		t.Fatalf("status = %q, want truncated", run.Status)
	}
	if len(run.LimitationCodes) == 0 {
		t.Fatal("expected a truncated limitation code")
	}
}

func TestPrometheusExecutorRejectsNonfiniteSamples(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"a":"1"},"values":[[1,"NaN"],[2,"5"]]}
		]}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	e := &PrometheusExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	var summary metricSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Series[0].AllFinite {
		t.Fatal("expected AllFinite=false when a NaN sample is present")
	}
	if summary.Series[0].FiniteCount != 1 {
		t.Fatalf("finite count = %d, want 1", summary.Series[0].FiniteCount)
	}
}

func TestPrometheusExecutorUnresolvedWithoutScopeLabels(t *testing.T) {
	e := &PrometheusExecutor{Client: nil}
	plan := testStorePlan()
	plan.Scope.Labels = nil

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

// TestPrometheusExecutorOversizedResponseIsTruncatedWithoutData proves an
// over-cap decoded body (F10) becomes a truncated, incomplete,
// response_too_large run with no facts — never an error, never partial data
// — and that the one physical request's outcome is recorded with the
// response_too_large code.
func TestPrometheusExecutorOversizedResponseIsTruncatedWithoutData(t *testing.T) {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[],"pad":"` + pad + `"}}`))
	}))
	defer srv.Close()

	e := &PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatalf("an over-limit response is a limitation, not an execution error: %v", err)
	}
	if requests.Load() != 1 || rec.reservations != 1 {
		t.Fatalf("physical=%d reservations=%d, want 1/1", requests.Load(), rec.reservations)
	}
	if got := rec.codes(); len(got) != 1 || got[0] != "response_too_large" {
		t.Fatalf("outcome codes = %v, want [response_too_large]", got)
	}
	if run.Status != model.ResultTruncated || run.Coverage.Complete {
		t.Fatalf("run status=%q complete=%v, want truncated/incomplete", run.Status, run.Coverage.Complete)
	}
	if len(run.LimitationCodes) != 1 || run.LimitationCodes[0] != "response_too_large" {
		t.Fatalf("limitation codes = %v, want [response_too_large]", run.LimitationCodes)
	}
	if len(run.Facts) != 0 {
		t.Fatalf("facts = %d, want none: no data from an unbounded response may be persisted", len(run.Facts))
	}
}

// TestPrometheusExecutorCapsFactBytes proves a fact is never emitted above
// model.MaxFactBytes: series are dropped deterministically from the tail
// of the canonical order, the run reports fact_bytes_capped, and coverage
// records the omission.
func TestPrometheusExecutorCapsFactBytes(t *testing.T) {
	// 60 series x ~500 bytes of labels each: far over the 16 KiB cap, well
	// under the request limit (plan.Limit = 80).
	var sb strings.Builder
	sb.WriteString(`{"status":"success","data":{"resultType":"matrix","result":[`)
	for i := 0; i < 60; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"metric":{"instance":"i%02d","pad":"%s"},"values":[[1,"1"]]}`, i, strings.Repeat("p", 480))
	}
	sb.WriteString(`]}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer srv.Close()

	e := &PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	plan.Limit = 80

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
		t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
	}
	if run.Status != model.ResultTruncated || run.Coverage.Complete {
		t.Fatalf("status=%q complete=%v, want truncated/incomplete when the fact was capped", run.Status, run.Coverage.Complete)
	}
	if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") {
		t.Fatalf("limitation codes = %v, want fact_bytes_capped", run.LimitationCodes)
	}
	if run.Coverage.Returned+run.Coverage.Omitted != 60 || run.Coverage.Omitted < 1 {
		t.Fatalf("coverage returned=%d omitted=%d, want them to sum to 60 with omitted >= 1", run.Coverage.Returned, run.Coverage.Omitted)
	}
	var summary metricSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Series) != run.Coverage.Returned {
		t.Fatalf("persisted series = %d, coverage returned = %d", len(summary.Series), run.Coverage.Returned)
	}
}
