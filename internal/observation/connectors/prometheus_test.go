// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

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
