// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
)

type cappedRecorder struct {
	capturingRecorder

	cap int
}

func (r *cappedRecorder) BeforeRequest(ctx context.Context) (model.RequestReservation, error) {
	if r.reservations >= r.cap {
		return model.RequestReservation{}, model.ErrBudgetExhausted
	}
	return r.capturingRecorder.BeforeRequest(ctx)
}

func TestPrometheusPriorityRetainsAlertMetricAndReportsIncompleteDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		cap                             int
		oversized, unavailable          bool
		rulesOversized                  bool
		limit, planBudget               int
		emptyPrimary, diagnosticsFailed bool
		code                            string
	}{
		{name: "summary cap", cap: 3, code: "fact_bytes_capped"},
		{name: "diagnostic response too large", cap: 3, oversized: true, code: "response_too_large"},
		{name: "diagnostic budget exhausted", cap: 2, code: "diagnostics_withheld_by_budget"},
		{name: "unavailable rules bounded fallback", cap: 3, unavailable: true, code: "rule_metrics_api_unavailable"},
		{name: "oversized rules bounded fallback", cap: 3, unavailable: true, rulesOversized: true, code: "rule_metrics_response_too_large"},
		{name: "priority uses series budget", cap: 3, limit: 1, code: "diagnostics_withheld_by_series_limit"},
		{name: "old one-call plan fallback", cap: 1, planBudget: 1, unavailable: true, code: "rule_metrics_withheld_by_budget"},
		{name: "empty priority collects diagnostics", cap: 3, emptyPrimary: true, code: "rule_metrics_empty"},
		{name: "diagnostic HTTP failure", cap: 3, diagnosticsFailed: true, code: "diagnostics_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v1/rules" {
					if tc.rulesOversized {
						_, _ = fmt.Fprintf(w, `{"status":"success","data":{"pad":%q}}`, strings.Repeat("p", model.MaxDecodedResponseBytes))
						return
					}
					if tc.unavailable {
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
						return
					}
					_, _ = fmt.Fprint(w, `{"status":"success","data":{"groups":[{"name":"exchange","rules":[{"type":"alerting","name":"ReplicationFailed","query":"z_exchange_replication_failed > 0","alerts":[{"state":"firing","labels":{"job":"windows","instance":"exchange01","cluster":"prod"}}]}]}]}}`)
					return
				}
				query := r.URL.Query().Get("query")
				queries = append(queries, query)
				for _, scope := range []string{`cluster="prod"`, `instance="exchange01"`, `job="windows"`} {
					if !strings.Contains(query, scope) {
						t.Errorf("scope lost: %s", query)
					}
				}
				if strings.Contains(query, `__name__=~`) {
					if tc.emptyPrimary {
						_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
						return
					}
					_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"z_exchange_replication_failed","instance":"exchange01"},"values":[[1,"1"]]}]}}`)
					return
				}
				if tc.oversized {
					_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[],"pad":%q}}`, strings.Repeat("p", model.MaxDecodedResponseBytes))
					return
				}
				if tc.diagnosticsFailed {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				var series []any
				for i := 0; i < 200; i++ {
					series = append(series, map[string]any{"metric": map[string]string{"__name__": "a_cpu_metric", "core": fmt.Sprint(i), "pad": strings.Repeat("p", 600)}, "values": [][2]any{{1, "1"}}})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": series}})
			}))
			defer srv.Close()
			plan := testStorePlan()
			plan.Capability = model.CapabilityPrometheusQuery
			plan.Scope.Source = "alertmanager"
			plan.Scope.Labels = map[string]string{"job": "windows", "instance": "exchange01", "cluster": "prod"}
			plan.Limit = 1000
			plan.MaxRequests = 3
			if tc.planBudget > 0 {
				plan.MaxRequests = tc.planBudget
			}
			if tc.limit > 0 {
				plan.Limit = tc.limit
			}
			plan.Parameters = json.RawMessage(`{"alert_name":"ReplicationFailed"}`)
			rec := &cappedRecorder{cap: tc.cap}
			run, err := (&PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL})}).Execute(context.Background(), plan, rec)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(run.LimitationCodes, tc.code) {
				t.Fatalf("limitations=%v want %s", run.LimitationCodes, tc.code)
			}
			if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
				t.Fatalf("facts=%v", run.Facts)
			}
			if !tc.unavailable && !tc.emptyPrimary && !strings.Contains(string(run.Facts[0].Value), "z_exchange_replication_failed") {
				t.Fatalf("priority metric discarded: %s", run.Facts[0].Value)
			}
			if run.Coverage.Complete || run.Status != model.ResultTruncated {
				t.Fatalf("incomplete diagnostics reported complete: %+v", run.Coverage)
			}
			if rec.reservations > tc.cap || len(rec.codes()) != rec.reservations {
				t.Fatalf("request accounting: %+v", rec)
			}
			if tc.unavailable && len(queries) != 1 {
				t.Fatalf("fallback queries=%v", queries)
			}
			if !tc.unavailable && len(queries) > 1 && !strings.Contains(queries[1], `__name__!~`) {
				t.Fatalf("diagnostics must exclude priority metrics: %v", queries)
			}
		})
	}
}
