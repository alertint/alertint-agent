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
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
)

type smallReadsCase struct {
	name                                    string
	resolved, inactive, missing             bool
	noName, otherSource, longLabels         bool
	budget, limit, primaryCount             int
	wantRequests, wantPrimary, wantReturned int
	wantCode                                string
}

type smallReadsCapture struct {
	calls       int
	queries     []string
	queryLimits []int
	bodyBytes   []int
}

// Regressions for an exporter-sized matrix, including the planner-to-connector
// path after a resolved delivery. The HTTP fixture honors Prometheus's series
// limit, but the real client still enforces the independent response byte cap.
func TestPrometheusSmallReadsPreservePrimaryHistoryAndHonestCoverage(t *testing.T) {
	for _, tc := range []smallReadsCase{
		{name: "firing", wantRequests: 3, wantPrimary: 4, wantReturned: 36, wantCode: "truncated"},
		{name: "source stopped firing", inactive: true, wantRequests: 3, wantPrimary: 4, wantReturned: 36, wantCode: "rule_metrics_current_definition_hint"},
		{name: "resolved delivery", resolved: true, inactive: true, wantRequests: 3, wantPrimary: 4, wantReturned: 36, wantCode: "rule_metrics_current_definition_hint"},
		{name: "missing rule", missing: true, wantRequests: 2, wantReturned: 32, wantCode: "rule_metrics_rule_not_found"},
		{name: "old one-call plan", budget: 1, wantRequests: 1, wantReturned: 32, wantCode: "rule_metrics_withheld_by_budget"},
		{name: "no rule name", noName: true, wantRequests: 1, wantReturned: 32, wantCode: "truncated"},
		{name: "non-alertmanager limit unchanged", otherSource: true, wantRequests: 1, wantCode: "response_too_large"},
		{name: "small plan budget", limit: 5, wantRequests: 3, wantPrimary: 4, wantReturned: 5, wantCode: "truncated"},
		{name: "primary is not background capped", primaryCount: 40, wantRequests: 3, wantPrimary: 40, wantReturned: -1, wantCode: "truncated"},
		{name: "large labels still respect byte cap", noName: true, longLabels: true, wantRequests: 1, wantCode: "response_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
			srv, got := newSmallReadsServer(t, tc, anchor)
			defer srv.Close()
			source := "alertmanager"
			if tc.otherSource {
				source = "local"
			}
			labels := map[string]string{"alertname": "ReplicationFailed"}
			if tc.noName {
				labels = nil
			}
			limit := 1000
			if tc.limit > 0 {
				limit = tc.limit
			}
			plans, _, err := observation.BuildPlans(observation.PlannerInput{
				Anchor: anchor, GroupKey: "job=windows", Phase: model.PhaseAssessment, CycleCap: 3,
				Members:    []observation.MemberSubject{{SubjectID: "exchange01", Source: source, Firing: !tc.resolved, Labels: labels, SelectorLabels: map[string]string{"cluster": "prod", "instance": "exchange01", "job": "windows"}}},
				Configured: []observation.CapabilityDescriptor{{Capability: model.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: limit, MaxRequestsHint: 3}},
			})
			if err != nil || len(plans) != 1 {
				t.Fatalf("plans=%v err=%v", plans, err)
			}
			plan := plans[0]
			plan.ID, plan.CycleID = "plan:small-reads", "cycle:small-reads"
			if tc.budget > 0 {
				plan.MaxRequests = tc.budget
			}
			rec := &capturingRecorder{denyAfter: 3}
			run, err := (&PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL}), Clock: func() time.Time { return anchor }}).Execute(context.Background(), plan, rec)
			if err != nil {
				t.Fatal(err)
			}
			if got.calls != tc.wantRequests || rec.reservations != got.calls || len(rec.outcomes) != got.calls {
				t.Fatalf("requests=%d reservations=%d outcomes=%v", got.calls, rec.reservations, rec.codes())
			}
			if !slices.Contains(run.LimitationCodes, tc.wantCode) || run.Coverage.Complete {
				t.Fatalf("coverage=%+v limitations=%v", run.Coverage, run.LimitationCodes)
			}
			primaryKept := smallReadsPrimaryCount(t, run)
			if primaryKept != tc.wantPrimary {
				t.Fatalf("retained primary=%d want %d", primaryKept, tc.wantPrimary)
			}
			if tc.wantReturned >= 0 && run.Coverage.Returned != tc.wantReturned {
				t.Fatalf("retained=%d want %d", run.Coverage.Returned, tc.wantReturned)
			}
			if tc.wantReturned > 0 && run.Coverage.Omitted < 1 {
				t.Fatal("sampled collection omitted overflow count")
			}
			if tc.wantPrimary > 0 && got.queryLimits[0] != limit+1 {
				t.Fatalf("primary limit reduced: %v", got.queryLimits)
			}
			if tc.wantPrimary > 0 && !strings.Contains(got.queries[len(got.queries)-1], `__name__!~`) {
				t.Fatalf("diagnostics repeated primary: %v", got.queries)
			}
			t.Logf("retained=%d primary=%d bytes=%v query_limits=%v", run.Coverage.Returned, primaryKept, got.bodyBytes, got.queryLimits)
		})
	}
}

func newSmallReadsServer(t *testing.T, tc smallReadsCase, anchor time.Time) (*httptest.Server, *smallReadsCapture) {
	t.Helper()
	got := &smallReadsCapture{}
	primaryCount := 4
	if tc.primaryCount > 0 {
		primaryCount = tc.primaryCount
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/rules" {
			if tc.missing {
				_, _ = fmt.Fprint(w, `{"status":"success","data":{"groups":[]}}`)
				return
			}
			alerts := `[{"state":"firing","labels":{"cluster":"prod","instance":"exchange01","job":"windows"}}]`
			if tc.inactive {
				alerts = `[]`
			}
			_, _ = fmt.Fprintf(w, `{"status":"success","data":{"groups":[{"rules":[{"type":"alerting","name":"ReplicationFailed","query":"z_replication_failed > 0","alerts":%s}]}]}}`, alerts)
			return
		}
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		expr := q.Get("query")
		got.queries = append(got.queries, expr)
		for _, matcher := range []string{`cluster="prod"`, `instance="exchange01"`, `job="windows"`} {
			if !strings.Contains(expr, matcher) {
				t.Errorf("scope lost from %s", expr)
			}
		}
		if q.Get("step") != "30s" || q.Get("start") != "1792062000.000" || q.Get("end") != "1792065600.000" {
			t.Errorf("window/resolution changed: %v", q)
		}
		limit, err := strconv.Atoi(q.Get("limit"))
		if err != nil {
			t.Errorf("missing series limit: %v", q)
		}
		got.queryLimits = append(got.queryLimits, limit)
		primary := strings.Contains(expr, `__name__=~`)
		count, name := 800, "a_diagnostic_metric"
		if primary {
			count, name = primaryCount, "z_replication_failed"
		}
		if tc.longLabels {
			count = 40
		}
		count = min(count, limit)
		series := make([]any, 0, count)
		for i := 0; i < count; i++ {
			labels := map[string]string{"__name__": name, "cluster": "prod", "instance": "exchange01", "job": "windows", "component": fmt.Sprintf("component-%04d", i)}
			if tc.longLabels {
				labels["description"] = strings.Repeat("x", 40000)
			}
			values := make([][2]any, 0, 121)
			for j := 0; j < 121; j++ {
				value := "12345.123456789"
				if primary {
					value = "0"
					if j == 61 {
						value = "100"
					}
				}
				values = append(values, [2]any{anchor.Add(-time.Hour + time.Duration(j)*30*time.Second).Unix(), value})
			}
			series = append(series, map[string]any{"metric": labels, "values": values})
		}
		body, err := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": series}})
		if err != nil {
			t.Error(err)
			return
		}
		got.bodyBytes = append(got.bodyBytes, len(body))
		_, _ = w.Write(body)
	}))
	return srv, got
}

func smallReadsPrimaryCount(t *testing.T, run model.Run) int {
	t.Helper()
	primaryKept := 0
	for _, fact := range run.Facts {
		if len(fact.Value) > model.MaxFactBytes {
			t.Fatal("summary cap exceeded")
		}
		var summary metricSummary
		if err := json.Unmarshal(fact.Value, &summary); err != nil {
			t.Fatal(err)
		}
		for _, s := range summary.Series {
			if s.Labels["__name__"] == "z_replication_failed" {
				primaryKept++
				if s.SampleCount != 121 || s.Max != 100 || s.Last != 0 {
					t.Fatalf("primary history lost: %+v", s)
				}
			}
		}
	}
	return primaryKept
}
