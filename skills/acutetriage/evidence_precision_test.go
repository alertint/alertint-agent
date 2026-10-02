// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// Catch loss of constant metric names when changed series fill the snapshot cap.
func TestFetchMetrics_DiscoveryIncludesUnrankedMetrics(t *testing.T) {
	at := time.Now().UTC()
	series := []map[string]any{s(map[string]string{"__name__": "container_memory_usage_limit_bytes", "container_name": "worker"}, "104857600")}
	for i := 0; i < 12; i++ {
		series = append(series, s(map[string]string{"__name__": fmt.Sprintf("activity_%02d_total", i), "container_name": "worker"}, "10"))
	}
	f := &fakeProm{responses: map[string]json.RawMessage{`{container_name="worker"}`: vector(series...)}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1, MaxSeries: 100, LabelMap: map[string]string{"service": "container_name"}}, nil, []store.Alert{alert(map[string]string{"service": "worker"})}, at, "discovery", nil)
	raw, err := json.Marshal(enr)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		MetricNames []string `json:"metric_names"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.MetricNames) != 13 || saved.MetricNames[12] != "container_memory_usage_limit_bytes" {
		t.Fatalf("catalog missing constant metric: %s", raw)
	}
	for _, snap := range enr.Snapshots {
		if snap.Metric == "container_memory_usage_limit_bytes" {
			t.Fatal("fixture must put the constant outside ranked snapshots")
		}
	}
	var b strings.Builder
	renderMetrics(&b, enr)
	if !strings.Contains(b.String(), "container_memory_usage_limit_bytes") || !strings.Contains(b.String(), "bounded sample") {
		t.Fatalf("prompt lost bounded discovery: %s", b.String())
	}
	if len(f.calls) != 3 {
		t.Fatalf("discovery must reuse queries; got %v", f.calls)
	}
	// The saved catalog must feed exactly the same prompt after replay.
	var replay MetricEnrichment
	if err := json.Unmarshal(raw, &replay); err != nil {
		t.Fatal(err)
	}
	var replayed strings.Builder
	renderMetrics(&replayed, &replay)
	if replayed.String() != b.String() {
		t.Fatal("catalog replay differs")
	}
}

func TestFetchMetrics_DiscoveryBoundedAndOrderIndependent(t *testing.T) {
	names := make([]map[string]any, 0, 80)
	for i := 79; i >= 0; i-- {
		names = append(names, s(map[string]string{"__name__": fmt.Sprintf("observed_%02d", i), "service": "worker"}, "1"))
	}
	names = append(names, s(map[string]string{"__name__": "ALERTS", "service": "worker"}, "1"))
	for _, reverse := range []bool{false, true} {
		if reverse {
			for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
				names[i], names[j] = names[j], names[i]
			}
		}
		f := &fakeProm{responses: map[string]json.RawMessage{`{service="worker"}`: vector(names...)}}
		enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1, MaxSeries: 100}, nil, []store.Alert{alert(map[string]string{"service": "worker"})}, time.Now(), "bounded", nil)
		raw, err := json.Marshal(enr)
		if err != nil {
			t.Fatal(err)
		}
		var saved struct {
			MetricNames []string `json:"metric_names"`
		}
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		want := make([]string, 64)
		for i := range want {
			want[i] = fmt.Sprintf("observed_%02d", i)
		}
		if !reflect.DeepEqual(saved.MetricNames, want) {
			t.Fatalf("unbounded/unstable catalog: %s", raw)
		}
	}
}

func TestRunUpRatio_HealthScopeIsExplicit(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			queries := []string{}
			prom := fakeQuerier(func(expr string) (json.RawMessage, error) {
				queries = append(queries, expr)
				if empty {
					return vector(), nil
				}
				return instantScalar(t, "1"), nil
			})
			q := VerificationQuery{Kind: kindUpRatio, Source: "floor", Expr: `{container_name="worker",cluster="production"}`}
			runUpRatio(context.Background(), prom, &q, time.Now(), slog.Default(), "scope")
			want := []string{`sum(up{container_name="worker",cluster="production"})`, `count(up{container_name="worker",cluster="production"})`}
			if !reflect.DeepEqual(queries, want) {
				t.Fatalf("scope broadened: %v", queries)
			}
			if !strings.Contains(q.Result, "scrape") || !strings.Contains(q.Result, "application health unknown") || !strings.Contains(q.Result, `cluster="production"`) {
				t.Fatalf("health/source/scope unclear: %+v", q)
			}
			if empty && (q.Outcome != OutcomeEmpty || !strings.Contains(q.Result, "no matching scrape targets")) {
				t.Fatalf("empty scope must remain unknown: %+v", q)
			}
			if !empty && q.Outcome != OutcomeFetched {
				t.Fatalf("scrape result lost: %+v", q)
			}
		})
	}
}

func TestRunPromQL_BaseUnits(t *testing.T) {
	for _, tc := range []struct{ expr, value, want string }{
		{`rate(worker_cpu_usage_nanoseconds_total[5m])`, "23351256.140350875", `[nanoseconds per second] 23351256.140350875 (0.0233513 CPU cores) {}`},
		{`sum(rate(worker_cpu_usage_seconds_total[5m]))`, "0.02335", `[seconds per second] 0.02335 (0.02335 CPU cores) {}`},
		{`worker_memory_usage_bytes`, "442368", `[bytes] 442368 {}`},
		{`increase(http_request_duration_seconds_sum[5m])`, "3", `[seconds over 5m] 3 {}`},
		{`rate(payload_bytes_sum[5m])`, "400", `[bytes per second] 400 {}`},
		{`increase((sum(worker_memory_bytes))[15m:])`, "32", `[bytes over 15m] 32 {}`},
		{`rate((sum(worker_cpu_usage_seconds_total))[5m:])`, "0.2", `[seconds per second] 0.2 {}`},

		{`rate(worker_cpu_usage_nanoseconds_total[5m])`, "0.1", `[nanoseconds per second] 0.1 (1e-10 CPU cores) {}`},
		{`rate(worker_cpu_usage_nanoseconds_total[5m])`, "+Inf", `[nanoseconds per second] +Inf {}`},
		{`rate(worker_cpu_throttled_seconds_total[5m])`, "0.01", `[seconds per second] 0.01 {}`},
		{`irate(worker_cpu_usage_microseconds_total[5m])`, "100000", `[microseconds per second] 100000 (0.1 CPU cores) {}`},
		{`max(rate(worker_cpu_usage_milliseconds_total[5m])) > 10`, "100", `[milliseconds per second] 100 (0.1 CPU cores) {}`},
		{`container_memory_percent_ratio`, "92", `92 {}`},
		{`worker_percent_ratio_total`, "92", `92 {}`},
		{`rate(worker_percent_ratio_total[5m])`, "2", `[per second] 2 {}`},

		{`sum(increase(network_receive_bytes_total[15m]))`, "18000", `[bytes over 15m] 18000 {}`},
		{`rate(worker_cpu_usage_nanoseconds_total[5m]) > bool 0`, "1", `1 {}`},
		{`count(worker_memory_usage_bytes)`, "4", `4 {}`},

		{`rate(network_receive_bytes_total[5m])`, "1200", `[bytes per second] 1200 {}`},
		{`increase(network_receive_bytes_total[15m])`, "18000", `[bytes over 15m] 18000 {}`},
		{`worker_cpu_utilization_ratio`, "0.2", `[ratio] 0.2 {}`},
		{`service:worker_bytes`, "42", `42 {}`},
		{`rate(worker_cpu_usage_nanoseconds_total[5m]) * 60`, "42", `42 {}`},
		{`rate(network_receive_bytes_total[5m]) / rate(network_send_bytes_total[5m])`, "2", `2 {}`},
		{`stdvar(worker_memory_usage_bytes)`, "42", `42 {}`},
		{`rate(custom_unknown_total[5m])`, "2", `[per second] 2 {}`},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			prom := fakeQuerier(func(string) (json.RawMessage, error) { return vector(s(map[string]string{}, tc.value)), nil })
			q := VerificationQuery{Kind: kindPromQL, Source: "model", Expr: tc.expr}
			runPromQL(context.Background(), prom, &q, 100, time.Now(), slog.Default(), "units")
			if q.Result != tc.want || q.Outcome != OutcomeFetched {
				t.Fatalf("got %+v; want %q", q, tc.want)
			}
		})
	}
}

func TestRenderMetrics_BaseUnits(t *testing.T) {
	var b strings.Builder
	renderMetrics(&b, &MetricEnrichment{Snapshots: []MetricSnapshot{
		{Metric: "worker_memory_usage_bytes", Series: "{}", Value: "442368", Baseline: "400000"},
		{Metric: "worker_cpu_usage_nanoseconds_total", Series: "{}", Value: "1000000000", Increase: "23351256", PriorIncrease: "20000000"},
		{Metric: "custom_gauge", Series: "{}", Value: "7"},
	}})
	if !strings.Contains(b.String(), "442368 [bytes]") || !strings.Contains(b.String(), "1000000000 [nanoseconds]") || strings.Contains(b.String(), "custom_gauge{} = 7 [") {
		t.Fatalf("snapshot units missing/guessed: %s", b.String())
	}
}

// The intermediate catalog must stay bounded even if a provider ignores its cap.
func TestCollectMetricNames_BoundsWorkingSet(t *testing.T) {
	series := make([]map[string]any, 0, 1000)
	for i := 999; i >= 0; i-- {
		series = append(series, s(map[string]string{"__name__": fmt.Sprintf("observed_%04d", i)}, "1"))
	}
	names := make(map[string]bool)
	collectMetricNames(vector(series...), names)
	if len(names) != 64 || !names["observed_0000"] || !names["observed_0063"] || names["observed_0064"] {
		t.Fatalf("working set unbounded/non-deterministic: size=%d", len(names))
	}
}
