// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func alert(labels map[string]string) store.Alert { return store.Alert{Labels: labels} }

func TestRenderPromMatcher_EqualityAndRegexEscaping(t *testing.T) {
	// Single value → equality, quoted verbatim (AE2).
	sel := map[string][]string{"instance": {"db-01:9100"}}
	if got := renderPromMatcher(sel); got != `{instance="db-01:9100"}` {
		t.Errorf("equality: got %q", got)
	}
	// Two values → anchored regex alternation, regex metacharacters escaped (AE2).
	sel = map[string][]string{"instance": {"db-01:9100", "10.0.0.2:9100"}}
	// Sorted, QuoteMeta escapes dots; %q escapes the backslashes for the PromQL string.
	if got := renderPromMatcher(sel); got != `{instance=~"10\\.0\\.0\\.2:9100|db-01:9100"}` {
		t.Errorf("regex: got %q", got)
	}
}

func TestBuildMetricSelector_AllowlistIntersectionUnioned(t *testing.T) {
	alerts := []store.Alert{
		alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x", "severity": "critical"}),
		alert(map[string]string{"namespace": "checkout", "pod": "api-2a1b", "severity": "warning"}),
	}
	sel := buildMetricSelector(alerts)
	// severity is not allowlisted → dropped; pod present on both, values unioned.
	if _, ok := sel["severity"]; ok {
		t.Error("severity must be dropped (not allowlisted)")
	}
	if got := renderPromMatcher(sel); got != `{namespace="checkout",pod=~"api-2a1b|api-7f9x"}` {
		t.Errorf("got %q", got)
	}
}

func TestInstanceSupplements_PerUniqueInstance(t *testing.T) {
	alerts := []store.Alert{
		alert(map[string]string{"instance": "db-01:9100", "job": "node"}),
		alert(map[string]string{"instance": "db-01:9100", "job": "node"}), // dup
		alert(map[string]string{"instance": "10.0.0.2:9100"}),
	}
	got := instanceSupplements(alerts)
	// One matcher per UNIQUE instance, each a bare {instance="X"} (AE7).
	want := []string{`{instance="db-01:9100"}`, `{instance="10.0.0.2:9100"}`}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing supplement %q in %v", w, got)
		}
	}
}

func TestRenderPhysicalCore_DropsLogicalKeys(t *testing.T) {
	// service is logical and exists on no series → physical-core drops it (AE8).
	shared := map[string][]string{"namespace": {"checkout"}, "pod": {"api-7f9x"}, "service": {"checkout-api"}}
	if got := renderPhysicalCore(shared); got != `{namespace="checkout",pod="api-7f9x"}` {
		t.Errorf("got %q", got)
	}
	// No logical key → no distinct retry.
	if got := renderPhysicalCore(map[string][]string{"namespace": {"checkout"}}); got != "" {
		t.Errorf("no-logical-key must yield empty retry, got %q", got)
	}
}

func vector(series ...map[string]any) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"resultType": "vector", "result": series})
	return b
}
func s(metric map[string]string, val string) map[string]any {
	return map[string]any{"metric": metric, "value": []any{0.0, val}}
}

func TestRankSeries_OverlapPreferredWithDeterministicTiebreak(t *testing.T) {
	// A member carries pod=api-7f9x; series also carrying that pod outrank
	// unrelated same-namespace series (AE11). System metrics are filtered.
	members := memberLabelPairs([]store.Alert{
		alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x"}),
	})
	raw := vector(
		s(map[string]string{"__name__": "http_reqs", "namespace": "checkout"}, "5"),                // overlap 1
		s(map[string]string{"__name__": "cpu", "namespace": "checkout", "pod": "api-7f9x"}, "0.9"), // overlap 2
		s(map[string]string{"__name__": "go_gc_duration_seconds", "namespace": "checkout"}, "0.1"), // system → dropped
		s(map[string]string{"__name__": "mem", "namespace": "checkout", "pod": "api-7f9x"}, "700"), // overlap 2
	)
	got := rankSeries(raw, members, 10)
	if len(got) != 3 {
		t.Fatalf("want 3 non-system, got %d: %+v", len(got), got)
	}
	// overlap-2 first; among equal overlap, metric name ascending → cpu before mem.
	if got[0].Metric != "cpu" || got[1].Metric != "mem" || got[2].Metric != "http_reqs" {
		t.Errorf("ranking wrong: %+v", got)
	}
	if got[0].Series != `{namespace="checkout",pod="api-7f9x"}` {
		t.Errorf("series identity wrong: %q", got[0].Series)
	}
}

func TestRankSeries_CapKeepsTopN(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"namespace": "n"})})
	list := make([]map[string]any, 0, 20)
	for i := 0; i < 20; i++ {
		list = append(list, s(map[string]string{"__name__": "m" + string(rune('a'+i)), "namespace": "n"}, "1"))
	}
	if got := rankSeries(vector(list...), members, 10); len(got) != 10 {
		t.Errorf("cap not applied: got %d", len(got))
	}
}

type fakeProm struct {
	// responses maps a matcher string → the instant-vector data blob to return.
	responses map[string]json.RawMessage
	// fail matchers error out.
	fail  map[string]bool
	calls []string
}

func (f *fakeProm) QueryInstant(_ context.Context, expr string, _ time.Time) (json.RawMessage, error) {
	f.calls = append(f.calls, expr)
	if f.fail[expr] {
		return nil, errors.New("boom")
	}
	if r, ok := f.responses[expr]; ok {
		return r, nil
	}
	return vector(), nil // matched nothing
}

func TestFetchMetrics_K8sSelectorFetches(t *testing.T) {
	// AE1: namespace+pod, no instance → generic selector fetches; Outcome fetched.
	alerts := []store.Alert{alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x", "severity": "critical"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{namespace="checkout",pod="api-7f9x"}`: vector(
			s(map[string]string{"__name__": "cpu", "namespace": "checkout", "pod": "api-7f9x"}, "0.9"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, alerts, time.Now(), "inc1", nil)
	if enr == nil || enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 {
		t.Fatalf("want fetched with 1 snapshot, got %+v", enr)
	}
}

func TestFetchMetrics_PhysicalCoreRetry(t *testing.T) {
	// AE8: service exists on no series → primary AND matches 0, retry with physical core.
	alerts := []store.Alert{alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x", "service": "checkout-api"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		// primary {namespace,pod,service} returns nothing (default vector()).
		`{namespace="checkout",pod="api-7f9x"}`: vector(
			s(map[string]string{"__name__": "cpu", "namespace": "checkout", "pod": "api-7f9x"}, "0.9"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, alerts, time.Now(), "inc1", nil)
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 {
		t.Fatalf("physical-core retry should recover metrics, got %+v", enr)
	}
}

func TestFetchMetrics_MixedMembersKeepInstanceSupplement(t *testing.T) {
	// AE7: {instance,job} + label-sparse member → shared selector empty, but the
	// instance supplement is still queried.
	alerts := []store.Alert{
		alert(map[string]string{"instance": "db-01:9100", "job": "node"}),
		alert(map[string]string{"alertname": "RecordingRuleFired"}),
	}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{instance="db-01:9100"}`: vector(
			s(map[string]string{"__name__": "node_load1", "instance": "db-01:9100"}, "4"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, alerts, time.Now(), "inc1", nil)
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 {
		t.Fatalf("instance supplement should be queried, got %+v; calls=%v", enr, f.calls)
	}
}

func TestFetchMetrics_Outcomes(t *testing.T) {
	now := time.Now()
	// no usable selector.
	enr := FetchMetrics(context.Background(), &fakeProm{}, MetricParams{TimeoutSeconds: 5},
		[]store.Alert{alert(map[string]string{"alertname": "X"})}, now, "i", nil)
	if enr.Outcome != OutcomeNoSelector {
		t.Errorf("want no_selector, got %q", enr.Outcome)
	}
	// queried, empty.
	enr = FetchMetrics(context.Background(), &fakeProm{}, MetricParams{TimeoutSeconds: 5},
		[]store.Alert{alert(map[string]string{"namespace": "n"})}, now, "i", nil)
	if enr.Outcome != OutcomeEmpty {
		t.Errorf("want empty, got %q", enr.Outcome)
	}
	// backend failed (every scope errors).
	f := &fakeProm{fail: map[string]bool{`{namespace="n"}`: true}}
	enr = FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5},
		[]store.Alert{alert(map[string]string{"namespace": "n"})}, now, "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Errorf("want failed, got %q", enr.Outcome)
	}
	// nil querier → nil enrichment (never looked).
	if FetchMetrics(context.Background(), nil, MetricParams{TimeoutSeconds: 5}, nil, now, "i", nil) != nil {
		t.Error("nil querier must yield nil enrichment")
	}
}
