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
	b, _ := json.Marshal(map[string]any{"resultType": "vector", "result": series}) //nolint:errchkjson // fixture built from literal strings/floats only; cannot fail to marshal
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
	// fail matchers error out with a non-timeout (hard) error.
	fail map[string]bool
	// slow matchers block until their query context is cancelled, then return
	// ctx.Err() — modeling a backend too slow to answer within the deadline.
	slow  map[string]bool
	calls []string
	// limits records the limit argument of each QueryInstant call, in order.
	limits []int
}

func (f *fakeProm) QueryInstant(ctx context.Context, expr string, _ time.Time, limit int) (json.RawMessage, error) {
	f.calls = append(f.calls, expr)
	f.limits = append(f.limits, limit)
	if f.slow[expr] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// A real client issues the request under ctx; an already-cancelled ctx fails
	// immediately rather than returning data.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

func TestFetchMetrics_CapsInstanceSupplements(t *testing.T) {
	// A mega-incident spanning many nodes must not fan out one bare per-node
	// query each — the instance supplements are capped so alertint never becomes
	// a thundering herd against the metric backend during a storm.
	alerts := make([]store.Alert, 0, 8)
	for i := 0; i < 8; i++ {
		alerts = append(alerts, alert(map[string]string{"namespace": "n", "instance": string(rune('a' + i))}))
	}
	f := &fakeProm{}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, alerts, time.Now(), "inc1", nil)
	if enr == nil {
		t.Fatal("nil enrichment")
	}
	// One primary (namespace+instance regex) + at most maxInstanceSupplements
	// bare per-instance scopes — never one per node.
	if want := 1 + maxInstanceSupplements; len(f.calls) != want {
		t.Fatalf("queried %d scopes, want %d (1 primary + %d capped supplements); calls=%v",
			len(f.calls), want, maxInstanceSupplements, f.calls)
	}
}

func TestFetchMetrics_PerScopeDeadlinePreventsStarvation(t *testing.T) {
	// Storm reproduction: the first (primary) scope is slow under load. With one
	// shared deadline it would consume the whole budget and starve the remaining
	// scopes — the real per-instance data — into "context deadline exceeded",
	// yielding a false backend failure. A per-scope deadline isolates the slow
	// query so the later scopes still run and return their metrics.
	alerts := []store.Alert{
		alert(map[string]string{"namespace": "n", "instance": "n1"}),
		alert(map[string]string{"namespace": "n", "instance": "n2"}),
	}
	f := &fakeProm{
		slow: map[string]bool{`{instance=~"n1|n2",namespace="n"}`: true}, // primary is slow
		responses: map[string]json.RawMessage{
			`{instance="n1"}`: vector(s(map[string]string{"__name__": "node_load1", "instance": "n1"}, "1")),
			`{instance="n2"}`: vector(s(map[string]string{"__name__": "node_load1", "instance": "n2"}, "2")),
		},
	}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, alerts, time.Now(), "inc1", nil)
	if len(f.calls) != 3 {
		t.Fatalf("all three scopes must be attempted, got calls=%v", f.calls)
	}
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 2 {
		t.Fatalf("slow primary must not starve the supplements: got outcome=%q snapshots=%d (%+v)",
			enr.Outcome, len(enr.Snapshots), enr.Snapshots)
	}
}

func TestFetchMetrics_PassesMaxSeriesToQuerier(t *testing.T) {
	// The server-side series bound must reach every enrichment query so a broad
	// selector can never dump an unbounded node-series payload.
	alerts := []store.Alert{alert(map[string]string{"namespace": "n", "instance": "db-01:9100"})}
	f := &fakeProm{}
	FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, MaxSeries: 200}, alerts, time.Now(), "i", nil)
	if len(f.limits) == 0 {
		t.Fatal("no queries ran")
	}
	for i, l := range f.limits {
		if l != 200 {
			t.Fatalf("MaxSeries must reach every query; call %d used limit %d (all=%v)", i, l, f.limits)
		}
	}
}

func TestFetchMetrics_TimeoutIsDegraded(t *testing.T) {
	// A scope that times out under load (backend reachable but slow) yields
	// OutcomeDegraded, not OutcomeFailed — the metric backend is not down, so the
	// finding must not be treated as "Prometheus unreachable".
	alerts := []store.Alert{alert(map[string]string{"namespace": "n"})}
	f := &fakeProm{slow: map[string]bool{`{namespace="n"}`: true}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, alerts, time.Now(), "i", nil)
	if enr.Outcome != OutcomeDegraded {
		t.Fatalf("timeout under load must be degraded, got %q", enr.Outcome)
	}
}

func TestFetchMetrics_HardErrorBeatsTimeout(t *testing.T) {
	// When one scope is genuinely unreachable (hard error) and another merely
	// times out, with no series recovered, report the more actionable outage:
	// OutcomeFailed wins over OutcomeDegraded.
	alerts := []store.Alert{alert(map[string]string{"namespace": "n", "instance": "db-01:9100"})}
	f := &fakeProm{
		fail: map[string]bool{`{instance="db-01:9100",namespace="n"}`: true}, // primary: hard down
		slow: map[string]bool{`{instance="db-01:9100"}`: true},               // supplement: slow
	}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, alerts, time.Now(), "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Fatalf("hard error must win over timeout, got %q", enr.Outcome)
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

func TestFetchMetrics_PartialFailureIsNotGenuineEmpty(t *testing.T) {
	// R8 (unreachable ≠ genuine zero): when one scope errors and another succeeds
	// matching zero series, the fetch must report OutcomeFailed — never mask the
	// connector failure as a clean OutcomeEmpty "0 metrics" on the evidence card.
	now := time.Now()
	// Two distinct scopes: primary {instance,namespace} and the {instance} supplement.
	alerts := []store.Alert{alert(map[string]string{"namespace": "n", "instance": "db-01:9100"})}
	// Primary errors; the supplement succeeds but matches nothing (default vector()).
	f := &fakeProm{fail: map[string]bool{`{instance="db-01:9100",namespace="n"}`: true}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, alerts, now, "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Fatalf("partial failure must report failed, got %q (%+v); calls=%v", enr.Outcome, enr, f.calls)
	}
}
