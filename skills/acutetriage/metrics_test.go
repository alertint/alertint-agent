// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

type rulesProm struct {
	fakeProm

	rules      map[string]string
	err        error
	rulesCalls int
	deadline   time.Time
}

func (f *rulesProm) RecordingRules(ctx context.Context) (map[string]string, error) {
	f.rulesCalls++
	f.deadline, _ = ctx.Deadline()
	return f.rules, f.err
}

func TestFetchMetrics_RecordingRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules map[string]string
		err   error
		want  map[string]string
	}{
		{"nested", map[string]string{"service:errors": `service:raw_errors`, "service:raw_errors": `rate(requests_total{status="error"}[5m])`, "unrelated": `up`}, nil, map[string]string{"service:errors": `service:raw_errors`, "service:raw_errors": `rate(requests_total{status="error"}[5m])`}},
		{"cycle", map[string]string{"service:errors": `service:raw_errors`, "service:raw_errors": `service:errors`}, nil, map[string]string{"service:errors": `service:raw_errors`, "service:raw_errors": `service:errors`}},
		{"fetch error", nil, errors.New("rules unsupported"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &rulesProm{rules: tc.rules, err: tc.err}
			f.responses = map[string]json.RawMessage{`{service="api"}`: vector(s(map[string]string{"__name__": "requests_total", "service": "api"}, "1"))}
			start := time.Now()
			enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, []string{`service:errors > 0.05`}, []store.Alert{alert(map[string]string{"service": "api"})}, start, "i", nil)
			if enr == nil || enr.Outcome != OutcomeFetched {
				t.Fatalf("triage metric evidence lost: %+v", enr)
			}
			raw, err := json.Marshal(enr)
			if err != nil {
				t.Fatal(err)
			}
			var persisted struct {
				RecordingRules map[string]string `json:"recording_rules"`
			}
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(persisted.RecordingRules, tc.want) {
				t.Errorf("persisted definitions=%v, want %v", persisted.RecordingRules, tc.want)
			}
			if f.rulesCalls != 1 || f.deadline.IsZero() || f.deadline.After(start.Add(time.Second+50*time.Millisecond)) {
				t.Errorf("rules must be fetched once within metrics deadline: calls=%d deadline=%v", f.rulesCalls, f.deadline)
			}
		})
	}
}

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
	sel := buildMetricSelector(alerts, nil)
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
	got := instanceSupplements(alerts, nil, nil)
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
	if got := renderPhysicalCore(shared, nil, nil); got != `{namespace="checkout",pod="api-7f9x"}` {
		t.Errorf("got %q", got)
	}
	// No logical key → no distinct retry.
	if got := renderPhysicalCore(map[string][]string{"namespace": {"checkout"}}, nil, nil); got != "" {
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

func TestRankSeries_ExcludesAlertBookkeepingOnly(t *testing.T) {
	raw := vector(
		s(map[string]string{"__name__": "ALERTS", "service": "payment"}, "1"),
		s(map[string]string{"__name__": "ALERTS_FOR_STATE", "service": "payment"}, "123"),
		s(map[string]string{"__name__": "ALERTS_x", "service": "payment"}, "2"),
		s(map[string]string{"__name__": "service:span_error_ratio:5m", "service": "payment"}, "0.54"),
	)
	got := rankSeries(raw, memberLabelPairs([]store.Alert{alert(map[string]string{"service": "payment"})}), 10, nil, nil)
	if len(got) != 2 || got[0].Metric != "ALERTS_x" || got[1].Metric != "service:span_error_ratio:5m" {
		t.Fatalf("want real series and ALERTS_x only, got %+v", got)
	}
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
	got := rankSeries(raw, members, 10, nil, nil)
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
	if got := rankSeries(vector(list...), members, 10, nil, nil); len(got) != 10 {
		t.Errorf("cap not applied: got %d", len(got))
	}
}

// ADR-0025: within one metric family at equal overlap, snapshots order by
// numeric value DESCENDING — a comparator sample is a top-N by magnitude,
// not an alphabetical slice (the f28da0d8 bias).
func TestRankSeries_ValueOrdersWithinFamily(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"instance": "node-1"})})
	raw := vector(
		s(map[string]string{"__name__": "fluentd_input_records_total", "instance": "node-1", "app": "abacus-live"}, "3.67e+06"),
		s(map[string]string{"__name__": "fluentd_input_records_total", "instance": "node-1", "app": "anu-iap-proxy"}, "6.6e+06"),
		s(map[string]string{"__name__": "fluentd_input_records_total", "instance": "node-1", "app": "payments-service-live"}, "5.5e+06"),
	)
	got := rankSeries(raw, members, 10, nil, nil)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	if got[0].Value != "6.6e+06" || got[1].Value != "5.5e+06" || got[2].Value != "3.67e+06" {
		t.Errorf("want value-descending order, got: %+v", got)
	}
}

// Unparsable values rank after parsable ones within their family, tiebroken
// by series identity — the order stays total and deterministic (R5).
func TestRankSeries_UnparsableValueRanksLast(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"instance": "node-1"})})
	raw := vector(
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "zz"}, "not-a-number"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "aa"}, "NaN"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "small"}, "1"),
	)
	got := rankSeries(raw, members, 10, nil, nil)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	if got[0].Value != "1" {
		t.Errorf("numeric value must rank before unparsable ones: %+v", got)
	}
	// The two unparsable entries tiebreak by series identity ascending: aa before zz.
	if !strings.Contains(got[1].Series, `app="aa"`) || !strings.Contains(got[2].Series, `app="zz"`) {
		t.Errorf("unparsable tiebreak must be series-identity asc: %+v", got)
	}
}

// Response order must not matter (R5): the same series presented reversed
// yield the identical ranking.
func TestRankSeries_ResponseOrderIndependent(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"instance": "node-1"})})
	fwd := vector(
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "a"}, "1"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "b"}, "2"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "c"}, "3"),
	)
	rev := vector(
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "c"}, "3"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "b"}, "2"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "a"}, "1"),
	)
	g1, g2 := rankSeries(fwd, members, 10, nil, nil), rankSeries(rev, members, 10, nil, nil)
	if len(g1) != 3 || len(g2) != 3 {
		t.Fatalf("want 3+3, got %d+%d", len(g1), len(g2))
	}
	for i := range g1 {
		if g1[i] != g2[i] {
			t.Fatalf("order-dependent ranking at %d: %+v vs %+v", i, g1[i], g2[i])
		}
	}
}

// ADR-0025: comparator-tier series (overlap ≤ 1) are capped at 3 per metric
// family per scope, so one big family cannot eat every slot and hide the
// other families.
func TestRankSeries_ComparatorFamilyCap(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"instance": "node-1"})})
	raw := vector(
		s(map[string]string{"__name__": "big_family", "instance": "node-1", "app": "a"}, "5"),
		s(map[string]string{"__name__": "big_family", "instance": "node-1", "app": "b"}, "4"),
		s(map[string]string{"__name__": "big_family", "instance": "node-1", "app": "c"}, "3"),
		s(map[string]string{"__name__": "big_family", "instance": "node-1", "app": "d"}, "2"),
		s(map[string]string{"__name__": "big_family", "instance": "node-1", "app": "e"}, "1"),
		s(map[string]string{"__name__": "other_family", "instance": "node-1"}, "9"),
	)
	got := rankSeries(raw, members, 10, nil, nil)
	if len(got) != 4 {
		t.Fatalf("want 3 capped big_family + 1 other_family = 4, got %d: %+v", len(got), got)
	}
	// big_family keeps its TOP 3 by value; other_family survives the flood.
	if got[0].Value != "5" || got[1].Value != "4" || got[2].Value != "3" || got[3].Metric != "other_family" {
		t.Errorf("cap/order wrong: %+v", got)
	}
}

// The no-regression guard: member-evidence series (overlap ≥ 2) are NEVER
// capped or counted against the family cap — a 5-pod storm keeps every
// member pod's series, and the family's comparators still get their own 3.
func TestRankSeries_MemberEvidenceNeverCapped(t *testing.T) {
	members := memberLabelPairs([]store.Alert{
		alert(map[string]string{"instance": "node-1", "pod": "api-1"}),
		alert(map[string]string{"instance": "node-1", "pod": "api-2"}),
		alert(map[string]string{"instance": "node-1", "pod": "api-3"}),
		alert(map[string]string{"instance": "node-1", "pod": "api-4"}),
		alert(map[string]string{"instance": "node-1", "pod": "api-5"}),
	})
	series := []map[string]any{
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "api-1"}, "1"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "api-2"}, "1"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "api-3"}, "1"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "api-4"}, "1"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "api-5"}, "1"),
		// Same family, comparator tier (shares only instance):
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "peer-x"}, "9"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "peer-y"}, "8"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "peer-z"}, "7"),
		s(map[string]string{"__name__": "http_reqs", "instance": "node-1", "pod": "peer-w"}, "6"),
	}
	got := rankSeries(vector(series...), members, 10, nil, nil)
	// 5 member series (overlap 2, uncapped) + 3 comparator series (capped) = 8.
	if len(got) != 8 {
		t.Fatalf("want 5 member + 3 comparators = 8, got %d: %+v", len(got), got)
	}
	// Members first (overlap 2), then comparators top-3 by value: 9, 8, 7.
	if got[5].Value != "9" || got[6].Value != "8" || got[7].Value != "7" {
		t.Errorf("comparator tail wrong: %+v", got)
	}
}

// A metric value whose magnitude exceeds float64's range (an adversarial
// "1e400") still parses to a meaningful ±Inf via strconv.ParseFloat's
// ErrRange overflow case — it must rank as the largest magnitude in its
// family, not fall to the unparsable tail (code-review finding).
func TestRankSeries_OverflowValueRanksAsInfinite(t *testing.T) {
	members := memberLabelPairs([]store.Alert{alert(map[string]string{"instance": "node-1"})})
	raw := vector(
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "normal"}, "42"),
		s(map[string]string{"__name__": "m", "instance": "node-1", "app": "overflow"}, "1e400"),
	)
	got := rankSeries(raw, members, 10, nil, nil)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	if got[0].Value != "1e400" {
		t.Errorf("overflowed value must rank first (as +Inf), got: %+v", got)
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
	limits            []int
	priorAt           time.Time
	priorResponses    map[string]json.RawMessage
	priorFail         bool
	baselineAt        time.Time
	baselineResponses map[string]json.RawMessage
	baselineFail      bool
	baselineTimeout   bool
	times             []time.Time
}

func (f *fakeProm) QueryInstant(ctx context.Context, expr string, at time.Time, limit int) (json.RawMessage, error) {
	f.calls = append(f.calls, expr)
	f.limits = append(f.limits, limit)
	f.times = append(f.times, at)
	if at.Equal(f.priorAt) {
		if f.priorFail {
			return nil, errors.New("prior baseline unavailable")
		}
		if r, ok := f.priorResponses[expr]; ok {
			return r, nil
		}
	}
	if at.Equal(f.baselineAt) {
		if f.baselineTimeout {
			return nil, context.DeadlineExceeded
		}
		if f.baselineFail {
			return nil, errors.New("baseline unavailable")
		}
		if r, ok := f.baselineResponses[expr]; ok {
			return r, nil
		}
	}
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

func TestFetchMetricsRanksNewErrorSeriesAheadOfUnchangedNoise(t *testing.T) {
	at := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	scope := `{service_name="worker"}`
	ruleExpr := `service:span_error_ratio:5m`
	series := vector(
		s(map[string]string{"__name__": "http_client_duration_milliseconds_bucket", "service_name": "worker", "le": "1"}, "4"),
		s(map[string]string{"__name__": "http_client_duration_milliseconds_count", "service_name": "worker", "net_peer_name": "169.254.169.254"}, "4"),
		s(map[string]string{"__name__": "http_client_duration_milliseconds_sum", "service_name": "worker", "net_peer_name": "169.254.169.254"}, "4"),
		s(map[string]string{"__name__": "nodejs_eventloop_delay_max_seconds", "service_name": "worker"}, "4"),
		s(map[string]string{"__name__": "traces_span_metrics_calls_total", "service_name": "worker", "status_code": "STATUS_CODE_ERROR"}, "1"),
	)
	baseline := vector(
		s(map[string]string{"__name__": "http_client_duration_milliseconds_count", "service_name": "worker", "net_peer_name": "169.254.169.254"}, "4"),
		s(map[string]string{"__name__": "http_client_duration_milliseconds_sum", "service_name": "worker", "net_peer_name": "169.254.169.254"}, "4"),
		s(map[string]string{"__name__": "nodejs_eventloop_delay_max_seconds", "service_name": "worker"}, "4"),
	)
	f := &fakeProm{responses: map[string]json.RawMessage{scope: series, ruleExpr: vector(s(map[string]string{"__name__": ruleExpr, "service_name": "worker"}, "0.5"))}, baselineAt: at.Add(-15 * time.Minute), baselineResponses: map[string]json.RawMessage{scope: baseline}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, ExtraSelectorLabels: []string{"service_name"}}, []string{ruleExpr}, []store.Alert{alert(map[string]string{"service_name": "worker"})}, at, "i", nil)
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 5 {
		t.Fatalf("snapshots=%+v outcome=%s", enr.Snapshots, enr.Outcome)
	}
	if enr.Snapshots[0].Metric != ruleExpr || enr.Snapshots[0].Baseline != "" || enr.Snapshots[1].Metric != "traces_span_metrics_calls_total" || enr.Snapshots[1].Baseline != "none" {
		t.Fatalf("new error series must rank first with absent baseline: %+v", enr.Snapshots)
	}
	for _, snap := range enr.Snapshots {
		if strings.HasSuffix(snap.Metric, "_bucket") {
			t.Fatalf("bucket retained: %+v", snap)
		}
		if snap.Metric != ruleExpr && snap.Metric != "traces_span_metrics_calls_total" && snap.Baseline != "4" {
			t.Fatalf("baseline missing: %+v", snap)
		}
	}
	if len(f.times) != 4 || !f.times[0].Equal(at) || !f.times[1].Equal(at) || !f.times[2].Equal(at.Add(-15*time.Minute)) || !f.times[3].Equal(at.Add(-30*time.Minute)) {
		t.Fatalf("query times=%v", f.times)
	}
}

func TestFetchMetricsBaselineFailureKeepsCurrentRanking(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout bool
	}{{name: "failed"}, {name: "timed out", timeout: true}} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
			scope := `{namespace="n"}`
			f := &fakeProm{responses: map[string]json.RawMessage{scope: vector(
				s(map[string]string{"__name__": "z_metric", "namespace": "n"}, "5"),
				s(map[string]string{"__name__": "a_metric", "namespace": "n"}, "1"),
			)}, baselineAt: at.Add(-15 * time.Minute), baselineFail: !tc.timeout, baselineTimeout: tc.timeout}
			enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, []store.Alert{alert(map[string]string{"namespace": "n"})}, at, "i", nil)
			if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 2 || enr.Snapshots[0].Metric != "a_metric" || enr.Snapshots[0].Baseline != "" {
				t.Fatalf("baseline failure changed current evidence: %+v", enr)
			}
		})
	}
}

func TestRankSeriesCapsHistogramCountAndSumTogether(t *testing.T) {
	series := make([]map[string]any, 0, 4)
	for _, metric := range []string{"http_client_duration_milliseconds_count", "http_client_duration_milliseconds_sum"} {
		for _, peer := range []string{"a", "b"} {
			series = append(series, s(map[string]string{"__name__": metric, "net_peer_name": peer}, "1"))
		}
	}
	got := rankSeries(vector(series...), nil, 10, nil, nil)
	if len(got) != 3 {
		t.Fatalf("one comparator family took %d slots, want 3: %+v", len(got), got)
	}
}

func TestRankSeriesChangeBeatsAlphabeticalTie(t *testing.T) {
	raw := vector(
		s(map[string]string{"__name__": "a_metric", "namespace": "n"}, "4"),
		s(map[string]string{"__name__": "z_metric", "namespace": "n"}, "8"),
	)
	baseline := map[string]string{
		"a_metric\x00" + `{namespace="n"}`: "4",
		"z_metric\x00" + `{namespace="n"}`: "4",
	}
	got := rankSeries(raw, memberLabelPairs([]store.Alert{alert(map[string]string{"namespace": "n"})}), 10, baseline, nil)
	if len(got) != 2 || got[0].Metric != "z_metric" || got[0].Baseline != "4" {
		t.Fatalf("changed series did not win equal-overlap tie: %+v", got)
	}
}

func TestFetchMetrics_K8sSelectorFetches(t *testing.T) {
	// AE1: namespace+pod, no instance → generic selector fetches; Outcome fetched.
	alerts := []store.Alert{alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x", "severity": "critical"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{namespace="checkout",pod="api-7f9x"}`: vector(
			s(map[string]string{"__name__": "cpu", "namespace": "checkout", "pod": "api-7f9x"}, "0.9"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, time.Now(), "inc1", nil)
	if enr == nil || enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 {
		t.Fatalf("want fetched with 1 snapshot, got %+v", enr)
	}
}

func TestFetchMetrics_LabelMapUsesSeriesLabel(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{"service": "payment"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{service_name="payment"}`: vector(s(map[string]string{"__name__": "service:span_error_ratio:5m", "service_name": "payment"}, "0.54")),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, LabelMap: map[string]string{"service": "service_name"}}, nil, alerts, time.Now(), "payment", nil)
	if len(f.calls) != 3 || f.calls[0] != `{service_name="payment"}` || f.calls[1] != f.calls[0] || f.calls[2] != f.calls[0] || enr.Outcome != OutcomeFetched {
		t.Fatalf("calls = %v, enrichment = %+v", f.calls, enr)
	}
}

func TestFetchMetrics_RuleExpressionLearnsLabelMap(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{"service": "payment", "service_name": "payment"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		case014RuleExpr:            vector(s(map[string]string{"__name__": "service:span_error_ratio:5m", "service_name": "payment"}, "0.54")),
		`{service_name="payment"}`: vector(s(map[string]string{"__name__": "payment_requests_total", "service_name": "payment"}, "42")),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, []string{case014RuleExpr}, alerts, time.Now(), "payment", nil)
	if len(f.calls) < 2 || f.calls[0] != case014RuleExpr || f.calls[1] != `{service_name="payment"}` {
		t.Fatalf("queries = %v", f.calls)
	}
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 2 || enr.Snapshots[0].Metric != "service:span_error_ratio:5m" {
		t.Fatalf("enrichment = %+v", enr)
	}
	if len(enr.RuleExprs) != 1 || enr.RuleExprs[0] != case014RuleExpr || enr.LabelMap["service"] != "service_name" {
		t.Fatalf("rule metadata = %+v", enr)
	}
	frozenJSON, err := json.Marshal(enr)
	if err != nil {
		t.Fatal(err)
	}
	var frozen MetricEnrichment
	if err := json.Unmarshal(frozenJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	floor := composeFloor(VerificationParams{HasPromQL: true, LabelMap: frozen.LabelMap}, "", alerts)
	if floor[0].Expr != `{service_name="payment"}` {
		t.Fatalf("frozen learned map did not reach floor: %+v", floor)
	}
}

func TestFetchMetrics_RuleExpressionJoinAndLearning(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{"service": "payment", "service_name": "payment", "region": "eu"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		"up": vector(
			s(map[string]string{"service_name": "payment"}, "1"),
			s(map[string]string{"__name__": "wrong_region", "service_name": "payment", "region": "us"}, "2"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, LabelMap: map[string]string{"service": "manual"}}, []string{"up"}, alerts, time.Now(), "payment", nil)
	if len(enr.Snapshots) != 1 || enr.Snapshots[0].Metric != "alert_rule_expr" {
		t.Fatalf("joined snapshots = %+v", enr.Snapshots)
	}
	if enr.LabelMap["service"] != "manual" {
		t.Fatalf("manual map lost: %v", enr.LabelMap)
	}
}

func TestFetchMetrics_RuleExpressionEmptyDoesNotLearn(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{"service": "payment"})}
	f := &fakeProm{fail: map[string]bool{"bad_metric": true}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, []string{"up", "bad_metric"}, alerts, time.Now(), "payment", nil)
	if len(enr.Snapshots) != 0 || len(enr.LabelMap) != 0 || enr.Outcome != OutcomeEmpty {
		t.Fatalf("empty rule results changed fetch: %+v", enr)
	}
}

func TestFetchMetrics_RuleExpressionAmbiguousLabelDoesNotLearn(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{"service": "payment", "service_name": "payment", "team": "payment"})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		"up": vector(s(map[string]string{"__name__": "up", "service_name": "payment", "team": "payment"}, "1")),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, []string{"up"}, alerts, time.Now(), "payment", nil)
	if _, ok := enr.LabelMap["service"]; ok {
		t.Fatalf("ambiguous match learned a map: %v", enr.LabelMap)
	}
	if f.calls[1] != `{service="payment"}` {
		t.Fatalf("scope changed after ambiguous rule result: %v", f.calls)
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, time.Now(), "inc1", nil)
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 {
		t.Fatalf("physical-core retry should recover metrics, got %+v", enr)
	}
}

func TestFetchMetrics_AlertBookkeepingTriggersPhysicalCoreRetry(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{
		"alertname": "ServiceErrorRateHigh", "service": "payment",
		"service_name": "payment", "severity": "critical",
	})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{service="payment",service_name="payment"}`: vector(
			s(map[string]string{"__name__": "ALERTS", "service": "payment", "service_name": "payment"}, "1"),
			s(map[string]string{"__name__": "ALERTS_FOR_STATE", "service": "payment", "service_name": "payment"}, "123"),
		),
		`{service_name="payment"}`: vector(
			s(map[string]string{"__name__": "service:span_error_ratio:5m", "service_name": "payment"}, "0.54"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, ExtraSelectorLabels: []string{"service_name"}}, nil, alerts, time.Now(), "payment", nil)
	if len(f.calls) != 6 || f.calls[0] != `{service="payment",service_name="payment"}` || f.calls[1] != f.calls[0] || f.calls[2] != f.calls[0] || f.calls[3] != `{service_name="payment"}` || f.calls[4] != f.calls[3] || f.calls[5] != f.calls[3] {
		t.Fatalf("want primary then physical-core fallback, got calls %v", f.calls)
	}
	if enr.Outcome != OutcomeFetched || len(enr.Snapshots) != 1 || enr.Snapshots[0].Metric != "service:span_error_ratio:5m" {
		t.Fatalf("want only the real metric as fetched evidence, got %+v", enr)
	}
}

func TestFetchMetrics_AlertBookkeepingWithoutFallbackIsEmpty(t *testing.T) {
	alerts := []store.Alert{alert(map[string]string{
		"alertname": "ServiceErrorRateHigh", "service": "payment",
		"service_name": "payment", "severity": "critical",
	})}
	f := &fakeProm{responses: map[string]json.RawMessage{
		`{service="payment"}`: vector(
			s(map[string]string{"__name__": "ALERTS", "service": "payment"}, "1"),
			s(map[string]string{"__name__": "ALERTS_FOR_STATE", "service": "payment"}, "123"),
		),
	}}
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, time.Now(), "payment", nil)
	if len(f.calls) != 3 || f.calls[0] != `{service="payment"}` || f.calls[1] != f.calls[0] || f.calls[2] != f.calls[0] {
		t.Fatalf("want only the primary scope, got calls %v", f.calls)
	}
	if enr.Outcome != OutcomeEmpty || enr.Note != "no metric series matched the incident selector" || len(enr.Snapshots) != 0 {
		t.Fatalf("want empty outcome and no alert bookkeeping evidence, got %+v", enr)
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, time.Now(), "inc1", nil)
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, time.Now(), "inc1", nil)
	if enr == nil {
		t.Fatal("nil enrichment")
	}
	// One primary (namespace+instance regex) + at most maxInstanceSupplements
	// bare per-instance scopes — never one per node.
	if want := 3 * (1 + maxInstanceSupplements); len(f.calls) != want {
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, nil, alerts, time.Now(), "inc1", nil)
	if len(f.calls) != 7 {
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
	FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5, MaxSeries: 200}, nil, alerts, time.Now(), "i", nil)
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, nil, alerts, time.Now(), "i", nil)
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 1}, nil, alerts, time.Now(), "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Fatalf("hard error must win over timeout, got %q", enr.Outcome)
	}
}

func TestFetchMetrics_Outcomes(t *testing.T) {
	now := time.Now()
	// no usable selector.
	enr := FetchMetrics(context.Background(), &fakeProm{}, MetricParams{TimeoutSeconds: 5}, nil,
		[]store.Alert{alert(map[string]string{"alertname": "X"})}, now, "i", nil)
	if enr.Outcome != OutcomeNoSelector {
		t.Errorf("want no_selector, got %q", enr.Outcome)
	}
	// queried, empty.
	enr = FetchMetrics(context.Background(), &fakeProm{}, MetricParams{TimeoutSeconds: 5}, nil,
		[]store.Alert{alert(map[string]string{"namespace": "n"})}, now, "i", nil)
	if enr.Outcome != OutcomeEmpty {
		t.Errorf("want empty, got %q", enr.Outcome)
	}
	// backend failed (every scope errors).
	f := &fakeProm{fail: map[string]bool{`{namespace="n"}`: true}}
	enr = FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil,
		[]store.Alert{alert(map[string]string{"namespace": "n"})}, now, "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Errorf("want failed, got %q", enr.Outcome)
	}
	// nil querier → nil enrichment (never looked).
	if FetchMetrics(context.Background(), nil, MetricParams{TimeoutSeconds: 5}, nil, nil, now, "i", nil) != nil {
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
	enr := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, alerts, now, "i", nil)
	if enr.Outcome != OutcomeFailed {
		t.Fatalf("partial failure must report failed, got %q (%+v); calls=%v", enr.Outcome, enr, f.calls)
	}
}

func TestFetchMetrics_CounterIncreaseOutranksChangingGauge(t *testing.T) {
	at := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	scope := `{service="api"}`
	current := vector(s(map[string]string{"__name__": "heap_bytes", "service": "api"}, "7063384"), s(map[string]string{"__name__": "request_errors_total", "service": "api"}, "987"))
	before := vector(s(map[string]string{"__name__": "heap_bytes", "service": "api"}, "1954512"), s(map[string]string{"__name__": "request_errors_total", "service": "api"}, "977"))
	prior := vector(s(map[string]string{"__name__": "request_errors_total", "service": "api"}, "977"))
	f := &fakeProm{responses: map[string]json.RawMessage{scope: current}, baselineAt: at.Add(-15 * time.Minute), baselineResponses: map[string]json.RawMessage{scope: before}, priorAt: at.Add(-30 * time.Minute), priorResponses: map[string]json.RawMessage{scope: prior}}
	e := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, []store.Alert{alert(map[string]string{"service": "api"})}, at, "i", nil)
	if len(e.Snapshots) != 2 || e.Snapshots[0].Metric != "request_errors_total" {
		t.Fatalf("new counter errors hidden by gauge: %+v", e.Snapshots)
	}
	if len(f.times) != 3 || !f.times[2].Equal(at.Add(-30*time.Minute)) {
		t.Fatalf("query times=%v", f.times)
	}
	var b strings.Builder
	renderMetrics(&b, e)
	for _, want := range []string{"request_errors_total{service=\"api\"} = 987 (+10 in last 15m, +0 in prior 15m)", "heap_bytes{service=\"api\"} = 7063384 [bytes] (15m earlier: 1954512)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q: %s", want, b.String())
		}
	}
}

func TestFetchMetrics_CounterIntervalsHandleResetsAndFlatCounters(t *testing.T) {
	for _, tc := range []struct{ name, current, before, prior, want string }{
		{"steady total", "987", "977", "967", "+10 in last 15m, +10 in prior 15m"},
		{"current reset", "7", "977", "967", "+7 in last 15m, +10 in prior 15m"},
		{"prior reset", "17", "7", "977", "+10 in last 15m, +7 in prior 15m"},
		{"flat", "977", "977", "977", "+0 in last 15m, +0 in prior 15m"},
	} {
		for _, suffix := range []string{"_total", "_count", "_sum"} {
			t.Run(tc.name+suffix, func(t *testing.T) {
				at := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
				scope := `{service="api"}`
				data := func(v string) json.RawMessage {
					return vector(s(map[string]string{"__name__": "requests" + suffix, "service": "api"}, v))
				}
				f := &fakeProm{responses: map[string]json.RawMessage{scope: data(tc.current)}, baselineAt: at.Add(-15 * time.Minute), baselineResponses: map[string]json.RawMessage{scope: data(tc.before)}, priorAt: at.Add(-30 * time.Minute), priorResponses: map[string]json.RawMessage{scope: data(tc.prior)}}
				e := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, []store.Alert{alert(map[string]string{"service": "api"})}, at, "i", nil)
				var b strings.Builder
				renderMetrics(&b, e)
				if !strings.Contains(b.String(), "("+tc.want+")") {
					t.Fatal(b.String())
				}
			})
		}
	}
}

func TestFetchMetrics_PriorFailureKeepsCurrentEvidence(t *testing.T) {
	at := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	scope := `{service="api"}`
	data := vector(s(map[string]string{"__name__": "requests_total", "service": "api"}, "987"))
	f := &fakeProm{responses: map[string]json.RawMessage{scope: data}, baselineAt: at.Add(-15 * time.Minute), baselineResponses: map[string]json.RawMessage{scope: vector(s(map[string]string{"__name__": "requests_total", "service": "api"}, "977"))}, priorAt: at.Add(-30 * time.Minute), priorFail: true}
	e := FetchMetrics(context.Background(), f, MetricParams{TimeoutSeconds: 5}, nil, []store.Alert{alert(map[string]string{"service": "api"})}, at, "i", nil)
	if e.Outcome != OutcomeFetched || len(e.Snapshots) != 1 || e.Snapshots[0].Value != "987" {
		t.Fatalf("prior failure discarded current evidence: %+v", e)
	}
	if len(f.times) != 3 {
		t.Fatalf("prior baseline not attempted: %v", f.times)
	}
	var b strings.Builder
	renderMetrics(&b, e)
	if strings.Contains(b.String(), "prior 15m") {
		t.Fatalf("invented interval: %s", b.String())
	}
}
