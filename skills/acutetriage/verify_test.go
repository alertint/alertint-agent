// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

func alertWithLabels(labels map[string]string) store.Alert {
	return store.Alert{ID: "a1", Labels: labels}
}

// fakeQuerier is the func-backed metricQuerier idiom from metrics_test.go,
// simplified for the runner tests: it ignores ctx/t/limit and switches purely
// on the expr string, which is all these tests need to assert on.
type fakeQuerier func(expr string) (json.RawMessage, error)

func (f fakeQuerier) QueryInstant(_ context.Context, expr string, _ time.Time, _ int) (json.RawMessage, error) {
	return f(expr)
}

// TestRunPromQLRejectsInvalidLocally covers issue #62: a model-proposed
// expression that fails local PromQL validation must never reach the
// querier at all — it is marked invalid and not executed.
func TestRunPromQLRejectsInvalidLocally(t *testing.T) {
	calls := 0
	prom := fakeQuerier(func(string) (json.RawMessage, error) {
		calls++
		return nil, nil
	})
	q := VerificationQuery{Kind: kindPromQL, Source: "model", Expr: `increase(metric_name[1h]) by (type)`}
	runPromQL(context.Background(), prom, &q, 100, time.Now(), slog.Default(), "inc-62")
	if calls != 0 || q.Outcome != OutcomeInvalid || q.Result != "invalid query (not executed)" {
		t.Fatalf("calls=%d query=%+v", calls, q)
	}
}

func TestClassifyErrBadDataIsInvalid(t *testing.T) {
	q := VerificationQuery{}
	classifyErr(&q, &promclient.APIError{StatusCode: 422, Type: "bad_data", Message: `invalid parameter "query": parse error`})
	if q.Outcome != OutcomeInvalid {
		t.Fatalf("outcome = %q, want invalid", q.Outcome)
	}
}

func TestClassifyErrNonQueryBadDataIsFailed(t *testing.T) {
	q := VerificationQuery{}
	classifyErr(&q, &promclient.APIError{StatusCode: 400, Type: "bad_data", Message: `invalid parameter "limit"`})
	if q.Outcome != OutcomeFailed {
		t.Fatalf("outcome = %q, want failed", q.Outcome)
	}
}

// TestClassifyPairErrsBadDataIsInvalid: up_ratio's two sub-queries share one
// outcome, and a query-specific bad_data on either sub-query must win the
// same way classifyErr's single-error case does — this is the branch that
// degrades the round when the FLOOR query itself is invalid.
func TestClassifyPairErrsBadDataIsInvalid(t *testing.T) {
	q := VerificationQuery{}
	classifyPairErrs(&q, &promclient.APIError{StatusCode: 422, Type: "bad_data", Message: `invalid parameter "query": parse error`}, nil)
	if q.Outcome != OutcomeInvalid {
		t.Fatalf("outcome = %q, want invalid", q.Outcome)
	}
}

// fakeState is the verifyStateReader test double: a canned (total, top, err)
// triple returned regardless of arguments.
type fakeState struct {
	total int
	top   []store.WindowIncident
	err   error
}

func (f fakeState) IncidentsInWindow(_ context.Context, _ time.Time, _, _ string, _ bool, _ int) (int, []store.WindowIncident, error) {
	return f.total, f.top, f.err
}

// seriesIdentityRe extracts k="v" pairs out of a rendered series-identity
// string like `{cluster="deequ3"}` — the inverse of formatSeriesIdentity,
// good enough for the literal matcher strings these fixtures use.
var seriesIdentityRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

func parseSeriesIdentity(s string) map[string]string {
	m := map[string]string{}
	for _, match := range seriesIdentityRe.FindAllStringSubmatch(s, -1) {
		m[match[1]] = match[2]
	}
	return m
}

// instantVector builds the same instant-vector envelope rankSeries consumes
// ({"resultType":"vector","result":[{"metric":{...},"value":[ts,"val"]}]}),
// keyed by rendered series identity for fixture readability.
func instantVector(t *testing.T, series map[string]string) json.RawMessage {
	t.Helper()
	result := make([]map[string]any, 0, len(series))
	for identity, val := range series {
		result = append(result, map[string]any{
			"metric": parseSeriesIdentity(identity),
			"value":  []any{0.0, val},
		})
	}
	b, err := json.Marshal(map[string]any{"resultType": "vector", "result": result})
	if err != nil {
		t.Fatalf("instantVector: %v", err)
	}
	return b
}

// instantScalar is instantVector's single-value, no-labels special case — the
// shape sum(...)/count(...) aggregate queries return.
func instantScalar(t *testing.T, val string) json.RawMessage {
	t.Helper()
	return instantVector(t, map[string]string{"": val})
}

// Floor: broad keys kept, narrow identity dropped (spec R2, grill resolution).
func TestParentScopeBroadKeys(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{
		"namespace": "paysvc-sandbox-staging", "pod": "stolon-0", "instance": "10.0.0.1:9100",
	})}
	if got := parentScope(alerts, nil); got != `{namespace="paysvc-sandbox-staging"}` {
		t.Fatalf("got %q", got)
	}
}

// Host-only alert → unscoped global ratio (spec R2).
func TestParentScopeInstanceOnlyIsUnscoped(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "10.0.0.1:9100"})}
	if got := parentScope(alerts, nil); got != "" {
		t.Fatalf("want unscoped, got %q", got)
	}
}

// T1 half 1: with the Prometheus floor source present, the composed floor is
// always the same two queries, regardless of anything else about the alerts
// — this is the old floorPlan behavior, now reached via composeFloor with
// HasPromQL: true (byte-identical to the pre-composition floor).
func TestFloorPlanAlways(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "x"})}
	fp := composeFloor(VerificationParams{HasPromQL: true}, "host", alerts)
	if len(fp) != 2 || fp[0].Kind != kindUpRatio || fp[1].Kind != kindIncidentsInWindow {
		t.Fatalf("unexpected floor: %+v", fp)
	}
	for _, q := range fp {
		if q.Source != "floor" {
			t.Fatalf("floor query mislabeled: %+v", q)
		}
	}
}

// composeFloor assembles the deterministic floor from whichever floor
// sources are configured (ADR-0034): Prometheus's up_ratio, the Zabbix
// floor's two kinds, plus the universal incidents_in_window own-state check
// — always last, always present.
func TestComposeFloor_PromOnly(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "prod"})}
	floor := composeFloor(VerificationParams{HasPromQL: true}, "host", alerts)
	kinds := kindsOf(floor)
	want := []string{kindUpRatio, kindIncidentsInWindow}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

func TestComposeFloor_ZabbixOnly(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"host": "db-01"})}
	floor := composeFloor(VerificationParams{HasZabbix: true}, "host", alerts)
	kinds := kindsOf(floor)
	want := []string{kindZabbixReachability, kindZabbixNeighborProblems, kindIncidentsInWindow}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

func TestComposeFloor_MixedShopGetsBothFloors(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"host": "db-01", "namespace": "prod"})}
	floor := composeFloor(VerificationParams{HasPromQL: true, HasZabbix: true}, "host", alerts)
	kinds := kindsOf(floor)
	want := []string{kindUpRatio, kindZabbixReachability, kindZabbixNeighborProblems, kindIncidentsInWindow}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

func TestComposeFloor_ZabbixConfiguredButNoHostLabel(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"alertname": "x"})}
	floor := composeFloor(VerificationParams{HasZabbix: true}, "host", alerts)
	kinds := kindsOf(floor)
	// Not applicable → own-state check only; the round will degrade honestly.
	want := []string{kindIncidentsInWindow}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

func kindsOf(qs []VerificationQuery) []string {
	out := make([]string, 0, len(qs))
	for _, q := range qs {
		out = append(out, q.Kind)
	}
	return out
}

// T2: a malformed verification block degrades to nil (floor-only), never errors.
func TestParseVerificationPlanMalformed(t *testing.T) {
	raw := json.RawMessage(`{"analysis_name":"x","verification":{"queries":"not-a-list"}}`)
	if got := parseVerificationPlan(raw, VerificationParams{MaxQueries: 4}, nil, "inc1"); got != nil {
		t.Fatalf("want nil on malformed, got %+v", got)
	}
}

// A bare-array verification value — {"verification":[...]} without the
// {"queries":[...]} wrapper — parses the same as the wrapped shape. This is
// the shape a model following the plan instruction most literally emits
// (seen in production on claude-haiku-4-5 under v0.8.0); it must not degrade
// to floor-only.
func TestParseVerificationPlanBareArray(t *testing.T) {
	raw := json.RawMessage(`{"analysis_name":"x","verification":[
		{"kind":"promql","expr":"up{job=\"db\"}","why":"peers down too?"},
		{"kind":"incidents_in_window","params":{"window_minutes":30},"why":"anything else firing?"}]}`)
	got := parseVerificationPlan(raw, VerificationParams{MaxQueries: 4, HasPromQL: true}, nil, "inc1")
	if len(got) != 2 {
		t.Fatalf("want 2 queries from bare-array shape, got %d: %+v", len(got), got)
	}
	if got[0].Kind != kindPromQL || got[1].Kind != kindIncidentsInWindow {
		t.Fatalf("kinds mismatch: %+v", got)
	}
	for _, q := range got {
		if q.Source != "model" {
			t.Fatalf("bare-array query mislabeled: %+v", q)
		}
	}
}

// Cap + closed kind set: unknown kinds dropped, list capped at maxQueries (R3/R4).
func TestParseVerificationPlanCapAndKinds(t *testing.T) {
	raw := json.RawMessage(`{"verification":{"queries":[
		{"kind":"promql","expr":"q1"},{"kind":"sql","expr":"DROP TABLE"},
		{"kind":"promql","expr":"q2"},{"kind":"incidents_in_window","params":{"window_minutes":30}},
		{"kind":"promql","expr":"q3"},{"kind":"promql","expr":"q4"}]}}`)
	got := parseVerificationPlan(raw, VerificationParams{MaxQueries: 4, HasPromQL: true}, nil, "inc1")
	if len(got) != 4 {
		t.Fatalf("want 4 (capped, sql dropped), got %d: %+v", len(got), got)
	}
	for _, q := range got {
		if q.Kind == "sql" {
			t.Fatal("raw sql must be rejected at parse time (R4)")
		}
		if q.Source != "model" {
			t.Fatalf("model query mislabeled: %+v", q)
		}
	}
}

// Task 8/ADR-0034: a model that still proposes promql on a Prometheus-less
// install must have that query dropped defensively (belt-and-suspenders on
// top of the prompt no longer offering the kind) — otherwise it always fails,
// triggering the R15 clamp every re-judge.
func TestParseVerificationPlan_DropsPromQLWithoutPrometheus(t *testing.T) {
	raw := json.RawMessage(`{"verification":{"queries":[
		{"kind":"promql","expr":"up","why":"x"},
		{"kind":"incidents_in_window","why":"y"}]}}`)
	qs := parseVerificationPlan(raw, VerificationParams{MaxQueries: 3, HasZabbix: true}, nil, "inc-1")
	if len(qs) != 1 || qs[0].Kind != kindIncidentsInWindow {
		t.Fatalf("qs = %+v, want only incidents_in_window", qs)
	}
}

// The 28cfd3e2 floor: healthy peers + zero other incidents (spec T3 seed data).
func TestRunVerificationHealthyPeers(t *testing.T) {
	prom := fakeQuerier(func(expr string) (json.RawMessage, error) {
		switch {
		case strings.HasPrefix(expr, "sum(up"):
			return instantScalar(t, "34"), nil
		case strings.HasPrefix(expr, "count(up"):
			return instantScalar(t, "37"), nil
		case strings.Contains(expr, "sum by (cluster)"):
			return instantVector(t, map[string]string{`{cluster="deequ3"}`: "3", `{cluster="oo3tho"}`: "3", `{cluster="iev9oo"}`: "0"}), nil
		}
		t.Fatalf("unexpected expr %q", expr)
		return nil, nil
	})
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "paysvc-sandbox-staging", "instance": "10.0.0.1"})}
	model := []VerificationQuery{{Kind: kindPromQL, Source: "model",
		Expr: `sum by (cluster) (up{env="paysvc-sandbox-staging"})`, Why: "peers down too?"}}
	params := VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10, HasPromQL: true}
	r := runVerification(context.Background(), prom, nil, fakeState{total: 0},
		params,
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, composeFloor(params, "host", alerts),
		DraftRef{RootCause: "regional partition", Confidence: 0.95}, nil, model, time.Now().UTC(), nil, nil)

	if len(r.Queries) != 3 { // 2 floor + 1 model
		t.Fatalf("want 3 queries, got %d", len(r.Queries))
	}
	if !strings.Contains(r.Queries[0].Result, "up 34/37") {
		t.Fatalf("up_ratio render: %q", r.Queries[0].Result)
	}
	if !strings.Contains(r.Queries[1].Result, "0 incidents on other group keys") {
		t.Fatalf("state render: %q", r.Queries[1].Result)
	}
	if !floorFetched(r) || anyUnfetched(r) {
		t.Fatal("all fetched: floorFetched must be true, anyUnfetched false")
	}
}

// R15 predicates: one failing model query → anyUnfetched, floor still fine.
func TestRunVerificationPartialFailure(t *testing.T) {
	prom := fakeQuerier(func(expr string) (json.RawMessage, error) {
		switch {
		case strings.HasPrefix(expr, "sum(up"):
			return instantScalar(t, "10"), nil
		case strings.HasPrefix(expr, "count(up"):
			return instantScalar(t, "10"), nil
		case strings.Contains(expr, "bogus_metric"):
			return nil, errors.New("boom")
		}
		t.Fatalf("unexpected expr %q", expr)
		return nil, nil
	})
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "checkout"})}
	model := []VerificationQuery{{Kind: kindPromQL, Source: "model",
		Expr: `bogus_metric{namespace="checkout"}`, Why: "does this exist?"}}
	params := VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10, HasPromQL: true}
	r := runVerification(context.Background(), prom, nil, fakeState{total: 0},
		params,
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, composeFloor(params, "host", alerts),
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, model, time.Now().UTC(), nil, nil)

	if len(r.Queries) != 3 {
		t.Fatalf("want 3 queries, got %d", len(r.Queries))
	}
	if !floorFetched(r) {
		t.Fatalf("floor must stay fine when only the model query fails: %+v", r.Queries)
	}
	if !anyUnfetched(r) {
		t.Fatal("a failing model query must trip anyUnfetched")
	}
	failing := r.Queries[2]
	if failing.Outcome != OutcomeFailed {
		t.Fatalf("model query outcome = %q, want failed", failing.Outcome)
	}
	if !strings.Contains(failing.Result, "unavailable") {
		t.Fatalf("failing result must carry an explicit unavailable note: %q", failing.Result)
	}
}

// Prometheus down entirely → floor up_ratio failed → floorFetched false.
func TestRunVerificationPromDown(t *testing.T) {
	prom := fakeQuerier(func(_ string) (json.RawMessage, error) {
		return nil, errors.New("connection refused")
	})
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "checkout"})}
	params := VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10, HasPromQL: true}
	r := runVerification(context.Background(), prom, nil,
		fakeState{total: 1, top: []store.WindowIncident{{GroupKey: "a|b", Status: "analyzed", Severity: "warning", AlertCount: 1}}},
		params,
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, composeFloor(params, "host", alerts),
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, nil, time.Now().UTC(), nil, nil)

	if len(r.Queries) != 2 { // floor only, no model queries proposed
		t.Fatalf("want 2 queries, got %d", len(r.Queries))
	}
	if floorFetched(r) {
		t.Fatal("prometheus entirely down must fail the floor")
	}
	if !anyUnfetched(r) {
		t.Fatal("a failed floor query must also trip anyUnfetched")
	}
	upRatio := r.Queries[0]
	if upRatio.Outcome != OutcomeFailed {
		t.Fatalf("up_ratio outcome = %q, want failed", upRatio.Outcome)
	}
	iiw := r.Queries[1]
	if iiw.Outcome != OutcomeFetched {
		t.Fatalf("incidents_in_window must still fetch when only prometheus is down, got %q (%+v)", iiw.Outcome, iiw)
	}
}

// prom == nil (Prometheus unconfigured): up_ratio fails explicitly, the state
// query is unaffected (R3 note in Step 3).
func TestRunVerificationNilProm(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "checkout"})}
	params := VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10, HasPromQL: true}
	r := runVerification(context.Background(), nil, nil, fakeState{total: 0},
		params,
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, composeFloor(params, "host", alerts),
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, nil, time.Now().UTC(), nil, nil)

	upRatio := r.Queries[0]
	if upRatio.Outcome != OutcomeFailed || !strings.Contains(upRatio.Result, "prometheus not configured") {
		t.Fatalf("nil prom must fail up_ratio with an explicit note, got %+v", upRatio)
	}
	if r.Queries[1].Outcome != OutcomeEmpty {
		t.Fatalf("state query unaffected by nil prom, got %+v", r.Queries[1])
	}
	if floorFetched(r) {
		t.Fatal("nil prom must fail the floor (up_ratio never fetched)")
	}
}

// TestRunVerification_ZabbixSeedAvoidsRedundantFetch proves runVerification's
// zabbixSeed parameter (analysisResult.zabbixSeed, from chunk-02's
// FetchZabbixContext) actually reaches the round's zabbixVerifier: a seeded
// host's reachability check must serve the seed, never call the live reader.
func TestRunVerification_ZabbixSeedAvoidsRedundantFetch(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(string) (zabbix.Topology, error) {
		t.Fatal("seeded host must not hit the live ZabbixReader")
		return zabbix.Topology{}, nil
	}}
	floor := []VerificationQuery{{Kind: kindZabbixReachability, Source: "floor",
		Params: map[string]any{"hosts": []string{"db-01"}, "hosts_total": float64(1)}}}
	params := VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10, HasZabbix: true}
	seed := map[string]zabbix.Topology{
		"db-01": {Interfaces: []zabbix.IfaceState{{Addr: "a", Available: "1"}}},
	}
	r := runVerification(context.Background(), nil, z, fakeState{total: 0},
		params,
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, floor,
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, nil, time.Now().UTC(), nil, seed)

	if r.Queries[0].Outcome != OutcomeFetched {
		t.Fatalf("zabbix_reachability outcome = %q, want fetched from the seed", r.Queries[0].Outcome)
	}
}

func TestFloorFetchedAndAnyUnfetched(t *testing.T) {
	r := &VerificationRound{Queries: []VerificationQuery{
		{Source: "floor", Outcome: OutcomeFetched},
		{Source: "floor", Outcome: OutcomeEmpty},
		{Source: "model", Outcome: OutcomeFailed},
	}}
	if !floorFetched(r) {
		t.Fatal("floor all fetched/empty must be true even with a failed model query")
	}
	if !anyUnfetched(r) {
		t.Fatal("a failed model query must trip anyUnfetched")
	}

	r2 := &VerificationRound{Queries: []VerificationQuery{
		{Source: "floor", Outcome: OutcomeFailed},
		{Source: "floor", Outcome: OutcomeEmpty},
	}}
	if floorFetched(r2) {
		t.Fatal("a failed floor query must fail floorFetched")
	}
	if !anyUnfetched(r2) {
		t.Fatal("a failed floor query must trip anyUnfetched too")
	}

	if floorFetched(nil) {
		t.Fatal("nil round must not be floorFetched")
	}
	if anyUnfetched(nil) {
		t.Fatal("nil round must not be anyUnfetched")
	}
}

// A zero-backend install (no Prometheus, no Zabbix — or Zabbix configured but
// the incident lacks host identity) composes a floor of ONLY
// incidents_in_window (own-state SQLite bookkeeping). That alone must never
// satisfy floorFetched — matching the pre-Task-6 behavior where an
// unconfigured up_ratio reliably failed and kept the caveat forever on such
// an install (the 0.6 metadata-only confidence cap persona).
func TestFloorFetchedZeroBackendNeverClears(t *testing.T) {
	r := &VerificationRound{Queries: []VerificationQuery{
		{Source: "floor", Kind: kindIncidentsInWindow, Outcome: OutcomeFetched},
	}}
	if floorFetched(r) {
		t.Fatal("incidents_in_window alone (no real backend contributed) must never satisfy floorFetched")
	}
}

// The same zero-backend shape must also trip anyUnfetched — extending R15's
// clamp rail symmetrically with floorFetched's fix above. Without this, a
// zero-real-backend round (nothing failed or degraded, because nothing real
// was even asked) would report anyUnfetched == false, silently disabling the
// confidence clamp on an install where nothing was actually verified.
func TestAnyUnfetched_IncidentsInWindowOnlyCountsAsUnfetched(t *testing.T) {
	r := &VerificationRound{Queries: []VerificationQuery{
		{Source: "floor", Kind: kindIncidentsInWindow, Outcome: OutcomeFetched},
	}}
	if !anyUnfetched(r) {
		t.Fatal("incidents_in_window alone (no real backend contributed) must count as unfetched for the clamp")
	}
}

func TestVerificationLive(t *testing.T) {
	if verificationLive(nil) {
		t.Fatal("nil enrichment must not be live")
	}
	v := &VerificationEnrichment{Rounds: []VerificationRound{{Queries: []VerificationQuery{
		{Kind: kindIncidentsInWindow, Outcome: OutcomeFetched},
	}}}}
	if verificationLive(v) {
		t.Fatal("incidents_in_window alone must never count as live (R17)")
	}
	v.Rounds[0].Queries = append(v.Rounds[0].Queries, VerificationQuery{Kind: kindPromQL, Outcome: OutcomeFailed})
	if verificationLive(v) {
		t.Fatal("a FAILED promql query must not count as live")
	}
	v.Rounds[0].Queries = append(v.Rounds[0].Queries, VerificationQuery{Kind: kindPromQL, Outcome: OutcomeFetched})
	if !verificationLive(v) {
		t.Fatal("a fetched promql query must count as live evidence (R17)")
	}

	v2 := &VerificationEnrichment{Rounds: []VerificationRound{{Queries: []VerificationQuery{
		{Kind: kindUpRatio, Outcome: OutcomeFetched},
	}}}}
	if !verificationLive(v2) {
		t.Fatal("a fetched up_ratio query must also count as live evidence")
	}
}

func TestVerificationLive_ZabbixFloorCounts(t *testing.T) {
	cases := []struct {
		name string
		kind string
		out  Outcome
		want bool
	}{
		{"reachability fetched lifts", kindZabbixReachability, OutcomeFetched, true},
		{"neighbor fetched lifts", kindZabbixNeighborProblems, OutcomeFetched, true},
		{"neighbor empty does not lift", kindZabbixNeighborProblems, OutcomeEmpty, false},
		{"reachability failed does not lift", kindZabbixReachability, OutcomeFailed, false},
		{"incidents_in_window never lifts", kindIncidentsInWindow, OutcomeFetched, false},
	}
	for _, tc := range cases {
		v := &VerificationEnrichment{Rounds: []VerificationRound{{Queries: []VerificationQuery{
			{Kind: tc.kind, Outcome: tc.out}}}}}
		if got := verificationLive(v); got != tc.want {
			t.Errorf("%s: verificationLive = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRenderVerificationResults(t *testing.T) {
	r := &VerificationRound{
		Queries: []VerificationQuery{
			{Kind: kindUpRatio, Source: "floor", Why: "peer-scope health", Outcome: OutcomeFetched, Result: `up 34/37 in {namespace="x"}`},
			{Kind: kindIncidentsInWindow, Source: "floor", Outcome: OutcomeEmpty, Result: "0 incidents on other group keys (60m)"},
			{Kind: kindPromQL, Source: sourceOperator, Why: "probe", Outcome: OutcomeFetched, Result: "pvc_bytes 1"},
		},
	}
	var b strings.Builder
	renderVerificationResults(&b, r)
	out := b.String()
	if !strings.Contains(out, "up 34/37") || !strings.Contains(out, "0 incidents on other group keys") {
		t.Fatalf("render missing query results: %q", out)
	}
	if !strings.Contains(out, "peer-scope health") {
		t.Fatalf("render missing why: %q", out)
	}
	if !strings.Contains(out, "- [operator/promql]") {
		t.Fatalf("render must tag operator-sourced queries, got %q", out)
	}
}

func TestRenderVerificationResultsNilRound(t *testing.T) {
	var b strings.Builder
	renderVerificationResults(&b, nil)
	if b.String() != "" {
		t.Fatalf("nil round must render nothing, got %q", b.String())
	}
}

func TestSnapshotExecutor_ServesFrozenAndMisses(t *testing.T) {
	frozen := []VerificationQuery{
		{Kind: "up_ratio", Source: "floor", Expr: `{namespace="prod"}`, Outcome: OutcomeFetched, Result: `up 9/10 in {namespace="prod"}`},
		{Kind: "incidents_in_window", Source: "floor", Params: map[string]any{"window_minutes": float64(60)}, Outcome: OutcomeFetched, Result: "2 other incidents"},
		{Kind: "promql", Source: "capture", Expr: "node_network_up", Outcome: OutcomeFetched, Result: "node_network_up 0"},
	}
	exec := newSnapshotExecutor(frozen)

	hit := VerificationQuery{Kind: "promql", Source: "model", Expr: "node_network_up"}
	exec.execute(context.Background(), &hit)
	if hit.Outcome != OutcomeFetched || hit.Result != "node_network_up 0" {
		t.Fatalf("frozen result not served: %+v", hit)
	}

	miss := VerificationQuery{Kind: "promql", Source: "model", Expr: "rate(other[5m])"}
	exec.execute(context.Background(), &miss)
	if miss.Outcome != OutcomeEmpty || miss.Result != "no data (replay)" {
		t.Fatalf("miss shape wrong: %+v", miss)
	}

	// incidents_in_window matches on window_minutes regardless of number encoding
	win := VerificationQuery{Kind: "incidents_in_window", Source: "floor", Params: map[string]any{"window_minutes": 60}}
	exec.execute(context.Background(), &win)
	if win.Outcome != OutcomeFetched {
		t.Fatalf("window match failed: %+v", win)
	}

	if got := exec.fidelity(); got != "partial (1/3 verification queries unmatched)" {
		t.Fatalf("fidelity: %q", got)
	}
}

// countingExecutor counts execute calls, useful for asserting runVerificationWith
// dispatches every query (floor + model) through the executor exactly once.
type countingExecutor struct{ calls int }

func (e *countingExecutor) execute(_ context.Context, q *VerificationQuery) {
	e.calls++
	q.Outcome = OutcomeFetched
	q.Result = "ok"
}

func TestRunVerificationWith_UsesExecutorForEveryQuery(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "prod"})}
	exec := &countingExecutor{}
	params := VerificationParams{MaxQueries: 4, QueryTimeoutSeconds: 5, MaxSeries: 100, HasPromQL: true}
	modelQ := []VerificationQuery{{Kind: kindPromQL, Source: "model", Expr: "up"}}

	round := runVerificationWith(context.Background(), exec, params, composeFloor(params, "host", alerts), DraftRef{}, nil, modelQ, time.Now())
	if exec.calls != 3 { // 2 floor queries + 1 model query
		t.Fatalf("executor calls = %d, want 3", exec.calls)
	}
	if len(round.Queries) != 3 {
		t.Fatalf("round queries = %d, want 3", len(round.Queries))
	}
}

// T6: operator-sourced (steering) queries ride the round between the floor
// and the model's own proposals — floor, operator, model (D10) — and are
// exempt from MaxQueries (the countingExecutor fake, reused from the test
// above, fills every dispatched query's Outcome/Result regardless of source).
func TestRunVerificationWith_OperatorQueriesRideTheRound(t *testing.T) {
	exec := &countingExecutor{}
	op := []VerificationQuery{{Kind: kindPromQL, Source: sourceOperator, Expr: "pvc_bytes", Why: "probe"}}
	model := []VerificationQuery{{Kind: kindPromQL, Source: "model", Expr: "up", Why: "check"}}
	params := VerificationParams{QueryTimeoutSeconds: 5, HasPromQL: true}
	round := runVerificationWith(context.Background(), exec, params,
		composeFloor(params, "host", nil), DraftRef{}, op, model, time.Now())
	if len(round.Queries) != 4 { // 2 floor + 1 operator + 1 model
		t.Fatalf("want 4 queries, got %d", len(round.Queries))
	}
	if round.Queries[2].Source != sourceOperator || round.Queries[2].Expr != "pvc_bytes" {
		t.Fatalf("operator query must follow the floor, got %+v", round.Queries[2])
	}
}

// deadlineRecordingExecutor records, for each dispatched query, the duration
// remaining until its context's deadline — pins minPerQueryTimeout's floor
// without depending on a real timeout actually firing (the fake executor
// returns instantly).
type deadlineRecordingExecutor struct {
	remaining []time.Duration
}

func (e *deadlineRecordingExecutor) execute(ctx context.Context, q *VerificationQuery) {
	if dl, ok := ctx.Deadline(); ok {
		e.remaining = append(e.remaining, time.Until(dl))
	} else {
		e.remaining = append(e.remaining, -1)
	}
	q.Outcome = OutcomeFetched
	q.Result = "ok"
}

// TestRunVerificationWith_PerQueryFloor_FullElevenQueryCase pins the D10
// floor (user-approved deviation): with the full 11-query case steering can
// produce (2 floor + 5 operator + 4 model) sharing a small total budget, a
// naive equal split (5s / 11 ≈ 454ms) would shrink every query's slice —
// including the floor's own essential up_ratio check — well under a second.
// minPerQueryTimeout ensures no single query's slice drops below it.
func TestRunVerificationWith_PerQueryFloor_FullElevenQueryCase(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"namespace": "prod"})}
	exec := &deadlineRecordingExecutor{}
	params := VerificationParams{QueryTimeoutSeconds: 5, HasPromQL: true} // 5s / 11 ≈ 454ms naive — well under the floor

	operatorQ := make([]VerificationQuery, 5)
	for i := range operatorQ {
		operatorQ[i] = VerificationQuery{Kind: kindPromQL, Source: sourceOperator, Expr: fmt.Sprintf("s%d", i)}
	}
	modelQ := make([]VerificationQuery, 4)
	for i := range modelQ {
		modelQ[i] = VerificationQuery{Kind: kindPromQL, Source: "model", Expr: fmt.Sprintf("m%d", i)}
	}

	round := runVerificationWith(context.Background(), exec, params, composeFloor(params, "host", alerts), DraftRef{}, operatorQ, modelQ, time.Now())
	if len(round.Queries) != 11 {
		t.Fatalf("want 11 queries (2 floor + 5 operator + 4 model), got %d", len(round.Queries))
	}
	if len(exec.remaining) != 11 {
		t.Fatalf("want 11 executed queries, got %d", len(exec.remaining))
	}
	const tolerance = 200 * time.Millisecond // wall-clock slack for ctx creation between capture and check
	for i, d := range exec.remaining {
		if d < minPerQueryTimeout-tolerance {
			t.Errorf("query %d: per-query slice %v below the floor %v", i, d, minPerQueryTimeout)
		}
	}
}
