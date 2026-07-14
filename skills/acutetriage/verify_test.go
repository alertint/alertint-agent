// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
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
	if got := parentScope(alerts); got != `{namespace="paysvc-sandbox-staging"}` {
		t.Fatalf("got %q", got)
	}
}

// Host-only alert → unscoped global ratio (spec R2).
func TestParentScopeInstanceOnlyIsUnscoped(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "10.0.0.1:9100"})}
	if got := parentScope(alerts); got != "" {
		t.Fatalf("want unscoped, got %q", got)
	}
}

// T1 half 1: the floor is always two queries, regardless of anything.
func TestFloorPlanAlways(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "x"})}
	fp := floorPlan(alerts)
	if len(fp) != 2 || fp[0].Kind != kindUpRatio || fp[1].Kind != kindIncidentsInWindow {
		t.Fatalf("unexpected floor: %+v", fp)
	}
	for _, q := range fp {
		if q.Source != "floor" {
			t.Fatalf("floor query mislabeled: %+v", q)
		}
	}
}

// T2: a malformed verification block degrades to nil (floor-only), never errors.
func TestParseVerificationPlanMalformed(t *testing.T) {
	raw := json.RawMessage(`{"analysis_name":"x","verification":{"queries":"not-a-list"}}`)
	if got := parseVerificationPlan(raw, 4, nil, "inc1"); got != nil {
		t.Fatalf("want nil on malformed, got %+v", got)
	}
}

// Cap + closed kind set: unknown kinds dropped, list capped at maxQueries (R3/R4).
func TestParseVerificationPlanCapAndKinds(t *testing.T) {
	raw := json.RawMessage(`{"verification":{"queries":[
		{"kind":"promql","expr":"q1"},{"kind":"sql","expr":"DROP TABLE"},
		{"kind":"promql","expr":"q2"},{"kind":"incidents_in_window","params":{"window_minutes":30}},
		{"kind":"promql","expr":"q3"},{"kind":"promql","expr":"q4"}]}}`)
	got := parseVerificationPlan(raw, 4, nil, "inc1")
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
	r := runVerification(context.Background(), prom, fakeState{total: 0},
		VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10},
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, alerts,
		DraftRef{RootCause: "regional partition", Confidence: 0.95}, model, time.Now().UTC(), nil)

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
	r := runVerification(context.Background(), prom, fakeState{total: 0},
		VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10},
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, alerts,
		DraftRef{RootCause: "x", Confidence: 0.8}, model, time.Now().UTC(), nil)

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
	r := runVerification(context.Background(), prom,
		fakeState{total: 1, top: []store.WindowIncident{{GroupKey: "a|b", Status: "analyzed", Severity: "warning", AlertCount: 1}}},
		VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10},
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, alerts,
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, time.Now().UTC(), nil)

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
	r := runVerification(context.Background(), nil, fakeState{total: 0},
		VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 10},
		store.Incident{ID: "inc1", GroupKey: "db|stolon"}, alerts,
		DraftRef{RootCause: "x", Confidence: 0.8}, nil, time.Now().UTC(), nil)

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

func TestRenderVerificationResults(t *testing.T) {
	r := &VerificationRound{
		Queries: []VerificationQuery{
			{Kind: kindUpRatio, Source: "floor", Why: "peer-scope health", Outcome: OutcomeFetched, Result: `up 34/37 in {namespace="x"}`},
			{Kind: kindIncidentsInWindow, Source: "floor", Outcome: OutcomeEmpty, Result: "0 incidents on other group keys (60m)"},
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
}

func TestRenderVerificationResultsNilRound(t *testing.T) {
	var b strings.Builder
	renderVerificationResults(&b, nil)
	if b.String() != "" {
		t.Fatalf("nil round must render nothing, got %q", b.String())
	}
}
