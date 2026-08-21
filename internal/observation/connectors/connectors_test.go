// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

var (
	testStart = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	testEnd   = time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
)

// runPlan executes one plan through the real Runner and Catalog, so every
// assertion below is about what the production path actually produces.
func runPlan(t *testing.T, sources Sources, plan observationmodel.Plan, allowed observation.Scope) ([]observationmodel.Fact, observation.Run) {
	t.Helper()
	runner := observation.NewRunner(observation.DefaultCatalog(sources.Adapters()), 8, 4)
	facts, runs, err := runner.Execute(context.Background(), []observationmodel.Plan{plan}, allowed)
	if err != nil {
		t.Fatalf("runner rejected the plan: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs=%d, want one", len(runs))
	}
	return facts, runs[0]
}

func params(t *testing.T, values map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// --------------------------------------------------------------------------
// Zabbix problem timeline (the capability Task 6 built)
// --------------------------------------------------------------------------

type fakeZabbix struct {
	series   zabbix.Series
	problems []zabbix.ProblemHistoryRow
	err      error
	calls    int
}

func (f *fakeZabbix) MetricHistory(_ context.Context, _, _ string, _, _ time.Time, _ int) (zabbix.Series, error) {
	f.calls++
	return f.series, f.err
}

func (f *fakeZabbix) ProblemHistory(_ context.Context, _ string, _, _ time.Time, _ string, _ int) ([]zabbix.ProblemHistoryRow, error) {
	f.calls++
	return f.problems, f.err
}

func problemPlan(t *testing.T) observationmodel.Plan {
	t.Helper()
	return observationmodel.Plan{
		Capability: observationmodel.CapabilityZabbixProblemHistory,
		Scope:      map[string]string{"host": "db-1"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 3, "severity_min": "3"}),
		Start:      testStart, End: testEnd, Limit: 100, Why: "duration and recurrence evidence", Budget: 3,
	}
}

// problemScope carries only the keys this capability permits: situation_id is
// a scope key for store_read alone, so every other plan names the Situation in
// its parameters instead.
func problemScope() observation.Scope {
	return observation.Scope{"host": {"db-1"}}
}

func TestZabbixProblemHistoryProducesEpisodeFactsThroughTheRunner(t *testing.T) {
	resolved := testStart.Add(20 * time.Minute)
	source := &fakeZabbix{problems: []zabbix.ProblemHistoryRow{
		{EventID: "e-2", TriggerID: "t-9", Name: "Disk space low", Severity: "4",
			StartedAt: testStart.Add(10 * time.Minute), ResolvedAt: &resolved, DurationSeconds: 600, Acknowledged: true},
		{EventID: "e-1", TriggerID: "t-9", Name: "Disk space low", Severity: "4",
			StartedAt: testStart, DurationSeconds: 300, Ongoing: true},
	}}
	facts, run := runPlan(t, Sources{Zabbix: source}, problemPlan(t), problemScope())

	if run.Status != observationmodel.ResultStatusConfirmedValue {
		t.Fatalf("run status=%q err=%q, want a confirmed value", run.Status, run.ErrorClass)
	}
	if run.Cost.SourceCalls != 3 || source.calls != 1 {
		t.Fatalf("cost=%+v zabbix calls=%d", run.Cost, source.calls)
	}
	if len(facts) != 2 {
		t.Fatalf("facts=%d, want one per problem episode", len(facts))
	}
	// Deterministic order, so a replay produces byte-identical evidence.
	if facts[0].Subject != "db-1:e-1" || facts[1].Subject != "db-1:e-2" {
		t.Fatalf("subjects=%q,%q", facts[0].Subject, facts[1].Subject)
	}
	for _, fact := range facts {
		if fact.Kind != "problem_episode" || fact.SituationID != "sit-1" || fact.InputVersion != 3 {
			t.Fatalf("fact identity=%+v", fact)
		}
		if fact.SourceCapability != observationmodel.CapabilityZabbixProblemHistory || !fact.Material {
			t.Fatalf("fact classification=%+v", fact)
		}
	}
	var episode problemEpisodeFact
	if err := json.Unmarshal(facts[1].Value, &episode); err != nil {
		t.Fatal(err)
	}
	if episode.ResolvedAt == nil || !episode.ResolvedAt.Equal(resolved) || episode.DurationSeconds != 600 || !episode.Acknowledged {
		t.Fatalf("episode=%+v, want the real resolved timeline", episode)
	}
	var ongoing problemEpisodeFact
	if err := json.Unmarshal(facts[0].Value, &ongoing); err != nil {
		t.Fatal(err)
	}
	if !ongoing.Ongoing || ongoing.ResolvedAt != nil {
		t.Fatalf("ongoing episode=%+v", ongoing)
	}
}

func TestConfirmedEmptyIsDistinctFromUnavailable(t *testing.T) {
	// The source answered, and the answer was nothing.
	facts, run := runPlan(t, Sources{Zabbix: &fakeZabbix{}}, problemPlan(t), problemScope())
	if run.Status != observationmodel.ResultStatusConfirmedEmpty || len(facts) != 0 {
		t.Fatalf("empty read: status=%q facts=%d, want a confirmed empty", run.Status, len(facts))
	}

	// No source at all: honestly unavailable, never a confirmed empty.
	facts, run = runPlan(t, Sources{}, problemPlan(t), problemScope())
	if run.Status != observationmodel.ResultStatusUnavailable || len(facts) != 0 {
		t.Fatalf("unwired capability: status=%q facts=%d, want unavailable", run.Status, len(facts))
	}
	if run.ErrorClass != "unavailable" {
		t.Fatalf("error class=%q", run.ErrorClass)
	}
}

func TestUnwiredSlotsDegradeCleanlyAndAreNamed(t *testing.T) {
	sources := Sources{Zabbix: &fakeZabbix{}}
	unavailable := sources.Unavailable()
	want := map[string]bool{
		"store_read": true, "prometheus_query": true, "loki_query": true,
		"sentry_issues": true, "change_events": true,
	}
	if len(unavailable) != len(want) {
		t.Fatalf("unavailable=%v", unavailable)
	}
	for _, name := range unavailable {
		if !want[name] {
			t.Fatalf("unexpected unavailable capability %q (zabbix is wired)", name)
		}
	}
	// Every capability stays registered, so an operator sees the whole
	// vocabulary rather than a silently shorter one.
	catalog := observation.DefaultCatalog(sources.Adapters())
	if len(catalog.Capabilities()) != 7 {
		t.Fatalf("registered capabilities=%v", catalog.Capabilities())
	}
}

func TestZabbixConnectorFailureIsReportedNotSilentlyEmpty(t *testing.T) {
	source := &fakeZabbix{err: errors.New("zabbix: api unreachable")}
	facts, run := runPlan(t, Sources{Zabbix: source}, problemPlan(t), problemScope())
	if run.Status != observationmodel.ResultStatusFailed || run.ErrorClass != "connector_error" || len(facts) != 0 {
		t.Fatalf("status=%q class=%q facts=%d", run.Status, run.ErrorClass, len(facts))
	}
}

func TestZabbixMetricRangeReducesToBoundedSeries(t *testing.T) {
	source := &fakeZabbix{series: zabbix.Series{
		Name: "CPU utilization", Units: "%", Source: "history",
		Points: []zabbix.SeriesPoint{
			{Clock: testStart, Value: "12.5"},
			{Clock: testStart.Add(30 * time.Minute), Value: "91.25"},
		},
	}}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityZabbixMetricRange,
		Scope:      map[string]string{"host": "db-1"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 2, "item_key": "system.cpu.util"}),
		Start:      testStart, End: testEnd, Limit: 500, Why: "confirm the reported saturation", Budget: 2,
	}
	facts, run := runPlan(t, Sources{Zabbix: source}, plan, observation.Scope{"host": {"db-1"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue || len(facts) != 1 {
		t.Fatalf("status=%q facts=%d", run.Status, len(facts))
	}
	if facts[0].SituationID != "sit-1" || facts[0].InputVersion != 2 {
		t.Fatalf("fact identity=%q/%d, want the Situation the plan named", facts[0].SituationID, facts[0].InputVersion)
	}
	var series metricSeriesFact
	if err := json.Unmarshal(facts[0].Value, &series); err != nil {
		t.Fatal(err)
	}
	if series.Samples != 2 || series.Min == nil || *series.Min != 12.5 || series.Max == nil || *series.Max != 91.25 {
		t.Fatalf("series=%+v", series)
	}
	if series.Latest == nil || *series.Latest != 91.25 {
		t.Fatalf("latest=%v, want the newest sample", series.Latest)
	}
}

// --------------------------------------------------------------------------
// Prometheus
// --------------------------------------------------------------------------

type fakePrometheus struct {
	payload json.RawMessage
	err     error
	ranged  bool
}

func (f *fakePrometheus) QueryInstant(context.Context, string, time.Time, int) (json.RawMessage, error) {
	return f.payload, f.err
}

func (f *fakePrometheus) QueryRange(context.Context, string, time.Time, time.Time, time.Duration) (json.RawMessage, error) {
	f.ranged = true
	return f.payload, f.err
}

func TestPrometheusQueryReducesAMatrixToBoundedShape(t *testing.T) {
	source := &fakePrometheus{payload: json.RawMessage(`{
		"resultType":"matrix",
		"result":[{"metric":{"instance":"db-1"},"values":[[1755680400,"0.25"],[1755682200,"0.90"]]}]
	}`)}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityPrometheusQuery,
		Scope:      map[string]string{"service": "api"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 1, "query": `rate(errors[5m])`}),
		Start:      testStart, End: testEnd, Limit: 100, Why: "confirm the error rate", Budget: 1,
	}
	facts, run := runPlan(t, Sources{Prometheus: source}, plan, observation.Scope{"service": {"api"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue || len(facts) != 1 {
		t.Fatalf("status=%q class=%q facts=%d", run.Status, run.ErrorClass, len(facts))
	}
	if !source.ranged {
		t.Fatal("a windowed plan did not use the range endpoint")
	}
	var series metricSeriesFact
	if err := json.Unmarshal(facts[0].Value, &series); err != nil {
		t.Fatal(err)
	}
	if series.Series != 1 || series.Samples != 2 || series.Latest == nil || *series.Latest != 0.90 {
		t.Fatalf("series=%+v", series)
	}
	if series.Query != `rate(errors[5m])` {
		t.Fatalf("query=%q, want the exact expression that ran", series.Query)
	}
	// The raw connector envelope must not survive into evidence.
	if bytesContain(facts[0].Value, "resultType") {
		t.Fatalf("raw prometheus response leaked into the fact: %s", facts[0].Value)
	}
}

// --------------------------------------------------------------------------
// Logs
// --------------------------------------------------------------------------

type fakeLogs struct{ payload json.RawMessage }

func (f fakeLogs) QueryRange(context.Context, string, time.Time, time.Time, int, string) (json.RawMessage, error) {
	return f.payload, nil
}

func TestLogQueryKeepsVolumeAndDropsLineBodies(t *testing.T) {
	source := fakeLogs{payload: json.RawMessage(`{
		"resultType":"streams",
		"result":[{"stream":{"app":"api"},"values":[["1755680400000000000","secret token abc"],["1755682200000000000","another"]]}]
	}`)}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityLokiQuery,
		Scope:      map[string]string{"service": "api"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 4, "query": `{app="api"} |= "error"`}),
		Start:      testStart, End: testEnd, Limit: 200, Why: "confirm the error burst", Budget: 1,
	}
	facts, run := runPlan(t, Sources{Logs: source}, plan, observation.Scope{"service": {"api"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue || len(facts) != 1 {
		t.Fatalf("status=%q facts=%d", run.Status, len(facts))
	}
	var volume logVolumeFact
	if err := json.Unmarshal(facts[0].Value, &volume); err != nil {
		t.Fatal(err)
	}
	if volume.Lines != 2 || volume.Streams != 1 {
		t.Fatalf("volume=%+v", volume)
	}
	if bytesContain(facts[0].Value, "secret token") {
		t.Fatalf("a log line body leaked into evidence: %s", facts[0].Value)
	}
}

// --------------------------------------------------------------------------
// Sentry
// --------------------------------------------------------------------------

type fakeSentry struct{ issues []sentry.Issue }

func (f fakeSentry) ListIssues(context.Context, string, string, time.Time, time.Time, string) ([]sentry.Issue, error) {
	return f.issues, nil
}

func TestSentryIssuesKeepShapeAndDropTitles(t *testing.T) {
	source := fakeSentry{issues: []sentry.Issue{{
		ID: "42", Title: "ValueError: user bob@example.com not found", Culprit: "app/api.py",
		Level: "error", UserCount: 12, FirstSeen: testStart, LastSeen: testEnd,
	}}}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilitySentryIssues,
		Scope:      map[string]string{"project": "api", "environment": "prod"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 1}),
		Start:      testStart, End: testEnd, Limit: 50, Why: "confirm the error surface", Budget: 1,
	}
	facts, run := runPlan(t, Sources{Sentry: source}, plan,
		observation.Scope{"project": {"api"}, "environment": {"prod"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue || len(facts) != 1 {
		t.Fatalf("status=%q facts=%d", run.Status, len(facts))
	}
	var issue errorIssueFact
	if err := json.Unmarshal(facts[0].Value, &issue); err != nil {
		t.Fatal(err)
	}
	if issue.IssueID != "42" || issue.Users != 12 || issue.Culprit != "app/api.py" {
		t.Fatalf("issue=%+v", issue)
	}
	if bytesContain(facts[0].Value, "bob@example.com") {
		t.Fatalf("the exception value leaked into evidence: %s", facts[0].Value)
	}
}

// --------------------------------------------------------------------------
// Changes and the local store
// --------------------------------------------------------------------------

type fakeChanges struct{ changes []store.Change }

func (f fakeChanges) ChangesInWindow(context.Context, time.Time, time.Time) ([]store.Change, error) {
	return f.changes, nil
}

func TestChangeEventsAreNarrowedToPlanScope(t *testing.T) {
	source := fakeChanges{changes: []store.Change{
		{ID: "c-1", Source: "sentry", Kind: "deploy", Title: "api v9", Labels: map[string]string{"service": "api"}, OccurredAt: testStart},
		{ID: "c-2", Source: "sentry", Kind: "deploy", Title: "billing v3", Labels: map[string]string{"service": "billing"}, OccurredAt: testStart},
		{ID: "c-3", Source: "manual", Kind: "config", Title: "unlabelled", Labels: map[string]string{}, OccurredAt: testStart},
	}}
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityChangeEvents,
		Scope:      map[string]string{"service": "api"},
		Parameters: params(t, map[string]any{"situation_id": "sit-1", "input_version": 1}),
		Start:      testStart, End: testEnd, Limit: 100, Why: "look for a correlated deploy", Budget: 1,
	}
	facts, run := runPlan(t, Sources{Changes: source}, plan, observation.Scope{"service": {"api"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue {
		t.Fatalf("status=%q class=%q", run.Status, run.ErrorClass)
	}
	// c-2 disagrees with the scope; c-3 has no opinion and is kept.
	if len(facts) != 2 {
		t.Fatalf("facts=%d, want the in-scope and unlabelled changes", len(facts))
	}
	for _, fact := range facts {
		if fact.Subject == "c-2" {
			t.Fatal("an out-of-scope deploy became this Situation's evidence")
		}
	}
}

type fakeSituations struct {
	deliveries []store.AlertDelivery
	incidents  []store.Incident
}

func (f fakeSituations) SituationDeliveries(context.Context, string) ([]store.AlertDelivery, error) {
	return f.deliveries, nil
}

func (f fakeSituations) SituationMemberIncidents(context.Context, string) ([]store.Incident, error) {
	return f.incidents, nil
}

func storeReadPlan(t *testing.T) observationmodel.Plan {
	t.Helper()
	return observationmodel.Plan{
		Capability: observationmodel.CapabilityStoreRead,
		Scope:      map[string]string{"situation_id": "sit-1"},
		Parameters: params(t, map[string]any{"input_version": 7, "resource": "deliveries"}),
		Start:      testStart, End: testEnd, Limit: 100, Why: "restate the delivery ledger", Budget: 1,
	}
}

func TestStoreReadReducesTheDeliveryLedger(t *testing.T) {
	source := fakeSituations{
		incidents: []store.Incident{{ID: "inc-1"}},
		deliveries: []store.AlertDelivery{
			{ID: "d-1", Source: "alertmanager", ReceivedAt: testStart,
				Alert: store.Alert{Fingerprint: "fp-1", Status: "firing", Labels: map[string]string{"severity": "warning"}}},
			{ID: "d-2", Source: "alertmanager", ReceivedAt: testEnd,
				Alert: store.Alert{Fingerprint: "fp-1", Status: "firing", Labels: map[string]string{"severity": "critical"}}},
		},
	}
	facts, run := runPlan(t, Sources{Situations: source}, storeReadPlan(t), observation.Scope{"situation_id": {"sit-1"}})
	if run.Status != observationmodel.ResultStatusConfirmedValue || len(facts) != 1 {
		t.Fatalf("status=%q class=%q facts=%d", run.Status, run.ErrorClass, len(facts))
	}
	var lifecycle symptomLifecycleFact
	if err := json.Unmarshal(facts[0].Value, &lifecycle); err != nil {
		t.Fatal(err)
	}
	if lifecycle.Deliveries != 2 || lifecycle.Severity != "critical" || lifecycle.Lifecycle != "firing" {
		t.Fatalf("lifecycle=%+v, want the newest delivery's state over the whole ledger", lifecycle)
	}
	if !lifecycle.FirstSeen.Equal(testStart) || !lifecycle.LastSeen.Equal(testEnd) {
		t.Fatalf("span=%s..%s", lifecycle.FirstSeen, lifecycle.LastSeen)
	}
}

// --------------------------------------------------------------------------
// Cross-cutting contracts
// --------------------------------------------------------------------------

func TestFactIdentityIsDeterministicAcrossRuns(t *testing.T) {
	source := fakeSituations{
		incidents:  []store.Incident{{ID: "inc-1"}},
		deliveries: []store.AlertDelivery{{ID: "d-1", Source: "alertmanager", ReceivedAt: testStart, Alert: store.Alert{Fingerprint: "fp-1", Status: "firing"}}},
	}
	first, _ := runPlan(t, Sources{Situations: source}, storeReadPlan(t), observation.Scope{"situation_id": {"sit-1"}})
	second, _ := runPlan(t, Sources{Situations: source}, storeReadPlan(t), observation.Scope{"situation_id": {"sit-1"}})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("facts=%d/%d", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[0].Digest != second[0].Digest {
		t.Fatalf("replay produced a different identity: %s/%s vs %s/%s",
			first[0].ID, first[0].Digest, second[0].ID, second[0].Digest)
	}
}

func TestPlanWithoutInputVersionFailsRatherThanGuessing(t *testing.T) {
	plan := storeReadPlan(t)
	plan.Parameters = params(t, map[string]any{"resource": "deliveries"})
	facts, run := runPlan(t, Sources{Situations: fakeSituations{}}, plan, observation.Scope{"situation_id": {"sit-1"}})
	if run.Status != observationmodel.ResultStatusFailed || len(facts) != 0 {
		t.Fatalf("status=%q facts=%d, want a reported input fault", run.Status, len(facts))
	}
}

func bytesContain(value json.RawMessage, needle string) bool {
	return len(value) > 0 && json.Valid(value) && containsString(string(value), needle)
}

func containsString(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
