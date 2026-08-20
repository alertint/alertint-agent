// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

type executorFunc func(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error)

func (f executorFunc) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
	return f(ctx, plan)
}

func TestValidatePlanRejectsMutationAndUnboundedScope(t *testing.T) {
	cat := DefaultCatalog(Adapters{})
	start := mustObservationTime(t, "2026-08-20T00:00:00Z")
	end := mustObservationTime(t, "2026-08-20T01:00:00Z")
	for _, plan := range []observationmodel.Plan{
		{Capability: observationmodel.CapabilityZabbixProblemHistory, Scope: map[string]string{}, Start: start, End: end, Limit: 10, Why: "compare prior episodes"},
		{Capability: "remediate_host", Scope: map[string]string{"host": "db-1"}, Start: start, End: end, Limit: 10, Why: "fix it"},
	} {
		if err := cat.Validate(plan, Scope{"host": {"db-1"}}); err == nil {
			t.Fatalf("accepted %+v", plan)
		}
	}
}

func TestValidatePlanRejectsNonCanonicalWindowVocabularyAndFastSampling(t *testing.T) {
	cat := DefaultCatalog(Adapters{})
	start := mustObservationTime(t, "2026-08-20T00:00:00Z")
	end := mustObservationTime(t, "2026-08-20T01:00:00Z")
	valid := observationmodel.Plan{
		Capability: observationmodel.CapabilityZabbixMetricRange,
		Scope:      map[string]string{"host": "db-1"},
		Parameters: json.RawMessage(`{"item_key":"system.cpu.util","sample_interval_seconds":60}`),
		Start:      start, End: end, Limit: 20, Why: "measure persistence",
	}
	cases := []struct {
		name   string
		mutate func(*observationmodel.Plan)
		want   string
	}{
		{"offset time", func(p *observationmodel.Plan) {
			p.Start = time.Date(2026, 8, 20, 3, 0, 0, 0, time.FixedZone("EEST", 3*3600))
		}, "canonical utc"},
		{"inverted window", func(p *observationmodel.Plan) { p.End = p.Start }, "window"},
		{"outside scope", func(p *observationmodel.Plan) { p.Scope["host"] = "db-2" }, "vocabulary unresolved"},
		{"recursive model", func(p *observationmodel.Plan) {
			p.Parameters = json.RawMessage(`{"item_key":"system.cpu.util","model":"ask-another-model"}`)
		}, "recursive model"},
		{"sampling too fast", func(p *observationmodel.Plan) {
			p.Parameters = json.RawMessage(`{"item_key":"system.cpu.util","sample_interval_seconds":1}`)
		}, "freshness"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := valid
			plan.Scope = map[string]string{"host": valid.Scope["host"]}
			tc.mutate(&plan)
			err := cat.Validate(plan, Scope{"host": {"db-1"}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunnerPreservesClosedEmptyUnavailableAndBudgetStates(t *testing.T) {
	now := mustObservationTime(t, "2026-08-20T02:00:00Z")
	empty := executorFunc(func(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
		return []observationmodel.Fact{}, Cost{SourceCalls: 1}, nil
	})
	unavailable := executorFunc(func(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
		return nil, Cost{}, ErrUnavailable
	})
	cat := DefaultCatalog(Adapters{StoreRead: empty, ChangeEvents: unavailable})
	runner := NewRunner(cat, 2, 2)
	runner.clock = func() time.Time { return now }
	plans := []observationmodel.Plan{
		validPlan(observationmodel.CapabilityStoreRead, map[string]string{"situation_id": "s-1"}, now.Add(-time.Hour), now),
		validPlan(observationmodel.CapabilityChangeEvents, map[string]string{"host": "db-1"}, now.Add(-time.Hour), now),
		validPlan(observationmodel.CapabilityStoreRead, map[string]string{"situation_id": "s-1"}, now.Add(-time.Hour), now),
	}
	facts, runs, err := runner.Execute(context.Background(), plans, Scope{"situation_id": {"s-1"}, "host": {"db-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 0 || len(runs) != 3 {
		t.Fatalf("facts=%+v runs=%+v", facts, runs)
	}
	want := []observationmodel.ResultStatus{
		observationmodel.ResultStatusConfirmedEmpty,
		observationmodel.ResultStatusUnavailable,
		observationmodel.ResultStatusWithheldByBudget,
	}
	for i := range want {
		if runs[i].Status != want[i] {
			t.Fatalf("run[%d].status=%q, want %q", i, runs[i].Status, want[i])
		}
	}
}

func TestRunnerBoundsTimeoutCostAndReducedResultSize(t *testing.T) {
	now := mustObservationTime(t, "2026-08-20T02:00:00Z")
	blocking := executorFunc(func(ctx context.Context, _ observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
		<-ctx.Done()
		return nil, Cost{}, ctx.Err()
	})
	oversize := executorFunc(func(_ context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
		return []observationmodel.Fact{{
			ID: "fact-large", SituationID: "s-1", InputVersion: 1, Kind: "metric", Subject: "db-1",
			Value:            json.RawMessage(`{"value":"` + strings.Repeat("x", 2048) + `"}`),
			SourceCapability: plan.Capability, ObservedAt: now,
			Freshness: observationmodel.FreshnessFresh, ResultStatus: observationmodel.ResultStatusConfirmedValue,
			Digest: "digest-large", EvidenceRefs: []string{}, Material: true,
		}}, Cost{SourceCalls: 1}, nil
	})
	cat := NewCatalog(
		Capability{Name: observationmodel.CapabilityStoreRead, ReadOnly: true, ScopeKeys: []string{"situation_id"}, RequiredScope: []string{"situation_id"}, MaxWindow: time.Hour, MaxLimit: 10, Freshness: time.Second, Timeout: 10 * time.Millisecond, MaxResultBytes: 128, MaxCost: Cost{SourceCalls: 1}, Executor: blocking},
		Capability{Name: observationmodel.CapabilityChangeEvents, ReadOnly: true, ScopeKeys: []string{"situation_id"}, RequiredScope: []string{"situation_id"}, MaxWindow: time.Hour, MaxLimit: 10, Freshness: time.Second, Timeout: time.Second, MaxResultBytes: 128, MaxCost: Cost{SourceCalls: 1}, Executor: oversize},
	)
	runner := NewRunner(cat, 2, 1)
	runner.clock = func() time.Time { return now }
	plans := []observationmodel.Plan{
		validPlan(observationmodel.CapabilityStoreRead, map[string]string{"situation_id": "s-1"}, now.Add(-time.Minute), now),
		validPlan(observationmodel.CapabilityChangeEvents, map[string]string{"situation_id": "s-1"}, now.Add(-time.Minute), now),
	}
	facts, runs, err := runner.Execute(context.Background(), plans, Scope{"situation_id": {"s-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 0 {
		t.Fatalf("oversize fact escaped reduction bound: %+v", facts)
	}
	if runs[0].Status != observationmodel.ResultStatusFailed || runs[0].ErrorClass != "timeout" {
		t.Fatalf("timeout run=%+v", runs[0])
	}
	if runs[1].Status != observationmodel.ResultStatusTruncated || !runs[1].Truncated {
		t.Fatalf("oversize run=%+v", runs[1])
	}
}

func TestRunnerRejectsInvalidPlanBeforeCallingExecutor(t *testing.T) {
	called := false
	executor := executorFunc(func(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
		called = true
		return nil, Cost{}, nil
	})
	cat := DefaultCatalog(Adapters{ZabbixProblemHistory: executor})
	runner := NewRunner(cat, 1, 1)
	now := mustObservationTime(t, "2026-08-20T02:00:00Z")
	plan := validPlan(observationmodel.CapabilityZabbixProblemHistory, map[string]string{"host": "outside"}, now.Add(-time.Hour), now)
	_, _, err := runner.Execute(context.Background(), []observationmodel.Plan{plan}, Scope{"host": {"db-1"}})
	if err == nil || !errors.Is(err, ErrVocabularyUnresolved) || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func validPlan(capability observationmodel.Capability, scope map[string]string, start, end time.Time) observationmodel.Plan {
	parameters := json.RawMessage(`{}`)
	switch capability {
	case observationmodel.CapabilityStoreRead:
		parameters = json.RawMessage(`{"resource":"situation"}`)
	case observationmodel.CapabilityPrometheusQuery:
		parameters = json.RawMessage(`{"query":"up"}`)
	case observationmodel.CapabilityZabbixMetricRange:
		parameters = json.RawMessage(`{"item_key":"system.cpu.util","sample_interval_seconds":60}`)
	case observationmodel.CapabilityLokiQuery:
		parameters = json.RawMessage(`{"query":"{host=\"db-1\"}"}`)
	}
	return observationmodel.Plan{Capability: capability, Scope: scope, Parameters: parameters, Start: start, End: end, Limit: 10, Why: "bounded evidence"}
}

func mustObservationTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
