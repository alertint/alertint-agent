// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

type fakeZabbixMetricClient struct {
	series zabbix.Series
	err    error
}

func (f *fakeZabbixMetricClient) MetricHistoryBounded(ctx context.Context, host, itemKey string, from, to time.Time, limit int,
	before func() error, after func(started bool, err error)) (zabbix.Series, error) {
	if err := before(); err != nil {
		return zabbix.Series{}, err
	}
	after(true, f.err)
	if f.err != nil {
		return zabbix.Series{}, f.err
	}
	return f.series, nil
}

func planWithParams(params any) model.Plan {
	p := testStorePlan()
	p.Capability = "zabbix_metric_range"
	p.Parameters = mustMarshal(params)
	return p
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestZabbixMetricExecutorConfirmedValue(t *testing.T) {
	client := &fakeZabbixMetricClient{series: zabbix.Series{ItemID: "1", Points: []zabbix.SeriesPoint{{Value: "1"}}}}
	e := &ZabbixMetricExecutor{Client: client}
	plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_value" {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}
}

func TestZabbixMetricExecutorUnresolvedWithoutItemKey(t *testing.T) {
	e := &ZabbixMetricExecutor{Client: &fakeZabbixMetricClient{}}
	plan := planWithParams(zabbixMetricParameters{Host: "web01"})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestZabbixMetricExecutorNotFoundIsUnresolved(t *testing.T) {
	client := &fakeZabbixMetricClient{err: zabbix.ErrNotFound}
	e := &ZabbixMetricExecutor{Client: client}
	plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "missing.key"})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestZabbixMetricExecutorHostFallsBackToSubjectID(t *testing.T) {
	client := &fakeZabbixMetricClient{series: zabbix.Series{}}
	e := &ZabbixMetricExecutor{Client: client}
	plan := planWithParams(zabbixMetricParameters{ItemKey: "system.cpu.util"}) // no host
	plan.Scope.SubjectID = "web01"

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_empty" {
		t.Fatalf("status = %q, want confirmed_empty (host fell back to SubjectID)", run.Status)
	}
}

type fakeZabbixProblemClient struct {
	result zabbix.ProblemHistoryResult
	err    error
}

func (f *fakeZabbixProblemClient) ProblemHistory(ctx context.Context, host, triggerID string, start, end time.Time, severityMin string, limit int,
	before func() error, after func(started bool, err error)) (zabbix.ProblemHistoryResult, error) {
	if err := before(); err != nil {
		return zabbix.ProblemHistoryResult{}, err
	}
	after(true, f.err)
	if f.err != nil {
		return zabbix.ProblemHistoryResult{}, f.err
	}
	return f.result, nil
}

func TestZabbixProblemExecutorConfirmedValueWithRecoveryUnknownLimitation(t *testing.T) {
	client := &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{
		Episodes:                []zabbix.ProblemEpisode{{EventID: "1", RecoveryUnknown: true}},
		Complete:                true,
		UnresolvedRecoveryCount: 1,
	}}
	e := &ZabbixProblemExecutor{Client: client}
	plan := testStorePlan()
	plan.Capability = "zabbix_problem_history"
	b := mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422"})
	plan.Parameters = b

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_value" {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}
	found := false
	for _, c := range run.LimitationCodes {
		if c == "recovery_unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a recovery_unknown limitation code")
	}
}

func TestZabbixProblemExecutorUnresolvedWithoutTriggerID(t *testing.T) {
	e := &ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{}}
	plan := testStorePlan()
	plan.Capability = "zabbix_problem_history"
	b := mustMarshal(zabbixProblemParameters{Host: "web01"})
	plan.Parameters = b

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestZabbixHooksReportBudgetExhausted(t *testing.T) {
	rec := &budgetExhaustedRecorder{}
	before, after, exhausted := zabbixHooks(context.Background(), rec, time.Now)
	if err := before(); !errors.Is(err, model.ErrBudgetExhausted) {
		t.Fatalf("expected ErrBudgetExhausted, got %v", err)
	}
	if !*exhausted {
		t.Fatal("expected budgetExhausted flag set")
	}
	after(false, nil) // must not panic when nothing was reserved
}

type budgetExhaustedRecorder struct{}

func (budgetExhaustedRecorder) BeforeRequest(ctx context.Context) (model.RequestReservation, error) {
	return model.RequestReservation{}, model.ErrBudgetExhausted
}
func (budgetExhaustedRecorder) AfterRequest(ctx context.Context, outcome model.RequestOutcome) error {
	return nil
}
