// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
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

// TestZabbixExecutorsOversizedResponseIsTruncatedWithoutData proves both
// Zabbix executors map the transport's ErrResponseTooLarge (F10) to a
// truncated, incomplete, response_too_large run with no facts.
func TestZabbixExecutorsOversizedResponseIsTruncatedWithoutData(t *testing.T) {
	assertTooLarge := func(t *testing.T, run model.Run, rec *capturingRecorder) {
		t.Helper()
		if got := rec.codes(); len(got) != 1 || got[0] != "response_too_large" {
			t.Fatalf("outcome codes = %v, want [response_too_large]", got)
		}
		if run.Status != model.ResultTruncated || run.Coverage.Complete || len(run.Facts) != 0 {
			t.Fatalf("run = %+v, want truncated/incomplete with no facts", run)
		}
		if len(run.LimitationCodes) != 1 || run.LimitationCodes[0] != "response_too_large" {
			t.Fatalf("limitation codes = %v", run.LimitationCodes)
		}
	}

	t.Run("metric", func(t *testing.T) {
		e := &ZabbixMetricExecutor{Client: &fakeZabbixMetricClient{err: zabbix.ErrResponseTooLarge}}
		rec := &capturingRecorder{}
		run, err := e.Execute(context.Background(), planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "k"}), rec)
		if err != nil {
			t.Fatal(err)
		}
		assertTooLarge(t, run, rec)
	})
	t.Run("problem", func(t *testing.T) {
		e := &ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{err: zabbix.ErrResponseTooLarge}}
		plan := testStorePlan()
		plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "1"})
		rec := &capturingRecorder{}
		run, err := e.Execute(context.Background(), plan, rec)
		if err != nil {
			t.Fatal(err)
		}
		assertTooLarge(t, run, rec)
	})
}

// TestZabbixExecutorsCapFactBytes proves neither Zabbix fact ever exceeds
// model.MaxFactBytes.
func TestZabbixExecutorsCapFactBytes(t *testing.T) {
	t.Run("metric points", func(t *testing.T) {
		points := make([]zabbix.SeriesPoint, 400)
		for i := range points {
			points[i] = zabbix.SeriesPoint{Clock: time.Unix(int64(i), 0).UTC(), Value: strings.Repeat("9", 60)}
		}
		e := &ZabbixMetricExecutor{Client: &fakeZabbixMetricClient{series: zabbix.Series{ItemID: "1", Points: points}}}
		plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "k"})
		plan.Limit = 500
		run, err := e.Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
			t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
		}
		if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") || run.Coverage.Complete || run.Coverage.Omitted < 1 {
			t.Fatalf("run codes=%v complete=%v omitted=%d, want fact_bytes_capped/incomplete", run.LimitationCodes, run.Coverage.Complete, run.Coverage.Omitted)
		}
	})
	t.Run("problem episodes", func(t *testing.T) {
		episodes := make([]zabbix.ProblemEpisode, 60)
		for i := range episodes {
			episodes[i] = zabbix.ProblemEpisode{EventID: strconv.Itoa(i), Tags: []zabbix.KV{{Tag: "t", Value: strings.Repeat("v", 500)}}}
		}
		e := &ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{Episodes: episodes, Complete: true}}}
		plan := testStorePlan()
		plan.Limit = 100
		plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "1"})
		run, err := e.Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
			t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
		}
		if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") || run.Coverage.Complete || run.Coverage.Omitted < 1 {
			t.Fatalf("run codes=%v complete=%v omitted=%d, want fact_bytes_capped/incomplete", run.LimitationCodes, run.Coverage.Complete, run.Coverage.Omitted)
		}
	})
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
