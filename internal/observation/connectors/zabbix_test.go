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

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

type fakeZabbixMetricClient struct {
	series   zabbix.Series
	err      error
	gotLimit int
}

func (f *fakeZabbixMetricClient) MetricHistoryBounded(ctx context.Context, host, itemKey string, from, to time.Time, limit int,
	before func() error, after func(started bool, err error)) (zabbix.Series, error) {
	f.gotLimit = limit
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

// TestZabbixMetricExecutorEmptyHostIsUnresolvedNeverSubjectID pins F17:
// a plan without a proven host is unresolvable — Scope.SubjectID is never
// substituted, and no request is reserved.
func TestZabbixMetricExecutorEmptyHostIsUnresolvedNeverSubjectID(t *testing.T) {
	client := &fakeZabbixMetricClient{series: zabbix.Series{}}
	e := &ZabbixMetricExecutor{Client: client}
	plan := planWithParams(zabbixMetricParameters{ItemKey: "system.cpu.util"}) // no host
	plan.Scope.SubjectID = "web01"
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved (never a SubjectID fallback)", run.Status)
	}
	if rec.reservations != 0 || client.gotLimit != 0 {
		t.Fatal("an unresolvable plan must reserve and dispatch nothing")
	}
}

// TestZabbixProblemExecutorEmptyHostIsUnresolvedNeverSubjectID is the
// problem-history twin of the test above.
func TestZabbixProblemExecutorEmptyHostIsUnresolvedNeverSubjectID(t *testing.T) {
	e := &ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{}}
	plan := testStorePlan()
	plan.Scope.SubjectID = "web01"
	plan.Parameters = mustMarshal(zabbixProblemParameters{TriggerID: "18422"}) // no host
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" || rec.reservations != 0 {
		t.Fatalf("status = %q reservations = %d, want vocabulary_unresolved with nothing reserved", run.Status, rec.reservations)
	}
}

type fakeZabbixProblemClient struct {
	result zabbix.ProblemHistoryResult
	err    error
}

type fakeZabbixSourceDefinitionClient struct {
	definition zabbix.SourceRuleDefinition
	err        error
	calls      int
}

func (f *fakeZabbixSourceDefinitionClient) SourceRuleVersionBounded(_ context.Context, _, _, _ string,
	before func() error, after func(started bool, err error)) (zabbix.SourceRuleDefinition, error) {
	f.calls++
	if f.err != nil {
		return zabbix.SourceRuleDefinition{}, f.err
	}
	if err := before(); err != nil {
		return zabbix.SourceRuleDefinition{}, err
	}
	after(true, nil)
	return f.definition, nil
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

func TestZabbixProblemExecutorRecordsCurrentSourceDefinition(t *testing.T) {
	problem := &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{Complete: true}}
	definition := &fakeZabbixSourceDefinitionClient{definition: zabbix.SourceRuleDefinition{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Host: "web01", EndpointID: "sha256:endpoint",
		RuleVersionEvidence: zabbix.RuleVersionEvidence{Algorithm: zabbix.SourceVersionAlgorithm, Version: "sha256:version", ComponentDigests: map[string]string{"logic": "sha256:logic"}, TriggerIDs: []string{"18422"}, ItemIDs: []string{"22"}},
	}}
	e := &ZabbixProblemExecutor{Client: problem, SourceDefinition: definition}
	plan := testStorePlan()
	plan.Capability = "zabbix_problem_history"
	plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422", SourceInstanceID: "prod-zbx", FreshForSeconds: 300})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if definition.calls != 1 {
		t.Fatalf("definition calls = %d", definition.calls)
	}
	var sourceFact *model.Fact
	for i := range run.Facts {
		if run.Facts[i].Kind == "source_definition" {
			sourceFact = &run.Facts[i]
		}
	}
	if sourceFact == nil {
		t.Fatalf("facts = %+v, want source_definition", run.Facts)
	}
	var value map[string]any
	if err := json.Unmarshal(sourceFact.Value, &value); err != nil {
		t.Fatal(err)
	}
	if value["available"] != true || value["instance_id"] != "prod-zbx" || value["version"] != "sha256:version" {
		t.Fatalf("source definition = %v", value)
	}
	if got := sourceFact.ExpiresAt.Sub(sourceFact.ObservedAt); got != 5*time.Minute {
		t.Fatalf("freshness = %v, want 5m", got)
	}
}

func TestZabbixProblemExecutorRecordsUnavailableSourceDefinition(t *testing.T) {
	problem := &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{Complete: true}}
	definition := &fakeZabbixSourceDefinitionClient{err: errors.New("API denied")}
	e := &ZabbixProblemExecutor{Client: problem, SourceDefinition: definition}
	plan := testStorePlan()
	plan.Capability = "zabbix_problem_history"
	plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422", SourceInstanceID: "prod-zbx", FreshForSeconds: 300})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	for _, fact := range run.Facts {
		if fact.Kind == "source_definition" {
			if err := json.Unmarshal(fact.Value, &value); err != nil {
				t.Fatal(err)
			}
		}
	}
	if value["available"] != false || value["unavailable_reason"] != "api_unavailable" {
		t.Fatalf("source definition = %v", value)
	}
}

func TestZabbixProblemExecutorPreservesSourceDefinitionWhenHistoryFails(t *testing.T) {
	problem := &fakeZabbixProblemClient{err: errors.New("problem history API denied")}
	definition := &fakeZabbixSourceDefinitionClient{err: errors.New("definition API denied")}
	e := &ZabbixProblemExecutor{Client: problem, SourceDefinition: definition}
	plan := testStorePlan()
	plan.Capability = "zabbix_problem_history"
	plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422", SourceInstanceID: "prod-zbx", FreshForSeconds: 300})

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err == nil {
		t.Fatal("Execute returned nil error for a transport failure")
	}
	var durable *observation.FailedRunWithEvidenceError
	if !errors.As(err, &durable) {
		t.Fatalf("error = %T, want FailedRunWithEvidenceError", err)
	}
	if run.Status != model.ResultFailed {
		t.Fatalf("status = %q, want failed", run.Status)
	}
	if !slices.Contains(run.LimitationCodes, "execution_failed") {
		t.Fatalf("limitation codes = %v, want execution_failed", run.LimitationCodes)
	}
	var value map[string]any
	for _, fact := range run.Facts {
		if fact.Kind == "source_definition" {
			if err := json.Unmarshal(fact.Value, &value); err != nil {
				t.Fatal(err)
			}
		}
	}
	if value["available"] != false || value["unavailable_reason"] != "api_unavailable" {
		t.Fatalf("source definition = %v, want independently preserved unavailability", value)
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

// TestZabbixMetricExecutorHardCapIsNotCompletenessProof proves F20 for
// metric history: limit+1 is requested, and more than limit points →
// truncated, incomplete, omission counted, newest points kept.
func TestZabbixMetricExecutorHardCapIsNotCompletenessProof(t *testing.T) {
	const limit = 2
	client := &fakeZabbixMetricClient{series: zabbix.Series{ItemID: "1", Points: []zabbix.SeriesPoint{
		{Clock: time.Unix(100, 0).UTC(), Value: "1"},
		{Clock: time.Unix(300, 0).UTC(), Value: "3"},
		{Clock: time.Unix(200, 0).UTC(), Value: "2"},
	}}}
	plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"})
	plan.Limit = limit

	run, err := (&ZabbixMetricExecutor{Client: client}).Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if client.gotLimit != limit+1 {
		t.Fatalf("requested limit = %d, want %d (overflow sentinel)", client.gotLimit, limit+1)
	}
	if run.Coverage.Complete || run.Status != model.ResultTruncated || run.Coverage.Returned != limit || run.Coverage.Omitted < 1 {
		t.Fatalf("run = status %q complete=%v returned=%d omitted=%d, want truncated/incomplete", run.Status, run.Coverage.Complete, run.Coverage.Returned, run.Coverage.Omitted)
	}
	if !slices.Contains(run.LimitationCodes, "truncated") {
		t.Fatalf("limitation codes = %v, want truncated", run.LimitationCodes)
	}
	var series zabbix.Series
	if err := json.Unmarshal(run.Facts[0].Value, &series); err != nil {
		t.Fatal(err)
	}
	if len(series.Points) != limit || series.Points[0].Value != "3" || series.Points[1].Value != "2" {
		t.Fatalf("kept points = %+v, want the newest two in canonical order", series.Points)
	}
}

// TestZabbixExecutorsPermutationIsImmaterial proves F28 for both Zabbix
// facts: reversed source order yields the same fact digest and id.
func TestZabbixExecutorsPermutationIsImmaterial(t *testing.T) {
	t.Run("metric points", func(t *testing.T) {
		points := []zabbix.SeriesPoint{
			{Clock: time.Unix(1, 0).UTC(), Value: "b"}, {Clock: time.Unix(1, 0).UTC(), Value: "a"}, {Clock: time.Unix(2, 0).UTC(), Value: "c"},
		}
		reversed := slices.Clone(points)
		slices.Reverse(reversed)
		plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "k"})
		runA, err := (&ZabbixMetricExecutor{Client: &fakeZabbixMetricClient{series: zabbix.Series{ItemID: "1", Points: points}}}).Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		runB, err := (&ZabbixMetricExecutor{Client: &fakeZabbixMetricClient{series: zabbix.Series{ItemID: "1", Points: reversed}}}).Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		if runA.Facts[0].Digest != runB.Facts[0].Digest || runA.Facts[0].ID != runB.Facts[0].ID {
			t.Fatalf("permutation changed evidence identity: %s vs %s", runA.Facts[0].Digest, runB.Facts[0].Digest)
		}
	})
	t.Run("problem episodes", func(t *testing.T) {
		episodes := []zabbix.ProblemEpisode{{EventID: "9"}, {EventID: "100"}, {EventID: "42"}}
		reversed := slices.Clone(episodes)
		slices.Reverse(reversed)
		plan := testStorePlan()
		plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "1"})
		runA, err := (&ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{Episodes: episodes, Complete: true}}}).Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		runB, err := (&ZabbixProblemExecutor{Client: &fakeZabbixProblemClient{result: zabbix.ProblemHistoryResult{Episodes: reversed, Complete: true}}}).Execute(context.Background(), plan, &noopRecorder{})
		if err != nil {
			t.Fatal(err)
		}
		if runA.Facts[0].Digest != runB.Facts[0].Digest || runA.Facts[0].ID != runB.Facts[0].ID {
			t.Fatalf("permutation changed evidence identity: %s vs %s", runA.Facts[0].Digest, runB.Facts[0].Digest)
		}
		var got []zabbix.ProblemEpisode
		if err := json.Unmarshal(runA.Facts[0].Value, &got); err != nil {
			t.Fatal(err)
		}
		if got[0].EventID != "100" || got[1].EventID != "42" || got[2].EventID != "9" {
			t.Fatalf("episodes = %+v, want newest numeric event id first", got)
		}
	})
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
