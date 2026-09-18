// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
)

type fakeLokiClient struct {
	fetched       logs.Fetched
	err           error
	physicalCalls int
}

func (f *fakeLokiClient) FetchRecentBounded(ctx context.Context, sel logs.Selector, start, end time.Time, limit int,
	before func() error, after func(started bool, err error)) (logs.Fetched, error) {
	if len(sel.Labels) == 0 {
		return logs.Fetched{}, nil
	}
	if err := before(); err != nil {
		return logs.Fetched{}, err
	}
	f.physicalCalls++
	after(true, f.err)
	if f.err != nil {
		return logs.Fetched{}, f.err
	}
	return f.fetched, nil
}

func TestLokiExecutorConfirmedValueWithLines(t *testing.T) {
	client := &fakeLokiClient{fetched: logs.Fetched{
		Query: `{service="checkout"}`,
		Lines: []logs.Line{{Timestamp: time.Now(), Line: "error: boom"}},
	}}
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_value" {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}
	if client.physicalCalls != 1 {
		t.Fatalf("physical calls = %d, want 1", client.physicalCalls)
	}
}

func TestLokiExecutorConfirmedEmptyWithNoLines(t *testing.T) {
	client := &fakeLokiClient{fetched: logs.Fetched{Query: `{service="checkout"}`}}
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_empty" {
		t.Fatalf("status = %q, want confirmed_empty", run.Status)
	}
}

func TestLokiExecutorUnresolvedWhenSelectorUntranslated(t *testing.T) {
	client := &fakeLokiClient{fetched: logs.Fetched{}} // empty Query: no label survived translation
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestLokiExecutorUnresolvedWhenNoScopeLabels(t *testing.T) {
	e := &LokiExecutor{Client: &fakeLokiClient{}}
	plan := testStorePlan()
	plan.Scope.Labels = nil

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestLokiExecutorSamplesAreBounded(t *testing.T) {
	lines := make([]logs.Line, maxLokiSampleLines+10)
	for i := range lines {
		lines[i] = logs.Line{Timestamp: time.Now(), Line: "line"}
	}
	client := &fakeLokiClient{fetched: logs.Fetched{Query: `{service="checkout"}`, Lines: lines}}
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Coverage.Returned != len(lines) {
		t.Fatalf("coverage returned = %d, want %d (true line count)", run.Coverage.Returned, len(lines))
	}
	var summary lokiSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.LineCount != len(lines) {
		t.Fatalf("distilled line_count = %d, want %d", summary.LineCount, len(lines))
	}
	if len(summary.Samples) != maxLokiSampleLines {
		t.Fatalf("retained samples = %d, want the bounded cap %d", len(summary.Samples), maxLokiSampleLines)
	}
}
