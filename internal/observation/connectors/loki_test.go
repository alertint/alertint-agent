// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/logs/loki"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

type fakeLokiClient struct {
	fetched       logs.Fetched
	err           error
	physicalCalls int
	gotLimit      int
}

func (f *fakeLokiClient) FetchRecentBounded(ctx context.Context, sel logs.Selector, start, end time.Time, limit int,
	before func() error, after func(started bool, err error)) (logs.Fetched, error) {
	f.gotLimit = limit
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
	plan.Limit = len(lines) // every line fits the plan limit: the sample cap alone is under test

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Coverage.Returned != len(lines) {
		t.Fatalf("coverage returned = %d, want %d (true line count)", run.Coverage.Returned, len(lines))
	}
	if !run.Coverage.Complete || run.Status != model.ResultConfirmedValue {
		t.Fatalf("status=%q complete=%v: capping SAMPLES is distillation, not truncation", run.Status, run.Coverage.Complete)
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

// TestLokiExecutorHardCapIsNotCompletenessProof proves the F20 contract:
// the executor requests limit+1, and when more than limit lines come back
// it keeps the first limit under canonical order and reports truncated /
// incomplete with the omission counted — never Complete=true on a hard cap.
func TestLokiExecutorHardCapIsNotCompletenessProof(t *testing.T) {
	const limit = 2
	lines := []logs.Line{
		{Timestamp: time.Unix(300, 0).UTC(), Line: "error 3"},
		{Timestamp: time.Unix(100, 0).UTC(), Line: "error 1"},
		{Timestamp: time.Unix(200, 0).UTC(), Line: "error 2"},
	}
	client := &fakeLokiClient{fetched: logs.Fetched{Query: `{service="checkout"}`, Lines: lines}}
	plan := testStorePlan()
	plan.Limit = limit
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := (&LokiExecutor{Client: client}).Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if client.gotLimit != limit+1 {
		t.Fatalf("requested limit = %d, want %d (overflow sentinel)", client.gotLimit, limit+1)
	}
	if run.Coverage.Complete || run.Status != model.ResultTruncated {
		t.Fatalf("hard cap reported as complete: complete=%v status=%q", run.Coverage.Complete, run.Status)
	}
	if run.Coverage.Returned != limit || run.Coverage.Omitted < 1 {
		t.Fatalf("coverage returned=%d omitted=%d, want %d / >=1", run.Coverage.Returned, run.Coverage.Omitted, limit)
	}
	if !slices.Contains(run.LimitationCodes, "truncated") {
		t.Fatalf("limitation codes = %v, want truncated", run.LimitationCodes)
	}
	var summary lokiSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.LineCount != limit || len(summary.Samples) != limit {
		t.Fatalf("summary line_count=%d samples=%d, want the bounded %d", summary.LineCount, len(summary.Samples), limit)
	}
	// Newest-first canonical order: the two newest lines survive.
	if summary.Samples[0].Line != "error 3" || summary.Samples[1].Line != "error 2" {
		t.Fatalf("kept samples = %+v, want the newest two in canonical order", summary.Samples)
	}
}

// TestLokiExecutorExactLimitIsComplete pins the other side of F20: exactly
// limit lines (no sentinel) is a complete, confirmed result.
func TestLokiExecutorExactLimitIsComplete(t *testing.T) {
	client := &fakeLokiClient{fetched: logs.Fetched{Query: `{service="checkout"}`, Lines: []logs.Line{
		{Timestamp: time.Unix(1, 0), Line: "a"}, {Timestamp: time.Unix(2, 0), Line: "b"},
	}}}
	plan := testStorePlan()
	plan.Limit = 2
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	run, err := (&LokiExecutor{Client: client}).Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if !run.Coverage.Complete || run.Status != model.ResultConfirmedValue || run.Coverage.Omitted != 0 {
		t.Fatalf("run = status %q complete=%v omitted=%d, want a complete confirmed_value", run.Status, run.Coverage.Complete, run.Coverage.Omitted)
	}
}

// TestLokiExecutorPermutationIsImmaterial proves F28 for log lines: the
// same line set in a different source order yields the same fact digest
// and id.
func TestLokiExecutorPermutationIsImmaterial(t *testing.T) {
	lines := []logs.Line{
		{Timestamp: time.Unix(100, 0).UTC(), Line: "same ts b"},
		{Timestamp: time.Unix(100, 0).UTC(), Line: "same ts a"},
		{Timestamp: time.Unix(200, 0).UTC(), Line: "newest"},
	}
	reversed := slices.Clone(lines)
	slices.Reverse(reversed)
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	runA, err := (&LokiExecutor{Client: &fakeLokiClient{fetched: logs.Fetched{Query: "q", Lines: lines}}}).Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	runB, err := (&LokiExecutor{Client: &fakeLokiClient{fetched: logs.Fetched{Query: "q", Lines: reversed}}}).Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if runA.Facts[0].Digest != runB.Facts[0].Digest || runA.Facts[0].ID != runB.Facts[0].ID {
		t.Fatalf("permutation changed evidence identity: %s vs %s", runA.Facts[0].Digest, runB.Facts[0].Digest)
	}
}

// TestLokiExecutorOversizedResponseIsTruncatedWithoutData proves the
// transport's ErrResponseTooLarge (F10) maps to a truncated, incomplete,
// response_too_large run with no facts and a response_too_large outcome.
func TestLokiExecutorOversizedResponseIsTruncatedWithoutData(t *testing.T) {
	client := &fakeLokiClient{err: loki.ErrResponseTooLarge}
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatalf("an over-limit response is a limitation, not an execution error: %v", err)
	}
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

// TestLokiExecutorCapsFactBytes proves the log_summary fact never exceeds
// model.MaxFactBytes even when every retained sample is at its own
// per-line cap and the query string is long.
func TestLokiExecutorCapsFactBytes(t *testing.T) {
	lines := make([]logs.Line, maxLokiSampleLines)
	for i := range lines {
		lines[i] = logs.Line{Timestamp: time.Unix(int64(1000-i), 0).UTC(), Line: strings.Repeat("e", 4*maxLokiSampleLineChars)}
	}
	longQuery := `{service="checkout",pad="` + strings.Repeat("q", 8*1024) + `"}`
	client := &fakeLokiClient{fetched: logs.Fetched{Query: longQuery, Lines: lines}}
	e := &LokiExecutor{Client: client}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	plan.Limit = 100

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
		t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
	}
	if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") || run.Coverage.Complete || run.Status != model.ResultTruncated {
		t.Fatalf("run = status %q complete=%v codes=%v, want truncated/fact_bytes_capped", run.Status, run.Coverage.Complete, run.LimitationCodes)
	}
	var summary lokiSummary
	if err := json.Unmarshal(run.Facts[0].Value, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Samples) >= maxLokiSampleLines || run.Coverage.Omitted != maxLokiSampleLines-len(summary.Samples) {
		t.Fatalf("samples=%d omitted=%d: the cap must drop samples and record the omission", len(summary.Samples), run.Coverage.Omitted)
	}
}
