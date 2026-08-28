// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
)

// repairLLM is the recording fake for the ONE bounded repair invocation: it
// counts calls (the repair-once guarantee is a call-count contract, not a
// prose promise) and keeps the last prompt so the per-call output ceiling can
// be asserted on the wire.
type repairLLM struct {
	raw    json.RawMessage
	err    error
	calls  int
	prompt llm.Prompt
}

func (f *repairLLM) Complete(_ context.Context, _ string, p llm.Prompt, _ []string) (llm.Completion, error) {
	f.calls++
	f.prompt = p
	return llm.Completion{Raw: f.raw}, f.err
}

func TestRepairModelPromQL_OneBatchCallPreservesValidQueries(t *testing.T) {
	fake := &repairLLM{raw: json.RawMessage(`{"queries":[{"index":0,"expr":"sum by (type) (increase(metric_name[1h]))"}]}`)}
	s := &Skill{llm: fake, logger: slog.Default()}
	in := []VerificationQuery{
		{Kind: kindPromQL, Source: "model", Expr: `increase(metric_name[1h]) by (type)`, Why: "rate by type"},
		{Kind: kindPromQL, Source: "model", Expr: `sum(up)`, Why: "peer health"},
	}
	out, stats := s.repairModelPromQL(context.Background(), "inc-62", in)
	if fake.calls != 1 || fake.prompt.MaxOutputTokens != 512 {
		t.Fatalf("calls=%d prompt=%+v", fake.calls, fake.prompt)
	}
	if stats != (verificationRepairStats{Attempted: 1, Repaired: 1}) {
		t.Fatalf("stats=%+v", stats)
	}
	if out[0].Expr != `sum by (type) (increase(metric_name[1h]))` || out[0].Why != "rate by type" || !reflect.DeepEqual(out[1], in[1]) {
		t.Fatalf("queries changed outside invalid expr: %+v", out)
	}
	if out[0].Outcome != "" || out[0].Kind != kindPromQL || out[0].Source != "model" {
		t.Fatalf("repaired query lost its identity or was marked: %+v", out[0])
	}

	// The prompt is a fixed instruction plus the invalid queries as JSON: only
	// the invalid entry rides along, carrying its own index and parser error.
	const wantPrefix = "Repair only the listed invalid PromQL expressions. Keep every index unchanged. " +
		`Respond as {"queries":[{"index":0,"expr":"..."}]}.` + "\n\nInvalid queries:\n"
	if !strings.HasPrefix(fake.prompt.Prefix, wantPrefix) {
		t.Fatalf("repair prompt prefix = %q", fake.prompt.Prefix)
	}
	if strings.Contains(fake.prompt.Prefix, `sum(up)`) {
		t.Fatalf("valid query was sent for repair: %q", fake.prompt.Prefix)
	}
	if !strings.Contains(fake.prompt.Prefix, `"index":0`) || !strings.Contains(fake.prompt.Prefix, `"why":"rate by type"`) {
		t.Fatalf("repair prompt lost the issue index or intent: %q", fake.prompt.Prefix)
	}
}

func TestRepairModelPromQL_AllValidSkipsCall(t *testing.T) {
	fake := &repairLLM{}
	s := &Skill{llm: fake, logger: slog.Default()}
	out, stats := s.repairModelPromQL(context.Background(), "inc", []VerificationQuery{{
		Kind: kindPromQL, Source: "model", Expr: "sum(up)",
	}})
	if fake.calls != 0 || stats != (verificationRepairStats{}) || out[0].Outcome != "" {
		t.Fatalf("calls=%d stats=%+v out=%+v", fake.calls, stats, out)
	}
}

func TestRepairModelPromQL_PartialResponseMarksResidualInvalid(t *testing.T) {
	// After the one valid index-0 entry the model also emits a duplicate for
	// index 0, an out-of-range index, and a blank expression for index 1:
	// first-valid-entry-wins, and none of the three may move a query.
	fake := &repairLLM{raw: json.RawMessage(`{"queries":[
		{"index":0,"expr":"sum by (type) (increase(a[1h]))"},
		{"index":0,"expr":"sum by (type) (increase(zzz[1h]))"},
		{"index":7,"expr":"sum(up)"},
		{"index":1,"expr":"   "}
	]}`)}
	s := &Skill{llm: fake, logger: slog.Default()}
	in := []VerificationQuery{
		{Kind: kindPromQL, Source: "model", Expr: `increase(a[1h]) by (type)`},
		{Kind: kindPromQL, Source: "model", Expr: `increase(b[1h]) by (type)`},
	}
	out, stats := s.repairModelPromQL(context.Background(), "inc", in)
	if fake.calls != 1 || stats != (verificationRepairStats{Attempted: 2, Repaired: 1, Invalid: 1}) {
		t.Fatalf("calls=%d stats=%+v", fake.calls, stats)
	}
	if out[0].Outcome != "" || out[1].Outcome != OutcomeInvalid {
		t.Fatalf("partial outcomes = %+v", out)
	}
	if out[0].Expr != `sum by (type) (increase(a[1h]))` {
		t.Fatalf("index 0 took a later duplicate instead of the first entry: %q", out[0].Expr)
	}
	if out[1].Expr != `increase(b[1h]) by (type)` {
		t.Fatalf("blank replacement was applied to index 1: %q", out[1].Expr)
	}
	if out[1].Result != "invalid query (not executed)" {
		t.Fatalf("residual invalid result = %q", out[1].Result)
	}
	if len(out) != len(in) {
		t.Fatalf("query count changed: %d, want %d", len(out), len(in))
	}
}

func TestRepairModelPromQL_CallFailureIsTerminal(t *testing.T) {
	fake := &repairLLM{err: llm.ErrResponseTruncated}
	s := &Skill{llm: fake, logger: slog.Default()}
	out, stats := s.repairModelPromQL(context.Background(), "inc", []VerificationQuery{{
		Kind: kindPromQL, Source: "model", Expr: `increase(a[1h]) by (type)`,
	}})
	if fake.calls != 1 || stats.Invalid != 1 || out[0].Outcome != OutcomeInvalid {
		t.Fatalf("calls=%d stats=%+v out=%+v", fake.calls, stats, out)
	}
	if out[0].Expr != `increase(a[1h]) by (type)` {
		t.Fatalf("failed call must leave the expression alone: %q", out[0].Expr)
	}
}

// TestRepairModelPromQL_MalformedResponseIsTerminal: a reply that is not the
// documented envelope is exactly as terminal as a failed call — no second
// invocation, every attempted query left invalid.
func TestRepairModelPromQL_MalformedResponseIsTerminal(t *testing.T) {
	fake := &repairLLM{raw: json.RawMessage(`{"queries": "not-a-list"`)}
	s := &Skill{llm: fake, logger: slog.Default()}
	out, stats := s.repairModelPromQL(context.Background(), "inc", []VerificationQuery{{
		Kind: kindPromQL, Source: "model", Expr: `increase(a[1h]) by (type)`, Why: "would refute",
	}})
	if fake.calls != 1 {
		t.Fatalf("malformed reply must not trigger a second call, calls=%d", fake.calls)
	}
	if stats != (verificationRepairStats{Attempted: 1, Invalid: 1}) {
		t.Fatalf("stats=%+v", stats)
	}
	if out[0].Outcome != OutcomeInvalid || out[0].Expr != `increase(a[1h]) by (type)` || out[0].Why != "would refute" {
		t.Fatalf("out=%+v", out)
	}
}

// TestRepairModelPromQL_SemanticChangeIsResidualInvalid: a reply that parses
// but quietly swaps the metric is NOT a syntax repair. It must never be
// treated as repaired (and so must never execute against the backend), even
// though promclient.ValidateExpr alone would accept it.
func TestRepairModelPromQL_SemanticChangeIsResidualInvalid(t *testing.T) {
	fake := &repairLLM{raw: json.RawMessage(`{"queries":[{"index":0,"expr":"sum by (type) (increase(other_metric[1h]))"}]}`)}
	s := &Skill{llm: fake, logger: slog.Default()}
	in := []VerificationQuery{
		{Kind: kindPromQL, Source: "model", Expr: `increase(metric_name[1h]) by (type)`, Why: "rate by type"},
		{Kind: kindIncidentsInWindow, Source: "model", Why: "is anything else firing?"},
	}
	out, stats := s.repairModelPromQL(context.Background(), "inc", in)
	if fake.calls != 1 {
		t.Fatalf("calls=%d, want exactly one batch call", fake.calls)
	}
	if stats != (verificationRepairStats{Attempted: 1, Repaired: 0, Invalid: 1}) {
		t.Fatalf("stats=%+v", stats)
	}
	if out[0].Outcome != OutcomeInvalid {
		t.Fatalf("semantically changed repair was accepted: %+v", out[0])
	}
	if out[0].Why != "rate by type" {
		t.Fatalf("Why must survive a failed repair: %q", out[0].Why)
	}
	// A non-promql model query is never a repair candidate.
	if !reflect.DeepEqual(out[1], in[1]) {
		t.Fatalf("non-promql query touched: %+v", out[1])
	}
	if strings.Contains(fake.prompt.Prefix, "is anything else firing?") {
		t.Fatalf("non-promql query was sent for repair: %q", fake.prompt.Prefix)
	}
}
