// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"slices"
	"strings"
	"testing"

	promqlparser "github.com/prometheus/prometheus/promql/parser"
)

func TestValidateExpr(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr string
	}{
		{name: "instant vector", expr: `sum by (type) (increase(metric_name[1h]))`},
		{name: "issue 62 invalid aggregation suffix", expr: `increase(metric_name[1h]) by (type)`, wantErr: "unexpected <by>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExpr(tc.expr)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("ValidateExpr(%q): %v", tc.expr, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ValidateExpr(%q) error = %v, want %q", tc.expr, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSyntaxRepair(t *testing.T) {
	original := `increase(metric_name{type="error"}[1h]) by (type)`
	if err := ValidateSyntaxRepair(original, `sum by (type) (increase(metric_name{type="error"}[1h]))`); err != nil {
		t.Fatalf("syntax-only repair rejected: %v", err)
	}
	for _, changed := range []string{
		`sum by (type) (increase(other_metric{type="error"}[1h]))`,
		`sum by (type) (increase(metric_name{type="warning"}[1h]))`,
		`sum by (type) (rate(metric_name{type="error"}[5m]))`,
	} {
		if err := ValidateSyntaxRepair(original, changed); err == nil {
			t.Fatalf("semantic workaround accepted: %s", changed)
		}
	}

	// A label value swapped between two different selectors must be
	// rejected even though the multiset of matcher values across the whole
	// expression is unchanged: sorting matchers globally instead of within
	// each selector would let this slip through.
	swapOriginal := `metric_a{x="1",y="2"} - metric_b{x="2",y="1"}`
	swapped := `metric_a{x="2",y="1"} - metric_b{x="1",y="2"}`
	if err := ValidateSyntaxRepair(swapOriginal, swapped); err == nil {
		t.Fatalf("label values swapped across selectors accepted: %s", swapped)
	}
}

// A repair may add the aggregation an expression was missing and move a
// grouping clause into place — that is the whole point of the repair path.
// Everything else about what the query asks must survive: the operators it
// combines terms with, the labels it groups over, and (when it already
// aggregated) which aggregator it used.
func TestValidateSyntaxRepair_SemanticAnchors(t *testing.T) {
	accept := []struct {
		name               string
		original, repaired string
	}{{
		// The canonical issue-62 relocation: aggregation introduced from
		// zero, `by` clause moved to where the grammar accepts it.
		name:     "issue 62 relocation",
		original: `increase(metric_name{type="error"}[1h]) by (type)`,
		repaired: `sum by (type) (increase(metric_name{type="error"}[1h]))`,
	}, {
		// The same repair with the clause left trailing the wrapper instead
		// of sitting between the aggregator and its parenthesis. Both spell
		// the same query, so both are inside the whitelist.
		name:     "issue 62 relocation with trailing clause",
		original: `increase(metric_name{type="error"}[1h]) by (type)`,
		repaired: `sum(increase(metric_name{type="error"}[1h])) by (type)`,
	}, {
		// Operator tracking must not over-reject: a matcher operator and a
		// top-level comparison coexist, and only the aggregation moves. The
		// wrapper opens at the start of the term the clause followed.
		name:     "matcher and comparison survive relocation",
		original: `foo{env="prod"} > increase(bar[1h]) by (type)`,
		repaired: `foo{env="prod"} > sum by (type) (increase(bar[1h]))`,
	}, {
		// Grouping labels are compared as a set, not a sequence: reordering
		// them groups identically and must stay acceptable.
		name:     "grouping labels reordered",
		original: `increase(metric_name[1h]) by (type, instance)`,
		repaired: `sum by (instance, type) (increase(metric_name[1h]))`,
	}, {
		// Matchers within ONE selector select identically in any order, so
		// reordering them is meaning-preserving and stays acceptable.
		name:     "matchers reordered inside one selector",
		original: `foo{b="2",a="1"} by (x)`,
		repaired: `sum by (x) (foo{a="1",b="2"})`,
	}}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err != nil {
				t.Fatalf("syntax-only repair rejected: %v", err)
			}
		})
	}

	reject := []struct {
		name               string
		original, repaired string
		wantErr            string
	}{{
		name:     "binary operator changed",
		original: `foo + increase(bar[1h]) by (type)`,
		repaired: `foo - sum by (type) (increase(bar[1h]))`,
		wantErr:  "changed an operator",
	}, {
		name:     "comparison operator changed",
		original: `foo{env="prod"} > 5`,
		repaired: `foo{env="prod"} < 5`,
		wantErr:  "changed an operator",
	}, {
		name:     "existing aggregator changed",
		original: `sum(foo) + increase(bar[1h]) by (type)`,
		repaired: `max(foo) + sum by (type) (increase(bar[1h]))`,
		wantErr:  "changed an aggregation operator",
	}, {
		name:     "existing aggregator swapped topk to bottomk",
		original: `topk(5, metric_name{type="error"}) by (type)`,
		repaired: `bottomk by (type) (5, metric_name{type="error"})`,
		wantErr:  "changed an aggregation operator",
	}, {
		name:     "grouping label changed",
		original: `increase(metric_name[1h]) by (type)`,
		repaired: `sum by (instance) (increase(metric_name[1h]))`,
		wantErr:  "changed a grouping label list",
	}, {
		// Same labels, inverted meaning: by keeps them, without drops them.
		name:     "by swapped for without",
		original: `sum by (type) (foo)`,
		repaired: `sum without (type) (foo)`,
		wantErr:  "changed a grouping label list",
	}, {
		// Caught by the collapsed matcher token, not by operator tracking:
		// the synthetic token already encodes label+op+value as one string.
		name:     "matcher operator changed",
		original: `sum(foo{env="prod"})`,
		repaired: `sum(foo{env!="prod"})`,
		wantErr:  "changed a label matcher",
	}}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := ValidateSyntaxRepair(tc.original, tc.repaired)
			if err == nil {
				t.Fatalf("semantic change accepted as syntax repair: %s", tc.repaired)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The gate accepts a rewrite only when it is one the repair path exists for:
// one new `sum` wrapper over an expression that had none, a relocated
// by/without clause, and matchers reordered inside one selector. Everything
// else — a modifier moved onto a different operand, a keyword the signature
// design had no case for, a second aggregation, a parameterised wrapper, added
// precedence parentheses — differs as a token sequence and is rejected by
// construction.
func TestValidateSyntaxRepair_RewriteWhitelist(t *testing.T) {
	accept := []struct {
		name               string
		original, repaired string
	}{{
		name:     "aggregation wrapper added with clause inside",
		original: `increase(x[1h]) by (type)`,
		repaired: `sum by (type) (increase(x[1h]))`,
	}, {
		name:     "aggregation wrapper added with clause trailing",
		original: `increase(x[1h]) by (type)`,
		repaired: `sum(increase(x[1h])) by (type)`,
	}}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err != nil {
				t.Fatalf("recognised rewrite rejected: %v", err)
			}
		})
	}

	reject := []struct {
		name               string
		original, repaired string
	}{{
		// A selector moved onto the other operand: flat per-class lists saw
		// the same matcher and the same metric names either way.
		name:     "selector reattached to the other operand",
		original: `foo{env="prod"} - bar`,
		repaired: `foo - bar{env="prod"}`,
	}, {
		name:     "offset reattached to the other operand",
		original: `foo offset 5m - bar`,
		repaired: `foo - bar offset 5m`,
	}, {
		name:     "vector matching moved to the other binary operator",
		original: `a / on(instance) b * c`,
		repaired: `a / b * on(instance) c`,
	}, {
		// `bool` turns a filter into a 0/1 valued series. It had no case at
		// all in the signature design, so it simply vanished.
		name:     "bool modifier introduced",
		original: `foo > bar`,
		repaired: `foo > bool bar`,
	}, {
		// group_left and group_right pick opposite sides as the "many" side.
		name:     "group_left swapped for group_right",
		original: `a / on(x) group_left b`,
		repaired: `a / on(x) group_right b`,
	}, {
		// @ start() and @ end() evaluate at opposite ends of the range.
		name:     "at modifier start swapped for end",
		original: `foo @ start()`,
		repaired: `foo @ end()`,
	}, {
		name:     "two aggregation wrappers added",
		original: `increase(x[1h]) by (type)`,
		repaired: `max(sum by (type) (increase(x[1h])))`,
	}, {
		// topk takes a parameter, so the wrapper is not a bare `sum( … )`.
		name:     "parameterised aggregation wrapper added",
		original: `increase(x[1h]) by (type)`,
		repaired: `topk by (type) (5, increase(x[1h]))`,
	}, {
		// Parentheses that change precedence change the arithmetic.
		name:     "precedence parentheses added",
		original: `a + b * c by (x)`,
		repaired: `sum by (x) ((a + b) * c)`,
	}, {
		// The original already aggregates, so no new wrapper is on offer.
		name:     "wrapper added to an already aggregating expression",
		original: `sum(foo) + increase(bar[1h]) by (type)`,
		repaired: `sum(foo) + sum by (type) (increase(bar[1h]))`,
	}}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err == nil {
				t.Fatalf("unrecognised rewrite accepted as syntax repair: %s", tc.repaired)
			}
		})
	}
}

// A by/without clause's POSITION says which sub-expression it groups, and a new
// wrapper's SCOPE says which sub-expression is aggregated. Both are
// meaning-carrying, so both are anchored: the clause keeps the remainder index
// it was lifted from, and a new `sum` wrapper must open at the start of the
// term its orphaned clause follows and close exactly where that clause sat.
//
// Every reject row below was an accepted false positive before those two rules
// existed; every original is invalid PromQL and every repaired expression
// parses, so each pair is one the repair path can really be handed.
func TestValidateSyntaxRepair_ClauseOwnershipAndWrapperScope(t *testing.T) {
	accept := []struct {
		name               string
		original, repaired string
	}{{
		// term = increase(http_errors_total[1h]); the wrapper closes where the
		// clause sat, leaving `> 100` outside it.
		name:     "wrapper closes at the clause boundary before a comparison",
		original: `increase(http_errors_total[1h]) by (code) > 100`,
		repaired: `sum by (code) (increase(http_errors_total[1h])) > 100`,
	}, {
		name:     "wrapper closes at the clause boundary before a subtraction",
		original: `increase(a[1h]) by (x) - b`,
		repaired: `sum by (x) (increase(a[1h])) - b`,
	}, {
		// term = rate(b[5m]) only — the clause follows the right operand.
		name:     "wrapper wraps only the operand the clause follows",
		original: `rate(a[5m]) / rate(b[5m]) by (job)`,
		repaired: `rate(a[5m]) / sum by (job) (rate(b[5m]))`,
	}, {
		// term = (a + b): a balanced parenthesized group is one term.
		name:     "parenthesized group is one term",
		original: `(a + b) by (x)`,
		repaired: `sum by (x) ((a + b))`,
	}, {
		// term = bar: a vector-matching modifier list ends the term to its
		// left, it is not part of the operand that follows it.
		name:     "vector matching list is not part of the term",
		original: `foo / on(x) bar by (t)`,
		repaired: `foo / on(x) sum by (t) (bar)`,
	}, {
		// term = foo offset 5m: offset is a postfix modifier of the term.
		name:     "offset belongs to the term",
		original: `foo offset 5m by (t)`,
		repaired: `sum by (t) (foo offset 5m)`,
	}, {
		// term = a: unary minus is an operator, so it bounds the term.
		name:     "unary minus bounds the term",
		original: `-a by (x)`,
		repaired: `-sum by (x) (a)`,
	}, {
		// An aggregator keyword used as a LABEL NAME inside on(...) must not
		// count as an aggregation, or this legitimate repair would look like
		// a second aggregator being introduced.
		name:     "aggregator keyword as an on-clause label name",
		original: `foo / on(sum) bar by (x)`,
		repaired: `foo / on(sum) sum by (x) (bar)`,
	}, {
		// The most common issue-62 shape in the wild: the orphaned clause
		// trails a function argument, and the wrapper opens at that argument.
		name:     "wrapper inside a function argument",
		original: `histogram_quantile(0.9, rate(x[5m]) by (le))`,
		repaired: `histogram_quantile(0.9, sum by (le) (rate(x[5m])))`,
	}}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err != nil {
				t.Fatalf("recognised rewrite rejected: %v", err)
			}
		})
	}

	reject := []struct {
		name               string
		original, repaired string
	}{{
		// High-1: the clause is re-owned by a DIFFERENT aggregator. Errors
		// grouped by code over total capacity becomes ungrouped errors over
		// capacity grouped by code.
		name:     "clause re-owned by a different aggregator",
		original: `increase(http_errors_total[1h]) by (code) / sum(capacity)`,
		repaired: `increase(http_errors_total[1h]) / sum by (code) (capacity)`,
	}, {
		name:     "without clause re-owned by a different aggregator",
		original: `increase(a[1h]) without (pod) / sum(b)`,
		repaired: `increase(a[1h]) / sum without (pod) (b)`,
	}, {
		name:     "clause re-owned by a different aggregator, short form",
		original: `increase(a[1h]) by (x) / sum(b)`,
		repaired: `increase(a[1h]) / sum by (x) (b)`,
	}, {
		name:     "two clauses swapped between operands",
		original: `by (a) sum(foo) + by (b) sum(bar)`,
		repaired: `sum by (b) (foo) + sum by (a) (bar)`,
	}, {
		name:     "two clauses swapped between valid operands",
		original: `sum by (a) (foo) + sum by (b) (bar)`,
		repaired: `sum by (b) (foo) + sum by (a) (bar)`,
	}, {
		// High-2: the same original also "accepted" this contradictory
		// wrapper, which filters per-series first and sums afterwards.
		name:     "wrapper swallows the comparison",
		original: `increase(http_errors_total[1h]) by (code) > 100`,
		repaired: `sum by (code) (increase(http_errors_total[1h]) > 100)`,
	}, {
		name:     "wrapper swallows the subtraction",
		original: `increase(a[1h]) by (x) - b`,
		repaired: `sum by (x) (increase(a[1h]) - b)`,
	}, {
		name:     "wrapper swallows the whole ratio",
		original: `rate(a[5m]) / rate(b[5m]) by (job)`,
		repaired: `sum by (job) (rate(a[5m]) / rate(b[5m]))`,
	}, {
		name:     "wrapper wraps the wrong operand of the ratio",
		original: `rate(a[5m]) / rate(b[5m]) by (job)`,
		repaired: `sum by (job) (rate(a[5m])) / rate(b[5m])`,
	}, {
		// Important-1: a new wrapper may only be `sum`. count returns the
		// number of series, group returns 1, avg/min/max/stddev/stdvar all
		// answer a different question than the orphaned `by` asked.
		name:     "new wrapper uses count",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `count by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses group",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `group by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses avg",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `avg by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses min",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `min by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses max",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `max by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses stddev",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `stddev by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		name:     "new wrapper uses stdvar",
		original: `increase(http_errors_total{job="api"}[1h]) by (code)`,
		repaired: `stdvar by (code) (increase(http_errors_total{job="api"}[1h]))`,
	}, {
		// Important-2: a truncated `by` with no label list must not be
		// extracted-and-dropped, or it unifies with an empty grouping clause
		// and silently becomes "aggregate away every label".
		name:     "truncated by keyword completed as an empty grouping",
		original: `rate(http_requests_total{job="api"}[5m]) by`,
		repaired: `sum by () (rate(http_requests_total{job="api"}[5m]))`,
	}, {
		name:     "truncated without keyword completed as an empty grouping",
		original: `rate(http_requests_total{job="api"}[5m]) without`,
		repaired: `sum without () (rate(http_requests_total{job="api"}[5m]))`,
	}, {
		// A label NAMED by inside a vector-matching list must stay in the
		// sequence rather than being lifted out as a clause.
		name:     "by used as an on-clause label name",
		original: `foo / on(by) bar`,
		repaired: `sum by () (foo / on() bar)`,
	}, {
		name:     "by used as a group_left label name",
		original: `a / on(x) group_left(by) b`,
		repaired: `sum by () (a / on(x) group_left() b)`,
	}, {
		// The wrapper must bind tightly to the term the clause follows, so
		// wrapping the whole expression is not on offer here either.
		name:     "wrapper swallows a vector-matching binary expression",
		original: `foo / on(sum) bar by (x)`,
		repaired: `sum by (x) (foo / on(sum) bar)`,
	}, {
		// A clause written INSIDE the aggregation's parentheses is not the
		// aggregator's modifier slot, so moving it out is not a recognised
		// respelling. Known false reject, documented on ValidateSyntaxRepair.
		name:     "clause moved out of the aggregation's parentheses",
		original: `sum(increase(x[1h]) by (type))`,
		repaired: `sum by (type) (increase(x[1h]))`,
	}, {
		name:     "clause moved out of the aggregation's parentheses, rate form",
		original: `sum(rate(a[5m]) by (job))`,
		repaired: `sum by (job) (rate(a[5m]))`,
	}}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err == nil {
				t.Fatalf("unrecognised rewrite accepted as syntax repair: %s", tc.repaired)
			}
		})
	}
}

// An aggregation keyword the original left DANGLING — `avg by (x)`, the
// truncated head of an aggregation — is still an aggregation, not a metric
// named `avg`. Counting it as zero would let the gate wrap it as the operand of
// a brand-new `sum`, which both changes the aggregation operator and invents an
// operand: `avg by (x)` -> `sum by (x) (avg)` asks for the sum of a series
// literally named "avg".
func TestValidateSyntaxRepair_DanglingAggregator(t *testing.T) {
	for _, agg := range []string{"sum", "avg", "count", "min", "max", "topk", "stddev", "stdvar", "group", "quantile", "bottomk", "count_values"} {
		t.Run("reject/by/"+agg, func(t *testing.T) {
			original := agg + ` by (x)`
			repaired := `sum by (x) (` + agg + `)`
			if err := ValidateSyntaxRepair(original, repaired); err == nil {
				t.Fatalf("dangling aggregator wrapped as a metric: %s -> %s", original, repaired)
			}
		})
	}
	for _, tc := range []struct {
		name               string
		original, repaired string
	}{{
		name:     "without form",
		original: `avg without (x)`,
		repaired: `sum without (x) (avg)`,
	}, {
		name:     "mid expression",
		original: `foo + sum by (x)`,
		repaired: `foo + sum by (x) (sum)`,
	}, {
		name:     "trailing aggregator with no clause at all",
		original: `foo + avg`,
		repaired: `foo + sum(avg)`,
	}} {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err == nil {
				t.Fatalf("dangling aggregator wrapped as a metric: %s", tc.repaired)
			}
		})
	}
}

// `agg by (t) (X)` and `agg(X) by (t)` are the same PromQL — the two spellings
// of one aggregation's modifier slot — so a repair may move a clause between
// them on an aggregation the original ALREADY had. What it may not do is move a
// clause to a slot belonging to a different aggregator, or to no aggregator at
// all: those are the High-1 re-ownership pairs, and they stay rejected.
func TestValidateSyntaxRepair_ClauseRespelling(t *testing.T) {
	accept := []struct {
		name               string
		original, repaired string
	}{{
		name:     "trailing clause respelled inline",
		original: `sum(foo) by (a)`,
		repaired: `sum by (a) (foo)`,
	}, {
		name:     "inline clause respelled trailing",
		original: `sum by (a) (foo)`,
		repaired: `sum(foo) by (a)`,
	}, {
		name:     "parameterised aggregator respelled inline",
		original: `topk(5, foo) by (t)`,
		repaired: `topk by (t) (5, foo)`,
	}, {
		name:     "parameterised aggregator respelled trailing",
		original: `topk by (t) (5, foo)`,
		repaired: `topk(5, foo) by (t)`,
	}, {
		name:     "both operands respelled",
		original: `sum by (a) (foo) + sum by (b) (bar)`,
		repaired: `sum(foo) by (a) + sum(bar) by (b)`,
	}}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err != nil {
				t.Fatalf("clause respelling on the same aggregator rejected: %v", err)
			}
		})
	}

	reject := []struct {
		name               string
		original, repaired string
	}{{
		// Respelling normalises the SLOT, not the owner: these two clauses
		// still belong to different aggregators.
		name:     "respelled but swapped between aggregators",
		original: `sum by (a) (foo) + sum by (b) (bar)`,
		repaired: `sum(bar) by (a) + sum(foo) by (b)`,
	}, {
		name:     "respelled onto a different aggregator",
		original: `increase(http_errors_total[1h]) by (code) / sum(capacity)`,
		repaired: `increase(http_errors_total[1h]) / sum(capacity) by (code)`,
	}}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err == nil {
				t.Fatalf("clause re-owned via respelling: %s", tc.repaired)
			}
		})
	}
}

// A wrapper must wrap something. When the orphaned clause sits at a term
// boundary the term is empty, and `sum by (t) ()` is not a repair of anything —
// it does not even parse. ValidateExpr runs before the gate in production, but
// the gate is written to be sound on its own rather than to lean on the
// caller's ordering.
func TestValidateSyntaxRepair_ZeroWidthWrapper(t *testing.T) {
	for _, tc := range []struct {
		name               string
		original, repaired string
	}{
		{name: "before a term", original: `by (t) foo`, repaired: `sum by (t) () foo`},
		{name: "mid expression", original: `a + by (t) b`, repaired: `a + sum by (t) () b`},
		{name: "clause alone", original: `by (t)`, repaired: `sum by (t) ()`},
	} {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err == nil {
				t.Fatalf("zero-width wrapper accepted: %s", tc.repaired)
			}
		})
	}
}

// PromQL's grammar (the pinned parser's `maybe_label` rule) accepts most
// KEYWORD tokens — quantile, count, sum, on, start, end, step, range, bool,
// and, or, ... — as label names, in matchers, in grouping clauses, and in
// vector-matching clauses alike. A canonical form that only recognizes
// IDENTIFIER in those slots is blind to exactly the label names that collide
// with keywords, and `quantile` is a label name Prometheus itself puts on every
// summary metric.
func TestValidateSyntaxRepair_KeywordNamedLabels(t *testing.T) {
	accept := []struct {
		name               string
		original, repaired string
	}{{
		// The canonical relocation on a metric carrying a keyword-named
		// matcher label. Before the matcher-triple case was widened, the
		// QUANTILE token inside {quantile="0.99"} was recorded as an
		// AGGREGATOR, so the original falsely appeared to already aggregate
		// and the repair's legitimately-new sum read as an aggregator change.
		name:     "keyword-named matcher label survives relocation",
		original: `increase(http_request_duration_seconds{quantile="0.99"}[1h]) by (type)`,
		repaired: `sum by (type) (increase(http_request_duration_seconds{quantile="0.99"}[1h]))`,
	}, {
		name:     "keyword-named grouping label survives relocation",
		original: `increase(metric_name[1h]) by (quantile)`,
		repaired: `sum by (quantile) (increase(metric_name[1h]))`,
	}}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateSyntaxRepair(tc.original, tc.repaired); err != nil {
				t.Fatalf("syntax-only repair rejected: %v", err)
			}
		})
	}

	reject := []struct {
		name               string
		original, repaired string
		wantErr            string
	}{{
		name:     "keyword-named grouping label changed",
		original: `sum by (quantile) (foo)`,
		repaired: `sum by (count) (foo)`,
		wantErr:  "changed a grouping label list",
	}, {
		// on/ignoring label lists are not extracted into the clause list —
		// they stay in the token sequence, so a changed label is reported by
		// the class of the token that diverged. START and END are bare
		// keywords, hence the structural class.
		name:     "keyword-named on-clause label changed",
		original: `foo / on (start) bar`,
		repaired: `foo / on (end) bar`,
		wantErr:  "changed the expression structure",
	}, {
		name:     "identifier-named on-clause label changed",
		original: `foo / on (instance) bar`,
		repaired: `foo / on (pod) bar`,
		wantErr:  "changed a metric reference",
	}, {
		name:     "ignoring clause label changed",
		original: `foo / ignoring (instance) bar`,
		repaired: `foo / ignoring (pod) bar`,
		wantErr:  "changed a metric reference",
	}, {
		name:     "on swapped for ignoring",
		original: `foo / on (instance) bar`,
		repaired: `foo / ignoring (instance) bar`,
		wantErr:  "changed the expression structure",
	}, {
		name:     "keyword-named matcher label value changed",
		original: `http_request_duration_seconds{quantile="0.99"}`,
		repaired: `http_request_duration_seconds{quantile="0.5"}`,
		wantErr:  "changed a label matcher",
	}}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := ValidateSyntaxRepair(tc.original, tc.repaired)
			if err == nil {
				t.Fatalf("semantic change accepted as syntax repair: %s", tc.repaired)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The label-matcher operators (=, !=, =~, !~) are consumed as part of a matcher
// triple and collapse into one synthetic token, so they must never survive as
// standalone tokens — three of the four (NEQ, EQL_REGEX, NEQ_REGEX) are inside
// the parser's IsOperator range, and a leaked one would split a matcher across
// two tokens whose order the W3 sort would then scramble.
func TestCanonicalizePromql_MatcherTriplesCollapse(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []string
		// degenerate marks the rows whose value slot is not a quoted string,
		// where the matcher operator is SUPPOSED to stay a standalone token.
		degenerate bool
	}{
		{expr: `foo{env="prod"} > 5`, want: []string{"foo", "{", `env="prod"`, "}", ">", "5"}},
		{
			expr: `foo{env!="prod",k=~"a.*",j!~"b.*"} > 5`,
			// Matchers are sorted within the selector; the separating commas
			// and the braces stay exactly where they were.
			want: []string{"foo", "{", `env!="prod"`, ",", `j!~"b.*"`, ",", `k=~"a.*"`, "}", ">", "5"},
		},
		{expr: `foo{env="prod"}`, want: []string{"foo", "{", `env="prod"`, "}"}},
		{expr: `foo + bar @ 1234`, want: []string{"foo", "+", "bar", "@", "1234"}},
		{expr: `foo and bar unless baz`, want: []string{"foo", "and", "bar", "unless", "baz"}},
		// A quoted label name puts a STRING in the name slot; the triple is
		// still consumed whole, so its !~ does not leak out.
		{expr: `foo{"and"!~"x"} > 5`, want: []string{"foo", "{", `"and"!~"x"`, "}", ">", "5"}},
		// Nothing else is dropped: offset, bool, @ start(), group_left and
		// their parens all stay in the sequence, positionally anchored.
		{expr: `foo offset 5m - bar`, want: []string{"foo", "offset", "5m", "-", "bar"}},
		{expr: `foo > bool bar`, want: []string{"foo", ">", "bool", "bar"}},
		{expr: `foo @ start()`, want: []string{"foo", "@", "start", "(", ")"}},
		{expr: `a / on(x) group_left b`, want: []string{"a", "/", "on", "(", "x", ")", "group_left", "b"}},
		// A valid matcher's value is always a quoted string, so a degenerate
		// value slot must NOT be swallowed into the triple — the } and the ,
		// below would otherwise vanish into a synthetic token and the brace
		// depth would never return to zero.
		{expr: `foo{a=}`, want: []string{"foo", "{", "a", "=", "}"}, degenerate: true},
		{expr: `foo{a=,b="1"}`, want: []string{"foo", "{", "a", "=", ",", `b="1"`, "}"}, degenerate: true},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if vals := canonTokenValues(got.tokens); !slices.Equal(vals, tc.want) {
			t.Fatalf("canonicalizePromql(%q) tokens = %v, want %v", tc.expr, vals, tc.want)
		}
		if tc.degenerate {
			continue
		}
		for _, tok := range got.tokens {
			if !tok.matcher && isMatcherOp(tok.typ) {
				t.Fatalf("canonicalizePromql(%q): matcher operator %q survived as its own token", tc.expr, tok.val)
			}
		}
	}
}

// The clause entries the grouping check compares, spelled out: keyword kept,
// labels sorted, one entry per by/without clause IN ENCOUNTER ORDER, each
// carrying the remainder index it was lifted from (its position is what says
// which sub-expression it groups, so it is compared, not discarded).
//
// on/ignoring are deliberately NOT extracted. Their position decides which
// binary operator they modify, so pulling them out of the sequence is exactly
// the hole that let `a / on(instance) b * c` be rewritten as
// `a / b * on(instance) c`. Nor is a bare by/without with no parenthesized
// label list extracted: dropping that token from the sequence let a truncated
// `… by` be "repaired" into `sum by () (…)`.
func TestCanonicalizePromql_GroupClauses(t *testing.T) {
	for _, tc := range []struct {
		expr            string
		wantClauses     []promqlClause
		wantInRemainder []string
	}{
		{expr: `sum by (b, a) (foo)`, wantClauses: []promqlClause{{index: 1, text: "by:a,b"}}},
		{expr: `sum without (type) (foo)`, wantClauses: []promqlClause{{index: 1, text: "without:type"}}},
		{
			expr:        `sum by (a) (foo) + sum by (b) (bar)`,
			wantClauses: []promqlClause{{index: 1, text: "by:a"}, {index: 6, text: "by:b"}},
		},
		{
			// Encounter order, not sorted: swapping two clauses between two
			// operands must be visible as a difference.
			expr:        `sum by (b) (bar) + sum by (a) (foo)`,
			wantClauses: []promqlClause{{index: 1, text: "by:b"}, {index: 6, text: "by:a"}},
		},
		{expr: `sum by () (foo)`, wantClauses: []promqlClause{{index: 1, text: "by:"}}},
		{expr: `sum(foo)`, wantClauses: nil},
		{expr: `sum by (quantile) (foo)`, wantClauses: []promqlClause{{index: 1, text: "by:quantile"}}},
		// Every token type the pinned grammar's grouping_label rule admits:
		// maybe_label's keywords and a quoted STRING.
		{
			expr:        `sum by (start, end, offset, on, bool, sum, count, quantile) (foo)`,
			wantClauses: []promqlClause{{index: 1, text: "by:bool,count,end,offset,on,quantile,start,sum"}},
		},
		{expr: `sum by ("quantile") (foo)`, wantClauses: []promqlClause{{index: 1, text: `by:"quantile"`}}},
		{expr: `foo / on (start) bar`, wantClauses: nil, wantInRemainder: []string{"on", "(", "start", ")"}},
		{expr: `foo / ignoring (b, a) bar`, wantClauses: nil, wantInRemainder: []string{"ignoring", "(", "b", ",", "a", ")"}},
		{
			expr:            `sum by (type) (foo / on (instance) bar)`,
			wantClauses:     []promqlClause{{index: 1, text: "by:type"}},
			wantInRemainder: []string{"on", "(", "instance", ")"},
		},
		// A bare by/without keeps its token; nothing is dropped.
		{expr: `rate(x[5m]) by`, wantClauses: nil, wantInRemainder: []string{")", "by"}},
		{expr: `rate(x[5m]) without`, wantClauses: nil, wantInRemainder: []string{")", "without"}},
		{expr: `foo / on(by) bar`, wantClauses: nil, wantInRemainder: []string{"on", "(", "by", ")"}},
		{expr: `a / on(x) group_left(by) b`, wantClauses: nil, wantInRemainder: []string{"group_left", "(", "by", ")"}},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if !slices.Equal(got.clauses, tc.wantClauses) {
			t.Fatalf("canonicalizePromql(%q).clauses = %+v, want %+v", tc.expr, got.clauses, tc.wantClauses)
		}
		vals := canonTokenValues(got.tokens)
		if tc.wantInRemainder != nil && !containsRun(vals, tc.wantInRemainder) {
			t.Fatalf("canonicalizePromql(%q) tokens = %v, want them to contain %v", tc.expr, vals, tc.wantInRemainder)
		}
		for _, clause := range got.clauses {
			if clause.index < 0 || clause.index > len(got.tokens) {
				t.Fatalf("canonicalizePromql(%q): clause index %d out of range for %d tokens", tc.expr, clause.index, len(got.tokens))
			}
		}
	}
}

// A grouping list is PromQL's flat `label_list`, nothing else. Anything nested
// inside it — a call, a selector, a parenthesized group — is not a label list,
// and reading one as if it were meant its inner tokens were consumed and thrown
// away: the clause then lifted out of the sequence carrying a metric, a matcher
// and a literal with it, so a repair could delete them and still compare equal.
// The reader now fails closed on any token that is not a label name or a comma,
// which is the invariant it must hold: every token it consumes either enters the
// canonical representation or causes a rejection.
func TestValidateSyntaxRepair_MalformedGroupingClause(t *testing.T) {
	const malformed = "syntax repair rejected: malformed grouping clause"
	for _, tc := range []struct {
		name               string
		original, repaired string
		wantErr            string
	}{{
		// The finding: `type(bar{env="prod"})` is not a label list. Reading it
		// as one dropped `bar`, `env="prod"` and `"prod"` from the original,
		// so the repair that deletes them compared equal and was ACCEPTED.
		name:     "call nested in the grouping list",
		original: `increase(foo[1h]) by (type(bar{env="prod"}))`,
		repaired: `sum by (type) (increase(foo[1h]))`,
		wantErr:  malformed,
	}, {
		name:     "parenthesized group nested in the grouping list",
		original: `foo by (a, (b))`,
		repaired: `sum by (a, b) (foo)`,
		wantErr:  malformed,
	}, {
		name:     "selector nested in the grouping list",
		original: `foo by (a{x="1"})`,
		repaired: `sum by (a) (foo)`,
		wantErr:  malformed,
	}, {
		name:     "number in the grouping list",
		original: `foo by (a 5)`,
		repaired: `sum by (a) (foo)`,
		wantErr:  malformed,
	}, {
		name:     "without clause with a nested call",
		original: `increase(foo[1h]) without (type(bar))`,
		repaired: `sum without (type) (increase(foo[1h]))`,
		wantErr:  malformed,
	}, {
		// The repaired side is read by the same rule.
		name:     "malformed grouping list on the repaired side",
		original: `foo by (a)`,
		repaired: `sum by (a(b)) (foo)`,
		wantErr:  malformed,
	}, {
		// Unterminated: today the lexer already refuses this one, so the
		// message is the tokenizer's. Either way it must not be accepted.
		name:     "unterminated grouping list",
		original: `foo by (a`,
		repaired: `sum by (a) (foo)`,
		wantErr:  "syntax repair rejected",
	}} {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := ValidateSyntaxRepair(tc.original, tc.repaired)
			if err == nil {
				t.Fatalf("malformed grouping clause accepted as syntax repair: %s -> %s", tc.original, tc.repaired)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "foo") || strings.Contains(err.Error(), "prod") {
				t.Fatalf("error leaked query text: %v", err)
			}
		})
	}
}

// readGroupClause's contract, spelled out: a flat list of label names and
// commas is reduced to its normalized text and the index of its closing paren;
// anything else — a nested paren, a brace, an operator, a number, or running
// out of input before the closing paren — is an error, never a silent
// truncation of what it consumed.
func TestReadGroupClause(t *testing.T) {
	// clauseOf lexes expr and reads the grouping clause opened by its first
	// by/without keyword.
	clauseOf := func(t *testing.T, expr string) (string, int, error) {
		t.Helper()
		items, err := lexAllItems(expr)
		if err != nil {
			t.Fatalf("lexAllItems(%q): %v", expr, err)
		}
		for i, it := range items {
			if isGroupClauseKeyword(it.Typ) {
				return readGroupClause(items, i)
			}
		}
		t.Fatalf("no grouping keyword in %q", expr)
		return "", 0, nil
	}

	for _, tc := range []struct {
		expr string
		want string
	}{
		{expr: `sum by (b, a) (foo)`, want: "by:a,b"},
		{expr: `sum without (type) (foo)`, want: "without:type"},
		{expr: `sum by () (foo)`, want: "by:"},
		{expr: `sum by (quantile) (foo)`, want: "by:quantile"},
		{expr: `sum by ("quantile") (foo)`, want: `by:"quantile"`},
		{expr: `sum by (start, end) (foo)`, want: "by:end,start"},
	} {
		text, last, err := clauseOf(t, tc.expr)
		if err != nil {
			t.Fatalf("readGroupClause(%q): %v", tc.expr, err)
		}
		if text != tc.want {
			t.Fatalf("readGroupClause(%q) = %q, want %q", tc.expr, text, tc.want)
		}
		items, _ := lexAllItems(tc.expr)
		if last >= len(items) || items[last].Typ != promqlparser.RIGHT_PAREN {
			t.Fatalf("readGroupClause(%q) last index %d is not the closing paren", tc.expr, last)
		}
	}

	for _, expr := range []string{
		`foo by (a, (b))`,
		`foo by (type(bar))`,
		`foo by (a{x="1"})`,
		`foo by (a 5)`,
		`foo by (a + b)`,
		`foo by (5m)`,
		`foo by (without)`, // WITHOUT is not in the grammar's maybe_label rule
	} {
		if _, _, err := clauseOf(t, expr); err == nil {
			t.Fatalf("readGroupClause(%q) accepted a non-flat label list", expr)
		}
	}

	// Running out of input before the closing paren is an error, not a
	// silently truncated clause.
	items, err := lexAllItems(`sum by (a, b)`)
	if err != nil {
		t.Fatalf("lexAllItems: %v", err)
	}
	if _, _, err := readGroupClause(items[:len(items)-1], 1); err == nil {
		t.Fatalf("readGroupClause accepted an unterminated label list")
	}
}

// A keyword-named matcher label must be captured as part of its matcher triple
// and must NOT be recorded as an aggregator. Today the lexer already guarantees
// this on its own — lexInsideBraces routes every alphanumeric run through
// lexIdentifier, which always emits IDENTIFIER, so `quantile` inside braces
// never carries the QUANTILE token type. The canonical form no longer depends on
// that: the matcher-triple case is keyed on a following matcher operator, not on
// the label name's token type. This test pins the outcome so a future parser
// bump that starts emitting keyword types inside braces cannot silently poison
// the aggregation count (which would falsely reject the canonical relocation on
// any summary metric).
func TestCanonicalizePromql_KeywordNamedMatcherLabel(t *testing.T) {
	got, err := canonicalizePromql(`http_request_duration_seconds{quantile="0.99"}`)
	if err != nil {
		t.Fatalf("canonicalizePromql: %v", err)
	}
	want := []canonToken{
		{typ: promqlparser.IDENTIFIER, val: "http_request_duration_seconds"},
		{typ: promqlparser.LEFT_BRACE, val: "{"},
		{val: `quantile="0.99"`, matcher: true},
		{typ: promqlparser.RIGHT_BRACE, val: "}"},
	}
	if !slices.Equal(got.tokens, want) {
		t.Fatalf("canonicalizePromql tokens = %+v, want %+v", got.tokens, want)
	}
	if idx := appliedAggregators(got.tokens); len(idx) != 0 {
		t.Fatalf("matcher label counted as an aggregator: %v", idx)
	}

	// A quoted label name lands in the same triple rather than scattering the
	// name and the value across two literal tokens.
	quoted, err := canonicalizePromql(`http_request_duration_seconds{"quantile"="0.99"}`)
	if err != nil {
		t.Fatalf("canonicalizePromql: %v", err)
	}
	wantQuoted := []string{"http_request_duration_seconds", "{", `"quantile"="0.99"`, "}"}
	if vals := canonTokenValues(quoted.tokens); !slices.Equal(vals, wantQuoted) {
		t.Fatalf("quoted tokens = %v, want %v", vals, wantQuoted)
	}
}

// An aggregation keyword IS an aggregation wherever it appears in the
// expression — including dangling at the end, which is a truncated aggregation
// rather than a metric of that name. The one exception is a keyword used as a
// LABEL NAME inside a vector-matching or cardinality list (PromQL's maybe_label
// rule admits every aggregator name there), which aggregates nothing and must
// not inflate the count, or a legitimate repair looks like a second aggregator.
func TestAppliedAggregators(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []int
	}{
		{expr: `sum(foo)`, want: []int{0}},
		{expr: `sum by (t) (foo)`, want: []int{0}},
		{expr: `sum(foo) by (t)`, want: []int{0}},
		{expr: `topk(5, foo)`, want: []int{0}},
		{expr: `max(sum by (t) (foo))`, want: []int{0, 2}},
		{expr: `increase(foo[1h])`, want: nil},
		// Label names, not aggregations.
		{expr: `foo / on(sum) bar`, want: nil},
		{expr: `foo / on(quantile) bar`, want: nil},
		{expr: `foo / ignoring(count) bar`, want: nil},
		{expr: `a / on(x) group_left(sum) b`, want: nil},
		{expr: `a / on(x) group_right(sum) b`, want: nil},
		{expr: `foo{quantile="0.99"}`, want: nil},
		// The real wrapper is found even when an aggregator-named label sits
		// in front of it.
		{expr: `foo / on(sum) sum by (x) (bar)`, want: []int{6}},
		// Dangling: a truncated aggregation still aggregates.
		{expr: `sum by`, want: []int{0}},
		{expr: `avg by (x)`, want: []int{0}},
		{expr: `foo + sum by (x)`, want: []int{2}},
		{expr: `sum by (x) (avg)`, want: []int{0, 2}},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if idx := appliedAggregators(got.tokens); !slices.Equal(idx, tc.want) {
			t.Fatalf("appliedAggregators(%q) = %v, want %v", tc.expr, idx, tc.want)
		}
	}
}

// A clause's slot is normalized before it is compared: the two spellings of one
// aggregation's modifier slot (`agg by (t) (X)` and `agg(X) by (t)`) name the
// same owner, and any other position is compared literally so a clause cannot
// drift onto a different owner.
func TestClauseSlot(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []string
	}{
		{expr: `sum by (a) (foo)`, want: []string{"owner:0"}},
		{expr: `sum(foo) by (a)`, want: []string{"owner:0"}},
		{expr: `topk(5, foo) by (t)`, want: []string{"owner:0"}},
		{expr: `topk by (t) (5, foo)`, want: []string{"owner:0"}},
		{expr: `sum by (a) (foo) + sum by (b) (bar)`, want: []string{"owner:0", "owner:5"}},
		{expr: `sum(foo) by (a) + sum(bar) by (b)`, want: []string{"owner:0", "owner:5"}},
		// A clause inside the aggregation's parentheses is NOT its modifier
		// slot, and a clause with no aggregator at all keeps its position.
		{expr: `sum(increase(x[1h]) by (type))`, want: []string{"pos:9"}},
		{expr: `increase(x[1h]) by (type)`, want: []string{"pos:7"}},
		{expr: `increase(a[1h]) by (x) / sum(b)`, want: []string{"pos:7"}},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		aggregators := appliedAggregators(got.tokens)
		slots := make([]string, 0, len(got.clauses))
		for _, clause := range got.clauses {
			slots = append(slots, clauseSlot(got.tokens, aggregators, clause.index))
		}
		if !slices.Equal(slots, tc.want) {
			t.Fatalf("clause slots for %q = %v, want %v", tc.expr, slots, tc.want)
		}
	}
}

// termStart is the tight-binding reading of `X by (t)`: the clause groups the
// operand it immediately follows, and that operand's extent is what a new
// wrapper is allowed to cover. One original therefore admits exactly one
// wrapping, which is what makes contradictory repairs of the same original
// impossible to both accept.
func TestTermStart(t *testing.T) {
	for _, tc := range []struct {
		expr     string
		wantTerm []string
	}{
		{expr: `increase(x[1h]) by (type)`, wantTerm: []string{"increase", "(", "x", "[", "1h", "]", ")"}},
		{
			expr:     `foo{env="prod"} > increase(bar[1h]) by (type)`,
			wantTerm: []string{"increase", "(", "bar", "[", "1h", "]", ")"},
		},
		{expr: `(a + b) by (x)`, wantTerm: []string{"(", "a", "+", "b", ")"}},
		{
			expr:     `rate(a[5m]) / rate(b[5m]) by (job)`,
			wantTerm: []string{"rate", "(", "b", "[", "5m", "]", ")"},
		},
		{expr: `foo / on(x) bar by (t)`, wantTerm: []string{"bar"}},
		{expr: `a / on(x) group_left(y) bar by (t)`, wantTerm: []string{"bar"}},
		{expr: `foo offset 5m by (t)`, wantTerm: []string{"foo", "offset", "5m"}},
		{expr: `-a by (x)`, wantTerm: []string{"a"}},
		{expr: `foo @ 1234 by (t)`, wantTerm: []string{"foo", "@", "1234"}},
		{expr: `foo{env="prod"} by (t)`, wantTerm: []string{"foo", "{", `env="prod"`, "}"}},
		{expr: `a and b by (t)`, wantTerm: []string{"b"}},
		{expr: `foo > bool bar by (t)`, wantTerm: []string{"bar"}},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if len(got.clauses) != 1 {
			t.Fatalf("canonicalizePromql(%q): want exactly one clause, got %+v", tc.expr, got.clauses)
		}
		boundary := got.clauses[0].index
		start, ok := termStart(got.tokens, boundary)
		if !ok {
			t.Fatalf("termStart(%q) could not determine a term start", tc.expr)
		}
		if term := canonTokenValues(got.tokens[start:boundary]); !slices.Equal(term, tc.wantTerm) {
			t.Fatalf("termStart(%q) term = %v, want %v", tc.expr, term, tc.wantTerm)
		}
	}
}

func TestValidateSyntaxRepair_FailClosed(t *testing.T) {
	// An unterminated string cannot be fully tokenized. ValidateSyntaxRepair
	// must reject the repair rather than approve it on a partial read.
	original := `metric_name{x="unterminated`
	repaired := `metric_name{x="unterminated"}`
	if err := ValidateSyntaxRepair(original, repaired); err == nil {
		t.Fatalf("unlexable original accepted as syntax-only repair")
	}
}

// canonTokenValues renders a canonical token sequence as its values, for
// readable table assertions.
func canonTokenValues(tokens []canonToken) []string {
	if len(tokens) == 0 {
		return nil
	}
	vals := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		vals = append(vals, tok.val)
	}
	return vals
}

// containsRun reports whether want appears in vals as a contiguous run.
func containsRun(vals, want []string) bool {
	for i := 0; i+len(want) <= len(vals); i++ {
		if slices.Equal(vals[i:i+len(want)], want) {
			return true
		}
	}
	return false
}
