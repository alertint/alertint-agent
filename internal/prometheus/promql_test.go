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
		// top-level comparison coexist, and only the aggregation moves.
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
// relocating by/without clauses, adding at most one aggregation wrapper to an
// expression that had none, and reordering matchers inside one selector.
// Everything else — a modifier moved onto a different operand, a keyword the
// signature design had no case for, a second aggregation, a parameterised
// wrapper, added precedence parentheses — differs as a token sequence and is
// rejected by construction.
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
		// topk takes a parameter, so the wrapper is not a bare `agg( … )`:
		// the 5 and its comma survive the strip and do not match.
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
		// on/ignoring label lists are no longer extracted into the clause
		// list — they stay in the token sequence, so a changed label is
		// reported by the class of the token that diverged. START and END are
		// bare keywords, hence the structural class.
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
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if vals := canonTokenValues(got.tokens); !slices.Equal(vals, tc.want) {
			t.Fatalf("canonicalizePromql(%q) tokens = %v, want %v", tc.expr, vals, tc.want)
		}
		for _, tok := range got.tokens {
			if !tok.matcher && isMatcherOp(tok.typ) {
				t.Fatalf("canonicalizePromql(%q): matcher operator %q survived as its own token", tc.expr, tok.val)
			}
		}
	}
}

// The clause entries the grouping check compares, spelled out: keyword kept,
// labels sorted, one entry per by/without clause, the whole list sorted (a
// relocated clause carries no position), and an entry recorded even for the
// degenerate no-list form so a clause is never silently dropped.
//
// on/ignoring are deliberately NOT extracted any more. Their position decides
// which binary operator they modify, so pulling them out of the sequence is
// exactly the hole that let `a / on(instance) b * c` be rewritten as
// `a / b * on(instance) c`. They stay in the remainder as ordinary tokens.
func TestCanonicalizePromql_GroupClauses(t *testing.T) {
	for _, tc := range []struct {
		expr            string
		wantClauses     []string
		wantInRemainder []string
	}{
		{expr: `sum by (b, a) (foo)`, wantClauses: []string{"by:a,b"}},
		{expr: `sum without (type) (foo)`, wantClauses: []string{"without:type"}},
		{expr: `sum by (a) (foo) + sum by (b) (bar)`, wantClauses: []string{"by:a", "by:b"}},
		{expr: `sum by (b) (bar) + sum by (a) (foo)`, wantClauses: []string{"by:a", "by:b"}},
		{expr: `sum by () (foo)`, wantClauses: []string{"by:"}},
		{expr: `sum(foo)`, wantClauses: nil},
		{expr: `sum by (quantile) (foo)`, wantClauses: []string{"by:quantile"}},
		{expr: `foo / on (start) bar`, wantClauses: nil, wantInRemainder: []string{"on", "(", "start", ")"}},
		{expr: `foo / ignoring (b, a) bar`, wantClauses: nil, wantInRemainder: []string{"ignoring", "(", "b", ",", "a", ")"}},
		{
			expr:            `sum by (type) (foo / on (instance) bar)`,
			wantClauses:     []string{"by:type"},
			wantInRemainder: []string{"on", "(", "instance", ")"},
		},
	} {
		got, err := canonicalizePromql(tc.expr)
		if err != nil {
			t.Fatalf("canonicalizePromql(%q): %v", tc.expr, err)
		}
		if !slices.Equal(got.clauses, tc.wantClauses) {
			t.Fatalf("canonicalizePromql(%q).clauses = %v, want %v", tc.expr, got.clauses, tc.wantClauses)
		}
		vals := canonTokenValues(got.tokens)
		for _, extracted := range []string{"by", "without"} {
			if slices.Contains(vals, extracted) {
				t.Fatalf("canonicalizePromql(%q): %q left in the remainder %v", tc.expr, extracted, vals)
			}
		}
		if tc.wantInRemainder != nil && !containsRun(vals, tc.wantInRemainder) {
			t.Fatalf("canonicalizePromql(%q) tokens = %v, want them to contain %v", tc.expr, vals, tc.wantInRemainder)
		}
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
	for _, tok := range got.tokens {
		if tok.typ.IsAggregator() {
			t.Fatalf("matcher label recorded as an aggregator: %q", tok.val)
		}
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
