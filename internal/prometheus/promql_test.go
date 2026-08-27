// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"slices"
	"strings"
	"testing"
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
	// expression is unchanged: pooling matchers globally instead of per
	// selector would let this slip through.
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
		// Caught by matcherGroups, not by operator tracking: the triple
		// already encodes label+op+value as one string.
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

// The label-matcher operators (=, !=, =~, !~) are consumed as part of a
// matcher triple, so they must never also land in the operator list — three of
// the four (NEQ, EQL_REGEX, NEQ_REGEX) are inside the parser's IsOperator
// range and would otherwise be double-counted, and an expression with a
// matcher would then compare unequal against one without for the wrong reason.
func TestBuildPromqlSignature_MatcherOpsNotCountedAsOperators(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []string
	}{
		{expr: `foo{env="prod"} > 5`, want: []string{">"}},
		{expr: `foo{env!="prod",k=~"a.*",j!~"b.*"} > 5`, want: []string{">"}},
		{expr: `foo{env="prod"}`, want: nil},
		{expr: `foo + bar @ 1234`, want: []string{"+", "@"}},
		{expr: `foo and bar unless baz`, want: []string{"and", "unless"}},
	} {
		sig, err := buildPromqlSignature(tc.expr)
		if err != nil {
			t.Fatalf("buildPromqlSignature(%q): %v", tc.expr, err)
		}
		if !slices.Equal(sig.operators, tc.want) {
			t.Fatalf("buildPromqlSignature(%q).operators = %v, want %v", tc.expr, sig.operators, tc.want)
		}
	}
}

// The clause entries the grouping check compares, spelled out: keyword kept,
// labels sorted, one entry per clause in encounter order, and an entry
// recorded even for the degenerate no-list form so a clause is never silently
// dropped.
func TestBuildPromqlSignature_GroupClauses(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []string
	}{
		{expr: `sum by (b, a) (foo)`, want: []string{"by:a,b"}},
		{expr: `sum without (type) (foo)`, want: []string{"without:type"}},
		{expr: `sum by (a) (foo) + sum by (b) (bar)`, want: []string{"by:a", "by:b"}},
		{expr: `sum by () (foo)`, want: []string{"by:"}},
		{expr: `sum(foo)`, want: nil},
	} {
		sig, err := buildPromqlSignature(tc.expr)
		if err != nil {
			t.Fatalf("buildPromqlSignature(%q): %v", tc.expr, err)
		}
		if !slices.Equal(sig.groupClauses, tc.want) {
			t.Fatalf("buildPromqlSignature(%q).groupClauses = %v, want %v", tc.expr, sig.groupClauses, tc.want)
		}
	}
}

func TestValidateSyntaxRepair_FailClosed(t *testing.T) {
	// An unterminated string cannot be fully tokenized. ValidateSyntaxRepair
	// must reject the repair rather than approve it on a partial signature.
	original := `metric_name{x="unterminated`
	repaired := `metric_name{x="unterminated"}`
	if err := ValidateSyntaxRepair(original, repaired); err == nil {
		t.Fatalf("unlexable original accepted as syntax-only repair")
	}
}
