// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
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

func TestValidateSyntaxRepair_FailClosed(t *testing.T) {
	// An unterminated string cannot be fully tokenized. ValidateSyntaxRepair
	// must reject the repair rather than approve it on a partial signature.
	original := `metric_name{x="unterminated`
	repaired := `metric_name{x="unterminated"}`
	if err := ValidateSyntaxRepair(original, repaired); err == nil {
		t.Fatalf("unlexable original accepted as syntax-only repair")
	}
}
