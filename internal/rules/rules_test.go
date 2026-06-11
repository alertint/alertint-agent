// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"strings"
	"testing"
)

// validRule returns a minimal rule that passes validation; tests mutate it.
func validRule() Rule {
	return Rule{
		ID:      "test.rule",
		Kind:    KindCorrelation,
		When:    When{MinAlerts: 2},
		Updated: "2026-06-11",
	}
}

func TestValidate_AcceptsMinimalRule(t *testing.T) {
	r := validRule()
	if errs := r.Validate(); len(errs) != 0 {
		t.Fatalf("want no errors, got %v", errs)
	}
}

func TestValidate_ErrorsCarryIDFieldReason(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Rule)
		want string // substring of the error
	}{
		{"missing id", func(r *Rule) { r.ID = "" }, "rule (missing id): id: is required"},
		{"bad kind", func(r *Rule) { r.Kind = "magic" }, "kind: \"magic\" must be one of"},
		{"bad window", func(r *Rule) { r.Window = "five minutes" }, "window: \"five minutes\" is not a valid duration"},
		{"negative window", func(r *Rule) { r.Window = "-5m" }, "window: must be positive"},
		{"bad updated", func(r *Rule) { r.Updated = "June 2026" }, "updated:"},
		{"empty when", func(r *Rule) { r.When = When{} }, "when: must define at least one condition"},
		{"min_distinct without label", func(r *Rule) { r.When.MinDistinct = &MinDistinct{Count: 3} }, "when.min_distinct.label: is required"},
		{"min_distinct zero count", func(r *Rule) { r.When.MinDistinct = &MinDistinct{Label: "service"} }, "when.min_distinct.count: must be >= 1"},
		{"bad action", func(r *Rule) { r.Then.Action = "page" }, "then.action: \"page\" must be one of"},
		{"bad severity", func(r *Rule) { r.Then.Severity = "catastrophic" }, "then.severity:"},
		{"grouping without group_by", func(r *Rule) { r.Kind = KindGrouping }, "then.group_by: is required for grouping rules"},
		{"short_circuit without hint", func(r *Rule) { r.Then.ShortCircuitLLM = true }, "then.root_cause_hint: is required when short_circuit_llm"},
		{"predicate without operand kind", func(r *Rule) {
			r.When.All = []Predicate{{Op: "equals", Value: "x"}}
		}, "when.all[0]: exactly one of label, field, or metric"},
		{"predicate bad op", func(r *Rule) {
			r.When.All = []Predicate{{Label: "severity", Op: "matches", Value: "x"}}
		}, "when.all[0].op: \"matches\" must be one of"},
		{"equals without value", func(r *Rule) {
			r.When.Any = []Predicate{{Label: "severity", Op: "equals"}}
		}, "when.any[0].value: is required for op \"equals\""},
		{"invalid regex", func(r *Rule) {
			r.When.All = []Predicate{{Label: "alertname", Op: "regex", Value: "("}}
		}, "when.all[0].value: invalid regex"},
		{"in without values", func(r *Rule) {
			r.When.All = []Predicate{{Label: "env", Op: "in"}}
		}, "when.all[0].values: is required for op \"in\""},
		{"unknown field predicate", func(r *Rule) {
			r.When.All = []Predicate{{Field: "summary", Op: "exists"}}
		}, "is not a known alert field"},
		{"metric predicate rejected", func(r *Rule) {
			r.When.All = []Predicate{{Metric: &MetricPredicate{Query: "up", Op: "lt", Value: 1}, Op: "exists"}}
		}, "metric predicates are reserved schema"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRule()
			tc.mut(&r)
			errs := r.Validate()
			if len(errs) == 0 {
				t.Fatalf("want validation error containing %q, got none", tc.want)
			}
			joined := make([]string, len(errs))
			for i, e := range errs {
				joined[i] = e.Error()
			}
			all := strings.Join(joined, "\n")
			if !strings.Contains(all, tc.want) {
				t.Fatalf("want error containing %q, got:\n%s", tc.want, all)
			}
		})
	}
}

func TestValidate_CompilesRegexAndWindow(t *testing.T) {
	r := validRule()
	r.Window = "5m"
	r.When.All = []Predicate{{Label: "alertname", Op: "regex", Value: "^High"}}
	if errs := r.Validate(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if r.WindowDuration().Minutes() != 5 {
		t.Errorf("window = %v, want 5m", r.WindowDuration())
	}
	if r.When.All[0].re == nil {
		t.Error("regex was not compiled by Validate")
	}
}
