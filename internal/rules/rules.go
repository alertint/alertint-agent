// SPDX-License-Identifier: FSL-1.1-ALv2

// Package rules implements the open rule schema and the rule engine.
//
// Design notes:
//   - Mechanism vs. content: this package is the mechanism (schema,
//     validation, loading, evaluation). Rules and prompt templates are
//     content, shipped in packs. The baseline pack is embedded in the
//     binary (packs/baseline); future packs load through the same
//     RuleSource interface without engine changes.
//   - Validation errors always carry rule id + field + reason so a pack
//     author can fix a broken rule without reading engine source.
//   - Metric predicates are part of the open schema but rejected by the
//     v1 engine at load time: failing loud beats silently never matching.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kind classifies what a rule does. Grouping rules describe how alerts are
// grouped into incidents; correlation rules match patterns across an
// incident's member alerts; known-issue rules attach curated diagnoses;
// enrichment rules add context for analysis.
type Kind string

const (
	KindGrouping    Kind = "grouping"
	KindCorrelation Kind = "correlation"
	KindKnownIssue  Kind = "known_issue"
	KindEnrichment  Kind = "enrichment"
)

var validKinds = map[Kind]bool{
	KindGrouping:    true,
	KindCorrelation: true,
	KindKnownIssue:  true,
	KindEnrichment:  true,
}

// Rule is one entry in a rule pack. See docs/rules-spec.md for the full
// schema reference with worked examples.
type Rule struct {
	ID          string    `yaml:"id"`
	Kind        Kind      `yaml:"kind"`
	Description string    `yaml:"description,omitempty"`
	Priority    int       `yaml:"priority,omitempty"`
	Window      string    `yaml:"window,omitempty"` // Go duration string, e.g. "5m"
	When        When      `yaml:"when"`
	Then        Then      `yaml:"then"`
	AppliesTo   AppliesTo `yaml:"applies_to,omitempty"`
	Updated     string    `yaml:"updated"` // YYYY-MM-DD

	window time.Duration // parsed by Validate
}

// WindowDuration returns the parsed window, or zero when the rule has none.
// Only meaningful after Validate has succeeded.
func (r *Rule) WindowDuration() time.Duration { return r.window }

// When is the match side of a rule. Predicates in All must each be
// satisfied by at least one member alert; Any requires at least one
// predicate to be satisfied. SharingLabels requires every member alert to
// carry an identical value for each listed label.
type When struct {
	All           []Predicate  `yaml:"all,omitempty"`
	Any           []Predicate  `yaml:"any,omitempty"`
	SharingLabels []string     `yaml:"sharing_labels,omitempty"`
	MinAlerts     int          `yaml:"min_alerts,omitempty"`
	MinDistinct   *MinDistinct `yaml:"min_distinct,omitempty"`
}

// MinDistinct requires at least Count distinct values of Label across the
// incident's member alerts (e.g. ">= 5 distinct services" in storm rules).
type MinDistinct struct {
	Label string `yaml:"label"`
	Count int    `yaml:"count"`
}

// Predicate matches a single member alert. Exactly one of Label, Field, or
// Metric must be set. Field supports "status" (firing|resolved). Metric
// predicates are reserved schema: accepted syntactically, rejected by the
// v1 engine at load.
type Predicate struct {
	Label  string           `yaml:"label,omitempty"`
	Field  string           `yaml:"field,omitempty"`
	Metric *MetricPredicate `yaml:"metric,omitempty"`
	Op     string           `yaml:"op"` // equals | not_equals | regex | in | exists
	Value  string           `yaml:"value,omitempty"`
	Values []string         `yaml:"values,omitempty"`

	re *regexp.Regexp // compiled by Validate for op: regex
}

// MetricPredicate is the reserved shape for metric-based matching
// (PromQL at evaluation time). Not supported by the v1 engine.
type MetricPredicate struct {
	Query string  `yaml:"query"`
	Op    string  `yaml:"op"` // gt | lt
	Value float64 `yaml:"value"`
}

// Then is the action side of a rule.
type Then struct {
	Action           string   `yaml:"action,omitempty"` // group | collapse | annotate
	Suppress         bool     `yaml:"suppress,omitempty"`
	GroupBy          []string `yaml:"group_by,omitempty"`
	RootCauseHint    string   `yaml:"root_cause_hint,omitempty"`
	AnalysisTemplate string   `yaml:"analysis_template,omitempty"`
	ShortCircuitLLM  bool     `yaml:"short_circuit_llm,omitempty"`
	Severity         string   `yaml:"severity,omitempty"` // low | medium | high (short-circuit findings)
	References       []string `yaml:"references,omitempty"`
}

// AppliesTo constrains a rule to a component and optionally to versions.
// Component is matched against the "component" label, falling back to
// "service". Versions entries are exact values or prefix wildcards
// ("1.2.*") matched against the "version" label.
type AppliesTo struct {
	Component string   `yaml:"component,omitempty"`
	Versions  []string `yaml:"versions,omitempty"`
}

var validActions = map[string]bool{"": true, "group": true, "collapse": true, "annotate": true}
var validSeverities = map[string]bool{"": true, "low": true, "medium": true, "high": true}
var validFieldPredicates = map[string]bool{"status": true}
var updatedFormat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Validate checks one rule and returns every problem found, each formatted
// as "rule <id>: <field>: <reason>". It also compiles regex predicates and
// parses the window so evaluation never re-parses.
func (r *Rule) Validate() []error {
	id := r.ID
	if strings.TrimSpace(id) == "" {
		id = "(missing id)"
	}
	fail := func(field, reason string) error {
		return fmt.Errorf("rule %s: %s: %s", id, field, reason)
	}

	var errs []error
	if strings.TrimSpace(r.ID) == "" {
		errs = append(errs, fail("id", "is required"))
	}
	if !validKinds[r.Kind] {
		errs = append(errs, fail("kind", fmt.Sprintf("%q must be one of grouping, correlation, known_issue, enrichment", r.Kind)))
	}
	if r.Window != "" {
		d, err := time.ParseDuration(r.Window)
		switch {
		case err != nil:
			errs = append(errs, fail("window", fmt.Sprintf("%q is not a valid duration (use Go syntax, e.g. \"5m\")", r.Window)))
		case d <= 0:
			errs = append(errs, fail("window", "must be positive"))
		default:
			r.window = d
		}
	}
	if !updatedFormat.MatchString(r.Updated) {
		errs = append(errs, fail("updated", fmt.Sprintf("%q must be a date in YYYY-MM-DD form", r.Updated)))
	}

	errs = append(errs, r.validateWhen(fail)...)
	errs = append(errs, r.validateThen(fail)...)
	return errs
}

func (r *Rule) validateWhen(fail func(field, reason string) error) []error {
	var errs []error
	w := &r.When
	hasCondition := len(w.All) > 0 || len(w.Any) > 0 || len(w.SharingLabels) > 0 ||
		w.MinAlerts > 0 || w.MinDistinct != nil
	if !hasCondition {
		errs = append(errs, fail("when", "must define at least one condition (all, any, sharing_labels, min_alerts, min_distinct)"))
	}
	if w.MinAlerts < 0 {
		errs = append(errs, fail("when.min_alerts", "must be >= 0"))
	}
	if w.MinDistinct != nil {
		if strings.TrimSpace(w.MinDistinct.Label) == "" {
			errs = append(errs, fail("when.min_distinct.label", "is required"))
		}
		if w.MinDistinct.Count < 1 {
			errs = append(errs, fail("when.min_distinct.count", "must be >= 1"))
		}
	}
	for i := range w.All {
		errs = append(errs, w.All[i].validate(fail, fmt.Sprintf("when.all[%d]", i))...)
	}
	for i := range w.Any {
		errs = append(errs, w.Any[i].validate(fail, fmt.Sprintf("when.any[%d]", i))...)
	}
	for i, l := range w.SharingLabels {
		if strings.TrimSpace(l) == "" {
			errs = append(errs, fail(fmt.Sprintf("when.sharing_labels[%d]", i), "is empty"))
		}
	}
	return errs
}

func (r *Rule) validateThen(fail func(field, reason string) error) []error {
	var errs []error
	t := &r.Then
	if !validActions[t.Action] {
		errs = append(errs, fail("then.action", fmt.Sprintf("%q must be one of group, collapse, annotate", t.Action)))
	}
	if !validSeverities[t.Severity] {
		errs = append(errs, fail("then.severity", fmt.Sprintf("%q must be one of low, medium, high", t.Severity)))
	}
	if r.Kind == KindGrouping && len(t.GroupBy) == 0 {
		errs = append(errs, fail("then.group_by", "is required for grouping rules"))
	}
	if t.ShortCircuitLLM && strings.TrimSpace(t.RootCauseHint) == "" {
		errs = append(errs, fail("then.root_cause_hint", "is required when short_circuit_llm is true (it becomes the finding)"))
	}
	return errs
}

func (p *Predicate) validate(fail func(field, reason string) error, path string) []error {
	var errs []error
	set := 0
	if p.Label != "" {
		set++
	}
	if p.Field != "" {
		set++
	}
	if p.Metric != nil {
		set++
	}
	if set != 1 {
		errs = append(errs, fail(path, "exactly one of label, field, or metric must be set"))
	}
	if p.Metric != nil {
		errs = append(errs, fail(path+".metric", "metric predicates are reserved schema and not supported by this engine version"))
		return errs
	}
	if p.Field != "" && !validFieldPredicates[p.Field] {
		errs = append(errs, fail(path+".field", fmt.Sprintf("%q is not a known alert field (supported: status)", p.Field)))
	}

	switch p.Op {
	case "equals", "not_equals":
		if p.Value == "" {
			errs = append(errs, fail(path+".value", fmt.Sprintf("is required for op %q", p.Op)))
		}
	case "regex":
		if p.Value == "" {
			errs = append(errs, fail(path+".value", "is required for op \"regex\""))
		} else if re, err := regexp.Compile(p.Value); err != nil {
			errs = append(errs, fail(path+".value", fmt.Sprintf("invalid regex: %v", err)))
		} else {
			p.re = re
		}
	case "in":
		if len(p.Values) == 0 {
			errs = append(errs, fail(path+".values", "is required for op \"in\""))
		}
	case "exists":
		// no operands
	case "":
		errs = append(errs, fail(path+".op", "is required (equals, not_equals, regex, in, exists)"))
	default:
		errs = append(errs, fail(path+".op", fmt.Sprintf("%q must be one of equals, not_equals, regex, in, exists", p.Op)))
	}
	return errs
}
