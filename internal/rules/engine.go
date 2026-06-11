// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// Engine holds the merged, validated rule set from all sources and
// evaluates incidents against it.
type Engine struct {
	rules     []Rule // sorted: rule priority desc, then id asc
	templates map[string]string
	defaults  PackDefaults
	packs     []PackMeta
	logger    *slog.Logger
}

// NewEngine loads every source, merges packs in source-priority order
// (higher priority overrides same rule id / template name), validates the
// merged rule set, and returns a ready Engine. Any validation error aborts
// with the full list of problems.
func NewEngine(ctx context.Context, logger *slog.Logger, sources ...RuleSource) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(sources) == 0 {
		return nil, errors.New("rules: at least one RuleSource is required")
	}

	ordered := make([]RuleSource, len(sources))
	copy(ordered, sources)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority() < ordered[j].Priority() })

	e := &Engine{templates: map[string]string{}, logger: logger}
	byID := map[string]Rule{}
	for _, src := range ordered {
		pack, err := src.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("rules: source %s: %w", src.Name(), err)
		}
		for _, r := range pack.Rules {
			byID[r.ID] = r
		}
		for name, body := range pack.Templates {
			e.templates[name] = body
		}
		// Later (higher-priority) packs override defaults wholesale when set.
		if pack.Defaults.Flap.WindowSeconds > 0 {
			e.defaults.Flap = pack.Defaults.Flap
		}
		e.packs = append(e.packs, pack.Meta)
		logger.Info("rules: pack loaded",
			slog.String("source", src.Name()),
			slog.String("pack", pack.Meta.Name),
			slog.String("version", pack.Meta.Version),
			slog.Int("rules", len(pack.Rules)),
			slog.Int("templates", len(pack.Templates)),
		)
	}

	for _, r := range byID {
		e.rules = append(e.rules, r)
	}
	sort.Slice(e.rules, func(i, j int) bool {
		if e.rules[i].Priority != e.rules[j].Priority {
			return e.rules[i].Priority > e.rules[j].Priority
		}
		return e.rules[i].ID < e.rules[j].ID
	})

	if err := e.validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// validate runs per-rule validation plus engine-level checks (template
// references must resolve in the merged template set).
func (e *Engine) validate() error {
	var errs []error
	for i := range e.rules {
		errs = append(errs, e.rules[i].Validate()...)
		if t := e.rules[i].Then.AnalysisTemplate; t != "" {
			if _, ok := e.templates[t]; !ok {
				errs = append(errs, fmt.Errorf("rule %s: then.analysis_template: template %q not found in any loaded pack", e.rules[i].ID, t))
			}
		}
	}
	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, err := range errs {
			msgs[i] = err.Error()
		}
		return fmt.Errorf("rules: invalid rule set:\n  - %s", strings.Join(msgs, "\n  - "))
	}
	return nil
}

// Rules returns the merged rule set, highest priority first.
func (e *Engine) Rules() []Rule { return e.rules }

// Packs returns metadata for every loaded pack, in load order.
func (e *Engine) Packs() []PackMeta { return e.packs }

// Template returns a prompt template by name from the merged template set.
func (e *Engine) Template(name string) (string, bool) {
	t, ok := e.templates[name]
	return t, ok
}

// Flap returns the merged flap-detection thresholds.
func (e *Engine) Flap() FlapConfig { return e.defaults.Flap }

// GroupLabels returns the union of group_by labels from grouping rules,
// preserving rule-priority order. This is the pack's description of MVP
// grouping behavior; the correlator config can override it.
func (e *Engine) GroupLabels() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range e.rules {
		if r.Kind != KindGrouping {
			continue
		}
		for _, l := range r.Then.GroupBy {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// Decision is the outcome of evaluating an incident against the rule set.
type Decision struct {
	// Rule is the highest-priority matching correlation/known_issue/
	// enrichment rule, or nil when nothing matched.
	Rule *Rule
	// TemplateName is the matched rule's analysis template ("" = caller
	// picks its default).
	TemplateName string
	// ShortCircuit means the finding comes from the rule, not the LLM.
	ShortCircuit bool
	// Suppress means individual member alerts should not page; the
	// incident-level finding is the single notification.
	Suppress      bool
	RootCauseHint string
	References    []string
}

// EvaluateIncident matches the incident's member alerts against every
// non-grouping rule (grouping is applied at correlation time, not here)
// and returns the highest-priority match. A nil Engine evaluates to an
// empty Decision so callers can stay nil-safe.
func (e *Engine) EvaluateIncident(alerts []store.Alert) Decision {
	if e == nil || len(alerts) == 0 {
		return Decision{}
	}
	for i := range e.rules {
		r := &e.rules[i]
		if r.Kind == KindGrouping {
			continue
		}
		if matchRule(r, alerts) {
			return Decision{
				Rule:          r,
				TemplateName:  r.Then.AnalysisTemplate,
				ShortCircuit:  r.Then.ShortCircuitLLM,
				Suppress:      r.Then.Suppress,
				RootCauseHint: r.Then.RootCauseHint,
				References:    r.Then.References,
			}
		}
	}
	return Decision{}
}

// matchRule reports whether the incident (its member alerts) satisfies
// every condition the rule defines.
func matchRule(r *Rule, alerts []store.Alert) bool {
	if !matchAppliesTo(r.AppliesTo, alerts) {
		return false
	}
	if r.When.MinAlerts > 0 && len(alerts) < r.When.MinAlerts {
		return false
	}
	if r.window > 0 && alertSpan(alerts) > r.window {
		return false
	}
	if md := r.When.MinDistinct; md != nil && distinctValues(alerts, md.Label) < md.Count {
		return false
	}
	for _, l := range r.When.SharingLabels {
		if !labelShared(alerts, l) {
			return false
		}
	}
	for i := range r.When.All {
		if !anyAlertMatches(&r.When.All[i], alerts) {
			return false
		}
	}
	if len(r.When.Any) > 0 {
		matched := false
		for i := range r.When.Any {
			if anyAlertMatches(&r.When.Any[i], alerts) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchAppliesTo(a AppliesTo, alerts []store.Alert) bool {
	if a.Component != "" {
		found := false
		for _, al := range alerts {
			if al.Labels["component"] == a.Component || al.Labels["service"] == a.Component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(a.Versions) > 0 {
		found := false
		for _, al := range alerts {
			if versionMatches(a.Versions, al.Labels["version"]) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func versionMatches(patterns []string, version string) bool {
	if version == "" {
		return false
	}
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(version, prefix) {
				return true
			}
		} else if version == p {
			return true
		}
	}
	return false
}

// anyAlertMatches reports whether at least one member alert satisfies the
// predicate (incident-level existential semantics; see docs/rules-spec.md).
func anyAlertMatches(p *Predicate, alerts []store.Alert) bool {
	for i := range alerts {
		if matchAlert(p, &alerts[i]) {
			return true
		}
	}
	return false
}

func matchAlert(p *Predicate, a *store.Alert) bool {
	var val string
	var present bool
	switch {
	case p.Label != "":
		val, present = a.Labels[p.Label]
	case p.Field == "status":
		val, present = a.Status, a.Status != ""
	default:
		return false
	}

	switch p.Op {
	case "exists":
		return present
	case "equals":
		return present && val == p.Value
	case "not_equals":
		return !present || val != p.Value
	case "regex":
		return present && p.re != nil && p.re.MatchString(val)
	case "in":
		if !present {
			return false
		}
		for _, v := range p.Values {
			if val == v {
				return true
			}
		}
	}
	return false
}

func alertSpan(alerts []store.Alert) (span time.Duration) {
	if len(alerts) < 2 {
		return 0
	}
	earliest, latest := alerts[0].ReceivedAt, alerts[0].ReceivedAt
	for _, a := range alerts[1:] {
		if a.ReceivedAt.Before(earliest) {
			earliest = a.ReceivedAt
		}
		if a.ReceivedAt.After(latest) {
			latest = a.ReceivedAt
		}
	}
	return latest.Sub(earliest)
}

func distinctValues(alerts []store.Alert, label string) int {
	seen := map[string]bool{}
	for _, a := range alerts {
		if v, ok := a.Labels[label]; ok {
			seen[v] = true
		}
	}
	return len(seen)
}

func labelShared(alerts []store.Alert, label string) bool {
	first, ok := alerts[0].Labels[label]
	if !ok {
		return false
	}
	for _, a := range alerts[1:] {
		if a.Labels[label] != first {
			return false
		}
	}
	return true
}
