// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// EnvelopeFacts are the deterministic, evidence-bound facts EvaluateEnvelope
// checks a confirmed EnvelopeVersion's Conditions against. Every field is a
// closed identity, a confirmed boolean signal, or a canonical instant — never
// free text — so a match or violation is always traceable to specific
// evidence rather than model narration.
type EnvelopeFacts struct {
	// Occurred is the instant evaluation happens at (schedule + duration checks).
	Occurred time.Time
	// ScopeStartedAt anchors DurationMinutes; zero means the elapsed duration
	// is unknown and is never treated as satisfying a configured bound.
	ScopeStartedAt time.Time
	// ActiveSignals are companion signal kinds currently confirmed present.
	ActiveSignals []string
	// ObservedSignals are companion signal kinds this evaluation actually
	// checked — present or confirmed absent. A signal missing from this set
	// was neither confirmed present nor confirmed absent this cycle.
	ObservedSignals []string
	// ActiveImpactSignals are impact kinds currently confirmed present,
	// checked against ForbiddenImpactSignals with the same present/observed
	// contract as companion signals.
	ActiveImpactSignals []string
	// ObservedImpactSignals are impact kinds this evaluation actually checked.
	ObservedImpactSignals []string
	// Workload is the current confirmed workload class; empty means unknown.
	Workload string
	// EvidenceQuality stands in for the current uncertainty ordinal and is
	// compared against Conditions.MaximumUncertainty using the same closed
	// vocabulary (model.EvidenceQuality) so free text never steers quieting.
	EvidenceQuality model.EvidenceQuality
	// EvidenceRefs are every fact reference this evaluation consulted.
	EvidenceRefs []string
}

var evidenceQualityRank = map[model.EvidenceQuality]int{
	model.EvidenceQualityComplete:     0,
	model.EvidenceQualityDegraded:     1,
	model.EvidenceQualityInsufficient: 2,
}

// EvaluateEnvelope matches a confirmed EnvelopeVersion's Conditions against
// EnvelopeFacts in a fixed, documented order:
//
//  1. Required companion signals — each must be confirmed present. One
//     confirmed absent is a violation; one never observed at all removes
//     quieting authority outright (mandatory evidence is missing, not just
//     inconclusive).
//  2. Every active companion signal outside the envelope's exact declared
//     required/allowed scope removes authority — the envelope cannot certify
//     a signal it never named, so this is treated as unresolvable rather
//     than a plain violation.
//  3. Forbidden impact signals — each must be confirmed absent, with the
//     same present/observed/unobserved three-way outcome as step 1.
//  4. Schedule, duration, workload, and the maximum-uncertainty ceiling, in
//     that order, each contributing to matched/violated/unobserved.
//
// A violation anywhere always wins over an authority-removed condition
// elsewhere (a confirmed breach is a stronger signal than missing evidence);
// only when nothing violates and nothing is unresolved does the result match.
// allow_expected_critical never widens this: it only controls whether a
// match additionally carries QuietingAuthority.
func EvaluateEnvelope(v model.EnvelopeVersion, facts EnvelopeFacts) EnvelopeResult {
	result := EnvelopeResult{EnvelopeID: v.EnvelopeID, EnvelopeVersion: v.Version}
	if v.Status != model.EnvelopeStatusActive {
		result.Result = model.EnvelopeEvaluationNotApplicable
		result.EvidenceRefs = canonicalStrings(facts.EvidenceRefs)
		return result
	}

	activeSet := stringSet(facts.ActiveSignals)
	observedSet := stringSet(facts.ObservedSignals)
	requiredSet := stringSet(v.Conditions.RequiredCompanionSignals)
	allowedSet := stringSet(v.Conditions.AllowedCompanionSignals)

	var matched, violations, observability []string
	authorityRemoved := false

	for _, sig := range canonicalStrings(v.Conditions.RequiredCompanionSignals) {
		switch {
		case has(activeSet, sig):
			matched = append(matched, "required_companion_present:"+sig)
		case has(observedSet, sig):
			violations = append(violations, "required_companion_absent:"+sig)
		default:
			authorityRemoved = true
			observability = append(observability, "required_companion_unobserved:"+sig)
		}
	}

	for _, sig := range canonicalStrings(facts.ActiveSignals) {
		if has(requiredSet, sig) {
			continue // already accounted for above
		}
		if has(allowedSet, sig) {
			matched = append(matched, "allowed_companion_present:"+sig)
			continue
		}
		authorityRemoved = true
		observability = append(observability, "unlisted_active_companion:"+sig)
	}

	activeImpact := stringSet(facts.ActiveImpactSignals)
	observedImpact := stringSet(facts.ObservedImpactSignals)
	for _, sig := range canonicalStrings(v.Conditions.ForbiddenImpactSignals) {
		switch {
		case has(activeImpact, sig):
			violations = append(violations, "forbidden_impact_present:"+sig)
		case has(observedImpact, sig):
			observability = append(observability, "forbidden_impact_confirmed_absent:"+sig)
		default:
			authorityRemoved = true
			observability = append(observability, "forbidden_impact_unobserved:"+sig)
		}
	}

	if v.Conditions.Schedule != nil {
		occurrence, err := ResolveScheduleOccurrence(*v.Conditions.Schedule, facts.Occurred)
		if err != nil || !occurrence.Contains(facts.Occurred, v.Conditions.Schedule.StartToleranceMinutes) {
			violations = append(violations, "schedule_outside_window")
		} else {
			matched = append(matched, "schedule_within_window")
		}
	}

	if v.Conditions.DurationMinutes != nil {
		dr := *v.Conditions.DurationMinutes
		switch {
		case dr.Max <= 0 || dr.Min < 0 || dr.Min > dr.Max:
			// A zero or missing upper bound never authorizes an arbitrary
			// duration; a malformed bound is treated as an unmet condition.
			violations = append(violations, "duration_bound_invalid")
		case facts.ScopeStartedAt.IsZero():
			authorityRemoved = true
			observability = append(observability, "duration_scope_unobserved")
		default:
			elapsed := facts.Occurred.Sub(facts.ScopeStartedAt)
			if elapsed < time.Duration(dr.Min)*time.Minute || elapsed > time.Duration(dr.Max)*time.Minute {
				violations = append(violations, "duration_out_of_range")
			} else {
				matched = append(matched, "duration_within_range")
			}
		}
	}

	if v.Conditions.Workload != nil {
		want := strings.ToLower(strings.TrimSpace(*v.Conditions.Workload))
		got := strings.ToLower(strings.TrimSpace(facts.Workload))
		switch {
		case got == "":
			authorityRemoved = true
			observability = append(observability, "workload_unobserved")
		case got != want:
			violations = append(violations, "workload_mismatch")
		default:
			matched = append(matched, "workload_match")
		}
	}

	if v.Conditions.MaximumUncertainty != nil {
		ceiling, ok := evidenceQualityRank[model.EvidenceQuality(strings.TrimSpace(*v.Conditions.MaximumUncertainty))]
		switch {
		case !ok:
			violations = append(violations, "maximum_uncertainty_invalid")
		case facts.EvidenceQuality == "":
			authorityRemoved = true
			observability = append(observability, "uncertainty_unobserved")
		default:
			rank, known := evidenceQualityRank[facts.EvidenceQuality]
			if !known || rank > ceiling {
				violations = append(violations, "uncertainty_exceeds_maximum")
			} else {
				matched = append(matched, "uncertainty_within_maximum")
			}
		}
	}

	switch {
	case len(violations) > 0:
		result.Result = model.EnvelopeEvaluationViolation
	case authorityRemoved:
		result.Result = model.EnvelopeEvaluationAuthorityRemoved
	default:
		result.Result = model.EnvelopeEvaluationMatch
	}
	result.MatchedFields = canonicalStrings(matched)
	result.Violations = canonicalStrings(violations)
	result.Observability = canonicalStrings(observability)
	result.EvidenceRefs = canonicalStrings(facts.EvidenceRefs)
	// Default-off critical quieting: a match alone never grants authority —
	// only an operator's explicit allow_expected_critical does, and even then
	// only critical_anchor is scoped by it (reasons.go enforces the scope).
	result.QuietingAuthority = result.Result == model.EnvelopeEvaluationMatch && v.Conditions.AllowExpectedCritical
	return result
}

// ValidateEnvelopeConditions enforces the structural guarantees every
// confirmed EnvelopeVersion must carry: required and allowed companion
// signals are disjoint (an envelope cannot simultaneously mandate and merely
// tolerate the same signal), a configured duration bound has a positive
// upper limit (an omitted or zero maximum never authorizes an arbitrary
// duration), a configured schedule is itself resolvable, and a configured
// uncertainty ceiling is one of the closed EvidenceQuality values — never
// free text.
func ValidateEnvelopeConditions(cond model.EnvelopeConditions) error {
	required := stringSet(cond.RequiredCompanionSignals)
	for _, sig := range cond.AllowedCompanionSignals {
		if has(required, strings.TrimSpace(sig)) {
			return fmt.Errorf("situation: required and allowed companion signals must be disjoint (shared %q)", sig)
		}
	}
	if cond.DurationMinutes != nil {
		dr := *cond.DurationMinutes
		if dr.Max <= 0 {
			return errors.New("situation: duration_minutes.max must be positive; an omitted or zero maximum never authorizes an arbitrary duration")
		}
		if dr.Min < 0 || dr.Min > dr.Max {
			return errors.New("situation: duration_minutes.min must be nonnegative and no greater than max")
		}
	}
	if cond.Schedule != nil {
		if _, _, _, _, _, _, err := parseSchedule(*cond.Schedule); err != nil {
			return fmt.Errorf("situation: invalid schedule: %w", err)
		}
	}
	if cond.MaximumUncertainty != nil {
		if _, ok := evidenceQualityRank[model.EvidenceQuality(strings.TrimSpace(*cond.MaximumUncertainty))]; !ok {
			return fmt.Errorf("situation: maximum_uncertainty %q must be one of the closed evidence-quality values", *cond.MaximumUncertainty)
		}
	}
	if cond.Workload != nil && strings.TrimSpace(*cond.Workload) == "" {
		return errors.New("situation: workload condition must not be blank when present")
	}
	return nil
}

func stringSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func has(set map[string]struct{}, key string) bool {
	_, ok := set[strings.TrimSpace(key)]
	return ok
}
