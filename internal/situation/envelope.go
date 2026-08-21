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
// checks a confirmed EnvelopeVersion's Scope/Conditions against. Every field
// is a closed identity, a confirmed boolean signal, or a canonical instant —
// never free text — so a match or violation is always traceable to specific
// evidence rather than model narration.
type EnvelopeFacts struct {
	// GroupKey, Source, TriggerID, and TriggerVersion are the current
	// Situation's own exact scope/trigger identity, checked against
	// EnvelopeVersion.Scope before any condition is evaluated.
	GroupKey       string
	Source         string
	TriggerID      string
	TriggerVersion string
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
	// EvidenceRefs are every fact reference this evaluation consulted.
	EvidenceRefs []string
}

// uncertaintyPolicyMandatorySignalsObservable is the one closed
// maximum_uncertainty vocabulary value the spec defines. It documents that
// this envelope's authority requires every mandatory signal (required
// companions, forbidden impacts) to have been observed — a policy already
// realized structurally by their own present/observed/unobserved outcomes
// (the "mandatory observability" matching step), not a separate runtime
// check. Free text can never be substituted for it.
const uncertaintyPolicyMandatorySignalsObservable = "mandatory_signals_observable"

// EvaluateEnvelope matches a confirmed EnvelopeVersion against EnvelopeFacts
// in the spec's exact order (planning/2026-08-19-proactive-situation-controller/spec.md,
// "Expected-behaviour envelopes"):
//
//  1. Exact group scope — GroupKey must match exactly.
//  2. Source/trigger identity — Source and TriggerID must match exactly.
//  3. Current trigger version — TriggerVersion must match exactly.
//     Steps 1-3 are hard gates: any mismatch returns not_applicable
//     immediately (this envelope simply is not for this Situation/trigger
//     reality), before any condition below is evaluated.
//  4. Schedule occurrence — the resolved UTC window is always persisted onto
//     the result (independently auditable) whenever a Schedule condition is
//     configured, whether or not Occurred falls inside it.
//  5. Mandatory observability — realized by steps 6, 7, and 10 below: any
//     mandatory signal (a duration scope, a required companion, a forbidden
//     impact) that was never observed at all removes quieting authority
//     rather than being read as absent.
//  6. Value/duration bounds — DurationMinutes and Workload.
//  7. Required companions — each must be confirmed present.
//  8. Allowed-but-not-required companions — present is fine, never a
//     violation or a missing-evidence condition by itself.
//  9. Unauthorized active symptoms — any active companion signal outside the
//     declared required/allowed scope removes authority: the envelope
//     cannot certify a signal it never named.
//  10. Forbidden impacts — each must be confirmed absent.
//  11. Critical authorization — whether allow_expected_critical was
//     explicitly confirmed (a plain read of Conditions, never inferred).
//  12. Quieting authority — the final combination: only a match plus an
//     explicit critical authorization ever grants it.
//
// A violation anywhere always wins over an authority-removed condition
// elsewhere (a confirmed breach is a stronger signal than missing evidence);
// only when nothing violates and nothing is unresolved does the result
// match. Missing mandatory evidence removes authority but never itself
// creates urgent Attention — that stays reasons.go's job.
func EvaluateEnvelope(v model.EnvelopeVersion, facts EnvelopeFacts) EnvelopeResult {
	result := EnvelopeResult{EnvelopeID: v.EnvelopeID, EnvelopeVersion: v.Version}
	if v.Status != model.EnvelopeStatusActive {
		result.Result = model.EnvelopeEvaluationNotApplicable
		result.EvidenceRefs = canonicalStrings(facts.EvidenceRefs)
		return result
	}

	// Steps 1-3: exact group scope, source/trigger identity, current trigger
	// version. Any mismatch is a hard gate.
	if strings.TrimSpace(v.Scope.GroupKey) != strings.TrimSpace(facts.GroupKey) ||
		strings.TrimSpace(v.Scope.Source) != strings.TrimSpace(facts.Source) ||
		strings.TrimSpace(v.Scope.TriggerID) != strings.TrimSpace(facts.TriggerID) ||
		strings.TrimSpace(v.Scope.TriggerVersion) != strings.TrimSpace(facts.TriggerVersion) {
		result.Result = model.EnvelopeEvaluationNotApplicable
		result.EvidenceRefs = canonicalStrings(facts.EvidenceRefs)
		return result
	}

	var matched, violations, observability []string
	authorityRemoved := false

	// Step 4: schedule occurrence. The resolved UTC window is persisted
	// regardless of match/violation so a DST-sensitive determination stays
	// independently auditable without re-deriving it.
	var scheduleStart, scheduleEnd *time.Time
	if v.Conditions.Schedule != nil {
		occurrence, err := ResolveScheduleOccurrence(*v.Conditions.Schedule, facts.Occurred)
		if err != nil {
			violations = append(violations, "schedule_outside_window")
		} else {
			start, end := occurrence.Start, occurrence.End
			scheduleStart, scheduleEnd = &start, &end
			if occurrence.Contains(facts.Occurred, v.Conditions.Schedule.StartToleranceMinutes) {
				matched = append(matched, "schedule_within_window")
			} else {
				violations = append(violations, "schedule_outside_window")
			}
		}
	}

	// Step 5 (mandatory observability) has no independent check of its own —
	// see steps 6, 7, and 10.

	// Step 6: value/duration bounds.
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

	// Step 7: required companions — each must be confirmed present.
	requiredSet := stringSet(v.Conditions.RequiredCompanionSignals)
	allowedSet := stringSet(v.Conditions.AllowedCompanionSignals)
	activeSet := stringSet(facts.ActiveSignals)
	observedSet := stringSet(facts.ObservedSignals)
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

	// Step 8: allowed-but-not-required companions — present is fine, never a
	// violation or a missing-evidence condition by itself.
	for _, sig := range canonicalStrings(facts.ActiveSignals) {
		if has(requiredSet, sig) {
			continue // already accounted for in step 7
		}
		if has(allowedSet, sig) {
			matched = append(matched, "allowed_companion_present:"+sig)
		}
	}

	// Step 9: unauthorized active symptoms — any active companion signal
	// outside the declared required/allowed scope removes authority.
	for _, sig := range canonicalStrings(facts.ActiveSignals) {
		if has(requiredSet, sig) || has(allowedSet, sig) {
			continue
		}
		authorityRemoved = true
		observability = append(observability, "unlisted_active_companion:"+sig)
	}

	// Step 10: forbidden impacts — each must be confirmed absent.
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
	result.ScheduleWindowStart = scheduleStart
	result.ScheduleWindowEnd = scheduleEnd
	// Step 11 (critical authorization): v.Conditions.AllowExpectedCritical is
	// read directly, never inferred. Step 12 (quieting authority): default-off
	// critical quieting — a match alone never grants authority, only an
	// operator's explicit allow_expected_critical does, and even then only
	// critical_anchor is scoped by it (reasons.go enforces the scope).
	result.QuietingAuthority = result.Result == model.EnvelopeEvaluationMatch && v.Conditions.AllowExpectedCritical
	return result
}

// ValidateEnvelopeConditions enforces the structural guarantees every
// confirmed EnvelopeVersion must carry: required and allowed companion
// signals are disjoint (an envelope cannot simultaneously mandate and merely
// tolerate the same signal), a configured duration bound has a positive
// upper limit (an omitted or zero maximum never authorizes an arbitrary
// duration), a configured schedule is itself resolvable, and a configured
// maximum_uncertainty is the one closed vocabulary value the spec defines —
// never free text.
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
		if strings.TrimSpace(*cond.MaximumUncertainty) != uncertaintyPolicyMandatorySignalsObservable {
			return fmt.Errorf("situation: maximum_uncertainty %q must be %q", *cond.MaximumUncertainty, uncertaintyPolicyMandatorySignalsObservable)
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
