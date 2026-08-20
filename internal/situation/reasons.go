// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

const ReasonCatalogVersion = 1

var reasonPredicateVersions = map[string]int{
	"critical_anchor":          1,
	"confirmed_severe_impact":  1,
	"expanding_blast_radius":   1,
	"urgent_policy":            1,
	"duration_outlier":         1,
	"novel_symptom":            1,
	"envelope_violation":       1,
	"operator_judgment_needed": 1,
	"terminal_uncertainty":     1,
}

var urgentFloorCodes = map[string]struct{}{
	"critical_anchor":         {},
	"confirmed_severe_impact": {},
	"expanding_blast_radius":  {},
	"urgent_policy":           {},
}

// EligibleReasons evaluates the closed version-one catalog. Candidates grant
// no publication authority beyond their deterministic predicates.
func EligibleReasons(snapshot Snapshot) []model.ReasonCandidate {
	reasons := make([]model.ReasonCandidate, 0, 9)
	criticalQuieted := snapshot.Envelope != nil && snapshot.Envelope.Result == model.EnvelopeEvaluationMatch && snapshot.Envelope.QuietingAuthority
	if !criticalQuieted {
		criticalRefs := make([]string, 0)
		for _, symptom := range snapshot.Symptoms {
			if symptom.Lifecycle == model.DeliveryStatusFiring && symptom.Severity == "critical" && len(canonicalStrings(symptom.EvidenceRefs)) > 0 {
				criticalRefs = append(criticalRefs, symptom.EvidenceRefs...)
			}
		}
		if len(canonicalStrings(criticalRefs)) > 0 {
			reasons = append(reasons, newCandidate("critical_anchor", "active_source_severity_critical", criticalRefs, true))
		}
	}

	impactRefs := make([]string, 0)
	for _, impact := range snapshot.Impact {
		if impact.Confirmed && severeImpact(impact.Severity) {
			impactRefs = append(impactRefs, impact.EvidenceRefs...)
		}
	}
	if len(canonicalStrings(impactRefs)) > 0 {
		reasons = append(reasons, newCandidate("confirmed_severe_impact", "confirmed_severe_availability_or_impact", impactRefs, true))
	}

	if radius := snapshot.BlastRadius; radius != nil && radius.UrgentBoundary > 0 && radius.Previous < radius.UrgentBoundary &&
		radius.Current >= radius.UrgentBoundary && radius.Current > radius.Previous && len(canonicalStrings(radius.EvidenceRefs)) > 0 {
		reasons = append(reasons, newCandidate("expanding_blast_radius", "configured_urgent_boundary_crossed", radius.EvidenceRefs, true))
	}

	policyRefs := make([]string, 0)
	for _, policy := range snapshot.UrgentPolicies {
		if policy.Active && policy.Scoped && strings.TrimSpace(policy.ID) != "" && len(canonicalStrings(policy.EvidenceRefs)) > 0 {
			policyRefs = append(policyRefs, policy.EvidenceRefs...)
		}
	}
	if len(canonicalStrings(policyRefs)) > 0 {
		reasons = append(reasons, newCandidate("urgent_policy", "active_explicit_scoped_urgent_policy", policyRefs, true))
	}

	if refs, ok := durationOutlierEvidence(snapshot); ok {
		reasons = append(reasons, newCandidate("duration_outlier", "current_duration_gt_p95_and_twice_median", refs, false))
	}

	novelRefs := make([]string, 0)
	for _, symptom := range snapshot.Symptoms {
		if symptom.Lifecycle == model.DeliveryStatusFiring && symptom.Novel &&
			len(canonicalStrings(symptom.EvidenceRefs)) > 0 && evidenceRefsResolveToFacts(snapshot, symptom.NoveltyEvidenceRefs) {
			novelRefs = append(novelRefs, symptom.EvidenceRefs...)
			novelRefs = append(novelRefs, symptom.NoveltyEvidenceRefs...)
		}
	}
	if len(canonicalStrings(novelRefs)) > 0 {
		reasons = append(reasons, newCandidate("novel_symptom", "active_normalized_symptom_absent_from_comparable_history", novelRefs, false))
	}

	if snapshot.Envelope != nil && snapshot.Envelope.Result == model.EnvelopeEvaluationViolation &&
		len(snapshot.Envelope.Violations) > 0 && len(snapshot.Envelope.Observability) > 0 &&
		evidenceRefsResolveToFacts(snapshot, snapshot.Envelope.EvidenceRefs) {
		reasons = append(reasons, newCandidate("envelope_violation", "active_envelope_violation", snapshot.Envelope.EvidenceRefs, false))
	}

	if uncertainty := snapshot.TerminalUncertainty; uncertainty != nil && uncertainty.DeadlineCrossed && uncertainty.Actionable &&
		validTerminalUncertainty(uncertainty.Reason) && len(canonicalStrings(uncertainty.EvidenceRefs)) > 0 {
		reasons = append(reasons, newCandidate("terminal_uncertainty", "lifecycle_deadline_crossed_actionable_uncertainty", uncertainty.EvidenceRefs, false))
	}

	if choice := snapshot.SemanticChoice; choice != nil && strings.TrimSpace(choice.Code) != "" &&
		(choice.State == model.ActionStatusBlocked || choice.State == model.ActionStatusExhausted) && len(canonicalStrings(choice.EvidenceRefs)) > 0 {
		refs := append([]string(nil), choice.EvidenceRefs...)
		hasOperationalReason := false
		for _, reason := range reasons {
			if reason.Code != "operator_judgment_needed" {
				hasOperationalReason = true
				refs = append(refs, reason.EvidenceRefs...)
			}
		}
		if hasOperationalReason {
			reasons = append(reasons, newCandidate("operator_judgment_needed", "specific_semantic_choice_blocked_or_exhausted", refs, false))
		}
	}

	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Code < reasons[j].Code })
	return reasons
}

func evidenceRefsResolveToFacts(snapshot Snapshot, refs []string) bool {
	refs = canonicalStrings(refs)
	if len(refs) == 0 {
		return false
	}
	known := make(map[string]struct{}, len(snapshot.Facts))
	for _, fact := range snapshot.Facts {
		known[fact.ID] = struct{}{}
		for _, ref := range fact.EvidenceRefs {
			known[ref] = struct{}{}
		}
	}
	for _, ref := range refs {
		if _, ok := known[ref]; !ok {
			return false
		}
	}
	return true
}

func severeImpact(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "severe", "critical", "unavailable":
		return true
	default:
		return false
	}
}

func validTerminalUncertainty(reason model.TerminalReason) bool {
	switch reason {
	case model.TerminalReasonObservationDeadline, model.TerminalReasonResolutionMissing,
		model.TerminalReasonSourceUnavailable, model.TerminalReasonBudgetExhausted:
		return true
	default:
		return false
	}
}

func durationOutlierEvidence(snapshot Snapshot) ([]string, bool) {
	durations := make([]int64, 0, len(snapshot.CompletedEpisodes))
	refs := append([]string(nil), snapshot.CurrentDurationEvidenceRefs...)
	for _, episode := range snapshot.CompletedEpisodes {
		if !episode.Comparable || episode.DurationSeconds <= 0 || len(canonicalStrings(episode.EvidenceRefs)) == 0 {
			continue
		}
		durations = append(durations, episode.DurationSeconds)
		refs = append(refs, episode.EvidenceRefs...)
	}
	refs = canonicalStrings(refs)
	if len(durations) < 5 || snapshot.ElapsedSeconds <= 0 || len(canonicalStrings(snapshot.CurrentDurationEvidenceRefs)) == 0 || len(refs) < 2 {
		return nil, false
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95Index := int(math.Ceil(float64(len(durations))*0.95)) - 1
	if p95Index < 0 {
		p95Index = 0
	}
	p95 := durations[p95Index]
	return refs, snapshot.ElapsedSeconds > p95 && exceedsTwiceMedian(snapshot.ElapsedSeconds, durations)
}

func exceedsTwiceMedian(current int64, sortedDurations []int64) bool {
	middle := len(sortedDurations) / 2
	if len(sortedDurations)%2 != 0 {
		median := sortedDurations[middle]
		return current > median && current-median > median
	}
	left, right := sortedDurations[middle-1], sortedDurations[middle]
	return current > left && current-left > right
}

func newCandidate(code, result string, refs []string, floor bool) model.ReasonCandidate {
	refs = canonicalStrings(refs)
	predicateVersion := reasonPredicateVersions[code]
	return model.ReasonCandidate{
		ID: candidateID(code, predicateVersion, refs), CatalogVersion: ReasonCatalogVersion,
		PredicateVersion: predicateVersion, Code: code, PredicateResult: result,
		EvidenceRefs: refs, DeterministicFloor: floor,
	}
}

func canonicalPredicateVersions() []string {
	out := make([]string, 0, len(reasonPredicateVersions))
	for code, version := range reasonPredicateVersions {
		out = append(out, code+":v"+strconv.Itoa(version))
	}
	sort.Strings(out)
	return out
}

func candidateID(code string, predicateVersion int, refs []string) string {
	material := code + "\x1f" + strconv.Itoa(predicateVersion) + "\x1f" + strings.Join(canonicalStrings(refs), "\x1f")
	sum := sha256.Sum256([]byte(material))
	return fmt.Sprintf("reason:%s:v%d:%x", code, predicateVersion, sum[:8])
}
