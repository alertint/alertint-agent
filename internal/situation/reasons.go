// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

const ReasonCatalogVersion = 1

var reasonPredicateVersions = map[string]int{
	"critical_anchor":          2,
	"confirmed_severe_impact":  2,
	"expanding_blast_radius":   2,
	"urgent_policy":            2,
	"duration_outlier":         2,
	"novel_symptom":            2,
	"envelope_violation":       2,
	"operator_judgment_needed": 2,
	"terminal_uncertainty":     2,
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
	criticalQuieted := envelopeQuietingAuthorized(snapshot)
	if !criticalQuieted {
		criticalRefs := make([]string, 0)
		for _, symptom := range snapshot.Symptoms {
			if symptom.Lifecycle == model.DeliveryStatusFiring && symptom.Severity == "critical" {
				refs, ok := matchingEvidence(snapshot, symptom.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
					return matchesSymptomState(fact, symptom)
				})
				if ok {
					criticalRefs = append(criticalRefs, refs...)
				}
			}
		}
		if len(canonicalStrings(criticalRefs)) > 0 {
			reasons = append(reasons, newCandidate("critical_anchor", "active_source_severity_critical", criticalRefs, true))
		}
	}

	impactRefs := make([]string, 0)
	for _, impact := range snapshot.Impact {
		if impact.Confirmed && severeImpact(impact.Severity) {
			refs, ok := matchingEvidence(snapshot, impact.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
				return matchesImpact(fact, impact)
			})
			if ok {
				impactRefs = append(impactRefs, refs...)
			}
		}
	}
	if len(canonicalStrings(impactRefs)) > 0 {
		reasons = append(reasons, newCandidate("confirmed_severe_impact", "confirmed_severe_availability_or_impact", impactRefs, true))
	}

	if radius := snapshot.BlastRadius; radius != nil && radius.UrgentBoundary > 0 && radius.Previous < radius.UrgentBoundary &&
		radius.Current >= radius.UrgentBoundary && radius.Current > radius.Previous {
		if refs, ok := matchingEvidence(snapshot, radius.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
			return matchesBlastRadius(fact, snapshot.SituationID, *radius)
		}); ok {
			reasons = append(reasons, newCandidate("expanding_blast_radius", "configured_urgent_boundary_crossed", refs, true))
		}
	}

	policyRefs := make([]string, 0)
	for _, policy := range snapshot.UrgentPolicies {
		if policy.Active && policy.Scoped && strings.TrimSpace(policy.ID) != "" {
			refs, ok := matchingEvidence(snapshot, policy.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
				return matchesUrgentPolicy(fact, policy)
			})
			if ok {
				policyRefs = append(policyRefs, refs...)
			}
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
		if symptom.Lifecycle == model.DeliveryStatusFiring && symptom.Novel {
			activeRefs, active := matchingEvidence(snapshot, symptom.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
				return matchesSymptomState(fact, symptom)
			})
			historyRefs, absent := matchingEvidence(snapshot, symptom.NoveltyEvidenceRefs, observationmodel.ResultStatusConfirmedEmpty, func(fact observationmodel.Fact) bool {
				return matchesSymptomHistoryAbsence(fact, symptom.ID)
			})
			if active && absent {
				novelRefs = append(novelRefs, activeRefs...)
				novelRefs = append(novelRefs, historyRefs...)
			}
		}
	}
	if len(canonicalStrings(novelRefs)) > 0 {
		reasons = append(reasons, newCandidate("novel_symptom", "active_normalized_symptom_absent_from_comparable_history", novelRefs, false))
	}

	if snapshot.Envelope != nil && snapshot.Envelope.Result == model.EnvelopeEvaluationViolation &&
		len(snapshot.Envelope.Violations) > 0 && len(snapshot.Envelope.Observability) > 0 {
		if refs, ok := envelopeEvidence(snapshot, *snapshot.Envelope); ok {
			reasons = append(reasons, newCandidate("envelope_violation", "active_envelope_violation", refs, false))
		}
	}

	if uncertainty := snapshot.TerminalUncertainty; uncertainty != nil && uncertainty.DeadlineCrossed && uncertainty.Actionable &&
		validTerminalUncertainty(uncertainty.Reason) {
		if refs, ok := matchingEvidence(snapshot, uncertainty.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
			return matchesTerminalUncertainty(fact, snapshot.SituationID, *uncertainty)
		}); ok {
			reasons = append(reasons, newCandidate("terminal_uncertainty", "lifecycle_deadline_crossed_actionable_uncertainty", refs, false))
		}
	}

	if choice := snapshot.SemanticChoice; choice != nil && strings.TrimSpace(choice.Code) != "" &&
		(choice.State == model.ActionStatusBlocked || choice.State == model.ActionStatusExhausted) {
		refs, choiceProven := matchingEvidence(snapshot, choice.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
			return matchesSemanticChoice(fact, *choice)
		})
		hasOperationalReason := false
		if choiceProven {
			for _, reason := range reasons {
				if reason.Code != "operator_judgment_needed" {
					hasOperationalReason = true
					refs = append(refs, reason.EvidenceRefs...)
				}
			}
		}
		if hasOperationalReason {
			reasons = append(reasons, newCandidate("operator_judgment_needed", "specific_semantic_choice_blocked_or_exhausted", refs, false))
		}
	}

	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Code < reasons[j].Code })
	return reasons
}

type factPredicate func(observationmodel.Fact) bool

func matchingEvidence(snapshot Snapshot, refs []string, status observationmodel.ResultStatus, predicate factPredicate) ([]string, bool) {
	refs = canonicalStrings(refs)
	if len(refs) == 0 {
		return nil, false
	}
	resolved := append([]string(nil), refs...)
	for _, ref := range refs {
		matched := false
		for _, fact := range snapshot.Facts {
			if !factReferences(fact, ref) || !usableEvidenceFact(snapshot, fact, status) || !predicate(fact) {
				continue
			}
			matched = true
			resolved = append(resolved, fact.ID)
		}
		if !matched {
			return nil, false
		}
	}
	return canonicalStrings(resolved), true
}

func factReferences(fact observationmodel.Fact, ref string) bool {
	if fact.ID == ref {
		return true
	}
	for _, evidenceRef := range fact.EvidenceRefs {
		if evidenceRef == ref {
			return true
		}
	}
	return false
}

func usableEvidenceFact(snapshot Snapshot, fact observationmodel.Fact, status observationmodel.ResultStatus) bool {
	return fact.SituationID == snapshot.SituationID && fact.InputVersion == snapshot.InputVersion && fact.Material &&
		fact.Freshness == observationmodel.FreshnessFresh && fact.ResultStatus == status
}

func decodeFactValue(fact observationmodel.Fact, target any) bool {
	return len(fact.Value) > 0 && json.Unmarshal(fact.Value, target) == nil
}

func matchesSymptomState(fact observationmodel.Fact, symptom Symptom) bool {
	var value struct {
		Lifecycle model.DeliveryStatus `json:"lifecycle"`
		Severity  string               `json:"severity"`
	}
	return fact.Kind == "symptom_state" && fact.Subject == symptom.ID && decodeFactValue(fact, &value) &&
		value.Lifecycle == symptom.Lifecycle && strings.ToLower(strings.TrimSpace(value.Severity)) == strings.ToLower(strings.TrimSpace(symptom.Severity))
}

func matchesImpact(fact observationmodel.Fact, impact ImpactFact) bool {
	var value struct {
		Kind      string `json:"kind"`
		Severity  string `json:"severity"`
		Confirmed bool   `json:"confirmed"`
	}
	return fact.Kind == "impact" && fact.Subject == impact.Kind && decodeFactValue(fact, &value) &&
		value.Kind == impact.Kind && strings.ToLower(strings.TrimSpace(value.Severity)) == strings.ToLower(strings.TrimSpace(impact.Severity)) &&
		value.Confirmed == impact.Confirmed
}

func matchesBlastRadius(fact observationmodel.Fact, situationID string, radius BlastRadius) bool {
	var value struct {
		Previous       int `json:"previous"`
		Current        int `json:"current"`
		UrgentBoundary int `json:"urgent_boundary"`
	}
	return fact.Kind == "blast_radius" && fact.Subject == situationID && decodeFactValue(fact, &value) &&
		value.Previous == radius.Previous && value.Current == radius.Current && value.UrgentBoundary == radius.UrgentBoundary
}

func matchesUrgentPolicy(fact observationmodel.Fact, policy UrgentPolicy) bool {
	var value struct {
		Active bool `json:"active"`
		Scoped bool `json:"scoped"`
	}
	return fact.Kind == "urgent_policy" && fact.Subject == policy.ID && decodeFactValue(fact, &value) &&
		value.Active == policy.Active && value.Scoped == policy.Scoped
}

func matchesCurrentDuration(fact observationmodel.Fact, snapshot Snapshot) bool {
	var value struct {
		ElapsedSeconds int64  `json:"elapsed_seconds"`
		DurationClass  string `json:"duration_class"`
	}
	return fact.Kind == "current_duration" && fact.Subject == snapshot.SituationID && decodeFactValue(fact, &value) &&
		value.ElapsedSeconds == snapshot.ElapsedSeconds && strings.TrimSpace(value.DurationClass) == strings.TrimSpace(snapshot.DurationClass)
}

func matchesCompletedEpisode(fact observationmodel.Fact, episode CompletedEpisode) bool {
	var value struct {
		DurationSeconds int64 `json:"duration_seconds"`
		Comparable      bool  `json:"comparable"`
	}
	return fact.Kind == "completed_episode" && fact.Subject == episode.ID && decodeFactValue(fact, &value) &&
		value.DurationSeconds == episode.DurationSeconds && value.Comparable == episode.Comparable
}

func matchesSymptomHistoryAbsence(fact observationmodel.Fact, symptomID string) bool {
	var value struct {
		Absent     bool `json:"absent"`
		Comparable bool `json:"comparable"`
	}
	return fact.Kind == "symptom_history" && fact.Subject == symptomID && decodeFactValue(fact, &value) && value.Absent && value.Comparable
}

func envelopeEvidence(snapshot Snapshot, envelope EnvelopeResult) ([]string, bool) {
	return matchingEvidence(snapshot, envelope.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
		var value struct {
			EnvelopeVersion   int                            `json:"envelope_version"`
			Result            model.EnvelopeEvaluationResult `json:"result"`
			MatchedFields     []string                       `json:"matched_fields"`
			Violations        []string                       `json:"violations"`
			Observability     []string                       `json:"observability"`
			QuietingAuthority bool                           `json:"quieting_authority"`
		}
		return fact.Kind == "envelope_evaluation" && fact.Subject == envelope.EnvelopeID && decodeFactValue(fact, &value) &&
			value.EnvelopeVersion == envelope.EnvelopeVersion && value.Result == envelope.Result &&
			stringSlicesEqual(value.MatchedFields, envelope.MatchedFields) && stringSlicesEqual(value.Violations, envelope.Violations) &&
			stringSlicesEqual(value.Observability, envelope.Observability) && value.QuietingAuthority == envelope.QuietingAuthority
	})
}

func envelopeQuietingAuthorized(snapshot Snapshot) bool {
	if snapshot.Envelope == nil || snapshot.Envelope.Result != model.EnvelopeEvaluationMatch || !snapshot.Envelope.QuietingAuthority {
		return false
	}
	_, ok := envelopeEvidence(snapshot, *snapshot.Envelope)
	return ok
}

func matchesSemanticChoice(fact observationmodel.Fact, choice SemanticChoice) bool {
	var value struct {
		State model.ActionStatus `json:"state"`
	}
	return fact.Kind == "semantic_choice" && fact.Subject == choice.Code && decodeFactValue(fact, &value) && value.State == choice.State
}

func matchesTerminalUncertainty(fact observationmodel.Fact, situationID string, uncertainty TerminalUncertainty) bool {
	var value struct {
		DeadlineCrossed bool                 `json:"deadline_crossed"`
		Actionable      bool                 `json:"actionable"`
		Reason          model.TerminalReason `json:"reason"`
	}
	return fact.Kind == "terminal_uncertainty" && fact.Subject == situationID && decodeFactValue(fact, &value) &&
		value.DeadlineCrossed == uncertainty.DeadlineCrossed && value.Actionable == uncertainty.Actionable && value.Reason == uncertainty.Reason
}

func stringSlicesEqual(left, right []string) bool {
	left = canonicalStrings(left)
	right = canonicalStrings(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
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
	if snapshot.ElapsedSeconds <= 0 {
		return nil, false
	}
	currentRefs, currentOK := matchingEvidence(snapshot, snapshot.CurrentDurationEvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
		return matchesCurrentDuration(fact, snapshot)
	})
	if !currentOK {
		return nil, false
	}

	durations := make([]int64, 0, len(snapshot.CompletedEpisodes))
	refs := append([]string(nil), currentRefs...)
	for _, episode := range snapshot.CompletedEpisodes {
		if !episode.Comparable || episode.DurationSeconds <= 0 {
			continue
		}
		episodeRefs, ok := matchingEvidence(snapshot, episode.EvidenceRefs, observationmodel.ResultStatusConfirmedValue, func(fact observationmodel.Fact) bool {
			return matchesCompletedEpisode(fact, episode)
		})
		if !ok {
			continue
		}
		durations = append(durations, episode.DurationSeconds)
		refs = append(refs, episodeRefs...)
	}
	refs = canonicalStrings(refs)
	if len(durations) < 5 || len(refs) < 2 {
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
