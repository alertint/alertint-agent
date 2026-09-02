// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 4: the versioned closed Sufficient-reason catalog (spec.md
// "Sufficient-reason catalog in Plan 2"). EligibleReasons exposes only
// candidates whose required local facts are actually available from this
// task's SnapshotInput — never a false positive for an unsupported input.
// ----------------------------------------------------------------------

const reasonCatalogVersion = 1

const (
	reasonCodeCriticalAnchor      = "critical_anchor"
	reasonCodeDurationOutlier     = "duration_outlier"
	reasonCodeNovelSymptom        = "novel_symptom"
	reasonCodeTerminalUncertainty = "terminal_uncertainty"

	// Reserved catalog codes. Their owning stages define authority, scope,
	// and evidence semantics; Plan 2 has no predicate for any of them, and
	// EligibleReasons never emits them — see
	// TestEligibleReasonsCatalogOnlyEmitsReachableCodes.
	reasonCodeConfirmedSevereImpact  = "confirmed_severe_impact"
	reasonCodeExpandingBlastRadius   = "expanding_blast_radius"
	reasonCodeUrgentPolicy           = "urgent_policy"
	reasonCodeEnvelopeViolation      = "envelope_violation"
	reasonCodeOperatorJudgmentNeeded = "operator_judgment_needed"
)

const (
	predicateVersionCriticalAnchor      = 1
	predicateVersionDurationOutlier     = 1
	predicateVersionNovelSymptom        = 1
	predicateVersionTerminalUncertainty = 1
)

// EligibleReasons evaluates the closed Plan 2 predicate set against in,
// symptoms, and durationClass, returning the reachable candidates in fixed
// catalog order — never dependent on any input's row/map order. Of the
// four candidates the catalog can reach in a later plan, critical_anchor and
// duration_outlier are provable from this task's SnapshotInput today;
// novel_symptom and terminal_uncertainty are not — see
// criticalAnchorEligible, novelSymptomEligible, and
// terminalUncertaintyEligible's doc comments for the specific data each one
// needs (or now has), and the Task 4 report for the full accounting.
func EligibleReasons(in SnapshotInput, symptoms []Symptom, durationClass string) []model.ReasonCandidate {
	situationID := in.Situation.ID
	inputVersion := in.Situation.InputVersion
	out := []model.ReasonCandidate{}

	if criticalAnchorEligible(in.Deliveries) {
		out = append(out, newReasonCandidate(situationID, inputVersion, reasonCodeCriticalAnchor,
			"Confirmed active critical source severity.", predicateVersionCriticalAnchor, true, nil))
	}

	priorSeconds := priorDurationsSeconds(in.PriorSituations)
	elapsed := elapsedDuration(in)
	if durationOutlierEligible(elapsed, priorSeconds) {
		out = append(out, newReasonCandidate(situationID, inputVersion, reasonCodeDurationOutlier,
			"Elapsed duration exceeds the p95 and twice the median of comparable completed Situations.",
			predicateVersionDurationOutlier, false, []string{
				factIdentity(durationFactIDPrefix, situationID, inputVersion, durationClass),
				factIdentity(factKindPriorSituationDurationDistribution, situationID, inputVersion, in.Situation.GroupKey),
			}))
	}

	if novelSymptomEligible(symptoms, in.PriorSituations) {
		refs := make([]string, 0, len(symptoms))
		for _, s := range symptoms {
			refs = append(refs, factIdentity(factKindSourceSymptomState, situationID, inputVersion, s.Key))
		}
		out = append(out, newReasonCandidate(situationID, inputVersion, reasonCodeNovelSymptom,
			"Local history proves confirmed absence of this symptom.", predicateVersionNovelSymptom, false, refs))
	}

	if terminalUncertaintyEligible(in, durationClass) {
		out = append(out, newReasonCandidate(situationID, inputVersion, reasonCodeTerminalUncertainty,
			"Source-aware lifecycle observation deadline expired with actionable uncertainty.",
			predicateVersionTerminalUncertainty, false, []string{
				factIdentity(durationFactIDPrefix, situationID, inputVersion, durationClass),
			}))
	}

	return out
}

func newReasonCandidate(situationID string, inputVersion int, code, summary string, predicateVersion int, floor bool, evidenceRefs []string) model.ReasonCandidate {
	refs := make([]string, len(evidenceRefs))
	copy(refs, evidenceRefs)
	sort.Strings(refs)
	return model.ReasonCandidate{
		ID:                 reasonCandidateID(situationID, inputVersion, code, reasonCatalogVersion, predicateVersion, floor, refs),
		Code:               code,
		Summary:            summary,
		CatalogVersion:     reasonCatalogVersion,
		PredicateVersion:   predicateVersion,
		EvidenceRefs:       refs,
		DeterministicFloor: floor,
	}
}

const reasonCandidateIDSchemaVersion = 1

// reasonCandidateIDDTO is reasonCandidateID's canonical hash input — spec.md:
// "Every candidate records an immutable ID, catalog version, predicate
// version, code, typed predicate result, supporting evidence references,
// and whether it is a deterministic floor." Code alone is not a stable
// identity: two candidates for the same code but different predicate
// versions, or the same predicate proving against different evidence, must
// hash to different IDs — see reasonCandidateID's doc comment.
type reasonCandidateIDDTO struct {
	SchemaVersion      int      `json:"schema_version"`
	SituationID        string   `json:"situation_id"`
	InputVersion       int      `json:"input_version"`
	Code               string   `json:"code"`
	CatalogVersion     int      `json:"catalog_version"`
	PredicateVersion   int      `json:"predicate_version"`
	DeterministicFloor bool     `json:"deterministic_floor"`
	EvidenceRefs       []string `json:"evidence_refs"`
}

// reasonCandidateID is the canonical digest of a Sufficient-reason
// candidate's full identity — code, catalog version, predicate version, its
// typed predicate result (DeterministicFloor), and its sorted evidence
// references — plus the SituationID/InputVersion scoping the original
// "reason:<code>:v<version>:<situation>:<input_version>" formula already
// carried. Hashing every one of these fields (not just code) means bumping
// a predicate's version, or the same predicate proving with a different
// evidence set, produces a distinguishable ID instead of colliding
// byte-for-byte with a prior candidate's ID for the same code — mirroring
// the DTO-then-hash pattern MembershipDigest/MaterialFactHash already use.
// sortedEvidenceRefs must already be sorted (newReasonCandidate guarantees
// this before calling in).
func reasonCandidateID(situationID string, inputVersion int, code string, catalogVersion, predicateVersion int, floor bool, sortedEvidenceRefs []string) string {
	return canonicalDigest(reasonCandidateIDDTO{
		SchemaVersion:      reasonCandidateIDSchemaVersion,
		SituationID:        situationID,
		InputVersion:       inputVersion,
		Code:               code,
		CatalogVersion:     catalogVersion,
		PredicateVersion:   predicateVersion,
		DeterministicFloor: floor,
		EvidenceRefs:       sortedEvidenceRefs,
	})
}

// criticalAnchorEligible is spec's "confirmed active critical source
// severity" predicate: at least one of the Situation's deliveries is
// currently firing (not merely historically observed — a resolved delivery
// no longer confirms an active severity) at or above the "critical" tier of
// internal/severity.Rank's shared ladder (rank 4, "critical"/"crit"; rank 5
// — "alert"/"emergency"/"fatal"/"page"/"disaster" — is even more severe, so
// the comparison is >= 4, not == 4). Delivery.Severity is the raw
// per-delivery severity label the store layer extracts from
// alert_deliveries.labels_json (see snapshot.go's Delivery doc comment);
// this function, not the store, decides what counts as critical.
func criticalAnchorEligible(deliveries []Delivery) bool {
	for _, d := range deliveries {
		if d.Status == model.DeliveryStatusFiring && severity.Rank(d.Severity) >= 4 {
			return true
		}
	}
	return false
}

// durationOutlierEligible is spec's "at least five comparable completed
// Situations and the versioned p95-and-twice-median predicate": the
// current Situation's elapsed duration must exceed both the p95 and twice
// the median of at least five comparable prior durations. priorSeconds
// must already be sorted ascending (priorDurationsSeconds guarantees
// this). "Comparable" is same-group-key by construction:
// SnapshotInput.PriorSituations is already scoped to the claimed
// Situation's exact group key by store.loadPriorTerminalSituationsTx's
// WHERE clause, so every element this function receives is already
// comparable.
func durationOutlierEligible(elapsed time.Duration, priorSeconds []float64) bool {
	if len(priorSeconds) < 5 {
		return false
	}
	p95 := p95NearestRank(priorSeconds)
	med := median(priorSeconds)
	elapsedSeconds := elapsed.Seconds()
	return elapsedSeconds > p95 && elapsedSeconds > 2*med
}

// novelSymptomEligible is spec's "only when local history proves confirmed
// absence" predicate. CompletedSituation (this task's only prior-history
// input) carries no persisted symptom identity at all — just ID, GroupKey,
// EffectiveStartedAt, TerminalAt, and TerminalReason — so there is no way
// to prove a given symptom Key was ever absent from any prior Situation,
// let alone confirm it. This predicate is always false given current data:
// novel_symptom is correctly unreachable until a later task threads
// persisted per-Situation symptom identity into CompletedSituation or a
// dedicated store read.
func novelSymptomEligible(_ []Symptom, _ []CompletedSituation) bool {
	return false
}

// terminalUncertaintyEligible is spec's "only when the source-aware
// lifecycle deadline and actionable uncertainty predicate are proven"
// gate. The full source-aware lifecycle-observation-deadline formula
// (spec.md's "Lifecycle, Attention, and cadence" section: deadlines vary by
// duration class and controller-owned recovery/grace state) is Task 8's
// (lifecycle.go) to define and own as a single deterministic source of
// truth. Implementing a second, simplified deadline formula here risks
// silently disagreeing with Task 8's real one and creating two competing
// answers to "is this Situation past its deadline?" — so this predicate is
// always false given this task's inputs: terminal_uncertainty is correctly
// unreachable until Task 8 exposes a deterministic deadline fact this
// predicate can consume.
func terminalUncertaintyEligible(_ SnapshotInput, _ string) bool {
	return false
}
