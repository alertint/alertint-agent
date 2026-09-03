// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 4: DeriveStoreFacts — the pure reduction of SnapshotInput into
// immutable model.Fact values — plus MaterialFactHash and
// AssessmentBasisHash. Persisting facts (AppendSituationFacts) is Task 3's
// job, already built; nothing in this file performs I/O.
// ----------------------------------------------------------------------

// Fact/hash schema versions. Plan 2 pins these at 1; a future task bumps
// the relevant constant (never silently) when a fact's shape, the material
// hash's included-field set, or the Assessment validator's rules change in
// a way that must invalidate old reuse/hash comparisons.
const (
	factSchemaVersion = 1

	// materialFactHashSchemaVersion and assessmentBasisHashSchemaVersion are
	// bumped to 2 (round 2, Task 4): materialFactHashDTO's included-field set
	// changed (Situation.InputVersion removed; per-Incident materiality is
	// now MembershipDigest alone, not the delivery-level IncidentInputDigest)
	// — see MaterialFactHash's doc comment. assessmentBasisHashDTO's own
	// shape did not change, but it embeds MaterialFactHash's output string
	// directly, so a hash produced before this fix must never be silently
	// treated as compatible with one produced after it.
	materialFactHashSchemaVersion = 2

	// assessmentBasisHashSchemaVersion is bumped to 3 (Task 5): the carried-
	// forward InputVersion-instability bug documented on
	// assessmentBasisReasonDTO is fixed by dropping that DTO's ID field. A
	// hash produced under the old ID-bearing shape must never be silently
	// treated as compatible with one produced under the fixed shape.
	assessmentBasisHashSchemaVersion = 3

	// assessmentValidatorVersion tracks Task 5's ValidateAssessmentProposal
	// rule set. Task 4 has no validator of its own; this placeholder lets
	// AssessmentBasisHash include "Assessment... validator versions" per
	// spec now, so a hash produced before Task 5 lands is never silently
	// treated as compatible with one produced after a validator rule
	// change. Task 5 must bump this the first time it changes what
	// "passes validation" means for a previously-accepted reuse candidate.
	assessmentValidatorVersion = 1
)

const (
	factKindSourceSymptomState                 = "source_symptom_state"
	factKindSourceLifecycleSummary             = "source_lifecycle_summary"
	factKindCurrentDuration                    = "current_duration"
	factKindIncidentMembership                 = "incident_membership"
	factKindIncidentTriageState                = "incident_triage_state"
	factKindAcuteFinding                       = "acute_finding"
	factKindPriorSituationDurationDistribution = "prior_situation_duration_distribution"
	factKindCapabilityLimitation               = "capability_limitation"
)

// durationFactIDPrefix is the literal identity prefix the brief mandates —
// "duration:<situation_id>:<input_version>:<class>" — deliberately not
// factKindCurrentDuration ("current_duration"), which remains the fact's
// Kind field value.
const durationFactIDPrefix = "duration"

const sourceLifecycleSummarySubject = "situation"

const capabilityLimitationSubject = "plan2"

// plan2UnsupportedCapabilities is Plan 2's fixed, versioned set of
// capabilities with no production fact producer yet (spec: "Prometheus,
// logs, Sentry, Zabbix history reads, changes, semantic profiles, Signal
// bindings, envelopes, and operator judgments do not have production fact
// producers in Plan 2."). It is controller/configuration state, not
// input-derived, so it is the same for every Situation in this build — a
// package var (not const) only so tests can prove MaterialFactHash
// actually threads it through; production code never mutates it.
var plan2UnsupportedCapabilities = []model.Limitation{
	{Code: "prometheus_unavailable", Detail: "Prometheus is not a Plan 2 fact producer."},
	{Code: "logs_unavailable", Detail: "Log evidence is not a Plan 2 fact producer."},
	{Code: "sentry_unavailable", Detail: "Sentry evidence is not a Plan 2 fact producer."},
	{Code: "zabbix_history_unavailable", Detail: "Zabbix history reads are not a Plan 2 fact producer."},
	{Code: "changes_unavailable", Detail: "Change evidence is not a Plan 2 fact producer."},
	{Code: "semantic_profile_unavailable", Detail: "Semantic profiles are not a Plan 2 fact producer."},
	{Code: "signal_binding_unavailable", Detail: "Signal bindings are not a Plan 2 fact producer."},
	{Code: "envelope_unavailable", Detail: "Expected-behaviour envelopes are not a Plan 2 fact producer."},
	{Code: "operator_judgment_unavailable", Detail: "Operator judgments are not a Plan 2 fact producer."},
}

// DeriveStoreFacts reduces in into the closed set of Plan 2 fact kinds:
// source_symptom_state, source_lifecycle_summary, current_duration,
// incident_membership, incident_triage_state, acute_finding,
// prior_situation_duration_distribution, and capability_limitation. It is
// pure and self-contained; BuildSnapshot reuses the same reduction through
// deriveStoreFactsWith to avoid recomputing symptoms/duration class twice.
func DeriveStoreFacts(in SnapshotInput) []model.Fact {
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	return deriveStoreFactsWith(in, symptoms, class)
}

func deriveStoreFactsWith(in SnapshotInput, symptoms []Symptom, class string) []model.Fact {
	situationID := in.Situation.ID
	inputVersion := in.Situation.InputVersion

	// Capacity 4 covers the guaranteed single-fact appends below (lifecycle
	// summary, duration, prior-duration-distribution, capability limitation);
	// the four variable-length appends still grow it as needed.
	facts := make([]model.Fact, 0, 4)
	facts = append(facts, deriveSymptomStateFacts(situationID, inputVersion, in.Now, symptoms)...)
	facts = append(facts, deriveLifecycleSummaryFact(situationID, inputVersion, in.Now, symptoms))
	facts = append(facts, deriveDurationFact(in, class))
	facts = append(facts, deriveIncidentMembershipFacts(in)...)
	facts = append(facts, deriveIncidentTriageStateFacts(situationID, inputVersion, in.Now, in.Incidents)...)
	facts = append(facts, deriveAcuteFindingFacts(situationID, inputVersion, in.Now, in.Incidents)...)
	facts = append(facts, derivePriorSituationDurationDistributionFact(in))
	facts = append(facts, deriveCapabilityLimitationFact(situationID, inputVersion, in.Now))

	sortFacts(facts)
	return facts
}

// factIdentity is the deterministic ID scheme every fact kind but
// current_duration uses: <prefix>:<situation_id>:<input_version>:<subject>.
func factIdentity(prefix, situationID string, inputVersion int, subject string) string {
	return fmt.Sprintf("%s:%s:%d:%s", prefix, situationID, inputVersion, subject)
}

// factIdentityWithContent extends factIdentity with the fact's own content
// digest (Task 10 replay finding): incident_triage_state and acute_finding
// are the two fact kinds whose content is not purely a function of
// (situationID, inputVersion, subject) — both read live, controller-owned
// Acute Triage schedule/attempt state (Phase/Attempts/Decision/
// DecisionReason; LatestAttempt's ResultCode/OutputDigest/FindingID) that
// legitimately advances WITHOUT the Situation's own input_version changing
// at all: a controller commit for THIS SAME cycle (DecideTriage's own
// request/skip decision, applied inside CommitController) already changes
// what the VERY NEXT reconcile of the unchanged input observes, and so does
// an independent Acute Triage worker completing/backing off/exhausting an
// attempt in between two controller cycles. Every other fact kind
// (incident_membership, source_symptom_state, current_duration, ...) reads
// only data that changes exactly when input_version does, so
// factIdentity's plain (prefix, situationID, inputVersion, subject) scheme
// is already a stable identity for those. For these two, appending the
// content digest makes each genuinely DISTINCT observation (a different
// Phase, a newly-completed attempt) its own immutable row — collapsing back
// to the SAME id, and so a safe idempotent no-op via AppendSituationFacts'
// own ON CONFLICT DO NOTHING, only when the content is ALSO unchanged.
// Without this, a second reconcile of an unchanged input that observes
// live Triage progress the first reconcile's own commit (or an
// independent Triage completion) just produced fails closed forever with
// ErrImmutableConflict — not a crash-only edge case: any Situation
// reconciled more than once at the same input_version while Triage
// progresses hits it in ordinary operation.
func factIdentityWithContent(prefix, situationID string, inputVersion int, subject string, digest string) string {
	return factIdentity(prefix, situationID, inputVersion, subject) + ":" + digest
}

// sortFacts orders facts by (kind, subject, id) so DeriveStoreFacts' output
// never depends on the order its private derive* helpers appended them in.
func sortFacts(facts []model.Fact) {
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Kind != facts[j].Kind {
			return facts[i].Kind < facts[j].Kind
		}
		if facts[i].Subject != facts[j].Subject {
			return facts[i].Subject < facts[j].Subject
		}
		return facts[i].ID < facts[j].ID
	})
}

// sortedRefs returns a lexically sorted copy of refs, never nil (an empty
// input yields a non-nil empty slice) so evidence reference ordering never
// depends on caller-side construction order.
func sortedRefs(refs []string) []string {
	out := make([]string, len(refs))
	copy(out, refs)
	sort.Strings(out)
	return out
}

// ---- source_symptom_state ----

type sourceSymptomStateFactValue struct {
	Key             string    `json:"key"`
	Status          string    `json:"status"`
	FirstObservedAt time.Time `json:"first_observed_at"`
}

func deriveSymptomStateFacts(situationID string, inputVersion int, now time.Time, symptoms []Symptom) []model.Fact {
	facts := make([]model.Fact, 0, len(symptoms))
	for _, s := range symptoms {
		value := sourceSymptomStateFactValue{Key: s.Key, Status: string(s.Status), FirstObservedAt: s.FirstObservedAt}
		facts = append(facts, model.Fact{
			ID:           factIdentity(factKindSourceSymptomState, situationID, inputVersion, s.Key),
			SituationID:  situationID,
			Kind:         factKindSourceSymptomState,
			Subject:      s.Key,
			Digest:       canonicalDigest(value),
			InputVersion: inputVersion,
			Value:        mustMarshal(value),
			ResultStatus: model.FactConfirmedValue,
			Material:     true,
			ObservedAt:   now,
		})
	}
	return facts
}

// ---- source_lifecycle_summary ----

type sourceLifecycleSummaryFactValue struct {
	FiringCount   int `json:"firing_count"`
	ResolvedCount int `json:"resolved_count"`
	TotalCount    int `json:"total_count"`
}

func deriveLifecycleSummaryFact(situationID string, inputVersion int, now time.Time, symptoms []Symptom) model.Fact {
	value := sourceLifecycleSummaryFactValue{TotalCount: len(symptoms)}
	for _, s := range symptoms {
		switch s.Status {
		case model.DeliveryStatusFiring:
			value.FiringCount++
		case model.DeliveryStatusResolved:
			value.ResolvedCount++
		}
	}
	status := model.FactConfirmedValue
	if len(symptoms) == 0 {
		// A durable, already-queried zero — Plan 2 does have a production
		// producer for delivery-derived symptom state, so "zero
		// deliveries" is a real confirmed-empty result, unlike
		// acute_finding's unwired-reader nil case below.
		status = model.FactConfirmedEmpty
	}
	return model.Fact{
		ID:           factIdentity(factKindSourceLifecycleSummary, situationID, inputVersion, sourceLifecycleSummarySubject),
		SituationID:  situationID,
		Kind:         factKindSourceLifecycleSummary,
		Subject:      sourceLifecycleSummarySubject,
		Digest:       canonicalDigest(value),
		InputVersion: inputVersion,
		Value:        mustMarshal(value),
		ResultStatus: status,
		Material:     true,
		ObservedAt:   now,
	}
}

// ---- current_duration ----

type currentDurationFactValue struct {
	Class              string    `json:"class"`
	ThresholdCrossedAt time.Time `json:"threshold_crossed_at"`
}

func deriveDurationFact(in SnapshotInput, class string) model.Fact {
	crossedAt := in.Situation.EffectiveStartedAt.Add(durationClassLowerBound(class))
	value := currentDurationFactValue{Class: class, ThresholdCrossedAt: crossedAt}
	return model.Fact{
		ID:           factIdentity(durationFactIDPrefix, in.Situation.ID, in.Situation.InputVersion, class),
		SituationID:  in.Situation.ID,
		Kind:         factKindCurrentDuration,
		Subject:      class,
		Digest:       canonicalDigest(value),
		InputVersion: in.Situation.InputVersion,
		Value:        mustMarshal(value),
		ResultStatus: model.FactConfirmedValue,
		Material:     true,
		ObservedAt:   in.Now,
	}
}

// ---- incident_membership ----

type incidentMembershipFactValue struct {
	IncidentID          string `json:"incident_id"`
	MembershipDigest    string `json:"membership_digest"`
	IncidentInputDigest string `json:"incident_input_digest"`
	MemberCount         int    `json:"member_count"`
}

func deriveIncidentMembershipFacts(in SnapshotInput) []model.Fact {
	facts := make([]model.Fact, 0, len(in.Incidents))
	for _, inc := range in.Incidents {
		memberCount := 0
		for _, d := range in.Deliveries {
			if d.IncidentID == inc.ID {
				memberCount++
			}
		}
		value := incidentMembershipFactValue{
			IncidentID:          inc.ID,
			MembershipDigest:    MembershipDigest(inc.ID, in.Deliveries),
			IncidentInputDigest: IncidentInputDigest(inc.ID, inc.GroupKey, in.Deliveries),
			MemberCount:         memberCount,
		}
		facts = append(facts, model.Fact{
			ID:           factIdentity(factKindIncidentMembership, in.Situation.ID, in.Situation.InputVersion, inc.ID),
			SituationID:  in.Situation.ID,
			Kind:         factKindIncidentMembership,
			Subject:      inc.ID,
			Digest:       canonicalDigest(value),
			InputVersion: in.Situation.InputVersion,
			Value:        mustMarshal(value),
			ResultStatus: model.FactConfirmedValue,
			Material:     true,
			ObservedAt:   in.Now,
		})
	}
	return facts
}

// ---- incident_triage_state ----

type incidentTriageStateFactValue struct {
	IncidentID     string  `json:"incident_id"`
	Phase          string  `json:"phase"`
	Attempts       int     `json:"attempts"`
	Decision       *string `json:"decision"`
	DecisionReason *string `json:"decision_reason"`
}

func deriveIncidentTriageStateFacts(situationID string, inputVersion int, now time.Time, incidents []IncidentState) []model.Fact {
	facts := make([]model.Fact, 0, len(incidents))
	for _, inc := range incidents {
		value := incidentTriageStateFactValue{
			IncidentID: inc.ID, Phase: inc.Triage.Phase, Attempts: inc.Triage.Attempts,
			Decision: inc.Triage.Decision, DecisionReason: inc.Triage.DecisionReason,
		}
		status := model.FactConfirmedValue
		if inc.Triage.Phase == "" {
			status = model.FactUnavailable
		}
		digest := canonicalDigest(value)
		facts = append(facts, model.Fact{
			// factIdentityWithContent, not plain factIdentity: see its own
			// doc comment — this fact's content (Phase/Attempts/Decision)
			// legitimately advances within one unchanged input_version.
			ID:           factIdentityWithContent(factKindIncidentTriageState, situationID, inputVersion, inc.ID, digest),
			SituationID:  situationID,
			Kind:         factKindIncidentTriageState,
			Subject:      inc.ID,
			Digest:       digest,
			InputVersion: inputVersion,
			Value:        mustMarshal(value),
			ResultStatus: status,
			// Non-material: scheduling phase/attempts/decision metadata is
			// evidence-free machinery (akin to "retry counters without
			// evidence meaning"), not decision-relevant evidence — see
			// MaterialFactHash's doc comment.
			Material:   false,
			ObservedAt: now,
		})
	}
	return facts
}

// ---- acute_finding ----

type acuteFindingFactValue struct {
	IncidentID         string  `json:"incident_id"`
	ResultCode         *string `json:"result_code"`
	OutputDigest       *string `json:"output_digest"`
	FindingID          *string `json:"finding_id"`
	EvidencePackDigest *string `json:"evidence_pack_digest"`
}

func deriveAcuteFindingFacts(situationID string, inputVersion int, now time.Time, incidents []IncidentState) []model.Fact {
	facts := make([]model.Fact, 0, len(incidents))
	for _, inc := range incidents {
		value := acuteFindingFactValue{IncidentID: inc.ID}
		status := model.FactUnavailable
		if la := inc.Triage.LatestAttempt; la != nil {
			rc, od := la.ResultCode, la.OutputDigest
			value.ResultCode = &rc
			value.OutputDigest = &od
			value.FindingID = la.FindingID
			value.EvidencePackDigest = la.EvidencePackDigest
			status = model.FactConfirmedValue
		}
		digest := canonicalDigest(value)
		facts = append(facts, model.Fact{
			// factIdentityWithContent, not plain factIdentity: see its own
			// doc comment — LatestAttempt can advance (nil -> a completed
			// attempt's ResultCode/OutputDigest/FindingID) within one
			// unchanged input_version, independent of any controller commit.
			ID:           factIdentityWithContent(factKindAcuteFinding, situationID, inputVersion, inc.ID, digest),
			SituationID:  situationID,
			Kind:         factKindAcuteFinding,
			Subject:      inc.ID,
			Digest:       digest,
			InputVersion: inputVersion,
			Value:        mustMarshal(value),
			ResultStatus: status,
			Material:     true,
			ObservedAt:   now,
		})
	}
	return facts
}

// ---- prior_situation_duration_distribution ----

type priorDurationDistributionFactValue struct {
	GroupKey         string    `json:"group_key"`
	SampleCount      int       `json:"sample_count"`
	MedianSeconds    float64   `json:"median_seconds"`
	P95Seconds       float64   `json:"p95_seconds"`
	DurationsSeconds []float64 `json:"durations_seconds"`
}

func derivePriorSituationDurationDistributionFact(in SnapshotInput) model.Fact {
	durations := priorDurationsSeconds(in.PriorSituations)
	value := priorDurationDistributionFactValue{
		GroupKey:         in.Situation.GroupKey,
		SampleCount:      len(durations),
		MedianSeconds:    median(durations),
		P95Seconds:       p95NearestRank(durations),
		DurationsSeconds: durations,
	}
	status := model.FactConfirmedValue
	if len(durations) == 0 {
		// A durable, already-queried zero (loadPriorTerminalSituationsTx
		// really did find no prior terminal Situations in this exact-group
		// lineage) — a real confirmed-empty result, not an unsupported
		// capability.
		status = model.FactConfirmedEmpty
	}
	return model.Fact{
		ID:           factIdentity(factKindPriorSituationDurationDistribution, in.Situation.ID, in.Situation.InputVersion, in.Situation.GroupKey),
		SituationID:  in.Situation.ID,
		Kind:         factKindPriorSituationDurationDistribution,
		Subject:      in.Situation.GroupKey,
		Digest:       canonicalDigest(value),
		InputVersion: in.Situation.InputVersion,
		Value:        mustMarshal(value),
		ResultStatus: status,
		EvidenceRefs: sortedRefs(priorSituationIDs(in.PriorSituations)),
		Material:     true,
		ObservedAt:   in.Now,
	}
}

func priorSituationIDs(prior []CompletedSituation) []string {
	out := make([]string, 0, len(prior))
	for _, p := range prior {
		out = append(out, p.ID)
	}
	return out
}

// priorDurationsSeconds reduces prior to each valid completed Situation's
// elapsed duration in seconds, sorted ascending — deterministic regardless
// of prior's row order. A row with a zero TerminalAt/EffectiveStartedAt or
// a negative computed duration (defensive only; store reads should never
// produce this) is skipped rather than corrupting the distribution.
func priorDurationsSeconds(prior []CompletedSituation) []float64 {
	out := make([]float64, 0, len(prior))
	for _, p := range prior {
		if p.TerminalAt.IsZero() || p.EffectiveStartedAt.IsZero() {
			continue
		}
		d := p.TerminalAt.Sub(p.EffectiveStartedAt)
		if d < 0 {
			continue
		}
		out = append(out, d.Seconds())
	}
	sort.Float64s(out)
	return out
}

// median returns the middle value of sorted (already ascending), averaging
// the two middle values for an even-length input. Returns 0 for an empty
// input.
func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// p95NearestRank returns the 95th percentile of sorted (already ascending)
// using the nearest-rank method: rank = ceil(0.95*n), 1-indexed, clamped to
// [1,n]. This is a simple, deterministic, documented method — no external
// statistics library is needed for a fixed percentile over a small sample.
func p95NearestRank(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(math.Ceil(0.95 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// ---- capability_limitation ----

type capabilityLimitationFactValue struct {
	Limitations []model.Limitation `json:"limitations"`
}

func deriveCapabilityLimitationFact(situationID string, inputVersion int, now time.Time) model.Fact {
	value := capabilityLimitationFactValue{Limitations: append([]model.Limitation(nil), plan2UnsupportedCapabilities...)}
	return model.Fact{
		ID:           factIdentity(factKindCapabilityLimitation, situationID, inputVersion, capabilityLimitationSubject),
		SituationID:  situationID,
		Kind:         factKindCapabilityLimitation,
		Subject:      capabilityLimitationSubject,
		Digest:       canonicalDigest(value),
		InputVersion: inputVersion,
		Value:        mustMarshal(value),
		// Never confirmed_empty: these capabilities are not absent from a
		// real query result, they simply have no Plan 2 producer at all —
		// spec: "Their absence is represented as unsupported capability
		// when relevant; it is never represented as confirmed empty,
		// healthy, or fetched."
		ResultStatus: model.FactUnavailable,
		Material:     true,
		ObservedAt:   now,
	}
}

// ----------------------------------------------------------------------
// MaterialFactHash / AssessmentBasisHash
// ----------------------------------------------------------------------

type materialSymptomDTO struct {
	Key    string `json:"key"`
	Status string `json:"status"`
}

type materialIncidentDTO struct {
	IncidentID         string  `json:"incident_id"`
	MembershipDigest   string  `json:"membership_digest"`
	TriageOutcomeClass *string `json:"triage_outcome_class"`
	// TriageOutputDigest is LatestAttempt.OutputDigest — the normalized
	// Finding *content* digest, present whenever LatestAttempt is (see
	// acute_finding's OutputDigest field for the same source). spec.md's
	// material-hash inclusion list is plural — "normalized Acute Triage
	// outcome classes and evidence digests" — and the acute_finding fact
	// already carries both OutputDigest and FindingID; the hash previously
	// carried neither, so a second Triage attempt with the same result_code
	// and evidence_pack_digest but a materially different Finding hashed
	// identically to the first. FindingID (the Finding row's own opaque
	// storage identity) is deliberately NOT included here: it is not itself
	// decision-relevant content — two attempts producing byte-identical
	// output under two different FindingIDs (e.g. a replay that re-persists
	// the same content) should reuse, not manufacture a spurious material
	// change. OutputDigest is the actual content signal; FindingID is a
	// storage pointer to it.
	TriageOutputDigest   *string `json:"triage_output_digest"`
	TriageEvidenceDigest *string `json:"triage_evidence_digest"`
}

type materialDurationHistogramDTO struct {
	Subminute   int `json:"subminute"`
	Short       int `json:"short"`
	Medium      int `json:"medium"`
	Long        int `json:"long"`
	SampleCount int `json:"sample_count"`
}

func priorDurationHistogram(durationsSeconds []float64) materialDurationHistogramDTO {
	h := materialDurationHistogramDTO{SampleCount: len(durationsSeconds)}
	for _, s := range durationsSeconds {
		switch DurationClass(time.Duration(s * float64(time.Second))) {
		case DurationClassSubminute:
			h.Subminute++
		case DurationClassShort:
			h.Short++
		case DurationClassMedium:
			h.Medium++
		case DurationClassLong:
			h.Long++
		}
	}
	return h
}

type materialFactHashDTO struct {
	SchemaVersion              int                          `json:"schema_version"`
	FactSchemaVersion          int                          `json:"fact_schema_version"`
	SituationID                string                       `json:"situation_id"`
	DurationClass              string                       `json:"duration_class"`
	DurationThresholdCrossedAt time.Time                    `json:"duration_threshold_crossed_at"`
	Symptoms                   []materialSymptomDTO         `json:"symptoms"`
	Incidents                  []materialIncidentDTO        `json:"incidents"`
	PriorDurationHistogram     materialDurationHistogramDTO `json:"prior_duration_histogram"`
	LimitationCodes            []string                     `json:"limitation_codes"`
}

// MaterialFactHash hashes only the evidence spec.md's "Material fact hash
// and Assessment basis" section names as decision-relevant: active symptom
// identity/lifecycle, duration class and threshold-crossing time, per-
// Incident membership, normalized Acute Triage outcome class, output digest,
// and evidence digest, comparable historical duration classes, typed
// evidence limitations, and fact producer/schema versions. It deliberately
// excludes exact elapsed seconds, raw payloads/prose, retry/lease/claim
// state, Triage scheduling phase/attempts/decision metadata (evidence-free
// machinery, not evidence), and Slack metadata — none of which reach this
// function's DTO construction, since this function only ever reads the
// specific fields it curates below rather than hashing SnapshotInput
// wholesale.
//
// Deliberately excludes Situation.InputVersion itself, too: InputVersion
// increments on every applied Situation input (every delivery correlation,
// every Triage outcome, every controller commit), so a hash meant to answer
// "did anything MATERIAL change" must not itself contain the one ingredient
// that changes on every reconciliation by definition — otherwise the hash
// could never equal itself across two input versions of the same Situation
// even when nothing material changed, defeating the whole reuse guarantee
// this function exists to serve. SituationID is kept (it does not change
// across a Situation's own input versions, and is useful defense-in-depth
// against hash collisions across unrelated Situations).
//
// Per-Incident materiality is MembershipDigest alone — WHICH Alerts belong
// to the Incident — not the full IncidentInputDigest (which is, by design,
// delivery-level granular: sorted immutable delivery identities, payload
// digests, lifecycle, and source times, for Acute Triage's input-coverage
// matching, a different question). Embedding the full IncidentInputDigest
// here would mean every routine Alertmanager re-send of an already-known
// Alert (a new immutable alert_deliveries row, same AlertID) still changes
// this hash — reintroducing, one level up, the exact class of problem the
// round-1 MembershipDigest fix solved for Delivery identity itself.
func MaterialFactHash(in SnapshotInput, symptoms []Symptom, durationClass string) string {
	symptomDTOs := make([]materialSymptomDTO, 0, len(symptoms))
	for _, s := range symptoms {
		symptomDTOs = append(symptomDTOs, materialSymptomDTO{Key: s.Key, Status: string(s.Status)})
	}
	sort.Slice(symptomDTOs, func(i, j int) bool { return symptomDTOs[i].Key < symptomDTOs[j].Key })

	incidentDTOs := make([]materialIncidentDTO, 0, len(in.Incidents))
	for _, inc := range in.Incidents {
		d := materialIncidentDTO{
			IncidentID:       inc.ID,
			MembershipDigest: MembershipDigest(inc.ID, in.Deliveries),
		}
		if la := inc.Triage.LatestAttempt; la != nil {
			rc := la.ResultCode
			d.TriageOutcomeClass = &rc
			od := la.OutputDigest
			d.TriageOutputDigest = &od
			if la.EvidencePackDigest != nil {
				ed := *la.EvidencePackDigest
				d.TriageEvidenceDigest = &ed
			}
		}
		incidentDTOs = append(incidentDTOs, d)
	}
	sort.Slice(incidentDTOs, func(i, j int) bool { return incidentDTOs[i].IncidentID < incidentDTOs[j].IncidentID })

	limitationCodes := make([]string, 0, len(plan2UnsupportedCapabilities))
	for _, l := range plan2UnsupportedCapabilities {
		limitationCodes = append(limitationCodes, l.Code)
	}
	sort.Strings(limitationCodes)

	dto := materialFactHashDTO{
		SchemaVersion:              materialFactHashSchemaVersion,
		FactSchemaVersion:          factSchemaVersion,
		SituationID:                in.Situation.ID,
		DurationClass:              durationClass,
		DurationThresholdCrossedAt: in.Situation.EffectiveStartedAt.Add(durationClassLowerBound(durationClass)),
		Symptoms:                   symptomDTOs,
		Incidents:                  incidentDTOs,
		PriorDurationHistogram:     priorDurationHistogram(priorDurationsSeconds(in.PriorSituations)),
		LimitationCodes:            limitationCodes,
	}
	return canonicalDigest(dto)
}

// assessmentBasisReasonDTO deliberately omits ReasonCandidate.ID — Task 5's
// carried-forward-gap fix. reasonCandidateID (reasons.go) hashes
// {SchemaVersion, SituationID, InputVersion, Code, CatalogVersion,
// PredicateVersion, DeterministicFloor, EvidenceRefs}: it still includes
// InputVersion (and, through EvidenceRefs, fact IDs that are themselves
// input-version-scoped via factIdentity), so for ANY Snapshot with at least
// one eligible reason candidate — exactly the interesting cases,
// critical_anchor or duration_outlier firing — the candidate's own ID
// differs on every single input version even when nothing material actually
// changed. Hashing that ID here would mean AssessmentBasisHash could never
// equal itself across two input versions whenever a reason is eligible,
// defeating RevalidateReuse's entire purpose in exactly the cases reuse
// matters most (Task 4's MaterialFactHash already fixed the identical class
// of bug for itself, across two rounds; this is the one place it survived).
//
// The fix hashes each candidate's stable semantic identity instead — Code,
// CatalogVersion, PredicateVersion, and its own DeterministicFloor — which is
// exactly what changes when the catalog or a predicate's proven result
// actually changes, and nothing else. This does not silently drop
// EvidenceRefs from the reuse guard: the material facts a candidate's
// evidence cites are already covered by MaterialFactHash (embedded in
// assessmentBasisHashDTO below), which changes whenever the underlying
// symptom/duration/membership/Triage-outcome content a candidate depends on
// actually changes. Including the candidate's own versioned evidence-ref ID
// strings here on top of that would only reintroduce the same input-version
// churn one level down (those ref strings bake in input_version via
// factIdentity too) without adding any real reuse-safety signal
// MaterialFactHash doesn't already provide — the identical reasoning
// MaterialFactHash's own doc comment gives for why per-Incident materiality
// is MembershipDigest alone, not the delivery-level IncidentInputDigest.
//
// This is a legitimate reading of spec.md's "eligible Sufficient-reason IDs
// and their catalog/predicate versions": spec's own stated intent (the
// "Assessment reuse across input versions" section) is that reuse across
// input versions must be POSSIBLE when nothing material changed — a literal
// ID inclusion would make it impossible whenever a reason is eligible, which
// cannot be what "IDs" was meant to require. See the Task 5 report for the
// full accounting of the alternatives considered.
type assessmentBasisReasonDTO struct {
	Code               string `json:"code"`
	CatalogVersion     int    `json:"catalog_version"`
	PredicateVersion   int    `json:"predicate_version"`
	DeterministicFloor bool   `json:"deterministic_floor"`
}

type assessmentBasisHashDTO struct {
	SchemaVersion           int                        `json:"schema_version"`
	MaterialFactHash        string                     `json:"material_fact_hash"`
	EligibleReasons         []assessmentBasisReasonDTO `json:"eligible_reasons"`
	Lifecycle               string                     `json:"lifecycle"`
	Attention               string                     `json:"attention"`
	DeterministicFloor      bool                       `json:"deterministic_floor"`
	AssessmentSchemaVersion int                        `json:"assessment_schema_version"`
	ValidatorVersion        int                        `json:"validator_version"`
}

// AssessmentBasisHash hashes materialFactHash plus the broader reuse-guard
// content spec.md names: eligible-reason identity (code, catalog/predicate
// version, and own deterministic-floor result — see assessmentBasisReasonDTO
// for why this is the candidates' stable semantic identity rather than their
// input-version-scoped opaque ID), relevant controller-owned
// lifecycle/Attention state, whether a deterministic urgent floor is
// currently active, and Assessment schema/validator versions.
func AssessmentBasisHash(in SnapshotInput, materialFactHash string, eligible []model.ReasonCandidate) string {
	reasons := make([]assessmentBasisReasonDTO, 0, len(eligible))
	floor := false
	for _, r := range eligible {
		reasons = append(reasons, assessmentBasisReasonDTO{
			Code: r.Code, CatalogVersion: r.CatalogVersion, PredicateVersion: r.PredicateVersion,
			DeterministicFloor: r.DeterministicFloor,
		})
		if r.DeterministicFloor {
			floor = true
		}
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Code < reasons[j].Code })

	dto := assessmentBasisHashDTO{
		SchemaVersion:           assessmentBasisHashSchemaVersion,
		MaterialFactHash:        materialFactHash,
		EligibleReasons:         reasons,
		Lifecycle:               string(in.Situation.Lifecycle),
		Attention:               string(in.Situation.Attention),
		DeterministicFloor:      floor,
		AssessmentSchemaVersion: model.AssessmentSchemaVersion,
		ValidatorVersion:        assessmentValidatorVersion,
	}
	return canonicalDigest(dto)
}

// ----------------------------------------------------------------------
// Canonical JSON / digest helpers shared by facts.go, incident_digest.go,
// and reasons.go.
// ----------------------------------------------------------------------

// mustMarshal marshals v — always one of this package's own closed DTOs,
// never user-controlled content — into json.RawMessage. A marshal failure
// here means a DTO stopped being marshalable (a func/chan field, or a
// cycle), which is a programming-time invariant violation, not a runtime
// data condition this pure package can meaningfully recover from.
func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("situation: marshal invariant violated: %v", err))
	}
	return b
}

// canonicalDigest returns the "sha256:<hex>" digest of v's canonical JSON
// encoding. Every hash DTO in this package is a plain struct (never a map)
// with fixed field order, so encoding/json's struct marshaling is already
// canonical and independent of any caller-side ordering.
func canonicalDigest(v any) string {
	sum := sha256.Sum256(mustMarshal(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}
