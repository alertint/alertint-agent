// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

const SnapshotSchemaVersion = 1

// Delivery is the immutable delivery subset consumed by deterministic
// reduction. Payload bodies and presentation metadata are intentionally absent.
type Delivery struct {
	ID               string                `json:"id"`
	IncidentID       string                `json:"incident_id"`
	StableSymptomID  string                `json:"stable_symptom_id"`
	Source           string                `json:"source,omitempty"`
	TriggerVersion   string                `json:"trigger_version,omitempty"`
	ProfileSignature string                `json:"profile_signature,omitempty"`
	ProfileVersion   int                   `json:"profile_version,omitempty"`
	Status           model.DeliveryStatus  `json:"status"`
	Severity         string                `json:"severity,omitempty"`
	SourceStartedAt  *time.Time            `json:"source_started_at,omitempty"`
	StartedAtBasis   model.SourceTimeBasis `json:"started_at_basis"`
	ReceivedAt       time.Time             `json:"received_at"`
	EvidenceRefs     []string              `json:"evidence_refs,omitempty"`
}

type Membership struct {
	IncidentID string `json:"incident_id"`
}

type Symptom struct {
	ID                  string               `json:"id"`
	Source              string               `json:"source,omitempty"`
	TriggerVersion      string               `json:"trigger_version,omitempty"`
	ProfileSignature    string               `json:"profile_signature,omitempty"`
	ProfileVersion      int                  `json:"profile_version,omitempty"`
	Lifecycle           model.DeliveryStatus `json:"lifecycle"`
	Severity            string               `json:"severity,omitempty"`
	Novel               bool                 `json:"novel"`
	EvidenceRefs        []string             `json:"evidence_refs"`
	NoveltyEvidenceRefs []string             `json:"novelty_evidence_refs,omitempty"`
}

type ProfileHead struct {
	SignatureKey string               `json:"signature_key"`
	Version      int                  `json:"version"`
	Profile      profilemodel.Profile `json:"profile"`
}

type CompletedEpisode struct {
	ID              string   `json:"id"`
	DurationSeconds int64    `json:"duration_seconds"`
	Comparable      bool     `json:"comparable"`
	EvidenceRefs    []string `json:"evidence_refs"`
}

type ImpactFact struct {
	Kind         string   `json:"kind"`
	Severity     string   `json:"severity"`
	Confirmed    bool     `json:"confirmed"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type BlastRadius struct {
	Previous       int      `json:"previous"`
	Current        int      `json:"current"`
	UrgentBoundary int      `json:"urgent_boundary"`
	EvidenceRefs   []string `json:"evidence_refs"`
}

type UrgentPolicy struct {
	ID           string   `json:"id"`
	Active       bool     `json:"active"`
	Scoped       bool     `json:"scoped"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type SemanticChoice struct {
	Code         string             `json:"code"`
	State        model.ActionStatus `json:"state"`
	EvidenceRefs []string           `json:"evidence_refs"`
}

type TerminalUncertainty struct {
	DeadlineCrossed bool                 `json:"deadline_crossed"`
	Actionable      bool                 `json:"actionable"`
	Reason          model.TerminalReason `json:"reason"`
	EvidenceRefs    []string             `json:"evidence_refs"`
}

// ConnectorState keeps evidence availability and freshness distinct from a
// confirmed healthy or empty observation.
type ConnectorState struct {
	Capability   observationmodel.Capability   `json:"capability"`
	Status       observationmodel.ResultStatus `json:"status"`
	Freshness    observationmodel.Freshness    `json:"freshness"`
	EvidenceRefs []string                      `json:"evidence_refs"`
}

// L1Output is the bounded acute-investigation input. BuildSnapshot discards
// prose and confidence before constructing the material Snapshot.
type L1Output struct {
	Status          string   `json:"status"`
	Summary         string   `json:"summary,omitempty"`
	RootCauseClass  string   `json:"root_cause_class,omitempty"`
	ConfidenceClass string   `json:"confidence_class,omitempty"`
	FactDigests     []string `json:"fact_digests,omitempty"`
	EvidenceRefs    []string `json:"evidence_refs,omitempty"`
}

// L1Finding is the material normalized subset retained by Snapshot.
type L1Finding struct {
	Status         string   `json:"status"`
	RootCauseClass string   `json:"root_cause_class,omitempty"`
	FactDigests    []string `json:"fact_digests,omitempty"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
}

// JudgmentFact retains steering semantics without audit identity or actor
// attribution metadata.
type JudgmentFact struct {
	CoveredFactHash string              `json:"covered_fact_hash"`
	CoveredSymptoms []string            `json:"covered_symptoms"`
	CoveredImpact   []string            `json:"covered_impact"`
	Judgment        model.JudgmentKind  `json:"judgment"`
	Basis           model.JudgmentBasis `json:"basis"`
	Workload        string              `json:"workload,omitempty"`
	ValidUntil      *time.Time          `json:"valid_until,omitempty"`
	EvidenceRefs    []string            `json:"evidence_refs"`
}

// EnvelopeResult is the material deterministic policy evaluation retained by
// Snapshot. Evaluation attempt identity and presentation time are discarded.
// ScheduleWindowStart/End are the resolved UTC schedule interval a
// configured Schedule condition evaluated against — persisted rather than
// re-derived so a DST-sensitive determination stays independently auditable.
type EnvelopeResult struct {
	EnvelopeID          string                         `json:"envelope_id"`
	EnvelopeVersion     int                            `json:"envelope_version"`
	Result              model.EnvelopeEvaluationResult `json:"result"`
	MatchedFields       []string                       `json:"matched_fields"`
	Violations          []string                       `json:"violations"`
	Observability       []string                       `json:"observability"`
	EvidenceRefs        []string                       `json:"evidence_refs"`
	ScheduleWindowStart *time.Time                     `json:"schedule_window_start,omitempty"`
	ScheduleWindowEnd   *time.Time                     `json:"schedule_window_end,omitempty"`
	QuietingAuthority   bool                           `json:"quieting_authority"`
}

// SnapshotInput is an immutable read model. Callers remain responsible for
// loading it; BuildSnapshot performs no store, connector, model, or Slack I/O.
type SnapshotInput struct {
	Situation                   model.Situation
	Now                         time.Time
	Deliveries                  []Delivery
	Memberships                 []Membership
	Symptoms                    []Symptom
	ProfileHeads                []ProfileHead
	Facts                       []observationmodel.Fact
	Judgments                   []model.Judgment
	Envelope                    *model.EnvelopeEvaluation
	EnvelopeEvidenceRefs        []string
	L1                          *L1Output
	CompletedEpisodes           []CompletedEpisode
	CurrentDurationEvidenceRefs []string
	DurationClass               string
	RecurrenceClass             string
	CrossedMilestones           []string
	Impact                      []ImpactFact
	BlastRadius                 *BlastRadius
	UrgentPolicies              []UrgentPolicy
	SemanticChoice              *SemanticChoice
	TerminalUncertainty         *TerminalUncertainty
	ConnectorStates             []ConnectorState
	Limitations                 []model.Limitation
}

// Snapshot is a detached, canonical, replayable fact view for one exact
// Situation input version.
type Snapshot struct {
	SchemaVersion               int                     `json:"schema_version"`
	SituationID                 string                  `json:"situation_id"`
	InputVersion                int                     `json:"input_version"`
	Lifecycle                   model.Lifecycle         `json:"lifecycle"`
	EffectiveStartedAt          time.Time               `json:"effective_started_at"`
	EffectiveStartedAtBasis     model.SourceTimeBasis   `json:"effective_started_at_basis"`
	FirstReceivedAt             time.Time               `json:"first_received_at"`
	ElapsedSeconds              int64                   `json:"elapsed_seconds"`
	DurationClass               string                  `json:"duration_class"`
	RecurrenceClass             string                  `json:"recurrence_class"`
	CrossedMilestones           []string                `json:"crossed_milestones"`
	IncidentIDs                 []string                `json:"incident_ids"`
	Deliveries                  []Delivery              `json:"deliveries"`
	Symptoms                    []Symptom               `json:"symptoms"`
	ProfileHeads                []ProfileHead           `json:"profile_heads"`
	Facts                       []observationmodel.Fact `json:"facts"`
	Judgments                   []JudgmentFact          `json:"judgments"`
	Envelope                    *EnvelopeResult         `json:"envelope,omitempty"`
	L1                          *L1Finding              `json:"l1,omitempty"`
	CompletedEpisodes           []CompletedEpisode      `json:"completed_episodes"`
	CurrentDurationEvidenceRefs []string                `json:"current_duration_evidence_refs"`
	Impact                      []ImpactFact            `json:"impact"`
	BlastRadius                 *BlastRadius            `json:"blast_radius,omitempty"`
	UrgentPolicies              []UrgentPolicy          `json:"urgent_policies"`
	SemanticChoice              *SemanticChoice         `json:"semantic_choice,omitempty"`
	TerminalUncertainty         *TerminalUncertainty    `json:"terminal_uncertainty,omitempty"`
	ConnectorStates             []ConnectorState        `json:"connector_states"`
	Limitations                 []model.Limitation      `json:"limitations"`
	EligibleReasons             []model.ReasonCandidate `json:"eligible_reasons"`
	MaterialHash                string                  `json:"material_hash"`
}

// BuildSnapshot canonically reduces already-loaded immutable evidence.
func BuildSnapshot(in SnapshotInput) (Snapshot, error) {
	if strings.TrimSpace(in.Situation.ID) == "" || in.Situation.InputVersion <= 0 {
		return Snapshot{}, errors.New("situation: snapshot requires situation id and positive input version")
	}
	if err := validateEffectiveStartProvenance(in.Situation, in.Deliveries); err != nil {
		return Snapshot{}, err
	}
	deliveries := canonicalDeliveries(in.Deliveries)
	effective, firstReceipt, basis := canonicalSituationTimes(in.Situation, deliveries)
	if effective.IsZero() || firstReceipt.IsZero() {
		return Snapshot{}, errors.New("situation: snapshot requires canonical effective start and first receipt")
	}
	facts, err := ReduceFacts(in.Facts)
	if err != nil {
		return Snapshot{}, err
	}
	now := in.Now.UTC()
	if in.Now.IsZero() {
		return Snapshot{}, errors.New("situation: snapshot requires current time")
	}
	elapsed := now.Sub(effective)
	if elapsed < 0 {
		elapsed = 0
	}
	durationClass := strings.TrimSpace(in.DurationClass)
	if durationClass == "" {
		durationClass = classifyDuration(elapsed)
	}
	recurrenceClass := strings.TrimSpace(in.RecurrenceClass)
	if recurrenceClass == "" {
		if len(in.CompletedEpisodes) == 0 {
			recurrenceClass = "first_episode"
		} else {
			recurrenceClass = "recurring"
		}
	}
	snapshot := Snapshot{
		SchemaVersion: SnapshotSchemaVersion, SituationID: in.Situation.ID, InputVersion: in.Situation.InputVersion,
		Lifecycle: in.Situation.Lifecycle, EffectiveStartedAt: effective, EffectiveStartedAtBasis: basis,
		FirstReceivedAt: firstReceipt, ElapsedSeconds: int64(elapsed / time.Second),
		DurationClass: durationClass, RecurrenceClass: recurrenceClass,
		CrossedMilestones: canonicalStrings(in.CrossedMilestones), Deliveries: deliveries,
		Symptoms: canonicalSymptoms(in.Symptoms, deliveries), ProfileHeads: canonicalProfiles(in.ProfileHeads), Facts: facts,
		Judgments: canonicalJudgments(in.Judgments), Envelope: canonicalEnvelope(in.Envelope, in.EnvelopeEvidenceRefs), L1: canonicalL1(in.L1),
		CompletedEpisodes: canonicalEpisodes(in.CompletedEpisodes), CurrentDurationEvidenceRefs: canonicalStrings(in.CurrentDurationEvidenceRefs),
		Impact: canonicalImpact(in.Impact), BlastRadius: canonicalBlastRadius(in.BlastRadius),
		UrgentPolicies: canonicalPolicies(in.UrgentPolicies), SemanticChoice: canonicalSemanticChoice(in.SemanticChoice),
		TerminalUncertainty: canonicalTerminalUncertainty(in.TerminalUncertainty), ConnectorStates: canonicalConnectorStates(in.ConnectorStates),
		Limitations: canonicalLimitations(in.Limitations),
	}
	incidentIDs := make([]string, 0, len(in.Memberships)+len(deliveries))
	for _, membership := range in.Memberships {
		incidentIDs = append(incidentIDs, membership.IncidentID)
	}
	for _, delivery := range deliveries {
		incidentIDs = append(incidentIDs, delivery.IncidentID)
	}
	snapshot.IncidentIDs = canonicalStrings(incidentIDs)
	snapshot.EligibleReasons = EligibleReasons(snapshot)
	snapshot.MaterialHash = MaterialFactHash(snapshot)
	return snapshot, nil
}

func validateEffectiveStartProvenance(situation model.Situation, deliveries []Delivery) error {
	if !situation.EffectiveStartedAt.IsZero() && !validHashBasis(situation.EffectiveStartedAtBasis) {
		return errors.New("situation: snapshot effective start requires source_payload, source_api, receipt_fallback, or mixed provenance")
	}
	for _, delivery := range deliveries {
		contributesStart := delivery.SourceStartedAt != nil ||
			delivery.StartedAtBasis == model.SourceTimeBasisReceiptFallback && !delivery.ReceivedAt.IsZero()
		if contributesStart && !validHashBasis(delivery.StartedAtBasis) {
			return errors.New("situation: snapshot delivery start requires source_payload, source_api, receipt_fallback, or mixed provenance")
		}
	}
	return nil
}

func classifyDuration(elapsed time.Duration) string {
	switch {
	case elapsed < time.Minute:
		return "subminute"
	case elapsed < 15*time.Minute:
		return "short"
	case elapsed < time.Hour:
		return "medium"
	default:
		return "long"
	}
}

func canonicalSituationTimes(situation model.Situation, deliveries []Delivery) (time.Time, time.Time, model.SourceTimeBasis) {
	effective := situation.EffectiveStartedAt.UTC()
	received := situation.FirstReceivedAt.UTC()
	bases := map[model.SourceTimeBasis]struct{}{}
	if validHashBasis(situation.EffectiveStartedAtBasis) {
		bases[situation.EffectiveStartedAtBasis] = struct{}{}
	}
	for _, delivery := range deliveries {
		if !delivery.ReceivedAt.IsZero() && (received.IsZero() || delivery.ReceivedAt.Before(received)) {
			received = delivery.ReceivedAt.UTC()
		}
		started := delivery.SourceStartedAt
		if started == nil && delivery.StartedAtBasis == model.SourceTimeBasisReceiptFallback && !delivery.ReceivedAt.IsZero() {
			started = &delivery.ReceivedAt
		}
		if started != nil {
			if effective.IsZero() || started.Before(effective) {
				effective = started.UTC()
			}
			if validHashBasis(delivery.StartedAtBasis) {
				bases[delivery.StartedAtBasis] = struct{}{}
			}
		}
	}
	basis := situation.EffectiveStartedAtBasis
	if len(bases) > 1 {
		basis = model.SourceTimeBasisMixed
	} else {
		for candidate := range bases {
			basis = candidate
		}
	}
	return effective, received, basis
}

func validHashBasis(basis model.SourceTimeBasis) bool {
	return basis == model.SourceTimeBasisSourcePayload || basis == model.SourceTimeBasisSourceAPI ||
		basis == model.SourceTimeBasisReceiptFallback || basis == model.SourceTimeBasisMixed
}

func canonicalDeliveries(in []Delivery) []Delivery {
	out := make([]Delivery, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].ID = strings.TrimSpace(out[i].ID)
		out[i].IncidentID = strings.TrimSpace(out[i].IncidentID)
		out[i].StableSymptomID = strings.TrimSpace(out[i].StableSymptomID)
		out[i].Severity = strings.ToLower(strings.TrimSpace(out[i].Severity))
		out[i].ReceivedAt = out[i].ReceivedAt.UTC()
		if out[i].SourceStartedAt != nil {
			started := out[i].SourceStartedAt.UTC()
			out[i].SourceStartedAt = &started
		}
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.Before(out[j].ReceivedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func canonicalSymptoms(explicit []Symptom, deliveries []Delivery) []Symptom {
	latest := make(map[string]Delivery)
	for _, delivery := range deliveries {
		if delivery.StableSymptomID == "" {
			continue
		}
		prior, ok := latest[delivery.StableSymptomID]
		if !ok || delivery.ReceivedAt.After(prior.ReceivedAt) || delivery.ReceivedAt.Equal(prior.ReceivedAt) && delivery.ID > prior.ID {
			latest[delivery.StableSymptomID] = delivery
		}
	}
	out := make([]Symptom, 0, len(explicit)+len(latest))
	for _, symptom := range explicit {
		symptom.ID = strings.TrimSpace(symptom.ID)
		symptom.Severity = strings.ToLower(strings.TrimSpace(symptom.Severity))
		symptom.EvidenceRefs = canonicalStrings(symptom.EvidenceRefs)
		symptom.NoveltyEvidenceRefs = canonicalStrings(symptom.NoveltyEvidenceRefs)
		out = append(out, symptom)
	}
	for _, delivery := range latest {
		refs := append([]string(nil), delivery.EvidenceRefs...)
		refs = append(refs, "delivery:"+delivery.ID)
		out = append(out, Symptom{ID: delivery.StableSymptomID, Source: delivery.Source, TriggerVersion: delivery.TriggerVersion,
			ProfileSignature: delivery.ProfileSignature, ProfileVersion: delivery.ProfileVersion, Lifecycle: delivery.Status,
			Severity: delivery.Severity, EvidenceRefs: canonicalStrings(refs)})
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := json.Marshal(out[i])
		right, _ := json.Marshal(out[j])
		return string(left) < string(right)
	})
	return dedupeJSON(out)
}

func canonicalProfiles(in []ProfileHead) []ProfileHead {
	out := append([]ProfileHead(nil), in...)
	for i := range out {
		out[i].Profile.CandidateScope = canonicalStrings(out[i].Profile.CandidateScope)
		out[i].Profile.CompanionSignalKinds = canonicalStrings(out[i].Profile.CompanionSignalKinds)
		out[i].Profile.UsefulCapabilities = canonicalStrings(out[i].Profile.UsefulCapabilities)
		out[i].Profile.Uncertainty = canonicalStrings(out[i].Profile.Uncertainty)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SignatureKey != out[j].SignatureKey {
			return out[i].SignatureKey < out[j].SignatureKey
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func canonicalJudgments(in []model.Judgment) []JudgmentFact {
	out := make([]JudgmentFact, len(in))
	for i := range in {
		out[i] = JudgmentFact{
			CoveredFactHash: in[i].CoveredFactHash,
			CoveredSymptoms: canonicalStrings(in[i].CoveredSymptoms),
			CoveredImpact:   canonicalStrings(in[i].CoveredImpact),
			Judgment:        in[i].Judgment,
			Basis:           in[i].Basis,
			EvidenceRefs:    canonicalStrings(in[i].EvidenceRefs),
		}
		if in[i].Workload != nil {
			out[i].Workload = strings.TrimSpace(*in[i].Workload)
		}
		if in[i].ValidUntil != nil {
			value := in[i].ValidUntil.UTC()
			out[i].ValidUntil = &value
		}
	}
	return canonicalJudgmentFacts(out)
}

func canonicalJudgmentFacts(in []JudgmentFact) []JudgmentFact {
	out := append([]JudgmentFact(nil), in...)
	for i := range out {
		out[i].CoveredSymptoms = canonicalStrings(out[i].CoveredSymptoms)
		out[i].CoveredImpact = canonicalStrings(out[i].CoveredImpact)
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
		out[i].Workload = strings.TrimSpace(out[i].Workload)
		if out[i].ValidUntil != nil {
			value := out[i].ValidUntil.UTC()
			out[i].ValidUntil = &value
		}
	}
	sort.Slice(out, func(i, j int) bool { return canonicalLess(out[i], out[j]) })
	return dedupeJSON(out)
}

func canonicalEnvelope(in *model.EnvelopeEvaluation, evidenceRefs []string) *EnvelopeResult {
	if in == nil {
		return nil
	}
	return &EnvelopeResult{
		EnvelopeID: in.EnvelopeID, EnvelopeVersion: in.EnvelopeVersion, Result: in.Result,
		MatchedFields: canonicalStrings(in.MatchedFields), Violations: canonicalStrings(in.Violations),
		Observability: canonicalStrings(in.Observability), EvidenceRefs: canonicalStrings(evidenceRefs),
		ScheduleWindowStart: canonicalTimePtr(in.ScheduleWindowStart), ScheduleWindowEnd: canonicalTimePtr(in.ScheduleWindowEnd),
		QuietingAuthority: in.QuietingAuthority,
	}
}

func canonicalEnvelopeResult(in *EnvelopeResult) *EnvelopeResult {
	if in == nil {
		return nil
	}
	out := *in
	out.MatchedFields = canonicalStrings(in.MatchedFields)
	out.Violations = canonicalStrings(in.Violations)
	out.Observability = canonicalStrings(in.Observability)
	out.EvidenceRefs = canonicalStrings(in.EvidenceRefs)
	out.ScheduleWindowStart = canonicalTimePtr(in.ScheduleWindowStart)
	out.ScheduleWindowEnd = canonicalTimePtr(in.ScheduleWindowEnd)
	return &out
}

func canonicalTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	value := in.UTC()
	return &value
}

func canonicalL1(in *L1Output) *L1Finding {
	if in == nil {
		return nil
	}
	return &L1Finding{Status: in.Status, RootCauseClass: in.RootCauseClass,
		FactDigests: canonicalStrings(in.FactDigests), EvidenceRefs: canonicalStrings(in.EvidenceRefs)}
}

func canonicalL1Finding(in *L1Finding) *L1Finding {
	if in == nil {
		return nil
	}
	out := *in
	out.FactDigests = canonicalStrings(in.FactDigests)
	out.EvidenceRefs = canonicalStrings(in.EvidenceRefs)
	return &out
}

func canonicalEpisodes(in []CompletedEpisode) []CompletedEpisode {
	out := append([]CompletedEpisode(nil), in...)
	for i := range out {
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DurationSeconds != out[j].DurationSeconds {
			return out[i].DurationSeconds < out[j].DurationSeconds
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func canonicalImpact(in []ImpactFact) []ImpactFact {
	out := append([]ImpactFact(nil), in...)
	for i := range out {
		out[i].Kind = strings.TrimSpace(out[i].Kind)
		out[i].Severity = strings.ToLower(strings.TrimSpace(out[i].Severity))
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := json.Marshal(out[i])
		right, _ := json.Marshal(out[j])
		return string(left) < string(right)
	})
	return dedupeJSON(out)
}

func canonicalBlastRadius(in *BlastRadius) *BlastRadius {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceRefs = canonicalStrings(in.EvidenceRefs)
	return &out
}

func canonicalPolicies(in []UrgentPolicy) []UrgentPolicy {
	out := append([]UrgentPolicy(nil), in...)
	for i := range out {
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool { return canonicalLess(out[i], out[j]) })
	return out
}

func canonicalSemanticChoice(in *SemanticChoice) *SemanticChoice {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceRefs = canonicalStrings(in.EvidenceRefs)
	return &out
}

func canonicalTerminalUncertainty(in *TerminalUncertainty) *TerminalUncertainty {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceRefs = canonicalStrings(in.EvidenceRefs)
	return &out
}

func canonicalConnectorStates(in []ConnectorState) []ConnectorState {
	out := append([]ConnectorState(nil), in...)
	for i := range out {
		out[i].EvidenceRefs = canonicalStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool { return canonicalLess(out[i], out[j]) })
	return out
}

func dedupeJSON[T any](in []T) []T {
	out := make([]T, 0, len(in))
	last := ""
	for _, value := range in {
		raw, _ := json.Marshal(value)
		key := string(raw)
		if len(out) > 0 && key == last {
			continue
		}
		last = key
		out = append(out, value)
	}
	return out
}

func canonicalLess[T any](left, right T) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) < string(rightJSON)
}

// MaterialFactHash hashes only normalized evidence meaning. Snapshot identity,
// exact elapsed seconds, presentation timestamps, and Slack state are omitted.
func MaterialFactHash(snapshot Snapshot) string {
	type materialFact struct {
		Kind             string                        `json:"kind"`
		Subject          string                        `json:"subject"`
		Value            json.RawMessage               `json:"value"`
		SourceCapability observationmodel.Capability   `json:"source_capability"`
		Freshness        observationmodel.Freshness    `json:"freshness"`
		ResultStatus     observationmodel.ResultStatus `json:"result_status"`
		Digest           string                        `json:"digest"`
		EvidenceRefs     []string                      `json:"evidence_refs"`
	}
	facts := make([]materialFact, 0, len(snapshot.Facts))
	for _, fact := range snapshot.Facts {
		if !fact.Material {
			continue
		}
		value, err := canonicalRawJSON(fact.Value)
		if err != nil {
			value = json.RawMessage(`null`)
		}
		facts = append(facts, materialFact{Kind: fact.Kind, Subject: fact.Subject, Value: value, SourceCapability: fact.SourceCapability,
			Freshness: fact.Freshness, ResultStatus: fact.ResultStatus, Digest: fact.Digest, EvidenceRefs: canonicalStrings(fact.EvidenceRefs)})
	}
	sort.Slice(facts, func(i, j int) bool {
		left, _ := json.Marshal(facts[i])
		right, _ := json.Marshal(facts[j])
		return string(left) < string(right)
	})
	type materialReason struct {
		CatalogVersion   int      `json:"catalog_version"`
		PredicateVersion int      `json:"predicate_version"`
		Code             string   `json:"code"`
		PredicateResult  string   `json:"predicate_result"`
		EvidenceRefs     []string `json:"evidence_refs"`
		Floor            bool     `json:"floor"`
	}
	reasons := EligibleReasons(snapshot)
	materialReasons := make([]materialReason, len(reasons))
	for i, reason := range reasons {
		materialReasons[i] = materialReason{reason.CatalogVersion, reason.PredicateVersion, reason.Code,
			reason.PredicateResult, canonicalStrings(reason.EvidenceRefs), reason.DeterministicFloor}
	}
	material := struct {
		SchemaVersion           int                   `json:"schema_version"`
		ReasonCatalogVersion    int                   `json:"reason_catalog_version"`
		ReasonPredicateVersions []string              `json:"reason_predicate_versions"`
		Lifecycle               model.Lifecycle       `json:"lifecycle"`
		StartedAtBasis          model.SourceTimeBasis `json:"started_at_basis"`
		DurationClass           string                `json:"duration_class"`
		RecurrenceClass         string                `json:"recurrence_class"`
		CrossedMilestones       []string              `json:"crossed_milestones"`
		Symptoms                []Symptom             `json:"symptoms"`
		ProfileHeads            []ProfileHead         `json:"profile_heads"`
		Facts                   []materialFact        `json:"facts"`
		Judgments               []JudgmentFact        `json:"judgments"`
		Envelope                *EnvelopeResult       `json:"envelope,omitempty"`
		L1                      *L1Finding            `json:"l1,omitempty"`
		Impact                  []ImpactFact          `json:"impact"`
		BlastRadius             *BlastRadius          `json:"blast_radius,omitempty"`
		UrgentPolicies          []UrgentPolicy        `json:"urgent_policies"`
		SemanticChoice          *SemanticChoice       `json:"semantic_choice,omitempty"`
		TerminalUncertainty     *TerminalUncertainty  `json:"terminal_uncertainty,omitempty"`
		ConnectorStates         []ConnectorState      `json:"connector_states"`
		Limitations             []model.Limitation    `json:"limitations"`
		Reasons                 []materialReason      `json:"reasons"`
	}{
		SnapshotSchemaVersion, ReasonCatalogVersion, canonicalPredicateVersions(), snapshot.Lifecycle, snapshot.EffectiveStartedAtBasis,
		strings.TrimSpace(snapshot.DurationClass), strings.TrimSpace(snapshot.RecurrenceClass), canonicalStrings(snapshot.CrossedMilestones),
		canonicalSymptoms(snapshot.Symptoms, nil), canonicalProfiles(snapshot.ProfileHeads), facts,
		canonicalJudgmentFacts(snapshot.Judgments), canonicalEnvelopeResult(snapshot.Envelope), canonicalL1Finding(snapshot.L1), canonicalImpact(snapshot.Impact),
		canonicalBlastRadius(snapshot.BlastRadius), canonicalPolicies(snapshot.UrgentPolicies), canonicalSemanticChoice(snapshot.SemanticChoice),
		canonicalTerminalUncertainty(snapshot.TerminalUncertainty), canonicalConnectorStates(snapshot.ConnectorStates),
		canonicalLimitations(snapshot.Limitations), materialReasons,
	}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
