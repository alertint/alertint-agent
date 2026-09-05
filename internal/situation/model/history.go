// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bounded lengths for the free-text and array fields this file defines.
// These mirror the sizing already used elsewhere for similar fields
// (internal/situation's maxBoundedTextLength = 2000) rather than inventing
// new conventions: a short rendered line, a longer bounded detail/summary,
// a generous identifier/coordinate bound, and a bounded reference count.
const (
	// maxJournalHeadlineLength bounds JournalData.Headline — a short,
	// rendered-facing summary line, never free-form prose.
	maxJournalHeadlineLength = 200
	// maxJournalDetailLength bounds JournalData.Detail and every other
	// bounded free-text field a Transition or NotificationIntent carries
	// (e.g. AssessmentConclusion.SufficientReasonSummary).
	maxJournalDetailLength = 2000
	// maxIdentifierLength bounds every identifier/coordinate-shaped string
	// field (IDs, idempotency/client-message keys, Slack channel/message
	// coordinates, error classes) — generous for any UUID or Slack ID shape
	// without being unbounded.
	maxIdentifierLength = 200
	// maxEvidenceRefs bounds how many evidence references a single
	// Transition may cite.
	maxEvidenceRefs = 50
)

// requireUTC reports an error unless t carries the UTC location. Every
// timestamp this package persists is normalized to UTC before storage
// (internal/store consistently calls time.Now().UTC()), so a non-UTC value
// signals the value never round-tripped through the store. field names just
// the JSON field (e.g. "created_at") — callers add their own "<type>: " scope
// when wrapping, matching the rest of this package's convention of a bare
// type-name prefix (e.g. "action_contract: ...") on hand-rolled errors.
func requireUTC(field string, t time.Time) error {
	if t.Location() != time.UTC {
		return fmt.Errorf("%s: must be UTC, got location %s", field, t.Location())
	}
	return nil
}

// requireNonZeroUTC reports an error unless t is both set and UTC.
func requireNonZeroUTC(field string, t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("%s: is required", field)
	}
	return requireUTC(field, t)
}

// ----------------------------------------------------------------------
// Interruption priority
// ----------------------------------------------------------------------

// InterruptionPriority is the controller-derived, deterministic priority
// that governs whether a Transition may create a new main-channel poke. It
// is never Alert severity or model-authored severity (spec.md "Publication
// authority and Interruption priority").
type InterruptionPriority string

const (
	InterruptionLow      InterruptionPriority = "low"
	InterruptionMedium   InterruptionPriority = "medium"
	InterruptionHigh     InterruptionPriority = "high"
	InterruptionCritical InterruptionPriority = "critical"
)

// Validate reports an error unless p is one of the closed InterruptionPriority
// values.
func (p InterruptionPriority) Validate() error {
	return validateEnum("interruption_priority", p,
		InterruptionLow, InterruptionMedium, InterruptionHigh, InterruptionCritical)
}

// rank returns p's position in the deterministic low < medium < high <
// critical ranking, or -1 for an unknown value.
func (p InterruptionPriority) rank() int {
	switch p {
	case InterruptionLow:
		return 0
	case InterruptionMedium:
		return 1
	case InterruptionHigh:
		return 2
	case InterruptionCritical:
		return 3
	default:
		return -1
	}
}

// Less reports whether p ranks strictly below other in the deterministic
// low < medium < high < critical ranking.
func (p InterruptionPriority) Less(other InterruptionPriority) bool {
	return p.rank() < other.rank()
}

// ----------------------------------------------------------------------
// Transition reason, actor, journal kind
// ----------------------------------------------------------------------

// TransitionReason is the closed reason recorded on one immutable
// Transition: exactly which material-change catalog entry produced it.
type TransitionReason string

const (
	ReasonFirstAuthoritativeState   TransitionReason = "first_authoritative_state"
	ReasonMaterialAssessmentChanged TransitionReason = "material_assessment_changed"
	ReasonAttentionChanged          TransitionReason = "attention_changed"
	ReasonOperatorContractChanged   TransitionReason = "operator_contract_changed"
	ReasonInvestigationStarted      TransitionReason = "investigation_started"
	ReasonInvestigationConcluded    TransitionReason = "investigation_concluded"
	ReasonRecoveryObserved          TransitionReason = "recovery_observed"
	ReasonRecoveryFailed            TransitionReason = "recovery_failed"
	ReasonRecovered                 TransitionReason = "recovered"
	ReasonClosedUnknown             TransitionReason = "closed_unknown"
	ReasonRecurrenceMilestone       TransitionReason = "recurrence_milestone"
	ReasonTriageStateChanged        TransitionReason = "triage_state_changed"
	ReasonOperatorArtifactRecorded  TransitionReason = "operator_artifact_recorded"
)

// Validate reports an error unless r is one of the closed TransitionReason
// values.
func (r TransitionReason) Validate() error {
	return validateEnum("transition_reason", r,
		ReasonFirstAuthoritativeState, ReasonMaterialAssessmentChanged, ReasonAttentionChanged,
		ReasonOperatorContractChanged, ReasonInvestigationStarted, ReasonInvestigationConcluded,
		ReasonRecoveryObserved, ReasonRecoveryFailed, ReasonRecovered, ReasonClosedUnknown,
		ReasonRecurrenceMilestone, ReasonTriageStateChanged, ReasonOperatorArtifactRecorded)
}

// TransitionActor is the closed authority that produced one Transition.
type TransitionActor string

const (
	ActorDeterministicController TransitionActor = "deterministic_controller"
	ActorLLM                     TransitionActor = "llm"
	ActorAttributedOperator      TransitionActor = "attributed_operator"
	// ActorOperatorPolicy is a defined value reserved for Plan 5's operator
	// policy authority. Plan 3 cannot produce it — Validate rejects it
	// unconditionally (spec.md "Domain model": "Plan 3 cannot produce
	// operator_policy; the value is reserved for Plan 5 and rejected unless
	// an attributed policy artifact exists").
	ActorOperatorPolicy TransitionActor = "operator_policy"
)

// Validate reports an error unless a is one of the three Transition actors
// Plan 3 may produce: deterministic_controller, llm, or attributed_operator.
// ActorOperatorPolicy is a defined constant for a later plan and is always
// rejected here.
func (a TransitionActor) Validate() error {
	return validateEnum("transition_actor", a,
		ActorDeterministicController, ActorLLM, ActorAttributedOperator)
}

// JournalKind is the closed shape of the immutable journal-render data a
// Transition carries, or JournalNone when the Transition creates no
// journal entry.
type JournalKind string

const (
	JournalNone                    JournalKind = "none"
	JournalPublication             JournalKind = "publication"
	JournalInvestigationStarted    JournalKind = "investigation_started"
	JournalInvestigationChanged    JournalKind = "investigation_changed"
	JournalEvidenceConclusion      JournalKind = "evidence_conclusion"
	JournalOperatorContractChanged JournalKind = "operator_contract_changed"
	JournalRecoveryPending         JournalKind = "recovery_pending"
	JournalRecoveryRefired         JournalKind = "recovery_refired"
	JournalRecurrenceMilestone     JournalKind = "recurrence_milestone"
	JournalRecovered               JournalKind = "recovered"
	JournalClosedUnknown           JournalKind = "closed_unknown"
	JournalOperatorNote            JournalKind = "operator_note"
	JournalCapturedVerdict         JournalKind = "captured_verdict"
)

// Validate reports an error unless k is one of the closed JournalKind
// values.
func (k JournalKind) Validate() error {
	return validateEnum("journal_kind", k,
		JournalNone, JournalPublication, JournalInvestigationStarted, JournalInvestigationChanged,
		JournalEvidenceConclusion, JournalOperatorContractChanged, JournalRecoveryPending,
		JournalRecoveryRefired, JournalRecurrenceMilestone, JournalRecovered, JournalClosedUnknown,
		JournalOperatorNote, JournalCapturedVerdict)
}

// JournalData is the bounded, immutable render payload for one Transition's
// journal entry. It never carries unbounded operator-authored prose.
type JournalData struct {
	Headline        string    `json:"headline"`
	Detail          string    `json:"detail,omitempty"`
	AttributedActor string    `json:"attributed_actor,omitempty"`
	ActionStatus    string    `json:"action_status,omitempty"`
	RecurrenceCount int       `json:"recurrence_count,omitempty"`
	Delayed         bool      `json:"delayed,omitempty"`
	NoLongerCurrent bool      `json:"no_longer_current,omitempty"`
	OccurredAt      time.Time `json:"occurred_at"`
}

// Validate checks JournalData's bounded lengths and its required, UTC
// occurred_at instant.
func (j JournalData) Validate() error {
	if len(j.Headline) > maxJournalHeadlineLength {
		return fmt.Errorf("journal_data: headline exceeds %d bytes", maxJournalHeadlineLength)
	}
	if len(j.Detail) > maxJournalDetailLength {
		return fmt.Errorf("journal_data: detail exceeds %d bytes", maxJournalDetailLength)
	}
	if len(j.AttributedActor) > maxIdentifierLength {
		return fmt.Errorf("journal_data: attributed_actor exceeds %d bytes", maxIdentifierLength)
	}
	if len(j.ActionStatus) > maxIdentifierLength {
		return fmt.Errorf("journal_data: action_status exceeds %d bytes", maxIdentifierLength)
	}
	if j.RecurrenceCount < 0 {
		return errors.New("journal_data: recurrence_count must be >= 0")
	}
	if err := requireNonZeroUTC("occurred_at", j.OccurredAt); err != nil {
		return fmt.Errorf("journal_data: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Assessment conclusion and projection facts (R3)
// ----------------------------------------------------------------------

// AssessmentConclusion is the closed, bounded slice of an authoritative
// Assessment's conclusion a Transition's ProjectionFacts may carry: closed
// judgment codes plus the bounded Sufficient-reason summary, never the full
// Assessment.
type AssessmentConclusion struct {
	Persistence             Persistence     `json:"persistence"`
	Impact                  Impact          `json:"impact"`
	Novelty                 Novelty         `json:"novelty"`
	Causality               Causality       `json:"causality"`
	EvidenceQuality         EvidenceQuality `json:"evidence_quality"`
	LimitationCodes         []string        `json:"limitation_codes"`
	SufficientReasonCode    string          `json:"sufficient_reason_code,omitempty"`
	SufficientReasonSummary string          `json:"sufficient_reason_summary,omitempty"`
}

// MarshalJSON canonicalizes LimitationCodes to [] before marshaling: a
// nil-constructed AssessmentConclusion must never serialize
// limitation_codes as JSON null.
func (a AssessmentConclusion) MarshalJSON() ([]byte, error) {
	type assessmentConclusionAlias AssessmentConclusion
	out := assessmentConclusionAlias(a)
	out.LimitationCodes = canonicalizeSlice(out.LimitationCodes)
	return json.Marshal(out)
}

// Validate checks AssessmentConclusion's closed judgment codes and the
// bounded Sufficient-reason summary (ProjectionFacts carries "no prose
// beyond the bounded Sufficient-reason summary").
func (a AssessmentConclusion) Validate() error {
	if err := a.Persistence.Validate(); err != nil {
		return fmt.Errorf("assessment_conclusion: %w", err)
	}
	if err := a.Impact.Validate(); err != nil {
		return fmt.Errorf("assessment_conclusion: %w", err)
	}
	if err := a.Novelty.Validate(); err != nil {
		return fmt.Errorf("assessment_conclusion: %w", err)
	}
	if err := a.Causality.Validate(); err != nil {
		return fmt.Errorf("assessment_conclusion: %w", err)
	}
	if err := a.EvidenceQuality.Validate(); err != nil {
		return fmt.Errorf("assessment_conclusion: %w", err)
	}
	if len(a.SufficientReasonSummary) > maxJournalDetailLength {
		return fmt.Errorf("assessment_conclusion: sufficient_reason_summary exceeds %d bytes", maxJournalDetailLength)
	}
	return nil
}

// ProjectionFacts is the bounded, immutable slice of the coherent claim the
// Episode fold and renderers may read (R3). Closed codes and instants only;
// no prose beyond the bounded Sufficient-reason summary.
type ProjectionFacts struct {
	PublicHandle            *string               `json:"public_handle,omitempty"`
	EffectiveStartedAt      time.Time             `json:"effective_started_at"`
	EffectiveStartedAtBasis SourceTimeBasis       `json:"effective_started_at_basis"`
	RecoveryObservedAt      *time.Time            `json:"recovery_observed_at,omitempty"`
	GraceUntil              *time.Time            `json:"grace_until,omitempty"`
	TerminalAt              *time.Time            `json:"terminal_at,omitempty"`
	TerminalReason          *TerminalReason       `json:"terminal_reason,omitempty"`
	Assessment              *AssessmentConclusion `json:"assessment,omitempty"`
}

// Validate checks ProjectionFacts' required UTC effective_started_at, the
// closed effective_started_at_basis/terminal_reason codes, every other
// captured instant's UTC-ness, the terminal_at/terminal_reason pairing, and
// the nested AssessmentConclusion when present.
func (p ProjectionFacts) Validate() error {
	if p.PublicHandle != nil && strings.TrimSpace(*p.PublicHandle) == "" {
		return errors.New("projection_facts: public_handle must not be empty when set")
	}
	if err := requireNonZeroUTC("effective_started_at", p.EffectiveStartedAt); err != nil {
		return fmt.Errorf("projection_facts: %w", err)
	}
	if err := validateEnum("effective_started_at_basis", p.EffectiveStartedAtBasis,
		SourceTimeBasisSourcePayload, SourceTimeBasisSourceAPI, SourceTimeBasisReceiptFallback,
		SourceTimeBasisMissing, SourceTimeBasisMixed); err != nil {
		return fmt.Errorf("projection_facts: %w", err)
	}
	if p.RecoveryObservedAt != nil {
		if err := requireUTC("recovery_observed_at", *p.RecoveryObservedAt); err != nil {
			return fmt.Errorf("projection_facts: %w", err)
		}
	}
	if p.GraceUntil != nil {
		if err := requireUTC("grace_until", *p.GraceUntil); err != nil {
			return fmt.Errorf("projection_facts: %w", err)
		}
	}
	if p.TerminalAt != nil {
		if err := requireUTC("terminal_at", *p.TerminalAt); err != nil {
			return fmt.Errorf("projection_facts: %w", err)
		}
	}
	switch {
	case p.TerminalAt != nil && p.TerminalReason == nil:
		return errors.New("projection_facts: terminal_at requires terminal_reason")
	case p.TerminalAt == nil && p.TerminalReason != nil:
		return errors.New("projection_facts: terminal_reason requires terminal_at")
	}
	if p.TerminalReason != nil {
		if err := validateEnum("terminal_reason", *p.TerminalReason,
			TerminalReasonObservationDeadline, TerminalReasonResolutionMissing,
			TerminalReasonSourceUnavailable, TerminalReasonBudgetExhausted); err != nil {
			return fmt.Errorf("projection_facts: %w", err)
		}
	}
	if p.Assessment != nil {
		if err := p.Assessment.Validate(); err != nil {
			return fmt.Errorf("projection_facts: %w", err)
		}
	}
	return nil
}

// ----------------------------------------------------------------------
// Transition
// ----------------------------------------------------------------------

// Transition is the immutable record of one authoritative material change
// to a Situation: exactly one controller-state Transition per material
// reconciliation, plus one per newly journaled operator artifact (R1). It
// is never a copy of mutable current state and is never rewritten.
type Transition struct {
	ID                      string                `json:"id"`
	SituationID             string                `json:"situation_id"`
	Sequence                int                   `json:"sequence"`
	InputVersion            int                   `json:"input_version"`
	MaterialFactHash        string                `json:"material_fact_hash"`
	AssessmentID            *string               `json:"assessment_id,omitempty"`
	Lifecycle               Lifecycle             `json:"lifecycle"`
	Attention               Attention             `json:"attention"`
	ActionContract          ActionContract        `json:"action_contract"`
	SufficientReasonID      *string               `json:"sufficient_reason_id,omitempty"`
	InterruptionPriority    *InterruptionPriority `json:"interruption_priority,omitempty"`
	Reason                  TransitionReason      `json:"reason"`
	JournalKind             JournalKind           `json:"journal_kind"`
	Journal                 JournalData           `json:"journal"`
	Projection              ProjectionFacts       `json:"projection"`                           // R3
	OperatorArtifactInputID *string               `json:"operator_artifact_input_id,omitempty"` // R1: the consumed situation_input_outbox row
	EvidenceRefs            []string              `json:"evidence_refs"`
	Actor                   TransitionActor       `json:"actor"`
	Drill                   bool                  `json:"drill,omitempty"`
	CreatedAt               time.Time             `json:"created_at"`
}

// MarshalJSON canonicalizes EvidenceRefs to [] before marshaling: a
// nil-constructed Transition must never serialize evidence_refs as JSON
// null. The nested ActionContract, Journal, and Projection canonicalize
// their own slice fields via their own MarshalJSON methods.
func (t Transition) MarshalJSON() ([]byte, error) {
	type transitionAlias Transition
	a := transitionAlias(t)
	a.EvidenceRefs = canonicalizeSlice(a.EvidenceRefs)
	return json.Marshal(a)
}

// Validate checks Transition's required, bounded identity fields; its
// closed lifecycle/attention/reason/journal-kind/actor codes; the Operator
// contract's shape/consistency against the Transition's own Lifecycle; the
// nested Journal and Projection; the operator_artifact_recorded <->
// OperatorArtifactInputID pairing (R1: required exactly for that reason,
// forbidden otherwise); the evidence-ref bound; and a required, UTC
// created_at. It is a shape/consistency check only — it never compares
// against a wall clock, since a historical Transition's own
// action_contract.next_update_at promise is expected to have long since
// elapsed by the time it is read back.
func (t Transition) Validate() error {
	if strings.TrimSpace(t.ID) == "" {
		return errors.New("transition: id is required")
	}
	if len(t.ID) > maxIdentifierLength {
		return fmt.Errorf("transition: id exceeds %d bytes", maxIdentifierLength)
	}
	if strings.TrimSpace(t.SituationID) == "" {
		return errors.New("transition: situation_id is required")
	}
	if t.Sequence < 1 {
		return fmt.Errorf("transition: sequence must be >= 1, got %d", t.Sequence)
	}
	if t.InputVersion < 1 {
		return fmt.Errorf("transition: input_version must be >= 1, got %d", t.InputVersion)
	}
	if strings.TrimSpace(t.MaterialFactHash) == "" {
		return errors.New("transition: material_fact_hash is required")
	}
	if t.AssessmentID != nil && strings.TrimSpace(*t.AssessmentID) == "" {
		return errors.New("transition: assessment_id must not be empty when set")
	}
	if err := t.Lifecycle.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := t.Attention.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := t.ActionContract.validate(t.Lifecycle.Terminal()); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if t.SufficientReasonID != nil && strings.TrimSpace(*t.SufficientReasonID) == "" {
		return errors.New("transition: sufficient_reason_id must not be empty when set")
	}
	if t.InterruptionPriority != nil {
		if err := t.InterruptionPriority.Validate(); err != nil {
			return fmt.Errorf("transition: %w", err)
		}
	}
	if err := t.Reason.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := t.JournalKind.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := t.Journal.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := t.Projection.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}

	switch {
	case t.Reason == ReasonOperatorArtifactRecorded && t.OperatorArtifactInputID == nil:
		return errors.New("transition: operator_artifact_input_id is required when reason is operator_artifact_recorded")
	case t.Reason != ReasonOperatorArtifactRecorded && t.OperatorArtifactInputID != nil:
		return errors.New("transition: operator_artifact_input_id must be unset unless reason is operator_artifact_recorded")
	}
	if t.OperatorArtifactInputID != nil && strings.TrimSpace(*t.OperatorArtifactInputID) == "" {
		return errors.New("transition: operator_artifact_input_id must not be empty when set")
	}

	if len(t.EvidenceRefs) > maxEvidenceRefs {
		return fmt.Errorf("transition: evidence_refs exceeds %d entries", maxEvidenceRefs)
	}

	if err := t.Actor.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}

	if err := requireNonZeroUTC("created_at", t.CreatedAt); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Episode summary
// ----------------------------------------------------------------------

// EpisodeSummary is the current, versioned Episode-summary projection
// folded from a Situation's Transitions in sequence order — the durable
// content the Situation-owned Slack root renders. Every fold advances
// Version by exactly one.
type EpisodeSummary struct {
	SituationID              string         `json:"situation_id"`
	PublicHandle             string         `json:"public_handle,omitempty"`
	Version                  int            `json:"version"`
	SourceTransitionSequence int            `json:"source_transition_sequence"`
	Title                    string         `json:"title"`
	InitialPublicationReason string         `json:"initial_publication_reason,omitempty"`
	LatestMaterialReason     string         `json:"latest_material_reason,omitempty"`
	EvidenceConclusion       string         `json:"evidence_conclusion,omitempty"`
	ImpactSummary            string         `json:"impact_summary,omitempty"`
	InvestigationWork        []string       `json:"investigation_work"`
	InvestigationStarted     bool           `json:"investigation_started"`
	CurrentAttention         Attention      `json:"current_attention"`
	PeakAttention            Attention      `json:"peak_attention"`
	ActionContract           ActionContract `json:"action_contract"`
	RecordedOperatorContext  []string       `json:"recorded_operator_context"`
	EffectiveStartedAt       time.Time      `json:"effective_started_at"`
	RecoveryObservedAt       *time.Time     `json:"recovery_observed_at,omitempty"`
	TerminalAt               *time.Time     `json:"terminal_at,omitempty"`
	DurationSeconds          *int64         `json:"duration_seconds,omitempty"`
	RecurrenceCount          int            `json:"recurrence_count"`
	FinalOutcome             string         `json:"final_outcome,omitempty"`
	RemainingUncertainty     string         `json:"remaining_uncertainty,omitempty"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

// MarshalJSON canonicalizes InvestigationWork and RecordedOperatorContext
// to [] before marshaling: a nil-constructed EpisodeSummary must never
// serialize either as JSON null. The nested ActionContract canonicalizes
// its own slice field via its own MarshalJSON method.
func (e EpisodeSummary) MarshalJSON() ([]byte, error) {
	type episodeSummaryAlias EpisodeSummary
	out := episodeSummaryAlias(e)
	out.InvestigationWork = canonicalizeSlice(out.InvestigationWork)
	out.RecordedOperatorContext = canonicalizeSlice(out.RecordedOperatorContext)
	return json.Marshal(out)
}

// Validate checks EpisodeSummary's required identity, its closed
// current/peak Attention, the Operator contract's shape against whether the
// summary is terminal (terminal_at set), required UTC instants, and
// non-negative counters. Terminal-ness is derived from TerminalAt since
// EpisodeSummary carries no Lifecycle field of its own.
func (e EpisodeSummary) Validate() error {
	if strings.TrimSpace(e.SituationID) == "" {
		return errors.New("episode_summary: situation_id is required")
	}
	if e.Version < 1 {
		return fmt.Errorf("episode_summary: version must be >= 1, got %d", e.Version)
	}
	if e.SourceTransitionSequence < 1 {
		return fmt.Errorf("episode_summary: source_transition_sequence must be >= 1, got %d", e.SourceTransitionSequence)
	}
	if strings.TrimSpace(e.Title) == "" {
		return errors.New("episode_summary: title is required")
	}
	if err := e.CurrentAttention.Validate(); err != nil {
		return fmt.Errorf("episode_summary: %w", err)
	}
	if err := e.PeakAttention.Validate(); err != nil {
		return fmt.Errorf("episode_summary: %w", err)
	}
	terminal := e.TerminalAt != nil
	if err := e.ActionContract.validate(terminal); err != nil {
		return fmt.Errorf("episode_summary: %w", err)
	}
	if err := requireNonZeroUTC("effective_started_at", e.EffectiveStartedAt); err != nil {
		return fmt.Errorf("episode_summary: %w", err)
	}
	if e.RecoveryObservedAt != nil {
		if err := requireUTC("recovery_observed_at", *e.RecoveryObservedAt); err != nil {
			return fmt.Errorf("episode_summary: %w", err)
		}
	}
	if e.TerminalAt != nil {
		if err := requireUTC("terminal_at", *e.TerminalAt); err != nil {
			return fmt.Errorf("episode_summary: %w", err)
		}
	}
	if e.DurationSeconds != nil && *e.DurationSeconds < 0 {
		return errors.New("episode_summary: duration_seconds must be >= 0")
	}
	if e.RecurrenceCount < 0 {
		return errors.New("episode_summary: recurrence_count must be >= 0")
	}
	if err := requireNonZeroUTC("updated_at", e.UpdatedAt); err != nil {
		return fmt.Errorf("episode_summary: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Notification intent
// ----------------------------------------------------------------------

// EffectClass is the closed shape of one Slack notification effect.
type EffectClass string

const (
	EffectRootSync                EffectClass = "root_sync"
	EffectThreadAppend            EffectClass = "thread_append"
	EffectBroadcastHandoff        EffectClass = "broadcast_handoff"
	EffectInstallationGapRecovery EffectClass = "installation_gap_recovery"
)

// Validate reports an error unless e is one of the closed EffectClass
// values.
func (e EffectClass) Validate() error {
	return validateEnum("effect_class", e,
		EffectRootSync, EffectThreadAppend, EffectBroadcastHandoff, EffectInstallationGapRecovery)
}

// IntentStatus is the closed lifecycle of one NotificationIntent.
type IntentStatus string

const (
	IntentPending              IntentStatus = "pending"
	IntentDelivered            IntentStatus = "delivered"
	IntentBlockedConfiguration IntentStatus = "blocked_configuration"
	IntentFailed               IntentStatus = "failed"
	IntentWithheld             IntentStatus = "withheld_by_operator_slack_floor"
	IntentSuperseded           IntentStatus = "superseded"
)

// Validate reports an error unless s is one of the closed IntentStatus
// values.
func (s IntentStatus) Validate() error {
	return validateEnum("intent_status", s,
		IntentPending, IntentDelivered, IntentBlockedConfiguration, IntentFailed, IntentWithheld, IntentSuperseded)
}

// NotificationIntent is one durable, fenced Slack delivery obligation
// created inside the authoritative controller commit. It is never
// serialized with json struct tags: it is a store/worker-internal record,
// not a wire shape.
type NotificationIntent struct {
	ID                   string
	IdempotencyKey       string
	EffectClass          EffectClass
	SituationID          *string
	TransitionID         *string
	TransitionSequence   *int
	SummaryVersion       *int
	GapGeneration        *string
	RequiresRoot         bool
	MainChannelPoke      bool
	InterruptionPriority *InterruptionPriority
	ContractDeadlineAt   *time.Time // root_sync only (R4): the committed promise this root renders
	ClientMessageID      string
	Status               IntentStatus
	ClaimOwner           *string
	ClaimToken           int64
	LeaseExpiresAt       *time.Time
	AttemptCount         int
	LastErrorClass       *string
	RetryAt              *time.Time
	SupersessionReason   *string
	ReplacementIntentID  *string
	DeliveredAs          *string
	Channel              *string
	MessageTS            *string
	CreatedAt            time.Time
	DeliveredAt          *time.Time
}

// Validate checks NotificationIntent's required, bounded identity fields;
// its closed effect-class/status/priority codes; the effect-class-specific
// reference rules (installation_gap_recovery forbids Situation/Transition
// references and requires a gap generation; the three Situation effects
// require a Situation/Transition/summary reference according to their
// class; contract_deadline_at is accepted only on root_sync; gap_generation
// is accepted only on installation_gap_recovery); and a required, UTC
// created_at.
func (n NotificationIntent) Validate() error {
	if strings.TrimSpace(n.ID) == "" {
		return errors.New("notification_intent: id is required")
	}
	if len(n.ID) > maxIdentifierLength {
		return fmt.Errorf("notification_intent: id exceeds %d bytes", maxIdentifierLength)
	}
	if strings.TrimSpace(n.IdempotencyKey) == "" {
		return errors.New("notification_intent: idempotency_key is required")
	}
	if len(n.IdempotencyKey) > maxIdentifierLength {
		return fmt.Errorf("notification_intent: idempotency_key exceeds %d bytes", maxIdentifierLength)
	}
	if err := n.EffectClass.Validate(); err != nil {
		return fmt.Errorf("notification_intent: %w", err)
	}
	if strings.TrimSpace(n.ClientMessageID) == "" {
		return errors.New("notification_intent: client_message_id is required")
	}
	if len(n.ClientMessageID) > maxIdentifierLength {
		return fmt.Errorf("notification_intent: client_message_id exceeds %d bytes", maxIdentifierLength)
	}
	if err := n.Status.Validate(); err != nil {
		return fmt.Errorf("notification_intent: %w", err)
	}
	if n.InterruptionPriority != nil {
		if err := n.InterruptionPriority.Validate(); err != nil {
			return fmt.Errorf("notification_intent: %w", err)
		}
	}
	if n.AttemptCount < 0 {
		return errors.New("notification_intent: attempt_count must be >= 0")
	}
	for _, ptrField := range []struct {
		name string
		v    *string
	}{
		{"situation_id", n.SituationID}, {"transition_id", n.TransitionID},
		{"gap_generation", n.GapGeneration}, {"claim_owner", n.ClaimOwner},
		{"last_error_class", n.LastErrorClass}, {"supersession_reason", n.SupersessionReason},
		{"replacement_intent_id", n.ReplacementIntentID}, {"delivered_as", n.DeliveredAs},
		{"channel", n.Channel}, {"message_ts", n.MessageTS},
	} {
		if ptrField.v == nil {
			continue
		}
		if strings.TrimSpace(*ptrField.v) == "" {
			return fmt.Errorf("notification_intent: %s must not be empty when set", ptrField.name)
		}
		if len(*ptrField.v) > maxIdentifierLength {
			return fmt.Errorf("notification_intent: %s exceeds %d bytes", ptrField.name, maxIdentifierLength)
		}
	}

	switch n.EffectClass {
	case EffectInstallationGapRecovery:
		if n.SituationID != nil {
			return errors.New("notification_intent: installation_gap_recovery must not set situation_id")
		}
		if n.TransitionID != nil {
			return errors.New("notification_intent: installation_gap_recovery must not set transition_id")
		}
		if n.TransitionSequence != nil {
			return errors.New("notification_intent: installation_gap_recovery must not set transition_sequence")
		}
		if n.SummaryVersion != nil {
			return errors.New("notification_intent: installation_gap_recovery must not set summary_version")
		}
		if n.GapGeneration == nil {
			return errors.New("notification_intent: installation_gap_recovery requires gap_generation")
		}
	case EffectRootSync, EffectThreadAppend, EffectBroadcastHandoff:
		if n.SituationID == nil {
			return fmt.Errorf("notification_intent: %s requires situation_id", n.EffectClass)
		}
		if n.TransitionID == nil {
			return fmt.Errorf("notification_intent: %s requires transition_id", n.EffectClass)
		}
		if n.GapGeneration != nil {
			return fmt.Errorf("notification_intent: gap_generation is accepted only on %s, not %s", EffectInstallationGapRecovery, n.EffectClass)
		}
		if n.EffectClass == EffectRootSync && n.SummaryVersion == nil {
			return errors.New("notification_intent: root_sync requires summary_version")
		}
	}

	if n.ContractDeadlineAt != nil {
		if n.EffectClass != EffectRootSync {
			return fmt.Errorf("notification_intent: contract_deadline_at is accepted only on %s, not %s", EffectRootSync, n.EffectClass)
		}
		if err := requireUTC("contract_deadline_at", *n.ContractDeadlineAt); err != nil {
			return fmt.Errorf("notification_intent: %w", err)
		}
	}

	if err := requireNonZeroUTC("created_at", n.CreatedAt); err != nil {
		return fmt.Errorf("notification_intent: %w", err)
	}
	if n.LeaseExpiresAt != nil {
		if err := requireUTC("lease_expires_at", *n.LeaseExpiresAt); err != nil {
			return fmt.Errorf("notification_intent: %w", err)
		}
	}
	if n.RetryAt != nil {
		if err := requireUTC("retry_at", *n.RetryAt); err != nil {
			return fmt.Errorf("notification_intent: %w", err)
		}
	}
	if n.DeliveredAt != nil {
		if err := requireUTC("delivered_at", *n.DeliveredAt); err != nil {
			return fmt.Errorf("notification_intent: %w", err)
		}
	}
	return nil
}
