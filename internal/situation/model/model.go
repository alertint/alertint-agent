// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines transport-neutral, closed contracts shared by the
// Situation controller and SQLite store. All non-Slack timestamps are UTC.
package model

import "time"

// Lifecycle is controller-owned and terminal states never reopen.
type Lifecycle string

const (
	LifecycleActive          Lifecycle = "active"
	LifecycleRecoveryPending Lifecycle = "recovery_pending"
	LifecycleRecovered       Lifecycle = "recovered"
	LifecycleClosedUnknown   Lifecycle = "closed_unknown"
)

// Attention expresses the current operator attention contract.
type Attention string

const (
	AttentionObserve     Attention = "observe"
	AttentionInvestigate Attention = "investigate"
	AttentionUrgent      Attention = "urgent"
)

// DueReason identifies an event that can advance reconciliation.
type DueReason string

const (
	DueIncidentCreated        DueReason = "incident_created"
	DueMembershipChanged      DueReason = "membership_changed"
	DueNewSymptom             DueReason = "new_symptom"
	DueAlertResolved          DueReason = "alert_resolved"
	DueAlertRefired           DueReason = "alert_refired"
	DueDurationMilestone      DueReason = "duration_milestone"
	DueConnectorHealthChanged DueReason = "connector_health_changed"
	DueSemanticProfileChanged DueReason = "semantic_profile_changed"
	DueOperatorJudgment       DueReason = "operator_judgment"
	DueEnvelopeChanged        DueReason = "envelope_changed"
	DueEnvelopeBoundary       DueReason = "envelope_boundary"
	DueJudgmentBoundary       DueReason = "judgment_boundary"
	DueManualReassessment     DueReason = "manual_reassessment"
	DueRecoveryGraceExpired   DueReason = "recovery_grace_expired"
	DueObservationDeadline    DueReason = "observation_deadline"
	DueRetry                  DueReason = "retry_due"
	DueUpgradeReconstruction  DueReason = "upgrade_reconstruction"
)

// SourceTimeBasis records provenance of a canonical source timestamp.
type SourceTimeBasis string

const (
	SourceTimeBasisSourcePayload   SourceTimeBasis = "source_payload"
	SourceTimeBasisSourceAPI       SourceTimeBasis = "source_api"
	SourceTimeBasisReceiptFallback SourceTimeBasis = "receipt_fallback"
	SourceTimeBasisMissing         SourceTimeBasis = "missing"
	SourceTimeBasisMixed           SourceTimeBasis = "mixed"
)

// DeliveryStatus is the immutable source lifecycle recorded for one accepted
// delivery; it is not inferred from a latest-wins Alert projection.
type DeliveryStatus string

const (
	DeliveryStatusFiring   DeliveryStatus = "firing"
	DeliveryStatusResolved DeliveryStatus = "resolved"
)

// TerminalReason is the one structured reason required by closed_unknown.
type TerminalReason string

const (
	TerminalReasonObservationDeadline TerminalReason = "observation_deadline"
	TerminalReasonResolutionMissing   TerminalReason = "resolution_missing"
	TerminalReasonSourceUnavailable   TerminalReason = "source_unavailable"
	TerminalReasonBudgetExhausted     TerminalReason = "budget_exhausted"
)

// Cadence selects a controller checkpoint interval.
type Cadence string

const (
	CadenceFast   Cadence = "fast"
	CadenceNormal Cadence = "normal"
	CadenceSlow   Cadence = "slow"
)

// Situation is the aggregate projection shared with the store.
type Situation struct {
	ID                      string          `json:"id"`
	PreviousSituationID     *string         `json:"previous_situation_id,omitempty"`
	GroupKey                string          `json:"group_key"`
	PublicHandle            *string         `json:"public_handle,omitempty"`
	Title                   *string         `json:"title,omitempty"`
	Lifecycle               Lifecycle       `json:"lifecycle"`
	Attention               Attention       `json:"attention"`
	InputVersion            int             `json:"input_version"`
	FactHash                *string         `json:"fact_hash,omitempty"`
	CurrentAssessmentID     *string         `json:"current_assessment_id,omitempty"`
	OpenedAt                time.Time       `json:"opened_at"`
	EffectiveStartedAt      time.Time       `json:"effective_started_at"`
	EffectiveStartedAtBasis SourceTimeBasis `json:"effective_started_at_basis"`
	FirstReceivedAt         time.Time       `json:"first_received_at"`
	LastLifecycleObservedAt time.Time       `json:"last_lifecycle_observed_at"`
	RecoveryObservedAt      *time.Time      `json:"recovery_observed_at,omitempty"`
	GraceUntil              *time.Time      `json:"grace_until,omitempty"`
	TerminalAt              *time.Time      `json:"terminal_at,omitempty"`
	TerminalReason          *TerminalReason `json:"terminal_reason,omitempty"`
	NextAssessmentAt        time.Time       `json:"next_assessment_at"`
	DueReasons              []DueReason     `json:"due_reasons"`
	LeaseOwner              *string         `json:"lease_owner,omitempty"`
	LeaseExpiresAt          *time.Time      `json:"lease_expires_at,omitempty"`
	AttemptCount            int             `json:"attempt_count"`
	LastErrorClass          *string         `json:"last_error_class,omitempty"`
	RetryAt                 *time.Time      `json:"retry_at,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}

// ReasonCandidate is immutable deterministic evidence that an Assessment may
// reference. It grants no model authority by itself.
type ReasonCandidate struct {
	ID                 string   `json:"id"`
	CatalogVersion     int      `json:"catalog_version"`
	PredicateVersion   int      `json:"predicate_version"`
	Code               string   `json:"code"`
	PredicateResult    string   `json:"predicate_result"`
	EvidenceRefs       []string `json:"evidence_refs"`
	DeterministicFloor bool     `json:"deterministic_floor"`
}

// ValidationAdjustment records a deterministic correction made while
// validating a proposed Assessment.
type ValidationAdjustment struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Transition is immutable Assessment/lifecycle/action-contract history.
type Transition struct {
	ID             string         `json:"id"`
	SituationID    string         `json:"situation_id"`
	InputVersion   int            `json:"input_version"`
	Lifecycle      Lifecycle      `json:"lifecycle"`
	Attention      Attention      `json:"attention"`
	Assessment     *Assessment    `json:"assessment,omitempty"`
	ActionContract ActionContract `json:"action_contract"`
	Reason         string         `json:"reason,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}
