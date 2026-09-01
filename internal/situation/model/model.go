// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines the closed, transport-neutral Situation domain
// vocabulary shared by the situation controller and the store: lifecycle
// states, attention levels, timestamp provenance, delivery status, due
// reasons, terminal reasons, material facts, the Assessment contract, and
// the Situation aggregate itself. It holds data plus closed-enum shape
// validation — Validate methods reject unknown values and internally
// inconsistent shapes, but never derive, persist, or call out. All
// timestamps are UTC.
package model

import (
	"fmt"
	"time"
)

// validateEnum reports an error unless v is one of allowed. It backs every
// closed-enum Validate method in this package.
func validateEnum[T ~string](kind string, v T, allowed ...T) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("model: %s: unknown value %q", kind, v)
}

// Lifecycle is controller-owned; terminal states never reopen.
type Lifecycle string

const (
	LifecycleActive          Lifecycle = "active"
	LifecycleRecoveryPending Lifecycle = "recovery_pending"
	LifecycleRecovered       Lifecycle = "recovered"
	LifecycleClosedUnknown   Lifecycle = "closed_unknown"
)

// Validate reports an error unless l is one of the closed Lifecycle values.
func (l Lifecycle) Validate() error {
	return validateEnum("lifecycle", l,
		LifecycleActive, LifecycleRecoveryPending, LifecycleRecovered, LifecycleClosedUnknown)
}

// Terminal reports whether l is a terminal lifecycle (recovered or
// closed_unknown): terminal lifecycles never reopen and carry no future
// Operator-contract update promise.
func (l Lifecycle) Terminal() bool {
	return l == LifecycleRecovered || l == LifecycleClosedUnknown
}

// Attention expresses the current operator attention contract.
type Attention string

const (
	AttentionObserve     Attention = "observe"
	AttentionInvestigate Attention = "investigate"
	AttentionUrgent      Attention = "urgent"
)

// Validate reports an error unless a is one of the closed Attention values.
func (a Attention) Validate() error {
	return validateEnum("attention", a, AttentionObserve, AttentionInvestigate, AttentionUrgent)
}

// SourceTimeBasis records the provenance of a canonical source timestamp.
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

// DueReason identifies an event that can make a Situation due for
// reassessment.
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
	DueTriageChanged          DueReason = "triage_changed"
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

// TerminalReason is the structured reason recorded when a Situation closes
// as closed_unknown.
type TerminalReason string

const (
	TerminalReasonObservationDeadline TerminalReason = "observation_deadline"
	TerminalReasonResolutionMissing   TerminalReason = "resolution_missing"
	TerminalReasonSourceUnavailable   TerminalReason = "source_unavailable"
	TerminalReasonBudgetExhausted     TerminalReason = "budget_exhausted"
)

// Situation is the durable foundation aggregate: identity, lifecycle, and
// scheduling/lease/retry state. It carries no assessment, fact, policy, or
// notification data — those belong to later slices.
type Situation struct {
	ID                      string          `json:"id"`
	PreviousSituationID     *string         `json:"previous_situation_id,omitempty"`
	GroupKey                string          `json:"group_key"`
	PublicHandle            *string         `json:"public_handle,omitempty"`
	Lifecycle               Lifecycle       `json:"lifecycle"`
	Attention               Attention       `json:"attention"`
	InputVersion            int             `json:"input_version"`
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
	ClaimToken              int64           `json:"claim_token"`
	AttemptCount            int             `json:"attempt_count"`
	LastErrorClass          *string         `json:"last_error_class,omitempty"`
	RetryAt                 *time.Time      `json:"retry_at,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}
