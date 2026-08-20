// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "time"

type JudgmentKind string

const (
	JudgmentExpectedThisEpisode JudgmentKind = "expected_this_episode"
	JudgmentUnexpected          JudgmentKind = "unexpected"
	JudgmentInconclusive        JudgmentKind = "inconclusive"
)

type JudgmentBasis string

const (
	JudgmentBasisOperatorKnowledge JudgmentBasis = "operator_knowledge"
	JudgmentBasisAlertintEvidence  JudgmentBasis = "alertint_evidence"
)

// Judgment is append-only operator steering tied to an exact Situation view.
type Judgment struct {
	ID                 string        `json:"id"`
	SituationID        string        `json:"situation_id"`
	JudgedInputVersion int           `json:"judged_input_version"`
	CoveredFactHash    string        `json:"covered_fact_hash"`
	CoveredSymptoms    []string      `json:"covered_symptoms"`
	CoveredImpact      []string      `json:"covered_impact"`
	Judgment           JudgmentKind  `json:"judgment"`
	Basis              JudgmentBasis `json:"basis"`
	Workload           *string       `json:"workload,omitempty"`
	ValidUntil         *time.Time    `json:"valid_until,omitempty"`
	EvidenceRefs       []string      `json:"evidence_refs"`
	AuthenticatedAs    string        `json:"authenticated_as"`
	AssertedOperator   string        `json:"asserted_operator"`
	CreatedAt          time.Time     `json:"created_at"`
}

// JudgmentRequest is the confirmed MCP write shape for a current judgment.
type JudgmentRequest struct {
	Situation         string        `json:"situation"`
	Judgment          JudgmentKind  `json:"judgment"`
	Basis             JudgmentBasis `json:"basis"`
	Workload          *string       `json:"workload,omitempty"`
	ValidUntil        *time.Time    `json:"valid_until,omitempty"`
	OperatorConfirmed bool          `json:"operator_confirmed"`
	ConfirmedBy       string        `json:"confirmed_by"`
}

// Schedule is an IANA wall-clock rule. Its resolved interval is persisted in
// UTC by policy evaluation; this contract never asks an LLM to interpret time.
type Schedule struct {
	Days                  []string `json:"days"`
	LocalStart            string   `json:"local_start"`
	LocalEnd              string   `json:"local_end"`
	Timezone              string   `json:"timezone"`
	StartToleranceMinutes int      `json:"start_tolerance_minutes,omitempty"`
}

type DurationRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// EnvelopeScope is the exact group and source/trigger identity an envelope
// can authorize; omitted fields grant no broader authority.
type EnvelopeScope struct {
	GroupKey       string `json:"group_key"`
	Source         string `json:"source"`
	TriggerID      string `json:"trigger_id"`
	TriggerVersion string `json:"trigger_version"`
}

// EnvelopeConditions keeps required and allowed companion signals distinct:
// each has intentionally different evaluation semantics.
type EnvelopeConditions struct {
	Schedule                 *Schedule      `json:"schedule,omitempty"`
	DurationMinutes          *DurationRange `json:"duration_minutes,omitempty"`
	Workload                 *string        `json:"workload,omitempty"`
	RequiredCompanionSignals []string       `json:"required_companion_signals,omitempty"`
	AllowedCompanionSignals  []string       `json:"allowed_companion_signals,omitempty"`
	ForbiddenImpactSignals   []string       `json:"forbidden_impact_signals,omitempty"`
	MaximumUncertainty       *string        `json:"maximum_uncertainty,omitempty"`
	AllowExpectedCritical    bool           `json:"allow_expected_critical"`
}

type EnvelopeStatus string

const (
	EnvelopeStatusActive      EnvelopeStatus = "active"
	EnvelopeStatusRevoked     EnvelopeStatus = "revoked"
	EnvelopeStatusInvalidated EnvelopeStatus = "invalidated"
)

// EnvelopeVersion is immutable policy history; edits append a new version.
type EnvelopeVersion struct {
	EnvelopeID       string             `json:"envelope_id"`
	Version          int                `json:"version"`
	Status           EnvelopeStatus     `json:"status"`
	Scope            EnvelopeScope      `json:"scope"`
	Conditions       EnvelopeConditions `json:"conditions"`
	ReviewDueAt      time.Time          `json:"review_due_at"`
	AuthenticatedAs  string             `json:"authenticated_as"`
	AssertedOperator string             `json:"asserted_operator"`
	Reason           *string            `json:"reason,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
}

// Envelope is the stable head and its current immutable version.
type Envelope struct {
	ID                 string           `json:"id"`
	CurrentVersion     int              `json:"current_version"`
	SourceJudgmentID   string           `json:"source_judgment_id"`
	LastReviewPromptAt *time.Time       `json:"last_review_prompt_at,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
	Version            *EnvelopeVersion `json:"version,omitempty"`
}

// EnvelopeConfirmation creates an active version after explicit operator
// confirmation and asserted attribution.
type EnvelopeConfirmation struct {
	SourceJudgmentID       string             `json:"source_judgment_id"`
	ExpectedCurrentVersion int                `json:"expected_current_version"`
	Scope                  EnvelopeScope      `json:"scope"`
	Conditions             EnvelopeConditions `json:"conditions"`
	ReviewDueAt            time.Time          `json:"review_due_at"`
	OperatorConfirmed      bool               `json:"operator_confirmed"`
	ConfirmedBy            string             `json:"confirmed_by"`
}

// EnvelopeRevocation appends a revoked version; it never mutates history.
type EnvelopeRevocation struct {
	EnvelopeID             string `json:"envelope_id"`
	ExpectedCurrentVersion int    `json:"expected_current_version"`
	Reason                 string `json:"reason"`
	OperatorConfirmed      bool   `json:"operator_confirmed"`
	ConfirmedBy            string `json:"confirmed_by"`
}

type EnvelopeEvaluationResult string

const (
	EnvelopeEvaluationMatch            EnvelopeEvaluationResult = "match"
	EnvelopeEvaluationViolation        EnvelopeEvaluationResult = "violation"
	EnvelopeEvaluationAuthorityRemoved EnvelopeEvaluationResult = "authority_removed"
	EnvelopeEvaluationNotApplicable    EnvelopeEvaluationResult = "not_applicable"
)

type EnvelopeEvaluation struct {
	ID                string                   `json:"id"`
	EnvelopeID        string                   `json:"envelope_id"`
	EnvelopeVersion   int                      `json:"envelope_version"`
	SituationID       string                   `json:"situation_id"`
	InputVersion      int                      `json:"input_version"`
	Result            EnvelopeEvaluationResult `json:"result"`
	MatchedFields     []string                 `json:"matched_fields"`
	Violations        []string                 `json:"violations"`
	Observability     []string                 `json:"observability"`
	QuietingAuthority bool                     `json:"quieting_authority"`
	CreatedAt         time.Time                `json:"created_at"`
}

// InterruptionPriority is derived deterministically and never model-authored.
type InterruptionPriority string

const (
	PriorityLow      InterruptionPriority = "low"
	PriorityMedium   InterruptionPriority = "medium"
	PriorityHigh     InterruptionPriority = "high"
	PriorityCritical InterruptionPriority = "critical"
)

type NotificationKind string

const (
	NotificationSituationRootCreate     NotificationKind = "situation_root_create"
	NotificationSituationRootEdit       NotificationKind = "situation_root_edit"
	NotificationSituationThreadReply    NotificationKind = "situation_thread_reply"
	NotificationSituationBroadcastReply NotificationKind = "situation_broadcast_reply"
	NotificationHealthRoot              NotificationKind = "health_root"
	NotificationHealthUpdate            NotificationKind = "health_update"
	NotificationEnvelopeReview          NotificationKind = "envelope_review"
)

type NotificationStatus string

const (
	NotificationPending                      NotificationStatus = "pending"
	NotificationDelivered                    NotificationStatus = "delivered"
	NotificationFailed                       NotificationStatus = "failed"
	NotificationWithheldByOperatorSlackFloor NotificationStatus = "withheld_by_operator_slack_floor"
)

type NotificationSubjectKind string

const (
	NotificationSubjectSituation        NotificationSubjectKind = "situation"
	NotificationSubjectDependencyHealth NotificationSubjectKind = "dependency_health"
	NotificationSubjectEnvelope         NotificationSubjectKind = "expected_behavior_envelope"
)

// NotificationIntent is persisted before every outward Slack effect.
type NotificationIntent struct {
	ID                   string                  `json:"id"`
	IdempotencyKey       string                  `json:"idempotency_key"`
	SubjectKind          NotificationSubjectKind `json:"subject_kind"`
	SubjectID            string                  `json:"subject_id"`
	SituationID          *string                 `json:"situation_id,omitempty"`
	TransitionID         *string                 `json:"transition_id,omitempty"`
	Kind                 NotificationKind        `json:"kind"`
	MainChannelPoke      bool                    `json:"main_channel_poke"`
	InterruptionPriority *InterruptionPriority   `json:"interruption_priority,omitempty"`
	Status               NotificationStatus      `json:"status"`
	Channel              *string                 `json:"channel,omitempty"`
	MessageTS            *string                 `json:"message_ts,omitempty"`
	ClientMessageID      string                  `json:"client_msg_id"`
	AttemptCount         int                     `json:"attempt_count"`
	LastErrorClass       *string                 `json:"last_error_class,omitempty"`
	RetryAt              *time.Time              `json:"retry_at,omitempty"`
	CreatedAt            time.Time               `json:"created_at"`
	DeliveredAt          *time.Time              `json:"delivered_at,omitempty"`
}
