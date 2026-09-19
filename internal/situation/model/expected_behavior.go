// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "time"

// ExpectedBehaviorOperation is one immutable operator-authored envelope revision.
type ExpectedBehaviorOperation string

const (
	ExpectedBehaviorOperationConfirm ExpectedBehaviorOperation = "confirm"
	ExpectedBehaviorOperationReplace ExpectedBehaviorOperation = "replace"
	ExpectedBehaviorOperationRevoke  ExpectedBehaviorOperation = "revoke"
	ExpectedBehaviorOperationRestore ExpectedBehaviorOperation = "restore"
)

// ExpectedBehaviorState is the authority state carried by the current head.
type ExpectedBehaviorState string

const (
	ExpectedBehaviorStateActive  ExpectedBehaviorState = "active"
	ExpectedBehaviorStateRevoked ExpectedBehaviorState = "revoked"
)

// ExpectedBehaviorInvalidationReason is a permanent, source-proven change.
type ExpectedBehaviorInvalidationReason string

const (
	ExpectedBehaviorSourceInstanceChanged    ExpectedBehaviorInvalidationReason = "source_instance_changed"
	ExpectedBehaviorPrimaryDefinitionChanged ExpectedBehaviorInvalidationReason = "primary_definition_changed"
	ExpectedBehaviorBindingDefinitionChanged ExpectedBehaviorInvalidationReason = "binding_definition_changed"
)

// ExpectedBehaviorWeekday is a closed local schedule weekday.
type ExpectedBehaviorWeekday string

const (
	ExpectedBehaviorMonday    ExpectedBehaviorWeekday = "mon"
	ExpectedBehaviorTuesday   ExpectedBehaviorWeekday = "tue"
	ExpectedBehaviorWednesday ExpectedBehaviorWeekday = "wed"
	ExpectedBehaviorThursday  ExpectedBehaviorWeekday = "thu"
	ExpectedBehaviorFriday    ExpectedBehaviorWeekday = "fri"
	ExpectedBehaviorSaturday  ExpectedBehaviorWeekday = "sat"
	ExpectedBehaviorSunday    ExpectedBehaviorWeekday = "sun"
)

// ExpectedBehaviorScope binds reusable authority to one proven Zabbix rule.
type ExpectedBehaviorScope struct {
	GroupKey              string `json:"group_key"`
	Source                string `json:"source"`
	SourceInstanceID      string `json:"source_instance_id"`
	Host                  string `json:"host"`
	PrimaryTriggerID      string `json:"primary_trigger_id"`
	PrimaryTriggerVersion string `json:"primary_trigger_version"`
}

// ExpectedBehaviorBinding is one exact companion or forbidden Zabbix rule.
type ExpectedBehaviorBinding struct {
	Role             string `json:"role"`
	Source           string `json:"source"`
	SourceInstanceID string `json:"source_instance_id"`
	Host             string `json:"host"`
	TriggerID        string `json:"trigger_id"`
	TriggerVersion   string `json:"trigger_version"`
}

// ExpectedBehaviorSchedule is a wall-clock schedule in one IANA timezone.
type ExpectedBehaviorSchedule struct {
	Days                  []ExpectedBehaviorWeekday `json:"days"`
	LocalStart            string                    `json:"local_start"`
	LocalEnd              string                    `json:"local_end"`
	Timezone              string                    `json:"timezone"`
	StartToleranceMinutes int                       `json:"start_tolerance_minutes"`
}

// ExpectedBehaviorConditions are the complete active revision body.
type ExpectedBehaviorConditions struct {
	Workload           string                    `json:"workload"`
	Schedule           ExpectedBehaviorSchedule  `json:"schedule"`
	MaxDurationMinutes int                       `json:"max_duration_minutes"`
	RequiredCompanions []ExpectedBehaviorBinding `json:"required_companions"`
	AllowedCompanions  []ExpectedBehaviorBinding `json:"allowed_companions"`
	ForbiddenSignals   []ExpectedBehaviorBinding `json:"forbidden_signals"`
}

// ExpectedBehaviorPolicy is the reusable content stored in active revisions.
type ExpectedBehaviorPolicy struct {
	Scope       ExpectedBehaviorScope      `json:"scope"`
	Conditions  ExpectedBehaviorConditions `json:"conditions"`
	ReviewDueAt time.Time                  `json:"review_due_at"`
}

// ExpectedBehaviorRevision is one immutable operator-authored revision.
type ExpectedBehaviorRevision struct {
	ID                      string                    `json:"id"`
	EnvelopeID              string                    `json:"envelope_id"`
	Version                 int                       `json:"version"`
	Operation               ExpectedBehaviorOperation `json:"operation"`
	State                   ExpectedBehaviorState     `json:"state"`
	Policy                  *ExpectedBehaviorPolicy   `json:"policy,omitempty"`
	SourceJudgmentID        string                    `json:"source_judgment_id,omitempty"`
	SourceSituationID       string                    `json:"source_situation_id,omitempty"`
	AssertedOperator        string                    `json:"asserted_operator"`
	TrustDomain             JudgmentTrustDomain       `json:"trust_domain"`
	RequestID               string                    `json:"request_id"`
	ExpectedPreviousVersion int                       `json:"expected_previous_version"`
	CreatedAt               time.Time                 `json:"created_at"`
}

// ExpectedBehaviorHead selects the only revision that can carry authority.
type ExpectedBehaviorHead struct {
	EnvelopeID         string                             `json:"envelope_id"`
	RevisionID         string                             `json:"revision_id"`
	Version            int                                `json:"version"`
	State              ExpectedBehaviorState              `json:"state"`
	Scope              ExpectedBehaviorScope              `json:"scope"`
	Policy             *ExpectedBehaviorPolicy            `json:"policy,omitempty"`
	AssertedOperator   string                             `json:"asserted_operator"`
	InvalidatedAt      *time.Time                         `json:"invalidated_at,omitempty"`
	InvalidationReason ExpectedBehaviorInvalidationReason `json:"invalidation_reason,omitempty"`
	UpdatedAt          time.Time                          `json:"updated_at"`
}

// ExpectedBehaviorOccurrence freezes one resolved wall-clock occurrence.
type ExpectedBehaviorOccurrence struct {
	OwningLocalDate  string    `json:"owning_local_date"`
	Timezone         string    `json:"timezone"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	PrimaryStartedAt time.Time `json:"primary_started_at"`
	Boundary         time.Time `json:"boundary"`
	ResolverVersion  int       `json:"resolver_version"`
}

// ExpectedBehaviorCandidateStatus is one candidate's deterministic result.
type ExpectedBehaviorCandidateStatus string

const (
	ExpectedBehaviorMatched              ExpectedBehaviorCandidateStatus = "matched"
	ExpectedBehaviorAuthorityUnavailable ExpectedBehaviorCandidateStatus = "authority_unavailable"
	ExpectedBehaviorViolated             ExpectedBehaviorCandidateStatus = "violated"
	ExpectedBehaviorNotCandidate         ExpectedBehaviorCandidateStatus = "not_candidate"
)

// ExpectedBehaviorReason is a closed current-authority explanation.
type ExpectedBehaviorReason string

const (
	ExpectedBehaviorReasonMatched                  ExpectedBehaviorReason = "matched"
	ExpectedBehaviorReasonRevoked                  ExpectedBehaviorReason = "revoked"
	ExpectedBehaviorReasonInvalidated              ExpectedBehaviorReason = "invalidated"
	ExpectedBehaviorReasonScopeMismatch            ExpectedBehaviorReason = "scope_mismatch"
	ExpectedBehaviorReasonPrimaryDefinitionChanged ExpectedBehaviorReason = "primary_definition_changed"
	ExpectedBehaviorReasonBindingDefinitionChanged ExpectedBehaviorReason = "binding_definition_changed"
	ExpectedBehaviorReasonDefinitionUnavailable    ExpectedBehaviorReason = "definition_unavailable"
	ExpectedBehaviorReasonScheduleUnavailable      ExpectedBehaviorReason = "schedule_unavailable"
	ExpectedBehaviorReasonOutsideSchedule          ExpectedBehaviorReason = "outside_schedule"
	ExpectedBehaviorReasonStartOutsideTolerance    ExpectedBehaviorReason = "start_outside_tolerance"
	ExpectedBehaviorReasonDurationExceeded         ExpectedBehaviorReason = "duration_exceeded"
	ExpectedBehaviorReasonRequiredMissing          ExpectedBehaviorReason = "required_companion_missing"
	ExpectedBehaviorReasonObservationUnavailable   ExpectedBehaviorReason = "observation_unavailable"
	ExpectedBehaviorReasonUnexpectedSymptom        ExpectedBehaviorReason = "unexpected_symptom"
	ExpectedBehaviorReasonForbiddenPresent         ExpectedBehaviorReason = "forbidden_signal_present"
	ExpectedBehaviorReasonUrgent                   ExpectedBehaviorReason = "urgent"
	ExpectedBehaviorReasonBudgetDeferred           ExpectedBehaviorReason = "budget_deferred"
)

// ExpectedBehaviorCandidate preserves each alternative's explanation.
type ExpectedBehaviorCandidate struct {
	EnvelopeID   string                          `json:"envelope_id"`
	Version      int                             `json:"version"`
	Status       ExpectedBehaviorCandidateStatus `json:"status"`
	Reason       ExpectedBehaviorReason          `json:"reason"`
	Occurrence   *ExpectedBehaviorOccurrence     `json:"occurrence,omitempty"`
	EvidenceRefs []string                        `json:"evidence_refs,omitempty"`
}

// ExpectedBehaviorDisposition is the aggregate authority result.
type ExpectedBehaviorDisposition string

const (
	ExpectedBehaviorDispositionMatched              ExpectedBehaviorDisposition = "matched"
	ExpectedBehaviorDispositionAuthorityUnavailable ExpectedBehaviorDisposition = "authority_unavailable"
	ExpectedBehaviorDispositionViolated             ExpectedBehaviorDisposition = "violated"
	ExpectedBehaviorDispositionNotApplicable        ExpectedBehaviorDisposition = "not_applicable"
)

// ExpectedBehaviorEvaluation is the immutable aggregate evaluation payload.
type ExpectedBehaviorEvaluation struct {
	ID               string                      `json:"id,omitempty"`
	SituationID      string                      `json:"situation_id,omitempty"`
	SituationVersion int                         `json:"situation_input_version,omitempty"`
	Disposition      ExpectedBehaviorDisposition `json:"disposition"`
	Reason           ExpectedBehaviorReason      `json:"reason,omitempty"`
	ChosenEnvelopeID string                      `json:"chosen_envelope_id,omitempty"`
	ChosenVersion    int                         `json:"chosen_version,omitempty"`
	Occurrence       *ExpectedBehaviorOccurrence `json:"occurrence,omitempty"`
	Candidates       []ExpectedBehaviorCandidate `json:"candidates"`
	BasisHash        string                      `json:"basis_hash,omitempty"`
	EvaluatedAt      time.Time                   `json:"evaluated_at,omitempty"`
}
