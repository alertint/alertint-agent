// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "time"

// JudgmentOperation names the explicit immutable revision operation.
type JudgmentOperation string

const (
	JudgmentOperationRecord  JudgmentOperation = "record"
	JudgmentOperationReplace JudgmentOperation = "replace"
	JudgmentOperationRevoke  JudgmentOperation = "revoke"
	JudgmentOperationRestore JudgmentOperation = "restore"
)

// JudgmentState is the authority carried by a revision.
type JudgmentState string

const (
	JudgmentStateExpected JudgmentState = "expected"
	JudgmentStateRevoked  JudgmentState = "revoked"
)

// JudgmentTrustDomain distinguishes MCP authentication from the asserted
// individual operator name. AlertINT authenticates the client domain; it does
// not claim that the supplied name is a verified person identity.
type JudgmentTrustDomain string

const JudgmentTrustAuthenticatedMCP JudgmentTrustDomain = "authenticated_mcp"

// ExpectedJudgmentSymptom is one stable covered firing condition. Receipt
// identity and payload digests are deliberately absent so routine telemetry
// repeats do not invalidate authority.
type ExpectedJudgmentSymptom struct {
	AlertID                     string            `json:"alert_id"`
	Source                      string            `json:"source"`
	EpisodeKey                  string            `json:"episode_key"`
	SourceSignalID              *string           `json:"source_signal_id"`
	SourceSignalVersion         *string           `json:"source_signal_version"`
	SourceInstanceID            *string           `json:"source_instance_id,omitempty"`
	ObservedSourceInstanceID    *string           `json:"observed_source_instance_id,omitempty"`
	ObservedSourceConfigVersion *string           `json:"observed_source_config_version,omitempty"`
	Severity                    string            `json:"severity"`
	IdentityLabels              map[string]string `json:"identity_labels"`
}

// ExpectedJudgmentCoverage is the server-derived applicability predicate for
// one exact Situation snapshot.
type ExpectedJudgmentCoverage struct {
	Scope        string                    `json:"scope"`
	Impact       Impact                    `json:"impact"`
	Symptoms     []ExpectedJudgmentSymptom `json:"symptoms"`
	EvidenceRefs []string                  `json:"evidence_refs"`
}

// SituationJudgment is one immutable episode-scoped revision.
type SituationJudgment struct {
	ID               string                   `json:"id"`
	SituationID      string                   `json:"situation_id"`
	Revision         int                      `json:"revision"`
	Operation        JudgmentOperation        `json:"operation"`
	State            JudgmentState            `json:"state"`
	AssertedOperator string                   `json:"asserted_operator"`
	TrustDomain      JudgmentTrustDomain      `json:"trust_domain"`
	RequestID        string                   `json:"request_id,omitempty"`
	ValidUntil       time.Time                `json:"valid_until,omitempty"`
	Coverage         ExpectedJudgmentCoverage `json:"coverage"`
	CreatedAt        time.Time                `json:"created_at,omitempty"`
}

// JudgmentApplicabilityReason is the deterministic current-authority result.
type JudgmentApplicabilityReason string

const (
	JudgmentApplicable             JudgmentApplicabilityReason = "applicable"
	JudgmentExpired                JudgmentApplicabilityReason = "expired"
	JudgmentRevoked                JudgmentApplicabilityReason = "revoked"
	JudgmentSituationTerminal      JudgmentApplicabilityReason = "situation_terminal"
	JudgmentScopeChanged           JudgmentApplicabilityReason = "scope_changed"
	JudgmentSymptomsChanged        JudgmentApplicabilityReason = "symptoms_changed"
	JudgmentSeverityChanged        JudgmentApplicabilityReason = "severity_changed"
	JudgmentImpactChanged          JudgmentApplicabilityReason = "impact_changed"
	JudgmentSourceSignatureChanged JudgmentApplicabilityReason = "source_signature_changed"
	JudgmentEvidenceMissing        JudgmentApplicabilityReason = "evidence_missing"
	JudgmentUrgent                 JudgmentApplicabilityReason = "urgent"
)

type JudgmentApplicability struct {
	Applicable bool                        `json:"applicable"`
	Reason     JudgmentApplicabilityReason `json:"reason"`
}

// ExpectedJudgmentProjection is the bounded active authority carried into
// the Situation history and Slack root.
type ExpectedJudgmentProjection struct {
	Revision         int       `json:"revision"`
	AssertedOperator string    `json:"asserted_operator"`
	ValidUntil       time.Time `json:"valid_until"`
}

// JudgmentChange is the typed meaningful transition rendered in the
// Situation thread. Invalidated covers changed facts, including urgency;
// the applicability reason remains available in MCP/history.
type JudgmentChange string

const (
	JudgmentChangeRecorded    JudgmentChange = "recorded"
	JudgmentChangeReplaced    JudgmentChange = "replaced"
	JudgmentChangeRevoked     JudgmentChange = "revoked"
	JudgmentChangeRestored    JudgmentChange = "restored"
	JudgmentChangeExpired     JudgmentChange = "expired"
	JudgmentChangeInvalidated JudgmentChange = "invalidated"
)
