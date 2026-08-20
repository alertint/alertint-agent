// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "time"

type Persistence string

const (
	PersistenceTransient Persistence = "transient"
	PersistenceSustained Persistence = "sustained"
	PersistenceUnknown   Persistence = "unknown"
)

type Impact string

const (
	ImpactNoneObserved Impact = "none_observed"
	ImpactSuspected    Impact = "suspected"
	ImpactConfirmed    Impact = "confirmed"
	ImpactUnknown      Impact = "unknown"
)

type Novelty string

const (
	NoveltyFamiliar            Novelty = "familiar"
	NoveltyChanged             Novelty = "changed"
	NoveltyNew                 Novelty = "new"
	NoveltyInsufficientHistory Novelty = "insufficient_history"
)

type Causality string

const (
	CausalitySupported         Causality = "supported"
	CausalityCorrelated        Causality = "correlated"
	CausalityContradicted      Causality = "contradicted"
	CausalityUnknown           Causality = "unknown"
	CausalityOperatorConfirmed Causality = "operator_confirmed"
)

type EvidenceQuality string

const (
	EvidenceQualityComplete     EvidenceQuality = "complete"
	EvidenceQualityDegraded     EvidenceQuality = "degraded"
	EvidenceQualityInsufficient EvidenceQuality = "insufficient"
)

type NextActor string

const (
	NextActorAlertint NextActor = "alertint"
	NextActorOperator NextActor = "operator"
	NextActorNone     NextActor = "none"
)

type ActionStatus string

const (
	ActionStatusPlanned   ActionStatus = "planned"
	ActionStatusRunning   ActionStatus = "running"
	ActionStatusBlocked   ActionStatus = "blocked"
	ActionStatusExhausted ActionStatus = "exhausted"
	ActionStatusComplete  ActionStatus = "complete"
	ActionStatusWaiting   ActionStatus = "waiting"
)

// SufficientReason names the deterministic eligible candidate selected for a
// material Assessment. CandidateID binds the selection to one snapshot.
type SufficientReason struct {
	Code         string   `json:"code"`
	CandidateID  string   `json:"candidate_id"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// ActionContract states who acts next and when AlertINT will update.
type ActionContract struct {
	NextActor                 NextActor    `json:"next_actor"`
	ActionStatus              ActionStatus `json:"action_status"`
	AlertintAction            *string      `json:"alertint_action,omitempty"`
	OperatorJudgmentRequested *string      `json:"operator_judgment_requested,omitempty"`
	OperatorActionRequired    *string      `json:"operator_action_required,omitempty"`
	NextUpdateAt              *time.Time   `json:"next_update_at,omitempty"`
	NextUpdateOn              []string     `json:"next_update_on,omitempty"`
	WaitReason                *string      `json:"wait_reason,omitempty"`
}

// Limitation preserves structured evidence limitations rather than collapsing
// unavailable, stale, or budget-limited evidence into a generic healthy state.
type Limitation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Assessment is the versioned authoritative controller contract. Lifecycle is
// included for self-contained replay but remains controller-owned.
type Assessment struct {
	SchemaVersion    int               `json:"schema_version"`
	Persistence      Persistence       `json:"persistence"`
	Impact           Impact            `json:"impact"`
	Novelty          Novelty           `json:"novelty"`
	Causality        Causality         `json:"causality"`
	Attention        Attention         `json:"attention"`
	Lifecycle        Lifecycle         `json:"lifecycle"`
	EvidenceQuality  EvidenceQuality   `json:"evidence_quality"`
	SufficientReason *SufficientReason `json:"sufficient_reason,omitempty"`
	ActionContract   ActionContract    `json:"action_contract"`
	Limitations      []Limitation      `json:"limitations"`
	ProposedCadence  Cadence           `json:"proposed_cadence"`
}
