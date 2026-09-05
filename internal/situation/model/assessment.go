// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AssessmentSchemaVersion is the only Assessment/AssessmentProposal schema
// version this build understands. Validate rejects any other value.
const AssessmentSchemaVersion = 1

// Persistence is the closed judgment of whether the condition behind a
// Situation is transient or holding steady.
type Persistence string

const (
	PersistenceTransient Persistence = "transient"
	PersistenceSustained Persistence = "sustained"
	PersistenceUnknown   Persistence = "unknown"
)

// Validate reports an error unless p is one of the closed Persistence
// values.
func (p Persistence) Validate() error {
	return validateEnum("persistence", p, PersistenceTransient, PersistenceSustained, PersistenceUnknown)
}

// Impact is the closed judgment of observed real-world impact.
type Impact string

const (
	ImpactNoneObserved Impact = "none_observed"
	ImpactSuspected    Impact = "suspected"
	ImpactConfirmed    Impact = "confirmed"
	ImpactUnknown      Impact = "unknown"
)

// Validate reports an error unless i is one of the closed Impact values.
func (i Impact) Validate() error {
	return validateEnum("impact", i, ImpactNoneObserved, ImpactSuspected, ImpactConfirmed, ImpactUnknown)
}

// Novelty is the closed judgment of how this Situation compares to prior
// history for the same identity.
type Novelty string

const (
	NoveltyFamiliar            Novelty = "familiar"
	NoveltyChanged             Novelty = "changed"
	NoveltyNew                 Novelty = "new"
	NoveltyInsufficientHistory Novelty = "insufficient_history"
)

// Validate reports an error unless n is one of the closed Novelty values.
func (n Novelty) Validate() error {
	return validateEnum("novelty", n, NoveltyFamiliar, NoveltyChanged, NoveltyNew, NoveltyInsufficientHistory)
}

// Causality is the closed strength of the claimed causal link between a
// candidate cause and the Situation's condition.
type Causality string

const (
	CausalitySupported         Causality = "supported"
	CausalityCorrelated        Causality = "correlated"
	CausalityContradicted      Causality = "contradicted"
	CausalityUnknown           Causality = "unknown"
	CausalityOperatorConfirmed Causality = "operator_confirmed"
)

// Validate reports an error unless c is one of the closed Causality values.
func (c Causality) Validate() error {
	return validateEnum("causality", c,
		CausalitySupported, CausalityCorrelated, CausalityContradicted, CausalityUnknown, CausalityOperatorConfirmed)
}

// EvidenceQuality is the closed judgment of how complete the evidence behind
// an Assessment is.
type EvidenceQuality string

const (
	EvidenceQualityComplete     EvidenceQuality = "complete"
	EvidenceQualityDegraded     EvidenceQuality = "degraded"
	EvidenceQualityInsufficient EvidenceQuality = "insufficient"
)

// Validate reports an error unless e is one of the closed EvidenceQuality
// values.
func (e EvidenceQuality) Validate() error {
	return validateEnum("evidence_quality", e, EvidenceQualityComplete, EvidenceQualityDegraded, EvidenceQualityInsufficient)
}

// NextActor is the closed party the Operator contract currently names as
// responsible for the next move.
type NextActor string

const (
	NextActorAlertINT NextActor = "alertint"
	NextActorOperator NextActor = "operator"
	NextActorNone     NextActor = "none"
)

// Validate reports an error unless a is one of the closed NextActor values.
func (a NextActor) Validate() error {
	return validateEnum("next_actor", a, NextActorAlertINT, NextActorOperator, NextActorNone)
}

// AlertINTAction is the closed set of controller-owned work the Operator
// contract can name as currently underway or planned. Never model-authored
// prose.
type AlertINTAction string

const (
	AlertINTActionRunAcuteTriage           AlertINTAction = "run_acute_triage"
	AlertINTActionRetrySituationAssessment AlertINTAction = "retry_situation_assessment"
	AlertINTActionMonitorSituation         AlertINTAction = "monitor_situation"
	AlertINTActionVerifyRecovery           AlertINTAction = "verify_recovery"
)

// Validate reports an error unless a is one of the closed AlertINTAction
// values.
func (a AlertINTAction) Validate() error {
	return validateEnum("alertint_action", a,
		AlertINTActionRunAcuteTriage, AlertINTActionRetrySituationAssessment,
		AlertINTActionMonitorSituation, AlertINTActionVerifyRecovery)
}

// AlertINTStatus is the closed lifecycle of the current AlertINTAction.
type AlertINTStatus string

const (
	AlertINTStatusPlanned   AlertINTStatus = "planned"
	AlertINTStatusRunning   AlertINTStatus = "running"
	AlertINTStatusWaiting   AlertINTStatus = "waiting"
	AlertINTStatusBlocked   AlertINTStatus = "blocked"
	AlertINTStatusExhausted AlertINTStatus = "exhausted"
	AlertINTStatusComplete  AlertINTStatus = "complete"
)

// Validate reports an error unless s is one of the closed AlertINTStatus
// values.
func (s AlertINTStatus) Validate() error {
	return validateEnum("alertint_status", s,
		AlertINTStatusPlanned, AlertINTStatusRunning, AlertINTStatusWaiting,
		AlertINTStatusBlocked, AlertINTStatusExhausted, AlertINTStatusComplete)
}

// OperatorAction is the closed set of actions the Operator contract can ask
// a human to take. Plan 2 has exactly one.
type OperatorAction string

const (
	OperatorActionInvestigateSituation OperatorAction = "investigate_situation"
)

// Validate reports an error unless o is one of the closed OperatorAction
// values.
func (o OperatorAction) Validate() error {
	return validateEnum("operator_action_required", o, OperatorActionInvestigateSituation)
}

// NextUpdateOn is one closed reconsideration-trigger code the Operator
// contract may promise as an earlier-than-next_update_at reconsideration
// point. It never replaces next_update_at.
type NextUpdateOn string

const (
	NextUpdateOnMaterialInput                NextUpdateOn = "material_input"
	NextUpdateOnTriageOutcome                NextUpdateOn = "triage_outcome"
	NextUpdateOnSourceResolution             NextUpdateOn = "source_resolution"
	NextUpdateOnSourceRefire                 NextUpdateOn = "source_refire"
	NextUpdateOnDependencyRecovery           NextUpdateOn = "dependency_recovery"
	NextUpdateOnAssessmentRetryDue           NextUpdateOn = "assessment_retry_due"
	NextUpdateOnRecoveryGraceExpired         NextUpdateOn = "recovery_grace_expired"
	NextUpdateOnLifecycleObservationDeadline NextUpdateOn = "lifecycle_observation_deadline"
)

// Validate reports an error unless o is one of the closed NextUpdateOn
// codes.
func (o NextUpdateOn) Validate() error {
	return validateEnum("next_update_on", o,
		NextUpdateOnMaterialInput, NextUpdateOnTriageOutcome, NextUpdateOnSourceResolution,
		NextUpdateOnSourceRefire, NextUpdateOnDependencyRecovery, NextUpdateOnAssessmentRetryDue,
		NextUpdateOnRecoveryGraceExpired, NextUpdateOnLifecycleObservationDeadline)
}

// WaitReason is the closed reason an AlertINTStatus of waiting or blocked is
// currently held.
type WaitReason string

const (
	WaitReasonAcuteTriageDecision WaitReason = "acute_triage_decision"
	WaitReasonAcuteTriageBackoff  WaitReason = "acute_triage_backoff"
	WaitReasonAssessmentRetry     WaitReason = "assessment_retry"
	WaitReasonAssessmentParked    WaitReason = "assessment_parked"
	WaitReasonSourceChange        WaitReason = "source_change"
	WaitReasonRecoveryGrace       WaitReason = "recovery_grace"
)

// Validate reports an error unless w is one of the closed WaitReason values.
func (w WaitReason) Validate() error {
	return validateEnum("wait_reason", w,
		WaitReasonAcuteTriageDecision, WaitReasonAcuteTriageBackoff, WaitReasonAssessmentRetry,
		WaitReasonAssessmentParked, WaitReasonSourceChange, WaitReasonRecoveryGrace)
}

// Cadence is the controller's internal reconsideration tempo. It is
// persisted machinery, not card content, and is never proposed by the
// model. The zero value ("") represents "no cadence", the only legal value
// for a terminal Assessment.
type Cadence string

const (
	CadenceFast   Cadence = "fast"
	CadenceNormal Cadence = "normal"
	CadenceSlow   Cadence = "slow"
)

// Validate reports an error unless c is "" (no cadence, terminal state only)
// or one of the closed Cadence values.
func (c Cadence) Validate() error {
	return validateEnum("cadence", c, Cadence(""), CadenceFast, CadenceNormal, CadenceSlow)
}

// AssessmentDerivation is the closed record of how an authoritative
// Assessment came to be.
type AssessmentDerivation string

const (
	DerivationModelValidated        AssessmentDerivation = "model_validated"
	DerivationDeterministic         AssessmentDerivation = "deterministic_controller"
	DerivationDeterministicFallback AssessmentDerivation = "deterministic_fallback"
	DerivationRevalidatedReuse      AssessmentDerivation = "revalidated_reuse"
)

// Validate reports an error unless d is one of the closed
// AssessmentDerivation values.
func (d AssessmentDerivation) Validate() error {
	return validateEnum("assessment_derivation", d,
		DerivationModelValidated, DerivationDeterministic, DerivationDeterministicFallback, DerivationRevalidatedReuse)
}

// ProviderRequestStarted records whether a call-backed outcome proved,
// disproved, or left ambiguous that a physical HTTP request reached the
// provider. It is conservative by construction: an outcome-less call under
// an expired claim records "unknown", never "false".
type ProviderRequestStarted string

const (
	ProviderRequestStartedTrue    ProviderRequestStarted = "true"
	ProviderRequestStartedFalse   ProviderRequestStarted = "false"
	ProviderRequestStartedUnknown ProviderRequestStarted = "unknown"
)

// Validate reports an error unless p is one of the closed
// ProviderRequestStarted values.
func (p ProviderRequestStarted) Validate() error {
	return validateEnum("provider_request_started", p,
		ProviderRequestStartedTrue, ProviderRequestStartedFalse, ProviderRequestStartedUnknown)
}

// SufficientReason is the accepted Sufficient reason recorded on an
// authoritative Assessment: the exact catalog candidate the controller (or,
// for an eligible candidate, the model) selected and explained, plus the
// evidence backing it. It mirrors ReasonCandidate's identity fields but
// names a selection, not a candidate offered for selection.
type SufficientReason struct {
	Code         string   `json:"code"`
	CandidateID  string   `json:"candidate_id"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// Validate checks the SufficientReason carries its required identity: a
// code and the exact candidate ID it was selected from. It does not check
// that the candidate is eligible or that the evidence refs exist in any
// snapshot — that authority check is Task 5's ValidateAssessmentProposal.
func (r SufficientReason) Validate() error {
	if r.Code == "" {
		return errors.New("model: sufficient_reason: code is required")
	}
	if r.CandidateID == "" {
		return errors.New("model: sufficient_reason: candidate_id is required")
	}
	return nil
}

// MarshalJSON canonicalizes EvidenceRefs to [] before marshaling: a
// nil-constructed SufficientReason must never serialize evidence_refs as
// JSON null.
func (r SufficientReason) MarshalJSON() ([]byte, error) {
	type sufficientReasonAlias SufficientReason
	a := sufficientReasonAlias(r)
	a.EvidenceRefs = canonicalizeSlice(a.EvidenceRefs)
	return json.Marshal(a)
}

// Limitation is one bounded, closed-code caveat attached to an Assessment,
// e.g. {"code": "semantic_assessment_unavailable", "detail": "..."}.
type Limitation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Validate checks the Limitation carries a code. Detail is free bounded
// text; Plan 2 defines no closed enum of limitation codes.
func (l Limitation) Validate() error {
	if l.Code == "" {
		return errors.New("model: limitation: code is required")
	}
	return nil
}

// ActionContract is the controller-owned Operator contract: who acts next,
// what AlertINT work is current, whether a human must act, and when the
// Situation is next due for reconsideration. It carries only closed codes,
// never model-authored action prose.
type ActionContract struct {
	NextActor              NextActor       `json:"next_actor"`
	AlertINTAction         *AlertINTAction `json:"alertint_action"`
	AlertINTStatus         *AlertINTStatus `json:"alertint_status"`
	OperatorActionRequired *OperatorAction `json:"operator_action_required"`
	NextUpdateAt           *time.Time      `json:"next_update_at"`
	NextUpdateOn           []NextUpdateOn  `json:"next_update_on"`
	WaitReason             *WaitReason     `json:"wait_reason"`
}

// MarshalJSON canonicalizes NextUpdateOn to [] before marshaling: a
// terminal (or nil-constructed) ActionContract must never serialize
// next_update_on as JSON null.
func (c ActionContract) MarshalJSON() ([]byte, error) {
	type actionContractAlias ActionContract
	a := actionContractAlias(c)
	a.NextUpdateOn = canonicalizeSlice(a.NextUpdateOn)
	return json.Marshal(a)
}

// validate checks ActionContract's closed codes, the next_actor/action
// consistency rule, and the terminal/nonterminal update-promise SHAPE —
// present (non-nil) for a nonterminal contract, absent for a terminal one.
// It never compares next_update_at against a wall clock; that freshness
// check is requireFreshNextUpdateAt below, kept separate so a caller can
// apply every shape/consistency rule without also rejecting on staleness
// alone (see Assessment.ValidateShape's doc comment for why that split
// matters). Deriving the correct values from controller state is Task 5's
// DeriveActionContract; this is a shape/consistency check only.
func (c ActionContract) validate(terminal bool) error {
	if err := c.NextActor.Validate(); err != nil {
		return fmt.Errorf("action_contract: %w", err)
	}
	if c.AlertINTAction != nil {
		if err := c.AlertINTAction.Validate(); err != nil {
			return fmt.Errorf("action_contract: %w", err)
		}
	}
	if c.AlertINTStatus != nil {
		if err := c.AlertINTStatus.Validate(); err != nil {
			return fmt.Errorf("action_contract: %w", err)
		}
	}
	if c.OperatorActionRequired != nil {
		if err := c.OperatorActionRequired.Validate(); err != nil {
			return fmt.Errorf("action_contract: %w", err)
		}
	}
	if c.WaitReason != nil {
		if err := c.WaitReason.Validate(); err != nil {
			return fmt.Errorf("action_contract: %w", err)
		}
	}
	for i, on := range c.NextUpdateOn {
		if err := on.Validate(); err != nil {
			return fmt.Errorf("action_contract: next_update_on[%d]: %w", i, err)
		}
	}

	// next_actor consistency: operator action wins even when AlertINT work
	// continues; otherwise a current AlertINT action makes it alertint;
	// otherwise terminal/no-action state makes it none.
	switch {
	case c.OperatorActionRequired != nil && c.NextActor != NextActorOperator:
		return fmt.Errorf("action_contract: next_actor must be %q when operator_action_required is set, got %q",
			NextActorOperator, c.NextActor)
	case c.OperatorActionRequired == nil && c.AlertINTAction != nil && c.NextActor != NextActorAlertINT:
		return fmt.Errorf("action_contract: next_actor must be %q when alertint_action is set without operator_action_required, got %q",
			NextActorAlertINT, c.NextActor)
	case c.OperatorActionRequired == nil && c.AlertINTAction == nil && c.NextActor != NextActorNone:
		return fmt.Errorf("action_contract: next_actor must be %q when neither operator_action_required nor alertint_action is set, got %q",
			NextActorNone, c.NextActor)
	}

	if terminal {
		if c.NextUpdateAt != nil {
			return errors.New("action_contract: terminal contract must not set next_update_at")
		}
		if len(c.NextUpdateOn) != 0 {
			return errors.New("action_contract: terminal contract must not set next_update_on")
		}
		return nil
	}
	if c.NextUpdateAt == nil {
		return errors.New("action_contract: nonterminal contract requires next_update_at")
	}
	return nil
}

// requireFreshNextUpdateAt additionally checks that a nonterminal contract's
// next_update_at promise is still strictly in the future relative to now.
// A terminal contract carries no next_update_at (validate above already
// guarantees that), so this trivially passes it. Kept separate from
// validate so a caller can check shape/consistency alone without also
// judging whether a PRIOR contract's own timing promise has since elapsed —
// see Assessment.ValidateShape.
func (c ActionContract) requireFreshNextUpdateAt(now time.Time) error {
	if c.NextUpdateAt == nil {
		return nil
	}
	if !c.NextUpdateAt.After(now) {
		return fmt.Errorf("action_contract: next_update_at %s must be after %s", c.NextUpdateAt, now)
	}
	return nil
}

// Assessment is one authoritative, versioned assessment of a Situation.
// Lifecycle, the Operator contract, and Cadence are exclusively derived by
// the controller — never proposed by the model. See AssessmentProposal for
// the L2-authored subset.
type Assessment struct {
	SchemaVersion    int               `json:"schema_version"`
	Persistence      Persistence       `json:"persistence"`
	Impact           Impact            `json:"impact"`
	Novelty          Novelty           `json:"novelty"`
	Causality        Causality         `json:"causality"`
	Attention        Attention         `json:"attention"`
	Lifecycle        Lifecycle         `json:"lifecycle"`
	EvidenceQuality  EvidenceQuality   `json:"evidence_quality"`
	SufficientReason *SufficientReason `json:"sufficient_reason"`
	ActionContract   ActionContract    `json:"action_contract"`
	Limitations      []Limitation      `json:"limitations"`
	Cadence          Cadence           `json:"cadence"`
}

// MarshalJSON canonicalizes Limitations to [] before marshaling: a
// nil-constructed Assessment must never serialize limitations as JSON
// null. The nested ActionContract and SufficientReason canonicalize their
// own slice fields via their own MarshalJSON methods.
func (a Assessment) MarshalJSON() ([]byte, error) {
	type assessmentAlias Assessment
	out := assessmentAlias(a)
	out.Limitations = canonicalizeSlice(out.Limitations)
	return json.Marshal(out)
}

// Validate checks that every Assessment field carries a known closed value
// and that the Operator contract is internally consistent: closed
// actor/action/status/next_update_on/wait_reason codes, a nonterminal
// contract with a future next_update_at versus a terminal one with neither
// update field, and a terminal Lifecycle carrying Cadence("") versus a
// nonterminal one requiring a non-empty Cadence. now anchors the "future"
// check. This is a shape/consistency check only — evidence authority,
// controller-derived contract/cadence values, and stale-input validation
// are Task 5's job (ValidateAssessmentProposal, DeriveActionContract,
// DeriveCadence).
func (a Assessment) Validate(now time.Time) error {
	if err := a.validateShape(); err != nil {
		return err
	}
	if err := a.ActionContract.requireFreshNextUpdateAt(now); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	return nil
}

// ValidateShape checks every rule Validate checks — closed enums, schema
// version, the Operator contract's actor/action consistency, the terminal/
// nonterminal update-field SHAPE, and the terminal/nonterminal Cadence
// split — EXCEPT it never compares the Operator contract's next_update_at
// against a current wall clock.
//
// It exists for reuse-eligibility checks against a PRIOR authoritative
// Assessment (internal/situation's RevalidateReuse/trustworthy). spec.md's
// reuse section is explicit that the controller "never copies a stale
// next_update_at" — it always recomputes the Operator contract fresh for
// the new input — so a prior Assessment's OWN next_update_at promise having
// already elapsed by the time reuse is actually evaluated (the whole point
// of reuse: a LATER reconciliation revisiting an unchanged basis) is
// expected, not a defect, and must never by itself make an otherwise
// well-formed, semantically valid prior ineligible for reuse. Every other
// closed-shape/consistency rule Validate enforces — unknown enums,
// actor/action inconsistency, a missing required field, a terminal/
// nonterminal Cadence mismatch — still applies here unchanged; only the
// single next_update_at-vs-now freshness comparison is skipped.
func (a Assessment) ValidateShape() error {
	return a.validateShape()
}

func (a Assessment) validateShape() error {
	if a.SchemaVersion != AssessmentSchemaVersion {
		return fmt.Errorf("assessment: schema_version %d unsupported (want %d)", a.SchemaVersion, AssessmentSchemaVersion)
	}
	if err := a.Persistence.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Impact.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Novelty.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Causality.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Attention.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Lifecycle.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.EvidenceQuality.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if err := a.Cadence.Validate(); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	if a.SufficientReason != nil {
		if err := a.SufficientReason.Validate(); err != nil {
			return fmt.Errorf("assessment: %w", err)
		}
	}
	for i, l := range a.Limitations {
		if err := l.Validate(); err != nil {
			return fmt.Errorf("assessment: limitations[%d]: %w", i, err)
		}
	}

	terminal := a.Lifecycle.Terminal()

	// Cadence terminal/nonterminal shape: "" is the only legal value for a
	// terminal Assessment (no future reconsideration is ever scheduled), and
	// a nonterminal Assessment must always carry a live cadence.
	switch {
	case terminal && a.Cadence != Cadence(""):
		return fmt.Errorf("assessment: terminal assessment must not set cadence, got %q", a.Cadence)
	case !terminal && a.Cadence == Cadence(""):
		return errors.New("assessment: nonterminal assessment requires a cadence")
	}

	if err := a.ActionContract.validate(terminal); err != nil {
		return fmt.Errorf("assessment: %w", err)
	}
	return nil
}

// AssessmentProposal is the only L2-authored shape. Lifecycle, the Operator
// contract (ActionContract), and Cadence are deliberately absent from the Go
// struct — the model cannot propose them regardless of what a raw JSON
// response carries, and the controller exclusively derives them.
type AssessmentProposal struct {
	SchemaVersion    int               `json:"schema_version"`
	Persistence      Persistence       `json:"persistence"`
	Impact           Impact            `json:"impact"`
	Novelty          Novelty           `json:"novelty"`
	Causality        Causality         `json:"causality"`
	Attention        Attention         `json:"attention"`
	SufficientReason *SufficientReason `json:"sufficient_reason"`
	Limitations      []Limitation      `json:"limitations"`
}

// MarshalJSON canonicalizes Limitations to [] before marshaling: a
// nil-constructed AssessmentProposal must never serialize limitations as
// JSON null.
func (p AssessmentProposal) MarshalJSON() ([]byte, error) {
	type assessmentProposalAlias AssessmentProposal
	out := assessmentProposalAlias(p)
	out.Limitations = canonicalizeSlice(out.Limitations)
	return json.Marshal(out)
}

// Validate checks that every AssessmentProposal field carries a known
// closed value. It is a shape check only: whether a SufficientReason
// candidate is actually eligible, whether cited evidence exists in the
// snapshot, and whether causality strength is supported by that evidence
// are Task 5's ValidateAssessmentProposal concerns, not this method's.
func (p AssessmentProposal) Validate() error {
	if p.SchemaVersion != AssessmentSchemaVersion {
		return fmt.Errorf("assessment_proposal: schema_version %d unsupported (want %d)", p.SchemaVersion, AssessmentSchemaVersion)
	}
	if err := p.Persistence.Validate(); err != nil {
		return fmt.Errorf("assessment_proposal: %w", err)
	}
	if err := p.Impact.Validate(); err != nil {
		return fmt.Errorf("assessment_proposal: %w", err)
	}
	if err := p.Novelty.Validate(); err != nil {
		return fmt.Errorf("assessment_proposal: %w", err)
	}
	if err := p.Causality.Validate(); err != nil {
		return fmt.Errorf("assessment_proposal: %w", err)
	}
	if err := p.Attention.Validate(); err != nil {
		return fmt.Errorf("assessment_proposal: %w", err)
	}
	if p.SufficientReason != nil {
		if err := p.SufficientReason.Validate(); err != nil {
			return fmt.Errorf("assessment_proposal: %w", err)
		}
	}
	for i, l := range p.Limitations {
		if err := l.Validate(); err != nil {
			return fmt.Errorf("assessment_proposal: limitations[%d]: %w", i, err)
		}
	}
	return nil
}

// IncidentCoverage is the canonical bounded coverage tuple an authoritative
// Assessment records for each Incident it covers: the Incident ID plus the
// exact membership and Incident-input digests current at Assessment time.
type IncidentCoverage struct {
	IncidentID          string `json:"incident_id"`
	MembershipDigest    string `json:"membership_digest"`
	IncidentInputDigest string `json:"incident_input_digest"`
}
