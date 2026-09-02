// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 5: validate, derive, reuse, and fall back Assessments. Every function
// in this file is pure — no I/O, no provider calls, no persistence. It
// consumes the bounded Snapshot/SnapshotInput Task 4 built and the durable
// controller/Triage/lifecycle state a caller (Task 8's Reconcile) already
// knows, and produces AssessmentResult values plus typed validation/outcome
// classifications. It never computes lifecycle transitions, Triage
// scheduling, or retry/checkpoint timing itself — those remain Task 8's
// (Reconcile/lifecycle.go's) job; this file's functions take that state as
// parameters.
//
// NOTE on internal/llmhealth: this file deliberately does NOT import
// internal/llmhealth even though its Classify/Reason vocabulary is exactly
// what ClassifyL2Outcome's transport-failure branch wants. internal/llmhealth
// imports internal/store, and internal/store imports internal/situation
// (controller.go's own package doc: "must never import internal/store") —
// importing llmhealth here would close an import cycle. The small local
// classification below intentionally mirrors llmhealth.Classify's
// timeout/network/rate-limit/malformed distinctions without reusing its code.
// ----------------------------------------------------------------------

// AssessmentResult is one pure-derived Assessment outcome — a controller
// commit's not-yet-persisted equivalent of controller.go's AssessmentAttempt/
// AuthoritativeAssessment: everything this file's pure functions can produce
// (content, derivation, basis/material hashes, input version, and bounded
// per-Incident coverage) without a durable row ID, CallID, or
// CreatedAt/CompletedAt — those only exist once Task 8's CommitController
// persists the row.
type AssessmentResult struct {
	Assessment             model.Assessment
	Derivation             model.AssessmentDerivation
	AssessmentBasisHash    string
	MaterialFactHash       string
	InputVersion           int
	Coverage               []model.IncidentCoverage
	ReusedFromAssessmentID *string
}

// ----------------------------------------------------------------------
// ControllerState: the durable controller/Triage/lifecycle state
// DeriveActionContract and DeriveCadence derive from. Never computed here —
// Task 8's Reconcile/lifecycle.go supplies it.
// ----------------------------------------------------------------------

// TriagePhase is the aggregate cross-Incident Acute Triage posture
// DeriveActionContract reads to pick the closed AlertINTAction/Status pair
// spec.md's Operator-contract table names. TriagePhaseNone means no member
// Incident has AlertINT Triage work pending, running, or backing off.
type TriagePhase int

const (
	TriagePhaseNone TriagePhase = iota
	TriagePhaseAwaitingDecision
	TriagePhaseInFlight
	TriagePhaseBackoff
)

// SemanticRetryPhase is the controller-owned L2 retry/park posture
// DeriveActionContract reads for the "semantic retry" row of spec.md's
// Operator-contract table: whether a bounded semantic retry is currently due
// (dispatches bounded L2 work), or parked (blocked — no further automatic
// calls until an admissible reconsideration event).
// SemanticRetryPhaseNone means a validated Assessment stands; no retry
// machinery applies.
type SemanticRetryPhase int

const (
	SemanticRetryPhaseNone SemanticRetryPhase = iota
	SemanticRetryPhaseDue
	SemanticRetryPhaseBlocked
)

// ControllerState is the durable controller/Triage/lifecycle state
// DeriveActionContract and DeriveCadence derive the Operator contract and
// cadence from. Task 5's pure functions never compute lifecycle transitions,
// Triage scheduling, or retry/checkpoint timing themselves; this struct is
// the bounded interface between "durable state already known" and
// "contract/cadence derivation."
//
// Lifecycle, Attention, and OperatorActionRequired are set by DeriveAssessment
// itself from the composed Assessment's own Lifecycle/Attention/
// SufficientReason before calling DeriveActionContract/DeriveCadence — a
// caller building ControllerState directly (as the DeriveActionContract/
// DeriveCadence unit tests do) sets them explicitly instead.
type ControllerState struct {
	Lifecycle              model.Lifecycle
	Attention              model.Attention
	OperatorActionRequired *model.OperatorAction

	TriagePhase   TriagePhase
	SemanticRetry SemanticRetryPhase

	// TriageDueAt, SemanticRetryAt, RecoveryGraceUntil,
	// LifecycleObservationDeadlineAt, and EarliestPersistedCheckpoint are
	// candidate reconsideration times DeriveActionContract's next_update_at
	// picks the earliest nonterminal one from — never computed here. Any
	// combination may be nil.
	TriageDueAt                    *time.Time
	SemanticRetryAt                *time.Time
	RecoveryGraceUntil             *time.Time
	LifecycleObservationDeadlineAt *time.Time
	EarliestPersistedCheckpoint    *time.Time
}

// Plan 2's cadence tempo. spec.md pins the relative ordering
// (fast < normal < slow) and the branch conditions but no exact durations;
// these are a Task 5 default, adjustable later without affecting Assessment
// validity — only next_update_at scheduling.
const (
	cadenceFastInterval   = 2 * time.Minute
	cadenceNormalInterval = 5 * time.Minute
	cadenceSlowInterval   = 15 * time.Minute

	// minNextUpdateLead is the minimum lead DeriveActionContract clamps
	// next_update_at to when every earliest-of candidate is already due
	// (<= now) — e.g. an overdue retry checkpoint at claim time. The
	// contract requires a genuinely future time (model.ActionContract.validate);
	// an already-due checkpoint means "immediately," which this clamp
	// represents as the smallest meaningful future offset rather than
	// rejecting the derivation.
	minNextUpdateLead = time.Second
)

func cadenceInterval(c model.Cadence) time.Duration {
	switch c {
	case model.CadenceFast:
		return cadenceFastInterval
	case model.CadenceNormal:
		return cadenceNormalInterval
	case model.CadenceSlow:
		return cadenceSlowInterval
	default:
		// Cadence("") (terminal) never reaches nextUpdateAt's cadenceInterval
		// call — DeriveActionContract returns before computing next_update_at
		// for a terminal lifecycle. Slow is the safe, defensive fallback.
		return cadenceSlowInterval
	}
}

// DeriveCadence derives Plan 2's internal reconsideration tempo from durable
// controller/Triage/lifecycle state alone (spec.md "Lifecycle, Attention, and
// cadence"): fast for urgent, recovery-pending, or durably running AlertINT
// work (Triage actually in flight); normal for investigate; slow for active
// observe, waiting, blocked, or parked state. Terminal lifecycle has no
// cadence. Cadence is persisted internal machinery, never card content, and
// is never proposed by the model — this function's only inputs are
// controller-owned state.
func DeriveCadence(state ControllerState) model.Cadence {
	if state.Lifecycle.Terminal() {
		return model.Cadence("")
	}
	switch {
	case state.Attention == model.AttentionUrgent:
		return model.CadenceFast
	case state.Lifecycle == model.LifecycleRecoveryPending:
		return model.CadenceFast
	case state.TriagePhase == TriagePhaseInFlight:
		return model.CadenceFast
	case state.Attention == model.AttentionInvestigate:
		return model.CadenceNormal
	default:
		return model.CadenceSlow
	}
}

// alertINTBranch is one closed (AlertINTAction, AlertINTStatus, WaitReason)
// triple DeriveActionContract's priority list can select.
type alertINTBranch struct {
	action     *model.AlertINTAction
	status     *model.AlertINTStatus
	waitReason *model.WaitReason
}

func actionPtr(a model.AlertINTAction) *model.AlertINTAction { return &a }
func statusPtr(s model.AlertINTStatus) *model.AlertINTStatus { return &s }
func waitPtr(w model.WaitReason) *model.WaitReason           { return &w }

// deriveAlertINTBranch picks the closed AlertINTAction/Status/WaitReason
// triple from durable state, per spec.md's Operator-contract table, in fixed
// priority order: AlertINT Triage machinery (awaiting_decision, in_flight,
// backoff) outranks the controller's own semantic-retry machinery, which
// outranks lifecycle recovery-pending, which outranks the default "nothing
// left to do" observe/monitor branch. A terminal lifecycle carries no
// AlertINT work at all, regardless of any other flag — a defensive guard;
// callers should never set Triage/SemanticRetry state against a terminal
// Situation.
//
// WaitReason is set only for a Waiting or Blocked status, per its own model
// doc comment ("the closed reason an AlertINTStatus of waiting or blocked is
// currently held") — awaiting_decision (status=planned) and in_flight
// (status=running) therefore carry no wait reason. This leaves
// WaitReasonAcuteTriageDecision unreachable from this function, mirroring
// the reserved-but-unreachable reason-catalog codes reasons.go already
// documents; see the Task 5 report for the full reasoning.
func deriveAlertINTBranch(state ControllerState) alertINTBranch {
	if state.Lifecycle.Terminal() {
		return alertINTBranch{}
	}
	switch {
	case state.TriagePhase == TriagePhaseAwaitingDecision:
		return alertINTBranch{action: actionPtr(model.AlertINTActionRunAcuteTriage), status: statusPtr(model.AlertINTStatusPlanned)}
	case state.TriagePhase == TriagePhaseInFlight:
		return alertINTBranch{action: actionPtr(model.AlertINTActionRunAcuteTriage), status: statusPtr(model.AlertINTStatusRunning)}
	case state.TriagePhase == TriagePhaseBackoff:
		return alertINTBranch{action: actionPtr(model.AlertINTActionRunAcuteTriage), status: statusPtr(model.AlertINTStatusWaiting), waitReason: waitPtr(model.WaitReasonAcuteTriageBackoff)}
	case state.SemanticRetry == SemanticRetryPhaseDue:
		return alertINTBranch{action: actionPtr(model.AlertINTActionRetrySituationAssessment), status: statusPtr(model.AlertINTStatusWaiting), waitReason: waitPtr(model.WaitReasonAssessmentRetry)}
	case state.SemanticRetry == SemanticRetryPhaseBlocked:
		return alertINTBranch{action: actionPtr(model.AlertINTActionRetrySituationAssessment), status: statusPtr(model.AlertINTStatusBlocked), waitReason: waitPtr(model.WaitReasonAssessmentParked)}
	case state.Lifecycle == model.LifecycleRecoveryPending:
		return alertINTBranch{action: actionPtr(model.AlertINTActionVerifyRecovery), status: statusPtr(model.AlertINTStatusWaiting), waitReason: waitPtr(model.WaitReasonRecoveryGrace)}
	default:
		return alertINTBranch{action: actionPtr(model.AlertINTActionMonitorSituation), status: statusPtr(model.AlertINTStatusWaiting), waitReason: waitPtr(model.WaitReasonSourceChange)}
	}
}

// actorFor derives the closed next_actor per spec.md: operator action makes
// next_actor=operator even when AlertINT work continues; otherwise a current
// AlertINT action makes it alertint, and terminal/no-action state makes it
// none.
func actorFor(operatorRequired *model.OperatorAction, alertAction *model.AlertINTAction) model.NextActor {
	switch {
	case operatorRequired != nil:
		return model.NextActorOperator
	case alertAction != nil:
		return model.NextActorAlertINT
	default:
		return model.NextActorNone
	}
}

// nextUpdateAt is the earliest of now+cadence and every non-nil candidate
// checkpoint in state (spec.md: "the earliest of now + cadence, Triage due
// time, L2 retry time, recovery-grace expiry, lifecycle-observation
// deadline, or any concurrently persisted earlier checkpoint"), clamped
// forward to at least minNextUpdateLead past now so an already-due candidate
// still satisfies the contract's future-time requirement.
func nextUpdateAt(state ControllerState, cadence model.Cadence, now time.Time) time.Time {
	earliest := now.Add(cadenceInterval(cadence))
	for _, t := range []*time.Time{
		state.TriageDueAt, state.SemanticRetryAt, state.RecoveryGraceUntil,
		state.LifecycleObservationDeadlineAt, state.EarliestPersistedCheckpoint,
	} {
		if t != nil && t.Before(earliest) {
			earliest = *t
		}
	}
	if !earliest.After(now) {
		earliest = now.Add(minNextUpdateLead)
	}
	return earliest
}

// nextUpdateOn derives the closed set of earlier-reconsideration promise
// codes from which candidate checkpoints are actually present in state.
// EarliestPersistedCheckpoint maps to material_input: spec.md's own example
// of a concurrently-persisted-earlier checkpoint is a newer material input
// landing mid-cycle. It never replaces next_update_at (nextUpdateAt above
// already folds every one of these candidates into that single time); this
// only names which of them apply.
func nextUpdateOn(state ControllerState) []model.NextUpdateOn {
	var out []model.NextUpdateOn
	if state.TriageDueAt != nil {
		out = append(out, model.NextUpdateOnTriageOutcome)
	}
	if state.SemanticRetryAt != nil {
		out = append(out, model.NextUpdateOnAssessmentRetryDue)
	}
	if state.RecoveryGraceUntil != nil {
		out = append(out, model.NextUpdateOnRecoveryGraceExpired)
	}
	if state.LifecycleObservationDeadlineAt != nil {
		out = append(out, model.NextUpdateOnLifecycleObservationDeadline)
	}
	if state.EarliestPersistedCheckpoint != nil {
		out = append(out, model.NextUpdateOnMaterialInput)
	}
	return out
}

// DeriveActionContract derives the controller-owned Operator contract from
// durable controller/Triage/lifecycle state alone — never from a model
// proposal (AssessmentProposal has no action/contract fields at all, so
// model-authored action prose cannot reach this function by construction).
// It combines deriveAlertINTBranch's closed AlertINTAction/Status/WaitReason
// triple with state.OperatorActionRequired (already decided by the caller —
// DeriveAssessment computes it from the composed Assessment's own accepted
// Sufficient reason and Attention; see operatorActionRequired), and derives
// next_actor and the terminal/nonterminal next_update_at/next_update_on
// shape per spec.md.
func DeriveActionContract(state ControllerState, cadence model.Cadence, now time.Time) model.ActionContract {
	branch := deriveAlertINTBranch(state)
	contract := model.ActionContract{
		NextActor:              actorFor(state.OperatorActionRequired, branch.action),
		AlertINTAction:         branch.action,
		AlertINTStatus:         branch.status,
		OperatorActionRequired: state.OperatorActionRequired,
		WaitReason:             branch.waitReason,
	}
	if state.Lifecycle.Terminal() {
		return contract
	}
	at := nextUpdateAt(state, cadence, now)
	contract.NextUpdateAt = &at
	contract.NextUpdateOn = nextUpdateOn(state)
	return contract
}

// ----------------------------------------------------------------------
// Evidence quality: derived from evidence availability alone (Snapshot's
// own material Facts), never from LLM/provider health — spec.md's
// deterministic-fallback section is explicit that "LLM dependency health is
// installation-level and never changes evidence quality," and this same
// derivation serves every derivation path (model-validated, deterministic,
// fallback, reuse) uniformly, so there is structurally no LLM-health input
// this function could read even if it wanted to.
// ----------------------------------------------------------------------

// DeriveEvidenceQuality reduces snap's material Facts' ResultStatus mix to
// the closed EvidenceQuality judgment: complete when every material fact
// confirmed a value or a confirmed-empty result, insufficient when none did,
// degraded otherwise. Non-material facts (e.g. Triage scheduling machinery)
// are excluded, matching MaterialFactHash's own materiality scope.
func DeriveEvidenceQuality(snap Snapshot) model.EvidenceQuality {
	total, confirmed := 0, 0
	for _, f := range snap.Facts {
		if !f.Material {
			continue
		}
		total++
		if f.ResultStatus == model.FactConfirmedValue || f.ResultStatus == model.FactConfirmedEmpty {
			confirmed++
		}
	}
	switch {
	case total == 0 || confirmed == 0:
		return model.EvidenceQualityInsufficient
	case confirmed == total:
		return model.EvidenceQualityComplete
	default:
		return model.EvidenceQualityDegraded
	}
}

// ----------------------------------------------------------------------
// Reason-candidate lookup helpers shared by validation, reuse, and
// deterministic derivation.
// ----------------------------------------------------------------------

func findEligibleCandidateByID(candidates []model.ReasonCandidate, id string) (model.ReasonCandidate, bool) {
	for _, c := range candidates {
		if c.ID == id {
			return c, true
		}
	}
	return model.ReasonCandidate{}, false
}

func findEligibleCandidateByCode(candidates []model.ReasonCandidate, code string) (model.ReasonCandidate, bool) {
	for _, c := range candidates {
		if c.Code == code {
			return c, true
		}
	}
	return model.ReasonCandidate{}, false
}

func findFloorCandidate(candidates []model.ReasonCandidate) (model.ReasonCandidate, bool) {
	for _, c := range candidates {
		if c.DeterministicFloor {
			return c, true
		}
	}
	return model.ReasonCandidate{}, false
}

func hasDeterministicFloor(candidates []model.ReasonCandidate) bool {
	_, ok := findFloorCandidate(candidates)
	return ok
}

func factExists(facts []model.Fact, id string) bool {
	for _, f := range facts {
		if f.ID == id {
			return true
		}
	}
	return false
}

// operatorActionRequired derives the closed Operator-contract human-action
// code from the composed Assessment's own accepted Sufficient reason and
// Attention. spec.md's Sufficient-reason catalog section: "critical_anchor is
// the only reachable deterministic urgent floor in this slice. Other
// reachable candidates make a non-critical reason admissible; they do not
// authorize a model to invent urgency or an operator action." Admissible
// therefore means: a validated, non-floor Sufficient reason accepted while
// Attention is investigate. The floor reason itself (critical_anchor) never
// produces an operator question — its own urgency already drives AlertINT's
// automated response (run_acute_triage), not a human one. Plan 2 defines
// exactly one Operator action; a later plan's catalog growth may need a
// richer mapping.
func operatorActionRequired(reason *model.SufficientReason, eligible []model.ReasonCandidate, attention model.Attention) *model.OperatorAction {
	if reason == nil || attention != model.AttentionInvestigate {
		return nil
	}
	candidate, found := findEligibleCandidateByID(eligible, reason.CandidateID)
	if !found || candidate.DeterministicFloor {
		return nil
	}
	action := model.OperatorActionInvestigateSituation
	return &action
}

// DeriveIncidentCoverage computes the canonical bounded coverage tuple
// (spec.md / model.IncidentCoverage) for every member Incident of in, sorted
// by Incident ID: the exact MembershipDigest and IncidentInputDigest current
// for THIS SnapshotInput. Every derivation path (model-validated,
// deterministic, fallback, and reuse) calls this fresh against the current
// SnapshotInput — never copies a prior Assessment's coverage rows, which
// spec.md's reuse section forbids explicitly ("Reuse rebinds coverage to the
// new input; it never copies stale coverage metadata").
func DeriveIncidentCoverage(in SnapshotInput) []model.IncidentCoverage {
	incidents := sortIncidentsByID(in.Incidents)
	out := make([]model.IncidentCoverage, 0, len(incidents))
	for _, inc := range incidents {
		out = append(out, model.IncidentCoverage{
			IncidentID:          inc.ID,
			MembershipDigest:    MembershipDigest(inc.ID, in.Deliveries),
			IncidentInputDigest: IncidentInputDigest(inc.ID, inc.GroupKey, in.Deliveries),
		})
	}
	return out
}

// ----------------------------------------------------------------------
// DeriveAssessment: the single composer every derivation path (model-
// validated, deterministic, fallback, reuse) uses to build the final
// AssessmentResult from a validated/adjusted semantic proposal.
// ----------------------------------------------------------------------

// DeriveAssessment composes one AssessmentResult from a validated/adjusted
// semantic proposal, the Snapshot/SnapshotInput it was validated against,
// durable controller/Triage/lifecycle state, and the derivation tag the
// caller has already decided. It is the single place every path composes the
// controller-owned fields (Lifecycle passthrough, EvidenceQuality,
// ActionContract, Cadence, OperatorActionRequired) and the bounded
// per-Incident coverage tuple — never copying stale coverage or
// ActionContract timing from any prior row. state's own Lifecycle/Attention/
// OperatorActionRequired fields are overwritten here from snap and proposal;
// a caller need not (and should not) pre-populate them.
func DeriveAssessment(proposal model.AssessmentProposal, snap Snapshot, in SnapshotInput, state ControllerState, derivation model.AssessmentDerivation, reusedFrom *string, now time.Time) AssessmentResult {
	state.Lifecycle = snap.Lifecycle
	state.Attention = proposal.Attention
	state.OperatorActionRequired = operatorActionRequired(proposal.SufficientReason, snap.EligibleReasons, proposal.Attention)

	cadence := DeriveCadence(state)
	contract := DeriveActionContract(state, cadence, now)
	quality := DeriveEvidenceQuality(snap)

	assessment := model.Assessment{
		SchemaVersion:    model.AssessmentSchemaVersion,
		Persistence:      proposal.Persistence,
		Impact:           proposal.Impact,
		Novelty:          proposal.Novelty,
		Causality:        proposal.Causality,
		Attention:        proposal.Attention,
		Lifecycle:        snap.Lifecycle,
		EvidenceQuality:  quality,
		SufficientReason: proposal.SufficientReason,
		ActionContract:   contract,
		Limitations:      proposal.Limitations,
		Cadence:          cadence,
	}

	return AssessmentResult{
		Assessment:             assessment,
		Derivation:             derivation,
		AssessmentBasisHash:    snap.AssessmentBasisHash,
		MaterialFactHash:       snap.MaterialFactHash,
		InputVersion:           snap.InputVersion,
		Coverage:               DeriveIncidentCoverage(in),
		ReusedFromAssessmentID: reusedFrom,
	}
}

// ----------------------------------------------------------------------
// Deterministic Assessment / fallback.
// ----------------------------------------------------------------------

const limitationSemanticAssessmentUnavailable = "semantic_assessment_unavailable"

// DeterministicAssessment builds a controller-authored Assessment with no L2
// involvement: conservative default semantic fields (persistence=unknown,
// impact=none_observed, novelty=insufficient_history, causality=unknown)
// wherever the state does not deterministically establish something
// stronger, Attention raised only to a proven deterministic floor — never
// invented, and never lowered below whatever floor is proven — and every
// controller-owned field derived exactly as DeriveAssessment derives them for
// a model-validated Assessment. It is Plan 2's shared deterministic-
// Assessment constructor: DeterministicFallback (the "L2 failed" case) is a
// thin wrapper that also attaches the semantic_assessment_unavailable
// limitation; a later task's terminal-closure Assessment (no L2 involvement
// needed because the Situation concluded, not because L2 failed) can call
// this directly with no extra limitation.
func DeterministicAssessment(snap Snapshot, in SnapshotInput, state ControllerState, derivation model.AssessmentDerivation, limitations []model.Limitation, now time.Time) AssessmentResult {
	attention := model.AttentionObserve
	var sufficientReason *model.SufficientReason
	if floorCandidate, floor := findFloorCandidate(snap.EligibleReasons); floor {
		attention = model.AttentionUrgent
		sufficientReason = &model.SufficientReason{
			Code:         floorCandidate.Code,
			CandidateID:  floorCandidate.ID,
			Summary:      floorCandidate.Summary,
			EvidenceRefs: append([]string(nil), floorCandidate.EvidenceRefs...),
		}
	}

	proposal := model.AssessmentProposal{
		SchemaVersion:    model.AssessmentSchemaVersion,
		Persistence:      model.PersistenceUnknown,
		Impact:           model.ImpactNoneObserved,
		Novelty:          model.NoveltyInsufficientHistory,
		Causality:        model.CausalityUnknown,
		Attention:        attention,
		SufficientReason: sufficientReason,
		Limitations:      limitations,
	}
	return DeriveAssessment(proposal, snap, in, state, derivation, nil, now)
}

// DeterministicFallback builds the controller-authored Assessment spec.md's
// "Deterministic fallback when L2 is unavailable" section requires when L2
// fails and no prior trustworthy Assessment exists: current lifecycle and
// source/store facts (via DeriveAssessment's normal Lifecycle passthrough and
// coverage derivation), conservative impact/novelty/causality, evidence
// quality derived from evidence availability alone (DeriveEvidenceQuality
// never reads LLM health), a deterministic urgent floor when one exists —
// else observe, because non-critical eligible reasons still require a
// validated L2 judgment — the semantic_assessment_unavailable limitation, and
// an Operator contract carrying the bounded model retry or next deterministic
// checkpoint via state.SemanticRetry (the caller sets Due while bounded work
// remains, Blocked once parked).
func DeterministicFallback(snap Snapshot, in SnapshotInput, state ControllerState, now time.Time) AssessmentResult {
	limitations := []model.Limitation{{
		Code:   limitationSemanticAssessmentUnavailable,
		Detail: "L2 failed and no trustworthy prior Assessment exists; this Assessment is controller-authored.",
	}}
	return DeterministicAssessment(snap, in, state, model.DerivationDeterministicFallback, limitations, now)
}

// ----------------------------------------------------------------------
// RevalidateReuse: spec.md "Assessment reuse across input versions."
// ----------------------------------------------------------------------

// ReuseResult is RevalidateReuse's outcome: either a fresh AssessmentResult
// bound to the new input (Ok, Derivation=revalidated_reuse), or a false Ok
// naming which trustworthiness/guard/revalidation check failed.
type ReuseResult struct {
	Result AssessmentResult
	Ok     bool
	Reason string
}

// trustworthy reports whether prior is eligible as a reuse source at all,
// per spec.md's Trustworthiness section: model-validated or deterministically
// complete for the reused fields (deterministic_controller and
// revalidated_reuse both qualify; deterministic_fallback never does — every
// fallback carries semantic_assessment_unavailable for its semantic fields by
// construction, spec.md: "that fallback is never a semantic reuse source"),
// and still passing the current schema/Operator-contract validators. Whether
// prior "was authoritative for its exact input" and "has not been superseded
// by a newer current Assessment" is the caller's responsibility: prior must
// be the Situation's own current AuthoritativeAssessment (Task 8's job to
// fetch) — a pure function has no way to independently verify either
// property offline.
func trustworthy(prior AuthoritativeAssessment, now time.Time) (string, bool) {
	if prior.Derivation == model.DerivationDeterministicFallback {
		return "fallback_not_a_semantic_reuse_source", false
	}
	if err := prior.Assessment.Validate(now); err != nil {
		return "fails_current_validators", false
	}
	return "", true
}

// RevalidateReuse implements spec.md's "Assessment reuse across input
// versions": when a newer input's Assessment basis is unchanged from a prior
// trustworthy Assessment, the controller reuses its semantic reasoning
// without a model call, but always writes a brand-new immutable Assessment
// bound to the NEW input — recomputing every controller-owned field
// (Lifecycle, EvidenceQuality, ActionContract, Cadence) fresh, revalidating
// the reused semantic fields against the new Snapshot's own eligible reasons
// and evidence, and rebinding per-Incident coverage to the new input. It
// never re-points prior's own row current, never copies prior's
// ActionContract/next_update_at, and never copies prior's coverage tuples.
//
// A prior accepted Sufficient reason is rebound to the NEW Snapshot's
// matching candidate by Code (the stable catalog identity), not reused
// verbatim: the prior's own CandidateID and EvidenceRefs are scoped to the
// OLD input version (reasonCandidateID and factIdentity both bake
// InputVersion into their IDs) and would fail this Snapshot's own evidence/
// eligibility checks if carried over unchanged.
func RevalidateReuse(prior AuthoritativeAssessment, snap Snapshot, in SnapshotInput, state ControllerState, now time.Time) ReuseResult {
	if reason, ok := trustworthy(prior, now); !ok {
		return ReuseResult{Reason: reason}
	}
	if prior.AssessmentBasisHash != snap.AssessmentBasisHash {
		return ReuseResult{Reason: "assessment_basis_changed"}
	}

	proposal := model.AssessmentProposal{
		SchemaVersion: prior.Assessment.SchemaVersion,
		Persistence:   prior.Assessment.Persistence,
		Impact:        prior.Assessment.Impact,
		Novelty:       prior.Assessment.Novelty,
		Causality:     prior.Assessment.Causality,
		Attention:     prior.Assessment.Attention,
		Limitations:   append([]model.Limitation(nil), prior.Assessment.Limitations...),
	}
	if prior.Assessment.SufficientReason != nil {
		matched, found := findEligibleCandidateByCode(snap.EligibleReasons, prior.Assessment.SufficientReason.Code)
		if !found {
			return ReuseResult{Reason: "sufficient_reason_no_longer_eligible"}
		}
		proposal.SufficientReason = &model.SufficientReason{
			Code:         matched.Code,
			CandidateID:  matched.ID,
			Summary:      prior.Assessment.SufficientReason.Summary,
			EvidenceRefs: append([]string(nil), matched.EvidenceRefs...),
		}
	}

	revalidated := validateProposalContent(proposal, snap)
	if !revalidated.Outcome.accepted() {
		reason := "revalidation_failed"
		if len(revalidated.Errors) > 0 {
			reason = "revalidation_failed:" + revalidated.Errors[0].Code
		}
		return ReuseResult{Reason: reason}
	}

	reusedFrom := prior.ID
	result := DeriveAssessment(revalidated.Proposal, snap, in, state, model.DerivationRevalidatedReuse, &reusedFrom, now)
	return ReuseResult{Result: result, Ok: true}
}

// ----------------------------------------------------------------------
// ValidateAssessmentProposal: deterministic validation of an L2 response.
// ----------------------------------------------------------------------

// ProposalOutcome is the closed content-classification outcome
// ValidateAssessmentProposal (and RevalidateReuse's own revalidation step)
// produce for one proposal.
type ProposalOutcome string

const (
	ProposalOutcomeAccepted           ProposalOutcome = "accepted"
	ProposalOutcomeContradicted       ProposalOutcome = "contradicted"
	ProposalOutcomeMalformed          ProposalOutcome = "malformed"
	ProposalOutcomePolicyRejected     ProposalOutcome = "policy_rejected"
	ProposalOutcomeCapabilityRejected ProposalOutcome = "capability_rejected"
	ProposalOutcomeStaleBasis         ProposalOutcome = "stale_basis"
)

// accepted reports whether o represents a validated, authoritative-eligible
// outcome (accepted or its contradicted special case) rather than a
// rejection.
func (o ProposalOutcome) accepted() bool {
	return o == ProposalOutcomeAccepted || o == ProposalOutcomeContradicted
}

// ValidationIssueCategory classifies a ValidationIssue: which outcome-matrix
// bucket it belongs to, or that it is a safe adjustment rather than a
// rejection.
type ValidationIssueCategory string

const (
	IssueCategoryMalformed  ValidationIssueCategory = "malformed"
	IssueCategoryPolicy     ValidationIssueCategory = "policy"
	IssueCategoryCapability ValidationIssueCategory = "capability"
	IssueCategoryStaleBasis ValidationIssueCategory = "stale_basis"
	IssueCategoryAdjustment ValidationIssueCategory = "adjustment"
)

// ValidationIssue is one typed, bounded rejection or adjustment reason.
// Detail is Task 5's own bounded diagnostic text — never raw prompts, raw
// provider responses, chain-of-thought, provider bodies, SQL, or secrets.
type ValidationIssue struct {
	Category ValidationIssueCategory
	Code     string
	Field    string
	Detail   string
}

// ValidationResult is ValidateAssessmentProposal's return: the outcome
// classification, the (possibly safely-adjusted) proposal when accepted, and
// the rejection/adjustment issues.
type ValidationResult struct {
	Outcome     ProposalOutcome
	Proposal    model.AssessmentProposal
	Errors      []ValidationIssue
	Adjustments []ValidationIssue
}

// forbiddenTopLevelKeys are Assessment fields the model must never author —
// the controller-exclusive lifecycle/Operator-contract/cadence subset a raw
// JSON reply could still smuggle in even though model.AssessmentProposal's Go
// struct has no field for them (a bare json.Unmarshal into that struct
// silently drops unknown keys instead of rejecting them).
var forbiddenTopLevelKeys = []string{"lifecycle", "action_contract", "cadence"}

// maxBoundedTextLength bounds every free-text field a proposal may carry
// (SufficientReason.Summary, each Limitation.Detail) — "bounded structured
// proposal fields," per the plan's global retention constraint.
const maxBoundedTextLength = 2000

func proposalTextBounded(p model.AssessmentProposal) bool {
	if p.SufficientReason != nil && len(p.SufficientReason.Summary) > maxBoundedTextLength {
		return false
	}
	for _, l := range p.Limitations {
		if len(l.Detail) > maxBoundedTextLength {
			return false
		}
	}
	return true
}

func malformedResult(code, field, detail string) ValidationResult {
	return ValidationResult{Outcome: ProposalOutcomeMalformed, Errors: []ValidationIssue{{Category: IssueCategoryMalformed, Code: code, Field: field, Detail: detail}}}
}

func policyResult(code, field, detail string) ValidationResult {
	return ValidationResult{Outcome: ProposalOutcomePolicyRejected, Errors: []ValidationIssue{{Category: IssueCategoryPolicy, Code: code, Field: field, Detail: detail}}}
}

func capabilityResult(code, field, detail string) ValidationResult {
	return ValidationResult{Outcome: ProposalOutcomeCapabilityRejected, Errors: []ValidationIssue{{Category: IssueCategoryCapability, Code: code, Field: field, Detail: detail}}}
}

func staleBasisResult(code, field, detail string) ValidationResult {
	return ValidationResult{Outcome: ProposalOutcomeStaleBasis, Errors: []ValidationIssue{{Category: IssueCategoryStaleBasis, Code: code, Field: field, Detail: detail}}}
}

// materialClaim reports whether p asserts a strong, confirmed-grade material
// claim — causality=supported or impact=confirmed — the kind spec.md's
// "material claims without supporting facts" rule requires grounding for. A
// weaker hedge (correlated, suspected, ...) is not held to this bar.
func materialClaim(p model.AssessmentProposal) bool {
	return p.Causality == model.CausalitySupported || p.Impact == model.ImpactConfirmed
}

// validateProposalContent is the deterministic policy core
// ValidateAssessmentProposal runs once shape/staleness checks pass, and
// RevalidateReuse runs directly (its candidate proposal is already
// shape-valid by construction — it was built from a prior Assessment's own
// already-validated fields plus a freshly re-matched Sufficient reason).
// This is what spec.md means by "the controller revalidates the reused
// semantic fields": the exact same policy checks, not a separate weaker
// pass.
func validateProposalContent(proposal model.AssessmentProposal, snap Snapshot) ValidationResult {
	// Plan 2 has no manual reassessment producer, so no operator-confirmation
	// input exists for the model to ground this value in.
	if proposal.Causality == model.CausalityOperatorConfirmed {
		return policyResult("operator_confirmation_unavailable", "causality", "Plan 2 has no manual reassessment producer to ground operator_confirmed causality")
	}

	if proposal.SufficientReason != nil {
		candidate, found := findEligibleCandidateByID(snap.EligibleReasons, proposal.SufficientReason.CandidateID)
		if !found || candidate.Code != proposal.SufficientReason.Code {
			return capabilityResult("reason_id_unknown", "sufficient_reason.candidate_id", "candidate ID not present in this Snapshot's eligible_reasons")
		}
		for _, ref := range proposal.SufficientReason.EvidenceRefs {
			if !factExists(snap.Facts, ref) {
				return policyResult("evidence_ref_missing", "sufficient_reason.evidence_refs", "evidence reference not present in the claimed snapshot")
			}
		}
	}

	if materialClaim(proposal) && proposal.SufficientReason == nil {
		return policyResult("ungrounded_material_claim", "", "a confirmed-grade material claim requires a grounded Sufficient reason")
	}

	if proposal.Causality == model.CausalitySupported {
		// proposal.SufficientReason is guaranteed non-nil here: materialClaim
		// already rejected causality=supported with a nil SufficientReason
		// above as an ungrounded_material_claim.
		if proposal.SufficientReason.Code == reasonCodeDurationOutlier {
			return policyResult("temporal_overlap_as_cause", "causality", "duration_outlier is a temporal-coincidence predicate, not a supported cause")
		}
		candidate, _ := findEligibleCandidateByID(snap.EligibleReasons, proposal.SufficientReason.CandidateID)
		if !candidate.DeterministicFloor {
			// Unreachable with Plan 2's current two reachable catalog codes
			// (critical_anchor is the floor, duration_outlier is caught
			// above) — kept as the generic fallback for any future
			// non-floor, non-duration_outlier reachable code.
			return policyResult("causality_too_strong", "causality", "supported causality requires a deterministic-floor Sufficient reason in Plan 2")
		}
	}

	floor := hasDeterministicFloor(snap.EligibleReasons)
	if proposal.Attention == model.AttentionUrgent && !floor {
		return policyResult("urgent_without_floor", "attention", "urgent attention requires a deterministic urgent anchor")
	}

	var adjustments []ValidationIssue
	if floor && proposal.Attention != model.AttentionUrgent {
		adjustments = append(adjustments, ValidationIssue{
			Category: IssueCategoryAdjustment, Code: "attention_raised_to_floor", Field: "attention",
			Detail: "raised to urgent: a deterministic urgent anchor is active",
		})
		proposal.Attention = model.AttentionUrgent
	}

	outcome := ProposalOutcomeAccepted
	if proposal.Causality == model.CausalityContradicted {
		outcome = ProposalOutcomeContradicted
	}
	return ValidationResult{Outcome: outcome, Proposal: proposal, Adjustments: adjustments}
}

// ValidateAssessmentProposal deterministically validates one raw L2 response
// against snap and the AssessmentCall it answers. It rejects or adjusts at
// least: unknown enums/schema version/reason IDs; forbidden model-authored
// lifecycle/Operator-contract/cadence fields; evidence references absent from
// the claimed snapshot; material claims without supporting facts; causality
// stronger than the cited evidence allows; temporal overlap presented as
// supported cause; urgent Attention without a deterministic urgent anchor;
// and a stale input version or Assessment basis. Safe adjustments (raising
// Attention to a proven floor) are recorded immutably alongside the
// (possibly adjusted) proposal, never silently. Policy rejection is never
// converted into a rewritten model proposal — a rejected ValidationResult
// carries no Proposal.
func ValidateAssessmentProposal(raw json.RawMessage, snap Snapshot, call AssessmentCall, now time.Time) ValidationResult {
	if call.InputVersion != snap.InputVersion || call.MaterialFactHash != snap.MaterialFactHash {
		return staleBasisResult("stale_input_version", "", "call dispatched against a superseded input version or material fact hash")
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return malformedResult("invalid_json", "", "response is not a JSON object")
	}
	for _, k := range forbiddenTopLevelKeys {
		if _, present := obj[k]; present {
			return malformedResult("forbidden_field", k, "model-authored "+k+" is forbidden; the controller derives it exclusively")
		}
	}

	var proposal model.AssessmentProposal
	if err := json.Unmarshal(raw, &proposal); err != nil {
		return malformedResult("invalid_shape", "", err.Error())
	}
	if err := proposal.Validate(); err != nil {
		return malformedResult("invalid_shape", "", err.Error())
	}
	if !proposalTextBounded(proposal) {
		return malformedResult("unbounded_text", "", "summary/detail text exceeds the bounded length")
	}

	return validateProposalContent(proposal, snap)
}

// ----------------------------------------------------------------------
// ClassifyL2Outcome: typed L2 outcome classification (spec.md "L2 call and
// attempt accounting" outcome matrix). Classifies an ALREADY-RECEIVED result
// — it never calls a provider.
// ----------------------------------------------------------------------

// L2Outcome is the closed outcome-matrix category one dispatched call's
// result reduces to.
type L2Outcome string

const (
	L2OutcomeAccepted           L2Outcome = "accepted"
	L2OutcomeContradicted       L2Outcome = "contradicted"
	L2OutcomeMalformed          L2Outcome = "malformed"
	L2OutcomeTransportFailure   L2Outcome = "transport_failure"
	L2OutcomeRateLimited        L2Outcome = "rate_limited"
	L2OutcomePolicyRejected     L2Outcome = "policy_rejected"
	L2OutcomeCapabilityRejected L2Outcome = "capability_rejected"
	L2OutcomeStaleBasis         L2Outcome = "stale_basis"
)

// L2RetryPolicy is the bounded, deterministic outcome-matrix verdict
// ClassifyL2Outcome derives: whether one immediate correction may be
// attempted now (Plan 2 permits at most one, and only for a malformed
// outcome), and whether a later durable retry is permitted. The call slot
// itself is always consumed once any result (success or failure) reaches
// this function — spec.md: "the slot is never refunded" — so that is not a
// field here; "crash after provider dispatch, before any result" has no
// result to classify and is a caller-detected case (the durable dispatch
// row's own existence with no matching attempt), not something
// ClassifyL2Outcome decides.
type L2RetryPolicy struct {
	Outcome             L2Outcome
	ImmediateCorrection bool
	DurableRetry        bool
}

// ClassifyL2Outcome maps one already-received L2 call result onto the
// outcome matrix's bounded retry policy. Exactly one of vr or transportErr
// should be meaningful: pass vr (ValidateAssessmentProposal's result) when
// the transport layer produced a completion, and transportErr (nil vr) when
// it did not — timeout, network error, provider unavailability, rate limit,
// or a transport/decode-layer schema failure (llm.ErrSchemaViolation,
// llm.ErrResponseTruncated, llm.ErrResponseInvalid). correctionAlreadyUsed is
// true once this controller attempt has already spent its one immediate
// correction call.
func ClassifyL2Outcome(vr *ValidationResult, transportErr error, correctionAlreadyUsed bool) L2RetryPolicy {
	if transportErr != nil {
		return classifyTransportErr(transportErr, correctionAlreadyUsed)
	}
	if vr == nil {
		return L2RetryPolicy{Outcome: L2OutcomeMalformed, ImmediateCorrection: !correctionAlreadyUsed, DurableRetry: true}
	}
	switch vr.Outcome {
	case ProposalOutcomeAccepted:
		return L2RetryPolicy{Outcome: L2OutcomeAccepted}
	case ProposalOutcomeContradicted:
		return L2RetryPolicy{Outcome: L2OutcomeContradicted}
	case ProposalOutcomeMalformed:
		return L2RetryPolicy{Outcome: L2OutcomeMalformed, ImmediateCorrection: !correctionAlreadyUsed, DurableRetry: true}
	case ProposalOutcomePolicyRejected:
		return L2RetryPolicy{Outcome: L2OutcomePolicyRejected}
	case ProposalOutcomeCapabilityRejected:
		return L2RetryPolicy{Outcome: L2OutcomeCapabilityRejected}
	case ProposalOutcomeStaleBasis:
		return L2RetryPolicy{Outcome: L2OutcomeStaleBasis}
	default:
		return L2RetryPolicy{Outcome: L2OutcomeMalformed, ImmediateCorrection: !correctionAlreadyUsed, DurableRetry: true}
	}
}

// classifyTransportErr distinguishes malformed/schema (transport-layer
// decode failure), rate-limited, and generic transport-failure classes from
// a raw error — the local mirror of internal/llmhealth.Classify's
// timeout/network/rate-limit/schema distinctions this package cannot import
// (see this file's top-of-file note on the import-cycle constraint).
func classifyTransportErr(err error, correctionAlreadyUsed bool) L2RetryPolicy {
	if errors.Is(err, llm.ErrSchemaViolation) || errors.Is(err, llm.ErrResponseTruncated) || errors.Is(err, llm.ErrResponseInvalid) {
		return L2RetryPolicy{Outcome: L2OutcomeMalformed, ImmediateCorrection: !correctionAlreadyUsed, DurableRetry: true}
	}

	var retry *llm.RetryableError
	if errors.As(err, &retry) {
		if retry.StatusCode == http.StatusTooManyRequests {
			return L2RetryPolicy{Outcome: L2OutcomeRateLimited, DurableRetry: true}
		}
		return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
	}
	var api *llm.APIError
	if errors.As(err, &api) {
		if api.StatusCode == http.StatusTooManyRequests {
			return L2RetryPolicy{Outcome: L2OutcomeRateLimited, DurableRetry: true}
		}
		return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
	}

	return L2RetryPolicy{Outcome: L2OutcomeTransportFailure, DurableRetry: true}
}
