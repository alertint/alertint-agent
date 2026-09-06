// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 4: the pure derivation of one controller reconciliation's
// durable operator history — the immutable Transitions it creates
// (BuildTransitions), the Episode-summary projection folded across them
// (ProjectEpisode), and the composition Task 5 commits atomically
// (BuildHistoryCommit). No I/O, no clock read beyond the explicit Now, no
// Slack rendering: this package decides what became true, never how it
// looks.
// ----------------------------------------------------------------------

// Bounded lengths mirroring internal/situation/model's own (unexported)
// bounds for the same fields, so a value derived here can never be
// rejected by model.Transition.Validate for length alone.
const (
	maxHistoryHeadline     = 200
	maxHistoryDetail       = 2000
	maxHistoryIdentifier   = 200
	maxHistoryEvidenceRefs = 50
	// maxHistoryListEntries bounds the two accumulating Episode-summary
	// lists (investigation work, recorded operator context). The immutable
	// Transition ledger remains the complete record; the summary is a
	// bounded current projection.
	maxHistoryListEntries = 50
)

// The two durable operator-artifact input kinds (R5). They mirror
// internal/store's isOperatorArtifactKind exactly.
const (
	artifactKindAnnotation = "operator_annotation_recorded"
	artifactKindVerdict    = "captured_verdict_recorded"
)

// Acute Triage schedule phases this package reads (migration 0016). Only
// the terminal skip phase needs naming here: it is the pre-claim clean skip
// (TriageStore.CleanSkipIncidentTriageBelowMinimumMembers) that consumes no
// attempt and must never read as investigation having run.
const triagePhaseSkipped = "skipped"

// historyNamespace is the fixed AlertINT UUID namespace every deterministic
// Plan 3 identity (Transition ID, notification intent ID, Slack client
// message ID) is derived under, so the same inputs always produce the same
// identity across retries, restarts, and processes.
var historyNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://alertint.com/ns/situation-history/v1"))

// AuthoritativeChange is one fenced controller reconciliation's
// authoritative result, reduced to exactly what deriving durable history
// needs. Situation carries the COMMITTED projection (lifecycle, Attention,
// recovery/terminal instants) — never the pre-commit read.
type AuthoritativeChange struct {
	Situation    model.Situation
	AssessmentID *string
	Assessment   model.Assessment
	// Derivation is how the authoritative Assessment came to be. It decides
	// the Transition actor for the reasons whose basis is model-authored
	// content: only a model_validated Assessment may be recorded as `llm`.
	Derivation model.AssessmentDerivation
	// Projection is captured from the coherent claim and the commit's
	// lifecycle fields (R3) — the only thing ProjectEpisode may read.
	Projection       model.ProjectionFacts
	PriorTransition  *model.Transition
	PriorSummary     *model.EpisodeSummary
	MaterialFactHash string
	EvidenceRefs     []string
	// Incidents is Plan 2's per-Incident state including IncidentState.Triage
	// (R7); TriageDecisions is this cycle's Plan 2 request/skip decisions.
	Incidents         []IncidentState
	TriageDecisions   []TriageDecision
	RecurrenceCount   int
	OperatorArtifacts []OperatorArtifactInput // R1: every applied-and-unjournaled artifact, in order
	Drill             bool
	Now               time.Time
}

// OperatorArtifactInput is one applied-and-unjournaled durable operator
// artifact input (R1). The caller orders these by
// (applied_input_version, occurred_at, id); BuildTransitions preserves that
// order exactly.
type OperatorArtifactInput struct {
	InputID             string // situation_input_outbox.id — becomes Transition.OperatorArtifactInputID
	Kind                string // operator_annotation_recorded | captured_verdict_recorded
	AnnotationID        *string
	VerdictID           *string
	AppliedInputVersion int
	OccurredAt          time.Time
	AttributedActor     string
	Headline            string // bounded, from the durable artifact
	Detail              string // bounded
}

// HistoryCommit is everything one fenced controller transaction commits on
// top of Plan 2's authoritative result.
type HistoryCommit struct {
	// Transitions is this reconciliation's immutable history in sequence
	// order: consumed operator artifacts first, the controller-state
	// Transition last (R1). Empty when nothing material happened.
	Transitions []model.Transition
	// Summary is the Episode projection after folding every Transition in
	// order; nil when Transitions is empty.
	Summary *model.EpisodeSummary
	Intents []model.NotificationIntent
}

// ----------------------------------------------------------------------
// BuildTransitions
// ----------------------------------------------------------------------

// BuildTransitions derives one reconciliation's immutable Transitions: one
// `operator_artifact_recorded` Transition per pending artifact in the given
// order, then at most one controller-state Transition when the semantic
// tuple actually changed (R1, R4).
//
// Materiality is semantic. The compared tuple is lifecycle, Attention, the
// Operator contract WITHOUT its next_update_at, the accepted Sufficient
// reason's code, the Assessment's closed conclusion codes, per-Incident
// Triage phase/decision/result, and the recurrence milestone. Plan 2's
// per-input-version identities — Assessment IDs, reason-candidate IDs,
// fact/evidence IDs, the material fact hash — and the refreshed
// next_update_at are deliberately excluded, so a `revalidated_reuse` cycle
// adds no history.
//
// Reason precedence for the single controller-state Transition, most
// operator-consequential first:
//
//	first_authoritative_state > recovered > closed_unknown >
//	recovery_failed > recovery_observed > investigation_concluded >
//	investigation_started > attention_changed > operator_contract_changed >
//	recurrence_milestone > triage_state_changed > material_assessment_changed
//
// The selected reason names the change; the Transition still records the
// complete state and every supporting evidence reference.
func BuildTransitions(change AuthoritativeChange) ([]model.Transition, error) {
	if err := validateChange(change); err != nil {
		return nil, err
	}

	out := make([]model.Transition, 0, len(change.OperatorArtifacts)+1)
	base := 0
	if change.PriorTransition != nil {
		base = change.PriorTransition.Sequence
	}

	for i, artifact := range change.OperatorArtifacts {
		tr, err := artifactTransition(change, artifact, base+1+i)
		if err != nil {
			return nil, fmt.Errorf("situation: operator artifact %d: %w", i, err)
		}
		out = append(out, tr)
	}

	if reason, material := selectControllerReason(change); material {
		out = append(out, controllerTransition(change, reason, base+1+len(out)))
	}

	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, fmt.Errorf("situation: derived transition %d: %w", i, err)
		}
	}
	return out, nil
}

func validateChange(change AuthoritativeChange) error {
	if strings.TrimSpace(change.Situation.ID) == "" {
		return errors.New("situation: authoritative change: situation id is required")
	}
	if change.Situation.InputVersion < 1 {
		return fmt.Errorf("situation: authoritative change: input version must be >= 1, got %d", change.Situation.InputVersion)
	}
	if strings.TrimSpace(change.MaterialFactHash) == "" {
		return errors.New("situation: authoritative change: material fact hash is required")
	}
	if change.Now.IsZero() || change.Now.Location() != time.UTC {
		return fmt.Errorf("situation: authoritative change: now must be a non-zero UTC instant, got %s", change.Now)
	}
	if change.RecurrenceCount < 0 {
		return fmt.Errorf("situation: authoritative change: recurrence count must be >= 0, got %d", change.RecurrenceCount)
	}
	if err := change.Situation.Lifecycle.Validate(); err != nil {
		return fmt.Errorf("situation: authoritative change: %w", err)
	}
	if err := change.Situation.Attention.Validate(); err != nil {
		return fmt.Errorf("situation: authoritative change: %w", err)
	}
	if change.Derivation != "" {
		if err := change.Derivation.Validate(); err != nil {
			return fmt.Errorf("situation: authoritative change: %w", err)
		}
	}
	// The Transition records the committed lifecycle and the projection
	// captured for the same commit; they must agree, or the durable record
	// would contradict itself.
	terminal := change.Situation.Lifecycle.Terminal()
	if terminal != (change.Projection.TerminalAt != nil) {
		return fmt.Errorf("situation: authoritative change: lifecycle %q and projection terminal_at %v disagree",
			change.Situation.Lifecycle, change.Projection.TerminalAt)
	}
	// Which terminal lifecycle carries a terminal reason, mirroring
	// migration 0014's own lifecycle CHECK in both directions.
	// ProjectionFacts.Validate deliberately allows a bare terminal_at (a
	// `recovered` Situation has no terminal reason), so this is the only
	// place that catches a closed_unknown with no reason — which would
	// otherwise fold into the Episode summary as a clean recovery, since
	// the outcome/uncertainty text keys off the terminal reason.
	switch change.Situation.Lifecycle {
	case model.LifecycleClosedUnknown:
		if change.Projection.TerminalReason == nil {
			return errors.New("situation: authoritative change: closed_unknown requires projection terminal_reason")
		}
	case model.LifecycleRecovered:
		if change.Projection.TerminalReason != nil {
			return fmt.Errorf("situation: authoritative change: recovered must not set projection terminal_reason, got %q",
				*change.Projection.TerminalReason)
		}
	case model.LifecycleActive, model.LifecycleRecoveryPending:
		// Nonterminal: the terminal_at agreement check above already
		// guarantees no terminal instant, and ProjectionFacts.Validate
		// guarantees no reason without an instant.
	}
	if err := change.Projection.Validate(); err != nil {
		return fmt.Errorf("situation: authoritative change: %w", err)
	}
	if change.PriorTransition != nil {
		if change.PriorTransition.SituationID != change.Situation.ID {
			return fmt.Errorf("situation: authoritative change: prior transition belongs to situation %q, not %q",
				change.PriorTransition.SituationID, change.Situation.ID)
		}
		if change.PriorSummary == nil {
			return errors.New("situation: authoritative change: a prior transition requires the prior episode summary")
		}
		if change.PriorSummary.SituationID != change.Situation.ID {
			return fmt.Errorf("situation: authoritative change: prior summary belongs to situation %q, not %q",
				change.PriorSummary.SituationID, change.Situation.ID)
		}
	}
	return nil
}

// artifactTransition records one durable operator artifact. It carries the
// commit's current controller state verbatim: an annotation or Captured
// verdict adds journal context and never alters the Assessment, Attention,
// or Operator contract (spec.md "Situation journal entry").
func artifactTransition(change AuthoritativeChange, artifact OperatorArtifactInput, sequence int) (model.Transition, error) {
	if strings.TrimSpace(artifact.InputID) == "" {
		return model.Transition{}, errors.New("input id is required")
	}
	if artifact.OccurredAt.IsZero() || artifact.OccurredAt.Location() != time.UTC {
		return model.Transition{}, fmt.Errorf("occurred_at must be a non-zero UTC instant, got %s", artifact.OccurredAt)
	}
	var journalKind model.JournalKind
	var evidence []string
	switch artifact.Kind {
	case artifactKindAnnotation:
		if artifact.AnnotationID == nil || strings.TrimSpace(*artifact.AnnotationID) == "" {
			return model.Transition{}, errors.New("operator_annotation_recorded requires an annotation id")
		}
		if artifact.VerdictID != nil {
			return model.Transition{}, errors.New("operator_annotation_recorded must not carry a verdict id")
		}
		journalKind = model.JournalOperatorNote
		evidence = []string{"annotation:" + *artifact.AnnotationID}
	case artifactKindVerdict:
		if artifact.VerdictID == nil || strings.TrimSpace(*artifact.VerdictID) == "" {
			return model.Transition{}, errors.New("captured_verdict_recorded requires a verdict id")
		}
		if artifact.AnnotationID != nil {
			return model.Transition{}, errors.New("captured_verdict_recorded must not carry an annotation id")
		}
		journalKind = model.JournalCapturedVerdict
		evidence = []string{"verdict:" + *artifact.VerdictID}
	default:
		return model.Transition{}, fmt.Errorf("unsupported operator artifact kind %q", artifact.Kind)
	}

	tr := newTransition(change, sequence, model.ReasonOperatorArtifactRecorded, artifact.InputID, journalKind, model.JournalData{
		Headline:        boundedText(artifact.Headline, maxHistoryHeadline),
		Detail:          boundedText(artifact.Detail, maxHistoryDetail),
		AttributedActor: boundedText(artifact.AttributedActor, maxHistoryIdentifier),
		ActionStatus:    contractActionStatus(change.Assessment.ActionContract),
		RecurrenceCount: change.RecurrenceCount,
		OccurredAt:      artifact.OccurredAt,
	}, evidence)
	tr.Actor = model.ActorAttributedOperator
	tr.OperatorArtifactInputID = stringPtrOf(artifact.InputID)
	return tr, nil
}

func controllerTransition(change AuthoritativeChange, reason model.TransitionReason, sequence int) model.Transition {
	journalKind := journalKindFor(reason)
	headline, detail := journalTextFor(change, reason)
	tr := newTransition(change, sequence, reason, "", journalKind, model.JournalData{
		Headline:        boundedText(headline, maxHistoryHeadline),
		Detail:          boundedText(detail, maxHistoryDetail),
		ActionStatus:    contractActionStatus(change.Assessment.ActionContract),
		RecurrenceCount: change.RecurrenceCount,
		OccurredAt:      change.Now,
	}, controllerEvidenceRefs(change))
	tr.Actor = controllerActor(change, reason)
	if class := ClassifyPoke(change.PriorTransition, tr); class != PokeNone {
		priority := DeriveInterruptionPriority(tr)
		tr.InterruptionPriority = &priority
	}
	return tr
}

// newTransition fills every field a Transition shares regardless of reason:
// deterministic identity, the committed controller state, this commit's
// captured projection facts (R3), and the Drill marker.
func newTransition(change AuthoritativeChange, sequence int, reason model.TransitionReason,
	artifactInputID string, journalKind model.JournalKind, journal model.JournalData, evidence []string) model.Transition {
	tr := model.Transition{
		SituationID:      change.Situation.ID,
		Sequence:         sequence,
		InputVersion:     change.Situation.InputVersion,
		MaterialFactHash: change.MaterialFactHash,
		AssessmentID:     change.AssessmentID,
		Lifecycle:        change.Situation.Lifecycle,
		Attention:        change.Situation.Attention,
		ActionContract:   change.Assessment.ActionContract,
		Reason:           reason,
		JournalKind:      journalKind,
		Journal:          journal,
		Projection:       change.Projection,
		EvidenceRefs:     evidence,
		Actor:            model.ActorDeterministicController,
		Drill:            change.Drill,
		CreatedAt:        change.Now,
	}
	if change.Assessment.SufficientReason != nil && change.Assessment.SufficientReason.CandidateID != "" {
		tr.SufficientReasonID = stringPtrOf(change.Assessment.SufficientReason.CandidateID)
	}
	tr.ID = transitionIdentity(change.Situation.ID, change.Situation.InputVersion, sequence, reason, artifactInputID)
	return tr
}

// transitionIdentitySchemaVersion versions the canonical hash input below;
// bump it only when the identity fields themselves change meaning.
const transitionIdentitySchemaVersion = 1

type transitionIdentityDTO struct {
	SchemaVersion int    `json:"schema_version"`
	SituationID   string `json:"situation_id"`
	InputVersion  int    `json:"input_version"`
	Sequence      int    `json:"sequence"`
	Reason        string `json:"reason"`
	Artifact      string `json:"artifact,omitempty"`
}

// transitionIdentity derives a Transition's stable UUIDv5 identity from the
// Situation, the authoritative input version, the Transition's own sequence
// and reason, and (for an artifact Transition) the artifact it journals.
// Two runs of the same fenced commit therefore produce byte-identical
// identities, and a later input version never collides with an earlier one.
func transitionIdentity(situationID string, inputVersion, sequence int, reason model.TransitionReason, artifact string) string {
	return uuid.NewSHA1(historyNamespace, mustMarshal(transitionIdentityDTO{
		SchemaVersion: transitionIdentitySchemaVersion,
		SituationID:   situationID,
		InputVersion:  inputVersion,
		Sequence:      sequence,
		Reason:        string(reason),
		Artifact:      artifact,
	})).String()
}

// controllerActor records `llm` only for the reasons whose basis is
// model-authored content (the conclusion codes, Attention, and the selected
// Sufficient reason), and only when the authoritative Assessment was
// actually model-validated. Lifecycle, the Operator contract, Triage state,
// and recurrence are controller-derived, so they are always
// deterministic_controller. Plan 3 never produces `operator_policy`.
//
// investigation_concluded is the one reason with both bases: it is selected
// because the Operator contract's investigation phase ENDED (controller-
// derived, from the Triage result), and it renders the Assessment's
// evidence conclusion. It records `llm` only when that conclusion actually
// changed in this commit. Otherwise the model authored nothing new here —
// whether the concluding cycle happened to consult it or reuse its prior
// answer is a scheduling accident (the crash-replay harness proved a crash
// mid-dispatch flipped the actor), and durable history must not depend on
// scheduling.
func controllerActor(change AuthoritativeChange, reason model.TransitionReason) model.TransitionActor {
	if change.Derivation != model.DerivationModelValidated {
		return model.ActorDeterministicController
	}
	switch reason { //nolint:exhaustive // the default is the point: every other reason records controller-derived lifecycle, contract, Triage, or recurrence state, which is never the model's authorship.
	case model.ReasonFirstAuthoritativeState, model.ReasonMaterialAssessmentChanged,
		model.ReasonAttentionChanged:
		return model.ActorLLM
	case model.ReasonInvestigationConcluded:
		if conclusionContentChanged(change) {
			return model.ActorLLM
		}
		return model.ActorDeterministicController
	default:
		return model.ActorDeterministicController
	}
}

// conclusionContentChanged reports whether the Assessment's closed
// conclusion (the model-authored part of the materiality tuple) differs
// from the prior Transition's. A first Transition has nothing to compare
// against and counts as changed.
func conclusionContentChanged(change AuthoritativeChange) bool {
	prior := change.PriorTransition
	if prior == nil {
		return true
	}
	cur := tupleOf("", "", model.ActionContract{}, change.Projection.Assessment, 0)
	prev := tupleOf("", "", model.ActionContract{}, prior.Projection.Assessment, 0)
	return canonicalDigest(cur) != canonicalDigest(prev)
}

// controllerEvidenceRefs retains every supporting evidence reference for
// this commit: the caller's collected references plus the accepted
// Sufficient reason's own, deduplicated and ordered so the durable record
// is canonical.
func controllerEvidenceRefs(change AuthoritativeChange) []string {
	refs := append([]string{}, change.EvidenceRefs...)
	if change.Assessment.SufficientReason != nil {
		refs = append(refs, change.Assessment.SufficientReason.EvidenceRefs...)
	}
	return canonicalRefs(refs)
}

func canonicalRefs(refs []string) []string {
	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		r = boundedText(strings.TrimSpace(r), maxHistoryIdentifier)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	if len(out) > maxHistoryEvidenceRefs {
		out = out[:maxHistoryEvidenceRefs]
	}
	return out
}

// ----------------------------------------------------------------------
// Materiality (R4)
// ----------------------------------------------------------------------

// materialTuple is the canonical semantic identity of one committed
// controller state. Everything in it is a closed code or a bounded closed
// list; no ID, hash, prose, or instant appears.
type materialTuple struct {
	Lifecycle           string   `json:"lifecycle"`
	Attention           string   `json:"attention"`
	Contract            string   `json:"contract"`
	HasAssessment       bool     `json:"has_assessment"`
	Persistence         string   `json:"persistence"`
	Impact              string   `json:"impact"`
	Novelty             string   `json:"novelty"`
	Causality           string   `json:"causality"`
	EvidenceQuality     string   `json:"evidence_quality"`
	LimitationCodes     []string `json:"limitation_codes"`
	SufficientReason    string   `json:"sufficient_reason_code"`
	RecurrenceMilestone int      `json:"recurrence_milestone"`
}

// operatorContractTuple canonicalizes the Operator contract WITHOUT its
// next_update_at: the deadline instant reaches the root through the
// intent's ContractDeadlineAt (R4), never by making every cadence tick
// material.
func operatorContractTuple(c model.ActionContract) string {
	on := make([]string, 0, len(c.NextUpdateOn))
	for _, o := range c.NextUpdateOn {
		on = append(on, string(o))
	}
	sort.Strings(on)
	return canonicalDigest(struct {
		NextActor      string   `json:"next_actor"`
		AlertINTAction string   `json:"alertint_action"`
		AlertINTStatus string   `json:"alertint_status"`
		OperatorAction string   `json:"operator_action_required"`
		NextUpdateOn   []string `json:"next_update_on"`
		WaitReason     string   `json:"wait_reason"`
	}{
		NextActor:      string(c.NextActor),
		AlertINTAction: derefAlertINTAction(c.AlertINTAction),
		AlertINTStatus: derefAlertINTStatus(c.AlertINTStatus),
		OperatorAction: derefOperatorAction(c.OperatorActionRequired),
		NextUpdateOn:   on,
		WaitReason:     derefWaitReason(c.WaitReason),
	})
}

func tupleOf(lifecycle model.Lifecycle, attention model.Attention, contract model.ActionContract,
	concl *model.AssessmentConclusion, recurrence int) materialTuple {
	t := materialTuple{
		Lifecycle:           string(lifecycle),
		Attention:           string(attention),
		Contract:            operatorContractTuple(contract),
		LimitationCodes:     []string{},
		RecurrenceMilestone: recurrenceMilestone(recurrence),
	}
	if concl != nil {
		codes := append([]string{}, concl.LimitationCodes...)
		sort.Strings(codes)
		t.HasAssessment = true
		t.Persistence = string(concl.Persistence)
		t.Impact = string(concl.Impact)
		t.Novelty = string(concl.Novelty)
		t.Causality = string(concl.Causality)
		t.EvidenceQuality = string(concl.EvidenceQuality)
		t.LimitationCodes = codes
		t.SufficientReason = concl.SufficientReasonCode
	}
	return t
}

func currentTuple(change AuthoritativeChange) materialTuple {
	return tupleOf(change.Situation.Lifecycle, change.Situation.Attention,
		change.Assessment.ActionContract, change.Projection.Assessment, change.RecurrenceCount)
}

func priorTuple(change AuthoritativeChange) materialTuple {
	prior := change.PriorTransition
	recurrence := 0
	if change.PriorSummary != nil {
		recurrence = change.PriorSummary.RecurrenceCount
	}
	return tupleOf(prior.Lifecycle, prior.Attention, prior.ActionContract, prior.Projection.Assessment, recurrence)
}

// recurrenceMilestone reduces a raw recurrence count to the sparse,
// roughly logarithmic milestone rung the legacy presentation path already
// used (ADR-0020: x5, x10, x25, x50, then every x100), and 0 below the
// first rung. The tuple carries the RUNG, not the raw count, so a flapper
// creates a bounded handful of Transitions instead of one per re-fire —
// spec.md: "A silent Situation has no Slack recurrence trace." The raw
// count still reaches the Episode summary through the journal.
func recurrenceMilestone(count int) int {
	switch {
	case count >= 100:
		return count / 100 * 100
	case count >= 50:
		return 50
	case count >= 25:
		return 25
	case count >= 10:
		return 10
	case count >= 5:
		return 5
	default:
		return 0
	}
}

// selectControllerReason applies the documented precedence over the
// semantic tuple, returning false when nothing material changed.
func selectControllerReason(change AuthoritativeChange) (model.TransitionReason, bool) {
	prior := change.PriorTransition
	if prior == nil {
		return model.ReasonFirstAuthoritativeState, true
	}

	current := currentTuple(change)
	previous := priorTuple(change)
	triage := triageStateChanged(change)
	if canonicalDigest(current) == canonicalDigest(previous) && !triage {
		return "", false
	}

	priorInvestigating := investigationCurrent(prior.ActionContract)
	nowInvestigating := investigationCurrent(change.Assessment.ActionContract)
	investigationStarted := nowInvestigating && !priorInvestigating &&
		(change.PriorSummary == nil || !change.PriorSummary.InvestigationStarted)

	switch {
	case change.Situation.Lifecycle == model.LifecycleRecovered:
		return model.ReasonRecovered, true
	case change.Situation.Lifecycle == model.LifecycleClosedUnknown:
		return model.ReasonClosedUnknown, true
	case prior.Lifecycle == model.LifecycleRecoveryPending && change.Situation.Lifecycle == model.LifecycleActive:
		return model.ReasonRecoveryFailed, true
	case change.Situation.Lifecycle == model.LifecycleRecoveryPending && prior.Lifecycle != model.LifecycleRecoveryPending:
		return model.ReasonRecoveryObserved, true
	case priorInvestigating && !nowInvestigating && change.Assessment.SufficientReason != nil:
		return model.ReasonInvestigationConcluded, true
	case investigationStarted:
		return model.ReasonInvestigationStarted, true
	case current.Attention != previous.Attention:
		return model.ReasonAttentionChanged, true
	case current.Contract != previous.Contract:
		return model.ReasonOperatorContractChanged, true
	case current.RecurrenceMilestone != previous.RecurrenceMilestone:
		return model.ReasonRecurrenceMilestone, true
	case triage:
		return model.ReasonTriageStateChanged, true
	default:
		// Whatever is left in the tuple is the Assessment's own conclusion.
		return model.ReasonMaterialAssessmentChanged, true
	}
}

// investigationCurrent reports whether the Operator contract currently
// names AlertINT investigation work — the durable basis for the Episode
// summary's InvestigationStarted flag and the root's Investigating phase.
// Monitoring and recovery verification are not investigation.
func investigationCurrent(c model.ActionContract) bool {
	if c.AlertINTAction == nil {
		return false
	}
	switch *c.AlertINTAction { //nolint:exhaustive // monitor_situation and verify_recovery are deliberately NOT investigation; they fall to the default.
	case model.AlertINTActionRunAcuteTriage, model.AlertINTActionRetrySituationAssessment:
		return true
	default:
		return false
	}
}

// triageStateChanged reports whether per-Incident Acute Triage state moved
// since the last recorded Transition. Neither the Transition ledger nor the
// Episode summary carries a prior per-Incident Triage tuple, so the change
// is established from three durable signals the reconciliation already
// carries: a decision made in this cycle, a Triage decision or completed
// attempt newer than the last recorded Transition, and the consumed
// `triage_changed` due reason (which is exactly what Plan 2's
// triage_skipped/triage_retry_changed/triage_exhausted inputs raise —
// including the pre-claim minimum-member clean skip that consumes no
// attempt).
func triageStateChanged(change AuthoritativeChange) bool {
	if len(change.TriageDecisions) > 0 {
		return true
	}
	for _, r := range change.Situation.DueReasons {
		if r == model.DueTriageChanged {
			return true
		}
	}
	if change.PriorTransition == nil {
		return false
	}
	watermark := change.PriorTransition.CreatedAt
	for _, inc := range change.Incidents {
		if inc.Triage.DecidedAt != nil && inc.Triage.DecidedAt.After(watermark) {
			return true
		}
		if inc.Triage.LatestAttempt != nil && inc.Triage.LatestAttempt.CompletedAt.After(watermark) {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------
// Journal render data
// ----------------------------------------------------------------------

func journalKindFor(reason model.TransitionReason) model.JournalKind {
	switch reason { //nolint:exhaustive // the default deliberately maps both remaining controller-state reasons to investigation_changed; operator_artifact_recorded never reaches here.
	case model.ReasonFirstAuthoritativeState:
		return model.JournalPublication
	case model.ReasonRecovered:
		return model.JournalRecovered
	case model.ReasonClosedUnknown:
		return model.JournalClosedUnknown
	case model.ReasonRecoveryFailed:
		return model.JournalRecoveryRefired
	case model.ReasonRecoveryObserved:
		return model.JournalRecoveryPending
	case model.ReasonInvestigationConcluded:
		return model.JournalEvidenceConclusion
	case model.ReasonInvestigationStarted:
		return model.JournalInvestigationStarted
	case model.ReasonAttentionChanged, model.ReasonOperatorContractChanged:
		return model.JournalOperatorContractChanged
	case model.ReasonRecurrenceMilestone:
		return model.JournalRecurrenceMilestone
	default:
		// triage_state_changed and material_assessment_changed both report
		// how the investigation itself moved.
		return model.JournalInvestigationChanged
	}
}

func journalTextFor(change AuthoritativeChange, reason model.TransitionReason) (headline, detail string) {
	summary := ""
	if change.Projection.Assessment != nil {
		summary = change.Projection.Assessment.SufficientReasonSummary
	}
	switch reason { //nolint:exhaustive // operator_artifact_recorded renders from the durable artifact itself (artifactTransition), never from here.
	case model.ReasonFirstAuthoritativeState:
		return "Situation published", summary
	case model.ReasonMaterialAssessmentChanged:
		return "Assessment conclusion changed", summary
	case model.ReasonAttentionChanged:
		return "Attention changed to " + string(change.Situation.Attention), summary
	case model.ReasonOperatorContractChanged:
		if change.Assessment.ActionContract.OperatorActionRequired != nil {
			return "Operator action required: " + string(*change.Assessment.ActionContract.OperatorActionRequired), summary
		}
		return "Operator contract changed", summary
	case model.ReasonInvestigationStarted:
		return "AlertINT investigation started", contractActionDetail(change.Assessment.ActionContract)
	case model.ReasonInvestigationConcluded:
		return "AlertINT investigation concluded", summary
	case model.ReasonRecoveryObserved:
		return "Recovery observed; watching for sustained recovery", contractActionDetail(change.Assessment.ActionContract)
	case model.ReasonRecoveryFailed:
		return "Recovery did not hold; the condition refired", contractActionDetail(change.Assessment.ActionContract)
	case model.ReasonRecovered:
		return "Recovered", summary
	case model.ReasonClosedUnknown:
		d := summary
		if change.Projection.TerminalReason != nil {
			d = "Terminal reason: " + string(*change.Projection.TerminalReason)
		}
		return "Closed with uncertainty", d
	case model.ReasonRecurrenceMilestone:
		return fmt.Sprintf("Recurrence milestone: %d occurrences", change.RecurrenceCount), summary
	case model.ReasonTriageStateChanged:
		return triageJournalText(change)
	default:
		return "Situation state changed", summary
	}
}

// triageJournalText reports what happened to Acute Triage and why, in
// closed codes only. A clean skip — Plan 2's B+ decision skip, or the
// pre-claim minimum-member skip that consumes no attempt — says so
// explicitly and never renders as investigation having run.
func triageJournalText(change AuthoritativeChange) (string, string) {
	for _, d := range change.TriageDecisions {
		if d.Decision == TriageDecisionSkip {
			return "Acute Triage skipped", "Decision: " + d.DecisionReason
		}
	}
	for _, inc := range change.Incidents {
		if inc.Triage.Phase != triagePhaseSkipped {
			continue
		}
		if inc.Triage.LatestAttempt != nil {
			return "Acute Triage skipped", "Attempt result: " + inc.Triage.LatestAttempt.ResultCode
		}
		return "Acute Triage skipped", "Closed as a clean skip before any attempt was claimed; no attempt was consumed."
	}
	for _, d := range change.TriageDecisions {
		if d.Decision == TriageDecisionRequest {
			return "Acute Triage requested", "Decision: " + d.DecisionReason
		}
	}
	for _, inc := range change.Incidents {
		if inc.Triage.LatestAttempt != nil {
			return "Acute Triage state changed", "Attempt result: " + inc.Triage.LatestAttempt.ResultCode
		}
	}
	return "Acute Triage state changed", ""
}

func contractActionStatus(c model.ActionContract) string {
	if c.AlertINTStatus == nil {
		return ""
	}
	return string(*c.AlertINTStatus)
}

func contractActionDetail(c model.ActionContract) string {
	if c.AlertINTAction == nil {
		return "Next actor: " + string(c.NextActor)
	}
	return "AlertINT action: " + string(*c.AlertINTAction) + " (" + contractActionStatus(c) + ")"
}

// ----------------------------------------------------------------------
// ProjectEpisode
// ----------------------------------------------------------------------

// ProjectEpisode folds one contiguous Transition into the durable Episode
// summary. It reads nothing but its two arguments (R3): every field comes
// from the Transition's captured projection facts and bounded journal data,
// never from mutable Incident or Situation state. Every fold advances the
// version by exactly one.
//
// It rejects a skipped or duplicated sequence, a Situation mismatch, a time
// reversal, and every mutation after a terminal Transition — a later firing
// creates a separately linked Situation through Plan 1/2 recurrence
// ownership and never reopens a terminal Episode.
func ProjectEpisode(prior *model.EpisodeSummary, t model.Transition) (model.EpisodeSummary, error) {
	if err := t.Validate(); err != nil {
		return model.EpisodeSummary{}, fmt.Errorf("situation: project episode: %w", err)
	}

	out := model.EpisodeSummary{
		SituationID:             t.SituationID,
		Version:                 1,
		InvestigationWork:       []string{},
		RecordedOperatorContext: []string{},
		PeakAttention:           t.Attention,
	}
	if prior != nil {
		if err := validateFold(*prior, t); err != nil {
			return model.EpisodeSummary{}, err
		}
		out = *prior
		out.Version = prior.Version + 1
		out.InvestigationWork = append([]string{}, prior.InvestigationWork...)
		out.RecordedOperatorContext = append([]string{}, prior.RecordedOperatorContext...)
		if attentionRank(t.Attention) > attentionRank(prior.PeakAttention) {
			out.PeakAttention = t.Attention
		}
	}

	out.SourceTransitionSequence = t.Sequence
	out.CurrentAttention = t.Attention
	out.ActionContract = t.ActionContract
	out.UpdatedAt = t.CreatedAt
	out.EffectiveStartedAt = t.Projection.EffectiveStartedAt
	out.RecoveryObservedAt = t.Projection.RecoveryObservedAt
	out.TerminalAt = t.Projection.TerminalAt
	if t.Projection.PublicHandle != nil && *t.Projection.PublicHandle != "" {
		out.PublicHandle = boundedText(*t.Projection.PublicHandle, maxHistoryIdentifier)
	}
	if out.Title == "" || t.Reason == model.ReasonFirstAuthoritativeState || t.Projection.PublicHandle != nil {
		out.Title = episodeTitle(out)
	}
	if out.RecurrenceCount < t.Journal.RecurrenceCount {
		out.RecurrenceCount = t.Journal.RecurrenceCount
	}

	if t.Reason != model.ReasonOperatorArtifactRecorded {
		if out.InitialPublicationReason == "" {
			out.InitialPublicationReason = string(t.Reason)
		}
	}
	out.LatestMaterialReason = string(t.Reason)

	if concl := t.Projection.Assessment; concl != nil {
		if concl.SufficientReasonSummary != "" {
			out.EvidenceConclusion = boundedText(concl.SufficientReasonSummary, maxHistoryDetail)
		}
		out.ImpactSummary = impactSummary(concl.Impact)
	}

	switch t.JournalKind { //nolint:exhaustive // only the accumulating journal kinds contribute to the two bounded summary lists; every other kind updates the scalar fields above.
	case model.JournalInvestigationStarted:
		out.InvestigationStarted = true
		out.InvestigationWork = appendBounded(out.InvestigationWork, investigationEntry(t), true)
	case model.JournalInvestigationChanged, model.JournalEvidenceConclusion:
		out.InvestigationWork = appendBounded(out.InvestigationWork, investigationEntry(t), true)
	case model.JournalOperatorNote, model.JournalCapturedVerdict:
		// Never collapsed: two artifacts that happen to read alike are still
		// two separate durable operator records.
		out.RecordedOperatorContext = appendBounded(out.RecordedOperatorContext, operatorContextEntry(t), false)
	}

	if out.TerminalAt != nil {
		seconds := int64(out.TerminalAt.Sub(out.EffectiveStartedAt) / time.Second)
		if seconds < 0 {
			seconds = 0
		}
		out.DurationSeconds = &seconds
		out.FinalOutcome = finalOutcome(t, out)
		out.RemainingUncertainty = remainingUncertainty(t)
	}

	if err := out.Validate(); err != nil {
		return model.EpisodeSummary{}, fmt.Errorf("situation: project episode: %w", err)
	}
	return out, nil
}

// validateFold rejects every incoherent fold: a Transition from another
// Situation, one that skips or repeats a sequence, one that moves time
// backwards, and any fold onto an already-terminal Episode — a later firing
// creates a separately linked Situation through Plan 1/2 recurrence
// ownership.
//
// The one permitted fold onto a terminal summary is the rest of the SAME
// terminal commit. R1 journals every pending operator artifact before the
// controller-state Transition, and every Transition of one commit carries
// the same captured projection (R3) — so a commit that both journals an
// artifact and closes the Situation folds an artifact Transition that
// already reports the closure, then the terminal Transition itself.
//
// "Same commit" is established by TWO facts together, because neither alone
// identifies a commit. The terminal instant is a DURABLE value that
// resolveLifecycle carries forward unchanged on every later cycle, so a
// matching Projection.TerminalAt proves only "the same closure", not "the
// same write". The commit identity is the instant: every Transition of one
// commit is stamped with that reconciliation's single Now (newTransition),
// and each fold copies it onto the summary as UpdatedAt — so
// t.CreatedAt.Equal(prior.UpdatedAt) holds for the rest of this commit and
// for nothing later. Requiring both keeps "a terminal Episode never
// reopens" an invariant of THIS function rather than something only
// ClaimDueSituations' active/recovery_pending filter happens to prevent —
// which matters for any future path that reconciles an already-terminal
// Situation (migration 0017's own header contemplates one: an idempotent
// upgrade_reconstruction for Plan 1/2 Situations that predate the ledger).
func validateFold(prior model.EpisodeSummary, t model.Transition) error {
	sameTerminalCommit := prior.TerminalAt != nil && t.Projection.TerminalAt != nil &&
		t.Projection.TerminalAt.Equal(*prior.TerminalAt) &&
		t.CreatedAt.Equal(prior.UpdatedAt)
	switch {
	case prior.SituationID != t.SituationID:
		return fmt.Errorf("situation: project episode: transition belongs to situation %q, summary to %q",
			t.SituationID, prior.SituationID)
	case prior.TerminalAt != nil && !sameTerminalCommit:
		return fmt.Errorf("situation: project episode: episode is terminal at %s and never reopens", prior.TerminalAt)
	case t.Sequence != prior.SourceTransitionSequence+1:
		return fmt.Errorf("situation: project episode: transition sequence %d is not contiguous with summary sequence %d",
			t.Sequence, prior.SourceTransitionSequence)
	case t.CreatedAt.Before(prior.UpdatedAt):
		return fmt.Errorf("situation: project episode: transition created at %s precedes summary updated at %s",
			t.CreatedAt, prior.UpdatedAt)
	}
	return nil
}

// episodeTitle names the Episode by the immutable Situation handle once one
// is assigned, and by the Situation ID before that. R3 restricts the fold
// to closed codes and the bounded Sufficient-reason summary, so there is no
// human-authored title to copy; renderers compose the operator-facing
// heading from this label plus the summary's own fields.
func episodeTitle(s model.EpisodeSummary) string {
	if s.PublicHandle != "" {
		return boundedText("Situation "+s.PublicHandle, maxHistoryHeadline)
	}
	return boundedText("Situation "+s.SituationID, maxHistoryHeadline)
}

func investigationEntry(t model.Transition) string {
	entry := t.Journal.Headline
	if t.Journal.Detail != "" {
		entry += " — " + t.Journal.Detail
	}
	return boundedText(entry, maxHistoryDetail)
}

func operatorContextEntry(t model.Transition) string {
	entry := t.Journal.Headline
	if t.Journal.AttributedActor != "" {
		entry = t.Journal.AttributedActor + ": " + entry
	}
	return boundedText(entry, maxHistoryDetail)
}

// appendBounded keeps a bounded accumulation: the list never exceeds its
// bound (the oldest entry is dropped; the immutable Transition ledger keeps
// the full history). With collapseRepeat, an entry identical to the last
// one does not grow the list — repeated identical investigation lines say
// nothing new.
func appendBounded(list []string, entry string, collapseRepeat bool) []string {
	if strings.TrimSpace(entry) == "" {
		return list
	}
	if collapseRepeat && len(list) > 0 && list[len(list)-1] == entry {
		return list
	}
	list = append(list, entry)
	if len(list) > maxHistoryListEntries {
		list = list[len(list)-maxHistoryListEntries:]
	}
	return list
}

func impactSummary(i model.Impact) string {
	switch i { //nolint:exhaustive // unknown (and any zero value) is the default.
	case model.ImpactConfirmed:
		return "Confirmed impact"
	case model.ImpactSuspected:
		return "Suspected impact"
	case model.ImpactNoneObserved:
		return "No impact observed"
	default:
		return "Impact unknown"
	}
}

// finalOutcome states what happened, and never collapses a terminal
// Situation to "no action": with no recorded operator artifact it says so
// explicitly rather than implying AlertINT or anyone else acted.
func finalOutcome(t model.Transition, s model.EpisodeSummary) string {
	if t.Projection.TerminalReason != nil {
		return boundedText("Closed with uncertainty ("+string(*t.Projection.TerminalReason)+")", maxHistoryDetail)
	}
	if len(s.RecordedOperatorContext) == 0 {
		return "Recovered without recorded operator intervention"
	}
	return "Recovered with recorded operator context"
}

func remainingUncertainty(t model.Transition) string {
	if t.Projection.TerminalReason == nil {
		return ""
	}
	out := "AlertINT could not confirm resolution: " + string(*t.Projection.TerminalReason) + "."
	if c := t.Projection.Assessment; c != nil && c.EvidenceQuality != model.EvidenceQualityComplete {
		out += " Evidence quality: " + string(c.EvidenceQuality) + "."
	}
	return boundedText(out, maxHistoryDetail)
}

func attentionRank(a model.Attention) int {
	switch a { //nolint:exhaustive // observe (and any zero value) is rank 0, the default.
	case model.AttentionUrgent:
		return 2
	case model.AttentionInvestigate:
		return 1
	default:
		return 0
	}
}

// ----------------------------------------------------------------------
// Orientation
// ----------------------------------------------------------------------

// Orientation is the single currently-emphasized phase of the Situation's
// compact orientation line. It is pure derived presentation, never another
// persisted lifecycle: phase movement alone creates no Transition.
type Orientation string

const (
	OrientationObserved        Orientation = "observed"
	OrientationInvestigating   Orientation = "investigating"
	OrientationMonitoring      Orientation = "monitoring"
	OrientationRecovered       Orientation = "recovered"
	OrientationClosedUncertain Orientation = "closed_uncertain"
)

// DeriveOrientation reports which phase the root currently emphasizes,
// from the accepted Transition and the folded Episode summary alone:
//
//	Observed -> Investigating -> Monitoring -> Recovered
//	Observed -> Investigating -> Closed uncertain
//
// A refire returns emphasis from Monitoring to Investigating (the summary
// keeps InvestigationStarted), and a direct closed_unknown never invents
// Monitoring. Which phases the rendered chain SHOWS — in particular whether
// a closed_unknown chain includes Monitoring at all — additionally needs
// the Situation's Transition history, which the Slack renderer reads.
func DeriveOrientation(summary model.EpisodeSummary, latest model.Transition) Orientation {
	switch latest.Lifecycle { //nolint:exhaustive // active is the default branch, where Observed and Investigating are told apart.
	case model.LifecycleRecovered:
		return OrientationRecovered
	case model.LifecycleClosedUnknown:
		return OrientationClosedUncertain
	case model.LifecycleRecoveryPending:
		return OrientationMonitoring
	default:
		if summary.InvestigationStarted || investigationCurrent(latest.ActionContract) ||
			latest.ActionContract.OperatorActionRequired != nil {
			return OrientationInvestigating
		}
		return OrientationObserved
	}
}

// ----------------------------------------------------------------------
// Composition
// ----------------------------------------------------------------------

// BuildHistoryCommit runs this task's three pure functions in the order the
// fenced commit applies them: derive the Transitions, fold the Episode
// summary once per Transition in sequence order, then plan the notification
// intents for the resulting publication.
//
// publication supplies only the delivery-side context — the committed
// contract deadline, whether the root is published, the last delivered root
// promise, the last main-channel poke, the operator's Slack floor, and the
// repage cooldown. Its Transitions and Summary fields are derived here and
// must be left zero; Situation/Drill/Now must match change.
//
// Task 5 may equally call BuildTransitions, ProjectEpisode, and
// PlanNotificationIntents itself when it needs the intermediate values.
func BuildHistoryCommit(change AuthoritativeChange, publication PublicationInput) (HistoryCommit, error) {
	if len(publication.Transitions) != 0 || publication.Summary.SituationID != "" || publication.Summary.Version != 0 {
		return HistoryCommit{}, errors.New("situation: build history commit: publication input must not carry transitions or a summary; both are derived here")
	}
	if publication.Situation.ID != change.Situation.ID {
		return HistoryCommit{}, fmt.Errorf("situation: build history commit: publication situation %q does not match change situation %q",
			publication.Situation.ID, change.Situation.ID)
	}
	if !publication.Now.Equal(change.Now) {
		return HistoryCommit{}, fmt.Errorf("situation: build history commit: publication now %s does not match change now %s",
			publication.Now, change.Now)
	}
	if publication.Drill != change.Drill {
		return HistoryCommit{}, errors.New("situation: build history commit: publication and change disagree about the Drill marker")
	}

	transitions, err := BuildTransitions(change)
	if err != nil {
		return HistoryCommit{}, err
	}

	commit := HistoryCommit{Transitions: transitions}
	prior := change.PriorSummary
	for i, tr := range transitions {
		folded, err := ProjectEpisode(prior, tr)
		if err != nil {
			return HistoryCommit{}, fmt.Errorf("situation: build history commit: transition %d: %w", i, err)
		}
		commit.Summary = &folded
		prior = commit.Summary
	}

	publication.Transitions = transitions
	if commit.Summary != nil {
		publication.Summary = *commit.Summary
	} else if change.PriorSummary != nil {
		publication.Summary = *change.PriorSummary
	}
	if publication.PriorTransition == nil {
		publication.PriorTransition = change.PriorTransition
	}
	intents, err := PlanNotificationIntents(publication)
	if err != nil {
		return HistoryCommit{}, err
	}
	commit.Intents = intents
	return commit, nil
}

// ----------------------------------------------------------------------
// Small local helpers.
// ----------------------------------------------------------------------

// boundedText truncates s to at most limit bytes without splitting a rune.
func boundedText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

func derefAlertINTAction(a *model.AlertINTAction) string {
	if a == nil {
		return ""
	}
	return string(*a)
}

func derefAlertINTStatus(s *model.AlertINTStatus) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func derefOperatorAction(o *model.OperatorAction) string {
	if o == nil {
		return ""
	}
	return string(*o)
}

func derefWaitReason(w *model.WaitReason) string {
	if w == nil {
		return ""
	}
	return string(*w)
}
