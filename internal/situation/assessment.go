// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// AssessmentSchemaVersion is the one authoritative Assessment schema version
// this controller validates. A proposal against another version is rejected
// outright — catalog/schema changes are versioned, never silently
// reinterpreted.
const AssessmentSchemaVersion = 1

// AssessmentClient is the narrow L2 model boundary. It mirrors
// acutetriage.LLMClient's shape so a shared provider client satisfies both.
type AssessmentClient interface {
	Complete(ctx context.Context, system string, prompt llm.Prompt, requiredKeys []string) (llm.Completion, error)
}

// urgentFloorPriority orders the four deterministic urgent floor codes for
// deterministic SufficientReason substitution when more than one is eligible
// at once (rare, e.g. a critical anchor during an already-expanding blast
// radius) — critical_anchor first, matching DeriveInterruptionPriority's own
// special case for it.
var urgentFloorPriority = []string{"critical_anchor", "confirmed_severe_impact", "expanding_blast_radius", "urgent_policy"}

// ValidateAssessment closes the gap between a proposed Assessment (model
// output or a deterministic degraded proposal) and the one an authoritative
// commit may use. It never invents a Sufficient reason and never lets L2
// downgrade a deterministic urgent floor: floors are recomputed from
// snapshot alone, independent of what the proposal claims. Two enforcement
// styles are used side by side, matching the spec: unsupported causal claims
// and attention below an active floor are downgraded/raised deterministically
// (returned as adjustments, no error); everything else that violates policy
// is rejected outright — no prompt-around retry follows a rejection.
func ValidateAssessment(snapshot Snapshot, proposal model.Assessment, now time.Time) (model.Assessment, []model.ValidationAdjustment, error) {
	if now.IsZero() {
		return model.Assessment{}, nil, errors.New("situation: assessment validation requires the current time")
	}
	if proposal.SchemaVersion != AssessmentSchemaVersion {
		return model.Assessment{}, nil, errors.New("situation: assessment schema version is not the authoritative version")
	}
	if err := validateAssessmentEnums(proposal); err != nil {
		return model.Assessment{}, nil, err
	}
	// Lifecycle is controller-owned (D4): the proposal may only echo the
	// lifecycle it was given as input. A conflicting value is a policy
	// violation, not something the validator can repair — only the
	// controller may initiate a lifecycle transition.
	if proposal.Lifecycle != snapshot.Lifecycle {
		return model.Assessment{}, nil, errors.New("situation: assessment lifecycle is controller-owned and cannot be proposed")
	}
	if proposal.SufficientReason != nil && len(proposal.SufficientReason.EvidenceRefs) == 0 {
		return model.Assessment{}, nil, errors.New("situation: assessment sufficient reason must cite evidence")
	}

	out := proposal
	var adjustments []model.ValidationAdjustment

	// Deterministic urgent floors are recomputed from the snapshot alone —
	// never from what the proposal claims — so L2 cannot mint or suppress
	// one. floorAttention is Urgent exactly when an eligible deterministic
	// floor candidate is present.
	floorAttention := ApplyAttentionFloors(model.AttentionObserve, snapshot, snapshot.EligibleReasons)
	if proposal.Attention == model.AttentionUrgent && floorAttention != model.AttentionUrgent {
		return model.Assessment{}, nil, errors.New("situation: urgent attention requires a deterministic anchor; a model cannot mint one")
	}
	if floorAttention == model.AttentionUrgent && proposal.Attention != model.AttentionUrgent {
		out.Attention = model.AttentionUrgent
		adjustments = append(adjustments, model.ValidationAdjustment{
			Code: "attention_floor_enforced", Detail: "a deterministic urgent floor cannot be overridden downward by L2",
		})
	}

	if out.Attention == model.AttentionUrgent {
		reason, ok := matchingEligibleReason(snapshot, out.SufficientReason)
		if !ok || !reason.DeterministicFloor {
			floor, found := selectUrgentFloorReason(snapshot)
			if !found {
				return model.Assessment{}, nil, errors.New("situation: urgent attention has no eligible deterministic floor reason to cite")
			}
			out.SufficientReason = sufficientReasonFromCandidate(floor, out.SufficientReason)
			adjustments = append(adjustments, model.ValidationAdjustment{
				Code: "sufficient_reason_substituted", Detail: "the proposed reason did not cite the active deterministic floor; substituted the floor candidate",
			})
		}
	} else if out.Attention == model.AttentionInvestigate {
		reason, ok := matchingEligibleReason(snapshot, out.SufficientReason)
		if !ok {
			return model.Assessment{}, nil, errors.New("situation: a non-critical publication requires a matching eligible reason candidate")
		}
		_ = reason
	} else if out.SufficientReason != nil {
		// Observe requires no reason, but a cited one still must be real.
		if _, ok := matchingEligibleReason(snapshot, out.SufficientReason); !ok {
			return model.Assessment{}, nil, errors.New("situation: cited sufficient reason is not an eligible candidate")
		}
	}

	// Temporal co-occurrence alone cannot become supported causality:
	// Supported requires a real, evidence-bound reason; anything weaker is
	// downgraded deterministically rather than rejected.
	if out.Causality == model.CausalitySupported {
		if _, ok := matchingEligibleReason(snapshot, out.SufficientReason); !ok {
			out.Causality = model.CausalityCorrelated
			adjustments = append(adjustments, model.ValidationAdjustment{
				Code: "causality_downgraded_unsupported", Detail: "supported causality requires an evidence-bound eligible reason; downgraded to correlated",
			})
		}
	}

	if err := validateActionContract(out); err != nil {
		return model.Assessment{}, nil, err
	}
	if err := validateUpdateSchedule(out, now); err != nil {
		return model.Assessment{}, nil, err
	}

	return out, adjustments, nil
}

func validateAssessmentEnums(a model.Assessment) error {
	switch a.Persistence {
	case model.PersistenceTransient, model.PersistenceSustained, model.PersistenceUnknown:
	default:
		return errors.New("situation: assessment persistence is not a recognized value")
	}
	switch a.Impact {
	case model.ImpactNoneObserved, model.ImpactSuspected, model.ImpactConfirmed, model.ImpactUnknown:
	default:
		return errors.New("situation: assessment impact is not a recognized value")
	}
	switch a.Novelty {
	case model.NoveltyFamiliar, model.NoveltyChanged, model.NoveltyNew, model.NoveltyInsufficientHistory:
	default:
		return errors.New("situation: assessment novelty is not a recognized value")
	}
	switch a.Causality {
	case model.CausalitySupported, model.CausalityCorrelated, model.CausalityContradicted, model.CausalityUnknown, model.CausalityOperatorConfirmed:
	default:
		return errors.New("situation: assessment causality is not a recognized value")
	}
	switch a.Attention {
	case model.AttentionObserve, model.AttentionInvestigate, model.AttentionUrgent:
	default:
		return errors.New("situation: assessment attention is not a recognized value")
	}
	switch a.Lifecycle {
	case model.LifecycleActive, model.LifecycleRecoveryPending, model.LifecycleRecovered, model.LifecycleClosedUnknown:
	default:
		return errors.New("situation: assessment lifecycle is not a recognized value")
	}
	switch a.EvidenceQuality {
	case model.EvidenceQualityComplete, model.EvidenceQualityDegraded, model.EvidenceQualityInsufficient:
	default:
		return errors.New("situation: assessment evidence quality is not a recognized value")
	}
	switch a.ActionContract.NextActor {
	case model.NextActorAlertint, model.NextActorOperator, model.NextActorNone:
	default:
		return errors.New("situation: assessment next actor is not a recognized value")
	}
	switch a.ActionContract.ActionStatus {
	case model.ActionStatusPlanned, model.ActionStatusRunning, model.ActionStatusBlocked,
		model.ActionStatusExhausted, model.ActionStatusComplete, model.ActionStatusWaiting:
	default:
		return errors.New("situation: assessment action status is not a recognized value")
	}
	return nil
}

// validateActionContract enforces actor/action consistency and that
// `running` is claimed only for AlertINT's own dispatched work.
func validateActionContract(a model.Assessment) error {
	ac := a.ActionContract
	switch ac.NextActor {
	case model.NextActorNone:
		if nonempty(ac.AlertintAction) || nonempty(ac.OperatorActionRequired) || nonempty(ac.OperatorJudgmentRequested) {
			return errors.New("situation: action contract names work for an actor while next actor is none")
		}
	case model.NextActorAlertint:
		if nonempty(ac.OperatorActionRequired) || nonempty(ac.OperatorJudgmentRequested) {
			return errors.New("situation: action contract requests operator work while next actor is alertint")
		}
	case model.NextActorOperator:
		if nonempty(ac.AlertintAction) {
			return errors.New("situation: action contract names alertint work while next actor is operator")
		}
	}
	if ac.ActionStatus == model.ActionStatusRunning && (ac.NextActor != model.NextActorAlertint || !nonempty(ac.AlertintAction)) {
		return errors.New("situation: action status running requires alertint's own dispatched action")
	}
	return nil
}

// validateUpdateSchedule enforces the next_update_at contract: required and
// strictly future for a nonterminal Assessment, absent for a terminal one.
func validateUpdateSchedule(a model.Assessment, now time.Time) error {
	terminal := a.Lifecycle == model.LifecycleRecovered || a.Lifecycle == model.LifecycleClosedUnknown
	if terminal {
		if a.ActionContract.NextUpdateAt != nil || len(a.ActionContract.NextUpdateOn) > 0 {
			return errors.New("situation: a terminal assessment must not carry a next update schedule")
		}
		return nil
	}
	if a.ActionContract.NextUpdateAt == nil {
		return errors.New("situation: a nonterminal assessment requires next_update_at")
	}
	if !a.ActionContract.NextUpdateAt.After(now) {
		return errors.New("situation: next_update_at must be strictly in the future")
	}
	return nil
}

// matchingEligibleReason resolves a proposal's cited SufficientReason against
// the snapshot's own freshly generated eligible candidates by exact
// candidate ID — the only way L2 can select a reason, never invent one. The
// candidate ID already binds code, predicate version, and evidence
// references, so an ID match is a complete match.
func matchingEligibleReason(snapshot Snapshot, cited *model.SufficientReason) (model.ReasonCandidate, bool) {
	if cited == nil || strings.TrimSpace(cited.CandidateID) == "" {
		return model.ReasonCandidate{}, false
	}
	for _, candidate := range snapshot.EligibleReasons {
		if candidate.ID == cited.CandidateID {
			return candidate, true
		}
	}
	return model.ReasonCandidate{}, false
}

// selectUrgentFloorReason returns the highest-priority eligible deterministic
// urgent floor candidate, if any.
func selectUrgentFloorReason(snapshot Snapshot) (model.ReasonCandidate, bool) {
	for _, code := range urgentFloorPriority {
		for _, candidate := range snapshot.EligibleReasons {
			if candidate.Code == code && candidate.DeterministicFloor {
				return candidate, true
			}
		}
	}
	return model.ReasonCandidate{}, false
}

func sufficientReasonFromCandidate(candidate model.ReasonCandidate, priorSummary *model.SufficientReason) *model.SufficientReason {
	summary := "deterministic urgent floor"
	if priorSummary != nil && strings.TrimSpace(priorSummary.Summary) != "" {
		summary = priorSummary.Summary
	}
	return &model.SufficientReason{
		Code: candidate.Code, CandidateID: candidate.ID, Summary: summary,
		EvidenceRefs: append([]string(nil), candidate.EvidenceRefs...),
	}
}
