// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 4: deterministic Interruption priority and main-channel poke
// classification (spec.md "Publication authority and Interruption
// priority"). Both are pure functions of one already-derived Transition
// (plus, for the poke class, the Transition it followed): the controller
// decides publication authority, and Slack delivery never makes a second
// publication decision.
// ----------------------------------------------------------------------

// DeriveInterruptionPriority ranks one Transition on the closed
// deterministic scale the operator's `notify.slack.min_severity` floor is
// compared against. It is never Alert severity and never model-authored
// severity:
//
//	critical  an unquieted deterministic critical floor
//	high      urgent Attention, operator judgment/action required, or
//	          actionable terminal uncertainty
//	medium    non-critical warranted investigation while AlertINT remains
//	          the next actor
//	low       informational standalone interruption
//
// "Unquieted" is the freshness test: a deterministic critical floor only
// ranks critical while the Situation is still nonterminal — a recovered
// Situation's historical criticality never re-pages. Recovery/refire and
// recurrence reach the poke decision through ClassifyPoke (a refire is
// ranked by the Attention and contract it lands in; a recurrence milestone
// is never a poke at all), not by inflating this rank.
func DeriveInterruptionPriority(t model.Transition) model.InterruptionPriority {
	terminal := t.Lifecycle.Terminal()
	switch {
	case !terminal && deterministicCriticalFloor(t):
		return model.InterruptionCritical
	case !terminal && t.Attention == model.AttentionUrgent:
		return model.InterruptionHigh
	case !terminal && t.ActionContract.OperatorActionRequired != nil:
		return model.InterruptionHigh
	case t.Lifecycle == model.LifecycleClosedUnknown:
		// Actionable terminal uncertainty: AlertINT closed the Situation
		// without being able to confirm resolution.
		return model.InterruptionHigh
	case !terminal && t.Attention == model.AttentionInvestigate && t.ActionContract.NextActor == model.NextActorAlertINT:
		return model.InterruptionMedium
	default:
		return model.InterruptionLow
	}
}

// deterministicCriticalFloor reports whether the Transition's accepted
// Sufficient reason is the catalog's deterministic critical floor
// (reasons.go's critical_anchor — the only DeterministicFloor candidate
// Plan 2 can reach).
func deterministicCriticalFloor(t model.Transition) bool {
	return t.Projection.Assessment != nil && t.Projection.Assessment.SufficientReasonCode == reasonCodeCriticalAnchor
}

// PublicationAuthority reports whether t carries the controller's
// deterministic publication authority: an unquieted deterministic floor or
// a validated Sufficient reason (spec.md "Publication authority and
// Interruption priority": "The controller derives publication authority
// from deterministic floors and a validated Sufficient reason"). A
// Situation whose authority Transition carries neither is quiet — it keeps
// its state, Transitions, and MCP history, but has no claim on Slack at
// all, so it never creates a Slack intent (not even a withheld one). The
// operator's Slack floor is a separate, later question: it ranks a
// PERMITTED new poke against the operator's minimum and can never grant an
// authority the Transition does not have. Lifecycle alone grants none
// either: a quiet Situation closing with uncertainty is still quiet.
//
// Urgent Attention counts as the floor: validateProposalContent rejects
// urgent without a deterministic anchor (`urgent_without_floor`) and raises
// Attention to urgent whenever one is active, but it does not select the
// anchor as the Sufficient reason when the model omitted it — so a floored
// Transition may carry urgent Attention with no reason code, and that
// Attention is itself proof of the proven floor.
func PublicationAuthority(t model.Transition) bool {
	if deterministicCriticalFloor(t) || t.Attention == model.AttentionUrgent {
		return true
	}
	return t.Projection.Assessment != nil && strings.TrimSpace(t.Projection.Assessment.SufficientReasonCode) != ""
}

// MeetsSlackFloor reports whether priority is at or above the operator's
// configured minimum Interruption priority. An empty floor is "no floor".
// critical always passes.
func MeetsSlackFloor(priority, floor model.InterruptionPriority) bool {
	return !priority.Less(floor)
}

// PokeClass names which entry on spec.md's closed list of permitted new
// main-channel pokes a Transition qualifies for, or PokeNone.
type PokeClass string

const (
	// PokeNone means this Transition may never create a new main-channel
	// poke. Root edits and non-broadcast replies are never pokes.
	PokeNone PokeClass = ""
	// PokeFirstPublication is the Situation's first warranted publication.
	PokeFirstPublication PokeClass = "first_publication"
	// PokeCriticalityCrossed is newly crossed deterministic criticality.
	PokeCriticalityCrossed PokeClass = "criticality_crossed"
	// PokeUrgentAttention is newly valid urgent Attention.
	PokeUrgentAttention PokeClass = "urgent_attention"
	// PokeOperatorHandoff is a no-action to operator-judgment/action handoff.
	PokeOperatorHandoff PokeClass = "operator_handoff"
	// PokeRequiredActionChanged is a materially changed required action; it
	// is the one class the configured repage cooldown gates.
	PokeRequiredActionChanged PokeClass = "required_action_changed"
)

// CooldownApplies reports whether this poke class must wait out the
// configured repage cooldown after the last delivered main-channel poke.
// Only a materially changed required action does; every escalation class
// (first publication, newly crossed criticality, newly urgent Attention, a
// handoff) bypasses it, because a cooldown must never swallow an
// escalation.
func (c PokeClass) CooldownApplies() bool { return c == PokeRequiredActionChanged }

// ClassifyPoke reports which permitted poke class t qualifies for, given
// the Transition it directly follows (nil when t is the Situation's first
// Transition). It answers the class question only: whether the poke is
// actually emitted also depends on the repage cooldown, the operator's
// Slack floor, and whether the root is already published — all of which
// PlanNotificationIntents owns.
func ClassifyPoke(prior *model.Transition, t model.Transition) PokeClass {
	switch t.Reason { //nolint:exhaustive // only these two reasons are categorically ineligible; every other reason continues to the class tests below.
	case model.ReasonOperatorArtifactRecorded:
		// An attributed annotation or Captured verdict grants no
		// publication authority (spec.md "Domain model").
		return PokeNone
	case model.ReasonRecurrenceMilestone:
		// Recurrence stays in the owning Situation thread; a flapper never
		// re-pages the channel (ADR-0020).
		return PokeNone
	}
	if prior == nil {
		return PokeFirstPublication
	}
	if t.Lifecycle.Terminal() {
		// Recovery and closure are reported by editing the root and
		// appending the journal, never by a new interruption.
		return PokeNone
	}
	switch {
	case deterministicCriticalFloor(t) && !deterministicCriticalFloor(*prior):
		return PokeCriticalityCrossed
	case t.Attention == model.AttentionUrgent && prior.Attention != model.AttentionUrgent:
		return PokeUrgentAttention
	case t.ActionContract.OperatorActionRequired != nil && prior.ActionContract.OperatorActionRequired == nil:
		return PokeOperatorHandoff
	case t.ActionContract.OperatorActionRequired != nil &&
		operatorContractTuple(prior.ActionContract) != operatorContractTuple(t.ActionContract):
		return PokeRequiredActionChanged
	default:
		return PokeNone
	}
}

// HandoffStillCurrent answers the deliverer's revalidation question for one
// broadcast_handoff (spec.md "Recovery replay": "if its requested action is
// no longer current, the same Transition is delivered as a non-broadcast
// entry marked delayed and no longer current"). It compares the poke's
// durable INTERRUPTION BASIS with the Situation's current authoritative
// state — never mere equality with the latest Transition sequence, which
// an attributed annotation advances without steering anything (review
// round 1, R1-F5):
//
//   - a terminal Situation has no current interruption;
//   - de-escalated Attention demotes the poke it followed;
//   - a handoff that asked the operator for something stays current only
//     while the current Operator contract still asks for the same thing
//     (operatorContractTuple, the same basis PokeRequiredActionChanged is
//     judged on); an escalation poke that asked for no operator action
//     (newly urgent Attention, newly crossed criticality) is current while
//     its Attention still holds.
//
// A summary that does not yet include the handoff cannot confirm it and
// counts as not current.
func HandoffStillCurrent(handoff model.Transition, summary model.EpisodeSummary) bool {
	if summary.SourceTransitionSequence < handoff.Sequence || summary.TerminalAt != nil {
		return false
	}
	if attentionRank(summary.CurrentAttention) < attentionRank(handoff.Attention) {
		return false
	}
	if handoff.ActionContract.OperatorActionRequired == nil {
		return true
	}
	return summary.ActionContract.OperatorActionRequired != nil &&
		operatorContractTuple(summary.ActionContract) == operatorContractTuple(handoff.ActionContract)
}
