// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "github.com/alertint/alertint-agent/internal/situation/model"

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
