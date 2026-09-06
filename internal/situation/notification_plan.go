// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 4: pure notification-intent planning. Publication authority
// is decided here, inside the authoritative controller commit's own
// derivation — Slack delivery never makes a second publication decision,
// and nothing in this file renders Slack.
// ----------------------------------------------------------------------

// PublicationInput is one committed reconciliation plus the delivery-side
// context the publication decision needs.
type PublicationInput struct {
	Situation model.Situation
	// Transitions is this commit's, in sequence order; empty on a
	// non-material cycle.
	Transitions []model.Transition
	// Summary is the Episode summary current after the fold. On a
	// non-material cycle it is the unchanged current summary.
	Summary model.EpisodeSummary
	// PriorTransition is the Situation's current Transition before this
	// commit — the authority a non-material R4 deadline refresh references,
	// since such a cycle creates no Transition of its own.
	PriorTransition *model.Transition
	// ContractDeadlineAt is the committed nonterminal next_update_at (R4):
	// the promise the root renders. Nil for a terminal commit.
	ContractDeadlineAt    *time.Time
	RootPublished         bool
	LatestRootSyncVersion *int
	// RootPublicationOwed reports whether an earlier root projection for
	// this Situation is still owed to Slack (pending, configuration-blocked,
	// or failed) — see SnapshotInput.RootPublicationOwed.
	RootPublicationOwed         bool
	LastDeliveredRootDeadlineAt *time.Time
	LastMainChannelPokeAt       *time.Time
	SlackFloor                  model.InterruptionPriority
	RepageCooldown              time.Duration
	// RecurrenceRepliesOff is notify.slack.recurrence_mode = off: a
	// recurrence milestone still creates its Transition and still edits
	// the root (the count updates in place), but posts no thread entry.
	RecurrenceRepliesOff bool
	Drill                bool
	Now                  time.Time
}

// PlanNotificationIntents derives every durable Slack obligation one
// committed reconciliation creates. A commit for a Situation that has
// never earned Slack (no published or owed root) creates NOTHING unless its
// authority Transition carries publication authority (PublicationAuthority);
// otherwise it creates:
//
//   - one coalescible `root_sync` carrying the current Episode-summary
//     version and the committed contract deadline it renders (R4);
//   - exactly one immutable reply per journaled Transition, in sequence
//     order, each rendering only its own Transition's stored journal data:
//     `thread_append` for a quiet entry, or `broadcast_handoff` for the one
//     Transition (at most) that may create a new main-channel poke — when
//     the permitted poke class allows it, the repage cooldown has elapsed
//     for the one class it gates, and the root is already published (an
//     unpublished root's first post IS the poke). The two classes render
//     the same journal data, so a poked Transition never also gets a
//     thread entry: that would post it to Slack twice;
//   - on a non-material cycle, only the R4 deadline refresh, and only when
//     the root is published, its last delivered promise has passed, and
//     this commit carries a different deadline.
//
// A poke below the operator's Slack floor becomes a durable
// `withheld_by_operator_slack_floor` decision, never an absent row, and the
// floor never suppresses a non-broadcast journal entry — a withheld
// broadcast is therefore the one case where a Transition carries two
// intents, of which only the quiet thread entry is ever delivered.
func PlanNotificationIntents(in PublicationInput) ([]model.NotificationIntent, error) {
	if err := validatePublicationInput(in); err != nil {
		return nil, err
	}
	if len(in.Transitions) == 0 {
		return planDeadlineRefresh(in)
	}

	authority := in.Transitions[len(in.Transitions)-1]

	// Publication authority comes BEFORE the floor. A Situation that has
	// never earned Slack — no published root, no root still owed — and
	// whose authority Transition carries neither a deterministic floor nor
	// a validated Sufficient reason is quiet: it creates no intent at all,
	// not a withheld one, because nothing was ever permitted that could be
	// withheld (spec.md: "quiet and floor-withheld Situations leave no
	// Slack trace"; the priority scale ranks a PERMITTED poke, it does not
	// grant permission). Once a root is on screen or owed, every later
	// commit keeps synchronizing it regardless of the Sufficient reason:
	// the floor "never suppresses ... an already-published root edit", and
	// a quiet terminal Transition is exactly the "latest informative
	// terminal Episode summary" the ordinary-delay rule posts.
	if !in.RootPublished && !in.RootPublicationOwed && !PublicationAuthority(authority) {
		return nil, nil
	}

	out := make([]model.NotificationIntent, 0, len(in.Transitions)+2)

	// The root: a first publication is itself the main-channel poke; every
	// later synchronization is a silent edit.
	rootPoke := !in.RootPublished
	root := newIntent(in, model.EffectRootSync, authority, rootSyncKey(in.Situation.ID, in.Summary.Version, authority.ID, in.ContractDeadlineAt))
	root.SummaryVersion = intPtrOf(in.Summary.Version)
	if !authority.Lifecycle.Terminal() {
		root.ContractDeadlineAt = in.ContractDeadlineAt
	}
	if rootPoke {
		priority := DeriveInterruptionPriority(authority)
		root.MainChannelPoke = true
		root.InterruptionPriority = &priority
		// The floor gates a NEW interruption. It does not revoke one the
		// operator already permitted: while an earlier root projection is
		// still owed to Slack, this projection is that same unmet first
		// publication re-rendered at the current summary version, and
		// spec.md's ordinary-delay rule publishes the latest informative
		// root rather than erasing an earned, merely-queued one. Withholding
		// here would also strand the projection it replaces — every later
		// journal entry waits on a root that would then never deliver.
		if !MeetsSlackFloor(priority, in.SlackFloor) && !in.RootPublicationOwed {
			root.Status = model.IntentWithheld
		}
	}
	out = append(out, root)

	// At most one new main-channel poke per commit, and none at all when
	// the root post above already is one. Deciding this BEFORE the journal
	// loop is what keeps a poked Transition from being delivered twice.
	pokeSequence := 0
	if !rootPoke {
		if poke, ok := selectPoke(in); ok {
			pokeSequence = poke.Sequence
		}
	}

	// Immutable journal entries, one per journaled Transition, in sequence
	// order. Each Transition produces exactly ONE reply: the poked one is
	// broadcast (a handoff edits the root and then creates one broadcast
	// reply), every other one is a quiet thread entry. Both classes render
	// the same stored journal data, so emitting both for one Transition
	// would post it to Slack twice.
	for _, tr := range in.Transitions {
		poked := pokeSequence != 0 && tr.Sequence == pokeSequence
		if tr.JournalKind == model.JournalNone && !poked {
			continue
		}
		if tr.Reason == model.ReasonRecurrenceMilestone && in.RecurrenceRepliesOff {
			// recurrence_mode: off keeps recurrence to the root's silent
			// count update (the root_sync above); a milestone is never a
			// poke, so nothing else is lost.
			continue
		}
		if !poked {
			out = append(out, newIntent(in, model.EffectThreadAppend, tr,
				threadKey(model.EffectThreadAppend, in.Situation.ID, tr.Sequence)))
			continue
		}

		priority := DeriveInterruptionPriority(tr)
		broadcast := newIntent(in, model.EffectBroadcastHandoff, tr,
			threadKey(model.EffectBroadcastHandoff, in.Situation.ID, tr.Sequence))
		broadcast.MainChannelPoke = true
		broadcast.InterruptionPriority = &priority
		if MeetsSlackFloor(priority, in.SlackFloor) {
			out = append(out, broadcast)
			continue
		}
		// Below the operator's floor the poke is withheld as a durable
		// decision, never an absent row — but the floor "never suppresses
		// ... a non-broadcast journal entry", so the same Transition still
		// gets its quiet thread entry. Only one of the two is ever
		// delivered, so this is not the duplicate the branch above avoids.
		broadcast.Status = model.IntentWithheld
		out = append(out,
			newIntent(in, model.EffectThreadAppend, tr, threadKey(model.EffectThreadAppend, in.Situation.ID, tr.Sequence)),
			broadcast)
	}

	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, fmt.Errorf("situation: planned notification intent %d: %w", i, err)
		}
	}
	return out, nil
}

func validatePublicationInput(in PublicationInput) error {
	if in.Situation.ID == "" {
		return errors.New("situation: publication input: situation id is required")
	}
	if in.Now.IsZero() || in.Now.Location() != time.UTC {
		return fmt.Errorf("situation: publication input: now must be a non-zero UTC instant, got %s", in.Now)
	}
	if in.SlackFloor != "" {
		if err := in.SlackFloor.Validate(); err != nil {
			return fmt.Errorf("situation: publication input: %w", err)
		}
	}
	if in.RepageCooldown < 0 {
		return fmt.Errorf("situation: publication input: repage cooldown must be >= 0, got %s", in.RepageCooldown)
	}
	if in.Summary.SituationID != "" && in.Summary.SituationID != in.Situation.ID {
		return fmt.Errorf("situation: publication input: summary belongs to situation %q, not %q",
			in.Summary.SituationID, in.Situation.ID)
	}
	if in.LatestRootSyncVersion != nil && in.Summary.Version != 0 && in.Summary.Version < *in.LatestRootSyncVersion {
		return fmt.Errorf("situation: publication input: summary version %d is older than the latest root sync version %d",
			in.Summary.Version, *in.LatestRootSyncVersion)
	}
	if len(in.Transitions) == 0 {
		return nil
	}
	if in.Summary.SituationID == "" || in.Summary.Version < 1 {
		return errors.New("situation: publication input: a commit with transitions requires the folded episode summary")
	}
	for i, tr := range in.Transitions {
		if tr.SituationID != in.Situation.ID {
			return fmt.Errorf("situation: publication input: transition %d belongs to situation %q, not %q",
				i, tr.SituationID, in.Situation.ID)
		}
		if i > 0 && tr.Sequence <= in.Transitions[i-1].Sequence {
			return fmt.Errorf("situation: publication input: transition %d sequence %d does not follow %d",
				i, tr.Sequence, in.Transitions[i-1].Sequence)
		}
	}
	if last := in.Transitions[len(in.Transitions)-1]; in.Summary.SourceTransitionSequence != last.Sequence {
		return fmt.Errorf("situation: publication input: summary source sequence %d is not this commit's last transition %d",
			in.Summary.SourceTransitionSequence, last.Sequence)
	}
	return nil
}

// planDeadlineRefresh implements R4's single permitted non-material effect:
// a coalescible silent root edit that replaces an expired promised-update
// time. It is never a poke and never a thread entry.
func planDeadlineRefresh(in PublicationInput) ([]model.NotificationIntent, error) {
	switch {
	case !in.RootPublished:
		// Nothing is on screen to leave sitting on an expired promise.
		return nil, nil
	case in.ContractDeadlineAt == nil:
		return nil, nil
	case in.LastDeliveredRootDeadlineAt == nil:
		return nil, nil
	case in.LastDeliveredRootDeadlineAt.After(in.Now):
		// The delivered promise has not passed yet.
		return nil, nil
	case in.ContractDeadlineAt.Equal(*in.LastDeliveredRootDeadlineAt):
		return nil, nil
	}
	if in.PriorTransition == nil {
		return nil, errors.New("situation: publication input: a published root requires its authority transition to refresh the promised update")
	}
	if in.Summary.Version < 1 {
		return nil, errors.New("situation: publication input: a deadline refresh requires the current episode summary")
	}

	refresh := newIntent(in, model.EffectRootSync, *in.PriorTransition,
		rootSyncKey(in.Situation.ID, in.Summary.Version, in.PriorTransition.ID, in.ContractDeadlineAt))
	refresh.SummaryVersion = intPtrOf(in.Summary.Version)
	refresh.ContractDeadlineAt = in.ContractDeadlineAt
	if err := refresh.Validate(); err != nil {
		return nil, fmt.Errorf("situation: planned deadline refresh: %w", err)
	}
	return []model.NotificationIntent{refresh}, nil
}

// selectPoke returns the one Transition in this commit that may create a
// new main-channel poke, applying spec's closed list of permitted poke
// classes and the configured repage cooldown for the one class it gates.
// When several qualify, the highest-priority (then latest) wins: a commit
// interrupts the channel at most once.
func selectPoke(in PublicationInput) (model.Transition, bool) {
	var best model.Transition
	found := false
	for i := range in.Transitions {
		tr := in.Transitions[i]
		// Every Transition is classified against the state BEFORE this
		// commit, never against an earlier Transition of the same commit.
		// An `operator_artifact_recorded` Transition copies this commit's
		// new lifecycle/Attention/contract verbatim (it changes none of
		// them), so advancing the comparison basis through one would make
		// the controller-state Transition — always last, per R1 — compare
		// new state against itself and silently swallow the escalation it
		// is entitled to. This also keeps the plan's poke decision
		// identical to the InterruptionPriority already stamped on the
		// durable Transition by controllerTransition.
		class := ClassifyPoke(in.PriorTransition, tr)
		if class == PokeNone {
			continue
		}
		if class.CooldownApplies() && !cooldownElapsed(in) {
			continue
		}
		if !found || !DeriveInterruptionPriority(tr).Less(DeriveInterruptionPriority(best)) {
			best = tr
			found = true
		}
	}
	return best, found
}

func cooldownElapsed(in PublicationInput) bool {
	if in.LastMainChannelPokeAt == nil {
		return true
	}
	return !in.Now.Before(in.LastMainChannelPokeAt.Add(in.RepageCooldown))
}

// newIntent fills the fields every Situation-scoped intent shares:
// deterministic identity, the effect's own subject references, the
// class-determined root dependency, and a pending status.
func newIntent(in PublicationInput, class model.EffectClass, subject model.Transition, key string) model.NotificationIntent {
	return model.NotificationIntent{
		ID:                 intentIdentity("intent:" + key),
		IdempotencyKey:     key,
		EffectClass:        class,
		SituationID:        stringPtrOf(in.Situation.ID),
		TransitionID:       stringPtrOf(subject.ID),
		TransitionSequence: intPtrOf(subject.Sequence),
		RequiresRoot:       class == model.EffectThreadAppend || class == model.EffectBroadcastHandoff,
		ClientMessageID:    intentIdentity("client_message:" + key),
		Status:             model.IntentPending,
		CreatedAt:          in.Now,
	}
}

// intentIdentity derives a stable UUIDv5 from the fixed AlertINT namespace
// and the intent's idempotency key, so a timeout, an uncertain success, a
// crash, and a restart all reuse the identical client message ID and
// payload identity.
func intentIdentity(scopedKey string) string {
	return uuid.NewSHA1(historyNamespace, []byte(scopedKey)).String()
}

// rootSyncKey folds the summary version and the rendered contract deadline
// into the root projection's identity (R4), so a deadline refresh is a
// distinct coalescible projection rather than a duplicate of the root it
// replaces.
func rootSyncKey(situationID string, summaryVersion int, transitionID string, deadline *time.Time) string {
	stamp := "none"
	if deadline != nil {
		stamp = deadline.UTC().Format(time.RFC3339)
	}
	return boundedText(fmt.Sprintf("root_sync:%s:v%d:%s:%s", situationID, summaryVersion, transitionID, stamp), maxHistoryIdentifier)
}

// threadKey identifies one immutable historical effect by its Transition's
// sequence, matching migration 0018's
// (situation_id, transition_sequence, effect_class) uniqueness.
func threadKey(class model.EffectClass, situationID string, sequence int) string {
	return boundedText(fmt.Sprintf("%s:%s:%d", class, situationID, sequence), maxHistoryIdentifier)
}

func intPtrOf(i int) *int { return &i }
