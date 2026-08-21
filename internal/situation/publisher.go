// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// PublisherStore is the narrow durable boundary the notification Publisher
// needs. It is situation-owned rather than *store.Store for the same reason
// as Controller.Store: internal/store already imports internal/situation,
// so this package cannot import it back. The concrete adapter over
// store.Store.CreateNotificationIntent lives in cmd/alertint wiring (Task
// 13).
type PublisherStore interface {
	CreateNotificationIntent(ctx context.Context, in model.NotificationIntent) error
}

// RootCoordinates is the Situation's current durable Slack root state.
// Exists is false only before the Situation's first publication.
type RootCoordinates struct {
	Exists    bool
	Channel   string
	MessageTS string
}

// PublishInput is everything PlanNotificationIntents needs to decide the
// notification intents one committed transition produces. It carries no
// store or Slack I/O — a caller (Task 13 wiring) assembles it from the
// committed transition, the prior transition, the durable root
// coordinates, and the resolved outward min_severity floor.
type PublishInput struct {
	Transition      model.Transition
	PriorTransition *model.Transition // nil on the Situation's first commit
	Root            RootCoordinates
	MinSeverity     model.InterruptionPriority
	// RecoveryPending is true for a transition that enters or remains in
	// recovery_pending; recovery-pending, recovery, and ordinary
	// de-escalation edits never count as a main-channel poke regardless of
	// what the priority ladder alone would suggest.
	RecoveryPending bool
	// RecurrenceCount is 0 when this transition is not a recurrence-collapse
	// attach; otherwise the exact-key episode count.
	RecurrenceCount int
	// RecurrenceMode is "off" to disable recurrence thread output entirely;
	// any other value (including empty) is the default change-gated mode.
	RecurrenceMode        string
	LastMainChannelPokeAt *time.Time
	CooldownSeconds       int
	Now                   time.Time
}

// PlanNotificationIntents deterministically decides the durable notification
// intents one committed transition produces, in the exact order they must
// be created: a root edit always precedes its broadcast reply on handoff. A
// Situation that has never published and carries no sufficient reason
// produces nothing at all — a silent Situation leaves no Slack trace.
func PlanNotificationIntents(in PublishInput) []model.NotificationIntent {
	now := in.Now
	if now.IsZero() {
		now = in.Transition.CreatedAt
	}
	hasReason := in.Transition.Assessment != nil && in.Transition.Assessment.SufficientReason != nil
	if !in.Root.Exists && !hasReason {
		return nil
	}

	var out []model.NotificationIntent
	if !in.Root.Exists {
		priority := transitionPriority(in.Transition)
		out = append(out, situationIntent(in, model.NotificationSituationRootCreate, true, &priority, "root", now))
		return applyMinSeverityFloor(out, in.MinSeverity)
	}

	poke := isRepage(in)
	var editPriority *model.InterruptionPriority
	if poke {
		p := transitionPriority(in.Transition)
		editPriority = &p
	}
	out = append(out, situationIntent(in, model.NotificationSituationRootEdit, poke, editPriority, "root", now))
	if poke {
		out = append(out, situationIntent(in, model.NotificationSituationBroadcastReply, false, nil, "root:broadcast", now))
	}
	if in.RecurrenceMode != "off" && recurrenceMilestone(in.RecurrenceCount) {
		suffix := fmt.Sprintf("root:recurrence:%d", in.RecurrenceCount)
		out = append(out, situationIntent(in, model.NotificationSituationThreadReply, false, nil, suffix, now))
	}
	return applyMinSeverityFloor(out, in.MinSeverity)
}

// PlanEnvelopeReviewIntent builds the standalone, high-priority envelope
// review reminder. It carries no Situation ID and never reuses a Situation
// thread.
func PlanEnvelopeReviewIntent(envelopeID string, now time.Time) model.NotificationIntent {
	priority := model.PriorityHigh
	return model.NotificationIntent{
		ID: uuid.NewString(), IdempotencyKey: fmt.Sprintf("envelope:%s:review:%s", envelopeID, now.UTC().Format(time.RFC3339)),
		SubjectKind: model.NotificationSubjectEnvelope, SubjectID: envelopeID, Kind: model.NotificationEnvelopeReview,
		MainChannelPoke: true, InterruptionPriority: &priority, Status: model.NotificationPending, CreatedAt: now.UTC(),
	}
}

// PlanDependencyHealthIntent builds the one health root a sustained shared
// outage produces (newlyDegraded true) or its one recovery/status update
// (false). Only the root counts as a main-channel poke.
func PlanDependencyHealthIntent(dependency string, newlyDegraded bool, now time.Time) model.NotificationIntent {
	kind := model.NotificationHealthUpdate
	var priority *model.InterruptionPriority
	if newlyDegraded {
		kind = model.NotificationHealthRoot
		p := model.PriorityHigh
		priority = &p
	}
	return model.NotificationIntent{
		ID: uuid.NewString(), IdempotencyKey: fmt.Sprintf("dependency:%s:%s:%s", dependency, kind, now.UTC().Format(time.RFC3339)),
		SubjectKind: model.NotificationSubjectDependencyHealth, SubjectID: dependency, Kind: kind,
		MainChannelPoke: newlyDegraded, InterruptionPriority: priority, Status: model.NotificationPending, CreatedAt: now.UTC(),
	}
}

// Publisher persists the planned notification intents for one committed
// transition — the durable "an outward effect exists before I/O" boundary.
// It never performs Slack I/O itself.
type Publisher struct {
	store           PublisherStore
	clientMessageID func(idempotencyKey string) string
}

// NewPublisher constructs a Publisher. clientMessageID computes the
// deterministic Slack client_msg_id for one idempotency key (injected so
// this package never imports internal/notify/slack, which imports
// internal/store, which imports this package).
func NewPublisher(store PublisherStore, clientMessageID func(string) string) *Publisher {
	return &Publisher{store: store, clientMessageID: clientMessageID}
}

// Publish plans and durably persists every notification intent one
// committed transition produces, root edit before broadcast reply. A retry
// of the same transition recomputes the identical idempotency_key and
// client_msg_id every time, so CreateNotificationIntent's own idempotent
// replay handling absorbs a duplicate Publish call safely.
func (p *Publisher) Publish(ctx context.Context, in PublishInput) error {
	for _, intent := range PlanNotificationIntents(in) {
		if p.clientMessageID != nil {
			intent.ClientMessageID = p.clientMessageID(intent.IdempotencyKey)
		}
		if err := p.store.CreateNotificationIntent(ctx, intent); err != nil {
			return fmt.Errorf("situation: publish notification intent: %w", err)
		}
	}
	return nil
}

func situationIntent(in PublishInput, kind model.NotificationKind, poke bool, priority *model.InterruptionPriority, idempotencySuffix string, now time.Time) model.NotificationIntent {
	situationID := in.Transition.SituationID
	var transitionID *string
	if in.Transition.ID != "" {
		id := in.Transition.ID
		transitionID = &id
	}
	return model.NotificationIntent{
		ID:                   uuid.NewString(),
		IdempotencyKey:       fmt.Sprintf("situation:%s:transition:%s:%s", situationID, in.Transition.ID, idempotencySuffix),
		SubjectKind:          model.NotificationSubjectSituation,
		SubjectID:            situationID,
		SituationID:          &situationID,
		TransitionID:         transitionID,
		Kind:                 kind,
		MainChannelPoke:      poke,
		InterruptionPriority: priority,
		Status:               model.NotificationPending,
		CreatedAt:            now.UTC(),
	}
}

// isRepage implements the spec's four re-page conditions plus cooldown.
// Recovery-pending, recovery, and ordinary de-escalation never re-page
// regardless of what the priority ladder alone would suggest.
func isRepage(in PublishInput) bool {
	if in.RecoveryPending || in.Transition.Lifecycle == model.LifecycleRecovered || in.Transition.Lifecycle == model.LifecycleClosedUnknown {
		return false
	}
	newPriority := transitionPriority(in.Transition)
	newUrgent := in.Transition.Attention == model.AttentionUrgent
	newAction, newJudgment := operatorWorkText(in.Transition)
	newHasWork := newAction != "" || newJudgment != ""

	priorPriority := model.PriorityLow
	priorUrgent := false
	priorAction, priorJudgment := "", ""
	if in.PriorTransition != nil {
		priorPriority = transitionPriority(*in.PriorTransition)
		priorUrgent = in.PriorTransition.Attention == model.AttentionUrgent
		priorAction, priorJudgment = operatorWorkText(*in.PriorTransition)
	}
	priorHasWork := priorAction != "" || priorJudgment != ""

	switch {
	case newPriority == model.PriorityCritical && priorPriority != model.PriorityCritical:
		return true // newly crossed deterministic criticality
	case newUrgent && !priorUrgent:
		return true // valid urgent Attention newly reached
	case newHasWork && !priorHasWork:
		return true // no-action to judgment/action handoff
	case newHasWork && priorHasWork && (newAction != priorAction || newJudgment != priorJudgment):
		return cooldownElapsed(in) // materially changed required action, after cooldown
	default:
		return false
	}
}

func operatorWorkText(tr model.Transition) (action, judgment string) {
	if tr.ActionContract.OperatorActionRequired != nil {
		action = strings.TrimSpace(*tr.ActionContract.OperatorActionRequired)
	}
	if tr.ActionContract.OperatorJudgmentRequested != nil {
		judgment = strings.TrimSpace(*tr.ActionContract.OperatorJudgmentRequested)
	}
	return action, judgment
}

func cooldownElapsed(in PublishInput) bool {
	if in.LastMainChannelPokeAt == nil {
		return true
	}
	cooldown := time.Duration(in.CooldownSeconds) * time.Second
	return in.Now.Sub(*in.LastMainChannelPokeAt) >= cooldown
}

func transitionPriority(tr model.Transition) model.InterruptionPriority {
	if tr.Assessment == nil {
		return model.PriorityLow
	}
	return DeriveInterruptionPriority(*tr.Assessment)
}

// recurrenceMilestone mirrors slack.RecurrenceMilestone's membership check
// (5, 10, 25, 50, 100, then every 100) without the rendered text — kept as a
// small duplicated predicate rather than an import, since notify/slack
// imports internal/store, which imports this package.
func recurrenceMilestone(count int) bool {
	switch count {
	case 5, 10, 25, 50, 100:
		return true
	default:
		return count > 100 && count%100 == 0
	}
}

// applyMinSeverityFloor withholds a new main-channel poke whose deterministic
// Interruption priority ranks below the configured outward floor. Critical
// always ranks above the configured maximum (low|medium|high) and therefore
// always passes. The floor never touches a non-poke root edit/thread reply,
// and never rewrites Assessment or Situation state.
func applyMinSeverityFloor(intents []model.NotificationIntent, min model.InterruptionPriority) []model.NotificationIntent {
	floor := priorityRank(min)
	if min == "" {
		floor = priorityRank(model.PriorityLow)
	}
	for i := range intents {
		if !intents[i].MainChannelPoke || intents[i].InterruptionPriority == nil {
			continue
		}
		if priorityRank(*intents[i].InterruptionPriority) < floor {
			intents[i].Status = model.NotificationWithheldByOperatorSlackFloor
		}
	}
	return intents
}

func priorityRank(p model.InterruptionPriority) int {
	switch p {
	case model.PriorityLow:
		return 1
	case model.PriorityMedium:
		return 2
	case model.PriorityHigh:
		return 3
	case model.PriorityCritical:
		return 4
	default:
		return 1
	}
}
