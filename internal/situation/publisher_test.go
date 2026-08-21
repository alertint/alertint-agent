// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func floorAssessment(attention model.Attention, code string, actionRequired, judgmentRequested *string) *model.Assessment {
	var reason *model.SufficientReason
	if code != "" {
		reason = &model.SufficientReason{Code: code}
	}
	return &model.Assessment{
		Attention: attention, SufficientReason: reason,
		ActionContract: model.ActionContract{
			NextActor: model.NextActorAlertint, OperatorActionRequired: actionRequired, OperatorJudgmentRequested: judgmentRequested,
		},
	}
}

// transitionFor builds a Transition whose own top-level ActionContract
// mirrors its Assessment's — exactly what controller.go's commitAssessment
// does in production (tr.ActionContract = validated.ActionContract).
// Publisher reads the transition's own field, not the nested Assessment
// copy, so a test that only set the latter would silently mismatch reality.
func transitionFor(id, situationID string, lifecycle model.Lifecycle, attention model.Attention, assessment *model.Assessment) model.Transition {
	tr := model.Transition{ID: id, SituationID: situationID, Lifecycle: lifecycle, Attention: attention, Assessment: assessment}
	if assessment != nil {
		tr.ActionContract = assessment.ActionContract
	}
	return tr
}

func TestPlanNotificationIntentsSilentSituationProducesNothing(t *testing.T) {
	in := PublishInput{
		Transition: model.Transition{ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve},
		Root:       RootCoordinates{Exists: false},
		Now:        mustPublisherTime(t, "2026-08-20T10:00:00Z"),
	}
	intents := PlanNotificationIntents(in)
	if len(intents) != 0 {
		t.Fatalf("expected a silent situation with no root and no sufficient reason to produce nothing, got %+v", intents)
	}
}

func TestPlanNotificationIntentsFirstPublishCreatesRoot(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityLow, Now: now,
	}
	intents := PlanNotificationIntents(in)
	if len(intents) != 1 {
		t.Fatalf("intents=%+v", intents)
	}
	got := intents[0]
	if got.Kind != model.NotificationSituationRootCreate {
		t.Fatalf("kind=%s", got.Kind)
	}
	if !got.MainChannelPoke || got.InterruptionPriority == nil || *got.InterruptionPriority != model.PriorityCritical {
		t.Fatalf("got=%+v", got)
	}
	if got.Status != model.NotificationPending {
		t.Fatalf("status=%s", got.Status)
	}
	if got.SituationID == nil || *got.SituationID != "s1" {
		t.Fatalf("situation_id=%v", got.SituationID)
	}
}

func TestPlanNotificationIntentsAppliesMinSeverityFloorToNewPokesOnly(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
			Assessment: floorAssessment(model.AttentionInvestigate, "duration_outlier", nil, nil),
		},
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityHigh, Now: now,
	}
	intents := PlanNotificationIntents(in)
	if len(intents) != 1 {
		t.Fatalf("intents=%+v", intents)
	}
	if intents[0].Status != model.NotificationWithheldByOperatorSlackFloor {
		t.Fatalf("status=%s, want withheld (medium priority below configured high floor)", intents[0].Status)
	}
}

func TestPlanNotificationIntentsCriticalAlwaysPassesFloor(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityHigh, Now: now,
	}
	intents := PlanNotificationIntents(in)
	if len(intents) != 1 || intents[0].Status != model.NotificationPending {
		t.Fatalf("intents=%+v, critical must always pass the configured floor", intents)
	}
}

func TestPlanNotificationIntentsRootEditBeforeBroadcastReplyOnHandoff(t *testing.T) {
	action := "restart the database"
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	prior := transitionFor("t0", "s1", model.LifecycleActive, model.AttentionInvestigate, floorAssessment(model.AttentionInvestigate, "duration_outlier", nil, nil))
	in := PublishInput{
		Transition:      transitionFor("t1", "s1", model.LifecycleActive, model.AttentionInvestigate, floorAssessment(model.AttentionInvestigate, "duration_outlier", &action, nil)),
		PriorTransition: &prior,
		Root:            RootCoordinates{Exists: true, Channel: "C1", MessageTS: "1700000000.000100"},
		MinSeverity:     model.PriorityLow, Now: now,
	}
	intents := PlanNotificationIntents(in)
	if len(intents) < 2 {
		t.Fatalf("expected a root edit followed by a broadcast reply on handoff, got %+v", intents)
	}
	if intents[0].Kind != model.NotificationSituationRootEdit {
		t.Fatalf("intents[0].Kind=%s, want root edit first", intents[0].Kind)
	}
	if intents[1].Kind != model.NotificationSituationBroadcastReply {
		t.Fatalf("intents[1].Kind=%s, want broadcast reply second", intents[1].Kind)
	}
	if !intents[0].MainChannelPoke {
		t.Fatal("the handoff root edit must count as the main-channel poke")
	}
	if intents[1].MainChannelPoke {
		t.Fatal("the broadcast reply itself must not double-count as a second poke")
	}
}

func TestPlanNotificationIntentsNoRepageForRecoveryOrDeescalation(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	prior := model.Transition{
		ID: "t0", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
		Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
	}
	cases := []struct {
		name string
		in   PublishInput
	}{
		{
			name: "recovery pending",
			in: PublishInput{
				Transition:      model.Transition{ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleRecoveryPending, Attention: model.AttentionUrgent},
				PriorTransition: &prior, RecoveryPending: true,
				Root: RootCoordinates{Exists: true, Channel: "C1", MessageTS: "ts1"}, MinSeverity: model.PriorityLow, Now: now,
			},
		},
		{
			name: "de-escalation to observe",
			in: PublishInput{
				Transition:      model.Transition{ID: "t2", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, Assessment: floorAssessment(model.AttentionObserve, "", nil, nil)},
				PriorTransition: &prior,
				Root:            RootCoordinates{Exists: true, Channel: "C1", MessageTS: "ts1"}, MinSeverity: model.PriorityLow, Now: now,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intents := PlanNotificationIntents(tc.in)
			for _, intent := range intents {
				if intent.MainChannelPoke {
					t.Fatalf("%s: expected no main-channel poke, got %+v", tc.name, intent)
				}
				if intent.Kind == model.NotificationSituationBroadcastReply {
					t.Fatalf("%s: expected no broadcast reply, got %+v", tc.name, intent)
				}
			}
		})
	}
}

func TestPlanNotificationIntentsRepageOnNewlyCrossedCriticality(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	prior := model.Transition{
		ID: "t0", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
		Assessment: floorAssessment(model.AttentionInvestigate, "duration_outlier", nil, nil),
	}
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		PriorTransition: &prior, Root: RootCoordinates{Exists: true, Channel: "C1", MessageTS: "ts1"}, MinSeverity: model.PriorityLow, Now: now,
	}
	intents := PlanNotificationIntents(in)
	poked := false
	for _, intent := range intents {
		if intent.MainChannelPoke {
			poked = true
			if intent.InterruptionPriority == nil || *intent.InterruptionPriority != model.PriorityCritical {
				t.Fatalf("expected critical priority on the newly crossed poke: %+v", intent)
			}
		}
	}
	if !poked {
		t.Fatalf("expected a repage on newly crossed critical, got %+v", intents)
	}
}

// stableRecurrenceInput builds a PublishInput against an already-published,
// unchanged-priority root (no repage in play) so recurrence-reply decisions
// can be observed in isolation from the handoff/repage logic covered
// elsewhere.
func stableRecurrenceInput(t *testing.T, count int, trigger, mode string) PublishInput {
	t.Helper()
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	prior := transitionFor("t0", "s1", model.LifecycleActive, model.AttentionInvestigate, floorAssessment(model.AttentionInvestigate, "duration_outlier", nil, nil))
	return PublishInput{
		Transition:      transitionFor("t1", "s1", model.LifecycleActive, model.AttentionInvestigate, floorAssessment(model.AttentionInvestigate, "duration_outlier", nil, nil)),
		PriorTransition: &prior,
		Root:            RootCoordinates{Exists: true, Channel: "C1", MessageTS: "ts1"},
		MinSeverity:     model.PriorityLow, Now: now,
		RecurrenceCount: count, RecurrenceTrigger: trigger, RecurrenceMode: mode,
	}
}

func threadReplies(intents []model.NotificationIntent) []model.NotificationIntent {
	var out []model.NotificationIntent
	for _, intent := range intents {
		if intent.Kind == model.NotificationSituationThreadReply {
			out = append(out, intent)
		}
	}
	return out
}

// TestRecurrenceRungTriggersProduceThreadOnlyReply covers the three
// real-world-change rungs from the brief ("severity change, a new alert
// name, cadence") against the legacy internal/notify/slack/occurrence.go
// semantic reference (isRejudgeTrigger/rungHeadline): each earns exactly
// one thread-only reply, regardless of RecurrenceCount, and it is never a
// main-channel poke or a broadcast.
func TestRecurrenceRungTriggersProduceThreadOnlyReply(t *testing.T) {
	for _, trigger := range []string{RecurrenceTriggerSeverity, RecurrenceTriggerNewAlertname, RecurrenceTriggerCadence} {
		t.Run(trigger, func(t *testing.T) {
			in := stableRecurrenceInput(t, 0, trigger, "")
			replies := threadReplies(PlanNotificationIntents(in))
			if len(replies) != 1 {
				t.Fatalf("trigger=%s: expected exactly one thread reply, got %+v", trigger, replies)
			}
			if replies[0].MainChannelPoke {
				t.Fatalf("trigger=%s: a recurrence rung reply must never be a main-channel poke: %+v", trigger, replies[0])
			}
			for _, intent := range PlanNotificationIntents(in) {
				if intent.Kind == model.NotificationSituationBroadcastReply {
					t.Fatalf("trigger=%s: a recurrence rung must never broadcast: %+v", trigger, intent)
				}
			}
		})
	}
}

// TestRecurrenceCapAndCeilingTriggersStaySilent proves the spec's explicit
// exception: "cap or ceiling changes stay silent."
func TestRecurrenceCapAndCeilingTriggersStaySilent(t *testing.T) {
	for _, trigger := range []string{RecurrenceTriggerCap, RecurrenceTriggerCeiling} {
		t.Run(trigger, func(t *testing.T) {
			in := stableRecurrenceInput(t, 100, trigger, "") // even a milestone count must not leak through a cap/ceiling trigger
			if replies := threadReplies(PlanNotificationIntents(in)); len(replies) != 0 {
				t.Fatalf("trigger=%s: expected silence, got %+v", trigger, replies)
			}
		})
	}
}

// TestRecurrenceMilestoneMembershipExactCounts proves the exact milestone
// schedule from the brief: "counts 5/10/25/50/100 then every 100" — no more,
// no less — for a plain attach (no rung trigger).
func TestRecurrenceMilestoneMembershipExactCounts(t *testing.T) {
	cases := []struct {
		count int
		want  bool
	}{
		{1, false}, {4, false}, {5, true}, {6, false},
		{9, false}, {10, true}, {11, false},
		{24, false}, {25, true}, {26, false},
		{49, false}, {50, true}, {51, false},
		{99, false}, {100, true}, {101, false},
		{150, false}, {199, false}, {200, true}, {201, false},
		{300, true},
	}
	for _, tc := range cases {
		in := stableRecurrenceInput(t, tc.count, "", "")
		got := len(threadReplies(PlanNotificationIntents(in))) == 1
		if got != tc.want {
			t.Fatalf("count=%d: milestone reply produced=%v, want %v", tc.count, got, tc.want)
		}
	}
}

// TestRecurrenceModeOffDisablesRungAndMilestoneOutput proves
// "recurrence_mode: off disables recurrence output" for both output paths —
// a rung trigger and a milestone count.
func TestRecurrenceModeOffDisablesRungAndMilestoneOutput(t *testing.T) {
	t.Run("rung trigger", func(t *testing.T) {
		in := stableRecurrenceInput(t, 0, RecurrenceTriggerSeverity, "off")
		if replies := threadReplies(PlanNotificationIntents(in)); len(replies) != 0 {
			t.Fatalf("expected recurrence_mode off to suppress the rung reply, got %+v", replies)
		}
	})
	t.Run("milestone count", func(t *testing.T) {
		in := stableRecurrenceInput(t, 50, "", "off")
		if replies := threadReplies(PlanNotificationIntents(in)); len(replies) != 0 {
			t.Fatalf("expected recurrence_mode off to suppress the milestone reply, got %+v", replies)
		}
	})
}

func TestClientMessageIDDerivedFromIdempotencyKeyReusedOnRetry(t *testing.T) {
	seen := map[string]string{}
	fn := func(key string) string {
		id := "cmid-for-" + key
		seen[key] = id
		return id
	}
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityLow, Now: now,
	}
	store := &fakePublisherStore{}
	p := NewPublisher(store, fn)
	if err := p.Publish(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(store.created) != 2 {
		t.Fatalf("expected two CreateNotificationIntent calls (one per Publish), got %d", len(store.created))
	}
	if store.created[0].ClientMessageID != store.created[1].ClientMessageID {
		t.Fatalf("retry must reuse the same client_msg_id: %q vs %q", store.created[0].ClientMessageID, store.created[1].ClientMessageID)
	}
	if store.created[0].IdempotencyKey != store.created[1].IdempotencyKey {
		t.Fatalf("retry must reuse the same idempotency key: %q vs %q", store.created[0].IdempotencyKey, store.created[1].IdempotencyKey)
	}
}

func TestPublisherPropagatesStoreError(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t1", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityLow, Now: now,
	}
	boom := errors.New("boom")
	store := &fakePublisherStore{err: boom}
	p := NewPublisher(store, func(key string) string { return "cmid" })
	if err := p.Publish(context.Background(), in); !errors.Is(err, boom) {
		t.Fatalf("err=%v, want boom", err)
	}
}

// TestPublishTreatsPendingUndeliveredRootCreateAsRootExists proves "one
// Situation owns one root" holds even before the first root-create has been
// delivered: a caller that has not yet observed delivered Slack coordinates
// (so RootCoordinates.Exists is conventionally still false) must not get a
// second situation_root_create out of Publish once a root-create intent —
// pending or not — already exists for the Situation.
func TestPublishTreatsPendingUndeliveredRootCreateAsRootExists(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t2", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
			Assessment: floorAssessment(model.AttentionUrgent, "critical_anchor", nil, nil),
		},
		// Root.Exists is false — the caller only knows about delivered
		// coordinates, and this root-create has not delivered yet.
		Root: RootCoordinates{Exists: false}, MinSeverity: model.PriorityLow, Now: now,
	}
	store := &fakePublisherStore{hasRootCreate: true}
	p := NewPublisher(store, func(key string) string { return "cmid" })
	if err := p.Publish(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if store.rootCreateCheckedFor != "s1" {
		t.Fatalf("expected Publish to check for an existing root-create against situation s1, checked %q", store.rootCreateCheckedFor)
	}
	for _, intent := range store.created {
		if intent.Kind == model.NotificationSituationRootCreate {
			t.Fatalf("expected no second situation_root_create once one already exists (even undelivered), got %+v", store.created)
		}
	}
	if len(store.created) == 0 {
		t.Fatal("expected the transition to still produce a root edit")
	}
	if store.created[0].Kind != model.NotificationSituationRootEdit {
		t.Fatalf("kind=%s, want situation_root_edit once the pending root-create counts as an existing root", store.created[0].Kind)
	}
}

// TestPublishSkipsRootCreateCheckWhenRootAlreadyKnownDelivered proves the
// store is not consulted at all when the caller already knows the root
// exists (the common case, avoiding a needless query on every routine edit).
func TestPublishSkipsRootCreateCheckWhenRootAlreadyKnownDelivered(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	in := PublishInput{
		Transition: model.Transition{
			ID: "t3", SituationID: "s1", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
			Assessment: floorAssessment(model.AttentionObserve, "", nil, nil),
		},
		Root: RootCoordinates{Exists: true, Channel: "C1", MessageTS: "ts1"}, MinSeverity: model.PriorityLow, Now: now,
	}
	store := &fakePublisherStore{}
	p := NewPublisher(store, func(key string) string { return "cmid" })
	if err := p.Publish(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if store.rootCreateCheckedFor != "" {
		t.Fatalf("expected no HasRootCreateIntent check when the root is already known, checked %q", store.rootCreateCheckedFor)
	}
}

func TestPlanEnvelopeReviewIntentIsStandaloneHighPriorityPoke(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	intent := PlanEnvelopeReviewIntent("env-1", now)
	if intent.SubjectKind != model.NotificationSubjectEnvelope || intent.SubjectID != "env-1" {
		t.Fatalf("intent=%+v", intent)
	}
	if intent.SituationID != nil {
		t.Fatalf("envelope review must carry no situation id: %+v", intent)
	}
	if !intent.MainChannelPoke || intent.InterruptionPriority == nil || *intent.InterruptionPriority != model.PriorityHigh {
		t.Fatalf("intent=%+v", intent)
	}
}

func TestPlanDependencyHealthIntentRootVsUpdate(t *testing.T) {
	now := mustPublisherTime(t, "2026-08-20T10:00:00Z")
	root := PlanDependencyHealthIntent("llm", true, now)
	if root.Kind != model.NotificationHealthRoot || !root.MainChannelPoke || root.InterruptionPriority == nil {
		t.Fatalf("root=%+v", root)
	}
	update := PlanDependencyHealthIntent("llm", false, now)
	if update.Kind != model.NotificationHealthUpdate || update.MainChannelPoke || update.InterruptionPriority != nil {
		t.Fatalf("update=%+v", update)
	}
	if root.SituationID != nil || update.SituationID != nil {
		t.Fatalf("dependency health intents must carry no situation id")
	}
}

type fakePublisherStore struct {
	created              []model.NotificationIntent
	err                  error
	hasRootCreate        bool
	hasRootCreateErr     error
	rootCreateCheckedFor string
}

func (f *fakePublisherStore) CreateNotificationIntent(ctx context.Context, in model.NotificationIntent) error {
	if f.err != nil {
		return f.err
	}
	f.created = append(f.created, in)
	return nil
}

func (f *fakePublisherStore) HasRootCreateIntent(ctx context.Context, situationID string) (bool, error) {
	f.rootCreateCheckedFor = situationID
	if f.hasRootCreateErr != nil {
		return false, f.hasRootCreateErr
	}
	return f.hasRootCreate, nil
}

func mustPublisherTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}
