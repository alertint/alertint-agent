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
	created []model.NotificationIntent
	err     error
}

func (f *fakePublisherStore) CreateNotificationIntent(ctx context.Context, in model.NotificationIntent) error {
	if f.err != nil {
		return f.err
	}
	f.created = append(f.created, in)
	return nil
}

func mustPublisherTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}
