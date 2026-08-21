// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func ptr[T any](v T) *T { return &v }

func testSituationIntent(id, idempotencyKey, situationID string, poke bool, status situationmodel.NotificationStatus, createdAt time.Time) situationmodel.NotificationIntent {
	in := situationmodel.NotificationIntent{
		ID: id, IdempotencyKey: idempotencyKey, SubjectKind: situationmodel.NotificationSubjectSituation, SubjectID: situationID,
		SituationID: &situationID, Kind: situationmodel.NotificationSituationRootCreate, MainChannelPoke: poke, Status: status,
		ClientMessageID: "client-" + id, CreatedAt: createdAt,
	}
	if poke {
		in.InterruptionPriority = ptr(situationmodel.PriorityHigh)
	}
	if status == situationmodel.NotificationDelivered {
		in.Channel = ptr("C123")
		in.MessageTS = ptr("1700000000.000100")
		in.DeliveredAt = ptr(createdAt)
	}
	return in
}

func TestCreateNotificationIntentPersistsAndReplaysIdempotently(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-1", "host=db-1", "", situationmodel.LifecycleActive, now)

	in := testSituationIntent("intent-1", "situation:s-notify-1:transition:t1:root", "s-notify-1", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Retry with the same idempotency key and identity (a different row id,
	// as a real retry would generate) succeeds silently rather than erroring.
	replay := in
	replay.ID = "intent-1-retry"
	if err := s.CreateNotificationIntent(ctx, replay); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}

	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents WHERE idempotency_key=?`, in.IdempotencyKey).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one persisted row for a replayed idempotency key, got %d", count)
	}
}

func TestCreateNotificationIntentRejectsIdentityCollision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-2", "host=db-2", "", situationmodel.LifecycleActive, now)

	in := testSituationIntent("intent-2", "situation:s-notify-2:transition:t1:root", "s-notify-2", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	other := in
	other.ID = "intent-2-other"
	other.MainChannelPoke = false
	other.InterruptionPriority = nil
	if err := s.CreateNotificationIntent(ctx, other); err == nil {
		t.Fatal("expected identity collision error for a replay whose content differs under the same idempotency key")
	}
}

func TestNotificationIntentSubjectKindChecks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-3", "host=db-3", "", situationmodel.LifecycleActive, now)

	// A situation-subject row without situation_id must be rejected by the DB.
	_, err := s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-1','k-1','situation','s-notify-3',NULL,'situation_root_create',1,'high','pending','c-1',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a situation intent with no situation_id")
	}

	// A dependency_health-subject row carrying situation_id must be rejected.
	_, err = s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-2','k-2','dependency_health','llm','s-notify-3','health_root',1,'high','pending','c-2',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a dependency_health intent carrying situation_id")
	}

	// kind must match subject_kind.
	_, err = s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-3','k-3','situation','s-notify-3','s-notify-3','health_root',1,'high','pending','c-3',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a kind/subject_kind mismatch")
	}
}

func TestNotificationIntentPriorityRequiredOnlyForPokes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-4", "host=db-4", "", situationmodel.LifecycleActive, now)

	// A poke with no priority is rejected.
	_, err := s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-4','k-4','situation','s-notify-4','s-notify-4','situation_root_create',1,NULL,'pending','c-4',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a poke with no interruption priority")
	}

	// A non-poke root edit carrying a priority is rejected.
	_, err = s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-5','k-5','situation','s-notify-4','s-notify-4','situation_root_edit',0,'low','pending','c-5',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a non-poke carrying an interruption priority")
	}

	// A non-poke root edit with no priority is legal.
	if err := s.CreateNotificationIntent(ctx, situationmodel.NotificationIntent{
		ID: "ok-1", IdempotencyKey: "k-ok-1", SubjectKind: situationmodel.NotificationSubjectSituation, SubjectID: "s-notify-4",
		SituationID: ptr("s-notify-4"), Kind: situationmodel.NotificationSituationRootEdit, MainChannelPoke: false,
		Status: situationmodel.NotificationPending, ClientMessageID: "c-ok-1", CreatedAt: now,
	}); err != nil {
		t.Fatalf("expected a legal non-poke root edit to persist: %v", err)
	}
}

func TestNotificationIntentFloorWithheldPersistence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-5", "host=db-5", "", situationmodel.LifecycleActive, now)

	// withheld status is legal only on a main-channel poke.
	_, err := s.DB().ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, kind, main_channel_poke,
		interruption_priority, status, client_msg_id, created_at
	) VALUES ('bad-6','k-6','situation','s-notify-5','s-notify-5','situation_root_edit',0,NULL,'withheld_by_operator_slack_floor','c-6',?)`, canonicalTime(now))
	if err == nil {
		t.Fatal("expected a CHECK violation for a withheld status on a non-poke")
	}

	in := testSituationIntent("intent-5", "situation:s-notify-5:transition:t1:root", "s-notify-5", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotificationWithheld(ctx, "intent-5"); err != nil {
		t.Fatalf("mark withheld: %v", err)
	}
	var status string
	if err := s.DB().QueryRowContext(ctx, `SELECT status FROM notification_intents WHERE id=?`, "intent-5").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(situationmodel.NotificationWithheldByOperatorSlackFloor) {
		t.Fatalf("status=%q, want withheld_by_operator_slack_floor", status)
	}
	// Withholding never touches Situation/Assessment state.
	var lifecycle, attention string
	if err := s.DB().QueryRowContext(ctx, `SELECT lifecycle, attention FROM situations WHERE id=?`, "s-notify-5").Scan(&lifecycle, &attention); err != nil {
		t.Fatal(err)
	}
	if lifecycle != string(situationmodel.LifecycleActive) || attention != "observe" {
		t.Fatalf("withholding a poke mutated situation state: lifecycle=%s attention=%s", lifecycle, attention)
	}
	// A second withhold call finds no pending row left to withhold.
	if err := s.MarkNotificationWithheld(ctx, "intent-5"); !errors.Is(err, ErrNotificationNotPending) {
		t.Fatalf("re-withhold err=%v, want ErrNotificationNotPending", err)
	}
}

func TestClaimNotificationIntentsClaimsDueAndReclaimsExpiredLease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-6", "host=db-6", "", situationmodel.LifecycleActive, now)

	in := testSituationIntent("intent-6", "situation:s-notify-6:transition:t1:root", "s-notify-6", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}

	claimed, err := s.ClaimNotificationIntents(ctx, now, 30*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != "intent-6" {
		t.Fatalf("claimed=%+v", claimed)
	}
	// A second claim before the lease expires finds nothing due.
	again, err := s.ClaimNotificationIntents(ctx, now.Add(5*time.Second), 30*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("expected no claimable intents while the lease is live, got %+v", again)
	}
	// After the lease expires, the same still-pending row is claimable again.
	expired, err := s.ClaimNotificationIntents(ctx, now.Add(31*time.Second), 30*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ID != "intent-6" {
		t.Fatalf("expired reclaim=%+v", expired)
	}
	if expired[0].Status != situationmodel.NotificationPending {
		t.Fatalf("claim must not introduce a new status; got %s", expired[0].Status)
	}
}

func TestMarkNotificationDeliveredStampsSituationRootCoordinates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-7", "host=db-7", "", situationmodel.LifecycleActive, now)

	in := testSituationIntent("intent-7", "situation:s-notify-7:transition:t1:root", "s-notify-7", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	deliveredAt := now.Add(time.Second)
	if err := s.MarkNotificationDelivered(ctx, "intent-7", "C123", "1700000000.000100", deliveredAt); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	var channel, rootTS string
	if err := s.DB().QueryRowContext(ctx, `SELECT slack_channel, slack_root_ts FROM situations WHERE id=?`, "s-notify-7").Scan(&channel, &rootTS); err != nil {
		t.Fatal(err)
	}
	if channel != "C123" || rootTS != "1700000000.000100" {
		t.Fatalf("situation root coordinates=%s/%s", channel, rootTS)
	}
	// Idempotent replay of the exact same coordinates succeeds.
	if err := s.MarkNotificationDelivered(ctx, "intent-7", "C123", "1700000000.000100", deliveredAt); err != nil {
		t.Fatalf("idempotent redelivery: %v", err)
	}
	// A mismatched replay fails closed.
	if err := s.MarkNotificationDelivered(ctx, "intent-7", "C999", "1700000000.000100", deliveredAt); err == nil {
		t.Fatal("expected a mismatched redelivery to fail")
	}
}

func TestRetryNotificationIntentTransientAndTerminal(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-8", "host=db-8", "", situationmodel.LifecycleActive, now)

	in := testSituationIntent("intent-8", "situation:s-notify-8:transition:t1:root", "s-notify-8", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	retryAt := now.Add(10 * time.Second)
	if err := s.RetryNotificationIntent(ctx, "intent-8", "rate_limited", retryAt, false); err != nil {
		t.Fatalf("retry: %v", err)
	}
	var status string
	var attemptCount int
	if err := s.DB().QueryRowContext(ctx, `SELECT status, attempt_count FROM notification_intents WHERE id=?`, "intent-8").Scan(&status, &attemptCount); err != nil {
		t.Fatal(err)
	}
	if status != string(situationmodel.NotificationPending) || attemptCount != 1 {
		t.Fatalf("status=%s attempt_count=%d", status, attemptCount)
	}

	if err := s.RetryNotificationIntent(ctx, "intent-8", "permanent_failure", time.Time{}, true); err != nil {
		t.Fatalf("terminal retry: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT status FROM notification_intents WHERE id=?`, "intent-8").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(situationmodel.NotificationFailed) {
		t.Fatalf("status=%s, want failed", status)
	}
	if err := s.RetryNotificationIntent(ctx, "intent-8", "again", retryAt, false); !errors.Is(err, ErrNotificationNotPending) {
		t.Fatalf("retry after terminal err=%v, want ErrNotificationNotPending", err)
	}
}

func TestDependencyHealthDegradedAndRecovered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")

	if _, ok, err := s.DependencyHealthState(ctx, "llm"); err != nil || ok {
		t.Fatalf("unseen dependency should not exist: ok=%v err=%v", ok, err)
	}

	health, transitioned, err := s.RecordDependencyDegraded(ctx, "llm", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioned || health.Status != DependencyDegraded || health.DegradedSince == nil || !health.DegradedSince.Equal(now) {
		t.Fatalf("health=%+v transitioned=%v", health, transitioned)
	}

	// A repeated degraded observation is idempotent and keeps the original
	// degraded_since anchor.
	later := now.Add(time.Minute)
	health, transitioned, err = s.RecordDependencyDegraded(ctx, "llm", false, later)
	if err != nil {
		t.Fatal(err)
	}
	if transitioned {
		t.Fatal("re-observing an already-degraded dependency must not report a fresh transition")
	}
	if !health.DegradedSince.Equal(now) {
		t.Fatalf("degraded_since moved on a repeated observation: %v", health.DegradedSince)
	}

	recoveredAt := now.Add(5 * time.Minute)
	health, transitioned, err = s.RecordDependencyRecovered(ctx, "llm", recoveredAt)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioned || health.Status != DependencyHealthy || health.DegradedSince != nil || health.RecoveredAt == nil || !health.RecoveredAt.Equal(recoveredAt) {
		t.Fatalf("recovered health=%+v transitioned=%v", health, transitioned)
	}

	// A repeated recovery observation is idempotent.
	_, transitioned, err = s.RecordDependencyRecovered(ctx, "llm", recoveredAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if transitioned {
		t.Fatal("re-observing an already-healthy dependency must not report a fresh transition")
	}
}

func TestMarkNotificationDeliveredStampsDependencyHealthCoordinates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	if _, _, err := s.RecordDependencyDegraded(ctx, "zabbix", false, now); err != nil {
		t.Fatal(err)
	}

	priority := situationmodel.PriorityHigh
	in := situationmodel.NotificationIntent{
		ID: "health-1", IdempotencyKey: "dependency:zabbix:health_root:1", SubjectKind: situationmodel.NotificationSubjectDependencyHealth,
		SubjectID: "zabbix", Kind: situationmodel.NotificationHealthRoot, MainChannelPoke: true, InterruptionPriority: &priority,
		Status: situationmodel.NotificationPending, ClientMessageID: "c-health-1", CreatedAt: now,
	}
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotificationDelivered(ctx, "health-1", "C-HEALTH", "1700000001.000100", now.Add(time.Second)); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	health, ok, err := s.DependencyHealthState(ctx, "zabbix")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if health.SlackChannel == nil || *health.SlackChannel != "C-HEALTH" || health.SlackMessageTS == nil || *health.SlackMessageTS != "1700000001.000100" {
		t.Fatalf("health=%+v", health)
	}
	if health.LastBroadcastAt == nil {
		t.Fatal("expected last_broadcast_at to be stamped")
	}
}

func TestMarkNotificationDeliveredStampsEnvelopeReviewCoordinatesAndPromptTime(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-9", "host=db-9", "", situationmodel.LifecycleActive, now)
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO situation_judgments (
		id, situation_id, judged_input_version, covered_fact_hash, covered_symptoms_json, covered_impact_json,
		judgment, basis, evidence_refs_json, authenticated_as, asserted_operator, created_at
	) VALUES ('j-1','s-notify-9',1,'sha256:x','[]','[]','expected_this_episode','operator_knowledge','[]','slack:U1','alice',?)`, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO expected_behavior_envelopes (id, current_version, source_judgment_id, created_at, updated_at)
		VALUES ('env-1', 1, 'j-1', ?, ?)`, canonicalTime(now), canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO expected_behavior_envelope_versions (
		envelope_id, version, status, scope_json, conditions_json, review_due_at, authenticated_as, asserted_operator, created_at
	) VALUES ('env-1',1,'active','{"group_key":"host=db-9"}','{}',?,'slack:U1','alice',?)`, canonicalTime(now), canonicalTime(now)); err != nil {
		t.Fatal(err)
	}

	priority := situationmodel.PriorityHigh
	in := situationmodel.NotificationIntent{
		ID: "review-1", IdempotencyKey: "envelope:env-1:review:1", SubjectKind: situationmodel.NotificationSubjectEnvelope,
		SubjectID: "env-1", Kind: situationmodel.NotificationEnvelopeReview, MainChannelPoke: true, InterruptionPriority: &priority,
		Status: situationmodel.NotificationPending, ClientMessageID: "c-review-1", CreatedAt: now,
	}
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	deliveredAt := now.Add(2 * time.Second)
	if err := s.MarkNotificationDelivered(ctx, "review-1", "C-REVIEW", "1700000002.000100", deliveredAt); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	env, err := s.Envelope(ctx, "env-1")
	if err != nil {
		t.Fatal(err)
	}
	if env.LastReviewPromptAt == nil || !env.LastReviewPromptAt.Equal(deliveredAt) {
		t.Fatalf("last_review_prompt_at=%v, want %v", env.LastReviewPromptAt, deliveredAt)
	}
	var channel, ts string
	if err := s.DB().QueryRowContext(ctx, `SELECT slack_channel, slack_message_ts FROM expected_behavior_envelopes WHERE id=?`, "env-1").Scan(&channel, &ts); err != nil {
		t.Fatal(err)
	}
	if channel != "C-REVIEW" || ts != "1700000002.000100" {
		t.Fatalf("channel=%s ts=%s", channel, ts)
	}
}

func TestNotificationIntentImmutableOnceCreated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-notify-10", "host=db-10", "", situationmodel.LifecycleActive, now)
	in := testSituationIntent("intent-10", "situation:s-notify-10:transition:t1:root", "s-notify-10", true, situationmodel.NotificationPending, now)
	if err := s.CreateNotificationIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM notification_intents WHERE id=?`, "intent-10"); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected an immutability trigger to block delete, got %v", err)
	}
}
