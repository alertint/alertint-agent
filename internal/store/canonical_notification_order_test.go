// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// TestNotificationReplyKindRoundTrips proves the rendering selection is a
// durable part of the obligation. Losing it on restart would collapse a split
// analysis/recovery transition back into one ambiguous legacy reply.
func TestNotificationReplyKindRoundTrips(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "canonical-reply-kind", now)
	tr := osCycle(t, st, sitID, now, osMonitoringContract(now.Add(time.Minute)),
		model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)

	intent := model.NotificationIntent{
		ID: "zzz-canonical-analysis-intent", IdempotencyKey: "canonical-analysis-key",
		EffectClass: model.EffectThreadAppend, ReplyKind: model.ReplyAnalysisCompleted,
		SituationID: &sitID, TransitionID: &tr.ID, TransitionSequence: &tr.Sequence,
		RequiresRoot: true, ClientMessageID: "canonical-analysis-client",
		Status: model.IntentPending, CreatedAt: now,
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertNotificationIntentTx(ctx, tx, intent); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert canonical intent: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetNotificationIntent(ctx, intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReplyKind != model.ReplyAnalysisCompleted {
		t.Fatalf("reply kind after store round trip = %q, want %q", got.ReplyKind, model.ReplyAnalysisCompleted)
	}
}

// TestCanonicalRepliesClaimAnalysisBeforeRecovery proves the store, rather
// than insertion order or UUID luck, preserves the canonical split-reply
// sequence across worker restarts. Recovery remains its own obligation.
func TestCanonicalRepliesClaimAnalysisBeforeRecovery(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 11, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "canonical-reply-order", now)
	tr := osCycle(t, st, sitID, now, osMonitoringContract(now.Add(time.Minute)),
		model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)

	insert := func(id string, kind model.NotificationReplyKind) {
		t.Helper()
		intent := model.NotificationIntent{
			ID: id, IdempotencyKey: "key:" + id, EffectClass: model.EffectThreadAppend,
			ReplyKind: kind, SituationID: &sitID, TransitionID: &tr.ID,
			TransitionSequence: &tr.Sequence, RequiresRoot: true,
			ClientMessageID: "client:" + id, Status: model.IntentPending, CreatedAt: now,
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertNotificationIntentTx(ctx, tx, intent); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert %s: %v", kind, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately give recovery the lexically earlier ID: the durable reply
	// rank must still put analysis first.
	insert("zzz-analysis", model.ReplyAnalysisCompleted)
	insert("aaa-recovery", model.ReplyRecoveryObserved)

	root := snClaimOne(t, st, now)
	if root.Intent.EffectClass != model.EffectRootSync {
		t.Fatalf("first claim = %s, want root_sync", root.Intent.EffectClass)
	}
	snDeliver(t, st, root, "100.1", now.Add(time.Second))

	analysis := snClaimOne(t, st, now.Add(2*time.Second))
	if analysis.Intent.ReplyKind != model.ReplyAnalysisCompleted {
		t.Fatalf("first reply after restart = %q, want analysis_completed", analysis.Intent.ReplyKind)
	}
	snDeliver(t, st, analysis, "100.2", now.Add(3*time.Second))
	recovery := snClaimOne(t, st, now.Add(4*time.Second))
	if recovery.Intent.ReplyKind != model.ReplyRecoveryObserved {
		t.Fatalf("second reply = %q, want recovery_observed", recovery.Intent.ReplyKind)
	}
}

func TestRecoverySupersedesUndeliveredStartAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "recovery-overtakes-start", now)
	start := oscCanonicalStart(t, st, sitID, now, "checkout", 1, 1)
	if got := osIntentDetail(t, st, sitID, start.Sequence).Status; got != "pending" {
		t.Fatalf("start assurance before clearance = %s, want pending", got)
	}
	grace := now.Add(4 * time.Minute)
	recovery := s5RecoveryCycle(t, st, sitID, now.Add(3*time.Minute),
		osMonitoringContract(grace),
		model.LifecycleRecoveryPending,
		&model.OperatorBriefing{Scope: "checkout", Firing: 0, Resolved: 1, Total: 1}, now.Add(3*time.Minute))
	startInfo := osIntentDetail(t, st, sitID, start.Sequence)
	if startInfo.Status != "superseded" {
		t.Fatalf("start assurance after clearance = %s, want superseded", startInfo.Status)
	}
	if startInfo.Reason != SupersessionReasonRecovery {
		t.Fatalf("start supersession reason = %q, want %q", startInfo.Reason, SupersessionReasonRecovery)
	}
	recoveryInfo := osIntentDetail(t, st, sitID, recovery.Sequence)
	if startInfo.Replacement != recoveryInfo.ID {
		t.Fatalf("start replacement = %q, want recovery intent %q", startInfo.Replacement, recoveryInfo.ID)
	}
}

func TestLaterAnalysisSupersedesQueuedCorrelationReply(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 13, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "correlation-overtaken", now)
	closes := now.Add(30 * time.Second)
	initial := &model.OperatorBriefing{
		Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
		Scope: "checkout", Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseCollecting},
	}
	first := osCycle(t, st, sitID, now, osMonitoringContract(closes), model.LifecycleActive, initial, false)
	var correlationID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM notification_intents WHERE situation_id = ? AND transition_sequence = ? AND reply_kind = 'correlation_started'`, sitID, first.Sequence).Scan(&correlationID); err != nil {
		t.Fatalf("queued correlation reply: %v", err)
	}

	analyzed := &model.OperatorBriefing{
		Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
		Scope: "checkout", Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseSettled},
		Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Checkout requests failed", Observations: []string{"request failed"}}},
	}
	second := osCycle(t, st, sitID, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)), model.LifecycleActive, analyzed, false)
	correlation, err := st.GetNotificationIntent(ctx, correlationID)
	if err != nil {
		t.Fatal(err)
	}
	if correlation.Status != model.IntentSuperseded {
		t.Fatalf("queued correlation after analysis = %s, want superseded", correlation.Status)
	}
	if correlation.ReplacementIntentID == nil {
		t.Fatal("superseded correlation does not name its replacement")
	}
	replacement, err := st.GetNotificationIntent(ctx, *correlation.ReplacementIntentID)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.TransitionSequence == nil || *replacement.TransitionSequence != second.Sequence || replacement.ReplyKind != model.ReplyAnalysisCompleted {
		t.Fatalf("correlation replacement = %+v, want later analysis reply", replacement)
	}
}

func TestLaterRecoverySupersedesQueuedCorrelationReply(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "correlation-overtaken-recovery", now)
	closes := now.Add(30 * time.Second)
	first := osCycle(t, st, sitID, now, osMonitoringContract(closes), model.LifecycleActive,
		&model.OperatorBriefing{
			Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
			Scope: "checkout", Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseCollecting},
		}, false)
	var correlationID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM notification_intents WHERE situation_id = ? AND transition_sequence = ? AND reply_kind = 'correlation_started'`, sitID, first.Sequence).Scan(&correlationID); err != nil {
		t.Fatalf("queued correlation reply: %v", err)
	}
	recoveredAt := now.Add(time.Minute)
	grace := recoveredAt.Add(2 * time.Minute)
	recovery := s5RecoveryCycle(t, st, sitID, recoveredAt, osMonitoringContract(grace), model.LifecycleRecoveryPending,
		&model.OperatorBriefing{
			Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
			Scope: "checkout", Firing: 0, Resolved: 1, Total: 1,
			Work: model.WorkProjection{Phase: model.WorkPhaseSettled, SourceGraceUntil: &grace},
		}, recoveredAt)
	correlation, err := st.GetNotificationIntent(ctx, correlationID)
	if err != nil {
		t.Fatal(err)
	}
	if correlation.Status != model.IntentSuperseded || correlation.ReplacementIntentID == nil {
		t.Fatalf("queued correlation after recovery = %+v, want superseded with replacement", correlation)
	}
	replacement, err := st.GetNotificationIntent(ctx, *correlation.ReplacementIntentID)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.TransitionSequence == nil || *replacement.TransitionSequence != recovery.Sequence || replacement.ReplyKind != model.ReplyRecoveryObserved {
		t.Fatalf("correlation replacement = %+v, want recovery-observed reply", replacement)
	}
}

func TestPostWindowQueuedRootSupersedesQueuedCorrelationReply(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 15, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "correlation-overtaken-queued", now)
	closes := now.Add(30 * time.Second)
	first := osCycle(t, st, sitID, now, osMonitoringContract(closes), model.LifecycleActive,
		&model.OperatorBriefing{
			Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
			Scope: "checkout", Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseCollecting},
		}, false)
	var correlationID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM notification_intents WHERE situation_id = ? AND transition_sequence = ? AND reply_kind = 'correlation_started'`, sitID, first.Sequence).Scan(&correlationID); err != nil {
		t.Fatalf("queued correlation reply: %v", err)
	}
	queuedAt := now.Add(time.Minute)
	queued := osCycle(t, st, sitID, queuedAt, oscPlannedTriageContract(queuedAt.Add(time.Minute)), model.LifecycleActive,
		&model.OperatorBriefing{
			Flow:  &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now, CorrelationClosesAt: &closes},
			Scope: "checkout", Firing: 1, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseQueued},
		}, true)
	if kinds := oscCandidateKinds(queued); len(kinds) != 0 {
		t.Fatalf("fixture queued transition candidates = %v, want none", kinds)
	}
	correlation, err := st.GetNotificationIntent(ctx, correlationID)
	if err != nil {
		t.Fatal(err)
	}
	if correlation.Status != model.IntentSuperseded || correlation.ReplacementIntentID == nil {
		t.Fatalf("queued correlation after post-window queueing = %+v, want superseded by current root", correlation)
	}
	replacement, err := st.GetNotificationIntent(ctx, *correlation.ReplacementIntentID)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.EffectClass != model.EffectRootSync || replacement.TransitionSequence == nil || *replacement.TransitionSequence != queued.Sequence {
		t.Fatalf("correlation replacement = %+v, want queued transition root", replacement)
	}
}
