// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 (earned delivery / communicated history): LoadReconciliationInput must
// read SnapshotInput.DeliveredHistory inside its own coherent transaction
// (B0 integration contract §4/§5) — folding delivered replies' own
// persisted candidates in Transition-sequence order, never a second
// materiality decision.
// ----------------------------------------------------------------------

// dhTransition inserts one Transition row directly (bypassing the
// controller) with journalKind and candidates, so this test can build an
// exact delivered-reply history without driving a full realistic
// reconciliation cycle.
func dhTransition(t *testing.T, st *Store, situationID, id string, sequence int, journalKind model.JournalKind, cands []model.MaterialCandidate, now time.Time) {
	t.Helper()
	ctx := context.Background()
	tr := model.Transition{
		ID: id, SituationID: situationID, Sequence: sequence, InputVersion: 1,
		MaterialFactHash: "sha256:dh-" + id, Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
		Reason: model.ReasonInvestigationStarted, JournalKind: journalKind,
		Journal: model.JournalData{Headline: "h", OccurredAt: now},
		Projection: model.ProjectionFacts{
			EffectiveStartedAt: now, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
			OperatorDelta: &model.OperatorDelta{Candidates: cands},
		},
		Actor: model.ActorDeterministicController, EvidenceRefs: []string{}, CreatedAt: now,
	}
	contractJSON, err := json.Marshal(tr.ActionContract)
	if err != nil {
		t.Fatal(err)
	}
	journalJSON, err := json.Marshal(tr.Journal)
	if err != nil {
		t.Fatal(err)
	}
	projectionJSON, err := json.Marshal(tr.Projection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)`,
		tr.ID, tr.SituationID, tr.Sequence, tr.MaterialFactHash, string(tr.Lifecycle), string(tr.Attention),
		string(contractJSON), string(tr.Reason), string(tr.JournalKind), string(journalJSON), string(projectionJSON),
		string(tr.Actor), canonicalTime(now)); err != nil {
		t.Fatalf("insert transition %s: %v", id, err)
	}
}

// dhIntent inserts one thread_append notification_intents row referencing
// transitionID, in the given status.
func dhIntent(t *testing.T, st *Store, situationID, id, transitionID string, sequence int, status string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if status == "delivered" {
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
				requires_root, main_channel_poke, client_message_id, status,
				delivered_as, channel, message_ts, delivered_at, created_at
			) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, 'delivered', 'thread', 'C', ?, ?, ?)`,
			id, "key:"+id, situationID, transitionID, sequence, "client:"+id, id+"-ts", canonicalTime(now), canonicalTime(now)); err != nil {
			t.Fatalf("insert delivered intent %s: %v", id, err)
		}
		return
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			requires_root, main_channel_poke, client_message_id, status, created_at
		) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, ?, ?)`,
		id, "key:"+id, situationID, transitionID, sequence, "client:"+id, status, canonicalTime(now)); err != nil {
		t.Fatalf("insert %s intent %s: %v", status, id, err)
	}
}

func TestLoadReconciliationInputDeliveredHistory(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "delivered-history", now)

	// No delivered reply at all yet: zero value.
	claim0 := claimSituation(t, st, sitID, "dh-owner", now)
	in0, err := st.LoadReconciliationInput(ctx, claim0, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput (empty): %v", err)
	}
	if in0.DeliveredHistory.AssuranceConveyed || in0.DeliveredHistory.LiveAssuranceIntentID != nil ||
		len(in0.DeliveredHistory.CommunicatedLimitationCodes) != 0 || in0.DeliveredHistory.CommunicatedAction != nil ||
		in0.DeliveredHistory.LastDeliveredSequence != 0 {
		t.Fatalf("empty ledger must read a zero-value DeliveredHistory: %+v", in0.DeliveredHistory)
	}

	action := model.OperatorActionInvestigateSituation
	assurance := model.MaterialCandidate{Kind: model.CandidateFirstExecutionAssurance,
		Members: &model.MemberFacts{FiringCount: 1, CountKnown: true, NowFiring: []string{"a"}}}
	limitAppear := model.MaterialCandidate{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: "evidence_source_unavailable", Cleared: false}}
	actionIntroduced := model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Introduced: true, Action: action}}

	// Sequence 1: the investigation_started assurance, delivered.
	dhTransition(t, st, sitID, "tr-1", 1, model.JournalInvestigationStarted, []model.MaterialCandidate{assurance, limitAppear, actionIntroduced}, now)
	dhIntent(t, st, sitID, "intent-1", "tr-1", 1, "delivered", now)

	in1, err := st.LoadReconciliationInput(ctx, claim0, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput (after sequence 1): %v", err)
	}
	if !in1.DeliveredHistory.AssuranceConveyed {
		t.Fatal("a delivered investigation_started reply must mark the assurance conveyed")
	}
	if len(in1.DeliveredHistory.CommunicatedLimitationCodes) != 1 || in1.DeliveredHistory.CommunicatedLimitationCodes[0] != "evidence_source_unavailable" {
		t.Fatalf("the delivered ability_changed appearance must be communicated: %+v", in1.DeliveredHistory.CommunicatedLimitationCodes)
	}
	if in1.DeliveredHistory.CommunicatedAction == nil || *in1.DeliveredHistory.CommunicatedAction != action {
		t.Fatalf("the delivered action_changed introduction must be communicated: %+v", in1.DeliveredHistory.CommunicatedAction)
	}
	if in1.DeliveredHistory.LastDeliveredSequence != 1 {
		t.Fatalf("LastDeliveredSequence = %d, want 1", in1.DeliveredHistory.LastDeliveredSequence)
	}

	// Sequence 2: the limitation clears and the action withdraws, but this
	// reply is still PENDING — not yet delivered, so the net communicated
	// state must not move yet.
	limitClear := model.MaterialCandidate{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: "evidence_source_unavailable", Cleared: true}}
	actionWithdrawn := model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Withdrawn: true, Action: action}}
	dhTransition(t, st, sitID, "tr-2", 2, model.JournalOperatorContractChanged, []model.MaterialCandidate{limitClear, actionWithdrawn}, now.Add(time.Minute))
	dhIntent(t, st, sitID, "intent-2", "tr-2", 2, "pending", now.Add(time.Minute))

	in2, err := st.LoadReconciliationInput(ctx, claim0, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput (sequence 2 pending): %v", err)
	}
	if len(in2.DeliveredHistory.CommunicatedLimitationCodes) != 1 {
		t.Fatalf("an UNDELIVERED clearing must not move communicated state yet: %+v", in2.DeliveredHistory.CommunicatedLimitationCodes)
	}
	if in2.DeliveredHistory.CommunicatedAction == nil {
		t.Fatal("an UNDELIVERED withdrawal must not clear the communicated action yet")
	}
	if in2.DeliveredHistory.LastDeliveredSequence != 1 {
		t.Fatalf("LastDeliveredSequence must not advance past the last DELIVERED reply, got %d", in2.DeliveredHistory.LastDeliveredSequence)
	}

	// Now mark sequence 2 delivered: the net communicated state moves.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', delivered_as = 'thread', channel = 'C', message_ts = 'ts-2', delivered_at = ?
		WHERE id = 'intent-2'`, canonicalTime(now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	in3, err := st.LoadReconciliationInput(ctx, claim0, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput (sequence 2 delivered): %v", err)
	}
	if len(in3.DeliveredHistory.CommunicatedLimitationCodes) != 0 {
		t.Fatalf("a DELIVERED clearing must remove the code from the communicated set: %+v", in3.DeliveredHistory.CommunicatedLimitationCodes)
	}
	if in3.DeliveredHistory.CommunicatedAction != nil {
		t.Fatalf("a DELIVERED withdrawal must clear the communicated action: %+v", in3.DeliveredHistory.CommunicatedAction)
	}
	if in3.DeliveredHistory.LastDeliveredSequence != 2 {
		t.Fatalf("LastDeliveredSequence = %d, want 2", in3.DeliveredHistory.LastDeliveredSequence)
	}
}

// TestLoadReconciliationInputDeliveredHistoryLiveAssurance proves a still-
// undelivered assurance is named by LiveAssuranceIntentID and does not mark
// AssuranceConveyed.
func TestLoadReconciliationInputDeliveredHistoryLiveAssurance(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "delivered-history-live", now)

	assurance := model.MaterialCandidate{Kind: model.CandidateFirstExecutionAssurance,
		Members: &model.MemberFacts{FiringCount: 1, CountKnown: true, NowFiring: []string{"a"}}}
	dhTransition(t, st, sitID, "tr-live", 1, model.JournalInvestigationStarted, []model.MaterialCandidate{assurance}, now)
	dhIntent(t, st, sitID, "intent-live", "tr-live", 1, "pending", now)

	claim := claimSituation(t, st, sitID, "dh-owner", now)
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if in.DeliveredHistory.AssuranceConveyed {
		t.Fatal("a still-pending assurance must not read as conveyed")
	}
	if in.DeliveredHistory.LiveAssuranceIntentID == nil || *in.DeliveredHistory.LiveAssuranceIntentID != "intent-live" {
		t.Fatalf("LiveAssuranceIntentID = %v, want intent-live", in.DeliveredHistory.LiveAssuranceIntentID)
	}
	_ = situation.DeliveredHistory{}
}
