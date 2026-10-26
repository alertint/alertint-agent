// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// retentionBriefing is a briefing large enough to show compression.
func retentionBriefing(alerts int, started bool) *situationmodel.OperatorBriefing {
	b := &situationmodel.OperatorBriefing{Scope: "service=checkout", Total: alerts, Firing: alerts}
	for i := 0; i < alerts; i++ {
		b.Alerts = append(b.Alerts, situationmodel.BriefingAlert{
			ID: fmt.Sprintf("alert-%04d", i), Name: fmt.Sprintf("KubePodCrashLooping/payments-%04d", i), State: "firing",
		})
	}
	b.Work.Phase = situationmodel.WorkPhaseExecuting
	b.Work.ExecutionStarted = started
	return b
}

func retentionTransition(situationID string, sequence int, created time.Time, briefing *situationmodel.OperatorBriefing) situationmodel.Transition {
	return situationmodel.Transition{
		ID: fmt.Sprintf("tr-retention-%s-%03d", situationID[:8], sequence), SituationID: situationID, Sequence: sequence,
		InputVersion: 1, MaterialFactHash: "sha256:retention", Lifecycle: situationmodel.LifecycleActive,
		Attention: situationmodel.AttentionInvestigate, Reason: situationmodel.ReasonTriageStateChanged,
		JournalKind: situationmodel.JournalInvestigationChanged, Actor: situationmodel.ActorDeterministicController,
		Projection: situationmodel.ProjectionFacts{
			Briefing:           briefing,
			EffectiveStartedAt: created.Add(-time.Hour), EffectiveStartedAtBasis: situationmodel.SourceTimeBasisSourcePayload,
			OperatorDelta: &situationmodel.OperatorDelta{Candidates: []situationmodel.MaterialCandidate{
				{Kind: situationmodel.CandidateFirstExecutionAssurance}}},
		},
		EvidenceRefs: []string{"fact:retention:1"},
		CreatedAt:    created,
	}
}

func insertRetentionTransitions(t *testing.T, st *Store, current bool, trs ...situationmodel.Transition) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, tr := range trs {
		if err := insertTransitionTx(ctx, tx, tr); err != nil {
			t.Fatal(err)
		}
	}
	if current {
		last := trs[len(trs)-1]
		if _, err := tx.ExecContext(ctx, `UPDATE situations SET current_transition_id = ?, current_transition_sequence = ? WHERE id = ?`,
			last.ID, last.Sequence, last.SituationID); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertRetentionIntent(t *testing.T, st *Store, tr situationmodel.Transition, status string) {
	t.Helper()
	var deliveredAs, channel, ts, deliveredAt any
	if status == "delivered" {
		deliveredAs, channel, ts, deliveredAt = "thread", "C0RET", fmt.Sprintf("1760947200.%06d", tr.Sequence), canonicalTime(tr.CreatedAt)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			summary_version, requires_root, main_channel_poke, interruption_priority,
			client_message_id, status, delivered_as, channel, message_ts, created_at, delivered_at
		) VALUES (?, ?, 'thread_append', ?, ?, ?, NULL, 1, 0, NULL, ?, ?, ?, ?, ?, ?, ?)`,
		"ni-"+tr.ID, "idem-"+tr.ID, tr.SituationID, tr.ID, tr.Sequence, "cmid-"+tr.ID, status,
		deliveredAs, channel, ts, canonicalTime(tr.CreatedAt), deliveredAt); err != nil {
		t.Fatalf("insert intent for %s: %v", tr.ID, err)
	}
}

func retentionCount(t *testing.T, st *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestTransitionBriefingStoredApartAndCompressed: a new Transition's briefing
// lives in situation_transition_briefings, compressed, and reads back whole;
// projection_json keeps every other field.
func TestTransitionBriefingStoredApartAndCompressed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=briefing-apart", now)
	tr := retentionTransition(sitID, 1, now, retentionBriefing(400, true))
	insertRetentionTransitions(t, st, true, tr)

	var projection string
	var raw, stored int
	if err := st.db.QueryRowContext(ctx, `
		SELECT t.projection_json, b.raw_bytes, length(b.briefing) FROM situation_transitions t
		JOIN situation_transition_briefings b ON b.transition_id = t.id WHERE t.id = ?`, tr.ID).Scan(&projection, &raw, &stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(projection, `"briefing"`) {
		t.Fatalf("projection_json still carries the briefing: %.200s", projection)
	}
	if !strings.Contains(projection, `"operator_delta"`) {
		t.Fatalf("projection_json lost the operator delta: %.200s", projection)
	}
	if stored*4 > raw {
		t.Fatalf("stored briefing %d bytes for %d raw, want at least 4x smaller", stored, raw)
	}
	got, err := st.GetSituationTransition(ctx, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(tr.Projection)
	if err != nil {
		t.Fatal(err)
	}
	have, err := json.Marshal(got.Projection)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(have) {
		t.Fatalf("projection read back differs:\nwant %.300s\nhave %.300s", want, have)
	}
	if got.DetailExpired {
		t.Fatal("a new Transition must not read as expired")
	}
}

// TestHistoryFactsMatchProjectionsForBriefingsStoredApart repeats 0047's
// parity check for Transitions written through insertTransitionTx, whose
// briefing is no longer in projection_json.
func TestHistoryFactsMatchProjectionsForBriefingsStoredApart(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=history-facts-apart", now)
	existing := retentionCount(t, st, `SELECT COUNT(*) FROM situation_transitions`)
	projections := historyFactsProjections(t)
	trs := make([]situationmodel.Transition, 0, len(projections))
	for i, p := range projections {
		tr := retentionTransition(sitID, 100+i, now.Add(time.Duration(i)*time.Second), nil)
		tr.JournalKind = p.journal
		tr.Projection = situationmodel.ProjectionFacts{}
		if err := json.Unmarshal([]byte(p.projection), &tr.Projection); err != nil {
			t.Fatal(err)
		}
		tr.Projection.EffectiveStartedAt, tr.Projection.EffectiveStartedAtBasis = now, situationmodel.SourceTimeBasisSourcePayload
		trs = append(trs, tr)
	}
	insertRetentionTransitions(t, st, false, trs...)
	assertHistoryFactsMatchProjections(t, st.db, existing+len(trs))
}

// TestTransitionLedgerStaysImmutableOutsideRetention: the only edits the
// narrowed trigger allows are the compaction move and an authorized expiry
// of a Transition nothing current uses.
func TestTransitionLedgerStaysImmutableOutsideRetention(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=immutable", now)
	old := retentionTransition(sitID, 1, now, retentionBriefing(3, false))
	current := retentionTransition(sitID, 2, now.Add(time.Minute), retentionBriefing(3, true))
	insertRetentionTransitions(t, st, true, old, current)

	refused := []struct {
		name, statement string
		args            []any
	}{
		{"journal edit", `UPDATE situation_transitions SET journal_json = '{"headline":"x"}' WHERE id = ?`, []any{old.ID}},
		{"unauthorized expiry", `UPDATE situation_transitions SET projection_json = json_remove(projection_json, '$.briefing', '$.operator_delta.candidates'),
			evidence_refs_json = '[]', detail_expired_at = 'now' WHERE id = ?`, []any{old.ID}},
		{"compaction without a stored briefing", `UPDATE situation_transitions SET projection_json = json_remove(projection_json, '$.briefing') WHERE id = ?`, []any{old.ID}},
		{"delete", `DELETE FROM situation_transitions WHERE id = ?`, []any{old.ID}},
		{"briefing delete", `DELETE FROM situation_transition_briefings WHERE transition_id = ?`, []any{old.ID}},
		{"briefing edit", `UPDATE situation_transition_briefings SET raw_bytes = 1 WHERE transition_id = ?`, []any{old.ID}},
	}
	for _, r := range refused {
		if _, err := st.db.ExecContext(ctx, r.statement, r.args...); err == nil {
			t.Errorf("%s: accepted", r.name)
		}
	}

	expire := func(id string) error {
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := expireTransitionDetailTx(ctx, tx, id, canonicalTime(now)); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := expire(current.ID); err == nil {
		t.Fatal("expiring the current Transition must be refused")
	}
	if err := expire(old.ID); err != nil {
		t.Fatalf("authorized expiry: %v", err)
	}
	got, err := st.GetSituationTransition(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DetailExpired || got.Projection.Briefing != nil || len(got.EvidenceRefs) != 0 ||
		(got.Projection.OperatorDelta != nil && len(got.Projection.OperatorDelta.Candidates) != 0) {
		t.Fatalf("expired Transition kept its detail: %+v", got)
	}
	if got.Journal != old.Journal || got.Reason != old.Reason || !got.CreatedAt.Equal(old.CreatedAt) {
		t.Fatalf("expiry changed the journal: %+v", got)
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_transition_history_facts WHERE transition_id = ?`, old.ID); n != 1 {
		t.Fatalf("history facts rows = %d, want 1", n)
	}
	if err := expire(old.ID); err == nil {
		t.Fatal("expiring twice must be refused")
	}
}

// TestFactsWrittenOnlyWhenChanged: a fact equal to its head is not written
// again; a changed one is, and the head it replaced is queued for retention.
func TestFactsWrittenOnlyWhenChanged(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=facts-dedup", now)
	claim := claimSituation(t, st, sitID, "facts-dedup", now)
	fact := func(version int, value string) situationmodel.Fact {
		f := factFixture(fmt.Sprintf("fact:%d", version), sitID, version, now.Add(time.Duration(version)*time.Minute))
		f.Value = json.RawMessage(value)
		f.Digest = "sha256:" + value
		return f
	}
	for _, f := range []situationmodel.Fact{fact(1, `{"v":1}`), fact(2, `{"v":1}`), fact(3, `{"v":1}`), fact(4, `{"v":2}`), fact(1, `{"v":1}`)} {
		if err := st.AppendSituationFacts(ctx, claim, []situationmodel.Fact{f}); err != nil {
			t.Fatalf("append %s: %v", f.ID, err)
		}
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_facts WHERE situation_id = ?`, sitID); n != 2 {
		t.Fatalf("fact rows = %d, want 2 (the first and the changed one)", n)
	}
	var head, superseded string
	if err := st.db.QueryRowContext(ctx, `SELECT fact_id FROM situation_fact_heads WHERE situation_id = ?`, sitID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT fact_id FROM situation_fact_supersessions`).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if head != "fact:4" || superseded != "fact:1" {
		t.Fatalf("head = %s superseded = %s, want fact:4 and fact:1", head, superseded)
	}
	conflict := fact(4, `{"v":3}`)
	if err := st.AppendSituationFacts(ctx, claim, []situationmodel.Fact{conflict}); !errors.Is(err, ErrImmutableConflict) {
		t.Fatalf("same id with other content: err = %v, want ErrImmutableConflict", err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM situation_facts WHERE id = 'fact:4'`); err == nil {
		t.Fatal("deleting a head fact must be refused")
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM situation_facts WHERE id = 'fact:1'`); err != nil {
		t.Fatalf("a superseded fact may go through retention: %v", err)
	}
}

// legacyRetentionFixture writes rows the way releases before 0048 did:
// briefings inside projection_json and one fact row per input version,
// then moves the legacy watermarks over them.
func legacyRetentionFixture(t *testing.T, st *Store, sitID string, now time.Time) []situationmodel.Transition {
	t.Helper()
	ctx := context.Background()
	var trs []situationmodel.Transition
	for i := 1; i <= 3; i++ {
		tr := retentionTransition(sitID, i, now.Add(time.Duration(i)*time.Minute), retentionBriefing(50*i, i == 3))
		projection, err := json.Marshal(tr.Projection)
		if err != nil {
			t.Fatal(err)
		}
		insertHistoryFactsTransition(t, st.db, sitID, i, tr.JournalKind, string(projection))
		tr.ID = fmt.Sprintf("tr-facts-%04d", i)
		trs = append(trs, tr)
	}
	for version := 1; version <= 6; version++ {
		value := `{"members":1}`
		if version >= 4 {
			value = `{"members":2}`
		}
		for _, subject := range []string{"inc-a", "inc-b"} {
			if _, err := st.db.ExecContext(ctx, `
				INSERT INTO situation_facts (id, situation_id, input_version, kind, subject, digest, value_json, result_status, evidence_refs_json, material, observed_at)
				VALUES (?, ?, ?, 'incident_membership', ?, ?, ?, 'confirmed_value', '[]', 1, ?)`,
				fmt.Sprintf("legacy:%d:%s", version, subject), sitID, version, subject, "sha256:"+value, value,
				canonicalTime(now.Add(time.Duration(version)*time.Minute))); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, key := range []string{"transitions_legacy_max_rowid", "facts_legacy_max_rowid"} {
		table := map[string]string{"transitions_legacy_max_rowid": "situation_transitions", "facts_legacy_max_rowid": "situation_facts"}[key]
		if _, err := st.db.ExecContext(ctx, `UPDATE storage_retention_state SET value = (SELECT CAST(max(rowid) AS TEXT) FROM `+table+`) WHERE key = ?`, key); err != nil {
			t.Fatal(err)
		}
	}
	return trs
}

// TestCompactStorageBacklogMovesLegacyRows: existing briefings move into
// compressed storage and read back the same; repeated legacy facts go; the
// coverage of attempts that are no longer current goes.
func TestCompactStorageBacklogMovesLegacyRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=legacy", now)
	legacy := legacyRetentionFixture(t, st, sitID, now)
	before := map[string]situationmodel.Transition{}
	for _, tr := range legacy {
		got, err := st.GetSituationTransition(ctx, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		before[tr.ID] = got
	}

	removed, err := st.CompactStorageBacklog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed.CompactedBriefings != 3 {
		t.Fatalf("compacted %d briefings, want 3", removed.CompactedBriefings)
	}
	// Versions 1-3 repeat {"members":1} and 4-6 repeat {"members":2}: the
	// first of each run stays, per subject.
	if removed.RepeatedFacts != 8 {
		t.Fatalf("removed %d repeated facts, want 8", removed.RepeatedFacts)
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_facts WHERE situation_id = ?`, sitID); n != 4 {
		t.Fatalf("facts left = %d, want 4", n)
	}
	for _, id := range []string{"legacy:1:inc-a", "legacy:4:inc-a", "legacy:1:inc-b", "legacy:4:inc-b"} {
		if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_facts WHERE id = ?`, id); n != 1 {
			t.Fatalf("fact %s should remain", id)
		}
	}
	for _, tr := range legacy {
		var projection string
		if err := st.db.QueryRowContext(ctx, `SELECT projection_json FROM situation_transitions WHERE id = ?`, tr.ID).Scan(&projection); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(projection, `"briefing"`) {
			t.Fatalf("%s still carries its briefing", tr.ID)
		}
		got, err := st.GetSituationTransition(ctx, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, before[tr.ID]) {
			t.Fatalf("%s reads differently after compaction:\nbefore %+v\nafter  %+v", tr.ID, before[tr.ID].Projection.Briefing.Work, got.Projection.Briefing.Work)
		}
	}
	again, err := st.CompactStorageBacklog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Total() != 0 {
		t.Fatalf("a finished backlog did more work: %+v", again)
	}
}

// TestSupersededCoverageGoesCurrentStays drives two real controller cycles,
// so the first attempt's coverage is superseded by the second's.
func TestSupersededCoverageGoesCurrentStays(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	sitID := seedReconcileSituation(t, st, "group-coverage", now)
	reconcileTwice(t, st, sitID, now)
	current := currentAssessmentID(t, st, sitID)
	total := retentionCount(t, st, `SELECT COUNT(*) FROM situation_assessment_coverage`)
	kept := retentionCount(t, st, `SELECT COUNT(*) FROM situation_assessment_coverage WHERE assessment_attempt_id = ?`, current)
	if total <= kept || kept == 0 {
		t.Fatalf("fixture: %d coverage rows, %d of the current attempt", total, kept)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM situation_assessment_coverage`); err == nil {
		t.Fatal("an unauthorized coverage delete must be refused")
	}
	removed, err := st.CompactStorageBacklog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Coverage != total-kept {
		t.Fatalf("removed %d coverage rows, want %d", removed.Coverage, total-kept)
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_assessment_coverage WHERE assessment_attempt_id = ?`, current); n != kept {
		t.Fatalf("current coverage rows = %d, want %d", n, kept)
	}
}

// reconcileTwice runs two real controller cycles on sitID: a model-validated
// assessment, then a revalidated reuse of it, each with its own coverage.
func reconcileTwice(t *testing.T, st *Store, sitID string, now time.Time) {
	t.Helper()
	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedProposalResponse(t)}}
	controllerNow := now.Add(5 * time.Minute)
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return controllerNow }, nil, nil)
	for i, at := range []time.Time{now.Add(time.Minute), now.Add(time.Hour)} {
		claim := claimSituation(t, st, sitID, fmt.Sprintf("coverage-%d", i), at)
		if err := controller.Reconcile(context.Background(), claim); err != nil {
			t.Fatalf("cycle %d: %v", i+1, err)
		}
	}
}

// TestExpireWorkingRecordKeepsMemoryAndCurrentState: past the cutoff, old
// Transitions lose their detail and the evidence only they cited, while the
// current Transition, one a pending notification needs, every journal entry
// and the history facts stay. Settling the notification lets it go too.
func TestExpireWorkingRecordKeepsMemoryAndCurrentState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	sitID, cycles := metadataRetentionCyclesAt(t, st, 3, false, false, 0, base)
	t1 := retentionTransition(sitID, 1, base, retentionBriefing(5, false))
	t2 := retentionTransition(sitID, 2, base.Add(time.Hour), retentionBriefing(5, true))
	t3 := retentionTransition(sitID, 3, base.Add(2*time.Hour), retentionBriefing(5, true))
	insertRetentionTransitions(t, st, true, t1, t2, t3)
	pin := func(cycleID, owner string) {
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := insertPermanentObservationReferencesTx(ctx, tx, cycleID, ObservationReferenceTransition, owner, base); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	pin(cycles[0].ID, t1.ID)
	pin(cycles[1].ID, t2.ID)
	insertRetentionIntent(t, st, t2, "pending")
	cycleCount := func() int {
		return retentionCount(t, st, `SELECT COUNT(*) FROM situation_preparation_cycles WHERE situation_id = ?`, sitID)
	}
	if cycleCount() != 3 {
		t.Fatalf("fixture cycles = %d", cycleCount())
	}

	now := base.Add(200 * 24 * time.Hour)
	removed, err := st.ExpireWorkingRecord(ctx, now, now.Add(-90*24*time.Hour), now.Add(-observationDetailRetention))
	if err != nil {
		t.Fatal(err)
	}
	if removed.TransitionDetails != 1 {
		t.Fatalf("expired %d Transitions, want 1 (t1 only)", removed.TransitionDetails)
	}
	for _, c := range []struct {
		tr      situationmodel.Transition
		expired bool
	}{{t1, true}, {t2, false}, {t3, false}} {
		got, err := st.GetSituationTransition(ctx, c.tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.DetailExpired != c.expired || (got.Projection.Briefing == nil) != c.expired {
			t.Fatalf("%s: expired=%v briefing=%v, want expired=%v", c.tr.ID, got.DetailExpired, got.Projection.Briefing != nil, c.expired)
		}
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_observation_references WHERE owner_id = ?`, t1.ID); n != 0 {
		t.Fatalf("%d references of the expired Transition remain", n)
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_observation_references WHERE owner_id = ?`, t2.ID); n == 0 {
		t.Fatal("the protected Transition lost its evidence")
	}
	if cycleCount() != 2 {
		t.Fatalf("cycles = %d, want 2: the first was cited only by the expired Transition", cycleCount())
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_transition_history_facts WHERE situation_id = ?`, sitID); n != 3 {
		t.Fatalf("history facts = %d, want 3", n)
	}

	if _, err := st.db.ExecContext(ctx, `UPDATE notification_intents SET status = 'delivered', delivered_as = 'thread',
		channel = 'C0RET', message_ts = '1760947200.000002', delivered_at = ? WHERE transition_id = ?`, canonicalTime(now), t2.ID); err != nil {
		t.Fatal(err)
	}
	removed, err = st.ExpireWorkingRecord(ctx, now, now.Add(-90*24*time.Hour), now.Add(-observationDetailRetention))
	if err != nil {
		t.Fatal(err)
	}
	if removed.TransitionDetails != 1 || cycleCount() != 1 {
		t.Fatalf("after delivery: expired %d, cycles %d; want 1 and 1", removed.TransitionDetails, cycleCount())
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys: %d, %v", n, err)
	}
}

// TestExpireWorkingRecordReleasesCallEvidence: a dispatched call pins its
// evidence under the call's ID, apart from the attempt's own pins. Releasing
// an old attempt releases its call's too; a call that never got an attempt is
// released once its Situation has moved past that input; the current
// assessment and its call keep theirs.
func TestExpireWorkingRecordReleasesCallEvidence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	sitID, cycles := metadataRetentionCyclesAt(t, st, 4, false, false, 0, base)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	call := func(id string, inputVersion, workAttempt int, callNumber ...int) {
		number := 1
		if len(callNumber) > 0 {
			number = callNumber[0]
		}
		exec(`INSERT INTO situation_assessment_calls (id, situation_id, input_version, work_attempt, call_number, material_fact_hash, dispatched_at)
			VALUES (?, ?, ?, ?, ?, 'sha256:material', ?)`, id, sitID, inputVersion, workAttempt, number, canonicalTime(base))
	}
	attempt := func(id, callID string, sequence, workAttempt int) {
		exec(`INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, call_id, status, derivation, provider_request_started,
			material_fact_hash, assessment_json, created_at, completed_at
		) VALUES (?, ?, ?, 1, ?, ?, 'authoritative', 'model_validated', 'true', 'sha256:material', '{}', ?, ?)`,
			id, sitID, sequence, workAttempt, callID, canonicalTime(base), canonicalTime(base))
	}
	pin := func(cycleID, owner string) {
		t.Helper()
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := insertPermanentObservationReferencesTx(ctx, tx, cycleID, ObservationReferenceAssessmentAttempt, owner, base); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	// Each work attempt dispatches a draft and a verification call; the
	// attempt names the last.
	call("call-old-draft", 1, 1)
	call("call-old", 1, 1, 2)
	attempt("att-old", "call-old", 1, 1)
	pin(cycles[0].ID, "call-old-draft")
	pin(cycles[0].ID, "call-old")
	pin(cycles[0].ID, "att-old")
	call("call-orphan-past", 1, 2)
	pin(cycles[1].ID, "call-orphan-past")
	call("call-current-draft", 1, 3)
	call("call-current", 1, 3, 2)
	attempt("att-current", "call-current", 2, 3)
	pin(cycles[2].ID, "call-current-draft")
	pin(cycles[2].ID, "call-current")
	pin(cycles[2].ID, "att-current")
	call("call-orphan-now", 2, 1)
	pin(cycles[3].ID, "call-orphan-now")
	exec(`UPDATE situations SET current_assessment_id = 'att-current', input_version = 2 WHERE id = ?`, sitID)

	now := base.Add(200 * 24 * time.Hour)
	if _, err := st.ExpireWorkingRecord(ctx, now, now.Add(-90*24*time.Hour), now.Add(-observationDetailRetention)); err != nil {
		t.Fatal(err)
	}
	refs := func(owner string) int {
		return retentionCount(t, st, `SELECT COUNT(*) FROM situation_observation_references WHERE owner_id = ?`, owner)
	}
	for owner, kept := range map[string]bool{
		"call-old-draft": false, "call-old": false, "att-old": false, "call-orphan-past": false,
		"call-current-draft": true, "call-current": true, "att-current": true, "call-orphan-now": true,
	} {
		if got := refs(owner) > 0; got != kept {
			t.Errorf("%s: references kept = %v, want %v", owner, got, kept)
		}
	}
	for i, kept := range []bool{false, false, true, true} {
		got := retentionCount(t, st, `SELECT COUNT(*) FROM situation_preparation_cycles WHERE id = ?`, cycles[i].ID) == 1
		if got != kept {
			t.Errorf("cycle %d kept = %v, want %v", i, got, kept)
		}
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys: %d, %v", n, err)
	}
}

// TestStorageSizeLimitRemovesOldestFirst: over the size limit, the oldest
// data goes first whatever its kind, the audit log included, down to an
// hour back; the chain still verifies from its anchor.
func TestStorageSizeLimitRemovesOldestFirst(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=size-limit", now)
	auditor := audit.New(st.db)
	var trs []situationmodel.Transition
	for day := 30; day >= 0; day-- {
		at := now.Add(-time.Duration(day)*24*time.Hour - 30*time.Minute)
		trs = append(trs, retentionTransition(sitID, 31-day, at, retentionBriefing(20, true)))
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := auditor.AppendTx(ctx, tx, "test", "test.event", map[string]int{"day": day}, at); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	insertRetentionTransitions(t, st, true, trs...)

	report, err := st.RunStorageMaintenance(ctx, now, StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365, SizeBytes: 1}, auditor)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ShortenedBySizeLimit {
		t.Fatal("the size limit should have shortened history")
	}
	if report.Removed.TransitionDetails != 30 {
		t.Fatalf("expired %d Transitions, want 30 (all but the current)", report.Removed.TransitionDetails)
	}
	var oldestEvent string
	if err := st.db.QueryRowContext(ctx, `SELECT min(ts) FROM audit_log WHERE kind = 'test.event'`).Scan(&oldestEvent); err != nil {
		t.Fatal(err)
	}
	if kept, err := parseStoredTime(oldestEvent); err != nil || report.Removed.Audit != 30 || now.Sub(kept) > 2*time.Hour {
		t.Fatalf("audit not shortened to the last hours: removed %d, oldest kept %s (%v)", report.Removed.Audit, oldestEvent, err)
	}
	verify, err := auditor.Verify(ctx)
	if err != nil {
		t.Fatalf("verify after pruning: %v", err)
	}
	if verify.PrunedThroughSeq == 0 || verify.AnchorSeq == 0 {
		t.Fatalf("verify report has no anchor: %+v", verify)
	}
	stored, ok := st.StorageReport()
	if !ok || stored.CheckedAt != now {
		t.Fatalf("StorageReport = %+v, %v", stored, ok)
	}
}

// TestStorageMaintenanceWithinLimitsRemovesNothing: a young database under
// its limits keeps everything and reports its usage.
func TestStorageMaintenanceWithinLimitsRemovesNothing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=young", now)
	insertRetentionTransitions(t, st, true,
		retentionTransition(sitID, 1, now.Add(-48*time.Hour), retentionBriefing(5, false)),
		retentionTransition(sitID, 2, now.Add(-time.Hour), retentionBriefing(5, true)))
	report, err := st.RunStorageMaintenance(ctx, now, StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365, SizePercent: 80}, audit.New(st.db))
	if err != nil {
		t.Fatal(err)
	}
	if report.Removed.Total() != 0 || report.ShortenedBySizeLimit {
		t.Fatalf("removed %+v shortened=%v", report.Removed, report.ShortenedBySizeLimit)
	}
	if report.UsedBytes <= 0 || report.FileBytes < report.UsedBytes || report.VolumeBytes <= 0 || report.LimitBytes != report.VolumeBytes/100*80 {
		t.Fatalf("usage not reported: %+v", report)
	}
	if report.KeptSince == nil || !report.KeptSince.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("kept since %v, want the older Transition", report.KeptSince)
	}
}

// TestStorageMaintenanceStepsFailIndependently: a step that fails on one row
// would fail on it every hour, so it must not hold back the others: with the
// backlog failing, the working record still expires and the audit log is
// still pruned, and the pass reports the failure.
func TestStorageMaintenanceStepsFailIndependently(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=independent", base)
	old := retentionTransition(sitID, 1, base, retentionBriefing(5, false))
	insertRetentionTransitions(t, st, false, old)
	insertRetentionTransitions(t, st, true, retentionTransition(sitID, 2, base.Add(time.Hour), retentionBriefing(5, true)))
	auditor := audit.New(st.db)
	if err := auditor.Append(ctx, "test", "test.old", map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { retentionFailpoint = nil })
	retentionFailpoint = func(step string) error {
		if step == "backlog" {
			return errors.New("backlog refused a row")
		}
		return nil
	}

	now := time.Now().UTC().Add(400 * 24 * time.Hour)
	report, err := st.RunStorageMaintenance(ctx, now, StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365}, auditor)
	if err == nil || !strings.Contains(err.Error(), "backlog refused a row") {
		t.Fatalf("err = %v, want the backlog failure reported", err)
	}
	if report.Removed.TransitionDetails != 1 || report.Removed.Audit == 0 {
		t.Fatalf("removed %+v: expiry and the audit prune must still run", report.Removed)
	}
	if stored, ok := st.StorageReport(); !ok || stored.CheckedAt.IsZero() {
		t.Fatalf("StorageReport = %+v, %v; a partly failed pass still reports", stored, ok)
	}
}

// TestControllerKeepsWorkingAfterRetention: a maintenance pass with every
// record past its cutoff leaves the current state the controller reads, so
// the next reconcile commits as usual and reads its prior Transition whole.
func TestControllerKeepsWorkingAfterRetention(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	sitID := seedReconcileSituation(t, st, "group-after-retention", now)
	reconcileTwice(t, st, sitID, now)
	transitions := retentionCount(t, st, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, sitID)

	later := now.Add(400 * 24 * time.Hour)
	if _, err := st.RunStorageMaintenance(ctx, later, StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365}, audit.New(st.db)); err != nil {
		t.Fatal(err)
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys after retention: %d, %v", n, err)
	}
	current, err := loadCurrentTransitionForTest(st, sitID)
	if err != nil {
		t.Fatal(err)
	}
	if current.DetailExpired || current.Projection.Briefing == nil {
		t.Fatalf("the current Transition lost its detail: %+v", current)
	}

	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedProposalResponse(t)}}
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return later }, nil, nil)
	claim := claimSituation(t, st, sitID, "after-retention", later)
	if err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatalf("reconcile after retention: %v", err)
	}
	if n := retentionCount(t, st, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, sitID); n < transitions {
		t.Fatalf("transitions = %d, was %d", n, transitions)
	}
	if _, err := st.GetSituationEpisodeView(ctx, sitID); err != nil {
		t.Fatalf("episode view after retention: %v", err)
	}
}

func loadCurrentTransitionForTest(st *Store, situationID string) (situationmodel.Transition, error) {
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return situationmodel.Transition{}, err
	}
	defer func() { _ = tx.Rollback() }()
	tr, err := loadCurrentTransitionTx(ctx, tx, situationID)
	if err != nil || tr == nil {
		return situationmodel.Transition{}, fmt.Errorf("current transition: %v", err)
	}
	return *tr, nil
}
