// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func judgmentSituationFixture(t *testing.T, st *Store, now time.Time) string {
	t.Helper()
	d := deliveryFixture("delivery-judgment", "fp-judgment", now)
	d.Alert.Labels = map[string]string{
		"alertname": "HighCPU", "instance": "db-prod-1", "service": "postgres", "severity": "warning",
	}
	signalID, signalVersion := "HighCPU", "rule-v3"
	d.SourceProvenance.SignalID, d.SourceProvenance.SignalVersion = &signalID, &signalVersion
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{d}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, "incident-judgment", "input-judgment", "instance=db-prod-1", d.ID, now)
	claim := claimOneInput(t, st, "input-worker", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	sitID := listSituations(t, st)[0].ID
	assessment := validAssessmentFixture()
	assessment.Impact = model.ImpactSuspected
	assessmentJSON := mustJSON(t, assessment)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, status, derivation,
			provider_request_started, material_fact_hash, assessment_json, created_at, completed_at
		) VALUES ('judgment-assessment', ?, 1, 1, 1, 'authoritative', 'deterministic_controller',
			'false', 'sha256:judgment', ?, ?, ?)
	`, sitID, assessmentJSON, canonicalTime(now), canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET current_assessment_id = 'judgment-assessment', attention = 'investigate' WHERE id = ?`, sitID); err != nil {
		t.Fatal(err)
	}
	return sitID
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func recordJudgmentRequest(sit model.Situation, now time.Time, requestID string) SituationJudgmentWrite {
	return SituationJudgmentWrite{
		Operation: model.JudgmentOperationRecord, SituationID: sit.ID,
		SituationInputVersion: sit.InputVersion, ExpectedJudgmentVersion: 0,
		RequestID: requestID, AssertedOperator: "Janis", Confirmed: true,
		ValidUntil: now.Add(time.Hour), Now: now,
	}
}

func TestSituationJudgmentRecordIsAtomicVersionedAndIdempotent(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	sit, _ := st.GetSituation(context.Background(), sitID)
	auditor := audit.New(st.DB())
	req := recordJudgmentRequest(sit, now, "request-1")

	first, err := st.WriteSituationJudgment(context.Background(), auditor, req)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Judgment.Revision != 1 || first.Judgment.State != model.JudgmentStateExpected {
		t.Fatalf("first result = %+v", first)
	}
	after, _ := st.GetSituation(context.Background(), sitID)
	if after.InputVersion != sit.InputVersion+1 || !hasDueReason(after.DueReasons, model.DueOperatorJudgment) || !hasDueReason(after.DueReasons, model.DueJudgmentBoundary) {
		t.Fatalf("situation after write = version %d due %v", after.InputVersion, after.DueReasons)
	}
	if !after.NextAssessmentAt.Equal(now) {
		t.Fatalf("next assessment = %s, want immediate %s", after.NextAssessmentAt, now)
	}

	retry, err := st.WriteSituationJudgment(context.Background(), auditor, req)
	if err != nil || retry.Judgment.ID != first.Judgment.ID {
		t.Fatalf("exact retry = %+v, %v", retry, err)
	}
	assertTableCount(t, st.DB(), "situation_judgments", 1)
	if got, _ := st.GetSituation(context.Background(), sitID); got.InputVersion != after.InputVersion {
		t.Fatalf("exact retry advanced input version to %d", got.InputVersion)
	}

	changed := req
	changed.ValidUntil = changed.ValidUntil.Add(time.Hour)
	if _, err := st.WriteSituationJudgment(context.Background(), auditor, changed); !errors.Is(err, ErrSituationJudgmentRequestConflict) {
		t.Fatalf("changed retry error = %v, want request conflict", err)
	}
}

type failingJudgmentAuditor struct{ err error }

func (a failingJudgmentAuditor) AppendTx(context.Context, AuditTx, string, string, any, time.Time) error {
	return a.err
}

func TestSituationJudgmentAuditFailureRollsBackAuthorityAndWake(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	before, _ := st.GetSituation(context.Background(), sitID)
	injected := errors.New("audit unavailable")
	if _, err := st.WriteSituationJudgment(context.Background(), failingJudgmentAuditor{injected}, recordJudgmentRequest(before, now, "rollback")); !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected", err)
	}
	assertTableCount(t, st.DB(), "situation_judgments", 0)
	after, _ := st.GetSituation(context.Background(), sitID)
	if after.InputVersion != before.InputVersion || !after.NextAssessmentAt.Equal(before.NextAssessmentAt) {
		t.Fatalf("partial wake persisted: before=%+v after=%+v", before, after)
	}
}

func TestSituationJudgmentReplaceRevokeRestoreAndStaleFences(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	auditor := audit.New(st.DB())
	sit, _ := st.GetSituation(context.Background(), sitID)
	first, err := st.WriteSituationJudgment(context.Background(), auditor, recordJudgmentRequest(sit, now, "record"))
	if err != nil {
		t.Fatal(err)
	}

	stale := SituationJudgmentWrite{Operation: model.JudgmentOperationReplace, SituationID: sitID,
		SituationInputVersion: sit.InputVersion, ExpectedJudgmentVersion: 1, RequestID: "stale", AssertedOperator: "Janis",
		Confirmed: true, ValidUntil: now.Add(2 * time.Hour), Now: now.Add(time.Minute)}
	if _, err := st.WriteSituationJudgment(context.Background(), auditor, stale); !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("stale input error = %v", err)
	}

	current, _ := st.GetSituation(context.Background(), sitID)
	replace := stale
	replace.SituationInputVersion, replace.RequestID = current.InputVersion, "replace"
	second, err := st.WriteSituationJudgment(context.Background(), auditor, replace)
	if err != nil || second.Judgment.Revision != 2 {
		t.Fatalf("replace = %+v, %v", second, err)
	}

	current, _ = st.GetSituation(context.Background(), sitID)
	revoke := SituationJudgmentWrite{Operation: model.JudgmentOperationRevoke, SituationID: sitID,
		SituationInputVersion: current.InputVersion, ExpectedJudgmentVersion: 2, RequestID: "revoke",
		AssertedOperator: "Janis", Confirmed: true, Now: now.Add(2 * time.Minute)}
	third, err := st.WriteSituationJudgment(context.Background(), auditor, revoke)
	if err != nil || third.Judgment.Revision != 3 || third.Judgment.State != model.JudgmentStateRevoked {
		t.Fatalf("revoke = %+v, %v", third, err)
	}

	current, _ = st.GetSituation(context.Background(), sitID)
	restore := SituationJudgmentWrite{Operation: model.JudgmentOperationRestore, SituationID: sitID,
		SituationInputVersion: current.InputVersion, ExpectedJudgmentVersion: 3, RequestID: "restore",
		AssertedOperator: "Janis", Confirmed: true, ValidUntil: now.Add(3 * time.Hour), Now: now.Add(3 * time.Minute)}
	fourth, err := st.WriteSituationJudgment(context.Background(), auditor, restore)
	if err != nil || fourth.Judgment.Revision != 4 || fourth.Judgment.State != model.JudgmentStateExpected {
		t.Fatalf("restore = %+v, %v", fourth, err)
	}

	history, err := st.ListSituationJudgments(context.Background(), sitID, 0, 10)
	if err != nil || len(history) != 4 || history[0].ID != first.Judgment.ID || history[3].ID != fourth.Judgment.ID {
		t.Fatalf("history = %+v, %v", history, err)
	}
	replay, err := st.WriteSituationJudgment(context.Background(), auditor, recordJudgmentRequest(sit, now, "record"))
	if err != nil || !replay.IdempotentReplay || replay.SituationInputVersion != first.SituationInputVersion {
		t.Fatalf("late exact replay = %+v, %v; want original result version %d", replay, err, first.SituationInputVersion)
	}
	lateReplay := recordJudgmentRequest(sit, now.Add(4*time.Hour), "record")
	lateReplay.ValidUntil = first.Judgment.ValidUntil
	replay, err = st.WriteSituationJudgment(context.Background(), auditor, lateReplay)
	if err != nil || !replay.IdempotentReplay || replay.Judgment.ID != first.Judgment.ID {
		t.Fatalf("post-deadline exact replay = %+v, %v", replay, err)
	}
}

func TestSituationJudgmentConcurrentExpectedVersionAllowsOneWriter(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	sit, _ := st.GetSituation(context.Background(), sitID)
	auditor := audit.New(st.DB())
	reqs := []SituationJudgmentWrite{recordJudgmentRequest(sit, now, "race-a"), recordJudgmentRequest(sit, now, "race-b")}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = st.WriteSituationJudgment(context.Background(), auditor, reqs[i])
		}(i)
	}
	wg.Wait()
	success, conflicts := 0, 0
	for _, err := range errs {
		//nolint:gocritic // this three-way count reads directly as success, expected conflict, or unexpected failure
		if err == nil {
			success++
		} else if errors.Is(err, ErrSituationJudgmentVersionConflict) || errors.Is(err, ErrSituationVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d errors=%v", success, conflicts, errs)
	}
	assertTableCount(t, st.DB(), "situation_judgments", 1)
}

func TestControllerCommitRejectsAuthorityThatExpiredDuringWork(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	auditor := audit.New(st.DB())
	sit, _ := st.GetSituation(context.Background(), sitID)
	result, err := st.WriteSituationJudgment(context.Background(), auditor, recordJudgmentRequest(sit, now, "expiry-race"))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sitID, "controller-expiry", now.Add(time.Minute))
	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now.Add(time.Minute))
	commit.JudgmentRevision = result.Judgment.Revision
	commit.JudgmentApplicable = true
	commit.JudgmentCheckedAt = result.Judgment.ValidUntil
	if err := st.CommitController(context.Background(), claim, commit); !errors.Is(err, ErrSituationJudgmentStale) {
		t.Fatalf("commit error = %v, want stale judgment", err)
	}
}

func TestSituationJudgmentInvalidationCannotSilentlyRevive(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	sitID := judgmentSituationFixture(t, st, now)
	auditor := audit.New(st.DB())
	sit, _ := st.GetSituation(context.Background(), sitID)
	recorded, err := st.WriteSituationJudgment(context.Background(), auditor, recordJudgmentRequest(sit, now, "monotonic-record"))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sitID, "controller-invalidate", now.Add(time.Minute))
	commit := basicControllerCommit(sitID, claim.Situation.InputVersion, now.Add(time.Minute))
	commit.JudgmentRevision = recorded.Judgment.Revision
	commit.JudgmentApplicabilityReason = model.JudgmentSymptomsChanged
	commit.JudgmentCheckedAt = now.Add(time.Minute)
	if err := st.CommitController(context.Background(), claim, commit); err != nil {
		t.Fatal(err)
	}

	// The current facts still match the original coverage. The durable
	// invalidation must win so that a transient mismatch cannot revive the
	// old decision when conditions happen to look the same again.
	view, err := st.GetCurrentSituationJudgment(context.Background(), sitID, now.Add(2*time.Minute))
	if err != nil || view == nil || view.Applicability.Applicable || view.Applicability.Reason != model.JudgmentSymptomsChanged {
		t.Fatalf("invalidated view = %+v, %v", view, err)
	}

	current, _ := st.GetSituation(context.Background(), sitID)
	replace := SituationJudgmentWrite{
		Operation: model.JudgmentOperationReplace, SituationID: sitID,
		SituationInputVersion: current.InputVersion, ExpectedJudgmentVersion: 1,
		RequestID: "monotonic-replace", AssertedOperator: "Janis", Confirmed: true,
		ValidUntil: now.Add(2 * time.Hour), Now: now.Add(2 * time.Minute),
	}
	if _, err := st.WriteSituationJudgment(context.Background(), auditor, replace); err != nil {
		t.Fatal(err)
	}
	view, err = st.GetCurrentSituationJudgment(context.Background(), sitID, now.Add(3*time.Minute))
	if err != nil || view == nil || !view.Applicability.Applicable || view.Judgment.Revision != 2 {
		t.Fatalf("fresh replacement = %+v, %v", view, err)
	}
}

func TestChangedSourceInputInvalidatesBeforeTransientConditionClears(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	// ApplySituationInput evaluates observed invalidation against the real
	// transaction clock. Keep this fixture current so its one-hour decision
	// cannot expire merely because the calendar moved past the original test
	// date.
	now := time.Now().UTC().Truncate(time.Second)
	sitID := judgmentSituationFixture(t, st, now)
	sit, _ := st.GetSituation(ctx, sitID)
	if _, err := st.WriteSituationJudgment(ctx, audit.New(st.DB()), recordJudgmentRequest(sit, now, "observed-change")); err != nil {
		t.Fatal(err)
	}

	changed := deliveryFixture("delivery-new-critical", "fp-new-critical", now.Add(time.Minute))
	changed.Alert.Labels = map[string]string{"alertname": "DatabaseUnavailable", "instance": "db-prod-1", "severity": "critical"}
	changed.Alert.Status = "firing"
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{changed}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, "incident-new-critical", "input-new-critical", "instance=db-prod-1", changed.ID, now.Add(time.Minute))
	claim := claimOneInput(t, st, "changed-source-worker", now.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatal(err)
	}
	view, err := st.GetCurrentSituationJudgment(ctx, sitID, now.Add(time.Minute))
	if err != nil || view == nil || view.Applicability.Reason != model.JudgmentUrgent {
		t.Fatalf("observed changed condition = %+v, %v", view, err)
	}

	// Model the short-lived alert clearing before controller reconciliation.
	// Current facts match the original coverage again, but observed change is
	// monotonic until an explicit replacement.
	if _, err := st.db.ExecContext(ctx, `UPDATE alert_deliveries SET status='resolved' WHERE id=?`, changed.ID); err != nil {
		t.Fatal(err)
	}
	view, err = st.GetCurrentSituationJudgment(ctx, sitID, now.Add(2*time.Minute))
	if err != nil || view == nil || view.Applicability.Applicable || view.Applicability.Reason != model.JudgmentUrgent {
		t.Fatalf("transient change silently revived authority: %+v, %v", view, err)
	}
}

func TestSituationJudgmentRejectsUrgentAndTerminalSituations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate string
		args   []any
	}{
		{name: "urgent", mutate: `UPDATE situations SET attention='urgent' WHERE id=?`},
		{name: "terminal", mutate: `UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing' WHERE id=?`},
	} {
		t.Run(test.name, func(t *testing.T) {
			st := newTestStore(t)
			now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
			sitID := judgmentSituationFixture(t, st, now)
			args := []any{sitID}
			if test.name == "terminal" {
				args = []any{canonicalTime(now), sitID}
			}
			if _, err := st.db.ExecContext(context.Background(), test.mutate, args...); err != nil {
				t.Fatal(err)
			}
			sit, _ := st.GetSituation(context.Background(), sitID)
			_, err := st.WriteSituationJudgment(context.Background(), audit.New(st.DB()), recordJudgmentRequest(sit, now, "rejected-"+test.name))
			if !errors.Is(err, ErrSituationJudgmentNotAllowed) {
				t.Fatalf("error = %v, want not allowed", err)
			}
			assertTableCount(t, st.DB(), "situation_judgments", 0)
		})
	}
}

func TestSituationJudgmentExpirySurvivesRestartAndRemainsDue(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "judgment-restart.db")
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	sitID := judgmentSituationFixture(t, st, now)
	sit, _ := st.GetSituation(ctx, sitID)
	result, err := st.WriteSituationJudgment(ctx, audit.New(st.DB()), recordJudgmentRequest(sit, now, "restart-expiry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	view, err := reopened.GetCurrentSituationJudgment(ctx, sitID, result.Judgment.ValidUntil)
	if err != nil || view == nil || view.Applicability.Reason != model.JudgmentExpired || view.Applicability.Applicable {
		t.Fatalf("restarted view = %+v, %v", view, err)
	}
	due, err := reopened.ClaimDueSituations(ctx, "restart-worker", result.Judgment.ValidUntil, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, claimed := range due {
		if claimed.ID == sitID {
			found = hasDueReason(claimed.DueReasons, model.DueJudgmentBoundary)
		}
	}
	if !found {
		t.Fatalf("restarted expiry did not produce a due judgment boundary: %+v", due)
	}
}

func TestTerminalRecurrenceDoesNotInheritSituationJudgment(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	oldID := judgmentSituationFixture(t, st, now)
	old, _ := st.GetSituation(ctx, oldID)
	if _, err := st.WriteSituationJudgment(ctx, audit.New(st.DB()), recordJudgmentRequest(old, now, "old-episode")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing' WHERE id=?`, canonicalTime(now.Add(time.Hour)), oldID); err != nil {
		t.Fatal(err)
	}

	d := deliveryFixture("delivery-recurrence", "fp-recurrence", now.Add(2*time.Hour))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{d}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, "incident-recurrence", "input-recurrence", "instance=db-prod-1", d.ID, now.Add(2*time.Hour))
	claim := claimOneInput(t, st, "recurrence-worker", now.Add(2*time.Hour))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatal(err)
	}
	var recurrence model.Situation
	for _, sit := range listSituations(t, st) {
		if sit.ID != oldID {
			recurrence = sit
		}
	}
	if recurrence.ID == "" || recurrence.PreviousSituationID == nil || *recurrence.PreviousSituationID != oldID {
		t.Fatalf("recurrence = %+v", recurrence)
	}
	view, err := st.GetCurrentSituationJudgment(ctx, recurrence.ID, now.Add(2*time.Hour))
	if err != nil || view != nil {
		t.Fatalf("recurrence inherited judgment: %+v, %v", view, err)
	}
}
