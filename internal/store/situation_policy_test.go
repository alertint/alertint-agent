// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func testJudgmentSnapshot(situationID string, inputVersion int) situation.Snapshot {
	return situation.Snapshot{SituationID: situationID, InputVersion: inputVersion, MaterialHash: "sha256:test"}
}

func testJudgmentRequest(target string) situationmodel.JudgmentRequest {
	return situationmodel.JudgmentRequest{
		Situation: target, Judgment: situationmodel.JudgmentExpectedThisEpisode, Basis: situationmodel.JudgmentBasisOperatorKnowledge,
		OperatorConfirmed: true, ConfirmedBy: "alice",
	}
}

func testAuditEvents(kind string) []SituationPolicyAuditEvent {
	return []SituationPolicyAuditEvent{{Kind: kind, Payload: map[string]any{"ok": true}}}
}

func TestRecordJudgmentPersistsAndSchedulesOperatorJudgment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-1", "host=db-1", "", situationmodel.LifecycleActive, now)

	snap := testJudgmentSnapshot("s-judge-1", 1)
	j, err := s.RecordJudgment(ctx, snap, testJudgmentRequest("s-judge-1"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}
	if j.SituationID != "s-judge-1" || j.JudgedInputVersion != 1 || j.CoveredFactHash != "sha256:test" {
		t.Fatalf("judgment=%+v", j)
	}

	var storedJudgment string
	if err := s.DB().QueryRowContext(ctx, `SELECT judgment FROM situation_judgments WHERE id=?`, j.ID).Scan(&storedJudgment); err != nil {
		t.Fatal(err)
	}
	if storedJudgment != string(situationmodel.JudgmentExpectedThisEpisode) {
		t.Fatalf("stored judgment=%q", storedJudgment)
	}

	var dueReasonsJSON string
	if err := s.DB().QueryRowContext(ctx, `SELECT due_reasons_json FROM situations WHERE id=?`, "s-judge-1").Scan(&dueReasonsJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dueReasonsJSON, string(situationmodel.DueOperatorJudgment)) {
		t.Fatalf("due_reasons=%s, want operator_judgment", dueReasonsJSON)
	}

	report, err := auditor.Verify(ctx)
	if err != nil || !report.OK {
		t.Fatalf("audit chain broken: report=%+v err=%v", report, err)
	}
}

func TestRecordJudgmentValidUntilSchedulesJudgmentBoundary(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-2", "host=db-2", "", situationmodel.LifecycleActive, now)
	// Push next_assessment_at far out so recording the judgment's ValidUntil
	// must pull it back in, rather than trivially already being sooner.
	if _, err := s.DB().ExecContext(ctx, `UPDATE situations SET next_assessment_at=? WHERE id=?`, canonicalTime(now.Add(10*time.Hour)), "s-judge-2"); err != nil {
		t.Fatal(err)
	}

	validUntil := now.Add(2 * time.Hour)
	req := testJudgmentRequest("s-judge-2")
	req.ValidUntil = &validUntil
	if _, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-judge-2", 1), req, "slack:U1", now, auditor, testAuditEvents("judgment.recorded")); err != nil {
		t.Fatal(err)
	}

	var dueReasonsJSON, nextAssessmentAt string
	if err := s.DB().QueryRowContext(ctx, `SELECT due_reasons_json, next_assessment_at FROM situations WHERE id=?`, "s-judge-2").
		Scan(&dueReasonsJSON, &nextAssessmentAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dueReasonsJSON, string(situationmodel.DueJudgmentBoundary)) {
		t.Fatalf("due_reasons=%s, want judgment_boundary", dueReasonsJSON)
	}
	if nextAssessmentAt != canonicalTime(validUntil) {
		t.Fatalf("next_assessment_at=%s, want %s", nextAssessmentAt, canonicalTime(validUntil))
	}
}

func TestRecordJudgmentRejectsStaleInputVersionAndAudits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-3", "host=db-3", "", situationmodel.LifecycleActive, now)

	_, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-judge-3", 2), testJudgmentRequest("s-judge-3"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}

	var kind string
	if err := s.DB().QueryRowContext(ctx, `SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "judgment.rejected" {
		t.Fatalf("last audit kind=%q, want judgment.rejected", kind)
	}
	var judgmentCount int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_judgments`).Scan(&judgmentCount); err != nil {
		t.Fatal(err)
	}
	if judgmentCount != 0 {
		t.Fatalf("expected no judgment persisted after a rejected write, got %d", judgmentCount)
	}
}

func TestRecordJudgmentRejectsUnconfirmedRequest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-4", "host=db-4", "", situationmodel.LifecycleActive, now)

	req := testJudgmentRequest("s-judge-4")
	req.OperatorConfirmed = false
	if _, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-judge-4", 1), req, "slack:U1", now, auditor, testAuditEvents("judgment.recorded")); err == nil {
		t.Fatal("expected an error for an unconfirmed judgment request")
	}
}

func TestRecordJudgmentRejectsTerminalSituation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-5", "host=db-5", "", situationmodel.LifecycleClosedUnknown, now)

	if _, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-judge-5", 1), testJudgmentRequest("s-judge-5"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded")); err == nil {
		t.Fatal("expected an error recording a judgment against a terminal situation")
	}
}

func confirmTestEnvelope(t *testing.T, s *Store, ctx context.Context, auditor *audit.Auditor, situationID, groupKey string, now time.Time) (judgmentID string, envelopeID string) {
	t.Helper()
	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot(situationID, 1), testJudgmentRequest(situationID), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: j.ID, ExpectedCurrentVersion: 0,
		Scope:       situationmodel.EnvelopeScope{GroupKey: groupKey},
		Conditions:  situationmodel.EnvelopeConditions{RequiredCompanionSignals: []string{"database_lock"}},
		ReviewDueAt: now.Add(30 * 24 * time.Hour), OperatorConfirmed: true, ConfirmedBy: "alice",
	}
	v, err := s.ConfirmEnvelope(ctx, confirmation, "slack:U1", now, auditor, testAuditEvents("envelope.confirmed"))
	if err != nil {
		t.Fatal(err)
	}
	return j.ID, v.EnvelopeID
}

func TestConfirmEnvelopeCreatesActiveHead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-1", "host=db-1", "", situationmodel.LifecycleActive, now)

	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-1", "host=db-1", now)

	head, err := s.Envelope(ctx, envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	if head.CurrentVersion != 1 || head.Version == nil || head.Version.Status != situationmodel.EnvelopeStatusActive {
		t.Fatalf("head=%+v", head)
	}
	if head.Version.Scope.GroupKey != "host=db-1" {
		t.Fatalf("scope=%+v", head.Version.Scope)
	}
}

func TestConfirmEnvelopeRejectsDisjointCompanionViolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-2", "host=db-2", "", situationmodel.LifecycleActive, now)
	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-env-2", 1), testJudgmentRequest("s-env-2"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: j.ID, ExpectedCurrentVersion: 0, Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-2"},
		Conditions:  situationmodel.EnvelopeConditions{RequiredCompanionSignals: []string{"x"}, AllowedCompanionSignals: []string{"x"}},
		ReviewDueAt: now.Add(30 * 24 * time.Hour), OperatorConfirmed: true, ConfirmedBy: "alice",
	}
	if _, err := s.ConfirmEnvelope(ctx, confirmation, "slack:U1", now, auditor, testAuditEvents("envelope.confirmed")); err == nil {
		t.Fatal("expected disjoint required/allowed companion rejection")
	}
}

func TestConfirmEnvelopeRejectsStaleExpectedVersionAndAudits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-3", "host=db-3", "", situationmodel.LifecycleActive, now)
	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-env-3", 1), testJudgmentRequest("s-env-3"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: j.ID, ExpectedCurrentVersion: 1, // stale: no version has ever been confirmed yet
		Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-3"}, ReviewDueAt: now.Add(30 * 24 * time.Hour),
		OperatorConfirmed: true, ConfirmedBy: "alice",
	}
	if _, err := s.ConfirmEnvelope(ctx, confirmation, "slack:U1", now, auditor, testAuditEvents("envelope.confirmed")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}
	var kind string
	if err := s.DB().QueryRowContext(ctx, `SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "envelope.confirm.rejected" {
		t.Fatalf("last audit kind=%q, want envelope.confirm.rejected", kind)
	}
}

func TestRevokeEnvelopeAppendsRevokedVersionAndCarriesScopeForward(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-4", "host=db-4", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-4", "host=db-4", now)

	revocation := situationmodel.EnvelopeRevocation{EnvelopeID: envelopeID, ExpectedCurrentVersion: 1, Reason: "no longer applies", OperatorConfirmed: true, ConfirmedBy: "alice"}
	v, err := s.RevokeEnvelope(ctx, revocation, "slack:U1", now.Add(time.Hour), auditor, testAuditEvents("envelope.revoked"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 2 || v.Status != situationmodel.EnvelopeStatusRevoked || v.Reason == nil || *v.Reason != "no longer applies" {
		t.Fatalf("revoked version=%+v", v)
	}
	if v.Scope.GroupKey != "host=db-4" {
		t.Fatalf("expected scope to carry forward, got %+v", v.Scope)
	}

	head, err := s.Envelope(ctx, envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	if head.CurrentVersion != 2 || head.Version.Status != situationmodel.EnvelopeStatusRevoked {
		t.Fatalf("head=%+v", head)
	}
}

func TestRevokeEnvelopeSchedulesAffectedActiveSituations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-5", "host=db-5", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-5", "host=db-5", now)

	if err := s.AppendEnvelopeEvaluation(ctx, situationmodel.EnvelopeEvaluation{
		ID: "eval-1", EnvelopeID: envelopeID, EnvelopeVersion: 1, SituationID: "s-env-5", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, MatchedFields: []string{"required_companion_present:database_lock"},
		QuietingAuthority: false, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Push next_assessment_at far out so revocation must pull it back in,
	// rather than trivially already being sooner.
	if _, err := s.DB().ExecContext(ctx, `UPDATE situations SET next_assessment_at=? WHERE id=?`, canonicalTime(now.Add(10*time.Hour)), "s-env-5"); err != nil {
		t.Fatal(err)
	}

	revocation := situationmodel.EnvelopeRevocation{EnvelopeID: envelopeID, ExpectedCurrentVersion: 1, Reason: "changed policy", OperatorConfirmed: true, ConfirmedBy: "alice"}
	revokeAt := now.Add(time.Hour)
	if _, err := s.RevokeEnvelope(ctx, revocation, "slack:U1", revokeAt, auditor, testAuditEvents("envelope.revoked")); err != nil {
		t.Fatal(err)
	}

	var dueReasonsJSON, nextAssessmentAt string
	if err := s.DB().QueryRowContext(ctx, `SELECT due_reasons_json, next_assessment_at FROM situations WHERE id=?`, "s-env-5").
		Scan(&dueReasonsJSON, &nextAssessmentAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dueReasonsJSON, string(situationmodel.DueEnvelopeChanged)) {
		t.Fatalf("due_reasons=%s, want envelope_changed", dueReasonsJSON)
	}
	if nextAssessmentAt != canonicalTime(revokeAt) {
		t.Fatalf("next_assessment_at=%s, want %s", nextAssessmentAt, canonicalTime(revokeAt))
	}
}

func TestAppendEnvelopeVersionRequiresExistingHead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	v := situationmodel.EnvelopeVersion{
		EnvelopeID: "does-not-exist", Status: situationmodel.EnvelopeStatusActive, Scope: situationmodel.EnvelopeScope{GroupKey: "host=x"},
		ReviewDueAt: time.Now().UTC().Add(time.Hour), AuthenticatedAs: "slack:U1", AssertedOperator: "alice", CreatedAt: time.Now().UTC(),
	}
	if err := s.AppendEnvelopeVersion(ctx, 0, v); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err=%v, want not found", err)
	}
}

func TestAppendEnvelopeVersionInvalidatesForTriggerChange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-6", "host=db-6", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-6", "host=db-6", now)

	invalidated := situationmodel.EnvelopeVersion{
		EnvelopeID: envelopeID, Status: situationmodel.EnvelopeStatusInvalidated, Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-6"},
		Conditions:  situationmodel.EnvelopeConditions{RequiredCompanionSignals: []string{"database_lock"}},
		ReviewDueAt: now.Add(30 * 24 * time.Hour), AuthenticatedAs: "system:trigger-watch", AssertedOperator: "system", CreatedAt: now,
	}
	if err := s.AppendEnvelopeVersion(ctx, 1, invalidated); err != nil {
		t.Fatal(err)
	}
	head, err := s.Envelope(ctx, envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	if head.CurrentVersion != 2 || head.Version.Status != situationmodel.EnvelopeStatusInvalidated {
		t.Fatalf("head=%+v", head)
	}
	got := situation.EvaluateEnvelope(*head.Version, situation.EnvelopeFacts{})
	if got.Result != situationmodel.EnvelopeEvaluationNotApplicable {
		t.Fatalf("evaluation of an invalidated version=%s, want not_applicable", got.Result)
	}
}

func TestAppendEnvelopeEvaluationIsIdempotentAndFailsClosedOnCollision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-8", "host=db-8", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-8", "host=db-8", now)
	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-x", EnvelopeID: envelopeID, EnvelopeVersion: 1, SituationID: "s-env-8", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, MatchedFields: []string{"a"}, QuietingAuthority: false, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err != nil {
		t.Fatalf("exact replay should succeed: %v", err)
	}
	changed := e
	changed.Result = situationmodel.EnvelopeEvaluationViolation
	if err := s.AppendEnvelopeEvaluation(ctx, changed); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("changed replay err=%v, want collision", err)
	}
}

func TestAppendEnvelopeEvaluationRejectsQuietingAuthorityWithoutMatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-y", EnvelopeID: "env-y", EnvelopeVersion: 1, SituationID: "sit-y", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationViolation, QuietingAuthority: true, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err == nil {
		t.Fatal("expected an error for quieting authority on a non-match evaluation")
	}
}

func TestDueEnvelopeReviewsOnePerInterval(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-7", "host=db-7", "", situationmodel.LifecycleActive, now)
	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-env-7", 1), testJudgmentRequest("s-env-7"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: j.ID, ExpectedCurrentVersion: 0, Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-7"},
		ReviewDueAt:       now.Add(-time.Hour), // already due
		OperatorConfirmed: true, ConfirmedBy: "alice",
	}
	v, err := s.ConfirmEnvelope(ctx, confirmation, "slack:U1", now, auditor, testAuditEvents("envelope.confirmed"))
	if err != nil {
		t.Fatal(err)
	}
	interval := 30 * 24 * time.Hour

	due, err := s.DueEnvelopeReviews(ctx, now, interval, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != v.EnvelopeID {
		t.Fatalf("due=%+v", due)
	}

	if err := s.MarkEnvelopeReviewPrompted(ctx, v.EnvelopeID, now); err != nil {
		t.Fatal(err)
	}
	stillWithinInterval, err := s.DueEnvelopeReviews(ctx, now.Add(time.Hour), interval, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stillWithinInterval) != 0 {
		t.Fatalf("expected no reminder within one interval of the last prompt, got %+v", stillWithinInterval)
	}

	afterInterval, err := s.DueEnvelopeReviews(ctx, now.Add(interval+time.Second), interval, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterInterval) != 1 {
		t.Fatalf("expected one reminder after a full interval elapsed, got %+v", afterInterval)
	}
}

func TestRecordSituationJudgmentLowLevelPrimitive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-low-1", "host=db-low", "", situationmodel.LifecycleActive, now)
	j := situationmodel.Judgment{
		ID: "j-low-1", SituationID: "s-low-1", JudgedInputVersion: 1, CoveredFactHash: "sha256:low",
		CoveredSymptoms: []string{}, CoveredImpact: []string{}, Judgment: situationmodel.JudgmentInconclusive,
		Basis: situationmodel.JudgmentBasisAlertintEvidence, EvidenceRefs: []string{}, AuthenticatedAs: "slack:U1",
		AssertedOperator: "alice", CreatedAt: now,
	}
	if err := s.RecordSituationJudgment(ctx, j); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_judgments WHERE id=?`, j.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
}

func lastAuditPayload(t *testing.T, s *Store) map[string]any {
	t.Helper()
	var payloadJSON string
	if err := s.DB().QueryRow(`SELECT payload_json FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&payloadJSON); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestRejectedJudgmentAuditCarriesAttribution covers review finding #2: a
// rejected optimistic write must be audited with both the authenticated
// trust domain and the asserted operator, not just the version conflict.
func TestRejectedJudgmentAuditCarriesAttribution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-judge-attr", "host=db-attr", "", situationmodel.LifecycleActive, now)

	req := testJudgmentRequest("s-judge-attr")
	req.ConfirmedBy = "janis"
	_, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-judge-attr", 2), req, "slack:U-janis", now, auditor, testAuditEvents("judgment.recorded"))
	if !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}
	payload := lastAuditPayload(t, s)
	if payload["authenticated_as"] != "slack:U-janis" || payload["asserted_operator"] != "janis" {
		t.Fatalf("rejected judgment audit payload=%+v, missing attribution", payload)
	}
}

// TestRejectedEnvelopeConfirmAuditCarriesAttribution covers review finding
// #2 for ConfirmEnvelope's head-resolution rejection path, exercised once
// against an unknown source judgment (no head exists yet) and once against
// an existing head at a stale version — both go through the same
// resolveOrCreateEnvelopeHeadTx rejection and both must carry attribution.
// (appendEnvelopeVersionTx's own defense-in-depth version check is not
// independently reachable here: within one transaction on this
// single-connection store, it always observes the same current_version
// resolveOrCreateEnvelopeHeadTx already validated.)
func TestRejectedEnvelopeConfirmAuditCarriesAttribution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-attr", "host=db-attr2", "", situationmodel.LifecycleActive, now)
	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-env-attr", 1), testJudgmentRequest("s-env-attr"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}

	confirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: j.ID, ExpectedCurrentVersion: 1, // stale: no version has ever been confirmed yet
		Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-attr2"}, ReviewDueAt: now.Add(30 * 24 * time.Hour),
		OperatorConfirmed: true, ConfirmedBy: "janis",
	}
	if _, err := s.ConfirmEnvelope(ctx, confirmation, "slack:U-janis", now, auditor, testAuditEvents("envelope.confirmed")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}
	payload := lastAuditPayload(t, s)
	if payload["authenticated_as"] != "slack:U-janis" || payload["asserted_operator"] != "janis" {
		t.Fatalf("rejected envelope confirm (head resolve) audit payload=%+v, missing attribution", payload)
	}

	// Now an existing head at a stale expected version.
	secondJudgmentID, _ := confirmTestEnvelope(t, s, ctx, auditor, "s-env-attr", "host=db-attr2-second", now)
	secondConfirmation := situationmodel.EnvelopeConfirmation{
		SourceJudgmentID: secondJudgmentID, ExpectedCurrentVersion: 0, // stale: head is already at version 1
		Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-attr2-second"}, ReviewDueAt: now.Add(30 * 24 * time.Hour),
		OperatorConfirmed: true, ConfirmedBy: "janis",
	}
	if _, err := s.ConfirmEnvelope(ctx, secondConfirmation, "slack:U-janis", now, auditor, testAuditEvents("envelope.confirmed")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}
	payload = lastAuditPayload(t, s)
	if payload["authenticated_as"] != "slack:U-janis" || payload["asserted_operator"] != "janis" || payload["source_judgment_id"] != secondJudgmentID {
		t.Fatalf("rejected envelope confirm (existing head, stale version) audit payload=%+v, missing attribution", payload)
	}
}

// TestRejectedEnvelopeRevokeAuditCarriesAttribution covers review finding
// #2 for RevokeEnvelope's rejection branch.
func TestRejectedEnvelopeRevokeAuditCarriesAttribution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-attr3", "host=db-attr3", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-attr3", "host=db-attr3", now)

	revocation := situationmodel.EnvelopeRevocation{EnvelopeID: envelopeID, ExpectedCurrentVersion: 99, Reason: "stale", OperatorConfirmed: true, ConfirmedBy: "janis"}
	if _, err := s.RevokeEnvelope(ctx, revocation, "slack:U-janis", now, auditor, testAuditEvents("envelope.revoked")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v, want version conflict", err)
	}
	payload := lastAuditPayload(t, s)
	if payload["authenticated_as"] != "slack:U-janis" || payload["asserted_operator"] != "janis" {
		t.Fatalf("rejected envelope revoke audit payload=%+v, missing attribution", payload)
	}
}

// TestAppendEnvelopeVersionWithAuditWritesAtomically covers review finding
// #3: the invalidation path (a system-driven AppendEnvelopeVersion call,
// unlike the operator-driven RecordJudgment/ConfirmEnvelope/RevokeEnvelope)
// must support atomic audit too.
func TestAppendEnvelopeVersionWithAuditWritesAtomically(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-audit1", "host=db-audit1", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-audit1", "host=db-audit1", now)

	if err := s.AppendEnvelopeVersionWithAudit(ctx, 1, situationmodel.EnvelopeVersion{}, nil, nil); err == nil {
		t.Fatal("expected an error when no auditor/events are supplied")
	}

	invalidated := situationmodel.EnvelopeVersion{
		EnvelopeID: envelopeID, Status: situationmodel.EnvelopeStatusInvalidated, Scope: situationmodel.EnvelopeScope{GroupKey: "host=db-audit1"},
		Conditions:  situationmodel.EnvelopeConditions{RequiredCompanionSignals: []string{"database_lock"}},
		ReviewDueAt: now.Add(30 * 24 * time.Hour), AuthenticatedAs: "system:trigger-watch", AssertedOperator: "system", CreatedAt: now,
	}
	if err := s.AppendEnvelopeVersionWithAudit(ctx, 1, invalidated, auditor, []SituationPolicyAuditEvent{{Kind: "envelope.invalidated", Payload: map[string]any{"envelope_id": envelopeID}}}); err != nil {
		t.Fatal(err)
	}
	var kind string
	if err := s.DB().QueryRowContext(ctx, `SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "envelope.invalidated" {
		t.Fatalf("last audit kind=%q, want envelope.invalidated", kind)
	}
	report, err := auditor.Verify(ctx)
	if err != nil || !report.OK {
		t.Fatalf("audit chain broken: report=%+v err=%v", report, err)
	}
}

// TestAppendEnvelopeEvaluationWithAuditWritesAtomically covers review
// finding #3 for AppendEnvelopeEvaluation.
func TestAppendEnvelopeEvaluationWithAuditWritesAtomically(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-audit2", "host=db-audit2", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-audit2", "host=db-audit2", now)

	if err := s.AppendEnvelopeEvaluationWithAudit(ctx, situationmodel.EnvelopeEvaluation{}, nil, nil); err == nil {
		t.Fatal("expected an error when no auditor/events are supplied")
	}

	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-audit", EnvelopeID: envelopeID, EnvelopeVersion: 1, SituationID: "s-env-audit2", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, MatchedFields: []string{"required_companion_present:database_lock"}, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluationWithAudit(ctx, e, auditor, []SituationPolicyAuditEvent{{Kind: "envelope.evaluated", Payload: map[string]any{"envelope_id": envelopeID}}}); err != nil {
		t.Fatal(err)
	}
	var kind string
	if err := s.DB().QueryRowContext(ctx, `SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "envelope.evaluated" {
		t.Fatalf("last audit kind=%q, want envelope.evaluated", kind)
	}
}

// TestAppendEnvelopeEvaluationPersistsResolvedScheduleWindow covers review
// finding #1 at the persistence layer: the resolved UTC schedule interval
// EvaluateEnvelope computes must round-trip through the store.
func TestAppendEnvelopeEvaluationPersistsResolvedScheduleWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-env-window", "host=db-window", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-env-window", "host=db-window", now)

	start := mustSituationTime(t, "2026-10-24T22:30:00Z")
	end := mustSituationTime(t, "2026-10-25T01:30:00Z")
	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-window", EnvelopeID: envelopeID, EnvelopeVersion: 1, SituationID: "s-env-window", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, MatchedFields: []string{"schedule_within_window"},
		ScheduleWindowStart: &start, ScheduleWindowEnd: &end, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err != nil {
		t.Fatal(err)
	}
	var startStr, endStr string
	if err := s.DB().QueryRowContext(ctx, `SELECT schedule_window_start, schedule_window_end FROM envelope_evaluations WHERE id=?`, "eval-window").
		Scan(&startStr, &endStr); err != nil {
		t.Fatal(err)
	}
	if startStr != canonicalTime(start) || endStr != canonicalTime(end) {
		t.Fatalf("persisted window=%s..%s want=%s..%s", startStr, endStr, canonicalTime(start), canonicalTime(end))
	}

	// Exact replay with the same window succeeds; a changed window is a collision.
	if err := s.AppendEnvelopeEvaluation(ctx, e); err != nil {
		t.Fatalf("exact replay should succeed: %v", err)
	}
	changed := e
	laterEnd := end.Add(time.Hour)
	changed.ScheduleWindowEnd = &laterEnd
	if err := s.AppendEnvelopeEvaluation(ctx, changed); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("changed window replay err=%v, want collision", err)
	}
}

func TestAppendEnvelopeEvaluationRejectsMismatchedScheduleWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	start := now
	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-mismatch", EnvelopeID: "env-x", EnvelopeVersion: 1, SituationID: "sit-x", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, ScheduleWindowStart: &start, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err == nil {
		t.Fatal("expected an error for a schedule window with only a start")
	}
}
