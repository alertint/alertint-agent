// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation"

	"github.com/alertint/alertint-agent/internal/store/storetest"
)

// ----------------------------------------------------------------------
// Fixtures.
// ----------------------------------------------------------------------

// triageFixture is one fully-wired ready Incident (with one real member
// delivery), its owning Situation, and the CURRENT digests a real claim
// would compute for it — everything triage_controller_test.go's methods
// need without going through the not-yet-wired controller decision path.
type triageFixture struct {
	IncidentID          string
	SituationID         string
	GroupKey            string
	DeliveryID          string
	MembershipDigest    string
	IncidentInputDigest string
}

// newTriageFixture inserts one delivery, an Incident owning it, transitions
// the Incident to ready (plain MarkIncidentReady — this task's tests build
// their own incident_triage rows directly rather than depending on
// MarkIncidentReadyWithSituationInput's own coverage, which
// deliveries_test.go/triage_test.go already exercise), and attaches the
// Incident to a real Situation via the existing ApplySituationInput round
// trip so incident_triage.situation_id's FK has somewhere real to point.
func newTriageFixture(t *testing.T, st *Store, groupKey string, now time.Time) triageFixture {
	t.Helper()
	ctx := context.Background()

	fp := "fp-" + groupKey
	dels, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-"+groupKey, fp, now)})
	if err != nil || len(dels) != 1 {
		t.Fatalf("accept delivery: %v (%d)", err, len(dels))
	}
	delivery := dels[0]

	incidentID := "inc-" + groupKey
	if err := st.InsertIncident(ctx, Incident{
		ID: incidentID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incidentID, delivery.ID, canonicalTime(now)); err != nil {
		t.Fatalf("link delivery: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	// Attach to a real Situation via the existing membership_changed +
	// ApplySituationInput round trip (situations_test.go machinery).
	inputID := "input-" + groupKey
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'membership_changed', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, delivery.ID, groupKey, canonicalTime(now)); err != nil {
		t.Fatalf("insert situation input: %v", err)
	}
	claim := claimOneInput(t, st, "seed:"+groupKey, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	var situationID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&situationID); err != nil {
		t.Fatalf("find situation: %v", err)
	}

	// Compute the expected digests through the exact same store-internal
	// path ClaimIncidentTriageAttempt/CompleteIncidentTriageAttempt use
	// (incidentDigestsTx), rather than reconstructing a situation.Delivery
	// by hand here — the store reads several immutable columns (status,
	// started_at_basis, resolved_at_basis, source times) this fixture would
	// otherwise have to duplicate exactly to avoid a spurious digest
	// mismatch.
	membership, incidentInput := digestsForTest(t, st, incidentID)

	return triageFixture{
		IncidentID: incidentID, SituationID: situationID, GroupKey: groupKey, DeliveryID: delivery.ID,
		MembershipDigest: membership, IncidentInputDigest: incidentInput,
	}
}

// digestsForTest recomputes incidentID's current membership/Incident-input
// digests through the store's own incidentDigestsTx, inside a throwaway
// read-only transaction — the single source of truth every fixture in this
// file compares against.
func digestsForTest(t *testing.T, st *Store, incidentID string) (membership, incidentInput string) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	membership, incidentInput, err = incidentDigestsTx(ctx, tx, incidentID)
	if err != nil {
		t.Fatalf("incident digests: %v", err)
	}
	return membership, incidentInput
}

// seedAwaitingDecisionRow inserts the incident_triage row directly at
// awaiting_decision, attempt zero — the exact shape
// MarkIncidentReadyWithSituationInput now creates atomically (this file's
// own tests exercise the decision/claim/completion methods in isolation
// from that call site, which deliveries_test.go covers separately).
func seedAwaitingDecisionRow(t *testing.T, st *Store, incidentID string, now time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at) VALUES (?, 'awaiting_decision', 0, ?)`,
		incidentID, canonicalTime(now)); err != nil {
		t.Fatalf("seed awaiting_decision row: %v", err)
	}
}

// requestDecisionFor builds a Decision=request TriageDecision for f, ready
// to hand to applyTriageDecisionsTx directly (this task's brief: applyTriageDecisionsTx
// is tested directly against its own transaction, not through DecideTriage).
func requestDecisionFor(f triageFixture, reason string, now time.Time) situation.TriageDecision {
	return situation.TriageDecision{
		IncidentID: f.IncidentID, Decision: situation.TriageDecisionRequest, DecisionReason: reason,
		SituationID: f.SituationID, SituationInputVersion: 1,
		MaterialFactHash: "sha256:material-" + f.GroupKey,
		MembershipDigest: f.MembershipDigest, IncidentInputDigest: f.IncidentInputDigest,
		DecidedAt: now,
	}
}

// insertMinimalAuthoritativeAssessment inserts a valid, minimal authoritative
// situation_assessment_attempts row (deterministic_controller derivation, no
// backing call) so a skip decision's assessment_id FK has somewhere real to
// point — this file tests the store-level decision-commit write, not
// Assessment content, so the row's own semantic content is deliberately
// bare-minimum-valid rather than realistic.
func insertMinimalAuthoritativeAssessment(t *testing.T, st *Store, situationID string) string {
	t.Helper()
	id := uuid.NewString()
	now := canonicalTime(time.Now())
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts
			(id, situation_id, sequence, input_version, work_attempt, status, derivation,
			 provider_request_started, material_fact_hash, assessment_json, created_at, completed_at)
		VALUES (?, ?, 1, 1, 1, 'authoritative', 'deterministic_controller', 'false', 'sha256:test-basis', '{}', ?, ?)`,
		id, situationID, now, now); err != nil {
		t.Fatalf("insert minimal authoritative assessment: %v", err)
	}
	return id
}

func skipDecisionFor(f triageFixture, coveredAssessmentID string, now time.Time) situation.TriageDecision {
	return situation.TriageDecision{
		IncidentID: f.IncidentID, Decision: situation.TriageDecisionSkip, DecisionReason: situation.DecisionReasonCleanSkip,
		SituationID: f.SituationID, SituationInputVersion: 1, CoveredAssessmentID: &coveredAssessmentID,
		MaterialFactHash: "sha256:material-" + f.GroupKey,
		MembershipDigest: f.MembershipDigest, IncidentInputDigest: f.IncidentInputDigest,
		DecidedAt: now,
	}
}

// decideAndApplyRequest is the fixture-setup shortcut most claim/completion
// tests need: seed awaiting_decision, apply a real "request" decision inside
// its own transaction (mirroring exactly what applyTriageDecisionsTx's own
// tests verify in isolation), and return f unchanged for convenience.
func decideAndApplyRequest(t *testing.T, st *Store, f triageFixture, now time.Time) {
	t.Helper()
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)
	applyDecisionsTx(t, st, []situation.TriageDecision{requestDecisionFor(f, "test_fixture", now)}, now)
}

// applyDecisionsTx runs applyTriageDecisionsTx inside its own committed
// transaction — the pattern this task's brief calls out explicitly: "an
// unexported function can still be tested from _test.go files in the same
// package".
func applyDecisionsTx(t *testing.T, st *Store, decisions []situation.TriageDecision, now time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := applyTriageDecisionsTx(ctx, tx, decisions, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply triage decisions: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// triageRowSnapshot is incident_triage's decision/lease-relevant columns, as
// read directly by triageRow — a plain struct (rather than a long
// positional multi-value return) so each assertion below names only the
// fields it actually cares about.
type triageRowSnapshot struct {
	Phase                                 string
	Attempts                              int
	SituationID, Decision, DecisionOrigin sql.NullString
	DecisionInputVersion                  sql.NullInt64
	MembershipDigest, IncidentInputDigest sql.NullString
	LeaseOwner, CurrentAttemptID          sql.NullString
}

func triageRow(t *testing.T, st *Store, incidentID string) triageRowSnapshot {
	t.Helper()
	var r triageRowSnapshot
	err := st.db.QueryRowContext(context.Background(), `
		SELECT phase, attempts, situation_id, decision, decision_origin, decision_input_version,
		       membership_digest, incident_input_digest, lease_owner, current_attempt_id
		FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(
		&r.Phase, &r.Attempts, &r.SituationID, &r.Decision, &r.DecisionOrigin, &r.DecisionInputVersion,
		&r.MembershipDigest, &r.IncidentInputDigest, &r.LeaseOwner, &r.CurrentAttemptID)
	if err != nil {
		t.Fatalf("read triage row: %v", err)
	}
	return r
}

func countSituationInputs(t *testing.T, st *Store, incidentID, kind string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id = ? AND kind = ?`, incidentID, kind).Scan(&n); err != nil {
		t.Fatalf("count situation inputs: %v", err)
	}
	return n
}

func incidentStatus(t *testing.T, st *Store, incidentID string) string {
	t.Helper()
	got, err := st.GetIncidentByID(context.Background(), incidentID)
	if err != nil || got == nil {
		t.Fatalf("get incident: %v, %v", got, err)
	}
	return got.Status
}

// ----------------------------------------------------------------------
// applyTriageDecisionsTx / "TestRequestTriage*": committing request/skip
// decisions.
// ----------------------------------------------------------------------

func TestRequestTriageMovesAwaitingDecisionToPendingWithoutConsumingAttemptOrSituationInput(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "req-basic", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)

	applyDecisionsTx(t, st, []situation.TriageDecision{requestDecisionFor(f, "no_trustworthy_assessment", now)}, now)

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "pending" || tr.Attempts != 0 {
		t.Fatalf("phase=%q attempts=%d, want pending/0 (request preserves attempt zero)", tr.Phase, tr.Attempts)
	}
	if !tr.SituationID.Valid || tr.SituationID.String != f.SituationID {
		t.Fatalf("situation_id = %v, want %q", tr.SituationID, f.SituationID)
	}
	if !tr.Decision.Valid || tr.Decision.String != "request" {
		t.Fatalf("decision = %v, want request", tr.Decision)
	}
	if !tr.DecisionOrigin.Valid || tr.DecisionOrigin.String != "controller_decision" {
		t.Fatalf("decision_origin = %v, want controller_decision", tr.DecisionOrigin)
	}
	if !tr.DecisionInputVersion.Valid || tr.DecisionInputVersion.Int64 != 1 {
		t.Fatalf("decision_input_version = %v, want 1", tr.DecisionInputVersion)
	}
	if !tr.MembershipDigest.Valid || tr.MembershipDigest.String != f.MembershipDigest {
		t.Fatalf("membership_digest = %v, want %q", tr.MembershipDigest, f.MembershipDigest)
	}
	if !tr.IncidentInputDigest.Valid || tr.IncidentInputDigest.String != f.IncidentInputDigest {
		t.Fatalf("incident_input_digest = %v, want %q", tr.IncidentInputDigest, f.IncidentInputDigest)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_retry_changed"); n != 0 {
		t.Fatalf("triage_retry_changed inputs after a bare request decision = %d, want 0 (only beginning an attempt appends it)", n)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status = %q, want ready", got)
	}
}

func TestRequestTriageRefreshDoesNotMovePhaseAttemptsOrNextAt(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "req-refresh", now)
	decideAndApplyRequest(t, st, f, now)

	staleNext := now.Add(90 * time.Second)
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE incident_triage SET next_at = ? WHERE incident_id = ?`, canonicalTime(staleNext), f.IncidentID); err != nil {
		t.Fatalf("seed next_at: %v", err)
	}

	refresh := requestDecisionFor(f, situation.DecisionReasonMembershipOrInputRefresh, now.Add(time.Minute))
	refresh.MembershipDigest = "sha256:newer-membership"
	applyDecisionsTx(t, st, []situation.TriageDecision{refresh}, now.Add(time.Minute))

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "pending" || tr.Attempts != 0 {
		t.Fatalf("phase=%q attempts=%d, want pending/0 unchanged by a refresh", tr.Phase, tr.Attempts)
	}
	var nextAtStr sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `SELECT next_at FROM incident_triage WHERE incident_id = ?`, f.IncidentID).Scan(&nextAtStr); err != nil {
		t.Fatal(err)
	}
	if !nextAtStr.Valid {
		t.Fatal("next_at cleared by a refresh, want unchanged")
	}
	got, err := time.Parse(time.RFC3339Nano, nextAtStr.String)
	if err != nil || !got.Equal(staleNext) {
		t.Fatalf("next_at = %v (%v), want unchanged %v (a refresh never moves due time earlier)", got, err, staleNext)
	}
	if tr.MembershipDigest.String != "sha256:newer-membership" {
		t.Fatalf("membership_digest = %q, want the refreshed value", tr.MembershipDigest.String)
	}
}

func TestSkipTriageMovesAwaitingDecisionToSkippedAndAppendsOneTriageSkippedInput(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "skip-basic", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)
	assessmentID := insertMinimalAuthoritativeAssessment(t, st, f.SituationID)

	applyDecisionsTx(t, st, []situation.TriageDecision{skipDecisionFor(f, assessmentID, now)}, now)

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "skipped" {
		t.Fatalf("phase = %q, want skipped", tr.Phase)
	}
	if tr.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0 (a clean skip consumes zero attempt)", tr.Attempts)
	}
	if !tr.Decision.Valid || tr.Decision.String != "skip" {
		t.Fatalf("decision = %v, want skip", tr.Decision)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status after clean skip = %q, want ready (a clean skip is a judgment, not a dispatch)", got)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs = %d, want exactly 1", n)
	}
}

func TestSkipTriageIdempotentReplayAppendsNoDuplicateInput(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "skip-idem", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)
	assessmentID := insertMinimalAuthoritativeAssessment(t, st, f.SituationID)
	decision := skipDecisionFor(f, assessmentID, now)

	applyDecisionsTx(t, st, []situation.TriageDecision{decision}, now)
	// A replay against the now-'skipped' row must not error and must not
	// duplicate the input — applyOneTriageDecisionTx's own phase guard
	// (phase == 'awaiting_decision') makes the second UPDATE affect zero
	// rows, which this function treats as "raced away", not an error.
	applyDecisionsTx(t, st, []situation.TriageDecision{decision}, now)

	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs after replay = %d, want exactly 1", n)
	}
}

func TestApplyTriageDecisionSilentlyDropsWhenRowNoLongerDecidable(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "req-raced", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE incident_triage SET phase = 'skipped' WHERE incident_id = ?`, f.IncidentID); err != nil {
		t.Fatal(err)
	}

	applyDecisionsTx(t, st, []situation.TriageDecision{requestDecisionFor(f, "no_trustworthy_assessment", now)}, now)

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "skipped" {
		t.Fatalf("phase = %q, want skipped (unchanged — a stale decision must never corrupt state a different path already owns)", tr.Phase)
	}
}

// ----------------------------------------------------------------------
// ClaimIncidentTriageAttempt / "TestClaimDueIncidentTriage*".
// ----------------------------------------------------------------------

func TestClaimDueIncidentTriageOnlyClaimsPendingOrBackoffNeverAwaitingDecision(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-gate", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)

	if _, err := st.ClaimIncidentTriageAttempt(context.Background(), f.IncidentID, "worker-1", now, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim against awaiting_decision = %v, want ErrNotFound", err)
	}
}

func TestClaimDueIncidentTriageRequiresADecidedRow(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-undecided", now)
	// A pending row seeded the OLD way (SeedIncidentTriage), never touched
	// by applyTriageDecisionsTx, carries no situation_id/decision_input_version.
	if err := storetest.SeedIncidentTriage(context.Background(), st.db, f.IncidentID, now); err != nil {
		t.Fatal(err)
	}

	if _, err := st.ClaimIncidentTriageAttempt(context.Background(), f.IncidentID, "worker-1", now, time.Minute); !errors.Is(err, ErrTriageNotDecided) {
		t.Fatalf("claim against an undecided pending row = %v, want ErrTriageNotDecided", err)
	}
}

func TestClaimDueIncidentTriageFreezesDigestsMemberDeliveryIDsAndLeasesSchedule(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-freeze", now)
	decideAndApplyRequest(t, st, f, now)

	claimAt := now.Add(time.Minute)
	got, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", claimAt, 30*time.Second)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got.AttemptNumber != 1 {
		t.Fatalf("AttemptNumber = %d, want 1", got.AttemptNumber)
	}
	if got.MembershipDigest != f.MembershipDigest || got.IncidentInputDigest != f.IncidentInputDigest {
		t.Fatalf("claimed digests = %+v, want fixture's %s/%s", got, f.MembershipDigest, f.IncidentInputDigest)
	}
	if len(got.MemberDeliveryIDs) != 1 || got.MemberDeliveryIDs[0] != f.DeliveryID {
		t.Fatalf("MemberDeliveryIDs = %v, want [%s]", got.MemberDeliveryIDs, f.DeliveryID)
	}
	if got.LeaseOwner != "worker-1" || !got.LeaseExpiresAt.Equal(claimAt.Add(30*time.Second)) {
		t.Fatalf("lease = %+v", got)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "in_flight" || tr.Attempts != 1 {
		t.Fatalf("phase=%q attempts=%d, want in_flight/1", tr.Phase, tr.Attempts)
	}
	if !tr.LeaseOwner.Valid || tr.LeaseOwner.String != "worker-1" {
		t.Fatalf("lease_owner = %v, want worker-1", tr.LeaseOwner)
	}
	if !tr.CurrentAttemptID.Valid || tr.CurrentAttemptID.String != got.AttemptID {
		t.Fatalf("current_attempt_id = %v, want %q", tr.CurrentAttemptID, got.AttemptID)
	}
	if gotStatus := incidentStatus(t, st, f.IncidentID); gotStatus != "processing" {
		t.Fatalf("incident status = %q, want processing", gotStatus)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_retry_changed"); n != 1 {
		t.Fatalf("triage_retry_changed inputs after claim = %d, want exactly 1", n)
	}

	// The attempt ledger row itself carries the frozen identity.
	var incID, memberIDsJSON string
	var attemptNumber int
	if err := st.db.QueryRowContext(ctx, `
		SELECT incident_id, attempt_number, member_delivery_ids_json FROM incident_triage_attempts WHERE id = ?`, got.AttemptID).
		Scan(&incID, &attemptNumber, &memberIDsJSON); err != nil {
		t.Fatal(err)
	}
	if incID != f.IncidentID || attemptNumber != 1 {
		t.Fatalf("attempt row identity = %s/%d", incID, attemptNumber)
	}
}

func TestClaimDueIncidentTriageSecondClaimFailsWhileInFlight(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-twice", now)
	decideAndApplyRequest(t, st, f, now)

	if _, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", now, time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-2", now, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim while in_flight = %v, want ErrNotFound", err)
	}
}

// TestClaimDueIncidentTriageBackoffRowNotYetDueFailsWithErrTriageNotDue pins
// the claim boundary's due-gate: a backoff row whose next_at has not
// arrived is claimable-shaped (decided, pending/backoff phase) but must
// still be refused, distinctly from ErrNotFound/ErrTriageNotDecided.
func TestClaimDueIncidentTriageBackoffRowNotYetDueFailsWithErrTriageNotDue(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-not-due", now)
	claim := mustClaim(t, st, f, now)

	nextAt := now.Add(time.Hour)
	if err := st.BackoffIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, nextAt, "timeout", "deadline exceeded", now.Add(time.Minute)); err != nil {
		t.Fatalf("backoff: %v", err)
	}

	if _, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-2", nextAt.Add(-time.Second), time.Minute); !errors.Is(err, ErrTriageNotDue) {
		t.Fatalf("claim one second before next_at = %v, want ErrTriageNotDue", err)
	}

	// The refused claim must not have disturbed the schedule at all.
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "backoff" {
		t.Fatalf("phase after refused claim = %q, want backoff (untouched)", tr.Phase)
	}
}

// TestClaimDueIncidentTriageBackoffRowDueClaimsSuccessfully is the positive
// control for the above: the identical row, claimed at (not before) its own
// next_at, succeeds and consumes the next attempt slot.
func TestClaimDueIncidentTriageBackoffRowDueClaimsSuccessfully(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "claim-due", now)
	claim := mustClaim(t, st, f, now)

	nextAt := now.Add(time.Hour)
	if err := st.BackoffIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, nextAt, "timeout", "deadline exceeded", now.Add(time.Minute)); err != nil {
		t.Fatalf("backoff: %v", err)
	}

	got, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-2", nextAt, time.Minute)
	if err != nil {
		t.Fatalf("claim exactly at next_at: %v", err)
	}
	if got.AttemptNumber != 2 {
		t.Fatalf("AttemptNumber = %d, want 2", got.AttemptNumber)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "in_flight" || tr.Attempts != 2 {
		t.Fatalf("phase=%q attempts=%d, want in_flight/2", tr.Phase, tr.Attempts)
	}
}

// ----------------------------------------------------------------------
// CompleteIncidentTriageAttempt / "TestCompleteIncidentTriageAttempt*".
// ----------------------------------------------------------------------

func mustClaim(t *testing.T, st *Store, f triageFixture, now time.Time) ClaimedTriageAttempt {
	t.Helper()
	decideAndApplyRequest(t, st, f, now)
	got, err := st.ClaimIncidentTriageAttempt(context.Background(), f.IncidentID, "worker-1", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return got
}

func sampleFinding() TriageFinding {
	return TriageFinding{
		OutputJSON: `{"ok":true}`, Summary: "name", RootCause: "issue", Confidence: 0.7,
		EnrichmentJSON: "", EvidencePackDigest: "sha256:evidence-1",
	}
}

func TestCompleteIncidentTriageAttemptSuccessPersistsFindingAndClosesSchedule(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "complete-success", now)
	claim := mustClaim(t, st, f, now)

	result, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, sampleFinding(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Outcome != TriageCompletionSuccess {
		t.Fatalf("Outcome = %q, want success", result.Outcome)
	}
	if result.FindingID != "finding:"+claim.AttemptID {
		t.Fatalf("FindingID = %q, want a stable id derived from the attempt", result.FindingID)
	}

	inc, err := st.GetIncidentByID(ctx, f.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("get incident: %v", err)
	}
	if inc.Status != "analyzed" || inc.OutputJSON != `{"ok":true}` || inc.LastJudgedAt == nil {
		t.Fatalf("incident after success = %+v", inc)
	}

	var count int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_triage WHERE incident_id = ?`, f.IncidentID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("incident_triage rows after success = %d, want 0 (schedule closed)", count)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "finding_persisted"); n != 1 {
		t.Fatalf("finding_persisted inputs = %d, want exactly 1", n)
	}
}

func TestCompleteIncidentTriageAttemptSuccessIdempotentReplayReturnsCommittedResult(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "complete-replay", now)
	claim := mustClaim(t, st, f, now)
	finding := sampleFinding()

	first, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, finding, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("first complete: %v", err)
	}
	second, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, finding, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("replay complete: %v", err)
	}
	if first != second {
		t.Fatalf("replay result = %+v, want identical to first %+v", second, first)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "finding_persisted"); n != 1 {
		t.Fatalf("finding_persisted inputs after replay = %d, want exactly 1", n)
	}
}

func TestCompleteIncidentTriageAttemptConflictingReplayFailsClosed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "complete-conflict", now)
	claim := mustClaim(t, st, f, now)

	if _, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, sampleFinding(), now.Add(time.Minute)); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	conflicting := sampleFinding()
	conflicting.Summary = "a different name entirely"
	if _, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, conflicting, now.Add(2*time.Minute)); !errors.Is(err, ErrTriageAttemptCompletedDifferently) {
		t.Fatalf("conflicting replay = %v, want ErrTriageAttemptCompletedDifferently", err)
	}
}

// TestCompleteIncidentTriageAttemptStaleMembershipRestoresAwaitingDecision
// pins the membership-changed-mid-flight path: a delivery attaches to the
// Incident after the attempt claimed its digests, so the current membership
// digest no longer matches what was frozen.
func TestCompleteIncidentTriageAttemptStaleMembershipRestoresAwaitingDecision(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "complete-stale-membership", now)
	claim := mustClaim(t, st, f, now)

	// A second delivery attaches to the same Incident after the claim froze
	// its digests — membership genuinely changed mid-flight.
	dels, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-2-"+f.GroupKey, "fp-2-"+f.GroupKey, now.Add(30*time.Second))})
	if err != nil || len(dels) != 1 {
		t.Fatalf("accept second delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		f.IncidentID, dels[0].ID, canonicalTime(now.Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}

	result, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, sampleFinding(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Outcome != TriageCompletionStaleMembership {
		t.Fatalf("Outcome = %q, want stale_membership", result.Outcome)
	}
	if result.FindingID != "" {
		t.Fatalf("FindingID = %q, want empty (no Finding persisted on a stale completion)", result.FindingID)
	}

	inc, err := st.GetIncidentByID(ctx, f.IncidentID)
	if err != nil || inc == nil || inc.Status != "ready" {
		t.Fatalf("incident after stale completion = %+v, %v, want status ready", inc, err)
	}
	if inc.OutputJSON != "" || inc.LastJudgedAt != nil {
		t.Fatalf("incident output projection touched by a stale completion: %+v", inc)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "awaiting_decision" {
		t.Fatalf("phase = %q, want awaiting_decision", tr.Phase)
	}
	if tr.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (the attempt is consumed, not refunded)", tr.Attempts)
	}
	if tr.LeaseOwner.Valid || tr.CurrentAttemptID.Valid {
		t.Fatalf("lease/current_attempt_id not cleared: owner=%v attempt=%v", tr.LeaseOwner, tr.CurrentAttemptID)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_retry_changed"); n != 2 { // one from claim's own begin, one from the stale completion
		t.Fatalf("triage_retry_changed inputs after stale completion = %d, want 2 (begin + stale)", n)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "finding_persisted"); n != 0 {
		t.Fatalf("finding_persisted inputs after a stale completion = %d, want 0", n)
	}
}

func TestCompleteIncidentTriageAttemptStaleIncidentInputRestoresAwaitingDecision(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "complete-stale-input", now)
	claim := mustClaim(t, st, f, now)

	// The SAME Alert re-fires (a new alert_deliveries row, same alert_id):
	// membership digest is unchanged (same set of AlertIDs), but the
	// Incident-input digest changes (a new delivery row joins the sorted
	// delivery set IncidentInputDigest hashes).
	var alertID string
	if err := st.db.QueryRowContext(ctx, `SELECT alert_id FROM alert_deliveries WHERE id = ?`, f.DeliveryID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	refireInput := deliveryFixture("delivery-refire-"+f.GroupKey, "fp-"+f.GroupKey, now.Add(30*time.Second))
	refireInput.Alert.ID = alertID // same underlying Alert re-firing
	dels, err := st.AcceptDeliveries(ctx, []DeliveryInput{refireInput})
	if err != nil || len(dels) != 1 {
		t.Fatalf("accept refire delivery: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		f.IncidentID, dels[0].ID, canonicalTime(now.Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}

	result, err := st.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, sampleFinding(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Outcome != TriageCompletionStaleIncidentInput {
		t.Fatalf("Outcome = %q, want stale_incident_input", result.Outcome)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "awaiting_decision" {
		t.Fatalf("phase = %q, want awaiting_decision", tr.Phase)
	}
}

// ----------------------------------------------------------------------
// BackoffIncidentTriageAttempt / ExhaustIncidentTriageAttempt.
// ----------------------------------------------------------------------

func TestBackoffIncidentTriageAttemptReschedulesAndAppendsRetryChanged(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "backoff-basic", now)
	claim := mustClaim(t, st, f, now)

	nextAt := now.Add(30 * time.Second)
	if err := st.BackoffIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, nextAt, "timeout", "deadline exceeded", now.Add(time.Minute)); err != nil {
		t.Fatalf("backoff: %v", err)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "backoff" || tr.Attempts != 1 {
		t.Fatalf("phase=%q attempts=%d, want backoff/1", tr.Phase, tr.Attempts)
	}
	if tr.LeaseOwner.Valid || tr.CurrentAttemptID.Valid {
		t.Fatalf("lease not released: owner=%v attempt=%v", tr.LeaseOwner, tr.CurrentAttemptID)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status = %q, want ready", got)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_retry_changed"); n != 2 { // one from claim's own begin, one from backoff
		t.Fatalf("triage_retry_changed inputs after backoff = %d, want 2 (begin + backoff)", n)
	}

	var resultCode string
	var completedAt sql.NullString
	if err := st.db.QueryRowContext(ctx, `SELECT result_code, completed_at FROM incident_triage_attempts WHERE id = ?`, claim.AttemptID).Scan(&resultCode, &completedAt); err != nil {
		t.Fatal(err)
	}
	if resultCode != "timeout" || !completedAt.Valid {
		t.Fatalf("attempt ledger row after backoff: code=%q completed=%v", resultCode, completedAt)
	}
}

func TestExhaustIncidentTriageAttemptClosesIncidentFailedAndAppendsExhausted(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "exhaust-basic", now)
	claim := mustClaim(t, st, f, now)

	if err := st.ExhaustIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, "max_attempts", "schedule spent", now.Add(time.Minute)); err != nil {
		t.Fatalf("exhaust: %v", err)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "exhausted" {
		t.Fatalf("phase = %q, want exhausted", tr.Phase)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "failed" {
		t.Fatalf("incident status = %q, want failed", got)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_exhausted"); n != 1 {
		t.Fatalf("triage_exhausted inputs = %d, want exactly 1", n)
	}
}

// ----------------------------------------------------------------------
// CompleteIncidentTriageAttemptAsCleanSkip (Task 7 fix, Finding #2): the
// dedicated skip-completion primitive Analyze's own ErrCleanSkip needs,
// distinct from both CompleteIncidentTriageAttempt (a real Finding) and
// ExhaustIncidentTriageAttempt (a genuine 5-attempt failure).
// ----------------------------------------------------------------------

func TestCompleteIncidentTriageAttemptAsCleanSkipClosesSkippedRestoresReadyAndAppendsTriageSkippedOnce(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "clean-skip-basic", now)
	claim := mustClaim(t, st, f, now)

	if err := st.CompleteIncidentTriageAttemptAsCleanSkip(ctx, claim.AttemptID, f.IncidentID, "clean_skip", "nothing to analyze", now.Add(time.Minute)); err != nil {
		t.Fatalf("complete as clean skip: %v", err)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "skipped" {
		t.Fatalf("phase = %q, want skipped (the same terminal phase the B+-gate skip uses)", tr.Phase)
	}
	if tr.LeaseOwner.Valid || tr.CurrentAttemptID.Valid {
		t.Fatalf("lease not released: owner=%v attempt=%v", tr.LeaseOwner, tr.CurrentAttemptID)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status = %q, want ready — not failed: a clean skip must stay collapse-eligible "+
			"(Global Constraint: triage exhaustion never closes a Situation)", got)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs = %d, want exactly 1", n)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_exhausted"); n != 0 {
		t.Fatalf("triage_exhausted inputs = %d, want 0 — a clean skip must never emit the code reserved for a genuine 5-attempt exhaustion", n)
	}

	var resultCode string
	var completedAt sql.NullString
	if err := st.db.QueryRowContext(ctx, `SELECT result_code, completed_at FROM incident_triage_attempts WHERE id = ?`, claim.AttemptID).Scan(&resultCode, &completedAt); err != nil {
		t.Fatal(err)
	}
	if resultCode != "clean_skip" || !completedAt.Valid {
		t.Fatalf("attempt ledger row after clean skip: code=%q completed=%v", resultCode, completedAt)
	}
}

func TestCompleteIncidentTriageAttemptAsCleanSkipReplayFailsClosedWithoutDuplicateInput(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "clean-skip-replay", now)
	claim := mustClaim(t, st, f, now)

	if err := st.CompleteIncidentTriageAttemptAsCleanSkip(ctx, claim.AttemptID, f.IncidentID, "clean_skip", "nothing to analyze", now.Add(time.Minute)); err != nil {
		t.Fatalf("complete as clean skip: %v", err)
	}
	err := st.CompleteIncidentTriageAttemptAsCleanSkip(ctx, claim.AttemptID, f.IncidentID, "clean_skip", "nothing to analyze", now.Add(2*time.Minute))
	if !errors.Is(err, ErrTriageAttemptLeaseLost) {
		t.Fatalf("second call err = %v, want ErrTriageAttemptLeaseLost — a replay against an already-completed "+
			"attempt fails closed rather than silently no-oping or re-appending a duplicate Situation input", err)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs after replay = %d, want still exactly 1", n)
	}
}

// ----------------------------------------------------------------------
// ExtendIncidentTriageLease.
// ----------------------------------------------------------------------

// leaseExpiresAt reads incident_triage.lease_expires_at directly for
// incidentID — the column ExtendIncidentTriageLease's whole job is to push
// forward.
func leaseExpiresAt(t *testing.T, st *Store, incidentID string) time.Time {
	t.Helper()
	var s string
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT lease_expires_at FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestExtendIncidentTriageLeasePushesExpiryForwardForCurrentOwner(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "extend-basic", now)
	claim := mustClaim(t, st, f, now)

	extendAt := now.Add(30 * time.Second)
	if err := st.ExtendIncidentTriageLease(ctx, claim.AttemptID, f.IncidentID, claim.LeaseOwner, extendAt, time.Minute); err != nil {
		t.Fatalf("extend: %v", err)
	}

	got := leaseExpiresAt(t, st, f.IncidentID)
	want := extendAt.Add(time.Minute)
	if !got.Equal(want) {
		t.Fatalf("lease_expires_at = %v, want %v (heartbeat pushed forward)", got, want)
	}
	// A successful heartbeat must not disturb phase/owner/attempt identity.
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "in_flight" {
		t.Fatalf("phase = %q, want in_flight (unchanged by extend)", tr.Phase)
	}
	if !tr.LeaseOwner.Valid || tr.LeaseOwner.String != claim.LeaseOwner {
		t.Fatalf("lease_owner = %v, want unchanged %q", tr.LeaseOwner, claim.LeaseOwner)
	}
	if !tr.CurrentAttemptID.Valid || tr.CurrentAttemptID.String != claim.AttemptID {
		t.Fatalf("current_attempt_id = %v, want unchanged %q", tr.CurrentAttemptID, claim.AttemptID)
	}
}

func TestExtendIncidentTriageLeaseWrongOwnerFailsWithLeaseLost(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "extend-wrong-owner", now)
	claim := mustClaim(t, st, f, now)
	before := leaseExpiresAt(t, st, f.IncidentID)

	err := st.ExtendIncidentTriageLease(ctx, claim.AttemptID, f.IncidentID, "someone-else", now.Add(30*time.Second), time.Minute)
	if !errors.Is(err, ErrTriageAttemptLeaseLost) {
		t.Fatalf("extend with wrong owner = %v, want ErrTriageAttemptLeaseLost", err)
	}
	if got := leaseExpiresAt(t, st, f.IncidentID); !got.Equal(before) {
		t.Fatalf("lease_expires_at changed by a rejected extend: %v, want unchanged %v", got, before)
	}
}

func TestExtendIncidentTriageLeaseWrongAttemptIDFailsWithLeaseLost(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "extend-wrong-attempt", now)
	claim := mustClaim(t, st, f, now)
	before := leaseExpiresAt(t, st, f.IncidentID)

	err := st.ExtendIncidentTriageLease(ctx, "not-the-current-attempt-id", f.IncidentID, claim.LeaseOwner, now.Add(30*time.Second), time.Minute)
	if !errors.Is(err, ErrTriageAttemptLeaseLost) {
		t.Fatalf("extend with a stale/wrong attempt id = %v, want ErrTriageAttemptLeaseLost", err)
	}
	if got := leaseExpiresAt(t, st, f.IncidentID); !got.Equal(before) {
		t.Fatalf("lease_expires_at changed by a rejected extend: %v, want unchanged %v", got, before)
	}
}

// TestExtendIncidentTriageLeaseAgainstNonInFlightRowFailsWithLeaseLost pins
// the phase fence: once the schedule has moved off in_flight (here, backed
// off by a recovery pass or a genuinely completing worker), a heartbeat
// naming the old attempt/owner must fail rather than resurrect a dead lease.
func TestExtendIncidentTriageLeaseAgainstNonInFlightRowFailsWithLeaseLost(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "extend-not-in-flight", now)
	claim := mustClaim(t, st, f, now)

	if err := st.BackoffIncidentTriageAttempt(ctx, claim.AttemptID, f.IncidentID, now.Add(time.Hour), "timeout", "x", now.Add(time.Minute)); err != nil {
		t.Fatalf("backoff: %v", err)
	}

	err := st.ExtendIncidentTriageLease(ctx, claim.AttemptID, f.IncidentID, claim.LeaseOwner, now.Add(2*time.Minute), time.Minute)
	if !errors.Is(err, ErrTriageAttemptLeaseLost) {
		t.Fatalf("extend against a backed-off row = %v, want ErrTriageAttemptLeaseLost", err)
	}
}

// ----------------------------------------------------------------------
// RecoverExpiredIncidentTriageAttempts.
// ----------------------------------------------------------------------

func TestRecoverExpiredIncidentTriageAttemptsBacksOffBelowCeiling(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "recover-backoff", now)
	decideAndApplyRequest(t, st, f, now)
	claim, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Nothing resolves the attempt: simulate a lease that has since expired
	// (or a crash before any heartbeat arrived).

	recovered, err := st.RecoverExpiredIncidentTriageAttempts(ctx, claim.LeaseExpiresAt.Add(time.Second))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "backoff" || tr.Attempts != 1 {
		t.Fatalf("phase=%q attempts=%d, want backoff/1", tr.Phase, tr.Attempts)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status = %q, want ready", got)
	}
}

func TestRecoverExpiredIncidentTriageAttemptsExhaustsAtCeiling(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "recover-exhaust", now)
	decideAndApplyRequest(t, st, f, now)

	// Walk the schedule to its final (5th) attempt via genuine
	// claim/backoff cycles, then abandon that last attempt in_flight.
	at := now
	var claim ClaimedTriageAttempt
	for i := 0; i < 5; i++ {
		got, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", at, time.Minute)
		if err != nil {
			t.Fatalf("claim %d: %v", i+1, err)
		}
		claim = got
		if i < 4 {
			at = at.Add(time.Minute)
			if err := st.BackoffIncidentTriageAttempt(ctx, got.AttemptID, f.IncidentID, at, "timeout", "x", at); err != nil {
				t.Fatalf("backoff %d: %v", i+1, err)
			}
		}
	}
	_ = claim

	recovered, err := st.RecoverExpiredIncidentTriageAttempts(ctx, at.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "exhausted" || tr.Attempts != 5 {
		t.Fatalf("phase=%q attempts=%d, want exhausted/5", tr.Phase, tr.Attempts)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "failed" {
		t.Fatalf("incident status = %q, want failed", got)
	}
}

// TestRecoverExpiredIncidentTriageAttemptsIgnoresLiveLease proves the
// negative: a row still comfortably inside its lease window (a healthy
// worker, or one that just heartbeat via ExtendIncidentTriageLease) is left
// entirely untouched — recovery only ever acts on a genuinely expired
// lease.
func TestRecoverExpiredIncidentTriageAttemptsIgnoresLiveLease(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "recover-live-lease", now)
	decideAndApplyRequest(t, st, f, now)
	claim, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	recovered, err := st.RecoverExpiredIncidentTriageAttempts(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("recovered = %d, want 0 (lease still live)", recovered)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "in_flight" {
		t.Fatalf("phase = %q, want in_flight (untouched)", tr.Phase)
	}
	if !tr.LeaseOwner.Valid || tr.LeaseOwner.String != "worker-1" || !tr.CurrentAttemptID.Valid || tr.CurrentAttemptID.String != claim.AttemptID {
		t.Fatalf("lease disturbed: owner=%v attempt=%v", tr.LeaseOwner, tr.CurrentAttemptID)
	}
}

// ----------------------------------------------------------------------
// BackfillUpgradedIncidentTriageSchedule / "TestUpgradeTriage*".
// ----------------------------------------------------------------------

func TestUpgradeTriageBackfillsSituationOwnershipOntoRetainedSchedulableRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "upgrade-backfill", now)
	// A retained legacy pending row — situation_id/decision_input_version/
	// membership_digest all null, exactly as migration 0016 preserves it.
	if err := storetest.SeedIncidentTriage(ctx, st.db, f.IncidentID, now); err != nil {
		t.Fatal(err)
	}

	n, err := st.BackfillUpgradedIncidentTriageSchedule(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 1 {
		t.Fatalf("backfilled = %d, want 1", n)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "pending" || tr.Attempts != 0 {
		t.Fatalf("phase=%q attempts=%d, want pending/0 unchanged", tr.Phase, tr.Attempts)
	}
	if !tr.SituationID.Valid || tr.SituationID.String != f.SituationID {
		t.Fatalf("situation_id = %v, want %q", tr.SituationID, f.SituationID)
	}
	if !tr.DecisionOrigin.Valid || tr.DecisionOrigin.String != "upgrade_existing_schedule" {
		t.Fatalf("decision_origin = %v, want upgrade_existing_schedule", tr.DecisionOrigin)
	}
	if !tr.DecisionInputVersion.Valid || tr.DecisionInputVersion.Int64 != 1 {
		t.Fatalf("decision_input_version = %v, want 1", tr.DecisionInputVersion)
	}
	if !tr.MembershipDigest.Valid || tr.MembershipDigest.String != f.MembershipDigest {
		t.Fatalf("membership_digest = %v, want %q", tr.MembershipDigest, f.MembershipDigest)
	}
	// The migration's own preserved-row contract: decision, incident_input_digest,
	// material_fact_hash, assessment_id, decided_at all stay null.
	if tr.Decision.Valid {
		t.Fatalf("decision = %v, want null (never retroactively decided)", tr.Decision)
	}
	if tr.IncidentInputDigest.Valid {
		t.Fatalf("incident_input_digest = %v, want null (not part of the upgrade backfill)", tr.IncidentInputDigest)
	}
}

func TestUpgradeTriageLeavesAwaitingDecisionRowsUntouched(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "upgrade-awaiting", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)

	n, err := st.BackfillUpgradedIncidentTriageSchedule(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 0 {
		t.Fatalf("backfilled = %d, want 0 (awaiting_decision is not retained schedulable work)", n)
	}
	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "awaiting_decision" {
		t.Fatalf("phase = %q, want awaiting_decision unchanged", tr.Phase)
	}
	if tr.SituationID.Valid {
		t.Fatalf("situation_id = %v, want null (untouched)", tr.SituationID)
	}
}

func TestUpgradeTriageSkipsIncidentsWithNoOwningSituationYet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	// An Incident that is ready and scheduled but never attached to any
	// Situation (Plan 1 reconstruction has not reached it yet).
	incID := uuid.NewString()
	if err := st.InsertIncident(ctx, Incident{ID: incID, GroupKey: "upgrade-no-situation", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, incID); err != nil {
		t.Fatal(err)
	}
	if err := storetest.SeedIncidentTriage(ctx, st.db, incID, now); err != nil {
		t.Fatal(err)
	}

	n, err := st.BackfillUpgradedIncidentTriageSchedule(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 0 {
		t.Fatalf("backfilled = %d, want 0", n)
	}
	var situationID sql.NullString
	if err := st.db.QueryRowContext(ctx, `SELECT situation_id FROM incident_triage WHERE incident_id = ?`, incID).Scan(&situationID); err != nil {
		t.Fatal(err)
	}
	if situationID.Valid {
		t.Fatalf("situation_id = %v, want null", situationID)
	}
}

// ----------------------------------------------------------------------
// CleanSkipIncidentTriageBelowMinimumMembers: the worker's PRE-CLAIM clean
// skip. Global Constraint: "A clean skip is a first judgment without Acute
// Triage dispatch and consumes no Triage attempt" — so, unlike
// CompleteIncidentTriageAttemptAsCleanSkip, this must leave the attempt
// count and the attempt ledger untouched.
// ----------------------------------------------------------------------

func countTriageAttemptRows(t *testing.T, st *Store, incidentID string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM incident_triage_attempts WHERE incident_id = ?`, incidentID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCleanSkipBelowMinimumMembersClosesDueRowWithoutConsumingAnAttempt(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "preclaim-skip", now) // exactly one member alert
	decideAndApplyRequest(t, st, f, now)

	got, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("clean skip below minimum: %v", err)
	}
	if !got.Skipped || got.SituationID != f.SituationID || got.MemberAlerts != 1 || got.DecisionInputVersion == 0 {
		t.Fatalf("result = %+v, want Skipped with situation %s, 1 member alert, and the decided input version", got, f.SituationID)
	}

	tr := triageRow(t, st, f.IncidentID)
	if tr.Phase != "skipped" {
		t.Fatalf("phase = %q, want skipped (the same terminal phase the B+-gate skip uses)", tr.Phase)
	}
	if tr.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0 — a pre-claim clean skip consumes no Triage attempt", tr.Attempts)
	}
	if n := countTriageAttemptRows(t, st, f.IncidentID); n != 0 {
		t.Fatalf("attempt ledger rows = %d, want 0 — nothing was ever claimed", n)
	}
	if tr.LeaseOwner.Valid || tr.CurrentAttemptID.Valid {
		t.Fatalf("lease fields set on a never-claimed row: owner=%v attempt=%v", tr.LeaseOwner, tr.CurrentAttemptID)
	}
	if got := incidentStatus(t, st, f.IncidentID); got != "ready" {
		t.Fatalf("incident status = %q, want ready — a clean skip must stay collapse-eligible", got)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs = %d, want exactly 1", n)
	}

	// Replay is a no-op: the row is no longer pending/backoff.
	again, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 2, now.Add(2*time.Minute))
	if err != nil || again.Skipped {
		t.Fatalf("replay = %+v, %v; want not skipped and no error", again, err)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 1 {
		t.Fatalf("triage_skipped inputs after replay = %d, want still exactly 1", n)
	}
	// And the ordinary claim now fails closed: nothing is claimable.
	if _, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-1", now.Add(2*time.Minute), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim after clean skip err = %v, want ErrNotFound", err)
	}
}

func TestCleanSkipBelowMinimumMembersLeavesEligibleIncidentForTheOrdinaryClaim(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "preclaim-eligible", now)
	decideAndApplyRequest(t, st, f, now)

	got, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 1, now.Add(time.Minute))
	if err != nil || got.Skipped || got.MemberAlerts != 1 {
		t.Fatalf("result = %+v, %v; want not skipped with 1 member alert", got, err)
	}
	if tr := triageRow(t, st, f.IncidentID); tr.Phase != "pending" {
		t.Fatalf("phase = %q, want pending (untouched)", tr.Phase)
	}
	if n := countSituationInputs(t, st, f.IncidentID, "triage_skipped"); n != 0 {
		t.Fatalf("triage_skipped inputs = %d, want 0", n)
	}
	claim := mustClaimExisting(t, st, f, now.Add(time.Minute))
	if claim.AttemptNumber != 1 {
		t.Fatalf("attempt number = %d, want 1", claim.AttemptNumber)
	}
}

func TestCleanSkipBelowMinimumMembersNeverTouchesAnAwaitingDecisionRow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "preclaim-undecided", now)
	seedAwaitingDecisionRow(t, st, f.IncidentID, now)

	got, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 5, now.Add(time.Minute))
	if err != nil || got.Skipped {
		t.Fatalf("result = %+v, %v; want not skipped — only a controller-decided pending/backoff row is the worker's to close", got, err)
	}
	if tr := triageRow(t, st, f.IncidentID); tr.Phase != "awaiting_decision" {
		t.Fatalf("phase = %q, want awaiting_decision (untouched)", tr.Phase)
	}
}

func TestCleanSkipBelowMinimumMembersLeavesANotYetDueRowAlone(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "preclaim-notdue", now)
	decideAndApplyRequest(t, st, f, now)
	if _, err := st.db.ExecContext(ctx, `UPDATE incident_triage SET next_at = ? WHERE incident_id = ?`, canonicalTime(now.Add(time.Hour)), f.IncidentID); err != nil {
		t.Fatal(err)
	}

	got, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 5, now.Add(time.Minute))
	if err != nil || got.Skipped {
		t.Fatalf("result = %+v, %v; want not skipped before next_at", got, err)
	}
}

// TestCleanSkipBelowMinimumMembersCountsLegacyIncidentAlertsWhenNoDeliveries
// mirrors skills/acutetriage's own loadFrozenClaimAlerts fallback: an
// Incident with incident_alerts rows but no delivery-ledger rows (pre-0013)
// still has real members and must not be clean-skipped as empty.
func TestCleanSkipBelowMinimumMembersCountsLegacyIncidentAlertsWhenNoDeliveries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f := newTriageFixture(t, st, "preclaim-legacy", now)
	decideAndApplyRequest(t, st, f, now)

	var alertID string
	if err := st.db.QueryRowContext(ctx, `SELECT alert_id FROM alert_deliveries WHERE id = ?`, f.DeliveryID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, created_at) VALUES (?, ?, ?)`, f.IncidentID, alertID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM incident_alert_deliveries WHERE incident_id = ?`, f.IncidentID); err != nil {
		t.Fatal(err)
	}

	got, err := st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 1, now.Add(time.Minute))
	if err != nil || got.Skipped || got.MemberAlerts != 1 {
		t.Fatalf("result = %+v, %v; want not skipped with 1 legacy member alert", got, err)
	}
	got, err = st.CleanSkipIncidentTriageBelowMinimumMembers(ctx, f.IncidentID, 2, now.Add(time.Minute))
	if err != nil || !got.Skipped {
		t.Fatalf("result = %+v, %v; want skipped below a minimum of 2", got, err)
	}
}

// mustClaimExisting claims a row an earlier decideAndApplyRequest already
// moved to pending, without re-seeding the decision.
func mustClaimExisting(t *testing.T, st *Store, f triageFixture, now time.Time) ClaimedTriageAttempt {
	t.Helper()
	got, err := st.ClaimIncidentTriageAttempt(context.Background(), f.IncidentID, "worker-1", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return got
}
