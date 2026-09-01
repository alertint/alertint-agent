// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ----------------------------------------------------------------------
// Migration-14 upgrade: 0015's ALTER TABLE additions to `situations` and
// its new tables must land cleanly on top of a populated Plan 1 database.
// ----------------------------------------------------------------------

// migration14Fixture builds a file-backed database with only migrations
// 1-14 applied (the schema as it existed immediately before this task's
// 0015/0016), seeds one Alert, one operational Incident, and one active
// Situation, and returns the file path so a caller can reopen it with the
// current Open and observe 0015/0016 land cleanly on pre-existing data.
func migration14Fixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "migration14.db")

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range all {
		if m.version > 14 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	if _, err := fixture.UpsertAlertByFingerprint(ctx, Alert{
		ID:          uuid.NewString(),
		Fingerprint: "pre-controller-fp",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "PreController"},
		Annotations: map[string]string{},
		StartsAt:    now,
		ReceivedAt:  now,
	}); err != nil {
		t.Fatalf("seed pre-upgrade alert: %v", err)
	}
	if err := fixture.InsertIncident(ctx, Incident{
		ID:           "pre-controller-incident",
		GroupKey:     "pre-controller-group",
		FirstAlertAt: now,
		LastAlertAt:  now,
		ReadyAt:      now,
	}); err != nil {
		t.Fatalf("seed pre-upgrade incident: %v", err)
	}
	if err := insertSituation(ctx, fixture, situationRow{
		id: "pre-controller-situation", groupKey: "pre-controller-situation-group", lifecycle: "active",
	}); err != nil {
		t.Fatalf("seed pre-upgrade situation: %v", err)
	}

	return path
}

// TestSituationControllerSchemaUpgradesMigration14Database is the brief's
// upgrade test: opening a migration-14 database with the current Open must
// apply 0015 and 0016 without disturbing rows that predate them, and the
// new situations columns must default to "no Assessment yet" on the
// pre-existing row. PRAGMA foreign_key_check must report no violations.
func TestSituationControllerSchemaUpgradesMigration14Database(t *testing.T) {
	ctx := context.Background()
	path := migration14Fixture(t)
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	var versions int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version IN (15,16)`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("new migration count = %d, want 2", versions)
	}

	var incidents int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE id='pre-controller-incident'`).Scan(&incidents); err != nil {
		t.Fatal(err)
	}
	if incidents != 1 {
		t.Fatalf("pre-upgrade incident count = %d, want 1", incidents)
	}

	var (
		currentAssessmentID  sql.NullString
		retryEpoch           int
		workAttempts         int
		lastConsumedRecovery int
	)
	if err := st.DB().QueryRowContext(ctx, `
		SELECT current_assessment_id, controller_retry_epoch, controller_work_attempts, last_consumed_recovery_generation
		FROM situations WHERE id = 'pre-controller-situation'
	`).Scan(&currentAssessmentID, &retryEpoch, &workAttempts, &lastConsumedRecovery); err != nil {
		t.Fatalf("read back upgraded situation: %v", err)
	}
	if currentAssessmentID.Valid {
		t.Errorf("current_assessment_id = %q, want NULL on a pre-upgrade situation", currentAssessmentID.String)
	}
	if retryEpoch != 0 || workAttempts != 0 || lastConsumedRecovery != 0 {
		t.Errorf("controller projection = (retry_epoch=%d, work_attempts=%d, last_consumed=%d), want all zero", retryEpoch, workAttempts, lastConsumedRecovery)
	}

	assertNoForeignKeyViolations(ctx, t, st)
}

// ----------------------------------------------------------------------
// Direct constraint/trigger tests for 0015's new tables.
// ----------------------------------------------------------------------

func insertSituationFact(ctx context.Context, s *Store, id, situationID, kind string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_facts (id, situation_id, input_version, kind, subject, digest, value_json, result_status, material, observed_at)
		VALUES (?, ?, 1, ?, 'checkout', 'sha256:fact', '{"a":1}', 'confirmed_value', 1, ?)
	`, id, situationID, kind, now)
	return err
}

// TestSituationControllerSchema_FactsAreImmutable proves situation_facts
// rows can be inserted but never updated or deleted.
func TestSituationControllerSchema_FactsAreImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-facts", groupKey: "group-facts", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertSituationFact(ctx, s, "fact-1", "sit-facts", "current_duration"); err != nil {
		t.Fatalf("insert fact: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situation_facts SET material = 0 WHERE id = 'fact-1'`); err == nil {
		t.Fatal("expected update of situation_facts to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_facts WHERE id = 'fact-1'`); err == nil {
		t.Fatal("expected delete of situation_facts to be rejected")
	}
}

// TestSituationControllerSchema_FactKindRejectsUnknown proves the closed
// fact-kind enum rejects a value outside the initial eight kinds.
func TestSituationControllerSchema_FactKindRejectsUnknown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-fact-kind", groupKey: "group-fact-kind", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertSituationFact(ctx, s, "fact-bad-kind", "sit-fact-kind", "invented_kind"); err == nil {
		t.Fatal("expected unknown fact kind to be rejected")
	}
}

type assessmentCallRow struct {
	id          string
	situationID string
	inputVer    int
	retryEpoch  int
	workAttempt int
	callNumber  int
}

func insertAssessmentCall(ctx context.Context, s *Store, r assessmentCallRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_assessment_calls (id, situation_id, input_version, retry_epoch, work_attempt, call_number, material_fact_hash, dispatched_at)
		VALUES (?, ?, ?, ?, ?, ?, 'sha256:material', ?)
	`, r.id, r.situationID, r.inputVer, r.retryEpoch, r.workAttempt, r.callNumber, now)
	return err
}

// TestSituationControllerSchema_AssessmentCallsAreImmutableAndUnique proves
// the dispatch ledger's identity uniqueness and its immutability triggers.
func TestSituationControllerSchema_AssessmentCallsAreImmutableAndUnique(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-calls", groupKey: "group-calls", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	base := assessmentCallRow{id: "call-1", situationID: "sit-calls", inputVer: 1, retryEpoch: 0, workAttempt: 1, callNumber: 1}
	if err := insertAssessmentCall(ctx, s, base); err != nil {
		t.Fatalf("insert call: %v", err)
	}

	dup := base
	dup.id = "call-1-dup"
	if err := insertAssessmentCall(ctx, s, dup); err == nil {
		t.Fatal("expected duplicate (situation_id,input_version,retry_epoch,work_attempt,call_number) to be rejected")
	}

	second := base
	second.id = "call-2"
	second.callNumber = 2
	if err := insertAssessmentCall(ctx, s, second); err != nil {
		t.Fatalf("expected the second call in the same attempt to succeed: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situation_assessment_calls SET call_number = 2 WHERE id = 'call-1'`); err == nil {
		t.Fatal("expected update of situation_assessment_calls to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_assessment_calls WHERE id = 'call-1'`); err == nil {
		t.Fatal("expected delete of situation_assessment_calls to be rejected")
	}
}

// TestSituationControllerSchema_AssessmentCallNumberBoundedToTwo proves
// call_number is bounded to the two-call draft/verification ceiling.
func TestSituationControllerSchema_AssessmentCallNumberBoundedToTwo(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-call-bound", groupKey: "group-call-bound", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertAssessmentCall(ctx, s, assessmentCallRow{id: "call-3rd", situationID: "sit-call-bound", inputVer: 1, workAttempt: 1, callNumber: 3}); err == nil {
		t.Fatal("expected call_number 3 to be rejected")
	}
}

type assessmentAttemptRow struct {
	id              string
	situationID     string
	sequence        int
	inputVer        int
	retryEpoch      int
	workAttempt     int
	callID          any
	status          string
	derivation      any
	providerStarted string
	reusedFrom      any
	assessmentJSON  any
}

func insertAssessmentAttempt(ctx context.Context, s *Store, r assessmentAttemptRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, retry_epoch, work_attempt, call_id,
			status, derivation, provider_request_started, material_fact_hash, reused_from_assessment_id,
			assessment_json, created_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sha256:material', ?, ?, ?, ?)
	`, r.id, r.situationID, r.sequence, r.inputVer, r.retryEpoch, r.workAttempt, r.callID,
		r.status, r.derivation, r.providerStarted, r.reusedFrom, r.assessmentJSON, now, now)
	return err
}

// TestSituationControllerSchema_AuthoritativeAttemptRequiresDerivationAndAssessment
// proves an authoritative row must carry both a derivation and Assessment
// content, while a non-authoritative row must not carry a derivation.
func TestSituationControllerSchema_AuthoritativeAttemptRequiresDerivationAndAssessment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-attempt-shape", groupKey: "group-attempt-shape", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-no-derivation", situationID: "sit-attempt-shape", sequence: 1, inputVer: 1, workAttempt: 1,
		status: "authoritative", providerStarted: "false", assessmentJSON: "{}",
	}); err == nil {
		t.Fatal("expected authoritative attempt without derivation to be rejected")
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-no-assessment", situationID: "sit-attempt-shape", sequence: 2, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_controller", providerStarted: "false",
	}); err == nil {
		t.Fatal("expected authoritative attempt without assessment_json to be rejected")
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-derivation-not-authoritative", situationID: "sit-attempt-shape", sequence: 3, inputVer: 1, workAttempt: 1,
		callID: "missing-call-ok-fk-off", status: "failed", derivation: "deterministic_controller", providerStarted: "true",
	}); err == nil {
		t.Fatal("expected a non-authoritative row carrying a derivation to be rejected")
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-ok", situationID: "sit-attempt-shape", sequence: 4, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_controller", providerStarted: "false", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("expected a well-shaped authoritative attempt to succeed: %v", err)
	}
}

// TestSituationControllerSchema_NonModelDerivationForbidsCallID proves
// Task 3's ground truth: only model_validated authoritative attempts carry
// call_id; every other authoritative derivation forbids it.
func TestSituationControllerSchema_NonModelDerivationForbidsCallID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-derivation", groupKey: "group-derivation", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertAssessmentCall(ctx, s, assessmentCallRow{id: "call-derivation", situationID: "sit-derivation", inputVer: 1, workAttempt: 1, callNumber: 1}); err != nil {
		t.Fatalf("insert call: %v", err)
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-fallback-with-call", situationID: "sit-derivation", sequence: 1, inputVer: 1, workAttempt: 1,
		callID: "call-derivation", status: "authoritative", derivation: "deterministic_fallback", providerStarted: "false", assessmentJSON: "{}",
	}); err == nil {
		t.Fatal("expected deterministic_fallback with call_id to be rejected")
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-model-without-call", situationID: "sit-derivation", sequence: 2, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "model_validated", providerStarted: "true", assessmentJSON: "{}",
	}); err == nil {
		t.Fatal("expected model_validated without call_id to be rejected")
	}

	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-fallback-ok", situationID: "sit-derivation", sequence: 3, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_fallback", providerStarted: "false", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("expected deterministic_fallback without call_id to succeed: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-model-ok", situationID: "sit-derivation", sequence: 4, inputVer: 1, workAttempt: 1,
		callID: "call-derivation", status: "authoritative", derivation: "model_validated", providerStarted: "true", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("expected model_validated with call_id to succeed: %v", err)
	}
}

// TestSituationControllerSchema_RejectedAndFailedRequireCallID proves a
// rejected or failed outcome must always trace back to a dispatched call.
func TestSituationControllerSchema_RejectedAndFailedRequireCallID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-reject", groupKey: "group-reject", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-rejected-no-call", situationID: "sit-reject", sequence: 1, inputVer: 1, workAttempt: 1,
		status: "rejected", providerStarted: "true",
	}); err == nil {
		t.Fatal("expected a rejected attempt without call_id to be rejected")
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-failed-no-call", situationID: "sit-reject", sequence: 2, inputVer: 1, workAttempt: 1,
		status: "failed", providerStarted: "false",
	}); err == nil {
		t.Fatal("expected a failed attempt without call_id to be rejected")
	}
}

// TestSituationControllerSchema_ProviderRequestStartedClosedEnum proves the
// closed provider_request_started enum: each call-backed outcome must record
// exactly true, false, or unknown, and nothing else.
func TestSituationControllerSchema_ProviderRequestStartedClosedEnum(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-prs", groupKey: "group-prs", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-prs-bad", situationID: "sit-prs", sequence: 1, inputVer: 1, workAttempt: 1,
		status: "failed", providerStarted: "maybe",
	}); err == nil {
		t.Fatal("expected an unknown provider_request_started value to be rejected")
	}

	for i, v := range []string{"true", "false", "unknown"} {
		if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
			id: "att-prs-" + v, situationID: "sit-prs", sequence: i + 2, inputVer: 1, workAttempt: 1,
			status: "stale", providerStarted: v,
		}); err != nil {
			t.Fatalf("expected provider_request_started=%q to be accepted: %v", v, err)
		}
	}
}

// TestSituationControllerSchema_AssessmentAttemptsAreImmutable proves the
// outcome ledger's immutability triggers.
func TestSituationControllerSchema_AssessmentAttemptsAreImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-attempt-immutable", groupKey: "group-attempt-immutable", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertAssessmentCall(ctx, s, assessmentCallRow{id: "call-immutable", situationID: "sit-attempt-immutable", inputVer: 1, workAttempt: 1, callNumber: 1}); err != nil {
		t.Fatalf("insert call: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-immutable", situationID: "sit-attempt-immutable", sequence: 1, inputVer: 1, workAttempt: 1,
		callID: "call-immutable", status: "failed", providerStarted: "true",
	}); err != nil {
		t.Fatalf("insert attempt: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situation_assessment_attempts SET status = 'stale' WHERE id = 'att-immutable'`); err == nil {
		t.Fatal("expected update of situation_assessment_attempts to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_assessment_attempts WHERE id = 'att-immutable'`); err == nil {
		t.Fatal("expected delete of situation_assessment_attempts to be rejected")
	}
}

// TestSituationControllerSchema_CurrentAssessmentPointerRequiresSameSituationAuthoritative
// proves only an authoritative attempt owned by the same Situation may
// become current_assessment_id.
func TestSituationControllerSchema_CurrentAssessmentPointerRequiresSameSituationAuthoritative(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-a", groupKey: "group-ptr-a", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation A: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-b", groupKey: "group-ptr-b", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation B: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-a-authoritative", situationID: "sit-a", sequence: 1, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_controller", providerStarted: "false", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("insert authoritative attempt for A: %v", err)
	}
	// A rejected row backed by a real call, for the "wrong status" case below
	// (a rejected outcome always requires call_id — see
	// TestSituationControllerSchema_RejectedAndFailedRequireCallID).
	if err := insertAssessmentCall(ctx, s, assessmentCallRow{id: "call-a-rejected", situationID: "sit-a", inputVer: 1, workAttempt: 2, callNumber: 1}); err != nil {
		t.Fatalf("insert call: %v", err)
	}
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-a-rejected", situationID: "sit-a", sequence: 2, inputVer: 1, workAttempt: 2,
		callID: "call-a-rejected", status: "rejected", providerStarted: "true",
	}); err != nil {
		t.Fatalf("insert rejected attempt for A: %v", err)
	}

	// Cross-situation: B may not point at A's attempt.
	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_assessment_id = 'att-a-authoritative' WHERE id = 'sit-b'`); err == nil {
		t.Fatal("expected cross-situation current_assessment_id to be rejected")
	}
	// Wrong status: A may not point at its own rejected attempt.
	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_assessment_id = 'att-a-rejected' WHERE id = 'sit-a'`); err == nil {
		t.Fatal("expected current_assessment_id pointing at a non-authoritative attempt to be rejected")
	}
	// Legal: A may point at its own authoritative attempt.
	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_assessment_id = 'att-a-authoritative' WHERE id = 'sit-a'`); err != nil {
		t.Fatalf("expected same-situation authoritative pointer to succeed: %v", err)
	}
	var got sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT current_assessment_id FROM situations WHERE id = 'sit-a'`).Scan(&got); err != nil {
		t.Fatalf("read back current_assessment_id: %v", err)
	}
	if !got.Valid || got.String != "att-a-authoritative" {
		t.Fatalf("current_assessment_id = %+v, want att-a-authoritative", got)
	}
}

// TestSituationControllerSchema_CoverageTuplesAreImmutable proves the
// per-Incident coverage ledger's PK uniqueness and immutability triggers.
func TestSituationControllerSchema_CoverageTuplesAreImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := insertSituation(ctx, s, situationRow{id: "sit-coverage", groupKey: "group-coverage", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	insertOperationalIncident(ctx, t, s, "inc-coverage", "group-coverage-incident")
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: "att-coverage", situationID: "sit-coverage", sequence: 1, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_controller", providerStarted: "false", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("insert attempt: %v", err)
	}

	insertCoverage := func() error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO situation_assessment_coverage (assessment_attempt_id, incident_id, membership_digest, incident_input_digest)
			VALUES ('att-coverage', 'inc-coverage', 'sha256:members', 'sha256:input')
		`)
		return err
	}
	if err := insertCoverage(); err != nil {
		t.Fatalf("insert coverage: %v", err)
	}
	if err := insertCoverage(); err == nil {
		t.Fatal("expected duplicate (assessment_attempt_id,incident_id) coverage tuple to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_assessment_coverage SET membership_digest = 'sha256:changed' WHERE incident_id = 'inc-coverage'`); err == nil {
		t.Fatal("expected update of situation_assessment_coverage to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_assessment_coverage WHERE incident_id = 'inc-coverage'`); err == nil {
		t.Fatal("expected delete of situation_assessment_coverage to be rejected")
	}
}
