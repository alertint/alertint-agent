// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

type legacyReadyRow struct {
	id       string
	groupKey string
	readyAt  time.Time
}

// seedV0134Fixture builds a database file at path shaped like v0.13.4 — every
// embedded migration through version 10 only, so no incident_triage table
// exists — and inserts the given "ready" incidents directly by SQL (the
// store API only knows migration 0011's shape and could not produce a
// pre-0011 row).
func seedV0134Fixture(t *testing.T, path string, rows []legacyReadyRow) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, m := range migrations {
		if m.version > 10 {
			continue
		}
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			m.version, appliedAt,
		); err != nil {
			t.Fatalf("record migration %d: %v", m.version, err)
		}
	}

	ts := func(x time.Time) string { return x.UTC().Format(time.RFC3339Nano) }
	for _, r := range rows {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO incidents
				(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, ?, 'ready', ?, ?, ?, 1, ?, ?)
		`, r.id, r.groupKey, ts(r.readyAt), ts(r.readyAt), ts(r.readyAt), ts(r.readyAt), ts(r.readyAt)); err != nil {
			t.Fatalf("seed legacy incident %s: %v", r.id, err)
		}
	}
}

func triagePhaseFor(t *testing.T, st *Store, incidentID string) TriagePhase {
	t.Helper()
	var phase TriagePhase
	err := st.db.QueryRowContext(context.Background(),
		`SELECT phase FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&phase)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ""
		}
		t.Fatalf("triage phase: %v", err)
	}
	return phase
}

// TestTriageUpgrade_V0134ReadyIncidentsBecomeAwaitingDecision opens a
// v0.13.4-shaped database (migrations 0001-0010 only, no incident_triage
// table at all) with legacy "ready" incidents seeded directly by SQL, then
// opens it through Store.Open — which applies every migration through
// 0016 in one pass.
//
// What this proves: migration 0016's own upgrade backfill ("ready Incident
// with no Triage row" -> awaiting_decision at attempt zero, spec's Upgrade
// mapping table) closes the one-time, v0.13.4-vintage gap at migration
// time — a pre-existing "ready"-without-schedule row present in a database
// being upgraded now gets awaiting_decision directly from the migration,
// before any Go-level reconciliation ever runs. So for THIS test's
// fixture (rows that pre-date this migration), ListLegacyReadyIncidents
// correctly finds none of them left to reconcile. Whether stale unjudged
// work is worth a fresh controller decision is now the controller's own
// B+ gate judgment (Task 6/8 territory), not a blind pre-controller SQL
// heuristic — but that judgment only applies to rows the migration itself
// already swept up.
//
// This does NOT make ListLegacyReadyIncidents dead code in general. It
// remains live, necessary production code: reconcileUnscheduledTriage in
// internal/correlator/triage_retry.go calls it every Correlator tick (not
// just at startup) to catch a separate, ongoing, non-transactional race —
// flushExpired in internal/correlator/correlator.go calls
// MarkIncidentReadyWithSituationInput and SeedIncidentTriage as two
// separate, non-transactional store calls, and if the second fails right
// after the first commits, the Incident is left "ready" with no triage
// row, otherwise invisible to every later scan. Migration 0016's backfill
// runs exactly once, at DB-upgrade time; it cannot repair an Incident that
// enters this state during live operation afterward — only the
// still-running reconciliation loop can, which is precisely why it keeps
// calling ListLegacyReadyIncidents every tick.
func TestTriageUpgrade_V0134ReadyIncidentsBecomeAwaitingDecision(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	recentID := uuid.NewString()
	staleID := uuid.NewString()
	otherID := uuid.NewString()
	seedV0134Fixture(t, path, []legacyReadyRow{
		{id: recentID, groupKey: "service=recent", readyAt: now.Add(-5 * time.Minute)},
		{id: staleID, groupKey: "service=stale", readyAt: now.Add(-2 * time.Hour)},
		{id: otherID, groupKey: "service=other", readyAt: now.Add(-10 * time.Minute)},
	})

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	legacy, err := st.ListLegacyReadyIncidents(ctx)
	if err != nil {
		t.Fatalf("list legacy: %v", err)
	}
	if len(legacy) != 0 {
		t.Fatalf("legacy ready incidents = %d, want 0 (migration 0016 already scheduled every one)", len(legacy))
	}

	for _, id := range []string{recentID, staleID, otherID} {
		// "awaiting_decision" is not yet a typed TriagePhase constant — that
		// belongs to Task 6, which owns triage.go's Go-level phase set.
		if phase := triagePhaseFor(t, st, id); phase != "awaiting_decision" {
			t.Errorf("incident %s phase = %q, want awaiting_decision", id, phase)
		}
	}

	// awaiting_decision is not pending/backoff, so it is never claimable
	// before a controller decision (spec acceptance criteria: "awaiting
	// work is never claimable before controller request").
	if _, err := st.BeginIncidentTriage(ctx, recentID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("BeginIncidentTriage on an awaiting_decision row: err = %v, want ErrNotFound", err)
	}
}

// ----------------------------------------------------------------------
// Migration-14 -> 0015/0016 upgrade: the controller-gated incident_triage
// rebuild must preserve every pre-existing schedulable/terminal row exactly
// and create awaiting_decision only for a ready Incident that never
// acquired a schedule row (spec: "Upgrade mapping for the existing Acute
// Triage schedule").
// ----------------------------------------------------------------------

// legacyTriageRow describes one pre-0016 incident_triage row (old schema:
// incident_id, phase, attempts, next_at, started_at, last_error_code,
// last_error_detail, updated_at) to seed directly by SQL, plus the
// incidents.status the owning Incident must carry.
type legacyTriageRow struct {
	incidentID      string
	groupKey        string
	incidentStatus  string
	phase           string
	attempts        int
	nextAt          any
	startedAt       any
	lastErrorCode   any
	lastErrorDetail any
}

// seedMigration14TriageFixture builds a database file shaped like the
// schema immediately before this task's 0015/0016 — every embedded
// migration through version 14 only, so incident_triage still has its
// 0011 shape with no awaiting_decision phase or controller metadata — and
// seeds the given legacy rows plus their owning incidents directly by SQL.
func seedMigration14TriageFixture(t *testing.T, path string, rows []legacyTriageRow) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range migrations {
		if m.version > 14 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, r := range rows {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO incidents
				(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
		`, r.incidentID, r.groupKey, r.incidentStatus, now, now, now, now, now); err != nil {
			t.Fatalf("seed legacy incident %s: %v", r.incidentID, err)
		}
		if r.phase == "" {
			continue // ready-without-schedule case: no incident_triage row at all.
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO incident_triage (incident_id, phase, attempts, next_at, started_at, last_error_code, last_error_detail, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, r.incidentID, r.phase, r.attempts, r.nextAt, r.startedAt, r.lastErrorCode, r.lastErrorDetail, now); err != nil {
			t.Fatalf("seed legacy triage row %s: %v", r.incidentID, err)
		}
	}
}

// legacyTriageState is a rebuilt incident_triage row's pre-existing columns,
// read back for comparison against the seeded fixture.
type legacyTriageState struct {
	found                          bool
	phase                          string
	attempts                       int
	nextAt, startedAt              sql.NullString
	lastErrorCode, lastErrorDetail sql.NullString
}

// legacyTriageRowFor reads back a rebuilt incident_triage row's
// pre-existing columns for comparison against the seeded fixture.
func legacyTriageRowFor(t *testing.T, st *Store, incidentID string) legacyTriageState {
	t.Helper()
	var s legacyTriageState
	row := st.db.QueryRowContext(context.Background(), `
		SELECT phase, attempts, next_at, started_at, last_error_code, last_error_detail
		FROM incident_triage WHERE incident_id = ?
	`, incidentID)
	err := row.Scan(&s.phase, &s.attempts, &s.nextAt, &s.startedAt, &s.lastErrorCode, &s.lastErrorDetail)
	if errors.Is(err, sql.ErrNoRows) {
		return legacyTriageState{}
	}
	if err != nil {
		t.Fatalf("read incident_triage row for %s: %v", incidentID, err)
	}
	s.found = true
	return s
}

// incidentTriageControllerUpgradeFixtureTimes are the fixed timestamps the
// shared migration-14 triage fixture seeds and asserts against.
var (
	incidentTriageControllerUpgradeNow     = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	incidentTriageControllerUpgradeStarted = time.Date(2026, 9, 1, 8, 55, 0, 0, time.UTC).Format(time.RFC3339Nano)
)

// openIncidentTriageControllerUpgradeFixture builds and opens a fresh
// migration-14 database seeded with one incident_triage row per
// pre-upgrade phase (pending, backoff, in_flight, skipped, exhausted), one
// analyzed Incident with a persisted Finding and no triage row, and one
// ready Incident that never acquired a schedule row — then opens it
// through Store.Open, which applies 0015/0016 in the same pass. Each test
// below gets its own isolated copy so per-case assertions stay simple
// (TestIncidentTriageControllerUpgrade itself, split into independent
// functions below, previously tripped gocyclo by combining every case).
func openIncidentTriageControllerUpgradeFixture(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration14-triage.db")
	now := incidentTriageControllerUpgradeNow
	started := incidentTriageControllerUpgradeStarted

	rows := []legacyTriageRow{
		{incidentID: "inc-pending", groupKey: "g-pending", incidentStatus: "ready", phase: "pending", attempts: 0, nextAt: now},
		{incidentID: "inc-backoff", groupKey: "g-backoff", incidentStatus: "ready", phase: "backoff", attempts: 2, nextAt: now, lastErrorCode: "timeout", lastErrorDetail: "deadline exceeded"},
		{incidentID: "inc-in-flight", groupKey: "g-in-flight", incidentStatus: "processing", phase: "in_flight", attempts: 1, startedAt: started},
		{incidentID: "inc-skipped", groupKey: "g-skipped", incidentStatus: "ready", phase: "skipped", attempts: 1},
		{incidentID: "inc-exhausted", groupKey: "g-exhausted", incidentStatus: "failed", phase: "exhausted", attempts: 5, lastErrorCode: "provider_unavailable", lastErrorDetail: "gave up after 5 attempts"},
		{incidentID: "inc-analyzed", groupKey: "g-analyzed", incidentStatus: "analyzed"}, // Finding already persisted; no triage row at all.
		{incidentID: "inc-ready-no-row", groupKey: "g-ready-no-row", incidentStatus: "ready"},
	}
	seedMigration14TriageFixture(t, path, rows)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestIncidentTriageControllerUpgrade_ForeignKeysIntact proves the 0016
// rebuild leaves no dangling foreign key across the upgraded database.
func TestIncidentTriageControllerUpgrade_ForeignKeysIntact(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	assertNoForeignKeyViolations(context.Background(), t, st)
}

// TestIncidentTriageControllerUpgrade_PendingPreservesPhaseAttemptsDue
// proves migration 0016 preserves a pending row's phase, attempts, and due
// time exactly, with no started_at/error fields spuriously introduced.
func TestIncidentTriageControllerUpgrade_PendingPreservesPhaseAttemptsDue(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-pending")
	if !s.found || s.phase != "pending" || s.attempts != 0 || !s.nextAt.Valid || s.nextAt.String != incidentTriageControllerUpgradeNow {
		t.Fatalf("pending row = %+v, want pending/0/%q/true", s, incidentTriageControllerUpgradeNow)
	}
	if s.startedAt.Valid || s.lastErrorCode.Valid || s.lastErrorDetail.Valid {
		t.Fatalf("pending row unexpectedly carries started_at/error fields: %+v", s)
	}
}

// TestIncidentTriageControllerUpgrade_BackoffPreservesPhaseAttemptsDueError
// proves migration 0016 preserves a backoff row's phase, attempts, due
// time, and bounded error classification exactly.
func TestIncidentTriageControllerUpgrade_BackoffPreservesPhaseAttemptsDueError(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-backoff")
	if !s.found || s.phase != "backoff" || s.attempts != 2 || !s.nextAt.Valid || s.nextAt.String != incidentTriageControllerUpgradeNow {
		t.Fatalf("backoff row = %+v, want backoff/2/%q/true", s, incidentTriageControllerUpgradeNow)
	}
	if !s.lastErrorCode.Valid || s.lastErrorCode.String != "timeout" || !s.lastErrorDetail.Valid || s.lastErrorDetail.String != "deadline exceeded" {
		t.Fatalf("backoff row error fields = %+v, want timeout/deadline exceeded", s)
	}
}

// TestIncidentTriageControllerUpgrade_InFlightPreservesPhaseAttemptsStarted
// proves migration 0016 leaves an in_flight row's phase, attempts, and
// started_at untouched — Task 6 startup recovery, not this migration, owns
// turning it into an interrupted attempt or a completed one.
func TestIncidentTriageControllerUpgrade_InFlightPreservesPhaseAttemptsStarted(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-in-flight")
	if !s.found || s.phase != "in_flight" || s.attempts != 1 || !s.startedAt.Valid || s.startedAt.String != incidentTriageControllerUpgradeStarted {
		t.Fatalf("in_flight row = %+v, want in_flight/1/%q/true", s, incidentTriageControllerUpgradeStarted)
	}
}

// TestIncidentTriageControllerUpgrade_SkippedPreservesTerminalJudgment
// proves migration 0016 retains a skipped row's terminal clean judgment.
func TestIncidentTriageControllerUpgrade_SkippedPreservesTerminalJudgment(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-skipped")
	if !s.found || s.phase != "skipped" || s.attempts != 1 || s.nextAt.Valid {
		t.Fatalf("skipped row = %+v, want skipped/1/NULL/true", s)
	}
}

// TestIncidentTriageControllerUpgrade_ExhaustedPreservesTerminalFailure
// proves migration 0016 retains an exhausted row's terminal failure.
func TestIncidentTriageControllerUpgrade_ExhaustedPreservesTerminalFailure(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-exhausted")
	if !s.found || s.phase != "exhausted" || s.attempts != 5 {
		t.Fatalf("exhausted row = %+v, want exhausted/5/true", s)
	}
	if !s.lastErrorCode.Valid || s.lastErrorCode.String != "provider_unavailable" {
		t.Fatalf("exhausted row last_error_code = %+v, want provider_unavailable", s)
	}
}

// TestIncidentTriageControllerUpgrade_AnalyzedIncidentGainsNoSchedule
// proves an already-analyzed Incident (Finding already persisted, no
// triage row) gains no incident_triage row on upgrade.
func TestIncidentTriageControllerUpgrade_AnalyzedIncidentGainsNoSchedule(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	if s := legacyTriageRowFor(t, st, "inc-analyzed"); s.found {
		t.Fatalf("analyzed incident must gain no incident_triage row on upgrade, got %+v", s)
	}
}

// TestIncidentTriageControllerUpgrade_ReadyWithoutScheduleBecomesAwaitingDecision
// proves the one genuinely new mapping: a ready Incident with no
// pre-existing triage row gets a fresh awaiting_decision row at attempt
// zero, with no due time or started_at yet.
func TestIncidentTriageControllerUpgrade_ReadyWithoutScheduleBecomesAwaitingDecision(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	s := legacyTriageRowFor(t, st, "inc-ready-no-row")
	if !s.found || s.phase != "awaiting_decision" || s.attempts != 0 {
		t.Fatalf("ready-without-schedule row = %+v, want awaiting_decision/0/true", s)
	}
	if s.nextAt.Valid || s.startedAt.Valid {
		t.Fatalf("awaiting_decision row unexpectedly carries next_at/started_at: %+v", s)
	}
}

// TestIncidentTriageControllerUpgrade_RetainedRowsCarryNoDecisionMetadataYet
// proves the migration itself never backfills Situation ownership or
// decision metadata onto a retained row — that is Task 6's startup-only
// Go logic, run after Plan 1 reconstruction establishes ownership.
func TestIncidentTriageControllerUpgrade_RetainedRowsCarryNoDecisionMetadataYet(t *testing.T) {
	st := openIncidentTriageControllerUpgradeFixture(t)
	var situationID sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `SELECT situation_id FROM incident_triage WHERE incident_id = 'inc-backoff'`).Scan(&situationID); err != nil {
		t.Fatalf("read situation_id: %v", err)
	}
	if situationID.Valid {
		t.Fatalf("situation_id = %q, want NULL straight out of the migration (Task 6 backfills it)", situationID.String)
	}
}

// assertNoForeignKeyViolations runs PRAGMA foreign_key_check and fails the
// test if it reports any violation.
func assertNoForeignKeyViolations(ctx context.Context, t *testing.T, st *Store) {
	t.Helper()
	rows, err := st.DB().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var violations []string
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			t.Fatalf("scan foreign_key_check row: %v", err)
		}
		violations = append(violations, table+" -> "+parent)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check rows: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("foreign_key_check violations: %v", violations)
	}
}

// ----------------------------------------------------------------------
// Direct constraint/trigger tests for 0016's new incident_triage columns
// and the incident_triage_attempts ledger.
// ----------------------------------------------------------------------

// setIncidentTriagePhase writes a raw incident_triage row directly,
// bypassing every Go-level helper (none of which understand phases beyond
// pending/in_flight/backoff/skipped/exhausted yet — that is Task 6's job).
// leaseOwner/leaseExpiresAt/currentAttemptID/decisionOrigin are any so a
// caller can pass nil for "column left NULL".
func setIncidentTriagePhase(ctx context.Context, s *Store, incidentID, phase string, decisionOrigin, leaseOwner, leaseExpiresAt, currentAttemptID any) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, decision_origin, lease_owner, lease_expires_at, current_attempt_id, updated_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?)
	`, incidentID, phase, decisionOrigin, leaseOwner, leaseExpiresAt, currentAttemptID, now)
	return err
}

// TestIncidentTriageController_InFlightRequiresLeaseUnlessLegacyOrigin
// proves the phase-linked lease CHECK: a fresh (non-legacy) in_flight row
// must carry a full lease, a migrated-but-not-yet-backfilled row
// (decision_origin NULL) or a backfilled one (decision_origin=
// 'upgrade_existing_schedule') may stay temporarily ownerless, and a
// non-in_flight row must carry no lease at all.
func TestIncidentTriageController_InFlightRequiresLeaseUnlessLegacyOrigin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	insertOperationalIncident(ctx, t, s, "inc-lease-fresh-unleased", "g-lease-fresh-unleased")
	if err := setIncidentTriagePhase(ctx, s, "inc-lease-fresh-unleased", "in_flight", "controller_decision", nil, nil, nil); err == nil {
		t.Fatal("expected a fresh (non-legacy) unleased in_flight row to be rejected")
	}

	insertOperationalIncident(ctx, t, s, "inc-lease-legacy-null", "g-lease-legacy-null")
	if err := setIncidentTriagePhase(ctx, s, "inc-lease-legacy-null", "in_flight", nil, nil, nil, nil); err != nil {
		t.Fatalf("expected a migrated in_flight row with decision_origin still NULL to be accepted: %v", err)
	}

	insertOperationalIncident(ctx, t, s, "inc-lease-legacy-backfilled", "g-lease-legacy-backfilled")
	if err := setIncidentTriagePhase(ctx, s, "inc-lease-legacy-backfilled", "in_flight", "upgrade_existing_schedule", nil, nil, nil); err != nil {
		t.Fatalf("expected a backfilled upgrade_existing_schedule in_flight row to be accepted: %v", err)
	}

	insertOperationalIncident(ctx, t, s, "inc-lease-full", "g-lease-full")
	attemptID := seedIncidentTriageAttempt(ctx, t, s, "inc-lease-full")
	if err := setIncidentTriagePhase(ctx, s, "inc-lease-full", "in_flight", "controller_decision", "worker-1", now, attemptID); err != nil {
		t.Fatalf("expected a fully leased in_flight row to be accepted: %v", err)
	}

	insertOperationalIncident(ctx, t, s, "inc-lease-non-in-flight", "g-lease-non-in-flight")
	if err := setIncidentTriagePhase(ctx, s, "inc-lease-non-in-flight", "pending", nil, "worker-1", now, nil); err == nil {
		t.Fatal("expected a non-in_flight row carrying a lease to be rejected")
	}
}

// TestIncidentTriageController_DecisionEnumRejectsUnknown proves decision
// is closed to exactly request|skip.
func TestIncidentTriageController_DecisionEnumRejectsUnknown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-decision-enum", "g-decision-enum")
	now := time.Now().UTC().Format(time.RFC3339Nano)

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, decision, updated_at)
		VALUES ('inc-decision-enum', 'awaiting_decision', 0, 'maybe', ?)
	`, now); err == nil {
		t.Fatal("expected an unknown decision value to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, decision, updated_at)
		VALUES ('inc-decision-enum', 'pending', 0, 'request', ?)
	`, now); err != nil {
		t.Fatalf("expected decision='request' to be accepted: %v", err)
	}
}

// seedIncidentTriageAttempt inserts one open (uncompleted) incident_triage_attempts
// row for incidentID, anchored to a fresh Situation, and returns its id.
func seedIncidentTriageAttempt(ctx context.Context, t *testing.T, s *Store, incidentID string) string {
	t.Helper()
	situationID := "sit-for-" + incidentID
	if err := insertSituation(ctx, s, situationRow{id: situationID, groupKey: "g-" + situationID, lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation for attempt: %v", err)
	}
	attemptID := "attempt-for-" + incidentID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_triage_attempts (
			id, incident_id, attempt_number, situation_id, decision_input_version,
			membership_digest, incident_input_digest, member_delivery_ids_json, started_at
		) VALUES (?, ?, 1, ?, 1, 'sha256:members', 'sha256:input', '[]', ?)
	`, attemptID, incidentID, situationID, now); err != nil {
		t.Fatalf("insert incident_triage_attempts: %v", err)
	}
	return attemptID
}

// TestIncidentTriageController_AttemptsClaimIdentityIsImmutable proves the
// claim-time identity/snapshot columns can never change, including across
// the one legal completing update.
func TestIncidentTriageController_AttemptsClaimIdentityIsImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-claim-immutable", "g-claim-immutable")
	attemptID := seedIncidentTriageAttempt(ctx, t, s, "inc-claim-immutable")

	if _, err := s.db.ExecContext(ctx, `UPDATE incident_triage_attempts SET membership_digest = 'sha256:changed' WHERE id = ?`, attemptID); err == nil {
		t.Fatal("expected changing membership_digest to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE incident_triage_attempts SET attempt_number = 2 WHERE id = ?`, attemptID); err == nil {
		t.Fatal("expected changing attempt_number to be rejected")
	}
}

// TestIncidentTriageController_AttemptsCompleteOnceThenFrozen proves the
// one legal completing update succeeds exactly once, after which the row
// is fully frozen.
func TestIncidentTriageController_AttemptsCompleteOnceThenFrozen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-complete-once", "g-complete-once")
	attemptID := seedIncidentTriageAttempt(ctx, t, s, "inc-complete-once")
	now := time.Now().UTC().Format(time.RFC3339Nano)

	if _, err := s.db.ExecContext(ctx, `
		UPDATE incident_triage_attempts SET result_code = 'success', output_digest = 'sha256:out', completed_at = ?
		WHERE id = ?
	`, now, attemptID); err != nil {
		t.Fatalf("expected the completing update to succeed: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE incident_triage_attempts SET result_code = 'stale_membership' WHERE id = ?
	`, attemptID); err == nil {
		t.Fatal("expected a second update on a completed attempt to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM incident_triage_attempts WHERE id = ?`, attemptID); err == nil {
		t.Fatal("expected delete of a completed attempt to be rejected")
	}
}

// TestIncidentTriageController_AttemptsUniqueAttemptNumber proves the
// (incident_id,attempt_number) identity uniqueness.
func TestIncidentTriageController_AttemptsUniqueAttemptNumber(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-dup-attempt", "g-dup-attempt")
	if err := insertSituation(ctx, s, situationRow{id: "sit-dup-attempt", groupKey: "g-sit-dup-attempt", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertAttempt := func(id string) error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO incident_triage_attempts (
				id, incident_id, attempt_number, situation_id, decision_input_version,
				membership_digest, incident_input_digest, member_delivery_ids_json, started_at
			) VALUES (?, 'inc-dup-attempt', 1, 'sit-dup-attempt', 1, 'sha256:members', 'sha256:input', '[]', ?)
		`, id, now)
		return err
	}
	if err := insertAttempt("attempt-1"); err != nil {
		t.Fatalf("insert first attempt: %v", err)
	}
	if err := insertAttempt("attempt-1-dup"); err == nil {
		t.Fatal("expected a duplicate (incident_id,attempt_number) to be rejected")
	}
}
