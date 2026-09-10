// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Migration 0023 upgrade test (D1, lead reviews 2026-09-10 rounds 2 and 3):
// a populated migration-22 database must swap
// notification_intents_thread_supersession_guard for the candidate-based
// one, keep every other trigger, index, CHECK and row exactly as it found
// them, pass PRAGMA foreign_key_check, and change the guard's verdict in
// BOTH directions — admitting the pure assurance 0022 refused, and
// refusing the mixed material row 0022's unconditional label rule admitted.
//
// The before/after verdicts are taken from the SAME database, seconds
// apart, so "the guard changed" is measured rather than asserted.
// ----------------------------------------------------------------------

// assuranceGuardRow is one seeded reply and the verdict each guard reaches
// for it.
type assuranceGuardRow struct {
	name           string
	journalKind    string
	projectionJSON string
	// under0022 is what 0022's `journal_kind = 'investigation_started'`
	// rule permits; under0023 is what the candidate rule permits.
	under0022 bool
	under0023 bool
	intentID  string
}

func assuranceGuardRows() []assuranceGuardRow {
	return []assuranceGuardRow{
		{
			name:           "the D1 row: a pure assurance journalled operator_contract_changed",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"}]}}`,
			under0022:      false,
			under0023:      true,
		},
		{
			name:           "mixed material journalled investigation_started",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":"members_changed"}]}}`,
			under0022:      true,
			under0023:      false,
		},
		{
			name:           "a legacy projection with no candidate list, journalled investigation_started",
			journalKind:    "investigation_started",
			projectionJSON: `{}`,
			under0022:      true,
			under0023:      true,
		},
		{
			name:           "an ordinary finding reply",
			journalKind:    "evidence_conclusion",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"useful_finding"}]}}`,
			under0022:      false,
			under0023:      false,
		},
	}
}

// seedMigration22AssuranceGuardFixture builds a database at exactly schema
// 22 and seeds one Situation with a Transition and a live pending
// thread_append for every row above, plus one delivered reply to point
// replacements at.
func seedMigration22AssuranceGuardFixture(t *testing.T, path string, rows []assuranceGuardRow) (replacementID string) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range migrations {
		if m.version > 22 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	situationID := "sit-assurance-guard"
	insertOperationalIncident(ctx, t, fixture, "inc-assurance-guard", "group-assurance-guard")
	if err := insertSituation(ctx, fixture, situationRow{
		id: situationID, groupKey: "group-assurance-guard", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	seed := func(seq int, journalKind, projectionJSON, status string) string {
		transitionID := fmt.Sprintf("tr-guard-%d", seq)
		intentID := fmt.Sprintf("intent-guard-%d", seq)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO situation_transitions (
				id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
				action_contract_json, reason, journal_kind, journal_json, projection_json,
				evidence_refs_json, actor, created_at
			) VALUES (?, ?, ?, 1, ?, 'active', 'observe', '{}', 'operator_contract_changed', ?, '{}', ?, '[]',
			          'deterministic_controller', ?)`,
			transitionID, situationID, seq, fmt.Sprintf("sha256:guard-%d", seq), journalKind,
			projectionJSON, canonicalTime(now)); err != nil {
			t.Fatalf("seed transition %d: %v", seq, err)
		}
		if status == "delivered" {
			if _, err := db.ExecContext(ctx, `
				INSERT INTO notification_intents (
					id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
					requires_root, main_channel_poke, client_message_id, status,
					delivered_as, channel, message_ts, delivered_at, created_at
				) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, 'delivered', 'thread', 'C', '1.1', ?, ?)`,
				intentID, "key:"+intentID, situationID, transitionID, seq, "client:"+intentID,
				canonicalTime(now), canonicalTime(now)); err != nil {
				t.Fatalf("seed delivered intent %d: %v", seq, err)
			}
			return intentID
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
				requires_root, main_channel_poke, client_message_id, status, created_at
			) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, 'pending', ?)`,
			intentID, "key:"+intentID, situationID, transitionID, seq, "client:"+intentID,
			canonicalTime(now)); err != nil {
			t.Fatalf("seed pending intent %d: %v", seq, err)
		}
		return intentID
	}

	replacementID = seed(1, "evidence_conclusion", `{"operator_delta":{"candidates":[{"kind":"useful_finding"}]}}`, "delivered")
	for i := range rows {
		rows[i].intentID = seed(i+2, rows[i].journalKind, rows[i].projectionJSON, "pending")
	}
	return replacementID
}

// guardPermits attempts the exact supersession UPDATE the store runs and
// reports whether the installed guard allowed it, ALWAYS rolling back so
// the row and the verdict stay independent.
func guardPermits(ctx context.Context, t *testing.T, db *sql.DB, intentID, replacementID string) bool {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin guard probe: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		UPDATE notification_intents
		   SET status = 'superseded', supersession_reason = 'superseded_by_finding', replacement_intent_id = ?
		 WHERE id = ?`, replacementID, intentID)
	if err == nil {
		return true
	}
	if !strings.Contains(err.Error(), "superseded thread_append must") {
		t.Fatalf("the UPDATE for %s failed for a reason that is not the supersession guard: %v", intentID, err)
	}
	return false
}

// guardTriggerSQL reads the installed trigger's own text out of
// sqlite_master, so "the guard was replaced" is read from the database
// rather than inferred from the migration file.
func guardTriggerSQL(ctx context.Context, t *testing.T, db *sql.DB) string {
	t.Helper()
	var text string
	if err := db.QueryRowContext(ctx, `
		SELECT sql FROM sqlite_master
		 WHERE type = 'trigger' AND name = 'notification_intents_thread_supersession_guard'`).Scan(&text); err != nil {
		t.Fatalf("read the installed guard trigger: %v", err)
	}
	return text
}

func TestAssuranceCandidateGuardUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration22-assurance-guard.db")
	rows := assuranceGuardRows()
	replacementID := seedMigration22AssuranceGuardFixture(t, path, rows)

	// ---- before: schema 22, the journal-label guard ----
	before, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("reopen fixture: %v", err)
	}
	beforeSQL := guardTriggerSQL(ctx, t, before)
	if !strings.Contains(beforeSQL, "investigation_started transition") {
		t.Fatalf("the seeded database is not carrying 0022's guard:\n%s", beforeSQL)
	}
	for _, r := range rows {
		if got := guardPermits(ctx, t, before, r.intentID, replacementID); got != r.under0022 {
			t.Errorf("before the upgrade, 0022's guard permits %q = %v, want %v", r.name, got, r.under0022)
		}
	}
	var seededIntents, seededTransitions int
	if err := before.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&seededIntents); err != nil {
		t.Fatal(err)
	}
	if err := before.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions`).Scan(&seededTransitions); err != nil {
		t.Fatal(err)
	}
	if err := before.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	// ---- upgrade ----
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 23`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 23 applied count = %d, want 1", applied)
	}
	assertNoForeignKeyViolations(ctx, t, st)

	// ---- after: the candidate guard, same database, same rows ----
	afterSQL := guardTriggerSQL(ctx, t, st.DB())
	if !strings.Contains(afterSQL, "purely transient first_execution_assurance") {
		t.Fatalf("0023 did not install its own guard:\n%s", afterSQL)
	}
	if strings.Contains(afterSQL, "NEW.transition_id AND tr.journal_kind = 'investigation_started'") {
		t.Fatalf("0023 left 0022's unconditional label rule in place:\n%s", afterSQL)
	}
	for _, r := range rows {
		if got := guardPermits(ctx, t, st.DB(), r.intentID, replacementID); got != r.under0023 {
			t.Errorf("after the upgrade, 0023's guard permits %q = %v, want %v", r.name, got, r.under0023)
		}
	}

	// Nothing was rebuilt, rewritten or fabricated: 0023 is a trigger swap.
	var intents, transitions int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if intents != seededIntents || transitions != seededTransitions {
		t.Fatalf("row counts after upgrade: %d intents / %d transitions, want the seeded %d / %d",
			intents, transitions, seededIntents, seededTransitions)
	}
	var statuses string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT group_concat(status, ',') FROM (SELECT status FROM notification_intents ORDER BY id)`).Scan(&statuses); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statuses, "superseded") {
		t.Fatalf("the upgrade itself superseded a row: statuses = %s", statuses)
	}
	// Every journal_kind the fixture recorded survived verbatim: 0023
	// relabels nothing.
	var kinds string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT group_concat(journal_kind, ',') FROM (SELECT journal_kind FROM situation_transitions ORDER BY sequence)`).Scan(&kinds); err != nil {
		t.Fatal(err)
	}
	want := "evidence_conclusion,operator_contract_changed,investigation_started,investigation_started,evidence_conclusion"
	if kinds != want {
		t.Fatalf("journal kinds after upgrade = %s, want the seeded %s", kinds, want)
	}

	// 0020's live-only rule and 0018's immutability rules survived the
	// trigger swap: 0023 drops exactly one trigger.
	for _, name := range []string{
		"notification_intents_transition_guard",
		"notification_intents_identity_immutable",
		"notification_intents_no_delete",
		"notification_intents_supersede_from_live_only",
		"notification_intents_thread_supersession_guard",
	} {
		var n int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?`, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("trigger %s present %d time(s) after the upgrade, want 1", name, n)
		}
	}
}

// TestAssuranceCandidateGuardOnAFreshDatabase proves the same guard is what
// a database created from scratch gets — an upgrade-only fix would leave
// every new installation on the old rule.
func TestAssuranceCandidateGuardOnAFreshDatabase(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	text := guardTriggerSQL(ctx, t, st.DB())
	if !strings.Contains(text, "purely transient first_execution_assurance") {
		t.Fatalf("a fresh database does not carry 0023's guard:\n%s", text)
	}
	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 23`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 23 applied count on a fresh database = %d, want 1", applied)
	}

	situationID := "sit-fresh-guard"
	insertOperationalIncident(ctx, t, st, "inc-fresh-guard", "group-fresh-guard")
	if err := insertSituation(ctx, st, situationRow{
		id: situationID, groupKey: "group-fresh-guard", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	replacementID := seedAssuranceParityRow(ctx, t, st, situationID, 1, assuranceParityCase{
		journalKind: "evidence_conclusion", projectionJSON: `{}`,
	})
	for i, r := range assuranceGuardRows() {
		intentID := seedAssuranceParityRow(ctx, t, st, situationID, i+2, assuranceParityCase{
			name: r.name, journalKind: r.journalKind, projectionJSON: r.projectionJSON,
		})
		if got := guardPermits(ctx, t, st.DB(), intentID, replacementID); got != r.under0023 {
			t.Errorf("on a fresh database the guard permits %q = %v, want %v", r.name, got, r.under0023)
		}
	}
}
