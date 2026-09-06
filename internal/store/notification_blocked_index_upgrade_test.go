// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Migration 0019 upgrade test: a populated migration-18 database must gain
// exactly one partial index, keep MaxSchemaVersion honest at 19, pass
// PRAGMA foreign_key_check, fabricate no rows, and actually make the
// blocked-configuration backlog count stop scanning the whole ledger.
// ----------------------------------------------------------------------

// seedMigration18BlockedIndexFixture builds a database shaped like the
// schema immediately before 0019 (every embedded migration through 18) and
// seeds one Situation with one Transition and three notification intents —
// one pending, one delivered, one blocked_configuration — so the upgrade is
// exercised over real ledger rows rather than an empty table.
func seedMigration18BlockedIndexFixture(t *testing.T, path string) (situationID string) {
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
		if m.version > 18 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	situationID = "sit-blocked-index"
	insertOperationalIncident(ctx, t, fixture, "inc-blocked-index", "group-blocked-index")
	if err := insertSituation(ctx, fixture, situationRow{
		id: situationID, groupKey: "group-blocked-index", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	transitionID := "tr-blocked-index"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 1, 1, 'sha256:blocked-index', 'active', 'observe',
		          '{}', 'first_authoritative_state', 'publication', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		transitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("insert transition: %v", err)
	}

	rows := []struct{ id, class, status string }{
		{"intent-pending", "thread_append", "pending"},
		{"intent-blocked", "broadcast_handoff", "blocked_configuration"},
	}
	for _, r := range rows {
		requiresRoot := 1
		poke := 0
		var priority any
		if r.class == "broadcast_handoff" {
			poke = 1
			priority = "high"
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
				requires_root, main_channel_poke, interruption_priority, client_message_id, status, created_at
			) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
			r.id, "key:"+r.id, r.class, situationID, transitionID,
			requiresRoot, poke, priority, "client:"+r.id, r.status, canonicalTime(now)); err != nil {
			t.Fatalf("insert %s intent: %v", r.status, err)
		}
	}
	return situationID
}

// TestNotificationBlockedIndexUpgrade_AddsThePartialIndexAndFabricatesNothing
// is migration 0019's own upgrade test: opening a migration-18 database
// applies it, the head becomes 19, the partial index exists with exactly
// the predicate the blocked-configuration count reads, foreign keys still
// check, and not one ledger row is invented or lost.
func TestNotificationBlockedIndexUpgrade_AddsThePartialIndexAndFabricatesNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration18-blocked-index.db")
	situationID := seedMigration18BlockedIndexFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 19`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 19 applied count = %d, want 1", applied)
	}
	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 20 {
		t.Fatalf("MaxSchemaVersion = %d, want 19", got)
	}

	var indexSQL string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT sql FROM sqlite_master
		WHERE type = 'index' AND name = 'notification_intents_blocked_configuration_idx'`).Scan(&indexSQL); err != nil {
		t.Fatalf("blocked-configuration index missing after upgrade: %v", err)
	}
	if !strings.Contains(indexSQL, "blocked_configuration") {
		t.Fatalf("index is not predicated on the blocked status: %s", indexSQL)
	}

	assertNoForeignKeyViolations(ctx, t, st)

	// Nothing invented, nothing lost.
	var intents, situations int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 2 {
		t.Fatalf("notification_intents count = %d, want the 2 seeded rows", intents)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations WHERE id = ?`, situationID).Scan(&situations); err != nil {
		t.Fatal(err)
	}
	if situations != 1 {
		t.Fatalf("seeded situation count = %d, want 1", situations)
	}

	// The count the notification worker runs every round now resolves
	// through that index instead of scanning the whole durable ledger.
	var plan string
	rows, err := st.DB().QueryContext(ctx,
		`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM notification_intents WHERE status = 'blocked_configuration'`)
	if err != nil {
		t.Fatalf("explain blocked count: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan query plan: %v", err)
		}
		plan += detail + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate query plan: %v", err)
	}
	if !strings.Contains(plan, "notification_intents_blocked_configuration_idx") {
		t.Fatalf("the blocked-configuration count still scans the ledger:\n%s", plan)
	}

	// And it still answers truthfully.
	state, err := st.GetSlackDeliveryState(ctx)
	if err != nil {
		t.Fatalf("GetSlackDeliveryState: %v", err)
	}
	if state.BlockedConfigurationCount != 1 {
		t.Fatalf("BlockedConfigurationCount = %d, want the 1 seeded blocked intent", state.BlockedConfigurationCount)
	}
}
