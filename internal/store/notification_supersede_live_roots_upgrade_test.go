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
// Migration 0020 upgrade test: a populated migration-19 database must have
// its supersession trigger replaced (a blocked or failed root projection
// may now be superseded by a newer one; a delivered one still may not),
// keep MaxSchemaVersion honest at 20, pass PRAGMA foreign_key_check, and
// fabricate no rows.
// ----------------------------------------------------------------------

func seedMigration19SupersedeFixture(t *testing.T, path string) (blockedRootID, deliveredRootID string) {
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
		if m.version > 19 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	situationID := "sit-supersede-live"
	insertOperationalIncident(ctx, t, fixture, "inc-supersede-live", "group-supersede-live")
	if err := insertSituation(ctx, fixture, situationRow{
		id: situationID, groupKey: "group-supersede-live", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	transitionID := "tr-supersede-live"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 1, 1, 'sha256:supersede-live', 'active', 'observe',
		          '{}', 'first_authoritative_state', 'publication', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		transitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("insert transition: %v", err)
	}
	blockedRootID = "root-blocked"
	deliveredRootID = "root-delivered"
	for _, row := range []struct{ id, status, extra string }{
		{blockedRootID, "blocked_configuration", "last_error_class"},
		{deliveredRootID, "delivered", ""},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence, summary_version, requires_root,
				main_channel_poke, client_message_id, status, last_error_class,
				delivered_as, channel, message_ts, delivered_at, created_at
			) VALUES (?, ?, 'root_sync', ?, ?, 1, 1, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.id, "idem:"+row.id, situationID, transitionID, "client:"+row.id, row.status,
			nullIf(row.extra == "", "channel_not_found"),
			nullIf(row.status != "delivered", "root"), nullIf(row.status != "delivered", "C"),
			nullIf(row.status != "delivered", "1.1"), nullIf(row.status != "delivered", canonicalTime(now)),
			canonicalTime(now)); err != nil {
			t.Fatalf("seed %s root: %v", row.status, err)
		}
	}
	return blockedRootID, deliveredRootID
}

// nullIf returns NULL when cond holds, else value.
func nullIf(cond bool, value string) any {
	if cond {
		return nil
	}
	return value
}

func TestNotificationSupersedeLiveRootsUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upgrade-20.db")
	blockedRootID, deliveredRootID := seedMigration19SupersedeFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open (apply migration 0020): %v", err)
	}
	defer func() { _ = st.Close() }()

	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 20 {
		t.Fatalf("MaxSchemaVersion = %d, want 20", got)
	}
	var version int
	if err := st.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 20 {
		t.Fatalf("applied schema version = %d (err=%v), want 20", version, err)
	}
	var fkViolations int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&fkViolations); err != nil || fkViolations != 0 {
		t.Fatalf("foreign_key_check violations = %d (err=%v), want 0", fkViolations, err)
	}
	var triggers string
	rows, err := st.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'notification_intents_supersede%'`)
	if err != nil {
		t.Fatalf("list triggers: %v", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan trigger: %v", err)
		}
		triggers += name + ";"
	}
	_ = rows.Close()
	if strings.Contains(triggers, "from_pending_only") || !strings.Contains(triggers, "from_live_only") {
		t.Fatalf("supersession triggers after upgrade = %q, want only notification_intents_supersede_from_live_only", triggers)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents`); n != 2 {
		t.Fatalf("notification intents after upgrade = %d, want the 2 seeded rows (nothing fabricated)", n)
	}

	// A blocked root projection may now be superseded by a newer one.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'newer_root_projection',
		       replacement_intent_id = ?, last_error_class = NULL
		WHERE id = ?`, deliveredRootID, blockedRootID); err != nil {
		t.Fatalf("supersede a blocked root after 0020: %v", err)
	}
	// A delivered one still may not.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'newer_root_projection',
		       replacement_intent_id = ?, delivered_as = NULL, channel = NULL, message_ts = NULL, delivered_at = NULL
		WHERE id = ?`, blockedRootID, deliveredRootID); err == nil || !strings.Contains(err.Error(), "live root_sync") {
		t.Fatalf("superseding a delivered root = %v, want the 0020 trigger's rejection", err)
	}
}
