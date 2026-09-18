// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyPlan4LineageRefusedBeforeMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// The ambiguous pre-release lineage has preparation tables but no
	// operator reply_kind column, regardless of its last evidence migration.
	if _, err := db.ExecContext(ctx, `CREATE TABLE situation_preparation_cycles(id TEXT); CREATE TABLE notification_intents(id TEXT); CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT); INSERT INTO schema_migrations VALUES(22,'legacy');`); err != nil {
		t.Fatal(err)
	}
	_, err = Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "unsupported pre-release Plan 4") {
		t.Fatalf("Open error=%v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration ledger mutated: count=%d err=%v", count, err)
	}
}
