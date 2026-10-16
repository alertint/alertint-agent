// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestProfileHeadHistoryUpgradePreservesPublishedHeads(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "profile-head-upgrade.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	fixture := &Store{db: db}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version > 45 {
			break
		}
		if err := fixture.applyMigration(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}
	ids := seedGuidanceProfiles(t, fixture, 2)
	if _, err := db.ExecContext(context.Background(), `INSERT INTO semantic_profile_versions(id,signature_key,version,schema_version,prompt_version,semantic_input_digest,origin,profile_json,created_at,asserted_by)
		SELECT 'unpublished-version',signature_key,99,1,1,'digest','correction',profile_json,created_at,asserted_by FROM semantic_profile_versions WHERE id='guidance-version-0000'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	assertTableCount(t, st.db, "semantic_profile_head_history", 2)
	_, versions, err := st.LoadProfileGuidanceForDeliveries(ctx, ids)
	if err != nil || len(versions) != 2 || versions[0] != "guidance-version-0000" {
		t.Fatalf("upgrade selected an unpublished version: versions=%v err=%v", versions, err)
	}
	if _, err := st.db.ExecContext(context.Background(), `UPDATE semantic_profile_heads SET current_version=99,version_id='unpublished-version' WHERE signature_key='guidance-signature-0000'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `DELETE FROM semantic_profile_heads WHERE signature_key='guidance-signature-0001'`); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, st.db, "semantic_profile_head_history", 4)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM semantic_profile_heads`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, st.db, "semantic_profile_head_history", 4)
	assertTableCount(t, st.db, "semantic_profile_heads", 1)
	guidance, versions, err := st.LoadProfileGuidanceForDeliveries(ctx, ids)
	if err != nil || len(guidance) != 1 || len(versions) != 1 || versions[0] != "unpublished-version" {
		t.Fatalf("published/deleted heads: guidance=%+v versions=%v err=%v", guidance, versions, err)
	}
	for _, statement := range []string{
		`UPDATE semantic_profile_head_history SET signature_key='changed'`,
		`DELETE FROM semantic_profile_head_history`,
	} {
		if _, err := st.db.ExecContext(context.Background(), statement); err == nil {
			t.Fatalf("head history must remain immutable: %s", statement)
		}
	}
	if err := st.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, st.db, "semantic_profile_head_history", 4)
	rows, err := st.db.QueryContext(context.Background(), `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		t.Fatal("upgrade left foreign-key violations")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
