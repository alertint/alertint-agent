// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestAlertDeliveryAuthorityIndexUpgradePreservesRetainedHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration37-authority-index.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	fixture := &Store{db: db}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version >= 38 {
			break
		}
		if err := fixture.applyMigration(ctx, migration); err != nil {
			t.Fatalf("apply migration %d: %v", migration.version, err)
		}
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	deliveries := make([]DeliveryInput, 1000)
	for i := range deliveries {
		deliveries[i] = deliveryFixture(fmt.Sprintf("upgrade-authority-%04d", i), "fp-upgrade-authority", now.Add(time.Duration(i)*time.Second))
	}
	if _, err := fixture.AcceptDeliveries(ctx, deliveries); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgraded.Close() }()
	assertTableCount(t, upgraded.DB(), "alert_deliveries", len(deliveries))
	var version, indexCount int
	if err := upgraded.DB().QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 39 {
		t.Fatalf("schema version = %d, want 39", version)
	}
	if err := upgraded.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='alert_deliveries_alert_authority_idx'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("authority index count = %d, want 1", indexCount)
	}
}
