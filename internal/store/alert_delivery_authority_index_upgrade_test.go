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
	if err := fixture.InsertIncident(ctx, Incident{ID: "upgrade-page-owner", GroupKey: "upgrade", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)`, "upgrade-page-owner", deliveries[0].ID, canonicalTime(now)); err != nil {
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
	if version != 48 {
		t.Fatalf("schema version = %d, want 48", version)
	}
	if err := upgraded.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='alert_deliveries_alert_authority_idx'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("authority index count = %d, want 1", indexCount)
	}
	for _, name := range []string{"alert_deliveries_alert_id_page_idx", "alert_deliveries_judgment_authority_idx"} {
		var count int
		if err := upgraded.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name=?`, name).Scan(&count); err != nil || count != 1 {
			t.Fatalf("index %s count=%d err=%v", name, count, err)
		}
	}
	var projected int
	if err := upgraded.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_delivery_alerts WHERE incident_id='upgrade-page-owner' AND alert_id=?`, deliveries[0].Alert.ID).Scan(&projected); err != nil || projected != 1 {
		t.Fatalf("backfilled owned Alert keys=%d err=%v", projected, err)
	}
	if err := upgraded.InsertIncident(ctx, Incident{ID: "upgrade-page-new-owner", GroupKey: "upgrade-new", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.DB().ExecContext(ctx, `INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)`, "upgrade-page-new-owner", deliveries[1].ID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_delivery_alerts WHERE incident_id='upgrade-page-new-owner' AND alert_id=?`, deliveries[1].Alert.ID).Scan(&projected); err != nil || projected != 1 {
		t.Fatalf("new owned Alert keys=%d err=%v", projected, err)
	}
}
