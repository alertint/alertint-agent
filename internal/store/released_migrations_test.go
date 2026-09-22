// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

// Pin the released lineage independently of the current embedded migrations.
// Never renumber or edit these entries when adding development migrations.
func TestReleasedMigrationPrefix(t *testing.T) {
	body, err := os.ReadFile("testdata/released-v0.13.9/sha256.json")
	if err != nil {
		t.Fatal(err)
	}
	var hashes map[string]string
	if err := json.Unmarshal(body, &hashes); err != nil {
		t.Fatal(err)
	}
	for name, want := range hashes {
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Errorf("released migration %s missing: %v", name, err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Errorf("released migration %s changed: %s != %s", name, got, want)
		}
	}
}

//nolint:unqueryvet // Upgrade snapshots deliberately compare every persisted column.
func TestReleased0139UpgradePreservesDataAndCreatesDeliveryLedger(t *testing.T) {
	ctx := context.Background()
	path := migration12Fixture(t)
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("testdata/released-v0.13.9/0013_audit_log_kind_ts_idx.sql")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &Store{db: db}
	if err := fixture.applyMigration(ctx, migration{version: 13, name: "audit_log_kind_ts_idx", sql: string(body)}); err != nil {
		t.Fatal(err)
	}
	if err := audit.New(db).Append(ctx, "upgrade-test", "upgrade.fixture", map[string]string{"version": "v0.13.9"}); err != nil {
		t.Fatal(err)
	}
	auditBefore := consolidationRows(t, db, `SELECT * FROM audit_log ORDER BY seq`)
	before := consolidationRows(t, db, `SELECT * FROM alerts ORDER BY id`)
	incidents := consolidationRows(t, db, `SELECT * FROM incidents ORDER BY id`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		st, err := openTestStoreWithMigrations(ctx, path)
		if err != nil {
			t.Fatalf("upgrade/reopen %d: %v", attempt, err)
		}
		if got := consolidationRows(t, st.db, `SELECT * FROM alerts ORDER BY id`); got != before {
			t.Error("upgrade changed existing alerts")
		}
		if got := consolidationRows(t, st.db, `SELECT * FROM incidents ORDER BY id`); got != incidents {
			t.Error("upgrade changed existing incidents")
		}
		for _, name := range []string{"alert_deliveries", "alert_delivery_dispatches", "situations", "expected_behavior_envelope_heads"} {
			var n int
			if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&n); err != nil || n != 1 {
				t.Errorf("table %s missing: count=%d err=%v", name, n, err)
			}
		}
		if got := consolidationRows(t, st.db, `SELECT * FROM audit_log ORDER BY seq`); got != auditBefore {
			t.Error("upgrade changed audit history")
		}
		var n int
		if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name='audit_log_kind_ts_idx'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("released index lost: count=%d err=%v", n, err)
		}
		if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&n); err != nil || n != 0 {
			t.Errorf("foreign keys: violations=%d err=%v", n, err)
		}
		if attempt == 0 {
			if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("post-upgrade", "post-upgrade", time.Now().UTC())}); err != nil {
				t.Fatalf("durable intake after released upgrade: %v", err)
			}
			before = consolidationRows(t, st.db, `SELECT * FROM alerts ORDER BY id`)
		}
		assertTableCount(t, st.db, "alert_deliveries", 1)
		assertTableCount(t, st.db, "alert_delivery_dispatches", 1)
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReleased0139UpgradeRecoveryReconcilesLegacyMemberships(t *testing.T) {
	ctx := context.Background()
	path := migration12Fixture(t)
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	var alertID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM alerts WHERE fingerprint='pre-upgrade-fp'`).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	ts := canonicalTime(now)
	if _, err := db.ExecContext(ctx, `UPDATE incidents SET status='analyzed', group_key='legacy-a' WHERE id='pre-upgrade-incident'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents (id,group_key,status,first_alert_at,last_alert_at,ready_at,alert_count,created_at,updated_at)
		VALUES ('pre-upgrade-second','legacy-b','analyzed',?,?,?,?,?,?)`, ts, ts, ts, 1, ts, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_alerts (incident_id,alert_id,created_at) VALUES
		('pre-upgrade-incident',?,?),('pre-upgrade-second',?,?)`, alertID, ts, alertID, ts); err != nil {
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
	resolvedAt := now.Add(time.Minute)
	in := deliveryFixture("legacy-recovery", "pre-upgrade-fp", resolvedAt)
	in.Alert.Status = "resolved"
	in.Alert.EndsAt = &resolvedAt
	in.SourceStartedAt = &now
	in.SourceResolvedAt = &resolvedAt
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{in}); err != nil {
		t.Fatal(err)
	}
	claims := claimDispatches(t, st, "legacy-recovery-worker", resolvedAt, 1)
	deliveryID := claims[0].Delivery.ID
	if _, err := st.ApplyCorrelatedDelivery(ctx, CorrelatedDeliveryMutation{
		DeliveryID: deliveryID, DispatchOwner: "legacy-recovery-worker", DispatchClaimToken: claims[0].ClaimToken,
		Incident: Incident{ID: "pre-upgrade-second", GroupKey: "legacy-b", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now},
		Input:    SituationInput{ID: "legacy-recovery-input", IdempotencyKey: "delivery:legacy-recovery", IncidentID: "pre-upgrade-second", DeliveryID: &deliveryID, Kind: "membership_changed", GroupKey: "legacy-b", OccurredAt: resolvedAt},
	}); err != nil {
		t.Fatal(err)
	}
	for _, incidentID := range []string{"pre-upgrade-incident", "pre-upgrade-second"} {
		var status string
		if err := st.DB().QueryRowContext(ctx, `SELECT status FROM incidents WHERE id=?`, incidentID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "resolved" {
			t.Errorf("%s status = %q, want resolved", incidentID, status)
		}
	}
	assertTableCount(t, st.DB(), "incident_alert_deliveries", 1)
}

func TestRejectUnrenumberedStateControllerBeforeMutation(t *testing.T) {
	for _, last := range []int{13, 35, -16} {
		t.Run(fmt.Sprint(last), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "prerelease.db")
			db, err := sql.Open("sqlite", buildDSN(path))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL) STRICT`); err != nil {
				t.Fatal(err)
			}
			all, err := loadMigrations()
			if err != nil {
				t.Fatal(err)
			}
			fixture := &Store{db: db}
			version := 0
			limit := last
			if limit < 0 {
				limit = -limit
			}
			for _, m := range all {
				if last > 0 && m.name == "audit_log_kind_ts_idx" {
					continue
				}
				if last < 0 && m.name == "alert_delivery_ledger" {
					continue
				}
				version++
				if last > 0 {
					m.version = version
				}
				// Negative last reproduces a released DB after the broken
				// binary skipped the ledger and committed old versions 14–16.
				if last < 0 && m.version > 14 {
					m.version--
				}
				if m.version > limit {
					break
				}
				if err := fixture.applyMigration(ctx, m); err != nil {
					t.Fatal(err)
				}
			}
			schema := consolidationRows(t, db, `SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name`)
			ledger := consolidationRows(t, db, `SELECT version,applied_at FROM schema_migrations ORDER BY version`)
			st, err := openTestStoreWithMigrations(ctx, path)
			if st != nil {
				_ = st.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "unsupported pre-release state-controller migration lineage") {
				t.Errorf("expected actionable lineage rejection, got %v", err)
			}
			if got := consolidationRows(t, db, `SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name`); got != schema {
				t.Error("rejected open mutated schema")
			}
			if got := consolidationRows(t, db, `SELECT version,applied_at FROM schema_migrations ORDER BY version`); got != ledger {
				t.Error("rejected open mutated migration ledger")
			}
		})
	}
}
