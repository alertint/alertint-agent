// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenMigratesExisting0010DatabaseToDeliveryLedger(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "from-0010.db")
	db, err := sql.Open("sqlite", buildDSN(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Store{db: db}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	files, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range files {
		if migration.version > 10 {
			break
		}
		if err := legacy.applyMigration(ctx, migration); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.version, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open migrated database: %v", err)
	}
	defer func() { _ = upgraded.Close() }()
	if n := deliveryRowCount(t, upgraded, "alert_deliveries"); n != 0 {
		t.Fatalf("deliveries=%d, want 0 after migration", n)
	}
}

func TestAcceptDeliveriesIsAtomicAndAppendOnly(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	in := []DeliveryInput{
		{
			ID:     "d1",
			Alert:  Alert{ID: "a1", Fingerprint: "fp1", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp1:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:a",
		},
		{
			ID:     "d2",
			Alert:  Alert{ID: "a2", Fingerprint: "fp2", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp2:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:b",
		},
	}
	got, err := s.AcceptDeliveries(context.Background(), in)
	if err != nil || len(got) != 2 {
		t.Fatalf("got=%d err=%v", len(got), err)
	}
	if _, err := s.AcceptDeliveries(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if n := deliveryRowCount(t, s, "alert_deliveries"); n != 2 {
		t.Fatalf("deliveries=%d", n)
	}
	if n := deliveryRowCount(t, s, "alert_delivery_dispatches"); n != 2 {
		t.Fatalf("dispatches=%d", n)
	}
}

func TestAcceptDeliveriesRollsBackWholeEnvelope(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	in := []DeliveryInput{
		{
			ID:     "d1",
			Alert:  Alert{ID: "a1", Fingerprint: "fp1", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp1:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:a",
		},
		{
			ID:     "d2",
			Alert:  Alert{ID: "a2", Fingerprint: "fp2", Status: "invalid", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp2:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:b",
		},
	}
	if _, err := s.AcceptDeliveries(context.Background(), in); err == nil {
		t.Fatal("AcceptDeliveries accepted an invalid envelope")
	}
	if n := deliveryRowCount(t, s, "alerts"); n != 0 {
		t.Fatalf("alerts=%d, want 0", n)
	}
	if n := deliveryRowCount(t, s, "alert_deliveries"); n != 0 {
		t.Fatalf("deliveries=%d, want 0", n)
	}
}

func deliveryRowCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
