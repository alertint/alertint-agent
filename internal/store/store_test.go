// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_AppliesEmbeddedMigrations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	rows, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer func() { _ = rows.Close() }()

	want := map[string]bool{
		"alerts":            false,
		"audit_log":         false,
		"incident_alerts":   false,
		"incidents":         false,
		"schema_migrations": false,
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("expected table %q after migrate, not found", name)
		}
	}
}

func TestMigrate_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	first, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() { _ = second.Close() }()

	var count int
	if err := second.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("load embedded migrations: %v", err)
	}
	if count != len(embedded) {
		t.Errorf("schema_migrations rows = %d, want %d (one per embedded migration) after re-open", count, len(embedded))
	}
}

func TestUpsertAlert_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	end := now.Add(5 * time.Minute)
	in := Alert{
		ID:          uuid.NewString(),
		Fingerprint: "abc123",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "HighCPU", "service": "api"},
		Annotations: map[string]string{"summary": "CPU is high"},
		StartsAt:    now,
		EndsAt:      &end,
		ReceivedAt:  now,
	}
	if _, err := s.UpsertAlertByFingerprint(ctx, in); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetAlertByFingerprint(ctx, "abc123")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != in.ID || got.Status != "firing" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.Labels["alertname"] != "HighCPU" || got.Annotations["summary"] != "CPU is high" {
		t.Errorf("labels/annotations not preserved: %+v / %+v", got.Labels, got.Annotations)
	}
	if got.EndsAt == nil || !got.EndsAt.Equal(end) {
		t.Errorf("ends_at not preserved: %v", got.EndsAt)
	}
}

func TestUpsertAlert_FingerprintDedupeUpdatesInPlace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	first := Alert{
		ID: id, Fingerprint: "fp", Status: "firing",
		Labels: map[string]string{"k": "v1"}, Annotations: map[string]string{},
		StartsAt: now, ReceivedAt: now,
	}
	if _, err := s.UpsertAlertByFingerprint(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Second call with a *different* id but same fingerprint must update
	// the existing row, keeping the original id stable.
	second := first
	second.ID = uuid.NewString()
	second.Status = "resolved"
	second.Labels = map[string]string{"k": "v2"}
	if _, err := s.UpsertAlertByFingerprint(ctx, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := s.GetAlertByFingerprint(ctx, "fp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != id {
		t.Errorf("id changed on dedupe: got %q, want %q", got.ID, id)
	}
	if got.Status != "resolved" || got.Labels["k"] != "v2" {
		t.Errorf("update not applied: %+v", got)
	}

	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("alerts row count = %d, want 1 (dedupe failed)", count)
	}
}

func TestGetAlertByFingerprint_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.GetAlertByFingerprint(ctx, "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestUpsertAlert_RejectsInvalidStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	_, err := s.UpsertAlertByFingerprint(ctx, Alert{
		ID: uuid.NewString(), Fingerprint: "x", Status: "weird",
		Labels: map[string]string{}, Annotations: map[string]string{},
		StartsAt: now, ReceivedAt: now,
	})
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestParseMigrationName(t *testing.T) {
	cases := []struct {
		in       string
		wantVer  int
		wantName string
		wantErr  bool
	}{
		{"0001_init.sql", 1, "init", false},
		{"0042_add_thing.sql", 42, "add_thing", false},
		{"bad.sql", 0, "", true},
		{"_init.sql", 0, "", true},
		{"abc_init.sql", 0, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			v, n, err := parseMigrationName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if v != tc.wantVer || n != tc.wantName {
				t.Errorf("got (%d, %q), want (%d, %q)", v, n, tc.wantVer, tc.wantName)
			}
		})
	}
}

// TestMarkIncidentResolved_FromAnalyzedAndReady is the regression test for
// the bug where the incidents.status CHECK constraint omitted 'resolved',
// causing MarkIncidentResolved to silently fail with a CHECK violation.
// It also exercises the relaxed WHERE clause that now accepts incidents
// stuck in "ready" (e.g. those that skipped LLM analysis).
func TestMarkIncidentResolved_FromAnalyzedAndReady(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	cases := []struct {
		name      string
		setStatus string
	}{
		{"analyzed", "analyzed"},
		{"ready", "ready"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := uuid.NewString()
			inc := Incident{
				ID:           id,
				GroupKey:     "test=" + tc.name,
				FirstAlertAt: now,
				LastAlertAt:  now,
				ReadyAt:      now.Add(time.Minute),
			}
			if err := s.InsertIncident(ctx, inc); err != nil {
				t.Fatalf("insert: %v", err)
			}
			if _, err := s.db.ExecContext(ctx,
				`UPDATE incidents SET status=?, updated_at=? WHERE id=?`,
				tc.setStatus, now.Format(time.RFC3339Nano), id,
			); err != nil {
				t.Fatalf("set status %s: %v", tc.setStatus, err)
			}

			if err := s.MarkIncidentResolved(ctx, id); err != nil {
				t.Fatalf("MarkIncidentResolved: %v", err)
			}

			var got string
			if err := s.db.QueryRowContext(ctx,
				`SELECT status FROM incidents WHERE id=?`, id,
			).Scan(&got); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if got != "resolved" {
				t.Errorf("status = %q, want resolved", got)
			}
		})
	}
}

// TestMarkIncidentResolved_RejectsCollecting confirms the WHERE clause
// still refuses to resolve incidents that are still actively collecting.
func TestMarkIncidentResolved_RejectsCollecting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	id := uuid.NewString()
	inc := Incident{
		ID:           id,
		GroupKey:     "test=collecting",
		FirstAlertAt: now,
		LastAlertAt:  now,
		ReadyAt:      now.Add(time.Minute),
	}
	if err := s.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert: %v", err)
	}

	err := s.MarkIncidentResolved(ctx, id)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound for collecting incident", err)
	}
}

func TestLoadMigrations_DiscoversInitMigration(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations found")
	}
	if ms[0].version != 1 || ms[0].name != "init" {
		t.Errorf("first migration = (%d, %q), want (1, %q)", ms[0].version, ms[0].name, "init")
	}
}
