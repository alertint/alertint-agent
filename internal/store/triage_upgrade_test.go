// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

type legacyReadyRow struct {
	id       string
	groupKey string
	readyAt  time.Time
}

// seedV0134Fixture builds a database file at path shaped like v0.13.4 — every
// embedded migration through version 10 only, so no incident_triage table
// exists — and inserts the given "ready" incidents directly by SQL (the
// store API only knows migration 0011's shape and could not produce a
// pre-0011 row).
func seedV0134Fixture(t *testing.T, path string, rows []legacyReadyRow) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open raw db: %v", err)
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
	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, m := range migrations {
		if m.version > 10 {
			continue
		}
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			m.version, appliedAt,
		); err != nil {
			t.Fatalf("record migration %d: %v", m.version, err)
		}
	}

	ts := func(x time.Time) string { return x.UTC().Format(time.RFC3339Nano) }
	for _, r := range rows {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO incidents
				(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, ?, 'ready', ?, ?, ?, 1, ?, ?)
		`, r.id, r.groupKey, ts(r.readyAt), ts(r.readyAt), ts(r.readyAt), ts(r.readyAt), ts(r.readyAt)); err != nil {
			t.Fatalf("seed legacy incident %s: %v", r.id, err)
		}
	}
}

func triagePhaseFor(t *testing.T, st *Store, incidentID string) TriagePhase {
	t.Helper()
	var phase TriagePhase
	err := st.db.QueryRowContext(context.Background(),
		`SELECT phase FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&phase)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ""
		}
		t.Fatalf("triage phase: %v", err)
	}
	return phase
}

// TestTriageUpgrade_ReconcilesV0134LegacyReadyRows opens a v0.13.4-shaped
// database (migrations 0001-0010 only) with legacy "ready" incidents seeded
// directly by SQL, then opens it through Store.Open — which applies 0011 —
// and exercises the store-level reconciliation primitives a restart uses:
// a recent row becomes pending, a stale row is exhausted with the
// startup-horizon reason, and a redispatched clean skip classifies as
// skipped. The Correlator-level restart tests in Task 3 already prove the
// end-to-end dispatch behavior; this proves the primitives survive a real
// pre-0011 database.
func TestTriageUpgrade_ReconcilesV0134LegacyReadyRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	recentID := uuid.NewString()
	staleID := uuid.NewString()
	skipID := uuid.NewString()
	seedV0134Fixture(t, path, []legacyReadyRow{
		{id: recentID, groupKey: "service=recent", readyAt: now.Add(-5 * time.Minute)},
		{id: staleID, groupKey: "service=stale", readyAt: now.Add(-2 * time.Hour)},
		{id: skipID, groupKey: "service=skip", readyAt: now.Add(-10 * time.Minute)},
	})

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	legacy, err := st.ListLegacyReadyIncidents(ctx)
	if err != nil {
		t.Fatalf("list legacy: %v", err)
	}
	if len(legacy) != 3 {
		t.Fatalf("legacy ready incidents = %d, want 3", len(legacy))
	}

	for _, inc := range legacy {
		if err := st.SeedIncidentTriage(ctx, inc.ID, inc.ReadyAt); err != nil {
			t.Fatalf("seed %s: %v", inc.ID, err)
		}
	}

	// Apply the one-hour startup horizon: the stale row is overdue by more
	// than an hour and closes without a dispatch.
	for _, inc := range legacy {
		if now.Sub(inc.ReadyAt) > time.Hour {
			if _, err := st.ExhaustIncidentTriage(ctx, inc.ID, "startup_retry_window_expired", "due time exceeded the one-hour startup horizon"); err != nil {
				t.Fatalf("exhaust %s: %v", inc.ID, err)
			}
		}
	}

	if phase := triagePhaseFor(t, st, recentID); phase != TriagePending {
		t.Fatalf("recent phase = %q, want pending", phase)
	}

	staleInc, err := st.GetIncidentByID(ctx, staleID)
	if err != nil || staleInc == nil || staleInc.Status != "failed" {
		t.Fatalf("stale incident = %+v, %v, want status failed", staleInc, err)
	}
	if phase := triagePhaseFor(t, st, staleID); phase != TriageExhausted {
		t.Fatalf("stale phase = %q, want exhausted", phase)
	}

	// The remaining pending row is redispatched; a clean-skip result (the
	// skill returns nil without persisting) classifies as skipped.
	if _, err := st.BeginIncidentTriage(ctx, skipID, now); err != nil {
		t.Fatalf("begin skip: %v", err)
	}
	if err := st.SkipIncidentTriage(ctx, skipID); err != nil {
		t.Fatalf("skip: %v", err)
	}
	skipInc, err := st.GetIncidentByID(ctx, skipID)
	if err != nil || skipInc == nil || skipInc.Status != "ready" {
		t.Fatalf("skip incident = %+v, %v, want status ready", skipInc, err)
	}
	if phase := triagePhaseFor(t, st, skipID); phase != TriageSkipped {
		t.Fatalf("skip phase = %q, want skipped", phase)
	}
}
