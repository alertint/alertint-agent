// SPDX-License-Identifier: FSL-1.1-ALv2

// Package storetest holds test-only fixtures over the store's database that
// no production path may call. It exists so a helper needed by tests in
// more than one package (internal/store and internal/correlator) does not
// have to live on the production Store type. It deliberately imports only
// database/sql, never internal/store, so internal/store's own in-package
// tests can use it without an import cycle.
package storetest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotPromoted reports an awaiting_decision row that was not promoted.
var ErrNotPromoted = errors.New("storetest: incident triage row not promoted")

// SeedIncidentTriage moves incidentID's Acute Triage schedule straight into
// the live pending dispatch loop, due at due, bypassing the controller's
// own B+ decision. Production has no such path: every ready Incident begins
// awaiting_decision (MarkIncidentReadyWithSituationInput) and only a fenced
// CommitController decision can request or skip it. Tests that exercise the
// pre-decision schedule mechanics (attachment during backoff, the startup
// horizon, lease fencing) use this to reach pending without driving a whole
// controller cycle. A row with no incident_triage entry at all (a fixture
// that used the plain MarkIncidentReady) gets a fresh pending insert; a
// fresh awaiting_decision row with zero attempts is promoted; anything else
// is an error.
func SeedIncidentTriage(ctx context.Context, db *sql.DB, incidentID string, due time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	dueStr := due.UTC().Format(time.RFC3339Nano)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storetest: begin seed incident triage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var phase string
	var attempts int
	err = tx.QueryRowContext(ctx, `SELECT phase, attempts FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&phase, &attempts)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO incident_triage (incident_id, phase, attempts, next_at, updated_at)
			VALUES (?, 'pending', 0, ?, ?)`, incidentID, dueStr, now); err != nil {
			return fmt.Errorf("storetest: seed incident triage: %w", err)
		}
	case err != nil:
		return fmt.Errorf("storetest: seed incident triage: read existing row: %w", err)
	case phase == "awaiting_decision" && attempts == 0:
		res, err := tx.ExecContext(ctx, `
			UPDATE incident_triage SET phase = 'pending', next_at = ?, updated_at = ?
			WHERE incident_id = ? AND phase = 'awaiting_decision'`, dueStr, now, incidentID)
		if err != nil {
			return fmt.Errorf("storetest: seed incident triage: promote awaiting_decision: %w", err)
		}
		if n, rerr := res.RowsAffected(); rerr != nil {
			return fmt.Errorf("storetest: seed incident triage: count promoted rows: %w", rerr)
		} else if n != 1 {
			return ErrNotPromoted
		}
	default:
		return fmt.Errorf("storetest: seed incident triage: incident %s already has a triage row in phase %q", incidentID, phase)
	}
	return tx.Commit()
}
