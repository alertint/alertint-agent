// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// LoadConnectorState returns the persisted value for a connector cursor by name.
// found is false (and value "") when no row exists yet — the first-run case the
// caller seeds. Used by the Sentry poller to resume its watermark across
// restarts (R14).
func (s *Store) LoadConnectorState(ctx context.Context, name string) (value string, found bool, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM connector_state WHERE name = ?`, name)
	switch err = row.Scan(&value); {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("store: load connector_state %q: %w", name, err)
	default:
		return value, true, nil
	}
}

// SaveConnectorState upserts the value for a connector cursor by name. Standalone
// (non-transactional) sibling of the watermark advance inside
// InsertChangesAndAdvanceWatermark.
func (s *Store) SaveConnectorState(ctx context.Context, name, value string) error {
	return saveConnectorState(ctx, s.db, name, value)
}

// saveConnectorState is the one place a connector_state row is written, against
// any execer, so the standalone save and the transactional advance share one
// upsert (no SQL drift).
func saveConnectorState(ctx context.Context, e execer, name, value string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := e.ExecContext(ctx, `
		INSERT INTO connector_state (name, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, name, value, now)
	if err != nil {
		return fmt.Errorf("store: save connector_state %q: %w", name, err)
	}
	return nil
}

// InsertChangesAndAdvanceWatermark inserts every change and advances the named
// connector cursor to value in a single transaction (R15). On any error the
// whole batch rolls back, so a crash mid-cycle can never leave changes persisted
// against a stale watermark (which would re-emit them) nor an advanced watermark
// with missing changes (which would drop them) — the poller's zero-duplicate /
// zero-loss guarantee. The append-only InsertChange path is reused verbatim via
// the shared insertChange helper, so a malformed change in the batch fails the
// whole tx exactly as a single InsertChange would.
func (s *Store) InsertChangesAndAdvanceWatermark(ctx context.Context, changes []Change, name, value string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, c := range changes {
		if err := insertChange(ctx, tx, c); err != nil {
			return err // rolls back via the deferred Rollback
		}
	}
	if err := saveConnectorState(ctx, tx, name, value); err != nil {
		return err
	}
	return tx.Commit()
}
