// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Change is the in-memory representation of a row in the changes table. A
// change is a point-in-time event (deploy/release/config/flag/scale/rollback).
// It is acquisition-agnostic: a change may be pushed in over a webhook by the
// change Receiver, or pulled and synthesized by a Change source (e.g. the Sentry
// release/deploy poller). Either way it enriches incident triage and is never
// correlated into an incident of its own. Labels carry alert-label vocabulary or
// a source's own keys so they can be matched against an incident's shared labels.
type Change struct {
	ID         string
	Source     string // "" is normalized to "unknown" at parse time
	Kind       string
	Title      string
	Labels     map[string]string
	Version    string // optional
	Link       string // optional
	OccurredAt time.Time
	ReceivedAt time.Time
}

// execer is the ExecContext-only seam satisfied by both *sql.DB and *sql.Tx, so
// the single change-INSERT path serves both the append-only InsertChange (on the
// db) and the transactional batch insert (on a tx) without SQL drift.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// InsertChange persists one change. Changes are append-only (no upsert): every
// acquired change — a received webhook or a polled deploy/release — is a
// distinct event. Idempotency (not re-acquiring the same source event) is the
// acquirer's job, not the store's.
func (s *Store) InsertChange(ctx context.Context, c Change) error {
	return insertChange(ctx, s.db, c)
}

// changeColumns is the shared column list so the append-only and batch insert
// paths can't drift.
const changeColumns = `(id, source, kind, title, labels_json, version, link, occurred_at, received_at)`

// changeRowArgs validates c, marshals its labels, and builds the positional args
// for a changes INSERT — shared by both insert paths so the column order stays in
// lockstep with changeColumns.
func changeRowArgs(c Change) ([]any, error) {
	if err := validateChange(c); err != nil {
		return nil, err
	}
	labelsJSON, err := json.Marshal(c.Labels)
	if err != nil {
		return nil, fmt.Errorf("store: marshal change labels: %w", err)
	}
	var version, link any
	if c.Version != "" {
		version = c.Version
	}
	if c.Link != "" {
		link = c.Link
	}
	return []any{
		c.ID, c.Source, c.Kind, c.Title, string(labelsJSON), version, link,
		c.OccurredAt.UTC().Format(time.RFC3339Nano), c.ReceivedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

// insertChange is the append-only single-row write used by InsertChange (the
// change Receiver): a plain INSERT where a duplicate id is a real fault. It
// passes s.db, byte-identical to the pre-extraction behavior (R17).
func insertChange(ctx context.Context, e execer, c Change) error {
	args, err := changeRowArgs(c)
	if err != nil {
		return err
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO changes `+changeColumns+` VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
		return fmt.Errorf("store: insert change: %w", err)
	}
	return nil
}

// insertChangeIgnoreDup is the batch write used only by the poller's
// InsertChangesAndAdvanceWatermark: identical to insertChange but treats an
// existing id as a no-op (ON CONFLICT(id) DO NOTHING) rather than an error. The
// watermark is the idempotency authority, so a change already on disk — a re-emit
// whose OccurredAt advanced, or a re-scan after the watermark was lost or
// reseeded — must not collide and roll the whole cycle back (which never advances
// the watermark and would wedge the poller permanently). The append-only
// InsertChange stays strict (R17).
func insertChangeIgnoreDup(ctx context.Context, e execer, c Change) error {
	args, err := changeRowArgs(c)
	if err != nil {
		return err
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO changes `+changeColumns+` VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, args...); err != nil {
		return fmt.Errorf("store: insert change: %w", err)
	}
	return nil
}

// ChangesInWindow returns changes whose occurred_at is in [start, end],
// newest-first. The window is small and occurred_at is indexed, so this is one
// cheap range scan; label-overlap matching happens in Go at the call site.
func (s *Store) ChangesInWindow(ctx context.Context, start, end time.Time) ([]Change, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source, kind, title, labels_json, version, link, occurred_at, received_at
		FROM changes
		WHERE occurred_at BETWEEN ? AND ?
		ORDER BY occurred_at DESC
	`, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: changes in window: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanChangeRows(rows)
}

// PruneChanges deletes changes whose occurred_at is strictly before the cutoff.
// Returns the number of rows removed. Called on insert and once at startup.
func (s *Store) PruneChanges(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM changes WHERE occurred_at < ?
	`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("store: prune changes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune changes rows: %w", err)
	}
	return n, nil
}

func scanChangeRows(rows *sql.Rows) ([]Change, error) {
	var out []Change
	for rows.Next() {
		var (
			c           Change
			labelsJSON  string
			version     sql.NullString
			link        sql.NullString
			occurredStr string
			receivedStr string
		)
		if err := rows.Scan(&c.ID, &c.Source, &c.Kind, &c.Title, &labelsJSON, &version, &link, &occurredStr, &receivedStr); err != nil {
			return nil, fmt.Errorf("store: scan change row: %w", err)
		}
		if err := json.Unmarshal([]byte(labelsJSON), &c.Labels); err != nil {
			return nil, fmt.Errorf("store: unmarshal change labels: %w", err)
		}
		c.Version = version.String
		c.Link = link.String
		t, err := time.Parse(time.RFC3339Nano, occurredStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse occurred_at: %w", err)
		}
		c.OccurredAt = t
		t, err = time.Parse(time.RFC3339Nano, receivedStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse received_at: %w", err)
		}
		c.ReceivedAt = t
		out = append(out, c)
	}
	return out, rows.Err()
}

func validateChange(c Change) error {
	switch {
	case c.ID == "":
		return errors.New("store: change.id is required")
	case c.Kind == "":
		return errors.New("store: change.kind is required")
	case c.Title == "":
		return errors.New("store: change.title is required")
	case c.Source == "":
		return errors.New("store: change.source is required")
	case len(c.Labels) == 0:
		return errors.New("store: change.labels must be non-empty")
	case c.OccurredAt.IsZero():
		return errors.New("store: change.occurred_at is required")
	case c.ReceivedAt.IsZero():
		return errors.New("store: change.received_at is required")
	}
	return nil
}
