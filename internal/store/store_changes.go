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
// change is a point-in-time event (deploy/config/flag/scale/rollback) pushed in
// over a webhook; it enriches incident triage and is never correlated into an
// incident of its own. Labels share the alert-label vocabulary so they can be
// matched against an incident's shared labels.
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

// InsertChange persists one change. Changes are append-only (no upsert): every
// POST is a distinct event.
func (s *Store) InsertChange(ctx context.Context, c Change) error {
	if err := validateChange(c); err != nil {
		return err
	}
	labelsJSON, err := json.Marshal(c.Labels)
	if err != nil {
		return fmt.Errorf("store: marshal change labels: %w", err)
	}
	var version, link any
	if c.Version != "" {
		version = c.Version
	}
	if c.Link != "" {
		link = c.Link
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO changes (id, source, kind, title, labels_json, version, link, occurred_at, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		c.ID, c.Source, c.Kind, c.Title, string(labelsJSON), version, link,
		c.OccurredAt.UTC().Format(time.RFC3339Nano), c.ReceivedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
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
