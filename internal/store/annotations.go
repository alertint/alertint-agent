// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// MaxAnnotationNoteChars caps an operator annotation note at the write
// boundary (D6). Enforced here, not in handlers, so every write path shares it.
const MaxAnnotationNoteChars = 2000

// validAnnotationKinds is the closed kind enum. "confirmation" rows are only
// ever written by verdict capture; the annotate tool rejects it upstream.
var validAnnotationKinds = map[string]bool{
	"correction": true, "observation": true, "confirmation": true,
}

// IncidentAnnotation is one append-only operator annotation row. The latest
// row is operative; nothing is updated or deleted.
type IncidentAnnotation struct {
	ID         int64
	IncidentID string
	Kind       string // correction | observation | confirmation
	Note       string
	CreatedAt  time.Time
}

func validateAnnotation(kind, note string) error {
	if !validAnnotationKinds[kind] {
		return fmt.Errorf("store: annotation kind %q not in {correction, observation, confirmation}", kind)
	}
	if note == "" {
		return errors.New("store: annotation note is required")
	}
	if n := utf8.RuneCountInString(note); n > MaxAnnotationNoteChars {
		return fmt.Errorf("store: annotation note exceeds %d chars (got %d)", MaxAnnotationNoteChars, n)
	}
	return nil
}

// InsertIncidentAnnotation appends one annotation row. Returns ErrNotFound
// when the incident does not exist.
func (s *Store) InsertIncidentAnnotation(ctx context.Context, incidentID, kind, note string) (*IncidentAnnotation, error) {
	if err := validateAnnotation(kind, note); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin annotation tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	a, err := insertAnnotationTx(ctx, tx, incidentID, kind, note)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit annotation: %w", err)
	}
	return a, nil
}

// insertAnnotationTx is the shared tx-scoped insert used by both the annotate
// path and PersistVerdictCapture (Task 2).
func insertAnnotationTx(ctx context.Context, tx *sql.Tx, incidentID, kind, note string) (*IncidentAnnotation, error) {
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM incidents WHERE id = ?`, incidentID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: check incident: %w", err)
	}
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO incident_annotations (incident_id, kind, note, created_at)
		VALUES (?, ?, ?, ?)`,
		incidentID, kind, note, now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: insert annotation: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: annotation id: %w", err)
	}
	return &IncidentAnnotation{ID: id, IncidentID: incidentID, Kind: kind, Note: note, CreatedAt: now}, nil
}

// ListIncidentAnnotations returns every annotation of one incident,
// newest-first.
func (s *Store) ListIncidentAnnotations(ctx context.Context, incidentID string) ([]IncidentAnnotation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, incident_id, kind, note, created_at
		FROM incident_annotations WHERE incident_id = ?
		ORDER BY created_at DESC, id DESC`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("store: list annotations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []IncidentAnnotation
	for rows.Next() {
		var a IncidentAnnotation
		var created string
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.Kind, &a.Note, &created); err != nil {
			return nil, fmt.Errorf("store: scan annotation: %w", err)
		}
		if a.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, fmt.Errorf("store: parse annotation created_at: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OperatorAnnotation is one recalled operator annotation for the human-locked
// memory tier (ADR-0028): fetched by group key over the recall lookback.
type OperatorAnnotation struct {
	IncidentID string
	Kind       string
	Note       string
	CreatedAt  time.Time
}

// OperatorAnnotations returns every annotation on the key's
// incidents within the lookback, newest-first, filtered to the caller's drill
// side (a real triage recalls only real incidents' notes and vice versa).
// Unlike prior-finding recall it does NOT exclude the current incident: a
// re-judgment must recall a correction captured on the incident itself.
func (s *Store) OperatorAnnotations(ctx context.Context, groupKey string, currentIsDrill bool, since time.Time) ([]OperatorAnnotation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.incident_id, a.kind, a.note, a.created_at
		FROM incident_annotations a
		JOIN incidents i ON i.id = a.incident_id
		WHERE i.group_key = ? AND a.created_at >= ?
		ORDER BY a.created_at DESC, a.id DESC`,
		groupKey, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: operator annotations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var all []OperatorAnnotation
	for rows.Next() {
		var a OperatorAnnotation
		var created string
		if err := rows.Scan(&a.IncidentID, &a.Kind, &a.Note, &created); err != nil {
			return nil, fmt.Errorf("store: scan operator annotation: %w", err)
		}
		if a.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, fmt.Errorf("store: parse operator annotation created_at: %w", err)
		}
		all = append(all, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(all))
	seen := make(map[string]bool, len(all))
	for _, a := range all {
		if !seen[a.IncidentID] {
			seen[a.IncidentID] = true
			ids = append(ids, a.IncidentID)
		}
	}
	flags, err := s.IncidentDrillFlags(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, a := range all {
		if flags[a.IncidentID] == currentIsDrill {
			out = append(out, a)
		}
	}
	return out, nil
}

// SetRefuteMarksFloor raises memory_refute_marks to at least floor — the D3
// correction demotion (idempotent; never lowers an already-higher count).
func (s *Store) SetRefuteMarksFloor(ctx context.Context, incidentID string, floor int) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET memory_refute_marks = MAX(memory_refute_marks, ?)
		WHERE id = ?`, floor, incidentID)
	if err != nil {
		return fmt.Errorf("store: set refute marks floor: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: refute marks floor rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
