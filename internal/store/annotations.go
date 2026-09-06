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
// when the incident does not exist. Task 8: in the SAME transaction, when
// the Incident currently belongs to a nonterminal Situation, this also
// enqueues exactly one operator_annotation_recorded situation_input_outbox
// row referencing the new annotation — see enqueueOperatorArtifactInputTx.
// With no owner at all (or an already-terminal one), only the annotation is
// persisted; it stays visible through Incident MCP/audit either way.
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
	idempotencyKey := fmt.Sprintf("operator-annotation:%d", a.ID)
	if err := enqueueOperatorArtifactInputTx(ctx, tx, incidentID, "operator_annotation_recorded", idempotencyKey, a.ID, nil, a.CreatedAt); err != nil {
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

// enqueueOperatorArtifactInputTx atomically enqueues one situation_input_outbox
// row for a durable operator artifact — an attributed annotation
// (kind="operator_annotation_recorded", annotationID set, verdictID nil) or
// a Captured verdict (kind="captured_verdict_recorded", verdictID set,
// annotationID nil) — that the caller already persisted earlier in this
// SAME transaction (insertAnnotationTx / PersistVerdictCapture's verdict
// insert). Shared by both InsertIncidentAnnotation and PersistVerdictCapture
// (verdicts.go).
//
// It enqueues ONLY when incidentID currently belongs to a Situation whose
// lifecycle is nonterminal right now: an Incident with no owning Situation
// at all keeps the artifact visible only through Incident MCP/audit (no
// outbox row at all — situation_incidents' link is permanent once made, so
// situationOwnerForIncidentTx alone cannot tell "never owned" from "owned by
// a since-terminalized Situation", hence the separate lifecycle check
// below), and an Incident whose owner has ALREADY reached a terminal
// lifecycle gets none either — enqueuing there would be pure waste, since
// ApplySituationInput's R2 owner-terminal handling could never journal it.
// R2 exists for the genuine RACE where the owner terminalizes strictly
// BETWEEN this enqueue and the input worker's later apply, which this
// write-time check neither needs to nor can prevent.
//
// idempotencyKey must be derived deterministically from the artifact's own
// row id (see callers) so a retried enqueue for the exact same annotation/
// verdict never creates a second input: ON CONFLICT(idempotency_key) DO
// NOTHING mirrors insertTriageSituationInputTx's own idempotency convention
// (triage_controller.go) and ApplyCorrelatedDelivery's outbox insert
// (deliveries.go).
func enqueueOperatorArtifactInputTx(ctx context.Context, tx *sql.Tx, incidentID, kind, idempotencyKey string, annotationID, verdictID any, occurredAt time.Time) error {
	ownerID, err := situationOwnerForIncidentTx(ctx, tx, incidentID)
	if err != nil {
		return err
	}
	if ownerID == "" {
		return nil
	}
	lifecycle, _, err := situationLifecycleAndVersionTx(ctx, tx, ownerID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if lifecycle.Terminal() {
		return nil
	}
	var groupKey string
	if err := tx.QueryRowContext(ctx, `SELECT group_key FROM incidents WHERE id = ?`, incidentID).Scan(&groupKey); err != nil {
		return fmt.Errorf("store: read incident group key for %s: %w", kind, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_input_outbox
			(id, idempotency_key, incident_id, kind, group_key, occurred_at, status, annotation_id, verdict_id, journal_state)
		VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'pending')
		ON CONFLICT(idempotency_key) DO NOTHING`,
		"situation-input:"+idempotencyKey, idempotencyKey, incidentID, kind, groupKey, canonicalTime(occurredAt), annotationID, verdictID); err != nil {
		return fmt.Errorf("store: enqueue %s situation input: %w", kind, err)
	}
	return nil
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
// memory tier (ADR-0028): fetched by group key, unbounded — human writes are
// permanent (R7), not subject to time-based decay.
type OperatorAnnotation struct {
	IncidentID string
	Kind       string
	Note       string
	CreatedAt  time.Time
}

// OperatorAnnotations returns every annotation on the key's incidents,
// unbounded and newest-first, filtered to the caller's drill side (a real
// triage recalls only real incidents' notes and vice versa). Unbounded by
// lookback: human writes are permanent (R7), not subject to time-based decay.
// Unlike prior-finding recall it does NOT exclude the current incident: a
// re-judgment must recall a correction captured on the incident itself.
func (s *Store) OperatorAnnotations(ctx context.Context, groupKey string, currentIsDrill bool) ([]OperatorAnnotation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.incident_id, a.kind, a.note, a.created_at
		FROM incident_annotations a
		JOIN incidents i ON i.id = a.incident_id
		WHERE i.group_key = ?
		ORDER BY a.created_at DESC, a.id DESC`,
		groupKey)
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
