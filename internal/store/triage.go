// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// TriagePhase is the durable dispatch phase of one Incident's Triage schedule
// (CONTEXT.md: Triage schedule) — it exists only while the Incident is
// unjudged and is what a restart recovers from.
type TriagePhase string

const (
	TriagePending   TriagePhase = "pending"
	TriageInFlight  TriagePhase = "in_flight"
	TriageBackoff   TriagePhase = "backoff"
	TriageSkipped   TriagePhase = "skipped"
	TriageExhausted TriagePhase = "exhausted"
)

// IncidentTriage mirrors a row in the incident_triage table.
type IncidentTriage struct {
	IncidentID      string
	Phase           TriagePhase
	Attempts        int
	NextAt          time.Time // zero when not scheduled
	StartedAt       time.Time // zero until the first attempt begins
	LastErrorCode   string
	LastErrorDetail string
}

// maxTriageDetailBytes bounds the persisted, sanitized last-error detail
// (R9): the stable code is authoritative, detail is diagnostic only.
const maxTriageDetailBytes = 256

// sanitizeTriageDetail replaces CR/LF with spaces, trims, and truncates to
// the longest valid UTF-8 prefix no longer than maxTriageDetailBytes.
func sanitizeTriageDetail(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	s = strings.TrimSpace(s)
	if len(s) <= maxTriageDetailBytes {
		return s
	}
	end := 0
	for i, r := range s {
		rl := utf8.RuneLen(r)
		if rl < 0 {
			rl = 1
		}
		if i+rl > maxTriageDetailBytes {
			break
		}
		end = i + rl
	}
	return s[:end]
}

// SeedIncidentTriage inserts the initial "pending" triage row for a freshly
// ready Incident, due at due.
func (s *Store) SeedIncidentTriage(ctx context.Context, incidentID string, due time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, next_at, updated_at)
		VALUES (?, 'pending', 0, ?, ?)
	`, incidentID, due.UTC().Format(time.RFC3339Nano), now)
	if err != nil {
		return fmt.Errorf("store: seed incident triage: %w", err)
	}
	return nil
}

// BeginIncidentTriage atomically moves incidentID's Incident status from
// "ready" to "processing" and its triage row to phase in_flight, incrementing
// attempts and recording startedAt. Returns ErrNotFound if the Incident is
// not currently "ready" — the guarded transition that makes "processing" a
// real in-flight lease.
func (s *Store) BeginIncidentTriage(ctx context.Context, incidentID string, startedAt time.Time) (IncidentTriage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'processing', updated_at = ?
		WHERE id = ? AND status = 'ready'
	`, now, incidentID)
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin incident triage: mark processing: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin incident triage: rows: %w", err)
	}
	if n == 0 {
		return IncidentTriage{}, ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'in_flight', attempts = attempts + 1, started_at = ?, next_at = NULL, updated_at = ?
		WHERE incident_id = ?
	`, startedAt.UTC().Format(time.RFC3339Nano), now, incidentID); err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin incident triage: update triage: %w", err)
	}

	active, err := scanIncidentTriage(tx.QueryRowContext(ctx, `
		SELECT incident_id, phase, attempts, next_at, started_at, COALESCE(last_error_code,''), COALESCE(last_error_detail,'')
		FROM incident_triage WHERE incident_id = ?
	`, incidentID))
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin incident triage: read back: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin incident triage: commit: %w", err)
	}
	return *active, nil
}

// BackoffIncidentTriage atomically returns incidentID's Incident from
// "processing" to "ready" and persists phase backoff with the next due time
// and a sanitized, bounded last-error classification. Returns ErrNotFound if
// the Incident is not currently "processing".
func (s *Store) BackoffIncidentTriage(ctx context.Context, incidentID string, nextAt time.Time, code, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ?
		WHERE id = ? AND status = 'processing'
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: backoff incident triage: mark ready: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: backoff incident triage: rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'backoff', next_at = ?, last_error_code = ?, last_error_detail = ?, updated_at = ?
		WHERE incident_id = ?
	`, nextAt.UTC().Format(time.RFC3339Nano), code, sanitizeTriageDetail(detail), now, incidentID); err != nil {
		return fmt.Errorf("store: backoff incident triage: update triage: %w", err)
	}
	return tx.Commit()
}

// SkipIncidentTriage atomically returns incidentID's Incident from
// "processing" to "ready" and persists phase skipped — a clean skip is a
// judgment (CONTEXT.md: Triage attempt), so it is never a candidate for
// retry-aware attachment.
func (s *Store) SkipIncidentTriage(ctx context.Context, incidentID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ?
		WHERE id = ? AND status = 'processing'
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: skip incident triage: mark ready: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: skip incident triage: rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'skipped', next_at = NULL, updated_at = ?
		WHERE incident_id = ?
	`, now, incidentID); err != nil {
		return fmt.Errorf("store: skip incident triage: update triage: %w", err)
	}
	return tx.Commit()
}

// CompleteIncidentTriage deletes the active triage row after a successful
// persisted Finding (R2) — membership closes at judgment, so nothing durable
// needs to remain. Returns ErrNotFound if no triage row exists for incidentID.
func (s *Store) CompleteIncidentTriage(ctx context.Context, incidentID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM incident_triage WHERE incident_id = ?`, incidentID)
	if err != nil {
		return fmt.Errorf("store: complete incident triage: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: complete incident triage: rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ExhaustIncidentTriage atomically moves incidentID's Incident from
// "processing" or "ready" to the terminal "failed" and persists phase
// exhausted. Returns ErrNotFound if the Incident is not in an eligible
// status (e.g. already judged or already failed).
func (s *Store) ExhaustIncidentTriage(ctx context.Context, incidentID, code, detail string) (IncidentTriage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'failed', updated_at = ?
		WHERE id = ? AND status IN ('processing','ready')
	`, now, incidentID)
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: exhaust incident triage: mark failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: exhaust incident triage: rows: %w", err)
	}
	if n == 0 {
		return IncidentTriage{}, ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'exhausted', next_at = NULL, last_error_code = ?, last_error_detail = ?, updated_at = ?
		WHERE incident_id = ?
	`, code, sanitizeTriageDetail(detail), now, incidentID); err != nil {
		return IncidentTriage{}, fmt.Errorf("store: exhaust incident triage: update triage: %w", err)
	}

	active, err := scanIncidentTriage(tx.QueryRowContext(ctx, `
		SELECT incident_id, phase, attempts, next_at, started_at, COALESCE(last_error_code,''), COALESCE(last_error_detail,'')
		FROM incident_triage WHERE incident_id = ?
	`, incidentID))
	if err != nil {
		return IncidentTriage{}, fmt.Errorf("store: exhaust incident triage: read back: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return IncidentTriage{}, fmt.Errorf("store: exhaust incident triage: commit: %w", err)
	}
	return *active, nil
}

// ListDueIncidentTriage returns every triage row in phase pending or backoff
// whose next_at is at or before now, ordered soonest-due first. A "pending"
// row normally never sits at rest between ticks (a freshly ready incident is
// seeded and dispatched atomically within the same flush), but startup
// recovery seeds legacy rows as pending without dispatching them immediately
// — this is what makes them due on the first tick after Start.
func (s *Store) ListDueIncidentTriage(ctx context.Context, now time.Time) ([]IncidentTriage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT incident_id, phase, attempts, next_at, started_at, COALESCE(last_error_code,''), COALESCE(last_error_detail,'')
		FROM incident_triage
		WHERE phase IN ('pending','backoff') AND next_at <= ?
		ORDER BY next_at ASC
	`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: list due incident triage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanIncidentTriageRows(rows)
}

// ListInterruptedIncidentTriage returns every triage row still in phase
// in_flight — either a dispatch a process restart interrupted mid-call, or a
// terminal write from an earlier tick that has not yet persisted.
func (s *Store) ListInterruptedIncidentTriage(ctx context.Context) ([]IncidentTriage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT incident_id, phase, attempts, next_at, started_at, COALESCE(last_error_code,''), COALESCE(last_error_detail,'')
		FROM incident_triage
		WHERE phase = 'in_flight'
		ORDER BY started_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list interrupted incident triage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanIncidentTriageRows(rows)
}

// GetBackoffIncidentByGroupKey returns the newest Incident for groupKey that
// is currently "ready" with a durable "backoff" triage row — the only state
// eligible for retry-aware attachment (R4, R8). Returns ErrNotFound otherwise,
// including for pending, in-flight, skipped, or exhausted rows.
func (s *Store) GetBackoffIncidentByGroupKey(ctx context.Context, groupKey string) (*Incident, *IncidentTriage, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT i.id, i.group_key, i.status, i.first_alert_at, i.last_alert_at, i.ready_at, i.alert_count, i.created_at, i.updated_at,
		       t.incident_id, t.phase, t.attempts, t.next_at, t.started_at, COALESCE(t.last_error_code,''), COALESCE(t.last_error_detail,'')
		FROM incidents i
		JOIN incident_triage t ON t.incident_id = i.id
		WHERE i.group_key = ? AND i.status = 'ready' AND t.phase = 'backoff'
		ORDER BY i.created_at DESC
		LIMIT 1
	`, groupKey)

	var (
		inc        Incident
		firstStr   string
		lastStr    string
		readyStr   string
		createdStr string
		updatedStr string
		tri        IncidentTriage
		nextStr    sql.NullString
		startedStr sql.NullString
	)
	if err := row.Scan(
		&inc.ID, &inc.GroupKey, &inc.Status, &firstStr, &lastStr, &readyStr, &inc.AlertCount, &createdStr, &updatedStr,
		&tri.IncidentID, &tri.Phase, &tri.Attempts, &nextStr, &startedStr, &tri.LastErrorCode, &tri.LastErrorDetail,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("store: get backoff incident by group key: %w", err)
	}

	parse := func(x string) (time.Time, error) { return time.Parse(time.RFC3339Nano, x) }
	var err error
	if inc.FirstAlertAt, err = parse(firstStr); err != nil {
		return nil, nil, fmt.Errorf("store: parse first_alert_at: %w", err)
	}
	if inc.LastAlertAt, err = parse(lastStr); err != nil {
		return nil, nil, fmt.Errorf("store: parse last_alert_at: %w", err)
	}
	if inc.ReadyAt, err = parse(readyStr); err != nil {
		return nil, nil, fmt.Errorf("store: parse ready_at: %w", err)
	}
	if inc.CreatedAt, err = parse(createdStr); err != nil {
		return nil, nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	if inc.UpdatedAt, err = parse(updatedStr); err != nil {
		return nil, nil, fmt.Errorf("store: parse updated_at: %w", err)
	}
	if nextStr.Valid {
		if tri.NextAt, err = parse(nextStr.String); err != nil {
			return nil, nil, fmt.Errorf("store: parse next_at: %w", err)
		}
	}
	if startedStr.Valid {
		if tri.StartedAt, err = parse(startedStr.String); err != nil {
			return nil, nil, fmt.Errorf("store: parse started_at: %w", err)
		}
	}
	return &inc, &tri, nil
}

// ListLegacyReadyIncidents returns "ready" Incidents with no incident_triage
// row — Incidents left ready by a pre-upgrade binary (R3).
func (s *Store) ListLegacyReadyIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at
		FROM incidents i
		WHERE status = 'ready'
		  AND NOT EXISTS (SELECT 1 FROM incident_triage t WHERE t.incident_id = i.id)
		ORDER BY ready_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list legacy ready incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inc)
	}
	return out, rows.Err()
}

// RecoverInterruptedIncidentTriage moves a triage row interrupted mid-attempt
// (Incident "processing", phase "in_flight") to durable backoff, guarded on
// both so it never touches a row already reconciled by another path.
func (s *Store) RecoverInterruptedIncidentTriage(ctx context.Context, incidentID string, nextAt time.Time, code, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = 'ready', updated_at = ?
		WHERE id = ? AND status = 'processing'
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: recover interrupted incident triage: mark ready: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: recover interrupted incident triage: rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}

	res2, err := tx.ExecContext(ctx, `
		UPDATE incident_triage
		SET phase = 'backoff', next_at = ?, last_error_code = ?, last_error_detail = ?, updated_at = ?
		WHERE incident_id = ? AND phase = 'in_flight'
	`, nextAt.UTC().Format(time.RFC3339Nano), code, sanitizeTriageDetail(detail), now, incidentID)
	if err != nil {
		return fmt.Errorf("store: recover interrupted incident triage: update triage: %w", err)
	}
	n2, err := res2.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: recover interrupted incident triage: triage rows: %w", err)
	}
	if n2 == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func scanIncidentTriage(s scanner) (*IncidentTriage, error) {
	var (
		t          IncidentTriage
		nextStr    sql.NullString
		startedStr sql.NullString
	)
	if err := s.Scan(&t.IncidentID, &t.Phase, &t.Attempts, &nextStr, &startedStr, &t.LastErrorCode, &t.LastErrorDetail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan incident triage: %w", err)
	}
	if nextStr.Valid {
		v, err := time.Parse(time.RFC3339Nano, nextStr.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse next_at: %w", err)
		}
		t.NextAt = v
	}
	if startedStr.Valid {
		v, err := time.Parse(time.RFC3339Nano, startedStr.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse started_at: %w", err)
		}
		t.StartedAt = v
	}
	return &t, nil
}

func scanIncidentTriageRows(rows *sql.Rows) ([]IncidentTriage, error) {
	var out []IncidentTriage
	for rows.Next() {
		t, err := scanIncidentTriage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}
