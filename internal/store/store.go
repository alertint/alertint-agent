// SPDX-License-Identifier: FSL-1.1-ALv2

// Package store wraps the embedded SQLite database that backs the
// AlertINT agent.
//
// Driver choice: modernc.org/sqlite (pure Go). This keeps the agent a
// single static binary and unblocks cross-compile targets in CI.
//
// The store owns:
//   - opening the database with sane PRAGMAs (WAL, foreign_keys, busy_timeout)
//   - running embedded migrations under migrations/*.sql in version order
//   - typed helpers for shapes that more than one slice consumes
//
// Slice scope:
//   - Slice 02 introduces the schema and Alert round-trip helpers.
//   - Slice 03 owns audit_log writes via the audit package.
//   - Slices 04 and 05 add incident helpers as they need them.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers driver name "sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the agent's persistence handle.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at path and applies all
// pending migrations. Pass ":memory:" for an in-memory store useful in
// tests.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	dsn := buildDSN(dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", dbPath, err)
	}
	// modernc.org/sqlite is safe for concurrent use, but a single
	// connection avoids "database is locked" with WAL on file-backed DBs
	// when the agent is the only writer. v1 has one writer process.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", dbPath, err)
	}

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// DB returns the underlying *sql.DB. Slices that don't yet have typed
// helpers can use it directly; prefer adding a typed method here over
// reaching into DB() from elsewhere.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases resources held by the store.
func (s *Store) Close() error { return s.db.Close() }

// buildDSN constructs the modernc.org/sqlite DSN. We use file: URIs so
// PRAGMA arguments compose cleanly. ":memory:" is converted to a unique
// shared in-memory DSN so SetMaxOpenConns(1) doesn't lose state across
// connections (modernc treats anonymous :memory: per-connection).
func buildDSN(dbPath string) string {
	pragmas := "_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	if dbPath == ":memory:" || dbPath == "" {
		return "file::memory:?cache=shared&" + pragmas
	}
	return "file:" + dbPath + "?" + pragmas
}

// migrate applies any pending embedded migrations. Migration files are
// named "NNNN_name.sql" where NNNN is the integer version. They run in
// ascending version order, each inside its own transaction, with the
// applied version recorded in schema_migrations.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		return fmt.Errorf("store: ensure schema_migrations: %w", err)
	}

	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}

	files, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range files {
		if applied[m.version] {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("store: apply migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: scan schema_migrations: %w", err)
		}
		out[v] = true
	}
	return out, rows.Err()
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
		m.version, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read embedded migrations: %w", err)
	}

	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		ver, name, err := parseMigrationName(e.Name())
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(migrationsFS, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: read migration %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: ver, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })

	// Guard against duplicate version prefixes which would silently let
	// one migration shadow another.
	seen := make(map[int]string)
	for _, m := range out {
		if prev, ok := seen[m.version]; ok {
			return nil, fmt.Errorf("store: duplicate migration version %d (%s and %s)", m.version, prev, m.name)
		}
		seen[m.version] = m.name
	}
	return out, nil
}

func parseMigrationName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || parts[0] == "" {
		return 0, "", fmt.Errorf("store: migration %q must be NNNN_name.sql", filename)
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("store: migration %q has non-integer version: %w", filename, err)
	}
	return v, parts[1], nil
}

// ----------------------------------------------------------------------
// Alert round-trip helpers (Slice 02 minimum surface).
// ----------------------------------------------------------------------

// Alert is the in-memory representation of a row in the alerts table.
type Alert struct {
	ID          string
	Fingerprint string
	Status      string // "firing" or "resolved"
	Labels      map[string]string
	Annotations map[string]string
	StartsAt    time.Time
	EndsAt      *time.Time
	ReceivedAt  time.Time
	// Role is populated only by GetIncidentAlertsWithRoles; empty otherwise.
	Role string
}

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("store: not found")

// UpsertAlertByFingerprint inserts the alert or, if a row with the same
// fingerprint already exists, updates it in place ("latest wins"). The
// id is preserved on update so foreign-key references in
// incident_alerts stay valid. The returned Alert carries the canonical
// id as stored in the DB (the original id on conflict, the supplied id
// on insert) so callers must use the returned value for any FK work.
func (s *Store) UpsertAlertByFingerprint(ctx context.Context, a Alert) (Alert, error) {
	if err := validateAlert(a); err != nil {
		return Alert{}, err
	}
	labelsJSON, err := json.Marshal(a.Labels)
	if err != nil {
		return Alert{}, fmt.Errorf("store: marshal labels: %w", err)
	}
	annoJSON, err := json.Marshal(a.Annotations)
	if err != nil {
		return Alert{}, fmt.Errorf("store: marshal annotations: %w", err)
	}

	var endsAt any
	if a.EndsAt != nil {
		endsAt = a.EndsAt.UTC().Format(time.RFC3339Nano)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, ends_at, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			status           = excluded.status,
			labels_json      = excluded.labels_json,
			annotations_json = excluded.annotations_json,
			starts_at        = excluded.starts_at,
			ends_at          = excluded.ends_at,
			received_at      = excluded.received_at
	`,
		a.ID, a.Fingerprint, a.Status, string(labelsJSON), string(annoJSON),
		a.StartsAt.UTC().Format(time.RFC3339Nano), endsAt, a.ReceivedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return Alert{}, fmt.Errorf("store: upsert alert: %w", err)
	}

	// Read back the row so we return the canonical id (preserved from the
	// original insert on conflict; callers must not use a.ID for FK work).
	stored, err := s.GetAlertByFingerprint(ctx, a.Fingerprint)
	if err != nil {
		return Alert{}, fmt.Errorf("store: read back upserted alert: %w", err)
	}
	return *stored, nil
}

// GetAlertByFingerprint returns the alert with the given fingerprint or
// ErrNotFound.
func (s *Store) GetAlertByFingerprint(ctx context.Context, fingerprint string) (*Alert, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, fingerprint, status, labels_json, annotations_json, starts_at, ends_at, received_at
		FROM alerts
		WHERE fingerprint = ?
	`, fingerprint)

	var (
		a           Alert
		labelsJSON  string
		annoJSON    string
		startsStr   string
		endsStr     sql.NullString
		receivedStr string
	)
	if err := row.Scan(&a.ID, &a.Fingerprint, &a.Status, &labelsJSON, &annoJSON, &startsStr, &endsStr, &receivedStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan alert: %w", err)
	}

	if err := json.Unmarshal([]byte(labelsJSON), &a.Labels); err != nil {
		return nil, fmt.Errorf("store: unmarshal labels: %w", err)
	}
	if err := json.Unmarshal([]byte(annoJSON), &a.Annotations); err != nil {
		return nil, fmt.Errorf("store: unmarshal annotations: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, startsStr)
	if err != nil {
		return nil, fmt.Errorf("store: parse starts_at: %w", err)
	}
	a.StartsAt = t
	if endsStr.Valid {
		t, err := time.Parse(time.RFC3339Nano, endsStr.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse ends_at: %w", err)
		}
		a.EndsAt = &t
	}
	t, err = time.Parse(time.RFC3339Nano, receivedStr)
	if err != nil {
		return nil, fmt.Errorf("store: parse received_at: %w", err)
	}
	a.ReceivedAt = t

	return &a, nil
}

// ----------------------------------------------------------------------
// Incident helpers (Slice 05).
// ----------------------------------------------------------------------

// Incident mirrors a row in the incidents table for in-process use.
type Incident struct {
	ID           string
	GroupKey     string
	Status       string // "collecting" | "ready" | "processing" | "analyzed" | "resolved" | "failed"
	FirstAlertAt time.Time
	LastAlertAt  time.Time
	ReadyAt      time.Time
	AlertCount   int
	// LLM output fields — populated only after status reaches "analyzed".
	Summary    string
	RootCause  string
	Confidence float64
	OutputJSON string
	// EnrichmentJSON is the marshaled log-enrichment snapshot persisted with
	// the finding so the MCP evidence pack can replay the exact lines the LLM
	// saw. Empty when logs are not configured or on the short-circuit path.
	EnrichmentJSON string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// InsertIncident creates a new incident row in status "collecting".
func (s *Store) InsertIncident(ctx context.Context, inc Incident) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, 'collecting', ?, ?, ?, ?, ?, ?)
	`,
		inc.ID,
		inc.GroupKey,
		inc.FirstAlertAt.UTC().Format(time.RFC3339Nano),
		inc.LastAlertAt.UTC().Format(time.RFC3339Nano),
		inc.ReadyAt.UTC().Format(time.RFC3339Nano),
		inc.AlertCount,
		now, now,
	)
	if err != nil {
		return fmt.Errorf("store: insert incident: %w", err)
	}
	return nil
}

// AddAlertToIncident inserts a row in incident_alerts and increments
// alert_count + updates last_alert_at on the parent incident.
func (s *Store) AddAlertToIncident(ctx context.Context, incidentID, alertID string, alertTime time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, created_at)
		VALUES (?, ?, ?)
	`, incidentID, alertID, now)
	if err != nil {
		return fmt.Errorf("store: insert incident_alert: %w", err)
	}

	// Only increment alert_count when the row was actually inserted
	// (rows_affected == 0 means the composite PK already existed — a duplicate
	// call for the same alert, e.g. resolved re-delivery of an already-linked
	// alert — so we skip the counter update to prevent inflation).
	inserted, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: insert incident_alert rows: %w", err)
	}
	if inserted > 0 {
		_, err = tx.ExecContext(ctx, `
			UPDATE incidents
			SET alert_count  = alert_count + 1,
			    last_alert_at = MAX(last_alert_at, ?),
			    updated_at    = ?
			WHERE id = ?
		`, alertTime.UTC().Format(time.RFC3339Nano), now, incidentID)
		if err != nil {
			return fmt.Errorf("store: update incident alert_count: %w", err)
		}
	}

	return tx.Commit()
}

// GetCollectingIncident returns the single incident in status
// "collecting" for the given group_key, or ErrNotFound.
func (s *Store) GetCollectingIncident(ctx context.Context, groupKey string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at
		FROM incidents
		WHERE group_key = ? AND status = 'collecting'
		LIMIT 1
	`, groupKey)

	return scanIncident(row)
}

// GetRecentIncidentByGroupKey returns the most recent incident (by created_at)
// for the given group_key regardless of status, or ErrNotFound.
// Returns the full incident including LLM output fields so the resolution
// notifier can preserve original analysis context in resolved notifications.
func (s *Store) GetRecentIncidentByGroupKey(ctx context.Context, groupKey string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, group_key, status,
		       first_alert_at, last_alert_at, ready_at, alert_count,
		       COALESCE(summary,''), COALESCE(root_cause,''),
		       COALESCE(confidence,0.0), COALESCE(output_json,''),
		       COALESCE(enrichment_json,''),
		       created_at, updated_at
		FROM incidents
		WHERE group_key = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, groupKey)

	return scanIncidentFull(row)
}

// MarkIncidentReady transitions an incident from "collecting" to
// "ready". Returns ErrNotFound if no such collecting incident exists.
func (s *Store) MarkIncidentReady(ctx context.Context, incidentID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET status     = 'ready',
		    updated_at = ?
		WHERE id = ? AND status = 'collecting'
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: mark incident ready: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: mark incident ready rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListCollectingIncidents returns all incidents in status "collecting",
// ordered by ready_at ascending (soonest deadline first).
func (s *Store) ListCollectingIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at
		FROM incidents
		WHERE status = 'collecting'
		ORDER BY ready_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list collecting incidents: %w", err)
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

// ListReadyIncidents returns all incidents in status "ready", ordered
// by ready_at ascending (oldest deadline first).
func (s *Store) ListReadyIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at
		FROM incidents
		WHERE status = 'ready'
		ORDER BY ready_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list ready incidents: %w", err)
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

// scanner abstracts *sql.Row and *sql.Rows for scanIncident.
type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(s scanner) (*Incident, error) {
	var (
		inc        Incident
		firstStr   string
		lastStr    string
		readyStr   string
		createdStr string
		updatedStr string
	)
	if err := s.Scan(
		&inc.ID, &inc.GroupKey, &inc.Status,
		&firstStr, &lastStr, &readyStr, &inc.AlertCount,
		&createdStr, &updatedStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan incident: %w", err)
	}

	parse := func(s string) (time.Time, error) {
		return time.Parse(time.RFC3339Nano, s)
	}
	var err error
	if inc.FirstAlertAt, err = parse(firstStr); err != nil {
		return nil, fmt.Errorf("store: parse first_alert_at: %w", err)
	}
	if inc.LastAlertAt, err = parse(lastStr); err != nil {
		return nil, fmt.Errorf("store: parse last_alert_at: %w", err)
	}
	if inc.ReadyAt, err = parse(readyStr); err != nil {
		return nil, fmt.Errorf("store: parse ready_at: %w", err)
	}
	if inc.CreatedAt, err = parse(createdStr); err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	if inc.UpdatedAt, err = parse(updatedStr); err != nil {
		return nil, fmt.Errorf("store: parse updated_at: %w", err)
	}
	return &inc, nil
}

// ----------------------------------------------------------------------
// Skill helpers (Slice 07).
// ----------------------------------------------------------------------

// GetIncidentAlerts returns all alerts that are members of the given
// incident, in the order they were added.
func (s *Store) GetIncidentAlerts(ctx context.Context, incidentID string) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.fingerprint, a.status, a.labels_json, a.annotations_json,
		       a.starts_at, a.ends_at, a.received_at
		FROM alerts a
		JOIN incident_alerts ia ON ia.alert_id = a.id
		WHERE ia.incident_id = ?
		ORDER BY ia.created_at ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("store: get incident alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanAlertRows(rows)
}

// MemberStatusCounts holds per-incident member-alert status tallies used to
// derive a recovery signal (how many members are firing vs resolved).
type MemberStatusCounts struct {
	Firing   int
	Resolved int
	Total    int
}

// IncidentMemberStatusCounts returns, for each incident id, the tally of its
// member alerts by status — the raw material for a recovery signal that tells
// an active incident from a recovering/recovered one. It runs ONE GROUP BY query
// for the whole id set (no N+1). Incidents with no members are absent from the
// returned map; an empty id list yields an empty map.
func (s *Store) IncidentMemberStatusCounts(ctx context.Context, ids []string) (map[string]MemberStatusCounts, error) {
	out := make(map[string]MemberStatusCounts, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ia.incident_id, a.status, COUNT(*)
		FROM incident_alerts ia
		JOIN alerts a ON a.id = ia.alert_id
		WHERE ia.incident_id IN (`+strings.Join(placeholders, ",")+`)
		GROUP BY ia.incident_id, a.status
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: incident member status counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, status string
		var n int
		if err := rows.Scan(&id, &status, &n); err != nil {
			return nil, fmt.Errorf("store: scan status count: %w", err)
		}
		c := out[id]
		switch status {
		case "firing":
			c.Firing += n
		case "resolved":
			c.Resolved += n
		}
		c.Total += n
		out[id] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: status count rows: %w", err)
	}
	return out, nil
}

// SaveIncidentOutput persists LLM output on a ready/processing incident,
// denormalizes summary/root_cause/confidence, and sets status="analyzed".
// enrichmentJSON is the log-enrichment snapshot (§3.7); pass "" when logs are
// not configured or on the short-circuit path, which stores SQL NULL so the
// evidence pack omits the logs section.
func (s *Store) SaveIncidentOutput(ctx context.Context, incidentID, outputJSON, summary, rootCause string, confidence float64, enrichmentJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var enrichment any
	if enrichmentJSON != "" {
		enrichment = enrichmentJSON
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET status          = 'analyzed',
		    output_json     = ?,
		    summary         = ?,
		    root_cause      = ?,
		    confidence      = ?,
		    enrichment_json = ?,
		    updated_at      = ?
		WHERE id = ? AND status IN ('ready','processing')
	`, outputJSON, summary, rootCause, confidence, enrichment, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: save incident output: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: save incident output rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkIncidentResolved transitions an incident from "analyzed" or "ready"
// to "resolved". "ready" is accepted because incidents that skipped LLM
// analysis (e.g. fewer alerts than MinAlerts) never advance to "analyzed"
// but can still become fully resolved when their member alerts recover.
// Returns ErrNotFound if no incident in an eligible status exists.
func (s *Store) MarkIncidentResolved(ctx context.Context, incidentID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET status     = 'resolved',
		    updated_at = ?
		WHERE id = ? AND status IN ('analyzed','ready')
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: mark incident resolved: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: mark incident resolved rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAlertRole sets the role column on an incident_alerts row.
func (s *Store) SetAlertRole(ctx context.Context, incidentID, alertID, role string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		UPDATE incident_alerts
		SET role = ?, created_at = created_at
		WHERE incident_id = ? AND alert_id = ?
	`, role, incidentID, alertID)
	if err != nil {
		return fmt.Errorf("store: set alert role: %w", err)
	}
	_ = now // suppress unused warning; updated_at not present on incident_alerts
	return nil
}

// GetIncidentSlackThread returns the Slack message ts and channel stored for
// the given incident, or ("", "", ErrNotFound) when no thread has been recorded.
func (s *Store) GetIncidentSlackThread(ctx context.Context, incidentID string) (ts, channel string, err error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(slack_ts,''), COALESCE(slack_channel,'')
		FROM incidents WHERE id = ?
	`, incidentID)
	if scanErr := row.Scan(&ts, &channel); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return "", "", fmt.Errorf("store: get slack thread: %w", scanErr)
	}
	if ts == "" {
		return "", "", ErrNotFound
	}
	return ts, channel, nil
}

// SetIncidentSlackThread records the Slack message ts and channel for an incident.
func (s *Store) SetIncidentSlackThread(ctx context.Context, incidentID, ts, channel string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET slack_ts = ?, slack_channel = ?, updated_at = ?
		WHERE id = ?
	`, ts, channel, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: set slack thread: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------
// MCP read helpers — read-only, never mutate state.
// ----------------------------------------------------------------------

// AlertFilter constrains SearchAlerts results. All fields are optional;
// zero/nil values mean "no constraint".
type AlertFilter struct {
	Since      *time.Time
	Until      *time.Time
	Status     string // "firing" | "resolved" | "" (any)
	LabelKey   string // filter by label key+value (both must be set)
	LabelValue string
	Limit      int // capped at 200; 0 defaults to 50
}

// ListRecentIncidents returns up to limit incidents ordered newest-first.
// It includes LLM output fields (Summary, RootCause, Confidence, OutputJSON)
// so callers get the full picture in one query. limit is capped at 100.
func (s *Store) ListRecentIncidents(ctx context.Context, limit int) ([]Incident, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, group_key, status,
		       first_alert_at, last_alert_at, ready_at, alert_count,
		       COALESCE(summary,''), COALESCE(root_cause,''),
		       COALESCE(confidence,0.0), COALESCE(output_json,''),
		       COALESCE(enrichment_json,''),
		       created_at, updated_at
		FROM incidents
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list recent incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Incident
	for rows.Next() {
		inc, err := scanIncidentFull(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inc)
	}
	return out, rows.Err()
}

// GetIncidentByID returns the full incident row including LLM output fields,
// or nil, nil when not found.
func (s *Store) GetIncidentByID(ctx context.Context, id string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, group_key, status,
		       first_alert_at, last_alert_at, ready_at, alert_count,
		       COALESCE(summary,''), COALESCE(root_cause,''),
		       COALESCE(confidence,0.0), COALESCE(output_json,''),
		       COALESCE(enrichment_json,''),
		       created_at, updated_at
		FROM incidents
		WHERE id = ?
	`, id)
	inc, err := scanIncidentFull(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil //nolint:nilnil // callers distinguish not-found by nil pointer, not sentinel
		}
		return nil, err
	}
	return inc, nil
}

// SearchAlerts returns alerts matching the given filter, ordered by
// received_at descending.
func (s *Store) SearchAlerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	q := `SELECT id, fingerprint, status, labels_json, annotations_json,
	             starts_at, ends_at, received_at
	      FROM alerts WHERE 1=1`
	var args []any

	if f.Since != nil {
		q += " AND received_at >= ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if f.Until != nil {
		q += " AND received_at <= ?"
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if f.Status != "" {
		q += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.LabelKey != "" && f.LabelValue != "" {
		q += " AND json_extract(labels_json, '$.' || ?) = ?"
		args = append(args, f.LabelKey, f.LabelValue)
	}
	q += " ORDER BY received_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: search alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanAlertRows(rows)
}

// GetIncidentAlertsWithRoles is like GetIncidentAlerts but also populates
// Alert.Role from the incident_alerts.role column.
func (s *Store) GetIncidentAlertsWithRoles(ctx context.Context, incidentID string) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.fingerprint, a.status, a.labels_json, a.annotations_json,
		       a.starts_at, a.ends_at, a.received_at, COALESCE(ia.role,'')
		FROM alerts a
		JOIN incident_alerts ia ON ia.alert_id = a.id
		WHERE ia.incident_id = ?
		ORDER BY ia.created_at ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("store: get incident alerts with roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Alert
	for rows.Next() {
		var (
			a           Alert
			labelsJSON  string
			annoJSON    string
			startsStr   string
			endsStr     sql.NullString
			receivedStr string
		)
		if err := rows.Scan(
			&a.ID, &a.Fingerprint, &a.Status, &labelsJSON, &annoJSON,
			&startsStr, &endsStr, &receivedStr, &a.Role,
		); err != nil {
			return nil, fmt.Errorf("store: scan incident alert with role: %w", err)
		}
		if err := json.Unmarshal([]byte(labelsJSON), &a.Labels); err != nil {
			return nil, fmt.Errorf("store: unmarshal labels: %w", err)
		}
		if err := json.Unmarshal([]byte(annoJSON), &a.Annotations); err != nil {
			return nil, fmt.Errorf("store: unmarshal annotations: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, startsStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse starts_at: %w", err)
		}
		a.StartsAt = t
		if endsStr.Valid {
			t, err := time.Parse(time.RFC3339Nano, endsStr.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse ends_at: %w", err)
			}
			a.EndsAt = &t
		}
		t, err = time.Parse(time.RFC3339Nano, receivedStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse received_at: %w", err)
		}
		a.ReceivedAt = t
		out = append(out, a)
	}
	return out, rows.Err()
}

// scanIncidentFull scans a row that SELECTs all 14 incident columns including
// the nullable LLM output fields (summary, root_cause, confidence, output_json)
// and the log-enrichment snapshot (enrichment_json). Callers must use COALESCE
// on the nullable columns before scanning.
func scanIncidentFull(s scanner) (*Incident, error) {
	var (
		inc        Incident
		firstStr   string
		lastStr    string
		readyStr   string
		createdStr string
		updatedStr string
	)
	if err := s.Scan(
		&inc.ID, &inc.GroupKey, &inc.Status,
		&firstStr, &lastStr, &readyStr, &inc.AlertCount,
		&inc.Summary, &inc.RootCause, &inc.Confidence, &inc.OutputJSON,
		&inc.EnrichmentJSON,
		&createdStr, &updatedStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan incident full: %w", err)
	}

	parse := func(s string) (time.Time, error) {
		return time.Parse(time.RFC3339Nano, s)
	}
	var err error
	if inc.FirstAlertAt, err = parse(firstStr); err != nil {
		return nil, fmt.Errorf("store: parse first_alert_at: %w", err)
	}
	if inc.LastAlertAt, err = parse(lastStr); err != nil {
		return nil, fmt.Errorf("store: parse last_alert_at: %w", err)
	}
	if inc.ReadyAt, err = parse(readyStr); err != nil {
		return nil, fmt.Errorf("store: parse ready_at: %w", err)
	}
	if inc.CreatedAt, err = parse(createdStr); err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	if inc.UpdatedAt, err = parse(updatedStr); err != nil {
		return nil, fmt.Errorf("store: parse updated_at: %w", err)
	}
	return &inc, nil
}

// scanAlertRows scans rows from a SELECT without the role column.
func scanAlertRows(rows *sql.Rows) ([]Alert, error) {
	var out []Alert
	for rows.Next() {
		var (
			a           Alert
			labelsJSON  string
			annoJSON    string
			startsStr   string
			endsStr     sql.NullString
			receivedStr string
		)
		if err := rows.Scan(
			&a.ID, &a.Fingerprint, &a.Status, &labelsJSON, &annoJSON,
			&startsStr, &endsStr, &receivedStr,
		); err != nil {
			return nil, fmt.Errorf("store: scan alert row: %w", err)
		}
		if err := json.Unmarshal([]byte(labelsJSON), &a.Labels); err != nil {
			return nil, fmt.Errorf("store: unmarshal labels: %w", err)
		}
		if err := json.Unmarshal([]byte(annoJSON), &a.Annotations); err != nil {
			return nil, fmt.Errorf("store: unmarshal annotations: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, startsStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse starts_at: %w", err)
		}
		a.StartsAt = t
		if endsStr.Valid {
			t, err := time.Parse(time.RFC3339Nano, endsStr.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse ends_at: %w", err)
			}
			a.EndsAt = &t
		}
		t, err = time.Parse(time.RFC3339Nano, receivedStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse received_at: %w", err)
		}
		a.ReceivedAt = t
		out = append(out, a)
	}
	return out, rows.Err()
}

func validateAlert(a Alert) error {
	switch {
	case a.ID == "":
		return errors.New("store: alert.id is required")
	case a.Fingerprint == "":
		return errors.New("store: alert.fingerprint is required")
	case a.Status != "firing" && a.Status != "resolved":
		return fmt.Errorf("store: alert.status %q must be firing or resolved", a.Status)
	case a.StartsAt.IsZero():
		return errors.New("store: alert.starts_at is required")
	case a.ReceivedAt.IsZero():
		return errors.New("store: alert.received_at is required")
	}
	return nil
}
