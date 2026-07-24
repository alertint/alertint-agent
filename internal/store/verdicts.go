// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IncidentVerdict is one version of an incident's captured verdict.
// Append-only; the highest version is operative. The existence of any row IS
// the derived verdict marker (spec: marker is derived, never stored).
type IncidentVerdict struct {
	ID              int64
	IncidentID      string
	Version         int
	Verdict         string // correction | confirmation
	ExpectationJSON string
	WidenedJSON     string // "" when no widened entries
	CauseCategory   string // free-form, "" when absent
	CreatedAt       time.Time
}

// VerdictCapture is the persist-phase input: verdict row + matching
// annotation row + (iff DemoteMarksFloor > 0) the D3 demotion, atomically.
type VerdictCapture struct {
	IncidentID       string
	Verdict          string // correction | confirmation
	ExpectationJSON  string
	WidenedJSON      string
	CauseCategory    string
	AnnotationNote   string
	DemoteMarksFloor int
}

// PersistVerdictCapture writes verdict + annotation (+ demotion) in one
// transaction (D7/D9 persist phase). Returns the new verdict version row and
// the annotation row.
func (s *Store) PersistVerdictCapture(ctx context.Context, c VerdictCapture) (*IncidentVerdict, *IncidentAnnotation, error) {
	if c.Verdict != "correction" && c.Verdict != "confirmation" {
		return nil, nil, fmt.Errorf("store: verdict %q not in {correction, confirmation}", c.Verdict)
	}
	if err := validateAnnotation(c.Verdict, c.AnnotationNote); err != nil {
		return nil, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("store: begin verdict tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ann, err := insertAnnotationTx(ctx, tx, c.IncidentID, c.Verdict, c.AnnotationNote)
	if err != nil {
		return nil, nil, err // ErrNotFound surfaces here for a missing incident
	}

	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM incident_verdicts WHERE incident_id = ?`,
		c.IncidentID).Scan(&version); err != nil {
		return nil, nil, fmt.Errorf("store: next verdict version: %w", err)
	}
	now := time.Now().UTC()
	var widened, cause any
	if c.WidenedJSON != "" {
		widened = c.WidenedJSON
	}
	if c.CauseCategory != "" {
		cause = c.CauseCategory
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO incident_verdicts
			(incident_id, version, verdict, expectation_json, widened_json, cause_category, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.IncidentID, version, c.Verdict, c.ExpectationJSON, widened, cause,
		now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, nil, fmt.Errorf("store: insert verdict: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, nil, fmt.Errorf("store: verdict id: %w", err)
	}
	if c.DemoteMarksFloor > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE incidents SET memory_refute_marks = MAX(memory_refute_marks, ?) WHERE id = ?`,
			c.DemoteMarksFloor, c.IncidentID); err != nil {
			return nil, nil, fmt.Errorf("store: verdict demotion: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("store: commit verdict: %w", err)
	}
	return &IncidentVerdict{
		ID: id, IncidentID: c.IncidentID, Version: version, Verdict: c.Verdict,
		ExpectationJSON: c.ExpectationJSON, WidenedJSON: c.WidenedJSON,
		CauseCategory: c.CauseCategory, CreatedAt: now,
	}, ann, nil
}

// LatestIncidentVerdict returns the operative (highest-version) verdict of an
// incident, or nil, nil when none exists.
func (s *Store) LatestIncidentVerdict(ctx context.Context, incidentID string) (*IncidentVerdict, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, version, verdict, expectation_json,
		       COALESCE(widened_json, ''), COALESCE(cause_category, ''), created_at
		FROM incident_verdicts WHERE incident_id = ?
		ORDER BY version DESC LIMIT 1`, incidentID)
	var v IncidentVerdict
	var created string
	if err := row.Scan(&v.ID, &v.IncidentID, &v.Version, &v.Verdict,
		&v.ExpectationJSON, &v.WidenedJSON, &v.CauseCategory, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // callers distinguish not-found by nil pointer, not sentinel
		}
		return nil, fmt.Errorf("store: latest verdict: %w", err)
	}
	var err error
	if v.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return nil, fmt.Errorf("store: parse verdict created_at: %w", err)
	}
	return &v, nil
}

// LatestVerdictKinds bulk-maps incident id → latest verdict kind for MCP list
// rows (derived verdict_kind). Ids without a verdict are absent from the map.
func (s *Store) LatestVerdictKinds(ctx context.Context, incidentIDs []string) (map[string]string, error) {
	out := make(map[string]string, len(incidentIDs))
	if len(incidentIDs) == 0 {
		return out, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(incidentIDs)), ",")
	args := make([]any, len(incidentIDs))
	for i, id := range incidentIDs {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.incident_id, v.verdict
		FROM incident_verdicts v
		JOIN (SELECT incident_id, MAX(version) AS mv FROM incident_verdicts
		      WHERE incident_id IN (`+placeholders+`) GROUP BY incident_id) m
		  ON m.incident_id = v.incident_id AND m.mv = v.version`, args...) // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(incidentIDs) only; all runtime values bound via ? in args
	if err != nil {
		return nil, fmt.Errorf("store: latest verdict kinds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, kind string
		if err := rows.Scan(&id, &kind); err != nil {
			return nil, fmt.Errorf("store: scan verdict kind: %w", err)
		}
		out[id] = kind
	}
	return out, rows.Err()
}
