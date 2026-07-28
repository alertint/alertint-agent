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

// VerdictSourceHuman marks a verdict captured explicitly over MCP: an
// operator-confirmed label, worth full label_confidence. Harvested channels
// (revert reconciliation, silence) get their own source values and lower
// confidence when they land — a verdict row is never written without
// provenance, so a harvested label can never masquerade as a human one.
const VerdictSourceHuman = "human"

// IncidentVerdict is one version of an incident's captured verdict.
// Append-only; the highest version is operative. The existence of any row IS
// the derived verdict marker (spec: marker is derived, never stored).
type IncidentVerdict struct {
	ID              int64
	IncidentID      string
	Version         int
	Verdict         string // correction | confirmation
	Source          string // label provenance, e.g. VerdictSourceHuman
	LabelConfidence float64
	ExpectationJSON string
	WidenedJSON     string // "" when no widened entries
	CauseCategory   string // free-form, "" when absent
	// Note is the verdict's operator note (the newest annotation of the verdict's
	// kind on its incident). Populated only by GoverningVerdict; "" elsewhere.
	Note      string
	CreatedAt time.Time
}

// VerdictCapture is the persist-phase input: verdict row + matching
// annotation row + (iff DemoteMarksFloor > 0) the D3 demotion, atomically.
type VerdictCapture struct {
	IncidentID       string
	Verdict          string // correction | confirmation
	Source           string
	LabelConfidence  float64 // (0, 1]
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
	if c.Source == "" {
		return nil, nil, errors.New("store: verdict source empty — every verdict carries provenance")
	}
	if c.LabelConfidence <= 0 || c.LabelConfidence > 1 {
		return nil, nil, fmt.Errorf("store: label_confidence %v outside (0, 1]", c.LabelConfidence)
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
			(incident_id, version, verdict, source, label_confidence, expectation_json, widened_json, cause_category, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.IncidentID, version, c.Verdict, c.Source, c.LabelConfidence,
		c.ExpectationJSON, widened, cause, now.Format(time.RFC3339Nano))
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
		Source: c.Source, LabelConfidence: c.LabelConfidence,
		ExpectationJSON: c.ExpectationJSON, WidenedJSON: c.WidenedJSON,
		CauseCategory: c.CauseCategory, CreatedAt: now,
	}, ann, nil
}

// LatestIncidentVerdict returns the operative (highest-version) verdict of an
// incident, or nil, nil when none exists.
func (s *Store) LatestIncidentVerdict(ctx context.Context, incidentID string) (*IncidentVerdict, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, version, verdict, source, label_confidence, expectation_json,
		       COALESCE(widened_json, ''), COALESCE(cause_category, ''), created_at
		FROM incident_verdicts WHERE incident_id = ?
		ORDER BY version DESC LIMIT 1`, incidentID)
	var v IncidentVerdict
	var created string
	if err := row.Scan(&v.ID, &v.IncidentID, &v.Version, &v.Verdict, &v.Source, &v.LabelConfidence,
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

// GoverningVerdict returns the latest captured verdict of any kind on a group
// key — the single operator artifact triage consumes (ADR-0029). Unbounded by
// lookback: human writes are permanent, superseded only by a newer capture.
// Drill parity applies: drill verdicts govern only drill triage, real only
// real. Verdicts on the incident currently being triaged are included (a
// correction on it steers its own re-judgment). Returns nil, nil when the key
// carries no verdict.
func (s *Store) GoverningVerdict(ctx context.Context, groupKey string, currentIsDrill bool) (*IncidentVerdict, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.incident_id, v.version, v.verdict, v.source, v.label_confidence,
		       v.expectation_json, COALESCE(v.widened_json, ''), COALESCE(v.cause_category, ''),
		       COALESCE((SELECT a.note FROM incident_annotations a
		                 WHERE a.incident_id = v.incident_id AND a.kind = v.verdict
		                 ORDER BY a.created_at DESC, a.id DESC LIMIT 1), ''),
		       v.created_at
		FROM incident_verdicts v
		JOIN incidents i ON i.id = v.incident_id
		WHERE i.group_key = ?
		ORDER BY v.created_at DESC, v.id DESC`, groupKey)
	if err != nil {
		return nil, fmt.Errorf("store: governing verdict: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var candidates []IncidentVerdict
	for rows.Next() {
		var v IncidentVerdict
		var created string
		if err := rows.Scan(&v.ID, &v.IncidentID, &v.Version, &v.Verdict, &v.Source,
			&v.LabelConfidence, &v.ExpectationJSON, &v.WidenedJSON, &v.CauseCategory,
			&v.Note, &created); err != nil {
			return nil, fmt.Errorf("store: governing verdict scan: %w", err)
		}
		if v.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, fmt.Errorf("store: governing verdict parse created_at: %w", err)
		}
		candidates = append(candidates, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: governing verdict rows: %w", err)
	}
	if len(candidates) == 0 {
		return nil, nil //nolint:nilnil // callers distinguish not-found by nil pointer, not sentinel
	}
	ids := make([]string, len(candidates))
	for i := range candidates {
		ids[i] = candidates[i].IncidentID
	}
	flags, err := s.IncidentDrillFlags(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("store: governing verdict drill flags: %w", err)
	}
	for i := range candidates {
		if flags[candidates[i].IncidentID] == currentIsDrill {
			return &candidates[i], nil
		}
	}
	return nil, nil //nolint:nilnil // callers distinguish not-found by nil pointer, not sentinel
}
