// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"time"
)

// WindowIncident is one other-key incident whose activity falls inside the
// verification round's own-state contrast window (spec R4: "is anything else
// firing right now?"). Severity is the incident's max member severity by
// rank (critical > high > warning > everything else), display-only — never
// used for filtering or scoring.
type WindowIncident struct {
	GroupKey   string
	Status     string
	Severity   string
	AlertCount int
}

// severityRankSQL orders a member alert's severity label so a correlated
// subselect can pick the incident's highest-ranked member. Local to this
// file: IncidentsInWindow is the only query that needs a per-incident max
// severity.
const severityRankSQL = `CASE json_extract(a.labels_json, '$.severity')
	WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END`

// incidentsInWindowWhere builds the WHERE clause shared by the count and
// top-N queries: activity inside the window, excluding the calling incident
// and its own group_key. When excludeDrills is set it also excludes any
// incident with a member alert carrying the Drill-alert marker
// (DrillMarkerLabel=DrillMarkerValue, ADR-0013) — the same marker
// IncidentDrillFlags checks — so a drill run's contrast isn't inflated by
// real incidents and vice versa. Returns the clause and its positional args
// (excluding the trailing LIMIT arg, added by the caller).
func incidentsInWindowWhere(since time.Time, excludeIncidentID, excludeGroupKey string, excludeDrills bool) (string, []any) {
	where := `WHERE last_alert_at >= ? AND id != ? AND group_key != ?`
	args := []any{since.UTC().Format(time.RFC3339Nano), excludeIncidentID, excludeGroupKey}
	if excludeDrills {
		where += `
			AND NOT EXISTS (
				SELECT 1 FROM incident_alerts ia
				JOIN alerts a ON a.id = ia.alert_id
				WHERE ia.incident_id = incidents.id
				  AND json_extract(a.labels_json, '$.` + DrillMarkerLabel + `') = ?
			)`
		args = append(args, DrillMarkerValue)
	}
	return where, args
}

// IncidentsInWindow reports the incidents on OTHER group keys whose activity
// falls inside [since, now] — the verification round's own-state contrast
// check ("is anything else firing right now?", spec R4). total is the full
// matching count; top is the most-recent-first rows, capped at limit
// (limit <= 0 returns every matching row, uncapped). excludeIncidentID and
// excludeGroupKey keep the calling incident, and any sibling incident on its
// own group_key, out of its own contrast.
func (s *Store) IncidentsInWindow(ctx context.Context, since time.Time,
	excludeIncidentID, excludeGroupKey string, excludeDrills bool, limit int,
) (int, []WindowIncident, error) {
	where, args := incidentsInWindowWhere(since, excludeIncidentID, excludeGroupKey, excludeDrills)

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents `+where, args...,
	).Scan(&total); err != nil {
		return 0, nil, fmt.Errorf("store: count incidents in window: %w", err)
	}
	if total == 0 {
		return 0, nil, nil
	}

	topQuery := `
		SELECT group_key, status, alert_count,
		       COALESCE((
		           SELECT json_extract(a.labels_json, '$.severity')
		           FROM incident_alerts ia
		           JOIN alerts a ON a.id = ia.alert_id
		           WHERE ia.incident_id = incidents.id
		           ORDER BY ` + severityRankSQL + ` DESC
		           LIMIT 1
		       ), '') AS severity
		FROM incidents ` + where + `
		ORDER BY last_alert_at DESC`
	topArgs := args
	if limit > 0 {
		topQuery += " LIMIT ?"
		topArgs = append(append([]any{}, args...), limit)
	}

	rows, err := s.db.QueryContext(ctx, topQuery, topArgs...)
	if err != nil {
		return total, nil, fmt.Errorf("store: list incidents in window: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var top []WindowIncident
	for rows.Next() {
		var wi WindowIncident
		if err := rows.Scan(&wi.GroupKey, &wi.Status, &wi.AlertCount, &wi.Severity); err != nil {
			return total, nil, fmt.Errorf("store: scan incident in window: %w", err)
		}
		top = append(top, wi)
	}
	if err := rows.Err(); err != nil {
		return total, nil, fmt.Errorf("store: incidents in window rows: %w", err)
	}
	return total, top, nil
}
