// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Select only bounded operator fields in the same transaction as membership,
// assessment and journal. Raw outputs, queries and enrichment never cross it.
func loadSituationAnalysesTx(ctx context.Context, tx *sql.Tx, id string) ([]model.IncidentAnalysis, int, error) {
	rows, err := tx.QueryContext(ctx, `
 SELECT i.id, substr(COALESCE(i.summary,''),1,181), substr(COALESCE(i.root_cause,''),1,501),
   (SELECT json_group_array(value) FROM (
     SELECT substr(value,1,401) AS value FROM json_each(CASE WHEN json_valid(i.output_json) THEN i.output_json ELSE '{}' END, '$.correlation_findings')
     WHERE type='text' LIMIT 3)),
   substr(COALESCE(json_extract(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.outcome'),''),1,40),
   substr(COALESCE(json_extract(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.degradation_reason'),''),1,100),
   i.last_judged_at, i.last_alert_at,
   (SELECT COUNT(*) FROM json_each(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.rounds') r,
     json_each(CASE WHEN r.type='object' THEN r.value ELSE '{}' END,'$.queries') q
     WHERE COALESCE(json_extract(CASE WHEN q.type='object' THEN q.value ELSE '{}' END,'$.outcome'),'') NOT IN ('fetched','empty')),
   COUNT(*) OVER ()
 FROM situation_incidents si JOIN incidents i ON i.id=si.incident_id
 WHERE si.situation_id=? AND i.status IN ('analyzed','resolved')
   AND (COALESCE(i.summary,'')<>'' OR COALESCE(i.root_cause,'')<>'')
 ORDER BY i.last_judged_at DESC, i.id ASC LIMIT 3`, id)
	if err != nil {
		return nil, 0, fmt.Errorf("store: load situation analyses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []model.IncidentAnalysis
	var total int
	for rows.Next() {
		var a model.IncidentAnalysis
		var findings, last string
		var judged sql.NullString
		if err := rows.Scan(&a.IncidentID, &a.Title, &a.Summary, &findings, &a.Verification, &a.VerificationLimit, &judged, &last, &a.VerificationGaps, &total); err != nil {
			return nil, 0, fmt.Errorf("store: scan situation analysis: %w", err)
		}
		if err := json.Unmarshal([]byte(findings), &a.Findings); err != nil {
			return nil, 0, fmt.Errorf("store: decode selected analysis findings: %w", err)
		}
		if judged.Valid {
			at, err := time.Parse(time.RFC3339Nano, judged.String)
			if err != nil {
				return nil, 0, fmt.Errorf("store: parse analysis time: %w", err)
			}
			at = at.UTC()
			a.AnalyzedAt = &at
			latest, err := time.Parse(time.RFC3339Nano, last)
			if err != nil {
				return nil, 0, fmt.Errorf("store: parse analysis member time: %w", err)
			}
			a.Stale = latest.After(at)
		} else {
			a.Stale = true
		}
		out = append(out, model.BoundIncidentAnalysis(a))
	}
	return out, total, rows.Err()
}
