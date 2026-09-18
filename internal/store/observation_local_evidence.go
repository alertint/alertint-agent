// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// PriorTerminalSituationSummaries returns the most recent, bounded prior
// terminal Situations sharing groupKey (excluding excludeSituationID),
// newest first, for the store_read capability (spec.md capability table:
// "bounded prior Situations ... SQL LIMIT before decoding"). limit is
// clamped to [1,100].
func (s *Store) PriorTerminalSituationSummaries(ctx context.Context, groupKey, excludeSituationID string, limit int) ([]observationmodel.LocalSituationSummary, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, effective_started_at, terminal_at, terminal_reason
		FROM situations
		WHERE group_key = ? AND id != ? AND lifecycle IN ('recovered','closed_unknown')
		ORDER BY terminal_at DESC, id DESC
		LIMIT ?`, groupKey, excludeSituationID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query prior terminal situations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []observationmodel.LocalSituationSummary{}
	for rows.Next() {
		var (
			id, startedStr             string
			terminalAt, terminalReason sql.NullString
		)
		if err := rows.Scan(&id, &startedStr, &terminalAt, &terminalReason); err != nil {
			return nil, fmt.Errorf("store: scan prior terminal situation summary: %w", err)
		}
		started, err := time.Parse(time.RFC3339Nano, startedStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse prior situation effective_started_at: %w", err)
		}
		summary := observationmodel.LocalSituationSummary{ID: id, EffectiveStartedAt: started}
		if terminalAt.Valid {
			t, err := time.Parse(time.RFC3339Nano, terminalAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse prior situation terminal_at: %w", err)
			}
			summary.TerminalAt = t
		}
		if terminalReason.Valid {
			summary.TerminalReason = terminalReason.String
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate prior terminal situation summaries: %w", err)
	}
	return out, nil
}

// RecentFindingsForGroup returns the most recent, bounded durable Acute
// Triage findings for groupKey's incidents, newest first, for the
// store_read capability. limit is clamped to [1,100].
func (s *Store) RecentFindingsForGroup(ctx context.Context, groupKey string, since time.Time, limit int) ([]observationmodel.LocalFinding, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(last_judged_at, created_at), COALESCE(summary,''), COALESCE(root_cause,''), COALESCE(confidence,0.0)
		FROM incidents
		WHERE group_key = ? AND status IN ('analyzed','resolved') AND COALESCE(last_judged_at, created_at) >= ?
		ORDER BY COALESCE(last_judged_at, created_at) DESC, id DESC
		LIMIT ?`, groupKey, canonicalTime(since), limit)
	if err != nil {
		return nil, fmt.Errorf("store: query recent findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []observationmodel.LocalFinding{}
	for rows.Next() {
		var (
			incidentID, analyzedAtStr, summary, rootCause string
			confidence                                    float64
		)
		if err := rows.Scan(&incidentID, &analyzedAtStr, &summary, &rootCause, &confidence); err != nil {
			return nil, fmt.Errorf("store: scan recent finding: %w", err)
		}
		analyzedAt, err := time.Parse(time.RFC3339Nano, analyzedAtStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse finding analyzed_at: %w", err)
		}
		out = append(out, observationmodel.LocalFinding{
			IncidentID: incidentID, AnalyzedAt: analyzedAt,
			Summary: summary, RootCause: rootCause, Confidence: confidence,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate recent findings: %w", err)
	}
	return out, nil
}
