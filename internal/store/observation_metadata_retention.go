// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PruneUnusedObservationMetadata removes sealed cycles older than ten days
// after their unused payloads have expired. Current query-slot heads, decision
// evidence, reuse sources, refresh cursors and source provenance remain intact.
// Each call commits at most 100 cycles; deleted SQLite pages are reusable by
// future writes without running a blocking VACUUM.
func (s *Store) PruneUnusedObservationMetadata(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin observation metadata retention: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		WITH protected_heads AS MATERIALIZED (
		  SELECT DISTINCT cycle_id FROM situation_observation_current_heads
		)
		SELECT c.id FROM situation_preparation_cycles c
		WHERE c.sealed = 1 AND c.sealed_at <= ?
		  AND NOT EXISTS (SELECT 1 FROM situations s WHERE s.current_preparation_cycle_id = c.id)
		  AND c.id NOT IN (SELECT cycle_id FROM protected_heads)
		  AND NOT EXISTS (SELECT 1 FROM situation_observation_refresh f WHERE f.admitted_cycle_id = c.id)
		  AND NOT EXISTS (
		    SELECT 1 FROM situation_observation_runs r WHERE r.cycle_id = c.id AND (
		      NOT EXISTS (SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = r.id)
		      OR EXISTS (SELECT 1 FROM situation_observation_references ref WHERE ref.run_id = r.id AND (ref.permanent = 1 OR ref.superseded = 0))
		      OR EXISTS (SELECT 1 FROM situation_observation_runs p WHERE p.reused_from_run_id = r.id)
		      OR EXISTS (SELECT 1 FROM situation_observation_plans p WHERE p.reuse_run_id = r.id)
		      OR EXISTS (SELECT 1 FROM situation_observation_refresh f WHERE f.last_run_id = r.id)
		      OR EXISTS (SELECT 1 FROM zabbix_source_observations z WHERE z.run_id = r.id)
		    )
		  )
		ORDER BY c.sealed_at DESC, c.generation DESC, c.id DESC LIMIT ?`, canonicalTime(now.Add(-observationDetailRetention)), limit)
	if err != nil {
		return 0, fmt.Errorf("store: select unused observation metadata: %w", err)
	}
	cycleIDs, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read unused observation cycles: %w", err)
	}
	for _, cycleID := range cycleIDs {
		if err := pruneObservationCycleTx(ctx, tx, cycleID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit observation metadata retention: %w", err)
	}
	return len(cycleIDs), nil
}

func pruneObservationCycleTx(ctx context.Context, tx *sql.Tx, cycleID string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO situation_preparation_pruning (cycle_id) VALUES (?)`, cycleID); err != nil {
		return fmt.Errorf("store: authorize observation retention: %w", err)
	}
	// Delete children before parents. References owned by a reuse cycle may
	// target a source run in another cycle, so remove those superseded pointers
	// as well as references to this cycle's own runs.
	statements := []string{
		`DELETE FROM situation_observation_request_outcomes WHERE reservation_id IN (SELECT id FROM situation_observation_requests WHERE cycle_id = ?)`,
		`DELETE FROM situation_observation_requests WHERE cycle_id = ?`,
		`DELETE FROM situation_observation_references WHERE permanent = 0 AND superseded = 1 AND owner_id = ?`,
		`DELETE FROM situation_observation_references WHERE run_id IN (SELECT id FROM situation_observation_runs WHERE cycle_id = ?)`,
		`DELETE FROM situation_observation_facts WHERE run_id IN (SELECT id FROM situation_observation_runs WHERE cycle_id = ?)`,
		`DELETE FROM situation_observation_detail_expirations WHERE run_id IN (SELECT id FROM situation_observation_runs WHERE cycle_id = ?)`,
		`DELETE FROM situation_observation_runs WHERE cycle_id = ?`,
		`DELETE FROM situation_observation_plans WHERE cycle_id = ?`,
		`DELETE FROM situation_preparation_cycles WHERE id = ?`,
		`DELETE FROM situation_preparation_pruning WHERE cycle_id = ?`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, cycleID); err != nil {
			return fmt.Errorf("store: prune observation cycle %s: %w", cycleID, err)
		}
	}
	return nil
}
