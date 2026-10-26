// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"
)

// Retention walks each candidate list once per pass, in pages: one page is one
// transaction that reads at most observationRetentionPageRows candidates, for
// about observationRetentionPageTime, then prunes up to a few of them. A cycle
// takes about as long to remove as a hundred runs take to expire, hence the
// smaller cap. Old history that something still protects grows forever;
// walking it once per batch held the store's only connection for seconds
// every hour (issue #99). Between pages every other store call gets it.
var (
	observationRetentionPageRows = 512
	observationRetentionPageTime = 100 * time.Millisecond
)

const (
	observationDetailPageExpiries = 100
	observationCyclePagePrunes    = 5
)

// PruneObservationRetention runs one retention pass at now: it expires every
// unused detail past the ten-day cutoff, drops the refresh cursors that read
// as no cursor, then removes every sealed cycle left with nothing to keep.
// Returns the expired runs, dropped cursors and removed cycles.
func (s *Store) PruneObservationRetention(ctx context.Context, now time.Time) (int, error) {
	return s.PruneObservationRetentionBefore(ctx, now, now.Add(-observationDetailRetention))
}

// PruneObservationRetentionBefore is PruneObservationRetention with an
// explicit cutoff: storage retention moves it later than ten days ago when
// the database outgrows its size limit.
func (s *Store) PruneObservationRetentionBefore(ctx context.Context, now, cutoff time.Time) (int, error) {
	runs, err := s.pruneObservationDetails(ctx, now, cutoff, 0)
	if err != nil {
		return runs, err
	}
	cursors, err := s.pruneStaleRefreshCursors(ctx, cutoff)
	if err != nil {
		return runs + cursors, err
	}
	cycles, err := s.pruneObservationMetadata(ctx, cutoff, 0)
	return runs + cursors + cycles, err
}

// pruneStaleRefreshCursors deletes the refresh cursors due since before
// cutoff whose last run's detail has expired. Such a cursor reads exactly
// like no cursor (due, nothing to reuse: LoadObservationRefreshCursors), but
// it pins its last run's cycle, so a subject never served again (a pod that
// went away) kept that cycle forever. Migration 0027 calls cursors never
// deleted; that holds for every cursor that still changes what the preparer
// does. A subject served again starts a new cursor.
func (s *Store) pruneStaleRefreshCursors(ctx context.Context, cutoff time.Time) (int, error) {
	var after int64
	before := cutoffText(cutoff)
	return s.retentionPages(ctx, "prune stale refresh cursors", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT rowid FROM situation_observation_refresh
			WHERE rowid > ? AND next_refresh_at < ?
			  AND (last_run_id IS NULL OR EXISTS (
			    SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = last_run_id))
			ORDER BY rowid LIMIT ?`, after, before, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select stale refresh cursors: %w", err)
		}
		rowIDs, err := scanRowIDs(rows)
		if err != nil {
			return 0, false, err
		}
		for i, rowID := range rowIDs {
			if i > 0 && time.Now().After(deadline) {
				return i, false, nil
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM situation_observation_refresh WHERE rowid = ?`, rowID); err != nil {
				return i, false, fmt.Errorf("delete stale refresh cursor: %w", err)
			}
			after = rowID
		}
		return len(rowIDs), len(rowIDs) < retentionPageRows, nil
	})
}

// PruneUnusedObservationMetadata removes sealed cycles older than ten days
// after their unused payloads have expired. Current query-slot heads, decision
// evidence, reuse sources, refresh cursors and source provenance remain intact.
// Each call removes at most limit cycles (at most 100), newest first, in short
// pages; deleted SQLite pages are reusable by future writes without running a
// blocking VACUUM.
func (s *Store) PruneUnusedObservationMetadata(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return s.pruneObservationMetadata(ctx, now.Add(-observationDetailRetention), limit)
}

// pruneObservationMetadata removes unused cycles sealed before cutoff page by
// page from the newest such cycle until upTo are removed (0: no limit) or none
// is left. Newest first: a cycle that reuses an older one's run is removed
// before the walk reaches the older cycle it was protecting.
func (s *Store) pruneObservationMetadata(ctx context.Context, cutoff time.Time, upTo int) (int, error) {
	total, cursor := 0, observationCycleCursor{}
	for {
		limit := observationCyclePagePrunes
		if upTo > 0 && upTo-total < limit {
			limit = upTo - total
		}
		n, next, done, err := s.pruneObservationMetadataPage(ctx, cutoff, cursor, limit)
		total += n
		if err != nil || done || (upTo > 0 && total >= upTo) {
			return total, err
		}
		cursor = next
	}
}

// observationCycleCursor is the last sealed cycle a metadata page examined.
// rowid breaks ties in sealed_at the way the retention index orders them.
type observationCycleCursor struct {
	sealedAt string
	rowID    int64
}

// observationCyclePage examines sealed cycles before a cursor in the
// retention index's order; like observationDetailPage, eligibility is a
// column computed as each row is read.
const observationCyclePage = `
	WITH protected_heads AS MATERIALIZED (
	  SELECT DISTINCT cycle_id FROM situation_observation_current_heads
	)
	SELECT c.sealed_at, c.rowid, c.id,
	  (substr(c.sealed_at, 1, 19) || '.' ||
	   substr(substr(rtrim(c.sealed_at, 'Z'), 21) || '000000000', 1, 9) || 'Z') <= ?
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
	FROM situation_preparation_cycles c
	WHERE c.sealed = 1 AND c.sealed_at < ?
	  AND c.sealed_at <= ? AND (c.sealed_at < ? OR c.rowid < ?)
	ORDER BY c.sealed_at DESC, c.rowid DESC
	LIMIT ?`

// pruneObservationMetadataPage reads one page of sealed cycles before `after`
// and removes up to limit unused ones in the same transaction. done reports
// that the page reached the oldest sealed cycle.
func (s *Store) pruneObservationMetadataPage(ctx context.Context, cutoff time.Time, after observationCycleCursor, limit int) (int, observationCycleCursor, bool, error) {
	if after.sealedAt == "" {
		upperBound, _ := observationRetentionCutoff(cutoff)
		after = observationCycleCursor{sealedAt: upperBound, rowID: math.MaxInt64}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, after, false, fmt.Errorf("store: begin observation metadata retention: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cycleIDs, next, done, err := readObservationCyclePage(ctx, tx, cutoff, after, limit)
	if err != nil {
		return 0, after, false, err
	}

	for _, cycleID := range cycleIDs {
		if err := pruneObservationCycleTx(ctx, tx, cycleID); err != nil {
			return 0, after, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, after, false, fmt.Errorf("store: commit observation metadata retention: %w", err)
	}
	return len(cycleIDs), next, done, nil
}

// readObservationCyclePage reads one cycles page: the unused cycles among at
// most observationRetentionPageRows sealed cycles before `after`, stopping
// early at limit unused cycles or after observationRetentionPageTime.
func readObservationCyclePage(ctx context.Context, tx *sql.Tx, at time.Time, after observationCycleCursor, limit int) ([]string, observationCycleCursor, bool, error) {
	upperBound, cutoff := observationRetentionCutoff(at)
	started := time.Now()
	rows, err := tx.QueryContext(ctx, observationCyclePage, cutoff, upperBound,
		after.sealedAt, after.sealedAt, after.rowID, observationRetentionPageRows)
	if err != nil {
		return nil, after, false, fmt.Errorf("store: select unused observation metadata: %w", err)
	}
	defer func() { _ = rows.Close() }()
	next, read := after, 0
	var cycleIDs []string
	for rows.Next() {
		var cycleID string
		var prunable bool
		if err := rows.Scan(&next.sealedAt, &next.rowID, &cycleID, &prunable); err != nil {
			return nil, after, false, fmt.Errorf("store: read unused observation cycle: %w", err)
		}
		read++
		if prunable {
			cycleIDs = append(cycleIDs, cycleID)
		}
		if len(cycleIDs) == limit || time.Since(started) >= observationRetentionPageTime {
			return cycleIDs, next, false, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, after, false, fmt.Errorf("store: read unused observation cycles: %w", err)
	}
	return cycleIDs, next, read < observationRetentionPageRows, nil
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

// Stored UTC RFC3339Nano timestamps omit trailing zeros, so their text order
// differs from time order within a second. Retention queries use an indexed
// next-second upper bound, then compare zero-padded fractions for exact expiry.
// Existing rows keep their original representation; no migration is needed.
func observationRetentionCutoff(at time.Time) (upperBound, cutoff string) {
	at = at.UTC()
	const layout = "2006-01-02T15:04:05.000000000Z"
	return at.Truncate(time.Second).Add(time.Second).Format(layout), at.Format(layout)
}
