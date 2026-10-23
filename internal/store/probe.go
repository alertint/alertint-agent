// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// buildProbeDSN is buildDSN for the probe handle: the same database, read
// only. WAL lets this reader run while the store connection is inside a long
// read or write; the busy timeout stays below a probe's own deadline.
func buildProbeDSN(dbPath string) string {
	pragmas := "_pragma=busy_timeout(500)&_pragma=query_only(1)"
	if dbPath == ":memory:" || dbPath == "" {
		return "file::memory:?cache=shared&" + pragmas
	}
	return "file:" + dbPath + "?" + pragmas
}

// Probe reports whether the database still answers a read. It runs on the
// probe handle, never on the store connection, so a long store call does not
// fail it: readiness used to queue behind every history read and flap
// (issue #99). Contention on the store connection is reported by
// ConnectionWait and WatchConnectionWait instead.
func (s *Store) Probe(ctx context.Context) error {
	db := s.probe
	if db == nil {
		db = s.db
	}
	var one int
	if err := db.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations LIMIT 1`).Scan(&one); err != nil {
		return fmt.Errorf("store: probe: %w", err)
	}
	return nil
}

// ConnectionWait is the store connection's contention since Open.
type ConnectionWait struct {
	// InUse is whether a store call holds the connection right now.
	InUse bool
	// Waits counts store calls that had to wait for the connection.
	Waits int64
	// Waited is the total time those calls waited.
	Waited time.Duration
}

// ConnectionWait reads the store connection's contention since Open.
func (s *Store) ConnectionWait() ConnectionWait {
	stats := s.db.Stats()
	return ConnectionWait{InUse: stats.InUse > 0, Waits: stats.WaitCount, Waited: stats.WaitDuration}
}

// ConnectionWatch sets what WatchConnectionWait reports.
type ConnectionWatch struct {
	// Interval is how often the store connection's waits are summed.
	Interval time.Duration
	// An interval is congested when its store calls waited at least Waited
	// in total and MeanWait on average. A busy agent makes thousands of short
	// waits a minute; the mean keeps those quiet (issue #99).
	Waited, MeanWait time.Duration
	// Hold is the shortest hold of the store connection worth naming. Zero
	// names none.
	Hold time.Duration
}

// congested reports whether an interval's waits make it congested.
// database/sql counts a wait when it starts and adds its time when it ends,
// so a long wait's time can land in the interval after its count. Comparing
// against MeanWait per counted wait, instead of dividing, still flags it.
func (w ConnectionWatch) congested(waited time.Duration, waits int64) bool {
	return waited >= w.Waited && waited >= w.MeanWait*time.Duration(waits)
}

// WatchConnectionWait logs a warning for every congested interval and for
// every hold of the store connection of at least watch.Hold, naming the store
// call that held it. Readiness no longer reports a busy store (Probe), so
// this is where a congested one shows. A call's wait is counted when it gets
// the connection, a hold when it gives the connection back. It returns when
// ctx is done.
func (s *Store) WatchConnectionWait(ctx context.Context, logger *slog.Logger, watch ConnectionWatch) {
	if s.holds != nil && watch.Hold > 0 {
		s.holds.threshold.Store(int64(watch.Hold))
		s.holds.logger.Store(logger)
		defer s.holds.logger.Store(nil)
	}
	ticker := time.NewTicker(watch.Interval)
	defer ticker.Stop()
	last := s.db.Stats()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := s.db.Stats()
		waited, waits := now.WaitDuration-last.WaitDuration, now.WaitCount-last.WaitCount
		if watch.congested(waited, waits) {
			logger.Warn("store: connection congested",
				slog.Duration("waited", waited),
				slog.Int64("waits", waits),
				slog.Duration("interval", watch.Interval),
			)
		}
		last = now
	}
}
