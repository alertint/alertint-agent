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

// WatchConnectionWait logs a warning for every interval in which store calls
// waited at least threshold in total for the store connection. Readiness no
// longer reports a busy store (Probe), so this is where a congested one
// shows. A call's wait is counted when it gets the connection. It returns
// when ctx is done.
func (s *Store) WatchConnectionWait(ctx context.Context, logger *slog.Logger, interval, threshold time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := s.db.Stats()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := s.db.Stats()
		if waited := now.WaitDuration - last.WaitDuration; waited >= threshold {
			logger.Warn("store: connection congested",
				slog.Duration("waited", waited),
				slog.Int64("waits", now.WaitCount-last.WaitCount),
				slog.Duration("interval", interval),
			)
		}
		last = now
	}
}
