// SPDX-License-Identifier: FSL-1.1-ALv2

// Package backup implements the operational safety net for the agent's
// SQLite state: consistent live snapshots (Create) and the safe-by-
// construction restore swap shared by the offline CLI and serve's staged
// startup path (Restore, ApplyStaged). See ADR-0030: the store is only
// ever swapped when the agent provably isn't holding it.
package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// DefaultTarget names a backup of dbPath taken at now, per the file-naming
// contract: "<dbbase>-<UTC-stamp>.backup.db" (sortable, colon-free), in
// the current working directory.
func DefaultTarget(dbPath string, now time.Time) string {
	base := strings.TrimSuffix(filepath.Base(dbPath), ".db")
	return fmt.Sprintf("%s-%s.backup.db", base, now.UTC().Format("20060102T150405Z"))
}

// Create writes a transactionally consistent snapshot of the database at
// dbPath to target via VACUUM INTO, opening the source strictly read-only
// so a running agent is never disturbed and the source is never written.
// It refuses an existing target unless force; on any error the partial
// target is removed. Returns the snapshot size in bytes.
func Create(ctx context.Context, dbPath, target string, force bool) (int64, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return 0, fmt.Errorf("source database: %w", err)
	}
	if _, err := os.Stat(target); err == nil {
		if !force {
			return 0, fmt.Errorf("target %s already exists (use --force to overwrite)", target)
		}
		if err := os.Remove(target); err != nil {
			return 0, fmt.Errorf("remove existing target: %w", err)
		}
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, fmt.Errorf("open source read-only: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, target); err != nil {
		_ = os.Remove(target) // never leave a partial snapshot behind
		return 0, fmt.Errorf("vacuum into %s: %w", target, err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		return 0, fmt.Errorf("stat snapshot: %w", err)
	}
	return fi.Size(), nil
}
