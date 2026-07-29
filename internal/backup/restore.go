// SPDX-License-Identifier: FSL-1.1-ALv2

package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alertint/alertint-agent/internal/store"
)

// AdmissionError marks a restore input that failed the deterministic
// Admission check: corrupt, not an alertint database, or schema newer
// than this binary. Staged mode sets the staging file aside as
// <db>.restore.rejected only for admission failures; every other failure
// (busy guard, I/O) is transient and leaves the staging file in place.
type AdmissionError struct{ err error }

func (e *AdmissionError) Error() string { return e.err.Error() }
func (e *AdmissionError) Unwrap() error { return e.err }

func admissionFailf(format string, args ...any) error {
	return &AdmissionError{err: fmt.Errorf(format, args...)}
}

// admissionCheck verifies file is a healthy alertint database this binary
// can serve. Read-only; the file is never modified.
func admissionCheck(ctx context.Context, file string) error {
	db, err := sql.Open("sqlite", "file:"+file+"?mode=ro")
	if err != nil {
		return admissionFailf("open backup read-only: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res); err != nil {
		return admissionFailf("integrity check: %w", err)
	}
	if res != "ok" {
		return admissionFailf("integrity check failed: %s", res)
	}

	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&count); err != nil {
		return admissionFailf("inspect schema: %w", err)
	}
	if count == 0 {
		// integrity_check passes for ANY healthy SQLite file; this is what
		// rejects "staged the wrong app's DB".
		return admissionFailf("not an alertint database (no schema_migrations table)")
	}

	var backupMax int
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`,
	).Scan(&backupMax); err != nil {
		return admissionFailf("read schema version: %w", err)
	}
	binaryMax, err := store.MaxSchemaVersion()
	if err != nil {
		return fmt.Errorf("embedded migrations: %w", err) // binary defect, not the backup's fault
	}
	if backupMax > binaryMax {
		return admissionFailf(
			"backup schema v%d is newer than this binary (v%d); upgrade alertint or use an older backup",
			backupMax, binaryMax)
	}
	return nil
}

// RestoreInfo describes a completed swap, for startup logs and the
// db.restore_applied audit row.
type RestoreInfo struct {
	Mode           string // "offline" | "staged"
	SourceFile     string
	SafetyCopy     string // "" when no previous DB existed
	SourceBytes    int64
	InstalledBytes int64
}

// testHookAfterSafetyCopy, when non-nil, runs between the safety-copy
// rename and the install — the crash-safety window the spec documents.
// Test seam only; nil in production.
var testHookAfterSafetyCopy func()

// Restore performs an offline restore of backupFile onto dbPath: the
// Admission check, the exclusivity guard, the Safety copy, then an atomic
// install. The backup file is preserved. See ADR-0030.
func Restore(ctx context.Context, dbPath, backupFile string) (*RestoreInfo, error) {
	return swap(ctx, dbPath, backupFile, "offline")
}

func swap(ctx context.Context, dbPath, source, mode string) (*RestoreInfo, error) {
	if err := admissionCheck(ctx, source); err != nil {
		return nil, err
	}
	srcInfo, err := os.Stat(source)
	if err != nil {
		return nil, fmt.Errorf("stat backup: %w", err)
	}

	info := &RestoreInfo{Mode: mode, SourceFile: source, SourceBytes: srcInfo.Size()}

	// Steps 2–3 run only over an existing DB; restoring into an empty data
	// dir is legal in both modes (first boot staged, new-host offline).
	if _, err := os.Stat(dbPath); err == nil {
		if err := foldAndProveExclusive(ctx, dbPath); err != nil {
			return nil, err
		}
		info.SafetyCopy = dbPath + ".pre-restore"
		if err := os.Rename(dbPath, info.SafetyCopy); err != nil {
			return nil, fmt.Errorf("safety copy: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat current database: %w", err)
	}

	if testHookAfterSafetyCopy != nil {
		testHookAfterSafetyCopy()
	}

	// Pre-install sweep: normally the flip already removed the sidecars;
	// this covers the skipped-steps path after unusual crash histories.
	for _, side := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(side); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("remove stale sidecar %s: %w", side, err)
		}
	}

	if err := install(dbPath, source, mode); err != nil {
		return nil, err
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		return nil, fmt.Errorf("stat installed database: %w", err)
	}
	info.InstalledBytes = fi.Size()
	return info, nil
}

// foldAndProveExclusive flips the current DB out of WAL mode. The flip
// checkpoints the WAL into the main file and deletes the sidecars (so the
// Safety copy is complete), and fails SQLITE_BUSY if ANY other connection
// has the DB open — even idle. wal_checkpoint(TRUNCATE) does NOT give
// that guarantee (spike-verified: it succeeds against an idle agent).
func foldAndProveExclusive(ctx context.Context, dbPath string) error {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(2000)")
	if err != nil {
		return fmt.Errorf("open current database: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode); err != nil {
		if strings.Contains(err.Error(), "SQLITE_BUSY") {
			return fmt.Errorf("agent appears to be running (database is locked); stop the agent, or stage the file as %s and restart", StagingPath(dbPath))
		}
		return fmt.Errorf("fold wal: %w", err)
	}
	return nil
}

// install puts source at dbPath atomically. Staged mode renames the
// staging file itself (same directory, atomic, consumed — a crash-looping
// pod can never re-apply an old restore). Offline mode copies via a temp
// file in the DB's directory + fsync + rename, preserving the backup.
func install(dbPath, source, mode string) error {
	if mode == "staged" {
		if err := os.Rename(source, dbPath); err != nil {
			return fmt.Errorf("install staged file: %w", err)
		}
		return nil
	}
	dir := filepath.Dir(dbPath)
	src, err := os.Open(source) // #nosec G304 -- operator-supplied backup path; reading it is the point
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer func() { _ = src.Close() }()

	tmp, err := os.CreateTemp(dir, ".alertint-restore-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after successful rename

	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy backup: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), dbPath); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// StagingPath returns the exact path whose presence triggers a Staged
// restore for dbPath: "<db>.restore" — this path and nothing else.
func StagingPath(dbPath string) string { return dbPath + ".restore" }
