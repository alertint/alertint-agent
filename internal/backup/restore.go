// SPDX-License-Identifier: FSL-1.1-ALv2

package backup

import (
	"context"
	"database/sql"
	"fmt"

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
