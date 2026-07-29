// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/backup"
	"github.com/alertint/alertint-agent/internal/store"
)

// seedAudit opens dbPath as a store and appends one real audit row so the
// chain is non-empty and verifiable.
func seedAudit(t *testing.T, dbPath, kind string) {
	t.Helper()
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := audit.New(st.DB()).Append(context.Background(), "test", kind, map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
}

func lastAuditKind(t *testing.T, dbPath string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var kind string
	if err := db.QueryRowContext(context.Background(), `SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	return kind
}

func TestRunRestore_RequiresBackupFileArgument(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	var stdout, stderr bytes.Buffer
	err := run([]string{"restore", "--db", dbPath}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "<backup-file>") {
		t.Fatalf("err = %v, want usage error naming <backup-file>", err)
	}
}

func TestRunRestore_FullRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	seedAudit(t, dbPath, "test.before_backup")

	// Take a real backup, then diverge the live DB.
	backupFile := filepath.Join(dir, "snap.backup.db")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"backup", "--db", dbPath, backupFile}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	seedAudit(t, dbPath, "test.after_backup") // live-only row, lost on restore

	stdout.Reset()
	if err := run([]string{"restore", "--db", dbPath, backupFile}, &stdout, &stderr); err != nil {
		t.Fatalf("restore: %v (stderr=%s)", err, stderr.String())
	}

	// Restored chain: the pre-backup row, then the db.restore_applied row.
	if got := lastAuditKind(t, dbPath); got != "db.restore_applied" {
		t.Errorf("last audit kind = %q, want db.restore_applied", got)
	}
	// The live-only row is on the safety copy, not the restored DB.
	if got := lastAuditKind(t, dbPath+".pre-restore"); got != "test.after_backup" {
		t.Errorf("safety copy last kind = %q, want test.after_backup", got)
	}
	// The restored chain still verifies (restore_applied extends it validly).
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := audit.New(st.DB()).Verify(context.Background()); err != nil {
		t.Errorf("restored chain fails verify: %v", err)
	}
	// Backup file preserved; stdout names the safety copy.
	if _, err := os.Stat(backupFile); err != nil {
		t.Errorf("backup file consumed: %v", err)
	}
	if !strings.Contains(stdout.String(), ".pre-restore") {
		t.Errorf("stdout %q does not mention the safety copy", stdout.String())
	}
}

func TestRunRestore_RefusesGarbageBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	bad := filepath.Join(dir, "bad.backup.db")
	if err := os.WriteFile(bad, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"restore", "--db", dbPath, bad}, &stdout, &stderr)
	if err == nil || !strings.HasPrefix(err.Error(), "restore: ") {
		t.Fatalf("err = %v, want 'restore: ...' admission refusal", err)
	}
	if _, statErr := os.Stat(dbPath + ".pre-restore"); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("refused restore created a safety copy")
	}
}

func TestOpenStoreWithStagedRestore_AppliesAndServesRestoredData(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	dbPath := newTestDB(t, dir)
	seedAudit(t, dbPath, "test.live_only")

	// Stage a distinguishable backup.
	incoming := filepath.Join(dir, "incoming.db")
	ist, err := store.Open(ctx, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.New(ist.DB()).Append(ctx, "test", "test.from_backup", nil); err != nil {
		t.Fatal(err)
	}
	_ = ist.Close()
	if err := os.Rename(incoming, backup.StagingPath(dbPath)); err != nil {
		t.Fatal(err)
	}

	st, info, err := openStoreWithStagedRestore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("openStoreWithStagedRestore: %v", err)
	}
	defer func() { _ = st.Close() }()
	if info == nil || info.Mode != "staged" {
		t.Fatalf("info = %+v, want staged restore applied", info)
	}
	// The open store serves the restored data.
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE kind = 'test.from_backup'`).Scan(&count); err != nil || count != 1 {
		t.Errorf("restored row count = %d (err=%v), want 1", count, err)
	}
	// Staging consumed; previous DB at the safety copy.
	if _, err := os.Stat(backup.StagingPath(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Error("staging file not consumed")
	}
	if _, err := os.Stat(dbPath + ".pre-restore"); err != nil {
		t.Errorf("safety copy missing: %v", err)
	}
}

func TestOpenStoreWithStagedRestore_RejectedStagingErrorsOut(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	dbPath := newTestDB(t, dir)
	if err := os.WriteFile(backup.StagingPath(dbPath), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := openStoreWithStagedRestore(ctx, dbPath, logger)
	if err == nil {
		t.Fatal("expected error for rejected staging file — serve must exit non-zero")
	}
	// Evidence preserved, original untouched: the NEXT start serves normally.
	if _, statErr := os.Stat(backup.StagingPath(dbPath) + ".rejected"); statErr != nil {
		t.Errorf(".rejected file missing: %v", statErr)
	}
	st, info, err := openStoreWithStagedRestore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("second start after rejection: %v", err)
	}
	defer func() { _ = st.Close() }()
	if info != nil {
		t.Errorf("second start applied a restore: %+v", info)
	}
}

func TestOpenStoreWithStagedRestore_NoStagingIsPlainOpen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	dbPath := newTestDB(t, dir)

	st, info, err := openStoreWithStagedRestore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("plain open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if info != nil {
		t.Errorf("info = %+v, want nil (nothing staged)", info)
	}
}
