// SPDX-License-Identifier: FSL-1.1-ALv2

package backup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdmissionCheck(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	valid := newStoreDB(t, dir, "valid.db")

	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not a sqlite file at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A perfectly healthy SQLite DB that is not an alertint database.
	foreign := filepath.Join(dir, "foreign.db")
	fdb, err := sql.Open("sqlite", "file:"+foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fdb.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	_ = fdb.Close()

	// A valid alertint DB claiming a future schema version.
	future := newStoreDB(t, dir, "future.db")
	fdb2, err := sql.Open("sqlite", "file:"+future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fdb2.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (9999, '2026-07-28T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_ = fdb2.Close()

	cases := []struct {
		name, file, wantSubstr string
		wantOK                 bool
	}{
		{"valid alertint db passes", valid, "", true},
		{"garbage file rejected", garbage, "", false},
		{"foreign sqlite db rejected", foreign, "not an alertint database", false},
		{"newer schema rejected", future, "newer than this binary", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admissionCheck(ctx, tc.file)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("admissionCheck = %v, want ok", err)
				}
				return
			}
			if err == nil {
				t.Fatal("admissionCheck = ok, want failure")
			}
			var adm *AdmissionError
			if !errors.As(err, &adm) {
				t.Fatalf("error %v is not an *AdmissionError", err)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not contain %q", err, tc.wantSubstr)
			}
		})
	}
}

// readProbeCount opens dbPath read-only and returns COUNT(*) of audit_log.
func readProbeCount(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRestore_HappyPathOverExistingDB(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	dbPath := newStoreDB(t, dir, "live.db")     // 1 probe row
	backupFile := newStoreDB(t, dir, "snap.db") // separate DB, 1 probe row
	// Make the current DB distinguishable: add a second row.
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_log (ts, actor, kind, payload_json, prev_hash, hash)
		 VALUES ('2026-07-28T00:00:01Z', 'test', 'test.probe', '{}', 'h0', 'h1')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	info, err := Restore(ctx, dbPath, backupFile)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// Sidecars swept: the flip removed -wal/-shm. Checked before any
	// subsequent open of dbPath — backupFile here is itself a WAL-format
	// store.Open database (unlike a real Create/VACUUM INTO backup, which
	// is rollback-journal), so a later read-only open would legitimately
	// recreate them as it services reads against the installed content.
	for _, side := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if _, err := os.Stat(side); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("sidecar %s still present (err=%v)", side, err)
		}
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("restored DB rows = %d, want 1 (the backup's content)", got)
	}
	if got := readProbeCount(t, dbPath+".pre-restore"); got != 2 {
		t.Errorf("safety copy rows = %d, want 2 (the previous content)", got)
	}
	if info.SafetyCopy != dbPath+".pre-restore" {
		t.Errorf("SafetyCopy = %q", info.SafetyCopy)
	}
	if info.Mode != "offline" || info.SourceBytes <= 0 || info.InstalledBytes <= 0 {
		t.Errorf("info = %+v", info)
	}
	// Offline mode preserves the backup file.
	if _, err := os.Stat(backupFile); err != nil {
		t.Errorf("backup file consumed in offline mode: %v", err)
	}
}

func TestRestore_RefusesWhileAgentHoldsDB(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := newStoreDB(t, dir, "live.db")
	backupFile := newStoreDB(t, dir, "snap.db")

	// Simulated live agent: an open store connection, idle. The
	// journal-mode flip must fail SQLITE_BUSY even against an idle holder
	// (spike-verified; wal_checkpoint would NOT catch this).
	agent, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=journal_mode(wal)")
	if err != nil {
		t.Fatal(err)
	}
	agent.SetMaxOpenConns(1)
	if err := agent.Ping(); err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	_, rerr := Restore(ctx, dbPath, backupFile)
	if rerr == nil || !strings.Contains(rerr.Error(), "agent appears to be running") {
		t.Fatalf("Restore err = %v, want 'agent appears to be running'", rerr)
	}
	var adm *AdmissionError
	if errors.As(rerr, &adm) {
		t.Error("busy-guard failure must NOT be an AdmissionError (staged mode would wrongly consume the staging file)")
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("current DB modified by refused restore: rows = %d", got)
	}
	if _, err := os.Stat(dbPath + ".pre-restore"); !errors.Is(err, os.ErrNotExist) {
		t.Error("refused restore created a safety copy")
	}
}

func TestRestore_IntoEmptyDirIsLegal(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	backupFile := newStoreDB(t, dir, "snap.db")
	dbPath := filepath.Join(dir, "fresh", "alertint-agent.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		t.Fatal(err)
	}

	info, err := Restore(ctx, dbPath, backupFile)
	if err != nil {
		t.Fatalf("Restore into empty dir: %v", err)
	}
	if info.SafetyCopy != "" {
		t.Errorf("SafetyCopy = %q, want empty (no previous DB)", info.SafetyCopy)
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("restored rows = %d, want 1", got)
	}
}

// Crash between safety-copy rename and install: DB missing, .pre-restore
// intact, backup untouched — and the documented recovery (rename back,
// retry) works.
func TestRestore_CrashAfterSafetyCopyIsRecoverable(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := newStoreDB(t, dir, "live.db")
	backupFile := newStoreDB(t, dir, "snap.db")

	testHookAfterSafetyCopy = func() { panic("simulated crash") }
	defer func() { testHookAfterSafetyCopy = nil }()

	func() {
		defer func() { _ = recover() }()
		_, _ = Restore(ctx, dbPath, backupFile)
		t.Error("expected simulated crash panic")
	}()

	// Documented post-crash state.
	if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DB path state after crash: %v", err)
	}
	if got := readProbeCount(t, dbPath+".pre-restore"); got != 1 {
		t.Fatalf("safety copy rows = %d, want 1", got)
	}
	if _, err := os.Stat(backupFile); err != nil {
		t.Fatalf("backup file touched by crashed restore: %v", err)
	}

	// Documented recovery: rename back, retry.
	testHookAfterSafetyCopy = nil
	if err := os.Rename(dbPath+".pre-restore", dbPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, dbPath, backupFile); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("restored rows = %d, want 1", got)
	}
}

func TestApplyStaged_NoStagingFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	dbPath := newStoreDB(t, dir, "live.db")
	info, err := ApplyStaged(context.Background(), dbPath)
	if info != nil || err != nil {
		t.Fatalf("ApplyStaged = (%+v, %v), want (nil, nil)", info, err)
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("DB modified by no-op: rows = %d", got)
	}
}

func TestApplyStaged_AppliesAndConsumesStagingFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := newStoreDB(t, dir, "live.db")
	staged := newStoreDB(t, dir, "incoming.db")
	if err := os.Rename(staged, StagingPath(dbPath)); err != nil {
		t.Fatal(err)
	}

	info, err := ApplyStaged(ctx, dbPath)
	if err != nil {
		t.Fatalf("ApplyStaged: %v", err)
	}
	if info == nil || info.Mode != "staged" {
		t.Fatalf("info = %+v, want staged", info)
	}
	// Staging file consumed — a crash loop can never re-apply it.
	if _, err := os.Stat(StagingPath(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Error("staging file still present after successful staged restore")
	}
	if got := readProbeCount(t, dbPath+".pre-restore"); got != 1 {
		t.Errorf("safety copy rows = %d, want 1", got)
	}
}

func TestApplyStaged_AdmissionFailureRejectsAside(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := newStoreDB(t, dir, "live.db")
	if err := os.WriteFile(StagingPath(dbPath), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := ApplyStaged(ctx, dbPath)
	if err == nil || info != nil {
		t.Fatalf("ApplyStaged = (%+v, %v), want admission error", info, err)
	}
	// Evidence preserved at .rejected; staging gone; original untouched.
	if _, statErr := os.Stat(StagingPath(dbPath) + ".rejected"); statErr != nil {
		t.Errorf("rejected file missing: %v", statErr)
	}
	if _, statErr := os.Stat(StagingPath(dbPath)); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("staging file still present — next start would crash-loop")
	}
	if got := readProbeCount(t, dbPath); got != 1 {
		t.Errorf("original DB touched: rows = %d", got)
	}
}

func TestApplyStaged_TransientFailureLeavesStagingInPlace(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := newStoreDB(t, dir, "live.db")
	staged := newStoreDB(t, dir, "incoming.db")
	if err := os.Rename(staged, StagingPath(dbPath)); err != nil {
		t.Fatal(err)
	}

	// Another process holds the DB: transient, NOT an admission failure.
	holder, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=journal_mode(wal)")
	if err != nil {
		t.Fatal(err)
	}
	holder.SetMaxOpenConns(1)
	if err := holder.Ping(); err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	_, aerr := ApplyStaged(ctx, dbPath)
	if aerr == nil {
		t.Fatal("expected busy-guard error")
	}
	if _, statErr := os.Stat(StagingPath(dbPath)); statErr != nil {
		t.Errorf("staging file consumed on transient failure: %v", statErr)
	}
	if _, statErr := os.Stat(StagingPath(dbPath) + ".rejected"); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("transient failure produced a .rejected file")
	}
}
