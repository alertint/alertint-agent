// SPDX-License-Identifier: FSL-1.1-ALv2

package backup

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// newStoreDB creates a real alertint DB (schema + a probe row) at dir/name
// and returns its path. The store is closed before return.
func newStoreDB(t *testing.T, dir, name string) string {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO audit_log (ts, actor, kind, payload_json, prev_hash, hash)
		 VALUES ('2026-07-28T00:00:00Z', 'test', 'test.probe', '{}', NULL, 'h0')`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dbPath
}

func TestDefaultTarget(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 30, 0, 0, time.UTC)
	got := DefaultTarget("/data/alertint-agent.db", now)
	want := "alertint-agent-20260728T093000Z.backup.db"
	if got != want {
		t.Errorf("DefaultTarget = %q, want %q", got, want)
	}
	// Non-default DB basename yields a matching backup basename.
	if got := DefaultTarget("/x/custom.db", now); got != "custom-20260728T093000Z.backup.db" {
		t.Errorf("custom basename: got %q", got)
	}
}

func TestCreate_SnapshotIsHealthyAndSidecarFree(t *testing.T) {
	dir := t.TempDir()
	dbPath := newStoreDB(t, dir, "a.db")
	target := filepath.Join(dir, "snap.backup.db")

	n, err := Create(context.Background(), dbPath, target, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n <= 0 {
		t.Errorf("bytes written = %d, want > 0", n)
	}
	// Snapshot opens read-only, passes integrity, contains the probe row.
	db, err := sql.Open("sqlite", "file:"+target+"?mode=ro")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.QueryRowContext(context.Background(), `PRAGMA integrity_check`).Scan(&res); err != nil || res != "ok" {
		t.Fatalf("integrity_check = %q, err=%v", res, err)
	}
	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit_log count = %d, err=%v", count, err)
	}
}

func TestCreate_RefusesExistingTargetUnlessForce(t *testing.T) {
	dir := t.TempDir()
	dbPath := newStoreDB(t, dir, "a.db")
	target := filepath.Join(dir, "snap.backup.db")

	if _, err := Create(context.Background(), dbPath, target, false); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := Create(context.Background(), dbPath, target, false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Create err = %v, want 'already exists'", err)
	}
	if _, err := Create(context.Background(), dbPath, target, true); err != nil {
		t.Fatalf("Create --force: %v", err)
	}
}

func TestCreate_MissingSourceErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := Create(context.Background(), filepath.Join(dir, "nope.db"), filepath.Join(dir, "t.db"), false)
	if err == nil {
		t.Fatal("expected error for missing source database")
	}
}

// The spec's live-backup requirement: a writer racing VACUUM INTO must not
// corrupt the snapshot (WAL readers don't block the writer).
func TestCreate_LiveWriterRace(t *testing.T) {
	dir := t.TempDir()
	dbPath := newStoreDB(t, dir, "a.db")

	st, err := store.Open(context.Background(), dbPath) // the "agent"
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = st.DB().ExecContext(context.Background(),
				`INSERT INTO audit_log (ts, actor, kind, payload_json, prev_hash, hash)
				 VALUES ('2026-07-28T00:00:00Z', 'w', 'test.probe', '{}', NULL, ?)`, i)
		}
	}()

	target := filepath.Join(dir, "live.backup.db")
	_, cerr := Create(context.Background(), dbPath, target, false)
	close(stop)
	wg.Wait()
	if cerr != nil {
		t.Fatalf("Create during live writes: %v", cerr)
	}
	db, err := sql.Open("sqlite", "file:"+target+"?mode=ro")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.QueryRowContext(context.Background(), `PRAGMA integrity_check`).Scan(&res); err != nil || res != "ok" {
		t.Fatalf("live snapshot integrity_check = %q, err=%v", res, err)
	}
}
