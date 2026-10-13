// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAssessmentRecoveryLookupUpgradeAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "released-43.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	st := &Store{db: db}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version <= 43 {
			if err := st.applyMigration(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := seedCompletedRecoveryHistory(t, st, 100)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	var applied string
	for range 3 {
		st, err = openTestStoreWithMigrations(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		var indexSQL, stamp string
		if err := st.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name='situation_assessment_attempts_call_idx'`).Scan(&indexSQL); err != nil {
			t.Fatalf("missing assessment recovery lookup: %v", err)
		}
		if err := st.db.QueryRowContext(ctx, `SELECT applied_at FROM schema_migrations WHERE version=44`).Scan(&stamp); err != nil {
			t.Fatal(err)
		}
		if applied != "" && stamp != applied {
			t.Fatal("migration reapplied on reopen")
		}
		applied = stamp
		var calls, outcomes int
		if err := st.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM situation_assessment_calls),(SELECT count(*) FROM situation_assessment_attempts)`).Scan(&calls, &outcomes); err != nil {
			t.Fatal(err)
		}
		if calls != 100 || outcomes != 100 {
			t.Fatalf("upgrade changed immutable history: %d %d", calls, outcomes)
		}
		if n, err := st.RecoverInterruptedAssessmentCalls(ctx, now); err != nil || n != 0 {
			t.Fatalf("completed recovery: %d %v", n, err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAssessmentRecoveryLookupInterruptedMigration(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("set ALERTINT_LARGE_DB_TEST=1")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "interrupted-43.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	st := &Store{db: db}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version <= 43 {
			if err := st.applyMigration(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	seedCompletedRecoveryHistory(t, st, 100000)
	var canceled bool
	for _, m := range migrations {
		if m.version == 44 {
			limited, cancel := context.WithTimeout(ctx, time.Millisecond)
			err = st.applyMigration(limited, m)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected interrupted index build, got %v", err)
			}
			canceled = true
		}
	}
	if !canceled {
		t.Fatal("migration 44 absent")
	}
	var ledger, index int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM schema_migrations WHERE version=44),(SELECT count(*) FROM sqlite_master WHERE name='situation_assessment_attempts_call_idx')`).Scan(&ledger, &index); err != nil {
		t.Fatal(err)
	}
	if ledger != 0 || index != 0 {
		t.Fatalf("partial migration: ledger=%d index=%d", ledger, index)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM situation_assessment_attempts`).Scan(&ledger); err != nil || ledger != 100000 {
		t.Fatalf("retry lost history: %d %v", ledger, err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=44`).Scan(&ledger); err != nil || ledger != 1 {
		t.Fatalf("retry missing migration: %d %v", ledger, err)
	}
}

func TestAssessmentRecoveryLookupPreservesResults(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		live, completed, stale bool
		want                   int
	}{
		{"orphan", false, false, false, 1},
		{"live-orphan", true, false, false, 0},
		{"completed", false, true, false, 0},
		{"completed-stale-basis", false, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
			id := newSituationForGroup(t, st, "lookup-"+tc.name, now)
			claim := claimSituation(t, st, id, "lookup-owner", now)
			call := callFixture("lookup-call", id, 1, 1, 1, now)
			if err := st.RecordAssessmentCall(ctx, claim, call); err != nil {
				t.Fatal(err)
			}
			if tc.completed {
				if _, err := st.db.ExecContext(ctx, `INSERT INTO situation_assessment_attempts
				(id,situation_id,sequence,input_version,retry_epoch,work_attempt,call_id,status,provider_request_started,material_fact_hash,created_at,completed_at)
				VALUES ('completed',?,1,1,0,1,?,'failed','true',?,?,?)`, id, call.ID, call.MaterialFactHash, canonicalTime(now), canonicalTime(now)); err != nil {
					t.Fatal(err)
				}
			}
			// A non-model stale outcome has no call_id and must not mask an orphan.
			if _, err := st.db.ExecContext(ctx, `INSERT INTO situation_assessment_attempts
				(id,situation_id,sequence,input_version,retry_epoch,work_attempt,status,provider_request_started,material_fact_hash,created_at,completed_at)
				VALUES ('deterministic-stale',?,2,1,0,1,'stale','false',?,?,?)`, id, call.MaterialFactHash, canonicalTime(now), canonicalTime(now)); err != nil {
				t.Fatal(err)
			}
			basis := call.MaterialFactHash
			if tc.stale {
				basis = "old-basis"
			}
			if _, err := st.db.ExecContext(ctx, `UPDATE situations SET current_material_fact_hash=?,controller_work_attempts=1 WHERE id=?`, basis, id); err != nil {
				t.Fatal(err)
			}
			at := now.Add(2 * time.Minute)
			if tc.live {
				at = now.Add(time.Second)
			}
			if n, err := st.RecoverInterruptedAssessmentCalls(ctx, at); err != nil || n != tc.want {
				t.Fatalf("recovered %d %v, want %d", n, err, tc.want)
			}
			if n, err := st.RecoverInterruptedAssessmentCalls(ctx, at); err != nil || n != 0 {
				t.Fatalf("replay %d %v", n, err)
			}
			var gotBasis string
			var epoch, attempts int
			if err := st.db.QueryRowContext(ctx, `SELECT current_material_fact_hash,controller_retry_epoch,controller_work_attempts FROM situations WHERE id=?`, id).Scan(&gotBasis, &epoch, &attempts); err != nil {
				t.Fatal(err)
			}
			wantEpoch := 0
			if tc.stale {
				wantEpoch = 1
			}
			if gotBasis != call.MaterialFactHash || epoch != wantEpoch || attempts != 1 {
				t.Fatalf("basis/budget changed: %q epoch=%d attempts=%d", gotBasis, epoch, attempts)
			}
			if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
				t.Fatalf("foreign keys %d %v", n, err)
			}
		})
	}
}
