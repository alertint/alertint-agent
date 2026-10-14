// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Completed dispatches span distinct input versions; each spends one legal
// attempt and has one immutable outcome. The current basis already matches.
func seedCompletedRecoveryHistory(tb testing.TB, st *Store, count int) time.Time {
	tb.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	at := canonicalTime(now)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO situations
		(id,group_key,lifecycle,attention,input_version,opened_at,effective_started_at,
		effective_started_at_basis,first_received_at,last_lifecycle_observed_at,
		next_assessment_at,due_reasons_json,created_at,updated_at,current_material_fact_hash,controller_work_attempts)
		VALUES ('recovery-history','service=recovery-history','active','observe',?, ?,?,'receipt_fallback',?,?,?,'[]',?,?,'completed-basis',1)`,
		count, at, at, at, at, canonicalTime(now.Add(time.Hour)), at, at)
	if err != nil {
		tb.Fatal(err)
	}
	calls, err := tx.PrepareContext(ctx, `INSERT INTO situation_assessment_calls
		(id,situation_id,input_version,retry_epoch,work_attempt,call_number,material_fact_hash,dispatched_at)
		VALUES (?,'recovery-history',?,0,1,1,'completed-basis',?)`)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = calls.Close() }()
	outcomes, err := tx.PrepareContext(ctx, `INSERT INTO situation_assessment_attempts
		(id,situation_id,sequence,input_version,retry_epoch,work_attempt,call_id,status,provider_request_started,material_fact_hash,created_at,completed_at)
		VALUES (?,'recovery-history',?,?,0,1,?,'failed','true','completed-basis',?,?)`)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = outcomes.Close() }()
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("history-call-%08d", i)
		dispatched := canonicalTime(now.Add(time.Duration(i-count) * time.Second))
		if _, err := calls.ExecContext(ctx, id, i, dispatched); err != nil {
			tb.Fatal(err)
		}
		if _, err := outcomes.ExecContext(ctx, "outcome-"+id, i, i, id, dispatched, dispatched); err != nil {
			tb.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
	return now
}

func recoveryHistoryStore(tb testing.TB, count int) (*Store, time.Time) {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "history.db")
	if err := writeMigratedTestDatabase(path); err != nil {
		tb.Fatal(err)
	}
	st, err := openTestStoreWithMigrations(context.Background(), path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := st.Close(); err != nil {
			tb.Error(err)
		}
	})
	return st, seedCompletedRecoveryHistory(tb, st, count)
}

func BenchmarkControllerRecoveryCompletedHistory(b *testing.B) {
	for _, count := range []int{1000, 10000, 50000} {
		for _, op := range []string{"backfill", "assessment", "triage", "horizon", "all"} {
			b.Run(fmt.Sprintf("rows=%d/%s", count, op), func(b *testing.B) {
				st, now := recoveryHistoryStore(b, count)
				b.ResetTimer()
				for range b.N {
					ctx := context.Background()
					var n int
					var err error
					if op == "backfill" || op == "all" {
						n, err = st.BackfillUpgradedIncidentTriageSchedule(ctx, now)
						if err != nil || n != 0 {
							b.Fatalf("backfill %d %v", n, err)
						}
					}
					if op == "assessment" || op == "all" {
						n, err = st.RecoverInterruptedAssessmentCalls(ctx, now)
						if err != nil || n != 0 {
							b.Fatalf("assessment %d %v", n, err)
						}
					}
					if op == "triage" || op == "all" {
						n, err = st.RecoverExpiredIncidentTriageAttempts(ctx, now)
						if err != nil || n != 0 {
							b.Fatalf("triage %d %v", n, err)
						}
					}
					if op == "horizon" || op == "all" {
						v, e := st.ExhaustOverdueUnclaimedIncidentTriage(ctx, now, time.Hour)
						if e != nil || len(v) != 0 {
							b.Fatalf("horizon %d %v", len(v), e)
						}
					}
				}
				b.ReportMetric(float64(count), "history-rows")
			})
		}
	}
}

func TestControllerRecoveryCompletedHistoryWithinBudget(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("set ALERTINT_LARGE_DB_TEST=1")
	}
	st, now := recoveryHistoryStore(t, 10000)
	before := st.db.Stats()
	start := time.Now()
	n, err := st.RecoverInterruptedAssessmentCalls(context.Background(), now)
	elapsed := time.Since(start)
	t.Logf("10000 completed calls: recovery=%s recovered=%d pool_wait=%s", elapsed, n, st.db.Stats().WaitDuration-before.WaitDuration)
	if err != nil || n != 0 {
		t.Fatalf("recovery=%d, %v", n, err)
	}
	if elapsed > time.Second {
		t.Fatalf("no-work recovery took %s, budget 1s", elapsed)
	}
	var calls, outcomes int
	if err := st.db.QueryRowContext(context.Background(), `SELECT (SELECT count(*) FROM situation_assessment_calls),(SELECT count(*) FROM situation_assessment_attempts)`).Scan(&calls, &outcomes); err != nil {
		t.Fatal(err)
	}
	if calls != 10000 || outcomes != 10000 {
		t.Fatalf("history changed: %d calls, %d outcomes", calls, outcomes)
	}
}
