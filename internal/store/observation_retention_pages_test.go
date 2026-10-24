// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// retentionPagesFixture is twenty sealed cycles with one shared timestamp, so
// every page boundary falls inside a tie. Cycles 0-3 and 12-17 are pinned as
// decision evidence, so both walks (details oldest first, cycles newest first)
// meet history that never expires before the rest.
func retentionPagesFixture(t *testing.T) (*Store, time.Time) {
	t.Helper()
	st := newTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, cycles := metadataRetentionCyclesAt(t, st, 20, false, false, 0, start)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, cycle := range cycles {
		if i < 4 || (i >= 12 && i < 18) {
			if err := insertPermanentObservationReferencesTx(ctx, tx, cycle.ID, ObservationReferenceAssessmentAttempt, "retained-decision", start); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return st, start.Add(11 * 24 * time.Hour)
}

func retentionPagesState(t *testing.T, st *Store) string {
	t.Helper()
	tables := []string{"situation_preparation_cycles", "situation_observation_runs",
		"situation_observation_fact_payloads", "situation_observation_detail_expirations", "situation_observation_references"}
	parts := make([]string, 0, len(tables))
	for _, table := range tables {
		parts = append(parts, fmt.Sprintf("%s=%d", table, metadataCount(t, st, table)))
	}
	return strings.Join(parts, " ")
}

func TestObservationRetentionPassWalksPastProtectedHistory(t *testing.T) {
	whole, at := retentionPagesFixture(t)
	wantN, err := whole.PruneObservationRetention(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	want := retentionPagesState(t, whole)
	if wantN == 0 {
		t.Fatalf("one-page pass pruned nothing: %s", want)
	}

	// A three-row page, then a page that stops after its first row.
	for _, budget := range []time.Duration{time.Minute, 0} {
		t.Run(fmt.Sprintf("page-time=%s", budget), func(t *testing.T) {
			rows, pageTime := observationRetentionPageRows, observationRetentionPageTime
			observationRetentionPageRows, observationRetentionPageTime = 3, budget
			t.Cleanup(func() { observationRetentionPageRows, observationRetentionPageTime = rows, pageTime })

			st, at := retentionPagesFixture(t)
			ctx := context.Background()
			n, err := st.PruneObservationRetention(ctx, at)
			if err != nil {
				t.Fatal(err)
			}
			if got := retentionPagesState(t, st); n != wantN || got != want {
				t.Fatalf("paged pass pruned %d to %s, want %d to %s", n, got, wantN, want)
			}
			if n, err := st.PruneObservationRetention(ctx, at); err != nil || n != 0 {
				t.Fatalf("second pass pruned %d %v, want 0", n, err)
			}
		})
	}
}

// A page whose query had to sort would read every candidate before its first
// row, which is the whole protected history the pages exist to spread out.
func TestObservationRetentionPagesReadTheirIndexInOrder(t *testing.T) {
	st := newTestStore(t)
	for _, q := range []struct {
		name, sql, index string
		args             []any
	}{
		{"details", observationDetailPage, "situation_observation_query_runs_pending_details_idx", []any{"", "", "", "", "", 1}},
		{"cycles", observationCyclePage, "situation_preparation_cycles_retention_idx", []any{"", "", "", "", 0, 1}},
	} {
		top, err := topLevelPlan(st, q.sql, q.args...)
		if err != nil {
			t.Fatalf("%s: %v", q.name, err)
		}
		plan := strings.Join(top, "; ")
		if !strings.Contains(plan, q.index) || strings.Contains(plan, "ORDER BY") {
			t.Errorf("%s page plan %q: want %s in order, no sort", q.name, plan, q.index)
		}
	}
}

// topLevelPlan is the EXPLAIN QUERY PLAN steps of query's outermost level.
func topLevelPlan(st *Store, query string, args ...any) ([]string, error) {
	rows, err := st.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var top []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			return nil, err
		}
		if parent == 0 {
			top = append(top, detail)
		}
	}
	return top, rows.Err()
}
