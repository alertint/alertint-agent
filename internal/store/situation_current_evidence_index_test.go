// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
)

func TestCurrentEvidenceIndexUpgradeAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "released-42.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	st := &Store{db: db}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version <= 42 {
			if err := st.applyMigration(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	id, cycles := metadataRetentionCycles(t, st, 3, false, false)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		st, err = openTestStoreWithMigrations(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		sit, err := st.GetSituation(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		in, err := st.LoadReconciliationInput(ctx, situation.Claim{Situation: sit}, cycles[2].Draft.Anchor)
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Prepared.Runs) != 1 || in.Prepared.Runs[0].ID != "run:consolidation:metadata-2" {
			t.Fatalf("upgrade lost latest outcome: %+v", in.Prepared.Runs)
		}
		if got := metadataCount(t, st, "situation_observation_query_runs"); got != 3 {
			t.Fatalf("indexed runs = %d, want 3", got)
		}
		if got := metadataCount(t, st, "situation_observation_query_slots"); got != 1 {
			t.Fatalf("query slots = %d, want 1", got)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCurrentEvidenceIndexRollsBackWithRun(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	ctx := context.Background()
	fence := observationmodel.Fence{SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "config-a", Plans: []observationmodel.Plan{testPlan(now)}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	run := consolidationRun("rollback-index", cycle, now)
	if _, err := st.db.ExecContext(context.Background(), `CREATE TRIGGER fail_reference BEFORE INSERT ON situation_observation_references BEGIN SELECT RAISE(ABORT, 'injected reference failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitObservationRun(ctx, fence, run, now); err == nil {
		t.Fatal("expected commit failure")
	}
	for _, table := range []string{"situation_observation_runs", "situation_observation_query_runs", "situation_observation_query_slots"} {
		if got := metadataCount(t, st, table); got != 0 {
			t.Fatalf("failed commit left %d rows in %s", got, table)
		}
	}
	if _, err := st.db.ExecContext(context.Background(), `DROP TRIGGER fail_reference`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := st.CommitObservationRun(ctx, fence, run, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := metadataCount(t, st, "situation_observation_query_runs"); got != 1 {
		t.Fatalf("replay indexed %d runs, want 1", got)
	}
}

func TestCurrentEvidenceIndexPrunesWithUnusedHistory(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 3, false, false)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 2 {
		t.Fatalf("prune = %d, %v; want 2", n, err)
	}
	if got := metadataCount(t, st, "situation_observation_query_runs"); got != 1 {
		t.Fatalf("retention left %d query pointers, want 1", got)
	}
	if got := metadataCount(t, st, "situation_observation_query_slots"); got != 1 {
		t.Fatalf("retention lost current query slot: %d", got)
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys: %d, %v", n, err)
	}
	// Once the input changes and its temporary references/cursor are retired,
	// deleting the final historical run also removes the empty dictionary slot.
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET input_version=input_version+1, current_preparation_cycle_id=NULL;
		UPDATE situation_observation_references SET superseded=1 WHERE permanent=0;
		DELETE FROM situation_observation_refresh`); err != nil {
		t.Fatal(err)
	}
	expireMetadataFixture(t, st, at)
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 1 {
		t.Fatalf("final prune = %d, %v; want 1", n, err)
	}
	for _, table := range []string{"situation_observation_query_runs", "situation_observation_query_slots"} {
		if got := metadataCount(t, st, table); got != 0 {
			t.Fatalf("final prune left %d rows in %s", got, table)
		}
	}
}

func TestCurrentEvidencePreservesHistoricalDecisionBasis(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "", "", observationmodel.ResultConfirmedEmpty)
	first, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	seedEvidenceCycle(t, st, claim, now.Add(time.Second), "config-a", observationmodel.CapabilityPrometheusQuery, "", "", observationmodel.ResultFailed)
	// A slot which only exists after the decision must not enter its basis.
	seedEvidenceCycle(t, st, claim, now.Add(2*time.Second), "config-a", observationmodel.CapabilityLokiQuery, "", "", observationmodel.ResultConfirmedEmpty)
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	runs, _, err := loadCurrentEvidenceTx(context.Background(), tx, claim.Situation.ID, first.Prepared.Runs[0].CycleID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != first.Prepared.Runs[0].ID || runs[0].Status != observationmodel.ResultConfirmedEmpty {
		t.Fatalf("historical basis changed: %+v", runs)
	}
}

// Opt-in because generating 100,000 real SQLite history rows is a performance
// regression experiment, rather than a fast unit test. It uses the same one-
// second budget as /ready and runs with ALERTINT_LARGE_DB_TEST=1.
func TestCurrentEvidenceLargeHistory(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("set ALERTINT_LARGE_DB_TEST=1 for the large-history regression")
	}
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "", "", observationmodel.ResultFailed)
	initial, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	cloneEvidenceHistory(t, tx, "situation_preparation_cycles", initial.Prepared.Runs[0].CycleID, map[string]string{"id": "'history-cycle:'||n", "generation": "generation+n"})
	cloneEvidenceHistory(t, tx, "situation_observation_plans", initial.Prepared.Runs[0].PlanID, map[string]string{"id": "'history-plan:'||n", "cycle_id": "'history-cycle:'||n"})
	cloneEvidenceHistory(t, tx, "situation_observation_runs", initial.Prepared.Runs[0].ID, map[string]string{"id": "'history-run:'||n", "plan_id": "'history-plan:'||n", "cycle_id": "'history-cycle:'||n"})
	if _, err := tx.ExecContext(context.Background(), `UPDATE situations SET current_preparation_cycle_id='history-cycle:100000', preparation_generation=100001 WHERE id=?`, claim.Situation.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("large-history read exceeds readiness budget: %v", err)
	}
	if len(in.Prepared.Runs) != 1 || in.Prepared.Runs[0].ID != "history-run:100000" || in.Prepared.Runs[0].Status != observationmodel.ResultFailed {
		t.Fatalf("latest failed result replaced or omitted: %+v", in.Prepared.Runs)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fence := observationmodel.Fence{SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	if _, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now.Add(time.Minute), ConfigDigest: "config-a", Plans: []observationmodel.Plan{testPlan(now.Add(time.Minute))}}, 4); err != nil {
		t.Fatalf("new cycle exceeds readiness budget: %v", err)
	}
}

// Copy a real, committed fixture's immutable metadata, with new relational IDs.
// Column discovery keeps the fixture compatible with released-schema additions.
func cloneEvidenceHistory(t *testing.T, tx *sql.Tx, table, id string, replacements map[string]string) {
	t.Helper()
	rows, err := tx.QueryContext(context.Background(), `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var columns, values []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		quoted := `"` + name + `"`
		columns = append(columns, quoted)
		if replacement, ok := replacements[name]; ok {
			values = append(values, replacement)
		} else {
			values = append(values, quoted)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	query := fmt.Sprintf(`WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<100000)
		INSERT INTO %s (%s) SELECT %s FROM %s CROSS JOIN numbers WHERE id=?`, table, strings.Join(columns, ","), strings.Join(values, ","), table)
	if _, err := tx.ExecContext(context.Background(), query, id); err != nil {
		t.Fatal(err)
	}
}
