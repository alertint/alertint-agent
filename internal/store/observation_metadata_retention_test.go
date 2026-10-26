// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
)

// The fixture repeatedly seals cycles on the same input. Retrying an open
// cycle is intentionally not the growth scenario reported in issue #99.
func metadataRetentionCycles(t *testing.T, st *Store, count int, reuse bool, pinFirst bool, plans ...observationmodel.Plan) (string, []observationmodel.Cycle) {
	t.Helper()
	return metadataRetentionCyclesWithSpacing(t, st, count, reuse, pinFirst, 0, plans...)
}

func metadataRetentionCyclesWithSpacing(t *testing.T, st *Store, count int, reuse bool, pinFirst bool, spacing time.Duration, plans ...observationmodel.Plan) (string, []observationmodel.Cycle) {
	t.Helper()
	return metadataRetentionCyclesAt(t, st, count, reuse, pinFirst, spacing, time.Now().UTC(), plans...)
}

func metadataRetentionCyclesAt(t *testing.T, st *Store, count int, reuse bool, pinFirst bool, spacing time.Duration, now time.Time, plans ...observationmodel.Plan) (string, []observationmodel.Cycle) {
	t.Helper()
	ctx := context.Background()
	id := newSituationForGroup(t, st, "service=retention", now)
	claim := claimSituation(t, st, id, "metadata-retention", now)
	fence := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	var source string
	var cycles []observationmodel.Cycle
	for i := 0; i < count; i++ {
		at := now.Add(time.Duration(i) * spacing)
		plan := testPlan(now)
		if i < len(plans) {
			plan = plans[i]
		}
		if reuse && i > 0 {
			plan.Tier, plan.ReuseRunID = observationmodel.TierReuse, source
		}
		cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: at, ConfigDigest: "retention-config", Plans: []observationmodel.Plan{plan}}, 2)
		if err != nil {
			t.Fatal(err)
		}
		run := consolidationRun(fmt.Sprintf("metadata-%d", i), cycle, at)
		if i == 0 {
			source = run.ID
		} else if reuse {
			run.Facts, run.ReusedFromRunID = nil, &source
		}
		if err := st.CommitObservationRun(ctx, fence, run, at); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pinFirst && i == 0 {
			if err := insertPermanentObservationReferencesTx(ctx, tx, cycle.ID, ObservationReferenceAssessmentAttempt, "retained-decision", now); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		if err := sealPreparationCycleTx(ctx, tx, id, cycle.ID, at); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		cycles = append(cycles, cycle)
	}
	return id, cycles
}

func expireMetadataFixture(t *testing.T, st *Store, at time.Time) {
	t.Helper()
	for {
		n, err := st.PruneUnusedObservationDetails(context.Background(), at, 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func metadataCount(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestObservationMetadataPruningBoundsUnchangedReuse(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 200, true, false)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	total := 0
	for {
		n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100)
		if err != nil {
			t.Fatal(err)
		}
		if n > 100 {
			t.Fatalf("unbounded transaction: %d cycles", n)
		}
		total += n
		if n == 0 {
			break
		}
	}
	if total != 198 {
		t.Fatalf("pruned %d cycles, want 198; preserve current cycle and reused source", total)
	}
	for _, table := range []string{"situation_preparation_cycles", "situation_observation_plans", "situation_observation_runs"} {
		if n := metadataCount(t, st, table); n != 2 {
			t.Errorf("%s retained %d rows, want 2", table, n)
		}
	}
	if n := metadataCount(t, st, "situation_observation_references"); n != 4 {
		t.Errorf("retained %d references, want 4", n)
	}
	if n := metadataCount(t, st, "situation_observation_fact_payloads"); n != 1 {
		t.Errorf("reused source payloads=%d, want 1", n)
	}
}

func TestObservationMetadataPruningPreservesDecisionEvidence(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 3, false, true)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100)
	if err != nil || n != 1 {
		t.Fatalf("pruned=%d err=%v, want one unused cycle", n, err)
	}
	rec, found, err := st.LoadObservationRun(context.Background(), "run:consolidation:metadata-0")
	if err != nil || !found || rec.DetailState != observationmodel.DetailStateRetained || string(rec.Run.Facts[0].Value) != `{"up":1}` {
		t.Fatalf("decision evidence damaged: record=%+v found=%v err=%v", rec, found, err)
	}
	fullObservationPass(t, st, at)
	rec, found, err = st.LoadObservationRun(context.Background(), "run:consolidation:metadata-0")
	if err != nil || !found || rec.DetailState != observationmodel.DetailStateRetained || string(rec.Run.Facts[0].Value) != `{"up":1}` {
		t.Fatalf("a full pass damaged decision evidence: record=%+v found=%v err=%v", rec, found, err)
	}
}

func TestObservationMetadataPruningPreservesExpiredDecisionBasis(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 3, false, false)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	pinMetadataDecision(t, st, cycles[0].ID, at)
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 1 {
		t.Fatalf("expired decision basis: pruned=%d err=%v, want only the middle cycle", n, err)
	}
	rec, found, err := st.LoadObservationRun(context.Background(), "run:consolidation:metadata-0")
	if err != nil || !found || rec.DetailState != observationmodel.DetailStateExpired || len(rec.Run.Facts) != 1 || string(rec.Run.Facts[0].Value) != "null" {
		t.Fatalf("expired basis lost or resurrected: record=%+v found=%v err=%v", rec, found, err)
	}
	fullObservationPass(t, st, at)
	rec, found, err = st.LoadObservationRun(context.Background(), "run:consolidation:metadata-0")
	if err != nil || !found || rec.DetailState != observationmodel.DetailStateExpired || len(rec.Run.Facts) != 1 {
		t.Fatalf("a full pass lost the expired basis: record=%+v found=%v err=%v", rec, found, err)
	}
	if _, err := st.db.ExecContext(context.Background(), `INSERT INTO situation_observation_references
		(id, run_id, reference_kind, owner_id, permanent, created_at)
		VALUES ('invalid-live-ref', 'run:consolidation:metadata-0', 'current_cycle', 'expired', 0, ?)`, canonicalTime(at)); err == nil {
		t.Fatal("an expired payload accepted a live reference")
	}
}

func TestObservationMetadataPruningPreservesDecisionReuseProjection(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 4, true, false)
	pinMetadataDecision(t, st, cycles[1].ID, cycles[1].Draft.Anchor)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 1 {
		t.Fatalf("reuse decision basis: pruned=%d err=%v, want only the unused projection", n, err)
	}
	rec, found, err := st.LoadObservationRun(context.Background(), "run:consolidation:metadata-1")
	if err != nil || !found || rec.Run.ReusedFromRunID == nil || *rec.Run.ReusedFromRunID != "run:consolidation:metadata-0" || len(rec.Run.Facts) != 1 {
		t.Fatalf("decision projection lost: record=%+v found=%v err=%v", rec, found, err)
	}
	fullObservationPass(t, st, at)
	rec, found, err = st.LoadObservationRun(context.Background(), "run:consolidation:metadata-1")
	if err != nil || !found || rec.Run.ReusedFromRunID == nil || *rec.Run.ReusedFromRunID != "run:consolidation:metadata-0" || len(rec.Run.Facts) != 1 {
		t.Fatalf("a full pass lost the decision projection: record=%+v found=%v err=%v", rec, found, err)
	}
}

// fullObservationPass runs the whole observation retention pass at at,
// trimming included, so a protection test proves the trim keeps it too.
func fullObservationPass(t *testing.T, st *Store, at time.Time) {
	t.Helper()
	if _, err := st.PruneObservationRetention(context.Background(), at); err != nil {
		t.Fatalf("full observation retention pass: %v", err)
	}
}

func pinMetadataDecision(t *testing.T, st *Store, cycleID string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertPermanentObservationReferencesTx(ctx, tx, cycleID, ObservationReferenceLifecycleDecision, "decision-basis", at); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestObservationMetadataPruningRespectsTenDayBoundary(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 3, false, false)
	before := cycles[0].Draft.Anchor.Add(10*24*time.Hour - time.Second)
	expireMetadataFixture(t, st, before)
	n, err := st.PruneUnusedObservationMetadata(context.Background(), before, 100)
	if err != nil || n != 0 {
		t.Fatalf("before cutoff: pruned=%d err=%v", n, err)
	}
	after := before.Add(2 * time.Second)
	expireMetadataFixture(t, st, after)
	n, err = st.PruneUnusedObservationMetadata(context.Background(), after, 100)
	if err != nil || n != 2 {
		t.Fatalf("after cutoff: pruned=%d err=%v, want 2", n, err)
	}
}

func TestObservationMetadataPruningPreservesOlderQuerySlotHead(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	a, b := testPlan(now), testPlan(now)
	b.Parameters = []byte(`{"expression":"errors_total"}`)
	id, cycles := metadataRetentionCycles(t, st, 3, false, false, a, b, b)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	load := func() situation.PreparedState {
		tx, err := st.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		prepared, err := loadPreparedStateTx(context.Background(), tx, id, at)
		if err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	before := load()
	n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100)
	if err != nil || n != 1 {
		t.Fatalf("pruned=%d err=%v, want only superseded query-slot cycle", n, err)
	}
	after := load()
	if len(before.Runs) != 2 || len(after.Runs) != 2 {
		t.Fatalf("current evidence changed: before=%+v after=%+v", before.Runs, after.Runs)
	}
	for i := range before.Runs {
		if before.Runs[i].ID != after.Runs[i].ID || before.Runs[i].Status != after.Runs[i].Status {
			t.Error("retention changed the latest query-slot outcome")
		}
	}
	fullObservationPass(t, st, at)
	trimmed := load()
	if len(trimmed.Runs) != len(before.Runs) {
		t.Fatalf("a full pass changed current evidence: before=%+v after=%+v", before.Runs, trimmed.Runs)
	}
	for i := range before.Runs {
		if before.Runs[i].ID != trimmed.Runs[i].ID || before.Runs[i].Status != trimmed.Runs[i].Status {
			t.Error("a full pass changed the latest query-slot outcome")
		}
	}
}

// reuseChainCycles seals count cycles, each with a fresh read of its own
// subject and, after the first, a reuse of the previous cycle's fresh run:
// the shape steady traffic leaves, where every cycle reuses the one before.
func reuseChainCycles(t *testing.T, st *Store, count int, base time.Time) (string, []observationmodel.Cycle) {
	t.Helper()
	ctx := context.Background()
	id := newSituationForGroup(t, st, "service=retention", base)
	claim := claimSituation(t, st, id, "reuse-chain", base)
	fence := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	var cycles []observationmodel.Cycle
	var previous string
	for i := 0; i < count; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		fresh := testPlan(at)
		fresh.Scope.SubjectID = fmt.Sprintf("signal-%d", i)
		plans := []observationmodel.Plan{fresh}
		if previous != "" {
			reuse := testPlan(at)
			reuse.Scope.SubjectID = fmt.Sprintf("signal-%d", i-1)
			reuse.Tier, reuse.ReuseRunID = observationmodel.TierReuse, previous
			plans = append(plans, reuse)
		}
		cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: at, ConfigDigest: "retention-config", Plans: plans}, 2)
		if err != nil {
			t.Fatal(err)
		}
		run := consolidationRun(fmt.Sprintf("chain-%d", i), cycle, at)
		if err := st.CommitObservationRun(ctx, fence, run, at); err != nil {
			t.Fatal(err)
		}
		if previous != "" {
			reused := consolidationRun(fmt.Sprintf("chain-reuse-%d", i), cycle, at)
			reused.PlanID = cycle.Draft.Plans[1].ID
			reused.Facts, reused.ReusedFromRunID = nil, &previous
			if err := st.CommitObservationRun(ctx, fence, reused, at); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := sealPreparationCycleTx(ctx, tx, id, cycle.ID, at); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		previous = run.ID
		cycles = append(cycles, cycle)
	}
	return id, cycles
}

// TestObservationRetentionTrimsReuseChains: a kept cycle used to keep every
// plan it had, and each cycle's reuse plan named a run of the cycle before,
// so the current cycle kept the whole history. Retention now trims a kept
// old cycle down to the runs something needs: the chain ends at the current
// cycle's reuse source.
func TestObservationRetentionTrimsReuseChains(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	sitID, cycles := reuseChainCycles(t, st, 6, base)
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET input_version = input_version + 1 WHERE id = ?`, sitID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.PruneObservationRetention(ctx, base.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	last, source := cycles[5].ID, cycles[4].ID
	var kept []string
	rows, err := st.db.QueryContext(ctx, `SELECT id FROM situation_preparation_cycles ORDER BY sealed_at`)
	if err != nil {
		t.Fatal(err)
	}
	kept, err = scanStrings(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0] != source || kept[1] != last {
		t.Fatalf("cycles kept = %v, want the source %s and the current %s", kept, source, last)
	}
	for cycleID, want := range map[string]int{last: 2, source: 1} {
		var plans, runs int
		if err := st.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM situation_observation_plans WHERE cycle_id = ?),
			(SELECT COUNT(*) FROM situation_observation_runs WHERE cycle_id = ?)`, cycleID, cycleID).Scan(&plans, &runs); err != nil {
			t.Fatal(err)
		}
		if plans != want || runs != want {
			t.Errorf("cycle %s: %d plans, %d runs; want %d of each", cycleID, plans, runs, want)
		}
	}
	if _, found, err := st.LoadObservationRun(ctx, "run:consolidation:chain-4"); err != nil || !found {
		t.Fatalf("the current cycle's reuse source: found=%v err=%v", found, err)
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys: %d, %v", n, err)
	}
}

// TestObservationRetentionDropsStaleRefreshCursors: a subject served once and
// never again keeps a refresh cursor that is long due and whose last run's
// detail has expired; it reads like no cursor at all, so retention deletes it
// and, once the input has moved on (query-slot heads are the current input's),
// the cycle it pinned goes. A live subject's cursor stays.
func TestObservationRetentionDropsStaleRefreshCursors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	stale := testPlan(base)
	stale.Scope.SubjectID = "signal-gone"
	sitID, cycles := metadataRetentionCyclesAt(t, st, 4, false, false, time.Second, base, stale)
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET input_version = input_version + 1 WHERE id = ?`, sitID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.PruneObservationRetention(ctx, base.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i, kept := range []bool{false, false, false, true} {
		var n int
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_preparation_cycles WHERE id = ?`, cycles[i].ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if (n == 1) != kept {
			t.Errorf("cycle %d kept = %v, want %v", i, n == 1, kept)
		}
	}
	cursors, err := st.LoadObservationRefreshCursors(ctx, sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors) != 1 || cursors[0].Subject != "signal-a" {
		t.Fatalf("cursors = %+v, want only the live subject's", cursors)
	}
	if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
		t.Fatalf("foreign keys: %d, %v", n, err)
	}
}

func TestObservationMetadataPruningRollsBackWholeBatch(t *testing.T) {
	st := newTestStore(t)
	_, cycles := metadataRetentionCycles(t, st, 3, false, false)
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	if _, err := st.db.ExecContext(context.Background(), `CREATE TRIGGER fail_pruning BEFORE DELETE ON situation_observation_runs BEGIN SELECT RAISE(ABORT, 'injected interruption'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err == nil || n != 0 {
		t.Fatalf("interrupted prune=%d err=%v", n, err)
	}
	for _, table := range []string{"situation_preparation_cycles", "situation_observation_plans", "situation_observation_runs", "situation_observation_facts"} {
		if n := metadataCount(t, st, table); n != 3 {
			t.Errorf("rollback lost %s: %d rows", table, n)
		}
	}
	if n := metadataCount(t, st, "situation_preparation_pruning"); n != 0 {
		t.Errorf("rollback leaked %d delete authorizations", n)
	}
	if _, err := st.db.ExecContext(context.Background(), `DROP TRIGGER fail_pruning`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 2 {
		t.Fatalf("retry prune=%d err=%v, want 2", n, err)
	}
}

func TestObservationMetadataPruningPreservesSourceProvenance(t *testing.T) {
	st := newTestStore(t)
	id, cycles := metadataRetentionCycles(t, st, 3, false, false)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO zabbix_source_observations (
		 id, fact_id, run_id, situation_id, source_key, rule_id, host, available,
		 unavailable_reason, content_digest, observed_at, expires_at
		) VALUES ('retained-source', 'fact:run:consolidation:metadata-0', 'run:consolidation:metadata-0', ?,
		 'zabbix:rule', 'rule', 'host', 0, 'source_unavailable', 'digest', ?, ?)`,
		id, canonicalTime(cycles[0].Draft.Anchor), canonicalTime(cycles[0].Draft.Anchor.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	if n, err := st.PruneUnusedObservationMetadata(context.Background(), at, 100); err != nil || n != 1 {
		t.Fatalf("source provenance: prune=%d err=%v, want 1", n, err)
	}
	if n := metadataCount(t, st, "zabbix_source_observations"); n != 1 {
		t.Fatalf("source provenance rows=%d, want 1", n)
	}
	fullObservationPass(t, st, at)
	if _, found, err := st.LoadObservationRun(context.Background(), "run:consolidation:metadata-0"); err != nil || !found {
		t.Fatalf("a full pass removed the provenance run: found=%v err=%v", found, err)
	}
}

func TestObservationMetadataRetentionUpgradesPopulatedDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v014.db")
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
	for _, migration := range migrations {
		if migration.version <= 41 {
			if err := st.applyMigration(ctx, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, cycles := metadataRetentionCycles(t, st, 3, false, false)
	if _, err := st.db.ExecContext(ctx, `INSERT INTO situation_observation_references
		(id, run_id, reference_kind, owner_id, permanent, created_at)
		VALUES ('legacy-decision', 'run:consolidation:metadata-0', 'assessment_attempt', 'retained-decision', 1, ?)`, canonicalTime(cycles[0].Draft.Anchor)); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
	expireMetadataFixture(t, st, at)
	if n, err := st.PruneUnusedObservationMetadata(ctx, at, 100); err != nil || n != 1 {
		t.Fatalf("upgraded retention: prune=%d err=%v", n, err)
	}
	rows, err := dbForeignKeyCheck(st)
	if err != nil || rows != 0 {
		t.Fatalf("foreign keys: violations=%d err=%v", rows, err)
	}
	for _, table := range []string{"situation_observation_plans", "situation_observation_runs", "situation_observation_references"} {
		if _, err := st.db.ExecContext(ctx, "DELETE FROM "+table); err == nil {
			t.Errorf("retention weakened direct-delete guard on %s", table)
		}
	}
}

func TestObservationMetadataRetentionProtectsLegacyDecisionBasis(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse=%v", reuse), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "legacy-basis.db")
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
			for _, migration := range migrations {
				if migration.version <= 41 {
					if err := st.applyMigration(ctx, migration); err != nil {
						t.Fatal(err)
					}
				}
			}
			id, cycles := metadataRetentionCyclesWithSpacing(t, st, 4, reuse, false, 2*time.Second)
			if _, err := db.ExecContext(ctx, `INSERT INTO situation_assessment_calls
				(id, situation_id, input_version, work_attempt, call_number, material_fact_hash, dispatched_at)
				VALUES ('legacy-call', ?, ?, 1, 1, 'legacy-basis', ?)`, id, cycles[1].Fence.InputVersion, canonicalTime(cycles[1].Draft.Anchor)); err != nil {
				t.Fatal(err)
			}
			at := cycles[0].Draft.Anchor.Add(11 * 24 * time.Hour)
			for i := 0; i < 3; i++ {
				if reuse && i == 0 {
					continue // The current projection still protects its source payload.
				}
				runID := fmt.Sprintf("run:consolidation:metadata-%d", i)
				if _, err := db.ExecContext(ctx, `INSERT INTO situation_observation_detail_expirations (run_id, expired_at) VALUES (?, ?)`, runID, canonicalTime(at)); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, `DELETE FROM situation_observation_fact_payloads WHERE fact_id IN (SELECT id FROM situation_observation_facts WHERE run_id = ?)`, runID); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = openTestStoreWithMigrations(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := st.PruneUnusedObservationMetadata(ctx, at, 100); err != nil || n != 1 {
				t.Fatalf("legacy basis: pruned=%d err=%v, want only the cycle after the last decision", n, err)
			}
			for _, i := range []int{0, 1, 3} {
				if _, found, err := st.LoadObservationRun(ctx, fmt.Sprintf("run:consolidation:metadata-%d", i)); err != nil || !found {
					t.Fatalf("legacy basis run %d: found=%v err=%v", i, found, err)
				}
			}
		})
	}
}

func dbForeignKeyCheck(st *Store) (int, error) {
	rows, err := st.db.QueryContext(context.Background(), `PRAGMA foreign_key_check`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}
