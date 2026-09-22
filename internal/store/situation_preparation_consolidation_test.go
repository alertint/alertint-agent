// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// Unlike the existing in-memory reopen fixture, this closes the database after
// a durable reservation without an outcome, then resumes through a new lease.
//
//nolint:gocyclo // one durable lifecycle scenario with assertions at both crash boundaries.
func TestConsolidationPreparationReservationSurvivesActualRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restart.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=restart", now)
	claim := claimSituation(t, st, id, "before-crash", now)
	old := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	cycle, err := st.BeginPreparation(ctx, old, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "frozen-config", Plans: []observationmodel.Plan{testPlan(now)}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.ReserveObservationRequest(ctx, old, cycle.ID, cycle.Draft.Plans[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Minute)
	claim = claimSituation(t, st, id, "after-crash", later)
	fresh := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	loaded, err := st.BeginPreparation(ctx, fresh, observationmodel.CycleDraft{Anchor: later, ConfigDigest: "changed-config", Plans: []observationmodel.Plan{testPlan(later)}}, 20)
	if err != nil {
		t.Fatal(err)
	}
	beforePlan, afterPlan := cycle.Draft.Plans[0], loaded.Draft.Plans[0]
	if loaded.ID != cycle.ID || loaded.Draft.ConfigDigest != cycle.Draft.ConfigDigest || !loaded.Draft.Anchor.Equal(cycle.Draft.Anchor) || beforePlan.ID != afterPlan.ID || !beforePlan.Start.Equal(afterPlan.Start) || !beforePlan.End.Equal(afterPlan.End) || !reflect.DeepEqual(beforePlan.Scope, afterPlan.Scope) || string(beforePlan.Parameters) != string(afterPlan.Parameters) || beforePlan.MaxRequests != afterPlan.MaxRequests {
		t.Fatalf("restart changed frozen draft: before=%+v after=%+v", cycle.Draft, loaded.Draft)
	}
	if _, err := st.ReserveObservationRequest(ctx, old, cycle.ID, cycle.Draft.Plans[0].ID, later); err == nil {
		t.Fatal("stale pre-crash owner reserved another request")
	}
	second, err := st.ReserveObservationRequest(ctx, fresh, cycle.ID, cycle.Draft.Plans[0].ID, later)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, second) {
		t.Fatal("repeat reused immutable reservation identity")
	}
	if _, err := st.ReserveObservationRequest(ctx, fresh, cycle.ID, cycle.Draft.Plans[0].ID, later); !errors.Is(err, observationmodel.ErrBudgetExhausted) {
		t.Fatalf("restart reset frozen budget: %v", err)
	}
	run := consolidationRun("restart", cycle, now)
	if err := st.CommitObservationRun(ctx, old, run, later); err == nil {
		t.Fatal("stale owner committed run")
	}
	if err := st.CommitObservationRun(ctx, fresh, run, later); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CommitObservationRun(ctx, fresh, run, later); err != nil {
		t.Fatalf("post-commit restart replay: %v", err)
	}
	var requests, runs, outcomes int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_requests WHERE cycle_id=?`, cycle.ID).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_runs WHERE cycle_id=?`, cycle.ID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_request_outcomes WHERE reservation_id IN (SELECT id FROM situation_observation_requests WHERE cycle_id=?)`, cycle.ID).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || runs != 1 || outcomes != 0 {
		t.Fatalf("ledger after replay requests=%d runs=%d outcomes=%d", requests, runs, outcomes)
	}
}

func consolidationRun(name string, cycle observationmodel.Cycle, now time.Time) observationmodel.Run {
	p := cycle.Draft.Plans[0]
	id := "run:consolidation:" + name
	return observationmodel.Run{ID: id, CycleID: cycle.ID, PlanID: p.ID, Status: observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: p.Start, End: p.End, Complete: true, Returned: 1}, ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Facts: []observationmodel.Fact{{ID: "fact:" + id, RunID: id, Kind: "metric_summary", Subject: p.Scope.SubjectID, Digest: "digest:" + name, SchemaVersion: 2,
			Value: []byte(`{"up":1}`), ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh, ObservedAt: now, ExpiresAt: now.Add(24 * time.Hour), Material: true}}}
}

// The same production Store is used concurrently for cleanup and archive reads;
// this exercises its transactional serialization rather than assuming a second
// writer process is supported. A real reopen separates cleanup batches.
//
//nolint:gocyclo // one retention lifetime spanning concurrent reads, two batches and a restart.
func TestConsolidationRetentionBatchesRestartAndProtectedReads(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retention.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=retention", now)
	claim := claimSituation(t, st, id, "retention-owner", now)
	fence := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	var source observationmodel.Run
	for i := 0; i < 106; i++ {
		cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "retention-config", Plans: []observationmodel.Plan{testPlan(now)}}, 2)
		if err != nil {
			t.Fatal(err)
		}
		run := consolidationRun(fmt.Sprintf("%03d", i), cycle, now)
		if err := st.CommitObservationRun(ctx, fence, run, now); err != nil {
			t.Fatal(err)
		}
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := insertPermanentObservationReferencesTx(ctx, tx, cycle.ID, ObservationReferenceAssessmentAttempt, "used-assessment", now); err != nil {
				t.Fatal(err)
			}
		}
		if err := sealPreparationCycleTx(ctx, tx, id, cycle.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if i == 105 {
			source = run
		}
	}
	// Begin a reuse cycle without committing its run: taking the source reference
	// atomically must already protect the payload during the in-flight read.
	reusePlan := testPlan(now)
	reusePlan.Tier = observationmodel.TierReuse
	reusePlan.ReuseRunID = source.ID
	reuseCycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "retention-config", Plans: []observationmodel.Plan{reusePlan}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(10 * 24 * time.Hour)
	failures := make(chan error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		n, err := st.PruneUnusedObservationDetails(ctx, at, 100)
		if err == nil && n != 100 {
			err = fmt.Errorf("first batch=%d want100", n)
		}
		failures <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10; i++ {
			rec, found, err := st.LoadObservationRun(ctx, source.ID)
			if err != nil {
				failures <- err
				return
			}
			if !found || rec.DetailState != observationmodel.DetailStateRetained || len(rec.Run.Facts) != 1 || string(rec.Run.Facts[0].Value) != `{"up":1}` {
				failures <- fmt.Errorf("in-flight reuse lost coherent retained detail: %+v", rec)
				return
			}
		}
		failures <- nil
	}()
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
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
	n, err := st.PruneUnusedObservationDetails(ctx, at, 100)
	if err != nil || n != 4 {
		t.Fatalf("second batch=%d err=%v want4", n, err)
	}
	n, err = st.PruneUnusedObservationDetails(ctx, at, 100)
	if err != nil || n != 0 {
		t.Fatalf("idempotent batch=%d err=%v", n, err)
	}
	for _, runID := range []string{"run:consolidation:000", source.ID} {
		rec, found, err := st.LoadObservationRun(ctx, runID)
		if err != nil || !found || rec.DetailState != observationmodel.DetailStateRetained {
			t.Fatalf("protected %s record=%+v err=%v", runID, rec, err)
		}
	}
	archived, found, err := st.LoadObservationRun(ctx, "run:consolidation:001")
	if err != nil || !found {
		t.Fatalf("archive found=%v err=%v", found, err)
	}
	if archived.DetailState != observationmodel.DetailStateExpired || len(archived.Run.Facts) != 1 || archived.Run.Facts[0].Digest != "digest:001" || string(archived.Run.Facts[0].Value) != "null" {
		t.Fatalf("expired immutable metadata=%+v", archived)
	}
	// Historical persistence cannot put the payload back into an old cycle.
	oldRun := archived.Run
	oldRun.Facts[0].Value = []byte(`{"up":1}`)
	if err := st.CommitObservationRun(ctx, fence, oldRun, now); err == nil {
		t.Fatal("historical run replay resurrected expired payload")
	}
	var payloads, expirations int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_fact_payloads`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_detail_expirations`).Scan(&expirations); err != nil {
		t.Fatal(err)
	}
	if payloads != 2 || expirations != 104 {
		t.Fatalf("payloads=%d expirations=%d", payloads, expirations)
	}
	// The current reuse cycle survives the restart unchanged, even though cleanup
	// has removed historical unused payloads from more than one hundred runs.
	current, err := st.BeginPreparation(ctx, fence, reuseCycle.Draft, 2)
	if err != nil || current.ID != reuseCycle.ID {
		t.Fatalf("current cycle changed after cleanup: %s %v", current.ID, err)
	}
}

func TestConsolidationInvestigationCreditChurnAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "credit.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=credit", now)
	for i := 0; i < 20; i++ {
		credit, err := st.AccrueInvestigationCredit(ctx, id, now.Add(time.Duration(i)*time.Second), time.Minute, 2)
		if err != nil || credit != 2 {
			t.Fatalf("input churn minted credit: %d %v", credit, err)
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE situations SET input_version=input_version+1 WHERE id=?`, id); err != nil {
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
	for _, step := range []struct {
		at   time.Duration
		want int
	}{{30 * time.Second, 2}, {time.Minute, 4}, {2 * time.Minute, 6}, {3 * time.Minute, 6}} {
		credit, err := st.AccrueInvestigationCredit(ctx, id, now.Add(step.at), time.Minute, 2)
		if err != nil || credit != step.want {
			t.Fatalf("at=%v credit=%d want=%d err=%v", step.at, credit, step.want, err)
		}
	}
}

// These are the production due/lease/outbox/follower query shapes. The fixture
// has real follower and job rows so EXPLAIN checks access paths, not index names
// merely existing in sqlite_master.
func TestConsolidationProfileWorkQueriesUseIndexes(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	signatureDeliveryFixture(t, st, "query-plan", "service=query-plan", now)
	tests := []struct {
		name, query, want string
		args              []any
	}{
		{"due", `SELECT id, signature_key, frozen_input_json, frozen_input_digest, expected_head_version, attempt, token
 FROM semantic_profile_inference_jobs WHERE status = 'pending' AND (retry_at IS NULL OR retry_at <= ?)
 ORDER BY created_at ASC, id ASC LIMIT 1`, "SEARCH semantic_profile_inference_jobs USING INDEX", []any{canonicalTime(now)}},
		{"lease", `SELECT id, attempt, attempt_budget, lease_expires_at FROM semantic_profile_inference_jobs
 WHERE status = 'running' AND lease_expires_at <= ? ORDER BY lease_expires_at ASC, id ASC LIMIT 100`, "SEARCH semantic_profile_inference_jobs USING INDEX", []any{canonicalTime(now)}},
		{"outbox", `SELECT id, signature_key, version_id, fan_out_cursor FROM semantic_profile_changes
 WHERE acknowledged = 0 ORDER BY id ASC LIMIT 1`, "semantic_profile_changes_pending_idx", nil},
		{"followers", `SELECT DISTINCT s.id FROM delivery_semantic_signatures dss
 JOIN alert_deliveries ad ON ad.id = dss.delivery_id
 JOIN incident_alert_deliveries iad ON iad.delivery_id = ad.id
 JOIN situation_incidents si ON si.incident_id = iad.incident_id
 JOIN situations s ON s.id = si.situation_id
 LEFT JOIN semantic_profile_change_deliveries scd ON scd.change_id = ? AND scd.situation_id = s.id
 WHERE dss.signature_key = ? AND s.lifecycle IN ('active', 'recovery_pending')
 AND scd.situation_id IS NULL AND (? IS NULL OR s.id > ?) ORDER BY s.id ASC LIMIT ?`, "delivery_semantic_signatures_signature_idx", []any{"change", "signature", nil, nil, 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := st.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+tt.query, tt.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			text := strings.Join(plan, "\n")
			t.Log(text)
			if !strings.Contains(text, tt.want) {
				t.Fatalf("missing indexed access %q:\n%s", tt.want, text)
			}
		})
	}
}

func TestConsolidationRetentionProtectedReusePreservesSourcePayload(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	id := newSituationForGroup(t, st, "service=reused-retention", now)
	claim := claimSituation(t, st, id, "reuse-owner", now)
	f := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	first, err := st.BeginPreparation(ctx, f, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "reuse", Plans: []observationmodel.Plan{testPlan(now)}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	source := consolidationRun("source", first, now)
	if err := st.CommitObservationRun(ctx, f, source, now); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealPreparationCycleTx(ctx, tx, id, first.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	p := testPlan(now)
	p.Tier = observationmodel.TierReuse
	p.ReuseRunID = source.ID
	next, err := st.BeginPreparation(ctx, f, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "reuse", Plans: []observationmodel.Plan{p}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	projection := consolidationRun("projection", next, now)
	projection.Facts = nil
	projection.ReusedFromRunID = &source.ID
	if err := st.CommitObservationRun(ctx, f, projection, now); err != nil {
		t.Fatal(err)
	}
	// Isolate the indirect protection guarantee: even once direct source
	// references are superseded, the still-referenced projection needs its bytes.
	if _, err := st.db.ExecContext(ctx, `UPDATE situation_observation_references SET superseded=1 WHERE run_id=?`, source.ID); err != nil {
		t.Fatal(err)
	}
	n, err := st.PruneUnusedObservationDetails(ctx, now.Add(10*24*time.Hour), 100)
	if err != nil || n != 0 {
		t.Fatalf("pruned referenced reuse source: n=%d err=%v", n, err)
	}
	rec, found, err := st.LoadObservationRun(ctx, projection.ID)
	if err != nil || !found {
		t.Fatalf("projection: found=%v err=%v", found, err)
	}
	if rec.DetailState != observationmodel.DetailStateRetained || len(rec.Run.Facts) != 1 || string(rec.Run.Facts[0].Value) != `{"up":1}` || rec.Run.Facts[0].Digest != source.Facts[0].Digest {
		t.Fatalf("reused source payload lost: %+v", rec)
	}
}
