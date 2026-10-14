// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

func TestObservationRetentionExactTenDayCutoff(t *testing.T) {
	// RFC3339Nano omits trailing zeros. Exercise both shortened fractions
	// and adjacent nanoseconds rather than relying on wall-clock precision.
	for _, nanos := range []int{0, 1, 10, 81, 100000000, 862946881, 999999999} {
		for _, offset := range []time.Duration{0, time.Nanosecond} {
			t.Run(fmt.Sprintf("nanos=%d/offset=%s", nanos, offset), func(t *testing.T) {
				st := newTestStore(t)
				start := time.Date(2026, 9, 1, 0, 0, 0, nanos, time.UTC)
				_, cycles := metadataRetentionCyclesAt(t, st, 3, false, false, 0, start)
				cutoff := cycles[0].Draft.Anchor.Add(10 * 24 * time.Hour)
				ctx := context.Background()
				for _, at := range []time.Time{cutoff.Add(-time.Nanosecond), cutoff.Add(offset)} {
					want := 0
					if !at.Before(cutoff) {
						want = 2
					}
					if n, err := st.PruneUnusedObservationDetails(ctx, at, 100); err != nil || n != want {
						t.Fatalf("details at %s: %d %v, want %d", at, n, err, want)
					}
					if n, err := st.PruneUnusedObservationMetadata(ctx, at, 25); err != nil || n != want {
						t.Fatalf("metadata at %s: %d %v, want %d", at, n, err, want)
					}
				}
				if n := metadataCount(t, st, "situation_preparation_cycles"); n != 1 {
					t.Fatalf("current head lost: cycles=%d", n)
				}
			})
		}
	}
}

func TestObservationRetentionKeepsUpWithRollingHistory(t *testing.T) {
	for _, growingProtection := range []bool{false, true} {
		t.Run(fmt.Sprintf("growing-protection=%v", growingProtection), func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			id := newSituationForGroup(t, st, "rolling-history", start)
			claim := claimSituation(t, st, id, "rolling-retention", start)
			if _, err := st.db.ExecContext(ctx, `UPDATE situations SET lease_expires_at=? WHERE id=?`, canonicalTime(start.Add(21*24*time.Hour)), id); err != nil {
				t.Fatal(err)
			}
			fence := observationmodel.Fence{SituationID: id, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
			var records []rollingRetentionRecord
			var source string
			deleted, expired := 0, 0
			for hour := 0; hour < 20*24; hour++ {
				at := start.Add(time.Duration(hour) * time.Hour)
				if hour%6 == 0 {
					rec := appendRollingRetentionCycle(t, st, fence, start, at, len(records), source, growingProtection)
					records = append(records, rec)
					if len(records) == 3 {
						source = rec.run
					}
				}
				// Model the production Drain: detail batches take precedence;
				// metadata batches continue until both operations return zero.
				for {
					n, err := st.PruneUnusedObservationDetails(ctx, at, 100)
					if err != nil {
						t.Fatal(err)
					}
					expired += n
					if n > 0 {
						continue
					}
					n, err = st.PruneUnusedObservationMetadata(ctx, at, 25)
					if err != nil {
						t.Fatal(err)
					}
					deleted += n
					if n == 0 {
						break
					}
				}
				bound := 44 + 3
				if growingProtection {
					bound += 20
				}
				if n := metadataCount(t, st, "situation_preparation_cycles"); n > bound {
					t.Fatalf("hour %d: retained %d cycles, bound %d", hour, n, bound)
				}
			}
			cutoff := start.Add((20*24-1)*time.Hour - 10*24*time.Hour)
			for _, r := range records {
				var exists int
				if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM situation_preparation_cycles WHERE id=?`, r.cycle).Scan(&exists); err != nil {
					t.Fatal(err)
				}
				want := 1
				if !r.protected && !r.at.After(cutoff) {
					want = 0
				}
				if exists != want {
					t.Errorf("cycle at %s protected=%v exists=%d want=%d", r.at, r.protected, exists, want)
				}
				if r.protected {
					rec, found, err := st.LoadObservationRun(ctx, r.run)
					payloadRequired := r.run != records[1].run // source provenance protects metadata; unused payload may expire
					if err != nil || !found || len(rec.Run.Facts) == 0 || (payloadRequired && string(rec.Run.Facts[0].Value) != `{"up":1}`) {
						t.Errorf("protected evidence lost: %s found=%v err=%v", r.run, found, err)
					}
				}
			}
			if n, err := dbForeignKeyCheck(st); err != nil || n != 0 {
				t.Fatalf("foreign keys %d %v", n, err)
			}
			var integrity string
			if err := st.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatalf("integrity %q %v", integrity, err)
			}
			t.Logf("20 days: created=%d expired=%d deleted=%d retained=%d growing_protection=%v", len(records), expired, deleted, metadataCount(t, st, "situation_preparation_cycles"), growingProtection)
		})
	}
}

type rollingRetentionRecord struct {
	cycle, run string
	at         time.Time
	protected  bool
}

func appendRollingRetentionCycle(t *testing.T, st *Store, fence observationmodel.Fence, start, at time.Time, index int, source string, growingProtection bool) rollingRetentionRecord {
	t.Helper()
	ctx := context.Background()
	id := fence.SituationID
	plan := testPlan(start)
	if index > 2 {
		plan.Tier = observationmodel.TierReuse
		plan.ReuseRunID = source
	}
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: at, ConfigDigest: "fixed-config", Plans: []observationmodel.Plan{plan}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	run := consolidationRun(fmt.Sprintf("rolling-%03d", index), cycle, at)
	if plan.Tier == observationmodel.TierReuse {
		run.Facts = nil
		run.ReusedFromRunID = &source
	}
	if err := st.CommitObservationRun(ctx, fence, run, at); err != nil {
		t.Fatal(err)
	}
	pin := index == 0 || (growingProtection && index%4 == 0)
	if pin {
		pinMetadataDecision(t, st, cycle.ID, at)
	}
	if index == 1 {
		if _, err := st.db.ExecContext(ctx, `INSERT INTO zabbix_source_observations
						(id,fact_id,run_id,situation_id,source_key,rule_id,host,available,unavailable_reason,content_digest,observed_at,expires_at)
						VALUES ('rolling-source',?,?,?,'zabbix:rule','rule','host',0,'source_unavailable','digest',?,?)`, "fact:"+run.ID, run.ID, id, canonicalTime(at), canonicalTime(at.Add(time.Hour))); err != nil {
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
	return rollingRetentionRecord{cycle.ID, run.ID, at, pin || index == 1 || index == 2}
}
