// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func seedLargeDeliveryHistory(t *testing.T) (*Store, string, time.Time) {
	t.Helper()
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sid := seedReconcileSituation(t, st, "delivery-history", now)
	var aid string
	if err := st.db.QueryRowContext(ctx, "SELECT alert_id FROM alert_deliveries LIMIT 1").Scan(&aid); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alerts(incident_id,alert_id,created_at) VALUES (?,?,?)", "inc-delivery-history", aid, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	rows, err := st.db.QueryContext(ctx, "PRAGMA table_info(alert_deliveries)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def any
		if err := rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	values := append([]string(nil), columns...)
	for i, c := range columns {
		values[i] = "d." + c
		if c == "id" {
			values[i] = "printf('repeat-%08d',n.i)"
		}
	}
	const count = 100000
	query := `WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < ?) INSERT INTO alert_deliveries (` + strings.Join(columns, ",") + `) SELECT ` + strings.Join(values, ",") + ` FROM n CROSS JOIN alert_deliveries d WHERE d.id='delivery-delivery-history'`
	if _, err := st.db.ExecContext(ctx, query, count); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) SELECT ?,id,? FROM alert_deliveries WHERE id LIKE 'repeat-%'`, "inc-delivery-history", canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	return st, sid, now
}

// Catches a reconciliation holding the sole storage connection for the whole
// immutable delivery history, instead of yielding between bounded reads.
func TestReconciliationDeliveryHistoryYieldsStorage(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("opt-in 100k delivery history")
	}
	st, sid, now := seedLargeDeliveryHistory(t)
	ctx := context.Background()
	const count = 100000
	sit, err := st.GetSituation(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		in, e := st.LoadReconciliationInput(ctx, situation.Claim{Situation: sit}, now)
		if e == nil && len(in.Deliveries) != count+1 {
			e = fmt.Errorf("deliveries=%d want=%d", len(in.Deliveries), count+1)
		}
		done <- e
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	failed := 0
	probes := 0
	var longest time.Duration
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("concurrent storage probes=%d expired=%d longest=%s", probes, failed, longest)
			if probes == 0 {
				t.Fatal("no concurrent storage probes")
			}
			if failed > 0 {
				t.Fatalf("%d storage probes exceeded 200ms during delivery history read", failed)
			}
			return
		case <-ticker.C:
			pc, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			start := time.Now()
			e := st.db.PingContext(pc)
			elapsed := time.Since(start)
			cancel()
			probes++
			if elapsed > longest {
				longest = elapsed
			}
			if e != nil {
				failed++
			}
		}
	}
}

func TestTriageDeliveryHistoryYieldsStorage(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("opt-in 100k delivery history")
	}
	st, _, _ := seedLargeDeliveryHistory(t)
	ctx := context.Background()
	const count = 100000
	done := make(chan error, 1)
	go func() {
		tx, history, e := st.beginIncidentHistoryTx(ctx, "inc-delivery-history")
		if e == nil {
			if len(history.deliveryIDs) != count+1 {
				e = fmt.Errorf("member IDs=%d want=%d", len(history.deliveryIDs), count+1)
			}
			_ = tx.Rollback()
		}
		done <- e
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	failed := 0
	probes := 0
	var longest time.Duration
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("concurrent storage probes=%d expired=%d longest=%s", probes, failed, longest)
			if probes == 0 {
				t.Fatal("no concurrent storage probes")
			}
			if failed > 0 {
				t.Fatalf("%d storage probes exceeded 200ms during delivery history read", failed)
			}
			return
		case <-ticker.C:
			pc, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			start := time.Now()
			e := st.db.PingContext(pc)
			elapsed := time.Since(start)
			cancel()
			probes++
			if elapsed > longest {
				longest = elapsed
			}
			if e != nil {
				failed++
			}
		}
	}
}

func TestJudgmentDeliveryHistoryYieldsStorage(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("opt-in 100k delivery history")
	}
	st, sid, _ := seedLargeDeliveryHistory(t)
	ctx := context.Background()
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		tx, e := st.db.BeginTx(ctx, nil)
		if e == nil {
			var deliveries []situation.Delivery
			deliveries, e = loadSituationJudgmentDeliveriesTx(ctx, tx, sid, nil)
			if e == nil && len(deliveries) != 1 {
				e = fmt.Errorf("judgment deliveries=%d want=1", len(deliveries))
			}
			_ = tx.Rollback()
		}
		done <- e
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	failed := 0
	probes := 0
	var longest time.Duration
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("concurrent storage probes=%d expired=%d longest=%s", probes, failed, longest)
			if probes == 0 && time.Since(started) > 200*time.Millisecond {
				t.Fatal("slow history read completed without concurrent probes")
			}
			if failed > 0 {
				t.Fatalf("%d storage probes exceeded 200ms during delivery history read", failed)
			}
			return
		case <-ticker.C:
			pc, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			start := time.Now()
			e := st.db.PingContext(pc)
			elapsed := time.Since(start)
			cancel()
			probes++
			if elapsed > longest {
				longest = elapsed
			}
			if e != nil {
				failed++
			}
		}
	}
}

func TestJudgmentPredecessorHistoryYieldsStorage(t *testing.T) {
	if os.Getenv("ALERTINT_LARGE_DB_TEST") != "1" {
		t.Skip("opt-in 100k delivery history")
	}
	st, sid, now := seedLargeDeliveryHistory(t)
	ctx := context.Background()
	if err := st.InsertIncident(ctx, Incident{ID: "predecessor", GroupKey: "old", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE incident_alert_deliveries SET incident_id='predecessor' WHERE incident_id='inc-delivery-history'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE incident_alerts SET created_at=? WHERE incident_id='inc-delivery-history'`, canonicalTime(now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		tx, e := st.db.BeginTx(ctx, nil)
		if e == nil {
			var deliveries []situation.Delivery
			deliveries, e = loadSituationJudgmentDeliveriesTx(ctx, tx, sid, nil)
			if e == nil && len(deliveries) != 0 {
				e = fmt.Errorf("judgment deliveries=%d want=0", len(deliveries))
			}
			_ = tx.Rollback()
		}
		done <- e
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	failed := 0
	probes := 0
	var longest time.Duration
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("concurrent storage probes=%d expired=%d longest=%s", probes, failed, longest)
			if probes == 0 {
				t.Fatal("no concurrent storage probes")
			}
			if failed > 0 {
				t.Fatalf("%d storage probes exceeded one second during delivery history read", failed)
			}
			return
		case <-ticker.C:
			pc, cancel := context.WithTimeout(ctx, time.Second)
			start := time.Now()
			e := st.db.PingContext(pc)
			elapsed := time.Since(start)
			cancel()
			probes++
			if elapsed > longest {
				longest = elapsed
			}
			if e != nil {
				failed++
			}
		}
	}
}

// Catches loss of middle deliveries, shared ownership, chronological ordering,
// and payload fields needed by lifecycle, digests, and operator presentation.
func TestDeliveryPagesMatchReleasedSnapshot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	sid := seedReconcileSituation(t, st, "page-equivalence", now)
	incident := "inc-page-equivalence"
	alert := "alert-fp-page-equivalence"
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alerts(incident_id,alert_id,created_at) VALUES (?,?,?)", incident, alert, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertIncident(ctx, Incident{ID: "shared-owner", GroupKey: "shared", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		at := now.Add(time.Duration((i*37)%300) * time.Second)
		if i%7 == 0 {
			at = at.Add(500 * time.Millisecond)
		}
		d := deliveryFixture(fmt.Sprintf("page-%04d", 599-i), "fp-page-equivalence", at)
		if i%3 == 0 {
			d.Alert.Status = "resolved"
			end := at
			d.SourceResolvedAt = &end
			d.ResolvedAtBasis = "source_payload"
		}
		if i%4 == 0 {
			start := now.Add(time.Duration(i%7) * time.Minute)
			d.SourceStartedAt = &start
		}
		if i%5 == 0 {
			d.Alert.Labels[DrillMarkerLabel] = DrillMarkerValue
		}
		d.Alert.Annotations = map[string]string{"description": "description fallback"}
		if i%2 == 0 {
			d.Alert.Annotations["summary"] = "summary"
		}
		if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{d}); err != nil {
			t.Fatal(err)
		}
		owner := incident
		if i%2 == 0 {
			owner = "shared-owner"
		}
		linkAt := at
		if i%11 == 0 {
			linkAt = now.Add(-time.Second)
		}
		if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)", owner, d.ID, canonicalTime(linkAt)); err != nil {
			t.Fatal(err)
		}
	}
	seedJudgmentMembershipEdges(t, st, sid, incident, alert, now)
	for _, terminal := range []*time.Time{nil, timePtrValue(now.Add(150*time.Second + 500*time.Millisecond))} {
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		history, err := captureDeliveryHistoryTx(ctx, tx, sid, terminal)
		if err != nil {
			t.Fatal(err)
		}
		// The legacy query gets the same terminal fence from the captured row.
		if terminal != nil {
			if _, err := tx.ExecContext(ctx, "UPDATE situations SET lifecycle='closed_unknown', terminal_reason='observation_deadline', terminal_at=? WHERE id=?", canonicalTime(*terminal), sid); err != nil {
				t.Fatal(err)
			}
		}
		want, err := loadSituationDeliveriesTx(ctx, tx, sid)
		if err != nil {
			t.Fatal(err)
		}
		narrow, err := loadSituationJudgmentDeliveriesTx(ctx, tx, sid, terminal)
		if err != nil {
			t.Fatal(err)
		}
		judgmentInput := situation.SnapshotInput{Situation: situationmodel.Situation{ID: sid, GroupKey: "page-equivalence", Lifecycle: situationmodel.LifecycleActive}, CurrentAssessment: &situation.AuthoritativeAssessment{Assessment: validAssessmentFixture()}, Deliveries: want}
		wantCoverage, wantErr := situation.DeriveExpectedJudgmentCoverage(judgmentInput)
		judgmentInput.Deliveries = narrow
		gotCoverage, gotErr := situation.DeriveExpectedJudgmentCoverage(judgmentInput)
		if !reflect.DeepEqual(gotCoverage, wantCoverage) || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("judgment coverage changed: got=%+v (%v) want=%+v (%v)", gotCoverage, gotErr, wantCoverage, wantErr)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		got, err := st.loadDeliveryHistory(ctx, history)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("paged snapshot differs from release: got %d deliveries, want %d", len(got), len(want))
		}
		if situation.MembershipDigest(incident, got) != situation.MembershipDigest(incident, want) || situation.IncidentInputDigest(incident, "page-equivalence", got) != situation.IncidentInputDigest(incident, "page-equivalence", want) {
			t.Fatal("coverage digests changed")
		}
	}
}

// New receipts may be backdated and lexically precede the paging cursor. Neither
// those receipts nor a newly created ownership link may enter a captured snapshot.
func TestDeliveryPagesExcludeConcurrentBackdatedRowsAndLinks(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sid := seedReconcileSituation(t, st, "page-boundary", now)
	incident := "inc-page-boundary"
	alert := "alert-fp-page-boundary"
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alerts(incident_id,alert_id,created_at) VALUES (?,?,?)", incident, alert, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	queued := deliveryFixture("aaa-queued", "fp-page-boundary", now.Add(-time.Minute))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{queued}); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := captureDeliveryHistoryTx(ctx, tx, sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	late := deliveryFixture("aaa-late", "fp-page-boundary", now.Add(-time.Hour))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{late}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{queued.ID, late.ID} {
		if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)", incident, id, canonicalTime(now.Add(-time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.loadDeliveryHistory(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "delivery-page-boundary" {
		t.Fatalf("captured history admitted future rows: %+v", got)
	}
	current, err := st.LoadReconciliationInput(ctx, situation.Claim{Situation: getSituationByID(t, st, sid)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Deliveries) != 3 {
		t.Fatalf("fresh snapshot must admit all three deliveries, got %d", len(current.Deliveries))
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := st.loadDeliveryHistory(cancelled, snap); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: %v", err)
	}
}

func seedJudgmentMembershipEdges(t *testing.T, st *Store, sid, incident, alert string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	// A direct legacy owner without incident_alerts must still contribute.
	directOnly := deliveryFixture("direct-only", "fp-direct-only", now)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{directOnly}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)", incident, directOnly.ID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	// A second member sees the same Alert only after its membership fence.
	if err := st.InsertIncident(ctx, Incident{ID: "second-member", GroupKey: "page-equivalence", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO situation_incidents(situation_id,incident_id,attached_at) VALUES (?,?,?)", sid, "second-member", canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alerts(incident_id,alert_id,created_at) VALUES (?,?,?)", "second-member", alert, canonicalTime(now.Add(100*time.Second))); err != nil {
		t.Fatal(err)
	}
	// An Alert with only predecessor-owned rows predating membership contributes nothing.
	predecessor := deliveryFixture("predecessor-only", "fp-predecessor-only", now.Add(-time.Hour))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{predecessor}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)", "shared-owner", predecessor.ID, canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "INSERT INTO incident_alerts(incident_id,alert_id,created_at) VALUES (?,?,?)", incident, predecessor.Alert.ID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
}

func TestTriageHistoryFenceDetectsBackdatedOwnership(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedReconcileSituation(t, st, "history-fence", now)
	incident := "inc-history-fence"
	readFence := func() incidentHistoryFence {
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		f, err := readIncidentHistoryFenceTx(ctx, tx, incident)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return f
	}
	before := readFence()
	queued := deliveryFixture("backdated-owner", "fp-history-fence", now.Add(-time.Hour))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{queued}); err != nil {
		t.Fatal(err)
	}
	if got := readFence(); got != before {
		t.Fatalf("unowned delivery changed incident fence: %+v -> %+v", before, got)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES (?,?,?)`, incident, queued.ID, canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if got := readFence(); got == before || got.count != before.count+1 || got.maxOwnership <= before.maxOwnership {
		t.Fatalf("backdated ownership escaped fence: %+v -> %+v", before, got)
	}
	tx, history, err := st.beginIncidentHistoryTx(ctx, incident)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	membership, input, err := incidentDigestsTx(ctx, tx, incident)
	if err != nil {
		t.Fatal(err)
	}
	if history.membership != membership || history.input != input || len(history.deliveryIDs) != 2 {
		t.Fatalf("triage snapshot differs from transactional coverage: %+v", history)
	}
}
