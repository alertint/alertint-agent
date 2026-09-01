// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"sort"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixture helpers
// ----------------------------------------------------------------------

// insertRawIncident inserts an Incident row directly, bypassing the normal
// lifecycle transition methods, so reconstruction tests can seed a
// specific status (including "processing", "analyzed", and "resolved",
// which the store's own transition helpers do not expose a one-step way
// to reach) with no other durable side effect. Mirrors the raw-INSERT
// pattern already used across this package's other fixtures (e.g.
// seedJudged in memory_test.go).
func insertRawIncident(t *testing.T, st *Store, id, groupKey, status string, firstAlertAt, lastAlertAt time.Time) {
	t.Helper()
	first := canonicalTime(firstAlertAt)
	last := canonicalTime(lastAlertAt)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, groupKey, status, first, last, last, first, last); err != nil {
		t.Fatalf("insert raw incident %s: %v", id, err)
	}
}

// attachDeliveryToIncident links an already-accepted delivery to an
// Incident via the immutable incident_alert_deliveries ownership row, the
// same link ApplyCorrelatedDelivery creates in production.
func attachDeliveryToIncident(t *testing.T, st *Store, incidentID, deliveryID string, at time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incidentID, deliveryID, canonicalTime(at)); err != nil {
		t.Fatalf("attach delivery %s to incident %s: %v", deliveryID, incidentID, err)
	}
}

// attachSituationMembership inserts an immutable situation_incidents row
// directly, so a fixture Incident can be marked "already represented"
// without going through ReconstructSituation/ApplySituationInput.
func attachSituationMembership(t *testing.T, st *Store, situationID, incidentID string, at time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)`,
		situationID, incidentID, canonicalTime(at)); err != nil {
		t.Fatalf("attach situation membership incident=%s: %v", incidentID, err)
	}
}

func sortedIncidentIDs(incidents []UpgradeIncident) []string {
	ids := make([]string, len(incidents))
	for i, inc := range incidents {
		ids[i] = inc.IncidentID
	}
	sort.Strings(ids)
	return ids
}

// ----------------------------------------------------------------------
// RecoverExpiredFoundationLeases
// ----------------------------------------------------------------------

// TestRecoverExpiredFoundationLeasesReleasesOnlyExpiredClaims seeds all
// three fenced foundation tables (alert dispatches, Situation inputs,
// Situations) with one claimed-expired and one claimed-still-live row
// each, and asserts one RecoverExpiredFoundationLeases call recovers
// exactly the expired one in each table, leaves the live one untouched,
// and reports the exact per-table counts. Split into one subtest per
// table — each subtest's own fixture is independent — purely to keep any
// one test's cyclomatic complexity readable; together they exercise the
// same single call this method's docs describe.
func TestRecoverExpiredFoundationLeasesReleasesOnlyExpiredClaims(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	expiredDispatchID := seedExpiredAndLiveDispatchClaims(t, st, base)
	expiredInputID := seedExpiredAndLiveInputClaims(t, st, base)
	seedExpiredAndLiveSituationClaims(t, st, base)

	rec, err := st.RecoverExpiredFoundationLeases(ctx, base)
	if err != nil {
		t.Fatalf("RecoverExpiredFoundationLeases: %v", err)
	}
	if rec.AlertDispatches != 1 {
		t.Errorf("AlertDispatches recovered = %d, want 1", rec.AlertDispatches)
	}
	if rec.SituationInputs != 1 {
		t.Errorf("SituationInputs recovered = %d, want 1", rec.SituationInputs)
	}
	if rec.Situations != 1 {
		t.Errorf("Situations recovered = %d, want 1", rec.Situations)
	}

	assertDispatchRecovered(t, st, expiredDispatchID, "d-live")
	assertSituationInputRecovered(t, st, expiredInputID)
	assertSituationLeaseRecovered(t, st)
}

// seedExpiredAndLiveDispatchClaims accepts three deliveries, claims two of
// them (leaving one "pending"), and force-expires only one of the two
// claims. Claim order ties on received_at, so delivery_id breaks it:
// "d-expired" sorts before "d-live" before "d-pending". Claiming both
// before force-expiring either matters: force-expiring "d-expired" first
// would make it eligible for reclaiming again immediately, and the second
// claim would pick it right back up instead of "d-live".
func seedExpiredAndLiveDispatchClaims(t *testing.T, st *Store, base time.Time) string {
	t.Helper()
	ctx := context.Background()
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{
		deliveryFixture("d-pending", "fp-pending", base),
		deliveryFixture("d-expired", "fp-expired", base),
		deliveryFixture("d-live", "fp-live", base),
	}); err != nil {
		t.Fatalf("accept deliveries: %v", err)
	}
	expiredClaims, err := st.ClaimAlertDispatches(ctx, "w1", base, time.Minute, 1)
	if err != nil || len(expiredClaims) != 1 || expiredClaims[0].Delivery.ID != "d-expired" {
		t.Fatalf("claim expired dispatch: %v / %+v", err, expiredClaims)
	}
	liveClaims, err := st.ClaimAlertDispatches(ctx, "w1", base, time.Hour, 1)
	if err != nil || len(liveClaims) != 1 || liveClaims[0].Delivery.ID != "d-live" {
		t.Fatalf("claim live dispatch: %v / %+v", err, liveClaims)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE alert_delivery_dispatches SET lease_expires_at = ? WHERE delivery_id = ?`,
		canonicalTime(base.Add(-time.Second)), "d-expired"); err != nil {
		t.Fatalf("force-expire dispatch lease: %v", err)
	}
	return "d-expired"
}

// seedExpiredAndLiveInputClaims inserts three pending situation_input_outbox
// rows (insertIncidentAndInput's id ties on occurred_at, so id order (ASC)
// is deterministic: "input-expired" < "input-live" < "input-pending"),
// claims two of them, and force-expires only one claim's lease — after
// both claims are settled, since force-expiring first would make
// "input-expired" eligible for reclaiming again and the second claim
// would pick it right back up instead of "input-live".
func seedExpiredAndLiveInputClaims(t *testing.T, st *Store, base time.Time) string {
	t.Helper()
	ctx := context.Background()
	insertIncidentAndInput(t, st, "inc-pending", "input-pending", "group-a", base)
	insertIncidentAndInput(t, st, "inc-expired", "input-expired", "group-b", base)
	insertIncidentAndInput(t, st, "inc-live", "input-live", "group-c", base)
	expiredInputClaim := claimOneInput(t, st, "w1", base) // claims "input-expired"
	if expiredInputClaim.ID != "input-expired" {
		t.Fatalf("claimed input id = %s, want input-expired", expiredInputClaim.ID)
	}
	liveInputClaim := claimOneInput(t, st, "w1", base) // claims "input-live" (next earliest pending)
	if liveInputClaim.ID != "input-live" {
		t.Fatalf("claimed input id = %s, want input-live", liveInputClaim.ID)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE situation_input_outbox SET lease_expires_at = ? WHERE id = ?`,
		canonicalTime(base.Add(-time.Second)), expiredInputClaim.ID); err != nil {
		t.Fatalf("force-expire input lease: %v", err)
	}
	return expiredInputClaim.ID
}

// seedExpiredAndLiveSituationClaims seeds two Situations directly, claims
// both, then force-expires one's lease — independent of the
// situation_input_outbox fixtures seedExpiredAndLiveInputClaims sets up, so
// applying an input to seed a Situation never overwrites the very
// claimed-input row that fixture is trying to keep "claimed" (applying an
// input marks it "applied", which would otherwise defeat it).
func seedExpiredAndLiveSituationClaims(t *testing.T, st *Store, base time.Time) {
	t.Helper()
	ctx := context.Background()
	seedSituationForMembership(t, st, "sit-expired", "group-sit-expired", base)
	seedSituationForMembership(t, st, "sit-live", "group-sit-live", base)
	if _, err := st.ClaimDueSituations(ctx, "w1", base, time.Minute, 10); err != nil {
		t.Fatalf("claim due situations: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET lease_expires_at = ? WHERE id = ?`,
		canonicalTime(base.Add(-time.Second)), "sit-expired"); err != nil {
		t.Fatalf("force-expire situation lease: %v", err)
	}
}

// assertDispatchRecovered checks the expired dispatch is pending again with
// its lease cleared but its attempt/claim history untouched, and that the
// live dispatch's claim is left alone.
func assertDispatchRecovered(t *testing.T, st *Store, expiredID, liveID string) {
	t.Helper()
	ctx := context.Background()
	var status string
	var leaseOwner *string
	var attemptCount int
	var claimToken int64
	if err := st.db.QueryRowContext(ctx, `SELECT status, lease_owner, attempt_count, claim_token FROM alert_delivery_dispatches WHERE delivery_id = ?`, expiredID).
		Scan(&status, &leaseOwner, &attemptCount, &claimToken); err != nil {
		t.Fatalf("read recovered dispatch: %v", err)
	}
	if status != "pending" || leaseOwner != nil {
		t.Errorf("recovered dispatch = status=%s lease_owner=%v, want pending/nil", status, leaseOwner)
	}
	if attemptCount != 1 || claimToken != 1 {
		t.Errorf("recovered dispatch attempt_count/claim_token = %d/%d, want 1/1 (no loss)", attemptCount, claimToken)
	}

	if err := st.db.QueryRowContext(ctx, `SELECT status FROM alert_delivery_dispatches WHERE delivery_id = ?`, liveID).Scan(&status); err != nil {
		t.Fatalf("read live dispatch: %v", err)
	}
	if status != "claimed" {
		t.Errorf("live dispatch status = %s, want still claimed", status)
	}
}

// assertSituationInputRecovered checks the expired situation_input_outbox
// row is pending again, un-fenced, with its attempt/claim history
// untouched.
func assertSituationInputRecovered(t *testing.T, st *Store, expiredID string) {
	t.Helper()
	var status string
	var leaseOwner *string
	var attemptCount int
	var claimToken int64
	if err := st.db.QueryRowContext(context.Background(), `SELECT status, lease_owner, attempt_count, claim_token FROM situation_input_outbox WHERE id = ?`, expiredID).
		Scan(&status, &leaseOwner, &attemptCount, &claimToken); err != nil {
		t.Fatalf("read recovered input: %v", err)
	}
	if status != "pending" || leaseOwner != nil {
		t.Errorf("recovered input = status=%s lease_owner=%v, want pending/nil", status, leaseOwner)
	}
	if attemptCount != 1 || claimToken != 1 {
		t.Errorf("recovered input attempt_count/claim_token = %d/%d, want 1/1 (no loss)", attemptCount, claimToken)
	}
}

// assertSituationLeaseRecovered checks "sit-expired"'s lease is cleared
// with its claim_token untouched, and "sit-live"'s claim is left alone.
func assertSituationLeaseRecovered(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	var leaseOwner *string
	var claimToken int64
	if err := st.db.QueryRowContext(ctx, `SELECT lease_owner, claim_token FROM situations WHERE id = ?`, "sit-expired").Scan(&leaseOwner, &claimToken); err != nil {
		t.Fatalf("read recovered situation: %v", err)
	}
	if leaseOwner != nil {
		t.Errorf("recovered situation lease_owner = %v, want nil", leaseOwner)
	}
	if claimToken != 1 {
		t.Errorf("recovered situation claim_token = %d, want 1 (no loss)", claimToken)
	}

	if err := st.db.QueryRowContext(ctx, `SELECT lease_owner FROM situations WHERE id = ?`, "sit-live").Scan(&leaseOwner); err != nil {
		t.Fatalf("read live situation: %v", err)
	}
	if leaseOwner == nil {
		t.Error("live situation lease_owner = nil, want still claimed")
	}
}

func TestRecoverExpiredFoundationLeasesNoOpWhenNothingExpired(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rec, err := st.RecoverExpiredFoundationLeases(ctx, now)
	if err != nil {
		t.Fatalf("RecoverExpiredFoundationLeases on empty store: %v", err)
	}
	if rec != (LeaseRecovery{}) {
		t.Fatalf("rec = %+v, want zero value", rec)
	}
}

// ----------------------------------------------------------------------
// UnrepresentedOperationalIncidents
// ----------------------------------------------------------------------

func TestUnrepresentedOperationalIncidentsIncludesEveryOperationalStatus(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	operational := []string{"collecting", "ready", "processing", "analyzed", "failed"}
	for i, status := range operational {
		id := "inc-" + status
		insertRawIncident(t, st, id, "group-"+status, status, base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute))
	}

	// Resolved with no firing member: excluded.
	insertRawIncident(t, st, "inc-resolved-settled", "group-resolved-settled", "resolved", base, base)

	// Resolved but still carrying an immutable firing delivery member: included.
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("d-firing-member", "fp-firing-member", base)}); err != nil {
		t.Fatalf("accept firing delivery: %v", err)
	}
	insertRawIncident(t, st, "inc-resolved-unsettled", "group-resolved-unsettled", "resolved", base, base)
	attachDeliveryToIncident(t, st, "inc-resolved-unsettled", "d-firing-member", base)

	// Already represented: excluded regardless of status.
	insertRawIncident(t, st, "inc-already-represented", "group-already-represented", "ready", base, base)
	seedSituationForMembership(t, st, "sit-already", "group-already-represented", base)
	attachSituationMembership(t, st, "sit-already", "inc-already-represented", base)

	got, err := st.UnrepresentedOperationalIncidents(ctx)
	if err != nil {
		t.Fatalf("UnrepresentedOperationalIncidents: %v", err)
	}

	want := []string{"inc-analyzed", "inc-collecting", "inc-failed", "inc-processing", "inc-ready", "inc-resolved-unsettled"}
	gotIDs := sortedIncidentIDs(got)
	if len(gotIDs) != len(want) {
		t.Fatalf("got %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("got %v, want %v", gotIDs, want)
		}
	}
}

func TestUnrepresentedOperationalIncidentsFallsBackToIncidentTimesWithoutDeliveries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	first := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	last := first.Add(5 * time.Minute)
	insertRawIncident(t, st, "inc-legacy", "group-legacy", "ready", first, last)

	got, err := st.UnrepresentedOperationalIncidents(ctx)
	if err != nil {
		t.Fatalf("UnrepresentedOperationalIncidents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d incidents, want 1", len(got))
	}
	inc := got[0]
	if inc.IncidentID != "inc-legacy" || inc.GroupKey != "group-legacy" {
		t.Fatalf("inc = %+v", inc)
	}
	if !inc.EffectiveStartedAt.Equal(first) || !inc.FirstReceivedAt.Equal(first) {
		t.Fatalf("times = %+v, want both %s (no attached delivery: fall back to first_alert_at)", inc, first)
	}
	if inc.EffectiveStartedAtBasis != situationmodel.SourceTimeBasisReceiptFallback {
		t.Fatalf("basis = %s, want receipt_fallback", inc.EffectiveStartedAtBasis)
	}
	if !inc.LastLifecycleObservedAt.Equal(last) {
		t.Fatalf("LastLifecycleObservedAt = %s, want last_alert_at %s", inc.LastLifecycleObservedAt, last)
	}
}

func TestUnrepresentedOperationalIncidentsDerivesTimesFromAttachedDeliveries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	earlier := base.Add(-time.Hour)

	fixture := deliveryFixture("d-source-start", "fp-source-start", base)
	sourceStart := earlier
	fixture.SourceStartedAt = &sourceStart
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{fixture}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	insertRawIncident(t, st, "inc-with-delivery", "group-with-delivery", "ready", base, base)
	attachDeliveryToIncident(t, st, "inc-with-delivery", "d-source-start", base)

	got, err := st.UnrepresentedOperationalIncidents(ctx)
	if err != nil {
		t.Fatalf("UnrepresentedOperationalIncidents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d incidents, want 1", len(got))
	}
	inc := got[0]
	if !inc.EffectiveStartedAt.Equal(earlier) {
		t.Fatalf("EffectiveStartedAt = %s, want the delivery's source_started_at %s", inc.EffectiveStartedAt, earlier)
	}
	if inc.EffectiveStartedAtBasis != situationmodel.SourceTimeBasisSourcePayload {
		t.Fatalf("basis = %s, want source_payload", inc.EffectiveStartedAtBasis)
	}
	if !inc.FirstReceivedAt.Equal(base) {
		t.Fatalf("FirstReceivedAt = %s, want the delivery's received_at %s", inc.FirstReceivedAt, base)
	}
}

// seedSituationForMembership creates a minimal active Situation directly,
// for tests that need one to exist purely as an attachment target.
func seedSituationForMembership(t *testing.T, st *Store, id, groupKey string, at time.Time) {
	t.Helper()
	ts := canonicalTime(at)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES (?, ?, 'active', 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, '[]', ?, ?)`,
		id, groupKey, ts, ts, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed situation %s: %v", id, err)
	}
}

// ----------------------------------------------------------------------
// ReconstructSituation
// ----------------------------------------------------------------------

func TestReconstructSituationCreatesAndAttachesEveryIncident(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	insertRawIncident(t, st, "inc-b", "group-x", "ready", now.Add(-time.Minute), now.Add(-time.Minute))
	insertRawIncident(t, st, "inc-a", "group-x", "collecting", now.Add(-2*time.Minute), now)

	incidents := []UpgradeIncident{
		{IncidentID: "inc-b", GroupKey: "group-x", EffectiveStartedAt: now.Add(-time.Minute), EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now.Add(-time.Minute), LastLifecycleObservedAt: now.Add(-time.Minute)},
		{IncidentID: "inc-a", GroupKey: "group-x", EffectiveStartedAt: now.Add(-2 * time.Minute), EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now.Add(-2 * time.Minute), LastLifecycleObservedAt: now},
	}

	situationID, err := st.ReconstructSituation(ctx, "group-x", incidents, now)
	if err != nil {
		t.Fatalf("ReconstructSituation: %v", err)
	}
	if situationID == "" {
		t.Fatal("situationID is empty")
	}

	sits := listSituations(t, st)
	if len(sits) != 1 {
		t.Fatalf("situations = %d, want 1", len(sits))
	}
	sit := sits[0]
	if sit.Lifecycle != situationmodel.LifecycleActive || sit.Attention != situationmodel.AttentionObserve {
		t.Fatalf("sit = %+v", sit)
	}
	if !sit.EffectiveStartedAt.Equal(now.Add(-2 * time.Minute)) {
		t.Fatalf("EffectiveStartedAt = %s, want the earliest incident's %s", sit.EffectiveStartedAt, now.Add(-2*time.Minute))
	}
	if !sit.LastLifecycleObservedAt.Equal(now) {
		t.Fatalf("LastLifecycleObservedAt = %s, want the latest incident's %s", sit.LastLifecycleObservedAt, now)
	}
	if !sit.NextAssessmentAt.Equal(now) {
		t.Fatalf("NextAssessmentAt = %s, want now (due immediately)", sit.NextAssessmentAt)
	}
	foundReason := false
	for _, r := range sit.DueReasons {
		if r == situationmodel.DueUpgradeReconstruction {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("due reasons = %v, want upgrade_reconstruction", sit.DueReasons)
	}

	var memberCount int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents WHERE situation_id = ?`, situationID).Scan(&memberCount); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if memberCount != 2 {
		t.Fatalf("member count = %d, want 2", memberCount)
	}
}

func TestReconstructSituationJoinsExistingNonterminalSituation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	insertRawIncident(t, st, "inc-seed", "group-y", "ready", now, now)
	seedInc := []UpgradeIncident{{IncidentID: "inc-seed", GroupKey: "group-y", EffectiveStartedAt: now, EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now, LastLifecycleObservedAt: now}}
	situationID, err := st.ReconstructSituation(ctx, "group-y", seedInc, now)
	if err != nil {
		t.Fatalf("seed ReconstructSituation: %v", err)
	}

	later := now.Add(time.Hour)
	insertRawIncident(t, st, "inc-more", "group-y", "collecting", now.Add(-time.Hour), later)
	moreInc := []UpgradeIncident{{IncidentID: "inc-more", GroupKey: "group-y", EffectiveStartedAt: now.Add(-time.Hour), EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now.Add(-time.Hour), LastLifecycleObservedAt: later}}
	joinedID, err := st.ReconstructSituation(ctx, "group-y", moreInc, later)
	if err != nil {
		t.Fatalf("join ReconstructSituation: %v", err)
	}
	if joinedID != situationID {
		t.Fatalf("joinedID = %s, want the same existing situation %s", joinedID, situationID)
	}

	sits := listSituations(t, st)
	if len(sits) != 1 {
		t.Fatalf("situations = %d, want 1 (joined, not a second one)", len(sits))
	}
	sit := sits[0]
	if sit.InputVersion != 2 {
		t.Fatalf("InputVersion = %d, want 2", sit.InputVersion)
	}
	if !sit.EffectiveStartedAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("EffectiveStartedAt = %s, want the earlier contribution %s", sit.EffectiveStartedAt, now.Add(-time.Hour))
	}
	if !sit.LastLifecycleObservedAt.Equal(later) {
		t.Fatalf("LastLifecycleObservedAt = %s, want the later contribution %s", sit.LastLifecycleObservedAt, later)
	}

	var memberCount int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents WHERE situation_id = ?`, situationID).Scan(&memberCount); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if memberCount != 2 {
		t.Fatalf("member count = %d, want 2 (both incidents attached)", memberCount)
	}
}

func TestReconstructSituationLinksToNewestTerminalPredecessor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	seedSituationForMembership(t, st, "sit-old", "group-z", now.Add(-2*time.Hour))
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id='sit-old'`, canonicalTime(now.Add(-time.Hour)), canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatalf("terminalize predecessor: %v", err)
	}

	insertRawIncident(t, st, "inc-fresh", "group-z", "ready", now, now)
	incidents := []UpgradeIncident{{IncidentID: "inc-fresh", GroupKey: "group-z", EffectiveStartedAt: now, EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now, LastLifecycleObservedAt: now}}
	newID, err := st.ReconstructSituation(ctx, "group-z", incidents, now)
	if err != nil {
		t.Fatalf("ReconstructSituation: %v", err)
	}
	if newID == "sit-old" {
		t.Fatal("expected a new situation, not the terminal predecessor")
	}

	var previousID *string
	if err := st.db.QueryRowContext(ctx, `SELECT previous_situation_id FROM situations WHERE id = ?`, newID).Scan(&previousID); err != nil {
		t.Fatalf("read previous_situation_id: %v", err)
	}
	if previousID == nil || *previousID != "sit-old" {
		t.Fatalf("previous_situation_id = %v, want sit-old", previousID)
	}
}

func TestReconstructSituationRepresentationIsIdempotentForUnrepresentedIncidents(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	insertRawIncident(t, st, "inc-once", "group-once", "ready", now, now)
	before, err := st.UnrepresentedOperationalIncidents(ctx)
	if err != nil || len(before) != 1 {
		t.Fatalf("before = %v, %v", before, err)
	}

	if _, err := st.ReconstructSituation(ctx, "group-once", before, now); err != nil {
		t.Fatalf("ReconstructSituation: %v", err)
	}

	after, err := st.UnrepresentedOperationalIncidents(ctx)
	if err != nil {
		t.Fatalf("UnrepresentedOperationalIncidents after reconstruction: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("after = %v, want none left unrepresented", after)
	}
}

func TestReconstructSituationRejectsGroupKeyMismatch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	insertRawIncident(t, st, "inc-mismatch", "actual-group", "ready", now, now)
	incidents := []UpgradeIncident{{IncidentID: "inc-mismatch", GroupKey: "actual-group", EffectiveStartedAt: now, EffectiveStartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, FirstReceivedAt: now, LastLifecycleObservedAt: now}}
	if _, err := st.ReconstructSituation(ctx, "claimed-group", incidents, now); err == nil {
		t.Fatal("expected an error for a group key mismatch between the batch and its incidents")
	}
}
