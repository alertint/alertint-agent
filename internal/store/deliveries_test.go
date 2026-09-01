// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func deliveryFixture(id, fingerprint string, now time.Time) DeliveryInput {
	return DeliveryInput{
		ID: id,
		Alert: Alert{
			ID:          "alert-" + fingerprint,
			Fingerprint: fingerprint,
			Status:      "firing",
			Labels:      map[string]string{"alertname": "test", "fp": fingerprint},
			Annotations: map[string]string{"summary": "test alert"},
			StartsAt:    now,
			ReceivedAt:  now,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:" + fingerprint + ":" + now.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "group:" + fingerprint,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance: SourceProvenance{
			AcquisitionMode: SourceAcquisitionWebhook,
		},
	}
}

func assertTableCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}

func TestAcceptDeliveriesIsAtomicAndIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	good := deliveryFixture("delivery-a", "fp-a", now)
	bad := deliveryFixture("delivery-b", "fp-b", now)
	bad.PayloadDigest = ""

	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{good, bad}); err == nil {
		t.Fatal("invalid batch accepted")
	}
	assertTableCount(t, st.DB(), "alerts", 0)
	assertTableCount(t, st.DB(), "alert_deliveries", 0)
	assertTableCount(t, st.DB(), "alert_delivery_dispatches", 0)

	bad.PayloadDigest = "sha256:b"
	first, err := st.AcceptDeliveries(ctx, []DeliveryInput{good, bad})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.AcceptDeliveries(ctx, []DeliveryInput{good, bad})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("redelivery changed rows: %#v %#v", first, second)
	}
	assertTableCount(t, st.DB(), "alert_deliveries", 2)
	assertTableCount(t, st.DB(), "alert_delivery_dispatches", 2)
}

func TestAcceptDeliveriesDuplicateIDIgnoresMutatedAlert(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)

	original := deliveryFixture("delivery-a", "fp-a", now)
	first, err := st.AcceptDeliveries(ctx, []DeliveryInput{original})
	if err != nil {
		t.Fatal(err)
	}

	mutated := deliveryFixture("delivery-a", "fp-a", now.Add(time.Hour))
	mutated.Alert.Status = "resolved"
	mutated.Alert.Labels = map[string]string{"alertname": "mutated", "fp": "fp-a"}
	second, err := st.AcceptDeliveries(ctx, []DeliveryInput{mutated})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("duplicate delivery id rewrote immutable delivery: %#v %#v", first, second)
	}
	assertTableCount(t, st.DB(), "alert_deliveries", 1)
	assertTableCount(t, st.DB(), "alert_delivery_dispatches", 1)

	projected, err := st.GetAlertByFingerprint(ctx, "fp-a")
	if err != nil {
		t.Fatal(err)
	}
	if projected.Status != "firing" || projected.Labels["alertname"] != "test" {
		t.Fatalf("duplicate delivery id rewrote Alert projection: %#v", projected)
	}
}

func TestAlertDispatchClaimTokenFencesExpiredOwner(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	_, _ = st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-a", "fp-a", now)})

	first, err := st.ClaimAlertDispatches(ctx, "worker-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.ClaimAlertDispatches(ctx, "worker-b", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ClaimToken >= second[0].ClaimToken {
		t.Fatal("claim token did not advance")
	}
	if err := st.RetryAlertDispatch(ctx, first[0], "transient", now.Add(3*time.Minute), false); !errors.Is(err, ErrAlertDispatchLeaseLost) {
		t.Fatalf("stale owner retry = %v", err)
	}
}

func TestClaimAlertDispatchesOrdersDeterministically(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)

	// "delivery-c" arrives first (earliest received_at); "delivery-b" and
	// "delivery-a" tie on a later received_at, so delivery ID breaks the tie.
	early := deliveryFixture("delivery-c", "fp-c", base)
	tieA := deliveryFixture("delivery-b", "fp-b", base.Add(time.Minute))
	tieB := deliveryFixture("delivery-a", "fp-a", base.Add(time.Minute))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{early, tieA, tieB}); err != nil {
		t.Fatal(err)
	}

	claimed, err := st.ClaimAlertDispatches(ctx, "worker-a", base.Add(5*time.Minute), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 3 {
		t.Fatalf("claimed %d dispatches, want 3", len(claimed))
	}
	want := []string{"delivery-c", "delivery-a", "delivery-b"}
	got := make([]string, len(claimed))
	for i, d := range claimed {
		got[i] = d.Delivery.ID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claim order = %v, want %v", got, want)
	}
}

func TestClaimAlertDispatchesRespectsLimit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	a := deliveryFixture("delivery-a", "fp-a", now)
	b := deliveryFixture("delivery-b", "fp-b", now.Add(time.Minute))
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{a, b}); err != nil {
		t.Fatal(err)
	}

	claimed, err := st.ClaimAlertDispatches(ctx, "worker-a", now.Add(5*time.Minute), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].Delivery.ID != "delivery-a" {
		t.Fatalf("claimed = %#v, want single earliest delivery-a", claimed)
	}
}

func TestRetryAlertDispatchHonorsRetryDueTiming(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-a", "fp-a", now)}); err != nil {
		t.Fatal(err)
	}

	claimed, err := st.ClaimAlertDispatches(ctx, "worker-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	retryAt := now.Add(10 * time.Minute)
	if err := st.RetryAlertDispatch(ctx, claimed[0], "transient", retryAt, false); err != nil {
		t.Fatal(err)
	}

	// Before retry_at, the dispatch must not be claimable.
	early, err := st.ClaimAlertDispatches(ctx, "worker-b", now.Add(5*time.Minute), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(early) != 0 {
		t.Fatalf("claimed before retry_at: %#v", early)
	}

	// At/after retry_at, it becomes claimable again.
	due, err := st.ClaimAlertDispatches(ctx, "worker-b", retryAt, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].Delivery.ID != "delivery-a" {
		t.Fatalf("claimed at retry_at = %#v", due)
	}
	if due[0].AttemptCount != 2 {
		t.Fatalf("attempt count = %d, want 2", due[0].AttemptCount)
	}
}

func TestRetryAlertDispatchRejectsNonConformingErrorClass(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-a", "fp-a", now)}); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimAlertDispatches(ctx, "worker-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}

	badClasses := []string{
		"",
		"Transient", // uppercase
		"connection refused: dial tcp 10.0.0.5:443",     // raw error text with spaces/colons
		"https://internal.example.com/secret?token=abc", // a URL that could leak
		"1_leading_digit",
		"trailing_space ",
		strings.Repeat("a", maxErrorClassLength+1), // over length cap
	}
	for _, class := range badClasses {
		if err := st.RetryAlertDispatch(ctx, claimed[0], class, now.Add(time.Minute), false); err == nil {
			t.Fatalf("accepted non-conforming error class %q", class)
		} else if errors.Is(err, ErrAlertDispatchLeaseLost) {
			t.Fatalf("error class %q rejected via lease-lost instead of validation: %v", class, err)
		}
	}

	// The claim must still be intact — a rejected class must not have
	// touched the row.
	var status string
	var leaseOwner sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT status, lease_owner FROM alert_delivery_dispatches WHERE delivery_id = ?`, "delivery-a").
		Scan(&status, &leaseOwner); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" || !leaseOwner.Valid || leaseOwner.String != "worker-a" {
		t.Fatalf("claim mutated by rejected retry: status=%q lease_owner=%v", status, leaseOwner)
	}

	// A conforming class still works on the same still-valid claim.
	if err := st.RetryAlertDispatch(ctx, claimed[0], "rate_limited", now.Add(time.Minute), false); err != nil {
		t.Fatalf("conforming error class rejected: %v", err)
	}
}

func TestRetryAlertDispatchTerminalFailureStopsRetrying(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-a", "fp-a", now)}); err != nil {
		t.Fatal(err)
	}

	claimed, err := st.ClaimAlertDispatches(ctx, "worker-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RetryAlertDispatch(ctx, claimed[0], "permanent", time.Time{}, true); err != nil {
		t.Fatal(err)
	}

	var status string
	var retryAt sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT status, retry_at FROM alert_delivery_dispatches WHERE delivery_id = ?`, "delivery-a").
		Scan(&status, &retryAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || retryAt.Valid {
		t.Fatalf("terminal failure state = status=%q retry_at.Valid=%v", status, retryAt.Valid)
	}

	// A terminal dispatch is never claimable again, even far in the future.
	later, err := st.ClaimAlertDispatches(ctx, "worker-b", now.Add(24*time.Hour), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 0 {
		t.Fatalf("terminal dispatch was reclaimed: %#v", later)
	}

	// Retrying an already-terminal (no longer claimed) dispatch loses the lease.
	if err := st.RetryAlertDispatch(ctx, claimed[0], "transient", now.Add(time.Minute), false); !errors.Is(err, ErrAlertDispatchLeaseLost) {
		t.Fatalf("retry after terminal = %v", err)
	}
}

func TestClaimAlertDispatchesConcurrentWorkersNeverDoubleClaim(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)

	const n = 20
	inputs := make([]DeliveryInput, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("delivery-%02d", i)
		fp := fmt.Sprintf("fp-%02d", i)
		inputs[i] = deliveryFixture(id, fp, now.Add(time.Duration(i)*time.Second))
	}
	if _, err := st.AcceptDeliveries(ctx, inputs); err != nil {
		t.Fatal(err)
	}

	const workers = 5
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimedBy := map[string]string{}
	errs := make(chan error, workers*n)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		owner := fmt.Sprintf("worker-%d", w)
		go func(owner string) {
			defer wg.Done()
			claimed, err := st.ClaimAlertDispatches(ctx, owner, now.Add(time.Minute), time.Minute, n)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, d := range claimed {
				if prev, ok := claimedBy[d.Delivery.ID]; ok {
					errs <- fmt.Errorf("delivery %s claimed by both %s and %s", d.Delivery.ID, prev, owner)
					continue
				}
				claimedBy[d.Delivery.ID] = owner
			}
		}(owner)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if len(claimedBy) != n {
		t.Fatalf("claimed %d of %d deliveries across %d concurrent workers", len(claimedBy), n, workers)
	}
}

func TestAcceptDeliveriesPersistsAcrossFileBackedCloseReopen(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "durable.db")

	st, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	accepted, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("delivery-a", "fp-a", now)})
	if err != nil {
		_ = st.Close()
		t.Fatalf("AcceptDeliveries: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	assertTableCount(t, reopened.DB(), "alert_deliveries", 1)
	assertTableCount(t, reopened.DB(), "alert_delivery_dispatches", 1)

	claimed, err := reopened.ClaimAlertDispatches(ctx, "worker-a", now.Add(time.Minute), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].Delivery.ID != accepted[0].ID {
		t.Fatalf("claimed after reopen = %#v, want delivery matching %q", claimed, accepted[0].ID)
	}
	if !reflect.DeepEqual(claimed[0].Delivery, accepted[0]) {
		t.Fatalf("delivery after reopen changed: %#v vs %#v", claimed[0].Delivery, accepted[0])
	}
}

func TestValidateDeliveryInputRejectsSignalVersionWithoutSignalID(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	d := deliveryFixture("delivery-a", "fp-a", now)
	version := "sha256:abc"
	d.SourceProvenance.SignalVersion = &version

	if _, err := newTestStore(t).AcceptDeliveries(context.Background(), []DeliveryInput{d}); err == nil {
		t.Fatal("accepted delivery with SignalVersion but no SignalID")
	}
}

func TestValidateDeliveryInputRequiresPollIntervalMatchingAcquisitionMode(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)

	webhookWithInterval := deliveryFixture("delivery-a", "fp-a", now)
	webhookWithInterval.SourceProvenance.PollIntervalSeconds = 30
	if _, err := newTestStore(t).AcceptDeliveries(context.Background(), []DeliveryInput{webhookWithInterval}); err == nil {
		t.Fatal("accepted webhook delivery with nonzero poll interval")
	}

	pollWithoutInterval := deliveryFixture("delivery-b", "fp-b", now)
	pollWithoutInterval.SourceProvenance.AcquisitionMode = SourceAcquisitionPoll
	if _, err := newTestStore(t).AcceptDeliveries(context.Background(), []DeliveryInput{pollWithoutInterval}); err == nil {
		t.Fatal("accepted poll delivery with zero poll interval")
	}
}

// ---------------------------------------------------------------------
// ApplyCorrelatedDelivery / MarkIncidentReadyWithSituationInput (Task 5)
// ---------------------------------------------------------------------

func insertCollectingIncident(t *testing.T, st *Store, id, groupKey string, readyAt time.Time) {
	t.Helper()
	if err := st.InsertIncident(context.Background(), Incident{
		ID: id, GroupKey: groupKey, FirstAlertAt: readyAt, LastAlertAt: readyAt, ReadyAt: readyAt,
	}); err != nil {
		t.Fatalf("insert collecting incident: %v", err)
	}
}

func assertIncidentStatus(t *testing.T, st *Store, incidentID, want string) {
	t.Helper()
	var got string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT status FROM incidents WHERE id = ?`, incidentID).Scan(&got); err != nil {
		t.Fatalf("read incident status: %v", err)
	}
	if got != want {
		t.Fatalf("incident %s status = %q, want %q", incidentID, got, want)
	}
}

func assertQueryCount(t *testing.T, db *sql.DB, query string, want int, args ...any) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count = %d, want %d (query: %s)", got, want, query)
	}
}

// assertCorrelatedDeliveryRows checks all five durable effects one commit of
// ApplyCorrelatedDelivery must have produced: the Incident row, the current
// incident_alerts compatibility membership, the immutable
// incident_alert_deliveries ownership link, the Situation input, and the
// dispatch's terminal status.
func assertCorrelatedDeliveryRows(t *testing.T, db *sql.DB, deliveryID, incidentID, inputID, dispatchStatus string) {
	t.Helper()
	ctx := context.Background()

	assertQueryCount(t, db, `SELECT COUNT(*) FROM incidents WHERE id = ?`, 1, incidentID)

	var alertID string
	if err := db.QueryRowContext(ctx, `SELECT alert_id FROM alert_deliveries WHERE id = ?`, deliveryID).Scan(&alertID); err != nil {
		t.Fatalf("read delivery alert id: %v", err)
	}
	assertQueryCount(t, db, `SELECT COUNT(*) FROM incident_alerts WHERE incident_id = ? AND alert_id = ?`, 1, incidentID, alertID)

	var linkIncidentID string
	if err := db.QueryRowContext(ctx, `SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = ?`, deliveryID).Scan(&linkIncidentID); err != nil {
		t.Fatalf("read immutable delivery ownership: %v", err)
	}
	if linkIncidentID != incidentID {
		t.Fatalf("immutable delivery ownership incident = %q, want %q", linkIncidentID, incidentID)
	}

	assertQueryCount(t, db, `SELECT COUNT(*) FROM situation_input_outbox WHERE id = ? AND incident_id = ?`, 1, inputID, incidentID)

	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM alert_delivery_dispatches WHERE delivery_id = ?`, deliveryID).Scan(&status); err != nil {
		t.Fatalf("read dispatch status: %v", err)
	}
	if status != dispatchStatus {
		t.Fatalf("dispatch status = %q, want %q", status, dispatchStatus)
	}
}

func TestApplyCorrelatedDeliveryCommitsIncidentInputAndDispatch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	_, _ = st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("d1", "fp1", now)})
	claims, _ := st.ClaimAlertDispatches(ctx, "dispatch-a", now, time.Minute, 1)
	deliveryID := claims[0].Delivery.ID

	result, err := st.ApplyCorrelatedDelivery(ctx, CorrelatedDeliveryMutation{
		DeliveryID:         deliveryID,
		DispatchOwner:      "dispatch-a",
		DispatchClaimToken: claims[0].ClaimToken,
		Incident:           Incident{ID: "inc-1", GroupKey: "service=api", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:              SituationInput{ID: "input-d1", IdempotencyKey: "delivery:d1", IncidentID: "inc-1", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=api", OccurredAt: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.Incident.ID != "inc-1" {
		t.Fatalf("result = %+v", result)
	}
	assertCorrelatedDeliveryRows(t, st.DB(), "d1", "inc-1", "input-d1", "applied")
}

func TestApplyCorrelatedDeliveryRollsBackOnSituationInputFailure(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)

	// A test-only trigger simulates a mid-transaction failure at the
	// Situation-input insertion step (step 9), so this test can assert the
	// whole transaction — Incident, membership, immutable ownership, and the
	// dispatch transition — rolls back together, not just the input row.
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER test_force_situation_input_failure
		BEFORE INSERT ON situation_input_outbox
		WHEN NEW.incident_id = 'inc-force-fail'
		BEGIN SELECT RAISE(ABORT, 'forced situation input failure'); END;
	`); err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	_, _ = st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("d-fail", "fp-fail", now)})
	claims, err := st.ClaimAlertDispatches(ctx, "dispatch-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	deliveryID := claims[0].Delivery.ID

	_, err = st.ApplyCorrelatedDelivery(ctx, CorrelatedDeliveryMutation{
		DeliveryID:         deliveryID,
		DispatchOwner:      "dispatch-a",
		DispatchClaimToken: claims[0].ClaimToken,
		Incident:           Incident{ID: "inc-force-fail", GroupKey: "service=fail", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:              SituationInput{ID: "input-fail", IdempotencyKey: "delivery:" + deliveryID, IncidentID: "inc-force-fail", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=fail", OccurredAt: now},
	})
	if err == nil {
		t.Fatal("expected forced situation input failure")
	}

	assertTableCount(t, st.DB(), "incidents", 0)
	assertTableCount(t, st.DB(), "incident_alerts", 0)
	assertTableCount(t, st.DB(), "incident_alert_deliveries", 0)
	assertTableCount(t, st.DB(), "situation_input_outbox", 0)

	var status string
	if err := st.DB().QueryRowContext(ctx, `SELECT status FROM alert_delivery_dispatches WHERE delivery_id = ?`, deliveryID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" {
		t.Fatalf("dispatch status = %q, want claimed (unchanged by the rolled-back transaction)", status)
	}
}

func TestApplyCorrelatedDeliveryStaleClaimTokenChangesNothing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	_, _ = st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("d-stale", "fp-stale", now)})
	claims, err := st.ClaimAlertDispatches(ctx, "dispatch-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	deliveryID := claims[0].Delivery.ID

	_, err = st.ApplyCorrelatedDelivery(ctx, CorrelatedDeliveryMutation{
		DeliveryID:         deliveryID,
		DispatchOwner:      "dispatch-a",
		DispatchClaimToken: claims[0].ClaimToken + 1, // stale/wrong token
		Incident:           Incident{ID: "inc-stale", GroupKey: "service=stale", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:              SituationInput{ID: "input-stale", IdempotencyKey: "delivery:" + deliveryID, IncidentID: "inc-stale", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=stale", OccurredAt: now},
	})
	if !errors.Is(err, ErrAlertDispatchLeaseLost) {
		t.Fatalf("err = %v, want ErrAlertDispatchLeaseLost", err)
	}
	assertTableCount(t, st.DB(), "incidents", 0)
	assertTableCount(t, st.DB(), "situation_input_outbox", 0)

	var status string
	if err := st.DB().QueryRowContext(ctx, `SELECT status FROM alert_delivery_dispatches WHERE delivery_id = ?`, deliveryID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" {
		t.Fatalf("dispatch status = %q, want claimed (unchanged)", status)
	}
}

func TestApplyCorrelatedDeliveryDuplicateRepairsAppliedProjection(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	_, _ = st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixture("d-dup", "fp-dup", now)})
	claims, err := st.ClaimAlertDispatches(ctx, "dispatch-a", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	deliveryID := claims[0].Delivery.ID
	mutation := CorrelatedDeliveryMutation{
		DeliveryID:         deliveryID,
		DispatchOwner:      "dispatch-a",
		DispatchClaimToken: claims[0].ClaimToken,
		Incident:           Incident{ID: "inc-dup", GroupKey: "service=dup", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:              SituationInput{ID: "input-dup", IdempotencyKey: "delivery:" + deliveryID, IncidentID: "inc-dup", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=dup", OccurredAt: now},
	}
	first, err := st.ApplyCorrelatedDelivery(ctx, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate {
		t.Fatal("first application marked duplicate")
	}

	// Manually reset only the dispatch row to a fresh claim, simulating
	// recovery code that reads stale claim state and replays the same
	// mutation. The store must repair the applied projection and report
	// Duplicate=true without creating a second Incident link or input.
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status='claimed', lease_owner='dispatch-b', lease_expires_at=?, claim_token=claim_token+1, applied_at=NULL, retry_at=NULL
		WHERE delivery_id=?`, now.Add(time.Minute).UTC().Format(time.RFC3339Nano), deliveryID); err != nil {
		t.Fatal(err)
	}
	var token int64
	if err := st.DB().QueryRowContext(ctx, `SELECT claim_token FROM alert_delivery_dispatches WHERE delivery_id=?`, deliveryID).Scan(&token); err != nil {
		t.Fatal(err)
	}

	replay := mutation
	replay.DispatchOwner = "dispatch-b"
	replay.DispatchClaimToken = token
	second, err := st.ApplyCorrelatedDelivery(ctx, replay)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate {
		t.Fatal("replay not marked duplicate")
	}
	if second.Incident.ID != "inc-dup" {
		t.Fatalf("replay incident = %+v", second.Incident)
	}

	assertCorrelatedDeliveryRows(t, st.DB(), deliveryID, "inc-dup", "input-dup", "applied")
	assertTableCount(t, st.DB(), "incident_alert_deliveries", 1)
	assertTableCount(t, st.DB(), "situation_input_outbox", 1)
}

func TestMarkIncidentReadyWithSituationInputIsAtomicAndIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 5, 0, 0, time.UTC)
	insertCollectingIncident(t, st, "inc-ready", "service=api", now.Add(-time.Minute))
	if err := st.MarkIncidentReadyWithSituationInput(ctx, "inc-ready", now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReadyWithSituationInput(ctx, "inc-ready", now); err != nil {
		t.Fatal(err)
	}
	assertIncidentStatus(t, st, "inc-ready", "ready")
	assertQueryCount(t, st.DB(), `SELECT COUNT(*) FROM situation_input_outbox WHERE idempotency_key=? AND kind='incident_ready'`, 1, "incident-ready:inc-ready")
}

func TestMarkIncidentReadyWithSituationInputRejectsUnknownIncident(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 5, 0, 0, time.UTC)
	if err := st.MarkIncidentReadyWithSituationInput(ctx, "does-not-exist", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestMarkIncidentReadyWithSituationInputRejectsTerminalIncident(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 5, 0, 0, time.UTC)
	insertCollectingIncident(t, st, "inc-done", "service=done", now)
	if _, err := st.DB().ExecContext(ctx, `UPDATE incidents SET status='failed' WHERE id=?`, "inc-done"); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReadyWithSituationInput(ctx, "inc-done", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func newFileTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "alertint.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	return st
}

func acceptSameGroupFixtures(t *testing.T, st *Store, ids []string, now time.Time) {
	t.Helper()
	inputs := make([]DeliveryInput, 0, len(ids))
	for _, id := range ids {
		in := deliveryFixture(id, "fp-"+id, now)
		in.ReceiverGroupingIdentity = "service=api"
		inputs = append(inputs, in)
	}
	if _, err := st.AcceptDeliveries(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
}

func claimDispatches(t *testing.T, st *Store, owner string, now time.Time, count int) []AlertDispatch {
	t.Helper()
	claims, err := st.ClaimAlertDispatches(context.Background(), owner, now, time.Minute, count)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != count {
		t.Fatalf("claims = %d, want %d", len(claims), count)
	}
	return claims
}

func applyFreshSameGroupMutation(st *Store, claim AlertDispatch, groupKey string, now time.Time) error {
	deliveryID := claim.Delivery.ID
	_, err := st.ApplyCorrelatedDelivery(context.Background(), CorrelatedDeliveryMutation{
		DeliveryID: deliveryID, DispatchOwner: *claim.LeaseOwner, DispatchClaimToken: claim.ClaimToken,
		Incident: Incident{ID: "inc-" + deliveryID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:    SituationInput{ID: "input-" + deliveryID, IdempotencyKey: "delivery:" + deliveryID, IncidentID: "inc-" + deliveryID, DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: groupKey, OccurredAt: now},
	})
	return err
}

func TestConcurrentFirstDeliveriesShareOneCollectingIncident(t *testing.T) {
	st := newFileTestStore(t)
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	acceptSameGroupFixtures(t, st, []string{"d1", "d2"}, now)
	claims := claimDispatches(t, st, "worker-a", now, 2)

	var wg sync.WaitGroup
	errs := make(chan error, len(claims))
	for _, claim := range claims {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- applyFreshSameGroupMutation(st, claim, "service=api", now)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	assertQueryCount(t, st.DB(), `SELECT COUNT(*) FROM incidents WHERE group_key=? AND status='collecting'`, 1, "service=api")
	assertQueryCount(t, st.DB(), `SELECT COUNT(*) FROM incident_alert_deliveries`, 2)
	assertQueryCount(t, st.DB(), `SELECT COUNT(*) FROM situation_input_outbox`, 2)
}
