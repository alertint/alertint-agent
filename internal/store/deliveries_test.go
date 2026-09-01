// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
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
