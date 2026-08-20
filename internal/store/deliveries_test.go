// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestOpenMigratesExisting0010DatabaseToDeliveryLedger(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "from-0010.db")
	db, err := sql.Open("sqlite", buildDSN(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Store{db: db}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	files, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range files {
		if migration.version > 10 {
			break
		}
		if err := legacy.applyMigration(ctx, migration); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.version, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open migrated database: %v", err)
	}
	defer func() { _ = upgraded.Close() }()
	if n := deliveryRowCount(t, upgraded, "alert_deliveries"); n != 0 {
		t.Fatalf("deliveries=%d, want 0 after migration", n)
	}
}

func TestAcceptDeliveriesIsAtomicAndAppendOnly(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	in := []DeliveryInput{
		{
			ID:     "d1",
			Alert:  Alert{ID: "a1", Fingerprint: "fp1", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp1:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:a",
		},
		{
			ID:     "d2",
			Alert:  Alert{ID: "a2", Fingerprint: "fp2", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp2:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:b",
		},
	}
	got, err := s.AcceptDeliveries(context.Background(), in)
	if err != nil || len(got) != 2 {
		t.Fatalf("got=%d err=%v", len(got), err)
	}
	if _, err := s.AcceptDeliveries(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if n := deliveryRowCount(t, s, "alert_deliveries"); n != 2 {
		t.Fatalf("deliveries=%d", n)
	}
	if n := deliveryRowCount(t, s, "alert_delivery_dispatches"); n != 2 {
		t.Fatalf("dispatches=%d", n)
	}
}

func TestAcceptDeliveriesRollsBackWholeEnvelope(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	in := []DeliveryInput{
		{
			ID:     "d1",
			Alert:  Alert{ID: "a1", Fingerprint: "fp1", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp1:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:a",
		},
		{
			ID:     "d2",
			Alert:  Alert{ID: "a2", Fingerprint: "fp2", Status: "invalid", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp2:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:b",
		},
	}
	if _, err := s.AcceptDeliveries(context.Background(), in); err == nil {
		t.Fatal("AcceptDeliveries accepted an invalid envelope")
	}
	if n := deliveryRowCount(t, s, "alerts"); n != 0 {
		t.Fatalf("alerts=%d, want 0", n)
	}
	if n := deliveryRowCount(t, s, "alert_deliveries"); n != 0 {
		t.Fatalf("deliveries=%d, want 0", n)
	}
}

func TestClaimAlertDispatchesReturnsOnlyRowsChangedByThisClaim(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	in := []DeliveryInput{
		{
			ID: "claim-d1", Alert: Alert{ID: "claim-a1", Fingerprint: "claim-fp1", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:claim-fp1:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:claim-a",
		},
		{
			ID: "claim-d2", Alert: Alert{ID: "claim-a2", Fingerprint: "claim-fp2", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
			Source: "alertmanager", SourceEpisodeKey: "alertmanager:claim-fp2:2026-08-20T10:00:00Z", SourceStartedAt: &now,
			StartedAtBasis: "source_payload", ResolvedAtBasis: "missing", ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:claim-b",
		},
	}
	if _, err := s.AcceptDeliveries(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimAlertDispatches(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(first) != 1 || first[0].Delivery.ID != "claim-d1" {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	second, err := s.ClaimAlertDispatches(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(second) != 1 || second[0].Delivery.ID != "claim-d2" {
		t.Fatalf("second claim=%+v err=%v", second, err)
	}
}

func TestAlertDispatchMutationsRejectExpiredReclaimedFence(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	acceptDeliveryFixture(t, s, "fenced-delivery", now)
	first, err := s.ClaimAlertDispatches(context.Background(), "worker-old", now, time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	second, err := s.ClaimAlertDispatches(context.Background(), "worker-new", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim=%+v err=%v", second, err)
	}
	if first[0].ClaimToken == second[0].ClaimToken {
		t.Fatalf("claim tokens both %d, want monotonic fence", first[0].ClaimToken)
	}
	if err := s.MarkAlertDispatchApplied(context.Background(), first[0], now.Add(2*time.Minute)); !errors.Is(err, ErrAlertDispatchLeaseLost) {
		t.Fatalf("stale apply err=%v, want ErrAlertDispatchLeaseLost", err)
	}
	if err := s.RetryAlertDispatch(context.Background(), first[0], "stale_retry", now.Add(3*time.Minute), false); !errors.Is(err, ErrAlertDispatchLeaseLost) {
		t.Fatalf("stale retry err=%v, want ErrAlertDispatchLeaseLost", err)
	}
	var owner string
	var token int64
	if err := s.DB().QueryRowContext(context.Background(), `SELECT lease_owner, claim_token FROM alert_delivery_dispatches WHERE delivery_id = 'fenced-delivery'`).Scan(&owner, &token); err != nil {
		t.Fatal(err)
	}
	if owner != "worker-new" || token != second[0].ClaimToken {
		t.Fatalf("durable fence=(%q,%d), want (%q,%d)", owner, token, "worker-new", second[0].ClaimToken)
	}
}

func TestApplyCorrelatedDeliveryRollsBackIncidentLinkAndInputTogether(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	acceptDeliveryFixture(t, s, "atomic-delivery", now)
	blocker := Incident{ID: "blocker-incident", GroupKey: "service=other", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)}
	if err := s.InsertIncident(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(context.Background(), `
		INSERT INTO situation_input_outbox(id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES ('blocker-input', 'delivery:collision', 'blocker-incident', 'incident_created', 'service=other', ?, 'pending')`, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	deliveryID := "atomic-delivery"
	claims, err := s.ClaimAlertDispatches(context.Background(), "atomic-worker", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	err = s.ApplyCorrelatedDelivery(context.Background(), CorrelatedDeliveryMutation{
		DeliveryID: deliveryID, DispatchOwner: "atomic-worker", DispatchClaimToken: claims[0].ClaimToken,
		Incident: Incident{ID: "atomic-incident", GroupKey: "service=api", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)},
		Input:    SituationInput{ID: "atomic-input", IdempotencyKey: "delivery:collision", IncidentID: "atomic-incident", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=api", OccurredAt: now},
	})
	if err == nil {
		t.Fatal("ApplyCorrelatedDelivery error=nil, want idempotency collision")
	}
	if got := deliveryRowCount(t, s, "incidents"); got != 1 {
		t.Fatalf("incidents=%d, want only blocker after rollback", got)
	}
	if got := deliveryRowCount(t, s, "incident_alert_deliveries"); got != 0 {
		t.Fatalf("delivery links=%d, want 0 after rollback", got)
	}
}

func TestConcurrentFirstDeliveriesShareOneCollectingIncident(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	acceptDeliveryFixture(t, s, "first-delivery-a", now)
	acceptDeliveryFixture(t, s, "first-delivery-b", now.Add(time.Second))
	claims, err := s.ClaimAlertDispatches(context.Background(), "concurrent-worker", now.Add(time.Minute), time.Minute, 2)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}

	start := make(chan struct{})
	errs := make(chan error, len(claims))
	for i, claim := range claims {
		go func() {
			<-start
			incidentID := fmt.Sprintf("concurrent-incident-%d", i)
			deliveryID := claim.Delivery.ID
			errs <- s.ApplyCorrelatedDelivery(context.Background(), CorrelatedDeliveryMutation{
				DeliveryID: deliveryID, DispatchOwner: "concurrent-worker", DispatchClaimToken: claim.ClaimToken,
				Incident: Incident{ID: incidentID, GroupKey: "service=api", FirstAlertAt: claim.Delivery.ReceivedAt,
					LastAlertAt: claim.Delivery.ReceivedAt, ReadyAt: claim.Delivery.ReceivedAt.Add(time.Minute)},
				Input: SituationInput{ID: "input-" + deliveryID, IdempotencyKey: "delivery:" + deliveryID,
					IncidentID: incidentID, DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "service=api", OccurredAt: claim.Delivery.ReceivedAt},
			})
		}()
	}
	close(start)
	for range claims {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent mutation: %v", err)
		}
	}
	if got := deliveryRowCount(t, s, "incidents"); got != 1 {
		t.Fatalf("collecting incidents=%d, want 1", got)
	}
	if got := deliveryRowCount(t, s, "incident_alert_deliveries"); got != 2 {
		t.Fatalf("delivery links=%d, want 2", got)
	}
	if got := deliveryRowCount(t, s, "situation_input_outbox"); got != 2 {
		t.Fatalf("Situation inputs=%d, want 2", got)
	}
	if got := deliveryDistinctIncidentCount(t, s); got != 1 {
		t.Fatalf("delivery Incident owners=%d, want 1", got)
	}
}

func deliveryDistinctIncidentCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(), `SELECT COUNT(DISTINCT incident_id) FROM incident_alert_deliveries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func acceptDeliveryFixture(t *testing.T, s *Store, deliveryID string, now time.Time) {
	t.Helper()
	started := now.Add(-time.Minute)
	_, err := s.AcceptDeliveries(context.Background(), []DeliveryInput{{
		ID:     deliveryID,
		Alert:  Alert{ID: deliveryID + "-alert", Fingerprint: deliveryID + "-fp", Status: "firing", Labels: map[string]string{"service": "api"}, Annotations: map[string]string{}, StartsAt: started, ReceivedAt: now},
		Source: "alertmanager", SourceEpisodeKey: "alertmanager:" + deliveryID, SourceStartedAt: &started,
		StartedAtBasis: model.SourceTimeBasisSourcePayload, ResolvedAtBasis: model.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:" + deliveryID,
	}})
	if err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
}

func deliveryRowCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
