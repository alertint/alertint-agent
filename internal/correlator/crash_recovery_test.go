// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestDispatchReplaysAfterReceiverCommit(t *testing.T) {
	st := openStore(t)
	delivery := acceptDispatchDelivery(t, st, "delivery-1", "fp-1", "firing", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC))
	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)
	w := NewDispatchWorker(st, cor, DispatchWorkerConfig{Owner: "worker-1", Lease: time.Minute}, nil)
	w.now = func() time.Time { return delivery.ReceivedAt.Add(time.Second) }

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("run dispatch: %v", err)
	}
	assertDispatchState(t, st, delivery.ID, "applied", 1)
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("delivery links=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE delivery_id = ? AND status = 'pending'`, delivery.ID); got != 1 {
		t.Fatalf("pending Situation inputs=%d, want 1", got)
	}

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("second dispatch run: %v", err)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("delivery links after replay=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("Situation inputs after replay=%d, want 1", got)
	}
}

func TestDispatchReplaysAfterCorrelationCommitBeforeDispatchAck(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	delivery := acceptDispatchDelivery(t, st, "delivery-post-commit", "fp-post-commit", "firing", now)
	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)

	first, err := st.ClaimAlertDispatches(context.Background(), "worker-old", now, time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	if err := cor.ApplyDelivery(context.Background(), first[0]); err != nil {
		t.Fatalf("first correlation commit: %v", err)
	}

	reclaimed, err := st.ClaimAlertDispatches(context.Background(), "worker-new", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim=%+v err=%v", reclaimed, err)
	}
	if err := cor.ApplyDelivery(context.Background(), reclaimed[0]); err != nil {
		t.Fatalf("replayed correlation: %v", err)
	}
	if err := st.MarkAlertDispatchApplied(context.Background(), reclaimed[0], now.Add(2*time.Minute)); err != nil {
		t.Fatalf("mark replay applied: %v", err)
	}

	assertDispatchState(t, st, delivery.ID, "applied", 2)
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incidents`); got != 1 {
		t.Fatalf("incidents=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("delivery links=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("Situation inputs=%d, want 1", got)
	}
}

func TestStaleApplyDeliveryAfterReclaimHasNoCorrelationEffects(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	delivery := acceptDispatchDelivery(t, st, "delivery-stale-apply", "fp-stale-apply", "firing", now)
	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)

	stale, err := st.ClaimAlertDispatches(context.Background(), "worker-stale", now, time.Minute, 1)
	if err != nil || len(stale) != 1 {
		t.Fatalf("stale claim=%+v err=%v", stale, err)
	}
	current, err := st.ClaimAlertDispatches(context.Background(), "worker-current", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(current) != 1 {
		t.Fatalf("current claim=%+v err=%v", current, err)
	}

	if err := cor.ApplyDelivery(context.Background(), stale[0]); !errors.Is(err, store.ErrAlertDispatchLeaseLost) {
		t.Fatalf("stale ApplyDelivery err=%v, want ErrAlertDispatchLeaseLost", err)
	}
	for _, table := range []string{"incidents", "incident_occurrences", "incident_alert_deliveries", "situation_input_outbox"} {
		if got := countQuery(t, st, `SELECT COUNT(*) FROM `+table); got != 0 {
			t.Fatalf("%s effects=%d after stale apply, want 0", table, got)
		}
	}

	if err := cor.ApplyDelivery(context.Background(), current[0]); err != nil {
		t.Fatalf("current ApplyDelivery: %v", err)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("current delivery links=%d, want 1", got)
	}
}

func TestClaimOrderPreservesFiringBeforeResolvedForLifecycle(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	acceptDispatchDelivery(t, st, "z-firing-digest", "fp-causal", "firing", now)
	acceptDispatchDelivery(t, st, "a-resolved-digest", "fp-causal", "resolved", now.Add(time.Minute))
	claims, err := st.ClaimAlertDispatches(context.Background(), "worker-causal", now.Add(2*time.Minute), time.Minute, 2)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	if claims[0].Delivery.ID != "z-firing-digest" || claims[1].Delivery.ID != "a-resolved-digest" {
		t.Fatalf("claim order=(%q,%q), want firing then resolved", claims[0].Delivery.ID, claims[1].Delivery.ID)
	}

	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)
	if err := cor.ApplyDelivery(context.Background(), claims[0]); err != nil {
		t.Fatalf("apply firing: %v", err)
	}
	var incidentID string
	if err := st.DB().QueryRow(`SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = 'z-firing-digest'`).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE incidents SET status = 'analyzed' WHERE id = ?`, incidentID); err != nil {
		t.Fatal(err)
	}
	if err := cor.ApplyDelivery(context.Background(), claims[1]); err != nil {
		t.Fatalf("apply resolved: %v", err)
	}
	var incidentStatus, inputKind string
	if err := st.DB().QueryRow(`SELECT status FROM incidents WHERE id = ?`, incidentID).Scan(&incidentStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT kind FROM situation_input_outbox WHERE delivery_id = 'a-resolved-digest'`).Scan(&inputKind); err != nil {
		t.Fatal(err)
	}
	if incidentStatus != "resolved" || inputKind != "incident_resolved" {
		t.Fatalf("lifecycle=(%q,%q), want (resolved,incident_resolved)", incidentStatus, inputKind)
	}
}

func TestTerminalOwnerForcesNewIncident(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	member := firingAlert("fp-old", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "incident-terminal", "analyzed", now.Add(-5*time.Minute), now.Add(-5*time.Minute), member)
	transitionOwnerToRecovered(t, st, "incident-terminal", now.Add(-4*time.Minute))
	delivery := acceptDispatchDelivery(t, st, "delivery-refire", "fp-refire", "firing", now)
	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)

	before := countQuery(t, st, `SELECT COUNT(*) FROM incidents`)
	claim := claimAcceptedDelivery(t, st, "worker-terminal", now.Add(time.Second))
	if err := cor.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatalf("apply refire: %v", err)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incidents`); got != before+1 {
		t.Fatalf("incidents=%d, want %d", got, before+1)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_occurrences WHERE incident_id = ?`, "incident-terminal"); got != 0 {
		t.Fatalf("terminal-owner occurrences=%d, want 0", got)
	}
	var incidentID string
	if err := st.DB().QueryRow(`SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = ?`, delivery.ID).Scan(&incidentID); err != nil {
		t.Fatalf("read delivery owner: %v", err)
	}
	if incidentID == "incident-terminal" {
		t.Fatal("refire delivery attached across terminal Situation boundary")
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE delivery_id = ? AND incident_id = ?`, delivery.ID, incidentID); got != 1 {
		t.Fatalf("new-Incident Situation inputs=%d, want 1", got)
	}
}

func TestNonterminalOwnerCollapsesThroughAtomicSituationInput(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	member := firingAlert("fp-active-old", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "incident-active", "analyzed", now.Add(-5*time.Minute), now.Add(-5*time.Minute), member)
	delivery := acceptDispatchDelivery(t, st, "delivery-active-refire", "fp-active-refire", "firing", now)
	cor, doubles := newCorrelatorFor(t, st)

	claim := claimAcceptedDelivery(t, st, "worker-active", now.Add(time.Second))
	if err := cor.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatalf("apply active refire: %v", err)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_occurrences WHERE incident_id = 'incident-active'`); got != 1 {
		t.Fatalf("occurrences=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE incident_id = 'incident-active' AND delivery_id = ?`, delivery.ID); got != 1 {
		t.Fatalf("delivery links=%d, want 1", got)
	}
	if got := countQuery(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id = 'incident-active' AND delivery_id = ? AND kind = 'membership_changed'`, delivery.ID); got != 1 {
		t.Fatalf("membership inputs=%d, want 1", got)
	}
	if doubles.notif.count() != 0 || doubles.rej.count() != 0 {
		t.Fatalf("direct notifier/rejudger calls=(%d,%d), want (0,0)", doubles.notif.count(), doubles.rej.count())
	}
}

func TestResolvedDeliveryAtomicallyMarksIncidentAndEmitsResolvedInput(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)
	cor := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)
	firing := acceptDispatchDelivery(t, st, "delivery-firing", "fp-lifecycle", "firing", now)
	firingClaim := claimAcceptedDelivery(t, st, "worker-firing", now.Add(time.Second))
	if err := cor.ApplyDelivery(context.Background(), firingClaim); err != nil {
		t.Fatalf("apply firing: %v", err)
	}
	if err := st.MarkAlertDispatchApplied(context.Background(), firingClaim, now.Add(time.Second)); err != nil {
		t.Fatalf("ack firing: %v", err)
	}
	var incidentID string
	if err := st.DB().QueryRow(`SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = ?`, firing.ID).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE incidents SET status = 'analyzed' WHERE id = ?`, incidentID); err != nil {
		t.Fatal(err)
	}
	resolved := acceptDispatchDelivery(t, st, "delivery-resolved", "fp-lifecycle", "resolved", now.Add(time.Minute))
	resolvedClaim := claimAcceptedDelivery(t, st, "worker-resolved", now.Add(2*time.Minute))
	if err := cor.ApplyDelivery(context.Background(), resolvedClaim); err != nil {
		t.Fatalf("apply resolved: %v", err)
	}
	var status, kind string
	if err := st.DB().QueryRow(`SELECT status FROM incidents WHERE id = ?`, incidentID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT kind FROM situation_input_outbox WHERE delivery_id = ?`, resolved.ID).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" || kind != "incident_resolved" {
		t.Fatalf("resolved mutation=(%q,%q), want (resolved,incident_resolved)", status, kind)
	}
}

func claimAcceptedDelivery(t *testing.T, st *store.Store, owner string, now time.Time) store.AlertDispatch {
	t.Helper()
	claims, err := st.ClaimAlertDispatches(context.Background(), owner, now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim accepted delivery=%+v err=%v", claims, err)
	}
	return claims[0]
}

func acceptDispatchDelivery(t *testing.T, st *store.Store, deliveryID, fingerprint, status string, at time.Time) store.AlertDelivery {
	t.Helper()
	started := at.Add(-time.Minute).UTC()
	input := store.DeliveryInput{
		ID: deliveryID,
		Alert: store.Alert{
			ID: deliveryID + "-alert", Fingerprint: fingerprint, Status: status,
			Labels:      map[string]string{"service": "api", "alertname": "DiskFull", "severity": "warning"},
			Annotations: map[string]string{"summary": "disk filling"}, StartsAt: started, ReceivedAt: at,
		},
		Source: "alertmanager", SourceEpisodeKey: "alertmanager:" + fingerprint + ":" + started.Format(time.RFC3339Nano),
		SourceStartedAt: &started, StartedAtBasis: model.SourceTimeBasisSourcePayload,
		ResolvedAtBasis: model.SourceTimeBasisMissing, ReceiverGroupingIdentity: gkAPI, PayloadDigest: "sha256:" + deliveryID,
	}
	if status == "resolved" {
		resolved := at.UTC()
		input.SourceResolvedAt = &resolved
		input.ResolvedAtBasis = model.SourceTimeBasisSourcePayload
		input.Alert.EndsAt = &resolved
	}
	deliveries, err := st.AcceptDeliveries(context.Background(), []store.DeliveryInput{input})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("accept delivery=%+v err=%v", deliveries, err)
	}
	return deliveries[0]
}

func seedIncidentOwner(t *testing.T, st *store.Store, incidentID, groupKey string, lifecycle model.Lifecycle, at time.Time) {
	t.Helper()
	now := at.UTC().Format(time.RFC3339Nano)
	var recoveryObserved, graceUntil, terminalAt any
	if lifecycle == model.LifecycleRecoveryPending || lifecycle == model.LifecycleRecovered {
		recoveryObserved = now
		graceUntil = at.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	}
	if lifecycle == model.LifecycleRecovered {
		terminalAt = at.Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
	}
	_, err := st.DB().Exec(`
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version, opened_at,
			effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, recovery_observed_at, grace_until, terminal_at,
			next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES (?, ?, ?, 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, ?, ?, ?, '[]', ?, ?)`,
		"situation-"+incidentID, groupKey, lifecycle, now, now, now, now,
		recoveryObserved, graceUntil, terminalAt, now, now, now)
	if err != nil {
		t.Fatalf("seed Situation owner: %v", err)
	}
	if _, err := st.DB().Exec(`INSERT INTO situation_incidents(situation_id, incident_id, attached_at) VALUES (?, ?, ?)`, "situation-"+incidentID, incidentID, now); err != nil {
		t.Fatalf("seed Situation membership: %v", err)
	}
}

func transitionOwnerToRecovered(t *testing.T, st *store.Store, incidentID string, at time.Time) {
	t.Helper()
	recoveryAt := at.UTC().Format(time.RFC3339Nano)
	graceAt := at.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().Exec(`
		UPDATE situations
		SET lifecycle = 'recovery_pending', recovery_observed_at = ?, grace_until = ?, updated_at = ?
		WHERE id = (SELECT situation_id FROM situation_incidents WHERE incident_id = ?)`, recoveryAt, graceAt, recoveryAt, incidentID); err != nil {
		t.Fatalf("move owner to recovery_pending: %v", err)
	}
	terminalAt := at.Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().Exec(`
		UPDATE situations SET lifecycle = 'recovered', terminal_at = ?, updated_at = ?
		WHERE id = (SELECT situation_id FROM situation_incidents WHERE incident_id = ?)`, terminalAt, terminalAt, incidentID); err != nil {
		t.Fatalf("move owner to recovered: %v", err)
	}
}

func assertDispatchState(t *testing.T, st *store.Store, deliveryID, wantStatus string, wantAttempts int) {
	t.Helper()
	var status string
	var attempts int
	if err := st.DB().QueryRow(`SELECT status, attempt_count FROM alert_delivery_dispatches WHERE delivery_id = ?`, deliveryID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read dispatch state: %v", err)
	}
	if status != wantStatus || attempts != wantAttempts {
		t.Fatalf("dispatch=(%s,%d), want (%s,%d)", status, attempts, wantStatus, wantAttempts)
	}
}

func countQuery(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var got int
	if err := st.DB().QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return got
}
