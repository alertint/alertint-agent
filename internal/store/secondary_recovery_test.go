// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// A recovery has one delivery owner, but every open membership needs to
// reach the Situation controller. Losing the delivery-less secondary input
// must leave the Situation active and lose its recovery reply.
func TestSecondaryRecoveryInputReachesSituationLifecycleAndReply(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	secondaryGroup, ownerGroup := "service=secondary-recovery", "service=owner-recovery"
	for i, incidentID := range []string{"inc-secondary", "inc-owner"} {
		at := now.Add(-10*time.Minute + time.Duration(i)*time.Minute)
		group := secondaryGroup
		if incidentID == "inc-owner" {
			group = ownerGroup
		}
		insertIncidentAndInput(t, st, incidentID, "seed-"+incidentID, group, at)
		if err := st.ApplySituationInput(ctx, claimOneInput(t, st, "seed-worker", at)); err != nil {
			t.Fatal(err)
		}
	}
	situations := listSituations(t, st)
	if len(situations) != 2 {
		t.Fatalf("initial Situations = %d, want 2", len(situations))
	}
	var sitID string
	for _, sit := range situations {
		if sit.GroupKey == secondaryGroup {
			sitID = sit.ID
		}
	}
	if sitID == "" {
		t.Fatal("secondary Situation not created")
	}
	alert := Alert{ID: "alert-shared-recovery", Fingerprint: "shared-recovery", Status: "firing",
		Labels: map[string]string{"alertname": "DiskFull"}, StartsAt: now.Add(-10 * time.Minute), ReceivedAt: now.Add(-10 * time.Minute)}
	if _, err := st.UpsertAlertByFingerprint(ctx, alert); err != nil {
		t.Fatal(err)
	}
	for _, incidentID := range []string{"inc-secondary", "inc-owner"} {
		if err := st.AddAlertToIncident(ctx, incidentID, alert.ID, now.Add(-9*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	firing := deliveryFixture("shared-firing-delivery", alert.Fingerprint, now.Add(-8*time.Minute))
	firing.Alert.ID = alert.ID
	started := now.Add(-10 * time.Minute)
	firing.SourceStartedAt = &started
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{firing}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO incident_alert_deliveries (incident_id,delivery_id,created_at) VALUES ('inc-owner',?,?)`,
		firing.ID, now.Add(-8*time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE alert_delivery_dispatches SET status='applied',applied_at=? WHERE delivery_id=?`,
		now.Add(-8*time.Minute).UTC().Format(time.RFC3339Nano), firing.ID); err != nil {
		t.Fatal(err)
	}
	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedProposalResponse(t), acceptedProposalResponse(t)}}
	controllerNow := now.Add(-7 * time.Minute)
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return controllerNow }, nil, nil)
	initialClaim := claimSituation(t, st, sitID, "controller-initial", controllerNow)
	if err := controller.Reconcile(ctx, initialClaim); err != nil {
		t.Fatal(err)
	}
	if initial := getSituationByID(t, st, sitID); initial.Lifecycle != model.LifecycleActive {
		t.Fatalf("initial lifecycle = %s, want active", initial.Lifecycle)
	}
	// The root was delivered after the initial active Transition. This
	// fixture sets its durable coordinates without exercising Slack transport.
	if _, err := st.DB().ExecContext(ctx, `UPDATE situations SET slack_channel='C-test', slack_root_ts='1.1' WHERE id=?`, sitID); err != nil {
		t.Fatal(err)
	}

	recovered := deliveryFixture("shared-recovery-delivery", alert.Fingerprint, now)
	recovered.Alert.ID = alert.ID
	recovered.Alert.Status = "resolved"
	recovered.Alert.EndsAt = &now
	recovered.SourceStartedAt, recovered.SourceResolvedAt = &started, &now
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{recovered}); err != nil {
		t.Fatal(err)
	}
	claims := claimDispatches(t, st, "recovery-worker", now, 1)
	if _, err := st.ApplyCorrelatedDelivery(ctx, CorrelatedDeliveryMutation{
		DeliveryID: recovered.ID, DispatchOwner: "recovery-worker", DispatchClaimToken: claims[0].ClaimToken,
		Incident: Incident{ID: "inc-owner", GroupKey: ownerGroup, FirstAlertAt: now.Add(-9 * time.Minute),
			LastAlertAt: now.Add(-9 * time.Minute), ReadyAt: now.Add(-9 * time.Minute)},
		Input: SituationInput{ID: "owner-recovery-input", IdempotencyKey: "delivery:shared-recovery-delivery",
			IncidentID: "inc-owner", DeliveryID: &recovered.ID, Kind: "membership_changed", GroupKey: ownerGroup, OccurredAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	var owners int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id=?`, recovered.ID).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Fatalf("recovery delivery owners = %d, want 1", owners)
	}
	var secondaryInputID string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM situation_input_outbox WHERE incident_id='inc-secondary' AND kind='incident_resolved' AND delivery_id IS NULL`).Scan(&secondaryInputID); err != nil {
		t.Fatalf("secondary delivery-less recovery input: %v", err)
	}
	for range 2 {
		if err := st.ApplySituationInput(ctx, claimOneInput(t, st, "input-worker", now.Add(time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	var appliedSituationID string
	if err := st.DB().QueryRowContext(ctx, `SELECT applied_situation_id FROM situation_input_outbox WHERE id=? AND status='applied'`, secondaryInputID).Scan(&appliedSituationID); err != nil {
		t.Fatal(err)
	}
	if appliedSituationID != sitID {
		t.Fatalf("secondary input Situation = %q, want %q", appliedSituationID, sitID)
	}

	controllerNow = now.Add(10 * time.Second)
	claim := claimSituation(t, st, sitID, "controller-secondary-recovery", now.Add(10*time.Second))
	if err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}
	sit := getSituationByID(t, st, sitID)
	if sit.Lifecycle != model.LifecycleRecoveryPending {
		t.Fatalf("Situation lifecycle = %s, want recovery_pending", sit.Lifecycle)
	}
	var replies int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents WHERE situation_id=? AND reply_kind='recovery_observed'`, sitID).Scan(&replies); err != nil {
		t.Fatal(err)
	}
	if replies != 1 {
		t.Fatalf("recovery replies = %d, want 1", replies)
	}
}
