// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func setDeliveryEpisode(in *store.DeliveryInput, started time.Time, resolved *time.Time) {
	in.SourceStartedAt = &started
	in.SourceResolvedAt = resolved
	in.SourceEpisodeKey = "alertmanager:" + in.Alert.Fingerprint + ":" + started.UTC().Format(time.RFC3339Nano)
}

func TestApplyDeliveryRecoveryReachesEveryOpenMembershipWithOneOwner(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	shared := firingAlert("fp-shared", "DiskFull", "warning", now.Add(-20*time.Minute), false)

	seedJudged(t, st, "inc-older", "analyzed", now.Add(-20*time.Minute), now.Add(-15*time.Minute), shared)
	seedJudged(t, st, "inc-newer", "analyzed", now.Add(-10*time.Minute), now.Add(-5*time.Minute), shared)

	in := deliveryInputFor("d-resolve", shared.Fingerprint, gkAPI, "resolved", now)
	started, ended := now.Add(-20*time.Minute), now.Add(-time.Minute)
	setDeliveryEpisode(&in, started, &ended)
	claim := claimOneDelivery(t, st, in, now)
	if err := c.ApplyDelivery(ctx, claim); err != nil {
		t.Fatal(err)
	}

	for _, incidentID := range []string{"inc-older", "inc-newer"} {
		inc, err := st.GetIncidentByID(ctx, incidentID)
		if err != nil {
			t.Fatal(err)
		}
		if inc.Status != "resolved" {
			t.Errorf("%s status = %q, want resolved", incidentID, inc.Status)
		}
		var inputs int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id=?`, incidentID).Scan(&inputs); err != nil {
			t.Fatal(err)
		}
		if inputs != 1 {
			t.Errorf("%s recovery inputs = %d, want 1", incidentID, inputs)
		}
	}

	var owners int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_alert_deliveries WHERE delivery_id='d-resolve'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Fatalf("delivery owners = %d, want exactly 1", owners)
	}
}

func TestApplyDeliveryRefireReopensIncidentAndRecoversAgain(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 13, 0, 0, 0, time.UTC)
	originalStart := now.Add(-10 * time.Minute)
	member := firingAlert("fp-refire", "DiskFull", "warning", originalStart, false)
	seedJudged(t, st, "inc-refire", "analyzed", originalStart, now.Add(-5*time.Minute), member)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at)
		VALUES ('inc-refire', 'backoff', 1, ?)`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	firstResolvedAt := now.Add(-time.Minute)
	first := deliveryInputFor("d-first-resolve", member.Fingerprint, gkAPI, "resolved", now)
	setDeliveryEpisode(&first, originalStart, &firstResolvedAt)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, first, now)); err != nil {
		t.Fatal(err)
	}
	var triageRows int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_triage WHERE incident_id='inc-refire'`).Scan(&triageRows); err != nil {
		t.Fatal(err)
	}
	if triageRows != 0 {
		t.Fatalf("triage rows after recovery = %d, want 0", triageRows)
	}

	refireStart := now.Add(time.Minute)
	refire := deliveryInputFor("d-refire", member.Fingerprint, gkAPI, "firing", refireStart)
	setDeliveryEpisode(&refire, refireStart, nil)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, refire, refireStart)); err != nil {
		t.Fatal(err)
	}
	inc, err := st.GetIncidentByID(ctx, "inc-refire")
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != "analyzed" {
		t.Fatalf("status after refire = %q, want analyzed", inc.Status)
	}

	secondResolvedAt := refireStart.Add(time.Minute)
	second := deliveryInputFor("d-second-resolve", member.Fingerprint, gkAPI, "resolved", secondResolvedAt)
	setDeliveryEpisode(&second, refireStart, &secondResolvedAt)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, second, secondResolvedAt)); err != nil {
		t.Fatal(err)
	}
	inc, err = st.GetIncidentByID(ctx, "inc-refire")
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != "resolved" {
		t.Fatalf("status after refire recovery = %q, want resolved", inc.Status)
	}

	duplicate := deliveryInputFor("d-duplicate-resolve", member.Fingerprint, gkAPI, "resolved", secondResolvedAt.Add(time.Second))
	setDeliveryEpisode(&duplicate, refireStart, &secondResolvedAt)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, duplicate, duplicate.Alert.ReceivedAt)); err != nil {
		t.Fatal(err)
	}
	var transitions int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id='inc-refire' AND kind='incident_resolved'`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if transitions != 2 {
		t.Fatalf("logical recovery transitions = %d, want 2 (one per episode)", transitions)
	}
}

func TestApplyDeliveryDelayedOlderRecoveryCannotCloseNewerFiringEpisode(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	oldStart := now
	member := firingAlert("fp-delayed", "DiskFull", "warning", oldStart, false)
	seedJudged(t, st, "inc-delayed", "analyzed", oldStart, now.Add(100*time.Millisecond), member)

	// RFC3339Nano strings have variable-width fractional seconds. Keep both
	// episodes inside one second so this test also proves source chronology is
	// chronological rather than lexicographic.
	newStart := now.Add(500 * time.Millisecond)
	refire := deliveryInputFor("d-new-firing", member.Fingerprint, gkAPI, "firing", newStart)
	setDeliveryEpisode(&refire, newStart, nil)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, refire, newStart)); err != nil {
		t.Fatal(err)
	}

	oldEnd := now.Add(250 * time.Millisecond)
	delayed := deliveryInputFor("d-old-resolved", member.Fingerprint, gkAPI, "resolved", now.Add(time.Second))
	setDeliveryEpisode(&delayed, oldStart, &oldEnd)
	if err := c.ApplyDelivery(ctx, claimOneDelivery(t, st, delayed, delayed.Alert.ReceivedAt)); err != nil {
		t.Fatal(err)
	}

	inc, err := st.GetIncidentByID(ctx, "inc-delayed")
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != "analyzed" {
		t.Fatalf("status after delayed older recovery = %q, want analyzed", inc.Status)
	}
	var resolvedInputs int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id='inc-delayed' AND kind='incident_resolved'`).Scan(&resolvedInputs); err != nil {
		t.Fatal(err)
	}
	if resolvedInputs != 0 {
		t.Fatalf("incident_resolved inputs = %d, want 0", resolvedInputs)
	}
}
