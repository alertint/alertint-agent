// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

type resolutionRecorder struct {
	calls []store.Incident
}

func (r *resolutionRecorder) OnIncidentResolved(_ context.Context, inc store.Incident) error {
	r.calls = append(r.calls, inc)
	return nil
}

func TestResolvedRecurrenceNotifiesWhenItResolvesAgain(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	resolved := &resolutionRecorder{}
	c.SetResolutionNotifier(resolved)
	ctx := context.Background()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	original := firingAlert("fp-original", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", original.ReceivedAt, now.Add(-10*time.Minute), original)

	resolve := func(a store.Alert, at time.Time) store.Alert {
		t.Helper()
		a.Status = "resolved"
		a.ReceivedAt = at
		stored, err := st.UpsertAlertByFingerprint(ctx, a)
		if err != nil {
			t.Fatalf("upsert resolved %s: %v", a.Fingerprint, err)
		}
		if err := c.handleAlert(ctx, stored); err != nil {
			t.Fatalf("handle resolved %s: %v", a.Fingerprint, err)
		}
		return stored
	}

	resolve(original, now)
	if got := len(resolved.calls); got != 1 {
		t.Fatalf("resolution notifications after initial recovery = %d, want 1", got)
	}

	recurrence := original
	recurrence.ReceivedAt = now.Add(time.Minute)
	recurrence, err := st.UpsertAlertByFingerprint(ctx, recurrence)
	if err != nil {
		t.Fatalf("upsert recurrence: %v", err)
	}
	if err := c.handleAlert(ctx, recurrence); err != nil {
		t.Fatalf("handle recurrence: %v", err)
	}
	reopened, err := st.GetIncidentByID(ctx, "inc_1")
	if err != nil {
		t.Fatalf("get reopened incident: %v", err)
	}
	if reopened.Status != "analyzed" {
		t.Fatalf("incident status after recurrence = %q, want analyzed", reopened.Status)
	}

	resolve(recurrence, now.Add(2*time.Minute))
	if got := len(resolved.calls); got != 2 {
		t.Fatalf("resolution notifications after recurrence recovery = %d, want 2", got)
	}
	inc, err := st.GetIncidentByID(ctx, "inc_1")
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if inc.Status != "resolved" {
		t.Fatalf("incident status after recurrence recovery = %q, want resolved", inc.Status)
	}

	resolve(recurrence, now.Add(3*time.Minute))
	if got := len(resolved.calls); got != 2 {
		t.Fatalf("resolution notifications after duplicate resolved delivery = %d, want 2", got)
	}
}

func TestResolvedMemberRoutesBeforeNewerCollectingIncident(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	resolved := &resolutionRecorder{}
	c.SetResolutionNotifier(resolved)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	member := firingAlert("fp-older-member", "DiskFull", "warning", now.Add(-20*time.Minute), false)
	seedJudged(t, st, "inc_older", "analyzed", now.Add(-20*time.Minute), now.Add(-15*time.Minute), member)

	newerMember := firingAlert("fp-newer-member", "HighLatency", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_newer", "analyzed", now.Add(-5*time.Minute), now.Add(-4*time.Minute), newerMember)
	if _, err := st.DB().ExecContext(ctx, `UPDATE incidents SET status = 'collecting' WHERE id = 'inc_newer'`); err != nil {
		t.Fatalf("make newer incident collecting: %v", err)
	}

	member.Status = "resolved"
	member.ReceivedAt = now
	stored, err := st.UpsertAlertByFingerprint(ctx, member)
	if err != nil {
		t.Fatalf("upsert resolved member: %v", err)
	}
	if err := c.handleAlert(ctx, stored); err != nil {
		t.Fatalf("handle resolved member: %v", err)
	}

	older, err := st.GetIncidentByID(ctx, "inc_older")
	if err != nil {
		t.Fatalf("get older incident: %v", err)
	}
	if older.Status != "resolved" {
		t.Errorf("older incident status = %q, want resolved", older.Status)
	}
	newer, err := st.GetIncidentByID(ctx, "inc_newer")
	if err != nil {
		t.Fatalf("get newer incident: %v", err)
	}
	if newer.Status != "collecting" {
		t.Errorf("newer incident status = %q, want collecting", newer.Status)
	}
	if got := memberCount(t, st, "inc_newer"); got != 1 {
		t.Errorf("newer incident member count = %d, want 1", got)
	}
	if got := len(resolved.calls); got != 1 {
		t.Fatalf("resolution notifications = %d, want 1", got)
	}
	if got := resolved.calls[0].ID; got != "inc_older" {
		t.Errorf("resolved incident notification = %q, want inc_older", got)
	}
	if got := resolved.calls[0].Status; got != "resolved" {
		t.Errorf("resolution notification status = %q, want resolved", got)
	}
}

func TestResolvedAlertChecksEveryExistingMembership(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	resolved := &resolutionRecorder{}
	c.SetResolutionNotifier(resolved)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 13, 0, 0, 0, time.UTC)

	shared := firingAlert("fp-shared-member", "DiskFull", "warning", now.Add(-20*time.Minute), false)
	seedJudged(t, st, "inc_older", "analyzed", now.Add(-20*time.Minute), now.Add(-15*time.Minute), shared)
	seedJudged(t, st, "inc_newer", "analyzed", now.Add(-10*time.Minute), now.Add(-5*time.Minute), shared)
	stillFiring := firingAlert("fp-still-firing", "HighLatency", "warning", now.Add(-9*time.Minute), false)
	storedFiring, err := st.UpsertAlertByFingerprint(ctx, stillFiring)
	if err != nil {
		t.Fatalf("upsert firing member: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, "inc_newer", storedFiring.ID, storedFiring.ReceivedAt); err != nil {
		t.Fatalf("add firing member: %v", err)
	}

	shared.Status = "resolved"
	shared.ReceivedAt = now
	stored, err := st.UpsertAlertByFingerprint(ctx, shared)
	if err != nil {
		t.Fatalf("upsert resolved shared member: %v", err)
	}
	if err := c.handleAlert(ctx, stored); err != nil {
		t.Fatalf("handle resolved shared member: %v", err)
	}

	older, err := st.GetIncidentByID(ctx, "inc_older")
	if err != nil {
		t.Fatalf("get older incident: %v", err)
	}
	newer, err := st.GetIncidentByID(ctx, "inc_newer")
	if err != nil {
		t.Fatalf("get newer incident: %v", err)
	}
	if older.Status != "resolved" {
		t.Errorf("older incident status = %q, want resolved", older.Status)
	}
	if newer.Status != "analyzed" {
		t.Errorf("newer incident status = %q, want analyzed while another member fires", newer.Status)
	}
	if got := len(resolved.calls); got != 1 {
		t.Fatalf("resolution notifications = %d, want 1", got)
	}
	if got := resolved.calls[0].ID; got != "inc_older" {
		t.Errorf("resolved incident notification = %q, want inc_older", got)
	}
}

func TestOrphanResolvedAlertFallsBackToRecentGroupIncident(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	resolved := &resolutionRecorder{}
	c.SetResolutionNotifier(resolved)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)

	existing := firingAlert("fp-existing-resolved", "DiskFull", "warning", now.Add(-10*time.Minute), false)
	existing.Status = "resolved"
	seedJudged(t, st, "inc_existing", "analyzed", now.Add(-10*time.Minute), now.Add(-5*time.Minute), existing)

	orphan := firingAlert("fp-orphan-resolved", "HighLatency", "warning", now, false)
	orphan.Status = "resolved"
	stored, err := st.UpsertAlertByFingerprint(ctx, orphan)
	if err != nil {
		t.Fatalf("upsert orphan resolved alert: %v", err)
	}
	if err := c.handleAlert(ctx, stored); err != nil {
		t.Fatalf("handle orphan resolved alert: %v", err)
	}

	inc, err := st.GetIncidentByID(ctx, "inc_existing")
	if err != nil {
		t.Fatalf("get existing incident: %v", err)
	}
	if inc.Status != "resolved" {
		t.Errorf("existing incident status = %q, want resolved", inc.Status)
	}
	if got := memberCount(t, st, "inc_existing"); got != 2 {
		t.Errorf("existing incident member count = %d, want 2", got)
	}
	if got := len(resolved.calls); got != 1 {
		t.Fatalf("resolution notifications = %d, want 1", got)
	}
}
