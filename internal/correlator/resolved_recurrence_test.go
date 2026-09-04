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
