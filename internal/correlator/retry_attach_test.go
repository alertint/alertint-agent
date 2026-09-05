// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/store/storetest"
)

// seedTriagePhase inserts a "ready" Incident on gkAPI with one member alert
// (drill per memberDrill) and drives its triage row to phase through the real
// Task-1 store transitions — never raw SQL — so the matrix proves the store
// guards too. phase == "" leaves no triage row at all (the legacy shape).
func seedTriagePhase(t *testing.T, st *store.Store, phase store.TriagePhase, memberDrill bool) (incID string, member store.Alert) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	inc := store.Incident{
		ID:           uuid.NewString(),
		GroupKey:     gkAPI,
		FirstAlertAt: now.Add(-2 * time.Minute),
		LastAlertAt:  now.Add(-2 * time.Minute),
		ReadyAt:      now.Add(-time.Minute),
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	stored, err := st.UpsertAlertByFingerprint(ctx, firingAlert("fp-member-"+inc.ID, "DiskFull", "warning", now.Add(-2*time.Minute), memberDrill))
	if err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	member = stored
	if err := st.AddAlertToIncident(ctx, inc.ID, member.ID, member.ReceivedAt); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	if phase == "" {
		return inc.ID, member
	}
	if err := storetest.SeedIncidentTriage(ctx, st.DB(), inc.ID, now); err != nil {
		t.Fatalf("seed triage: %v", err)
	}
	if phase == store.TriagePending {
		return inc.ID, member
	}
	if _, err := st.BeginIncidentTriage(ctx, inc.ID, now); err != nil {
		t.Fatalf("begin triage: %v", err)
	}
	switch phase {
	case store.TriageInFlight:
		// leave as-is: processing/in_flight
	case store.TriageBackoff:
		if err := st.BackoffIncidentTriage(ctx, inc.ID, now.Add(2*time.Minute), "timeout", "deadline exceeded"); err != nil {
			t.Fatalf("backoff: %v", err)
		}
	case store.TriageSkipped:
		if err := st.SkipIncidentTriage(ctx, inc.ID); err != nil {
			t.Fatalf("skip: %v", err)
		}
	case store.TriageExhausted:
		if _, err := st.ExhaustIncidentTriage(ctx, inc.ID, "max_attempts", "exhausted"); err != nil {
			t.Fatalf("exhaust: %v", err)
		}
	case store.TriagePending:
		t.Fatalf("unreachable: pending is handled above")
	default:
		t.Fatalf("seedTriagePhase: unsupported phase %q", phase)
	}
	return inc.ID, member
}

// TestMaybeAttachRetryingIncident_Matrix covers R4/R8: only ready + backoff,
// non-exhausted, matching Drill parity is eligible for retry-aware
// attachment. Every other phase — and every terminal/in-flight status —
// follows the existing alternative path instead.
func TestMaybeAttachRetryingIncident_Matrix(t *testing.T) {
	tests := []struct {
		name          string
		phase         store.TriagePhase
		incomingDrill bool
		wantAttach    bool
	}{
		{"backoff real", store.TriageBackoff, false, true},
		{"pending", store.TriagePending, false, false},
		{"in flight", store.TriageInFlight, false, false},
		{"clean skip", store.TriageSkipped, false, false},
		{"exhausted", store.TriageExhausted, false, false},
		{"drill mismatch", store.TriageBackoff, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			c, td := newCorrelatorFor(t, st)
			ctx := context.Background()
			incID, _ := seedTriagePhase(t, st, tc.phase, false)
			before := memberCount(t, st, incID)

			incoming := firingAlert("fp-incoming-"+incID, "DiskFull", "warning", time.Now().UTC(), tc.incomingDrill)
			if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
				t.Fatalf("upsert incoming: %v", err)
			}

			handled, err := c.maybeAttachRetryingIncident(ctx, incoming, gkAPI)
			if err != nil {
				t.Fatalf("maybeAttachRetryingIncident: %v", err)
			}
			if handled != tc.wantAttach {
				t.Fatalf("handled = %v, want %v", handled, tc.wantAttach)
			}
			wantMembers := before
			if tc.wantAttach {
				wantMembers++
			}
			if got := memberCount(t, st, incID); got != wantMembers {
				t.Errorf("members = %d, want %d", got, wantMembers)
			}
			if occCount(t, st, incID) != 0 {
				t.Errorf("occurrences = %d, want 0 (never an Occurrence)", occCount(t, st, incID))
			}
			if td.notif.count() != 0 {
				t.Errorf("recurrence notifier called %d times, want 0", td.notif.count())
			}
		})
	}
}

// TestMaybeAttachRetryingIncident_PositiveAttachDetails proves R4-R6: a plain
// backoff attach adds membership only, never accelerates next_at, and the
// next dispatch would see the fresh member set.
func TestMaybeAttachRetryingIncident_PositiveAttachDetails(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	incID, _ := seedTriagePhase(t, st, store.TriageBackoff, false)

	_, triBefore, err := st.GetBackoffIncidentByGroupKey(ctx, gkAPI)
	if err != nil {
		t.Fatalf("lookup before: %v", err)
	}
	wantNext := triBefore.NextAt

	incoming := firingAlert("fp-incoming", "DiskFull", "warning", time.Now().UTC(), false)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert incoming: %v", err)
	}
	handled, err := c.maybeAttachRetryingIncident(ctx, incoming, gkAPI)
	if err != nil || !handled {
		t.Fatalf("attach = (%v, %v), want (true, nil)", handled, err)
	}

	if memberCount(t, st, incID) != 2 {
		t.Errorf("members = %d, want 2", memberCount(t, st, incID))
	}
	if occCount(t, st, incID) != 0 {
		t.Errorf("occurrences = %d, want 0", occCount(t, st, incID))
	}
	if td.notif.count() != 0 {
		t.Errorf("recurrence notifier called %d times, want 0 (retry-aware attach is not an occurrence)", td.notif.count())
	}
	attached := td.aud.rowsOfKind("incident.triage_member_attached")
	if len(attached) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(attached))
	}
	if got := attached[0].payload["member_count"]; got != 2 {
		t.Errorf("audit member_count = %v, want 2", got)
	}

	_, triAfter, err := st.GetBackoffIncidentByGroupKey(ctx, gkAPI)
	if err != nil {
		t.Fatalf("lookup after: %v", err)
	}
	if !triAfter.NextAt.Equal(wantNext) {
		t.Errorf("next_at = %v, want %v (unchanged — never accelerated)", triAfter.NextAt, wantNext)
	}

	members, err := st.GetIncidentAlerts(ctx, incID)
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	var found bool
	for _, m := range members {
		if m.Fingerprint == incoming.Fingerprint {
			found = true
		}
	}
	if !found {
		t.Errorf("next dispatch's member set = %+v, want to include the attached alert", members)
	}
}

// TestMaybeAttachRetryingIncident_SameFingerprintIsIdempotent: a
// same-fingerprint re-fire while the incident is backing off attaches
// without duplicating membership, and — since nothing new actually
// happened — without logging or auditing an attach.
func TestMaybeAttachRetryingIncident_SameFingerprintIsIdempotent(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	incID, member := seedTriagePhase(t, st, store.TriageBackoff, false)

	repeat := member
	repeat.Status = "firing"
	repeat.ReceivedAt = time.Now().UTC()
	stored, err := st.UpsertAlertByFingerprint(ctx, repeat)
	if err != nil {
		t.Fatalf("upsert repeat: %v", err)
	}

	handled, err := c.maybeAttachRetryingIncident(ctx, stored, gkAPI)
	if err != nil || !handled {
		t.Fatalf("attach = (%v, %v), want (true, nil)", handled, err)
	}
	if got := memberCount(t, st, incID); got != 1 {
		t.Errorf("members = %d, want 1 (same fingerprint, idempotent)", got)
	}
	if got := len(td.aud.rowsOfKind("incident.triage_member_attached")); got != 0 {
		t.Errorf("audit rows = %d, want 0 (no new membership, nothing to audit)", got)
	}
}

// TestMaybeAttachRetryingIncident_FailSafeOnLookupError mirrors
// TestMaybeAttach_FailSafeOnLookupError: any store error during the decision
// degrades to the new-incident path, never to a silent drop.
func TestMaybeAttachRetryingIncident_FailSafeOnLookupError(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	_, _ = seedTriagePhase(t, st, store.TriageBackoff, false)
	_ = st.Close() // force every subsequent read to error

	incoming := firingAlert("fp-new", "DiskFull", "warning", time.Now().UTC(), false)
	handled, err := c.maybeAttachRetryingIncident(context.Background(), incoming, gkAPI)
	if err != nil || handled {
		t.Fatalf("maybeAttachRetryingIncident on a store error = (%v, %v), want (false, nil) — fail-safe", handled, err)
	}
}

// TestMaybeAttachRetryingIncident_DrillParityBothDirections covers R4/ADR-0013:
// Drill parity blocks attachment in both directions — a drill re-fire never
// joins a real retrying incident, and a real re-fire never joins a Drill one.
func TestMaybeAttachRetryingIncident_DrillParityBothDirections(t *testing.T) {
	t.Run("drill incoming, real candidate", func(t *testing.T) {
		st := openStore(t)
		c, _ := newCorrelatorFor(t, st)
		incID, _ := seedTriagePhase(t, st, store.TriageBackoff, false)
		incoming := firingAlert("fp-drill", "DiskFull", "warning", time.Now().UTC(), true)
		if _, err := st.UpsertAlertByFingerprint(context.Background(), incoming); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		handled, err := c.maybeAttachRetryingIncident(context.Background(), incoming, gkAPI)
		if err != nil || handled {
			t.Fatalf("drill incoming vs real candidate = (%v, %v), want (false, nil)", handled, err)
		}
		if got := memberCount(t, st, incID); got != 1 {
			t.Errorf("members = %d, want 1 (no cross-drill attach)", got)
		}
	})

	t.Run("real incoming, drill candidate", func(t *testing.T) {
		st := openStore(t)
		c, _ := newCorrelatorFor(t, st)
		incID, _ := seedTriagePhase(t, st, store.TriageBackoff, true)
		incoming := firingAlert("fp-real", "DiskFull", "warning", time.Now().UTC(), false)
		if _, err := st.UpsertAlertByFingerprint(context.Background(), incoming); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		handled, err := c.maybeAttachRetryingIncident(context.Background(), incoming, gkAPI)
		if err != nil || handled {
			t.Fatalf("real incoming vs drill candidate = (%v, %v), want (false, nil)", handled, err)
		}
		if got := memberCount(t, st, incID); got != 1 {
			t.Errorf("members = %d, want 1 (no cross-drill attach)", got)
		}
	})
}

// TestHandleAlert_RetryAttachPrecedesRecurrenceCollapse proves the ordering
// in Task 4 Step 4: retry-aware attach is decided before recurrence collapse
// and before minting a new Incident. A firing re-fire during backoff joins
// the retrying Incident even when an older, already-judged Incident on the
// same key would otherwise be a recurrence-collapse candidate.
func TestHandleAlert_RetryAttachPrecedesRecurrenceCollapse(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Now().UTC()

	judgedMember := firingAlert("fp-judged", "DiskFull", "warning", now.Add(-time.Hour), false)
	seedJudged(t, st, "inc_judged", "analyzed", now.Add(-time.Hour), now.Add(-time.Hour), judgedMember)

	retryID, _ := seedTriagePhase(t, st, store.TriageBackoff, false)

	incoming := firingAlert("fp-new", "DiskFull", "warning", now, false)
	stored, err := st.UpsertAlertByFingerprint(ctx, incoming)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := c.handleAlert(ctx, stored); err != nil {
		t.Fatalf("handleAlert: %v", err)
	}

	if got := memberCount(t, st, retryID); got != 2 {
		t.Errorf("retrying incident members = %d, want 2 (attached)", got)
	}
	if got := occCount(t, st, "inc_judged"); got != 0 {
		t.Errorf("judged incident occurrences = %d, want 0 (retry attach wins)", got)
	}
	if td.notif.count() != 0 {
		t.Errorf("recurrence notifier called %d times, want 0", td.notif.count())
	}
}
