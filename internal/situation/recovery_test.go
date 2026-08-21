// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func activeSituation(now time.Time) model.Situation {
	return model.Situation{
		ID: "s-recovery", GroupKey: "group-1", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
		InputVersion: 1, EffectiveStartedAt: now.Add(-time.Hour), EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt: now.Add(-time.Hour), LastLifecycleObservedAt: now,
		NextAssessmentAt: now, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
}

// TestRecoveryPendingRefireAndGrace mirrors the D4 lifecycle contract:
// active -> recovery_pending (grace stamped) -> active (refire clears
// grace) and, independently, recovery_pending -> recovered (clean grace
// expiry, terminal Attention observe).
func TestRecoveryPendingRefireAndGrace(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	pending := ObserveRecovery(s, now, 2*time.Minute)
	if pending.Lifecycle != model.LifecycleRecoveryPending {
		t.Fatalf("pending lifecycle = %q, want recovery_pending", pending.Lifecycle)
	}
	if pending.GraceUntil == nil || !pending.GraceUntil.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("pending grace_until = %+v, want %v", pending.GraceUntil, now.Add(2*time.Minute))
	}
	if pending.RecoveryObservedAt == nil || !pending.RecoveryObservedAt.Equal(now) {
		t.Fatalf("pending recovery_observed_at = %+v, want %v", pending.RecoveryObservedAt, now)
	}
	if pending.Attention != s.Attention {
		t.Fatalf("pending attention = %q, want preserved %q", pending.Attention, s.Attention)
	}

	active := ObserveRefire(pending, now.Add(time.Minute))
	if active.Lifecycle != model.LifecycleActive || active.GraceUntil != nil {
		t.Fatalf("active=%+v", active)
	}
	if active.RecoveryObservedAt != nil {
		t.Fatalf("refire must clear recovery_observed_at, got %+v", active.RecoveryObservedAt)
	}

	recovered := ExpireGrace(pending, now.Add(2*time.Minute))
	if recovered.Lifecycle != model.LifecycleRecovered || recovered.Attention != model.AttentionObserve {
		t.Fatalf("recovered=%+v", recovered)
	}
	if recovered.TerminalAt == nil || !recovered.TerminalAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("recovered terminal_at = %+v, want %v", recovered.TerminalAt, now.Add(2*time.Minute))
	}
	if recovered.GraceUntil != nil || recovered.RecoveryObservedAt != nil {
		t.Fatalf("recovered must clear grace fields, got %+v", recovered)
	}
}

// TestObserveRecoveryPreservesNonObserveAttentionAcrossRefire verifies D4's
// "preserves the prior Attention for audit and refire handling": entering
// recovery_pending from an Urgent (or Investigate) Situation keeps that
// exact Attention — not just Observe — and a later refire back to active
// still sees the preserved value, since neither ObserveRecovery nor
// ObserveRefire ever computes a fresh Attention; both only ever copy it
// forward from the pre-transition Situation.
func TestObserveRecoveryPreservesNonObserveAttentionAcrossRefire(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	for _, attention := range []model.Attention{model.AttentionUrgent, model.AttentionInvestigate} {
		s := activeSituation(now)
		s.Attention = attention

		pending := ObserveRecovery(s, now, 2*time.Minute)
		if pending.Attention != attention {
			t.Fatalf("[%s] pending attention = %q, want preserved %q", attention, pending.Attention, attention)
		}

		refired := ObserveRefire(pending, now.Add(time.Minute))
		if refired.Attention != attention {
			t.Fatalf("[%s] refired attention = %q, want preserved %q (refire handling sees the preserved attention)", attention, refired.Attention, attention)
		}
	}
}

// TestObserveRecoveryOnIllegalLifecycleIsNoop verifies the pure functions
// never mutate a Situation whose current lifecycle cannot legally take the
// requested event (terminal states never reopen).
func TestObserveRecoveryOnIllegalLifecycleIsNoop(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	s.Lifecycle = model.LifecycleRecovered
	if got := ObserveRecovery(s, now, time.Minute); got.Lifecycle != model.LifecycleRecovered {
		t.Fatalf("terminal recovered situation must not enter recovery_pending, got %+v", got)
	}
	if got := ExpireGrace(s, now); got.Lifecycle != model.LifecycleRecovered {
		t.Fatalf("terminal recovered situation must ignore grace expiry, got %+v", got)
	}
}

// TestFreshFiringCannotCloseUnknown verifies the terminal invariant that
// attempt/LLM budget exhaustion alone can never end a Situation while a
// fresh, authoritative firing state remains current — CloseUnknown refuses
// regardless of the cited reason.
func TestFreshFiringCannotCloseUnknown(t *testing.T) {
	s := activeSituation(mustTime(t, "2026-08-20T10:00:00Z"))
	s.LastLifecycleObservedAt = mustTime(t, "2026-08-20T10:30:00Z")
	_, err := CloseUnknown(s, model.TerminalReasonBudgetExhausted, mustTime(t, "2026-08-20T11:00:00Z"))
	if err == nil {
		t.Fatal("fresh firing closed_unknown")
	}
}

// TestCloseUnknownRequiresStructuredReason verifies the one-of-four closed
// reason catalog is enforced.
func TestCloseUnknownRequiresStructuredReason(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	s.LastLifecycleObservedAt = now.Add(-3 * 24 * time.Hour)
	if _, err := CloseUnknown(s, model.TerminalReason("not_a_real_reason"), now); err == nil {
		t.Fatal("unstructured terminal reason accepted")
	}
}

// TestCloseUnknownPastDeadlineSucceeds verifies a lifecycle observation old
// enough to have crossed every horizon's deadline is legally closeable, and
// stamps terminal_at/terminal_reason.
func TestCloseUnknownPastDeadlineSucceeds(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	s.LastLifecycleObservedAt = now.Add(-8 * 24 * time.Hour)
	out, err := CloseUnknown(s, model.TerminalReasonSourceUnavailable, now)
	if err != nil {
		t.Fatalf("CloseUnknown: %v", err)
	}
	if out.Lifecycle != model.LifecycleClosedUnknown {
		t.Fatalf("lifecycle = %q, want closed_unknown", out.Lifecycle)
	}
	if out.TerminalAt == nil || !out.TerminalAt.Equal(now) {
		t.Fatalf("terminal_at = %+v, want %v", out.TerminalAt, now)
	}
	if out.TerminalReason == nil || *out.TerminalReason != model.TerminalReasonSourceUnavailable {
		t.Fatalf("terminal_reason = %+v, want source_unavailable", out.TerminalReason)
	}
}

func TestLifecycleDeadlineByHorizonTier(t *testing.T) {
	cases := []struct {
		tier string
		want time.Duration
	}{
		{"minutes", 2 * time.Hour},
		{"hours", 24 * time.Hour},
		{"days", 7 * 24 * time.Hour},
		{"unknown", 24 * time.Hour},
		{"", 24 * time.Hour},
		{"bogus", 24 * time.Hour},
	}
	for _, tc := range cases {
		if got := LifecycleDeadline(tc.tier); got != tc.want {
			t.Errorf("LifecycleDeadline(%q) = %v, want %v", tc.tier, got, tc.want)
		}
	}
}

// TestWidenLifecycleDeadlineNeverShortens verifies an advisory profile tier
// may only extend the deterministic horizon, never shorten it.
func TestWidenLifecycleDeadlineNeverShortens(t *testing.T) {
	if got, want := WidenLifecycleDeadline("days", "minutes"), 7*24*time.Hour; got != want {
		t.Errorf("WidenLifecycleDeadline(days, minutes) = %v, want %v (never shortened)", got, want)
	}
	if got, want := WidenLifecycleDeadline("minutes", "days"), 7*24*time.Hour; got != want {
		t.Errorf("WidenLifecycleDeadline(minutes, days) = %v, want %v (widened)", got, want)
	}
	if got, want := WidenLifecycleDeadline("minutes"), 2*time.Hour; got != want {
		t.Errorf("WidenLifecycleDeadline(minutes) = %v, want %v (no profile tiers)", got, want)
	}
}

func TestRecoveryGraceWebhookAndPolling(t *testing.T) {
	cfg := RecoveryGraceConfig{WebhookSeconds: 120, PollingMinSeconds: 120, PollingMaxSeconds: 600}
	if got, want := cfg.RecoveryGrace(SourceGrace{Webhook: true}), 120*time.Second; got != want {
		t.Errorf("webhook grace = %v, want %v", got, want)
	}
	// 2x a 30s poll interval clamps up to the 120s floor.
	if got, want := cfg.RecoveryGrace(SourceGrace{PollIntervalSeconds: 30}), 120*time.Second; got != want {
		t.Errorf("polling grace (clamped low) = %v, want %v", got, want)
	}
	// 2x a 100s poll interval (200s) is within [120,600].
	if got, want := cfg.RecoveryGrace(SourceGrace{PollIntervalSeconds: 100}), 200*time.Second; got != want {
		t.Errorf("polling grace = %v, want %v", got, want)
	}
	// 2x a 1000s poll interval clamps down to the 600s ceiling.
	if got, want := cfg.RecoveryGrace(SourceGrace{PollIntervalSeconds: 1000}), 600*time.Second; got != want {
		t.Errorf("polling grace (clamped high) = %v, want %v", got, want)
	}
	// Multi-source uses the longest applicable grace.
	if got, want := cfg.RecoveryGrace(SourceGrace{Webhook: true}, SourceGrace{PollIntervalSeconds: 100}), 200*time.Second; got != want {
		t.Errorf("multi-source grace = %v, want longest %v", got, want)
	}
	if got, want := (RecoveryGraceConfig{}).RecoveryGrace(), 120*time.Second; got != want {
		t.Errorf("no-source default grace = %v, want webhook default %v", got, want)
	}
}

func TestSelectTerminalReasonPrefersPrecision(t *testing.T) {
	got, ok := SelectTerminalReason(model.TerminalReasonBudgetExhausted, model.TerminalReasonSourceUnavailable)
	if !ok || got != model.TerminalReasonSourceUnavailable {
		t.Fatalf("SelectTerminalReason = %v, %v, want source_unavailable", got, ok)
	}
	got, ok = SelectTerminalReason(model.TerminalReasonBudgetExhausted, model.TerminalReasonObservationDeadline)
	if !ok || got != model.TerminalReasonObservationDeadline {
		t.Fatalf("SelectTerminalReason = %v, %v, want observation_deadline over budget_exhausted", got, ok)
	}
	if _, ok := SelectTerminalReason(); ok {
		t.Fatal("SelectTerminalReason with no candidates must report false")
	}
}

func TestReconcileLifecycleGraceExpiry(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	pending := ObserveRecovery(s, now, time.Minute)
	outcome := ReconcileLifecycle(pending, nil, nil, now.Add(time.Minute), 2*time.Minute)
	if !outcome.Changed || !outcome.Decisive || outcome.Situation.Lifecycle != model.LifecycleRecovered {
		t.Fatalf("outcome = %+v, want terminal recovered", outcome)
	}
}

func TestReconcileLifecycleRefireBeforeGraceExpiry(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	pending := ObserveRecovery(s, now, 2*time.Minute)
	symptoms := []Symptom{{ID: "sym-1", Lifecycle: model.DeliveryStatusFiring}}
	outcome := ReconcileLifecycle(pending, symptoms, nil, now.Add(time.Minute), 2*time.Minute)
	if !outcome.Changed || outcome.Decisive || outcome.Situation.Lifecycle != model.LifecycleActive {
		t.Fatalf("outcome = %+v, want active refire", outcome)
	}
}

func TestReconcileLifecycleEntersRecoveryPendingWhenAllResolved(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	symptoms := []Symptom{{ID: "sym-1", Lifecycle: model.DeliveryStatusResolved}}
	outcome := ReconcileLifecycle(s, symptoms, nil, now, 2*time.Minute)
	if !outcome.Changed || !outcome.Decisive || outcome.Situation.Lifecycle != model.LifecycleRecoveryPending {
		t.Fatalf("outcome = %+v, want recovery_pending", outcome)
	}
	if outcome.Situation.GraceUntil == nil || !outcome.Situation.GraceUntil.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("outcome grace_until = %+v, want %v", outcome.Situation.GraceUntil, now.Add(2*time.Minute))
	}
}

func TestReconcileLifecycleStaysActiveWhileAnySymptomFires(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	symptoms := []Symptom{{ID: "sym-1", Lifecycle: model.DeliveryStatusFiring}, {ID: "sym-2", Lifecycle: model.DeliveryStatusResolved}}
	outcome := ReconcileLifecycle(s, symptoms, nil, now, 2*time.Minute)
	if outcome.Changed {
		t.Fatalf("outcome = %+v, want no transition while a symptom still fires", outcome)
	}
}

func TestReconcileLifecycleClosesUnknownFromTerminalUncertainty(t *testing.T) {
	now := mustTime(t, "2026-08-20T10:00:00Z")
	s := activeSituation(now)
	s.LastLifecycleObservedAt = now.Add(-8 * 24 * time.Hour)
	uncertainty := &TerminalUncertainty{DeadlineCrossed: true, Actionable: true, Reason: model.TerminalReasonSourceUnavailable}
	outcome := ReconcileLifecycle(s, nil, uncertainty, now, 2*time.Minute)
	if !outcome.Changed || !outcome.Decisive || outcome.Situation.Lifecycle != model.LifecycleClosedUnknown {
		t.Fatalf("outcome = %+v, want closed_unknown", outcome)
	}
}
