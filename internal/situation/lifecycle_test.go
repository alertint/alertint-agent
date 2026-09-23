// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestAdvanceLifecycleLegalTransitions(t *testing.T) {
	tests := []struct {
		from  model.Lifecycle
		event Event
		want  model.Lifecycle
	}{
		{model.LifecycleActive, EventRecoveryObserved, model.LifecycleRecoveryPending},
		{model.LifecycleActive, EventRefired, model.LifecycleActive},
		{model.LifecycleActive, EventLifecycleUnobservable, model.LifecycleClosedUnknown},
		{model.LifecycleRecoveryPending, EventRefired, model.LifecycleActive},
		{model.LifecycleRecoveryPending, EventGraceExpired, model.LifecycleRecovered},
		{model.LifecycleRecoveryPending, EventLifecycleUnobservable, model.LifecycleClosedUnknown},
	}
	for _, tt := range tests {
		got, err := AdvanceLifecycle(tt.from, tt.event)
		if err != nil || got != tt.want {
			t.Fatalf("AdvanceLifecycle(%q, %q) = %q, %v; want %q", tt.from, tt.event, got, err, tt.want)
		}
	}
}

func TestTerminalLifecycleNeverReopens(t *testing.T) {
	for _, from := range []model.Lifecycle{model.LifecycleRecovered, model.LifecycleClosedUnknown} {
		for _, event := range []Event{EventRecoveryObserved, EventRefired, EventGraceExpired, EventLifecycleUnobservable} {
			got, err := AdvanceLifecycle(from, event)
			if err == nil || got != from {
				t.Fatalf("terminal transition %q + %q = %q, %v", from, event, got, err)
			}
		}
	}
}

// ----------------------------------------------------------------------
// Task 8: source-aware recovery-grace and lifecycle-observation-deadline
// timing derivation.
// ----------------------------------------------------------------------

func TestRecoveryGraceDurationWebhookUsesConfiguredGrace(t *testing.T) {
	deliveries := []Delivery{{StartedAtBasis: model.SourceTimeBasisSourcePayload}}
	got := RecoveryGraceDuration(deliveries, 120*time.Second, 0)
	if got != 120*time.Second {
		t.Fatalf("webhook grace = %v, want 120s", got)
	}
}

func TestRecoveryGraceDurationReceiptFallbackUsesWebhookGrace(t *testing.T) {
	// A delivery-less/reconstructed input carries receipt_fallback when no
	// more precise provenance exists — treated the same as webhook, the
	// tightest, most-informed grace this build ever has.
	deliveries := []Delivery{{StartedAtBasis: model.SourceTimeBasisReceiptFallback}}
	got := RecoveryGraceDuration(deliveries, 120*time.Second, 0)
	if got != 120*time.Second {
		t.Fatalf("receipt_fallback grace = %v, want 120s", got)
	}
}

func TestRecoveryGraceDurationPollingIsTwiceIntervalClamped(t *testing.T) {
	deliveries := []Delivery{{StartedAtBasis: model.SourceTimeBasisSourceAPI}}

	if got := RecoveryGraceDuration(deliveries, 120*time.Second, 30); got != 120*time.Second {
		t.Fatalf("polling grace (interval=30s, floor) = %v, want 120s", got)
	}
	if got := RecoveryGraceDuration(deliveries, 120*time.Second, 200); got != 400*time.Second {
		t.Fatalf("polling grace (interval=200s) = %v, want 400s", got)
	}
	if got := RecoveryGraceDuration(deliveries, 120*time.Second, 1000); got != 600*time.Second {
		t.Fatalf("polling grace (interval=1000s, ceiling) = %v, want 600s", got)
	}
}

func TestRecoveryGraceDurationMultiSourceUsesLongest(t *testing.T) {
	deliveries := []Delivery{
		{StartedAtBasis: model.SourceTimeBasisSourcePayload},
		{StartedAtBasis: model.SourceTimeBasisSourceAPI},
	}
	// Webhook candidate is 120s; polling candidate (interval=200s) is 400s —
	// the longer one must win regardless of slice order.
	got := RecoveryGraceDuration(deliveries, 120*time.Second, 200)
	if got != 400*time.Second {
		t.Fatalf("multi-source grace = %v, want the longest candidate (400s)", got)
	}
}

func TestRecoveryGraceDurationNoDeliveriesFallsBackToWebhookGrace(t *testing.T) {
	got := RecoveryGraceDuration(nil, 120*time.Second, 0)
	if got != 120*time.Second {
		t.Fatalf("no-delivery grace = %v, want the webhook default (120s)", got)
	}
}

func TestObservationDeadlineDurationByClass(t *testing.T) {
	cases := []struct {
		class string
		want  time.Duration
	}{
		{DurationClassSubminute, 2 * time.Hour},
		{DurationClassShort, 2 * time.Hour},
		{DurationClassMedium, 24 * time.Hour},
		{DurationClassLong, 7 * 24 * time.Hour},
		{"unknown-class", 24 * time.Hour},
	}
	for _, tt := range cases {
		if got := ObservationDeadlineDuration(tt.class); got != tt.want {
			t.Fatalf("ObservationDeadlineDuration(%q) = %v, want %v", tt.class, got, tt.want)
		}
	}
}

func TestObservationDeadlineAtAnchorsOnEffectiveStartedAt(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := ObservationDeadlineAt(start, DurationClassMedium)
	want := start.Add(24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("ObservationDeadlineAt = %v, want %v", got, want)
	}
}

func TestClosedUnknownReasonPreciseProvenanceWithNoResolutionIsResolutionMissing(t *testing.T) {
	got := ClosedUnknownReason(model.SourceTimeBasisSourcePayload, false)
	if got != model.TerminalReasonResolutionMissing {
		t.Fatalf("ClosedUnknownReason(source_payload, unresolved) = %q, want %q", got, model.TerminalReasonResolutionMissing)
	}
	got = ClosedUnknownReason(model.SourceTimeBasisSourceAPI, false)
	if got != model.TerminalReasonResolutionMissing {
		t.Fatalf("ClosedUnknownReason(source_api, unresolved) = %q, want %q", got, model.TerminalReasonResolutionMissing)
	}
}

func TestClosedUnknownReasonIncompleteProvenanceIsObservationDeadline(t *testing.T) {
	for _, basis := range []model.SourceTimeBasis{
		model.SourceTimeBasisReceiptFallback, model.SourceTimeBasisMixed, model.SourceTimeBasisMissing, "",
	} {
		if got := ClosedUnknownReason(basis, false); got != model.TerminalReasonObservationDeadline {
			t.Fatalf("ClosedUnknownReason(%q, unresolved) = %q, want %q", basis, got, model.TerminalReasonObservationDeadline)
		}
	}
}

func TestClosedUnknownReasonPreciseProvenanceWithResolutionIsObservationDeadline(t *testing.T) {
	// A precise-provenance source that DID see an explicit resolved
	// observation has no missing-resolution story to tell; the fallback
	// applies (defensive only — AdvanceLifecycle should already have
	// reached a terminal state via the ordinary recovery path in this case).
	got := ClosedUnknownReason(model.SourceTimeBasisSourcePayload, true)
	if got != model.TerminalReasonObservationDeadline {
		t.Fatalf("ClosedUnknownReason(source_payload, resolved) = %q, want %q", got, model.TerminalReasonObservationDeadline)
	}
}

func TestAnyFiringDetectsAtLeastOneFiringSymptom(t *testing.T) {
	if AnyFiring(nil) {
		t.Fatal("AnyFiring(nil) = true, want false")
	}
	if AnyFiring([]Symptom{{Status: model.DeliveryStatusResolved}}) {
		t.Fatal("all-resolved symptoms must not report firing")
	}
	if !AnyFiring([]Symptom{{Status: model.DeliveryStatusResolved}, {Status: model.DeliveryStatusFiring}}) {
		t.Fatal("one firing symptom among several must report firing")
	}
}

func TestReservedTerminalReasonsHaveNoPlan2Producer(t *testing.T) {
	// ClosedUnknownReason's only two return values are resolution_missing
	// and observation_deadline (exhaustively proven by the branch tests
	// above); source_unavailable and budget_exhausted are declared in
	// model.TerminalReason but no function in this package can ever produce
	// them — this test documents that invariant at the type level.
	reserved := map[model.TerminalReason]bool{
		model.TerminalReasonSourceUnavailable: true,
		model.TerminalReasonBudgetExhausted:   true,
	}
	for _, basis := range []model.SourceTimeBasis{
		model.SourceTimeBasisSourcePayload, model.SourceTimeBasisSourceAPI,
		model.SourceTimeBasisReceiptFallback, model.SourceTimeBasisMixed, model.SourceTimeBasisMissing,
	} {
		for _, resolved := range []bool{true, false} {
			if reserved[ClosedUnknownReason(basis, resolved)] {
				t.Fatalf("ClosedUnknownReason(%q, %v) produced a reserved terminal reason", basis, resolved)
			}
		}
	}
}
