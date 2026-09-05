// SPDX-License-Identifier: FSL-1.1-ALv2

// Package situation implements deterministic Situation lifecycle and
// scheduling rules. It performs no outbound or operated-system writes.
package situation

import (
	"errors"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Event is a controller-owned lifecycle observation.
type Event string

const (
	EventRecoveryObserved      Event = "recovery_observed"
	EventRefired               Event = "refired"
	EventGraceExpired          Event = "grace_expired"
	EventLifecycleUnobservable Event = "lifecycle_unobservable"
)

// AdvanceLifecycle applies one legal lifecycle event. Terminal lifecycles
// (recovered, closed_unknown) never reopen: every event against them returns
// the original state plus an error.
func AdvanceLifecycle(from model.Lifecycle, event Event) (model.Lifecycle, error) {
	switch from {
	case model.LifecycleActive:
		switch event {
		case EventRecoveryObserved:
			return model.LifecycleRecoveryPending, nil
		case EventLifecycleUnobservable:
			return model.LifecycleClosedUnknown, nil
		case EventRefired:
			return model.LifecycleActive, nil
		case EventGraceExpired:
			// No grace runs while active.
		}
	case model.LifecycleRecoveryPending:
		switch event {
		case EventRefired:
			return model.LifecycleActive, nil
		case EventGraceExpired:
			return model.LifecycleRecovered, nil
		case EventLifecycleUnobservable:
			return model.LifecycleClosedUnknown, nil
		case EventRecoveryObserved:
			return model.LifecycleRecoveryPending, nil
		}
	case model.LifecycleRecovered, model.LifecycleClosedUnknown:
		// Terminal: no event advances a terminal lifecycle.
	}
	return from, errors.New("situation: invalid lifecycle transition")
}

// ----------------------------------------------------------------------
// Task 8: source-aware timing derivation — the grace period a recovery-
// pending Situation waits before clean grace expiry, and the lifecycle-
// observation deadline that (absent a fresh authoritative firing symptom)
// eventually reaches closed_unknown. Both are pure functions of durable
// local state Reconcile already has in hand (a Snapshot's Symptoms/
// DurationClass, a SnapshotInput's Deliveries) — no I/O, no clock read
// beyond the explicit times/durations callers already computed elsewhere
// (elapsedDuration, BuildSnapshot).
// ----------------------------------------------------------------------

const (
	// pollingRecoveryGraceFloor and pollingRecoveryGraceCeiling bound a
	// polling-provenance source's own "twice its interval" grace formula —
	// the brief's fixed [120s,600s] clamp.
	pollingRecoveryGraceFloor   = 120 * time.Second
	pollingRecoveryGraceCeiling = 600 * time.Second

	// observationDeadlineShort, observationDeadlineMedium, and
	// observationDeadlineLong are the brief's fixed versioned lifecycle-
	// observation-deadline lengths, keyed by DurationClass.
	observationDeadlineShort  = 2 * time.Hour
	observationDeadlineMedium = 24 * time.Hour
	observationDeadlineLong   = 7 * 24 * time.Hour
)

// basisGrace derives ONE delivery basis's own candidate recovery-grace
// duration: webhookGrace for a webhook-provenance basis (source_payload) or
// the receipt_fallback basis a delivery-less/reconstructed input carries
// when no more precise provenance exists (the tightest, most-informed grace
// this build ever has, so it is treated the same as webhook rather than
// defaulting to the wider polling range); twice pollIntervalSeconds, clamped
// to [pollingRecoveryGraceFloor,pollingRecoveryGraceCeiling], for a polling-
// provenance basis (source_api). An unrecognized/mixed/missing basis falls
// back to webhookGrace defensively — model.SourceTimeBasis is a closed enum,
// but this function must still be total.
func basisGrace(basis model.SourceTimeBasis, webhookGrace time.Duration, pollIntervalSeconds int) time.Duration {
	if basis != model.SourceTimeBasisSourceAPI {
		return webhookGrace
	}
	g := 2 * time.Duration(pollIntervalSeconds) * time.Second
	switch {
	case g < pollingRecoveryGraceFloor:
		return pollingRecoveryGraceFloor
	case g > pollingRecoveryGraceCeiling:
		return pollingRecoveryGraceCeiling
	default:
		return g
	}
}

// RecoveryGraceDuration derives the source-aware recovery-grace duration —
// how long a recovery-pending Situation waits, after its last recovery
// observation, before clean grace expiry reaches "recovered" (spec.md
// "Lifecycle, Attention, and cadence": "clean grace expiry reaches
// recovered") — from the StartedAtBasis of every one of deliveries' own
// member Deliveries. webhookGrace configures the grace for a webhook (or
// receipt_fallback) basis; pollIntervalSeconds is the assumed poll interval
// for any source_api-basis delivery ("polling grace twice its interval
// clamped to 120-600 seconds"). "multi-source uses the longest" (spec.md):
// when deliveries carries more than one basis, the longest of their
// individual candidate graces wins — deliveries is scanned by its own
// per-delivery StartedAtBasis, never the Situation-level aggregate
// EffectiveStartedAtBasis (which collapses a genuine multi-basis Situation
// to "mixed", losing exactly the per-source distinction this formula needs).
// An empty deliveries slice defensively returns webhookGrace.
//
// No connector in this build ever writes a source_api-basis delivery — the
// only production ingress (internal/ingress/alert_receiver.go, the
// Alertmanager webhook) always writes source_payload — and no config
// surface in this build carries a real per-source poll interval yet
// (config.SituationsConfig has none; Task 8 is not authorized to add one).
// The polling branch is therefore fully implemented and unit-tested here,
// exactly like reasons.go's own not-yet-reachable predicates
// (novelSymptomEligible, terminalUncertaintyEligible), but provably
// unreachable from live Reconcile data until a later plan threads a real
// polling connector and its interval through to ControllerConfig.
func RecoveryGraceDuration(deliveries []Delivery, webhookGrace time.Duration, pollIntervalSeconds int) time.Duration {
	longest := webhookGrace
	for i, d := range deliveries {
		g := basisGrace(d.StartedAtBasis, webhookGrace, pollIntervalSeconds)
		if i == 0 || g > longest {
			longest = g
		}
	}
	return longest
}

// RecoveryGraceUntil is recoveryObservedAt plus
// RecoveryGraceDuration(deliveries, webhookGrace, pollIntervalSeconds) — the
// Situation.GraceUntil value a fresh EventRecoveryObserved transition
// stamps.
func RecoveryGraceUntil(recoveryObservedAt time.Time, deliveries []Delivery, webhookGrace time.Duration, pollIntervalSeconds int) time.Time {
	return recoveryObservedAt.Add(RecoveryGraceDuration(deliveries, webhookGrace, pollIntervalSeconds))
}

// ObservationDeadlineDuration derives the versioned lifecycle-observation-
// deadline LENGTH from durationClass (Snapshot.DurationClass): 2 hours for
// subminute or short, 24 hours for medium or any unrecognized class value,
// and 7 days for long (the brief's fixed table). durationClass is a
// closed-shape string produced only by DurationClass, but this function must
// still be total against any input.
func ObservationDeadlineDuration(durationClass string) time.Duration {
	switch durationClass {
	case DurationClassSubminute, DurationClassShort:
		return observationDeadlineShort
	case DurationClassLong:
		return observationDeadlineLong
	default: // DurationClassMedium, or any unrecognized value ("... or unknown").
		return observationDeadlineMedium
	}
}

// ObservationDeadlineAt is effectiveStartedAt plus
// ObservationDeadlineDuration(durationClass) — anchored at
// EffectiveStartedAt and recomputed from durationClass exactly the way
// facts.go's own current_duration fact anchors its threshold_crossed_at
// (durationClassLowerBound): the deadline widens automatically as a
// long-running Situation's duration class advances, rather than needing a
// second tracked field a controller cycle must separately maintain.
func ObservationDeadlineAt(effectiveStartedAt time.Time, durationClass string) time.Time {
	return effectiveStartedAt.Add(ObservationDeadlineDuration(durationClass))
}

// ClosedUnknownReason derives which of Plan 2's two reachable closed_unknown
// terminal reasons applies once the lifecycle-observation deadline has
// passed with no fresh authoritative firing symptom (AnyFiring must already
// have been checked false by the caller — this function does not itself
// consult symptom state): resolution_missing when the source contract is
// known/precise — source_payload or source_api, a genuinely observed
// provenance, per spec.md "resolution_missing is used when a source
// contract expects an explicit resolved observation" — and no delivery for
// this Situation has ever carried an explicit resolved status;
// observation_deadline otherwise, spec.md's documented fallback ("the
// fallback when reconstructed or incomplete provenance proves no more
// precise cause") for receipt_fallback, mixed, or missing basis, and
// defensively also for a precise-provenance Situation that DID see an
// explicit resolved observation (a case AdvanceLifecycle's ordinary
// recovery path should already have resolved before a deadline check ever
// runs). The reserved codes source_unavailable and budget_exhausted
// (spec.md: "remain reserved but unreachable until an owning stage supplies
// authoritative source-health or lifecycle-observation-budget facts") are
// never returned by this function — see
// TestReservedTerminalReasonsHaveNoPlan2Producer.
func ClosedUnknownReason(basis model.SourceTimeBasis, anyDeliveryResolved bool) model.TerminalReason {
	preciseProvenance := basis == model.SourceTimeBasisSourcePayload || basis == model.SourceTimeBasisSourceAPI
	if preciseProvenance && !anyDeliveryResolved {
		return model.TerminalReasonResolutionMissing
	}
	return model.TerminalReasonObservationDeadline
}

// AnyFiring reports whether at least one of symptoms is currently firing —
// spec.md: "Fresh authoritative firing truth always prevents terminal
// closure." Reconcile must never transition a Situation to closed_unknown
// while this is true, regardless of how overdue its observation deadline
// is, and must never let LLM/Assessment/Triage exhaustion close a Situation
// either — this function's own signature (Symptoms only, no L2/Triage
// state) makes the latter structurally impossible to consult here.
func AnyFiring(symptoms []Symptom) bool {
	for _, s := range symptoms {
		if s.Status == model.DeliveryStatusFiring {
			return true
		}
	}
	return false
}
