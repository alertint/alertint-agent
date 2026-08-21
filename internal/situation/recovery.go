// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Horizon tiers mirror internal/semanticprofile/model.Profile.HorizonTier's
// vocabulary ("unknown" | "minutes" | "hours" | "days") — the only source of
// advisory horizon information this package consumes.
const (
	HorizonMinutes = "minutes"
	HorizonHours   = "hours"
	HorizonDays    = "days"
	HorizonUnknown = "unknown"
)

// Default lifecycle observation deadlines (spec: "two hours for a short
// horizon, 24 hours for medium/unknown, and seven days for long").
const (
	shortLifecycleDeadline  = 2 * time.Hour
	mediumLifecycleDeadline = 24 * time.Hour
	longLifecycleDeadline   = 7 * 24 * time.Hour
)

// LifecycleDeadline returns the default maximum time since the last
// trustworthy lifecycle observation before lifecycle truth is considered
// unobservable, keyed by advisory horizon tier. Any tier other than
// "minutes"/"days" — including "hours", "unknown", and empty — falls into
// the medium bucket (spec: "24 hours for medium/unknown").
func LifecycleDeadline(horizonTier string) time.Duration {
	switch horizonTier {
	case HorizonMinutes:
		return shortLifecycleDeadline
	case HorizonDays:
		return longLifecycleDeadline
	default:
		return mediumLifecycleDeadline
	}
}

// WidenLifecycleDeadline combines a base horizon tier with zero or more
// advisory L0 profile tiers, returning the longest applicable deadline — an
// advisory profile may only extend the deterministic horizon, never
// shorten it.
func WidenLifecycleDeadline(baseTier string, profileTiers ...string) time.Duration {
	deadline := LifecycleDeadline(baseTier)
	for _, tier := range profileTiers {
		if d := LifecycleDeadline(tier); d > deadline {
			deadline = d
		}
	}
	return deadline
}

// minimumLifecycleFreshness is the floor CloseUnknown enforces regardless
// of horizon tier: a lifecycle observation newer than the shortest possible
// deadline can never be "unobservable past its source-aware deadline" for
// ANY tier, so attempt/LLM budget exhaustion alone can never terminate a
// Situation this fresh (spec: "Attempt or LLM budget exhaustion alone
// cannot make a Situation terminal while a fresh, authoritative firing
// state remains current"). A caller that has already resolved the exact
// tier-specific deadline (LifecycleDeadline/WidenLifecycleDeadline) is
// expected to confirm deadline crossing before ever calling CloseUnknown;
// this is the last-resort structural guard, not the primary check.
const minimumLifecycleFreshness = shortLifecycleDeadline

// terminalReasonPriority ranks the closed_unknown reason catalog: a precise
// source/missing-resolution finding always outranks generic deadline
// crossing, which in turn outranks generic budget exhaustion (spec:
// "choose the most precise source/missing-resolution reason before
// budget_exhausted").
var terminalReasonPriority = map[model.TerminalReason]int{
	model.TerminalReasonSourceUnavailable:   0,
	model.TerminalReasonResolutionMissing:   1,
	model.TerminalReasonObservationDeadline: 2,
	model.TerminalReasonBudgetExhausted:     3,
}

// SelectTerminalReason returns the most precise applicable reason among
// candidates that independently justify closed_unknown. Unrecognized
// candidates are ignored; ok is false when none of the candidates are valid.
func SelectTerminalReason(candidates ...model.TerminalReason) (model.TerminalReason, bool) {
	var best model.TerminalReason
	found := false
	bestRank := len(terminalReasonPriority)
	for _, candidate := range candidates {
		rank, valid := terminalReasonPriority[candidate]
		if !valid {
			continue
		}
		if !found || rank < bestRank {
			best, bestRank, found = candidate, rank, true
		}
	}
	return best, found
}

// RecoveryGraceConfig bounds source-specific recovery confirmation windows
// (spec defaults: webhook 120s; polling clamped to [120,600]s).
type RecoveryGraceConfig struct {
	WebhookSeconds    int
	PollingMinSeconds int
	PollingMaxSeconds int
}

func (c RecoveryGraceConfig) normalized() RecoveryGraceConfig {
	if c.WebhookSeconds <= 0 {
		c.WebhookSeconds = 120
	}
	if c.PollingMinSeconds <= 0 {
		c.PollingMinSeconds = 120
	}
	if c.PollingMaxSeconds <= 0 {
		c.PollingMaxSeconds = 600
	}
	return c
}

// SourceGrace is one delivery source's recovery-grace input: either
// webhook-delivered (fixed grace) or polling (grace derived from its
// configured interval).
type SourceGrace struct {
	Webhook             bool
	PollIntervalSeconds int
}

// RecoveryGrace returns the source-aware recovery confirmation window: a
// webhook source uses the fixed webhook grace; a polling source uses twice
// its configured interval clamped to [polling_min, polling_max]; a
// multi-source Situation uses the longest applicable grace. No sources
// given returns the webhook default (the safest — longest float-free —
// baseline when source delivery method is unknown).
func (c RecoveryGraceConfig) RecoveryGrace(sources ...SourceGrace) time.Duration {
	cfg := c.normalized()
	webhook := time.Duration(cfg.WebhookSeconds) * time.Second
	if len(sources) == 0 {
		return webhook
	}
	min := time.Duration(cfg.PollingMinSeconds) * time.Second
	max := time.Duration(cfg.PollingMaxSeconds) * time.Second
	var longest time.Duration
	for _, src := range sources {
		d := webhook
		if !src.Webhook {
			d = 2 * time.Duration(src.PollIntervalSeconds) * time.Second
			if d < min {
				d = min
			}
			if d > max {
				d = max
			}
		}
		if d > longest {
			longest = d
		}
	}
	return longest
}

// ObserveRecovery applies the active -> recovery_pending transition (D4):
// it preserves the prior Attention for audit and refire handling — the
// pending Slack contract, not Attention color, controls presentation — and
// stamps the recovery observation and grace deadline. A Situation whose
// current lifecycle cannot legally take this event is returned unchanged.
func ObserveRecovery(s model.Situation, now time.Time, grace time.Duration) model.Situation {
	next, err := AdvanceLifecycle(s.Lifecycle, EventRecoveryObserved)
	if err != nil {
		return s
	}
	observed := now.UTC()
	until := observed.Add(grace)
	out := s
	out.Lifecycle = next
	out.RecoveryObservedAt = &observed
	out.GraceUntil = &until
	out.LastLifecycleObservedAt = observed
	return out
}

// ObserveRefire applies the recovery_pending -> active refire (D4): it
// clears the recovery fields — "recovery did not hold" — and refreshes the
// lifecycle observation. The caller records the "recovery did not hold"
// transition reason and is expected to reassess current facts afterward
// (this function only advances lifecycle state). A Situation whose current
// lifecycle cannot legally take this event is returned unchanged.
func ObserveRefire(s model.Situation, now time.Time) model.Situation {
	next, err := AdvanceLifecycle(s.Lifecycle, EventRefired)
	if err != nil {
		return s
	}
	out := s
	out.Lifecycle = next
	out.RecoveryObservedAt = nil
	out.GraceUntil = nil
	out.LastLifecycleObservedAt = now.UTC()
	return out
}

// ExpireGrace applies clean grace expiry (D4): terminal `recovered` with
// terminal Attention `observe`, stopping automatic live probes/LLM work. A
// Situation whose current lifecycle cannot legally take this event is
// returned unchanged.
func ExpireGrace(s model.Situation, now time.Time) model.Situation {
	next, err := AdvanceLifecycle(s.Lifecycle, EventGraceExpired)
	if err != nil {
		return s
	}
	terminal := now.UTC()
	out := s
	out.Lifecycle = next
	out.Attention = model.AttentionObserve
	out.RecoveryObservedAt = nil
	out.GraceUntil = nil
	out.TerminalAt = &terminal
	return out
}

// CloseUnknown applies active|recovery_pending -> closed_unknown (D4) with
// the one required structured reason. It refuses when the last trustworthy
// lifecycle observation is still fresh: closed_unknown is legal only once
// lifecycle truth itself is unobservable past deadline, never merely
// because attempts/LLM budget were exhausted while firing truth remains
// current (spec). Callers that have already resolved the exact
// tier-specific deadline are expected to confirm crossing before calling
// this; the freshness check here is the structural last-resort guard.
func CloseUnknown(s model.Situation, reason model.TerminalReason, now time.Time) (model.Situation, error) {
	if !validTerminalUncertainty(reason) {
		return s, fmt.Errorf("situation: closed_unknown requires one structured terminal reason, got %q", reason)
	}
	if now.Sub(s.LastLifecycleObservedAt) < minimumLifecycleFreshness {
		return s, errors.New("situation: fresh lifecycle observation prevents closed_unknown")
	}
	next, err := AdvanceLifecycle(s.Lifecycle, EventLifecycleUnobservable)
	if err != nil {
		return s, fmt.Errorf("situation: closed_unknown: %w", err)
	}
	terminal := now.UTC()
	out := s
	out.Lifecycle = next
	out.TerminalAt = &terminal
	out.TerminalReason = &reason
	out.RecoveryObservedAt = nil
	out.GraceUntil = nil
	return out, nil
}

// LifecycleOutcome is the deterministic pre-L1/L2 lifecycle decision for one
// reconciliation pass.
type LifecycleOutcome struct {
	Situation model.Situation
	// Changed is true when a lifecycle transition applies this pass.
	Changed bool
	// Decisive is true when the outcome must be committed directly and the
	// pass must skip L1/L2 entirely (grace expiry, closed_unknown, and
	// entering recovery_pending are all controller-owned, model-free
	// commits). It does NOT mean the resulting Lifecycle is terminal —
	// recovery_pending is decisive and nonterminal, and only `recovered` and
	// `closed_unknown` are terminal. A refire (Changed=true, Decisive=false)
	// instead falls through to the ordinary L1/L2 path so current facts are
	// reassessed (D4: "returns to active and reassesses current facts").
	Decisive bool
	Event    Event
}

// ReconcileLifecycle applies deterministic D4 lifecycle transitions ahead
// of any L1/L2 work, in priority order: a closed_unknown candidate first
// (lifecycle truth unobservable past deadline — an externally resolved
// determination, since only the caller loading connector/observation state
// knows the exact source-aware deadline and reason), then clean grace
// expiry, then refire, then recovery entry. At most one transition applies
// per pass; Changed=false means the current lifecycle stands and the
// ordinary reconciliation flow continues unmodified.
func ReconcileLifecycle(s model.Situation, symptoms []Symptom, uncertainty *TerminalUncertainty, now time.Time, grace time.Duration) LifecycleOutcome {
	if uncertainty != nil && uncertainty.DeadlineCrossed && uncertainty.Actionable && validTerminalUncertainty(uncertainty.Reason) {
		if next, err := CloseUnknown(s, uncertainty.Reason, now); err == nil {
			return LifecycleOutcome{Situation: next, Changed: true, Decisive: true, Event: EventLifecycleUnobservable}
		}
	}
	switch s.Lifecycle {
	case model.LifecycleRecoveryPending:
		if hasFiringSymptom(symptoms) {
			return LifecycleOutcome{Situation: ObserveRefire(s, now), Changed: true, Decisive: false, Event: EventRefired}
		}
		if s.GraceUntil != nil && !now.Before(*s.GraceUntil) {
			return LifecycleOutcome{Situation: ExpireGrace(s, now), Changed: true, Decisive: true, Event: EventGraceExpired}
		}
	case model.LifecycleActive:
		if allSymptomsResolved(symptoms) {
			return LifecycleOutcome{Situation: ObserveRecovery(s, now, grace), Changed: true, Decisive: true, Event: EventRecoveryObserved}
		}
	}
	return LifecycleOutcome{Situation: s}
}

func hasFiringSymptom(symptoms []Symptom) bool {
	for _, sym := range symptoms {
		if sym.Lifecycle == model.DeliveryStatusFiring {
			return true
		}
	}
	return false
}

func allSymptomsResolved(symptoms []Symptom) bool {
	if len(symptoms) == 0 {
		return false
	}
	for _, sym := range symptoms {
		if sym.Lifecycle != model.DeliveryStatusResolved {
			return false
		}
	}
	return true
}
