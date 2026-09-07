// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Source lifecycle states — the closed three-value vocabulary a prepared
// source observation reports for one Alert/episode.
const (
	SourceStateFiring     = "firing"
	SourceStateResolved   = "resolved"
	SourceStateUnobserved = "unobserved"
)

// Recovery-grace hard bounds (spec.md "Recovery grace"): a polling lifecycle
// path's grace is twice its configured interval, clamped to [120,600]s.
const (
	minPollingGrace = 120 * time.Second
	maxPollingGrace = 600 * time.Second
)

// SourceObservation is one member Alert's prepared, source-proven lifecycle
// observation — the durable evidence ReduceSourceLifecycle folds across
// every expected member, replacing the prior Plan 2 time-basis-only
// inference with the real acquisition mode and interval a source
// connector actually observed (spec.md R13).
type SourceObservation struct {
	AlertID             string                `json:"alert_id"`
	EpisodeKey          string                `json:"episode_key"`
	Source              string                `json:"source"`
	State               string                `json:"state"` // firing | resolved | unobserved
	ObservedAt          time.Time             `json:"observed_at"`
	EventStartedAt      *time.Time            `json:"event_started_at,omitempty"`
	EventResolvedAt     *time.Time            `json:"event_resolved_at,omitempty"`
	TimeBasis           model.SourceTimeBasis `json:"time_basis,omitempty"`
	AcquisitionMode     string                `json:"acquisition_mode"` // webhook | poll
	PollIntervalSeconds int                   `json:"poll_interval_seconds,omitempty"`
	DeadlineAt          time.Time             `json:"deadline_at"`
	EvidenceRefs        []string              `json:"evidence_refs,omitempty"`
}

// SourceLifecycle is ReduceSourceLifecycle's pure fold result across every
// expected member Alert. AnyResolved tracks "at least one member's latest
// observation is resolved" independently of AllResolved — controller.go
// needs it (mirroring the local-only path's anyDeliveryResolved) to choose
// ClosedUnknownReason even on a MIXED member set that closes by deadline
// rather than by every member actually resolving.
type SourceLifecycle struct {
	AnyFiring      bool
	AnyResolved    bool
	AllResolved    bool
	ClosureDue     bool
	Grace          time.Duration
	NextDeadlineAt *time.Time
}

// ReduceSourceLifecycle folds observations (which may contain more than one
// entry per AlertID — e.g. an older API-sourced resolution alongside a
// newer webhook firing) across expectedAlertIDs into one SourceLifecycle.
// For each Alert it selects the latest authoritative observation (ties
// broken toward firing — spec.md: "On an ordering conflict prefer firing
// and record conflicting evidence"); a resolved observation older than a
// still-firing one can never recover that Alert (spec.md R7). Grace is the
// longest grace owed across every currently-resolved member (webhook: the
// fixed webhookGrace; polling: twice its own configured interval, clamped
// to [120,600]s). ClosureDue is true only once every non-firing,
// non-resolved (i.e. unobserved-or-missing) member has passed its own
// observation deadline and no member is firing — a single still-pending
// deadline, or any firing member, blocks it.
func ReduceSourceLifecycle(observations []SourceObservation, expectedAlertIDs []string, now time.Time, webhookGrace time.Duration) SourceLifecycle {
	latest := make(map[string]SourceObservation, len(expectedAlertIDs))
	for _, o := range observations {
		cur, ok := latest[o.AlertID]
		if !ok || preferObservation(o, cur) {
			latest[o.AlertID] = o
		}
	}

	if len(expectedAlertIDs) == 0 {
		return SourceLifecycle{}
	}

	anyFiring := false
	anyResolved := false
	allResolved := true
	allDeadlinePassed := true
	var nextDeadline *time.Time
	var maxGrace time.Duration

	for _, id := range expectedAlertIDs {
		obs, ok := latest[id]
		state := SourceStateUnobserved
		if ok {
			state = obs.State
		}

		switch state {
		case SourceStateFiring:
			anyFiring = true
			allResolved = false
			allDeadlinePassed = false
		case SourceStateResolved:
			anyResolved = true
			if g := graceFor(obs, webhookGrace); g > maxGrace {
				maxGrace = g
			}
		default: // unobserved, or no observation exists at all for this member
			allResolved = false
			deadline := obs.DeadlineAt
			switch {
			case deadline.IsZero():
				// No known deadline for a member with no observation at all:
				// never claim its silence has "passed" an unknowable horizon.
				allDeadlinePassed = false
			case now.Before(deadline):
				allDeadlinePassed = false
				if nextDeadline == nil || deadline.Before(*nextDeadline) {
					d := deadline
					nextDeadline = &d
				}
			}
		}
	}

	return SourceLifecycle{
		AnyFiring:      anyFiring,
		AnyResolved:    anyResolved,
		AllResolved:    allResolved,
		ClosureDue:     !anyFiring && !allResolved && allDeadlinePassed,
		Grace:          maxGrace,
		NextDeadlineAt: nextDeadline,
	}
}

// preferObservation reports whether candidate should replace current as the
// authoritative observation for one Alert: a strictly later ObservedAt
// always wins; an exact tie prefers firing (spec.md: "On an ordering
// conflict prefer firing").
func preferObservation(candidate, current SourceObservation) bool {
	if candidate.ObservedAt.After(current.ObservedAt) {
		return true
	}
	if candidate.ObservedAt.Equal(current.ObservedAt) && candidate.State == SourceStateFiring && current.State != SourceStateFiring {
		return true
	}
	return false
}

// expectedAlertIDs reduces deliveries to the deduplicated, deterministically
// sorted set of distinct expected member Alert IDs ReduceSourceLifecycle
// folds observations against — the same per-Alert identity
// incidentSymptomStatus already uses (Delivery.AlertID, falling back to
// "delivery:"+ID for a no-AlertID test fixture so it can never be
// superseded by an unrelated row).
func expectedAlertIDs(deliveries []Delivery) []string {
	seen := make(map[string]struct{}, len(deliveries))
	for _, d := range deliveries {
		alertKey := d.AlertID
		if alertKey == "" {
			alertKey = "delivery:" + d.ID
		}
		seen[alertKey] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// graceFor returns obs's own recovery grace: webhookGrace for a webhook (or
// any non-polling) acquisition mode, or twice obs's configured poll
// interval clamped to [120,600]s for a polling one.
func graceFor(obs SourceObservation, webhookGrace time.Duration) time.Duration {
	if obs.AcquisitionMode != "poll" {
		return webhookGrace
	}
	g := time.Duration(obs.PollIntervalSeconds) * time.Second * 2
	if g < minPollingGrace {
		g = minPollingGrace
	}
	if g > maxPollingGrace {
		g = maxPollingGrace
	}
	return g
}
