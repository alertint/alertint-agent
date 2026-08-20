// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// attachAction is the outcome of evaluating a firing re-fire against an
// already-judged incident (spec flow F1).
type attachAction int

const (
	// actionNewIncident: outside the collapse horizon (or no candidate) — mint a
	// new incident and triage as usual.
	actionNewIncident attachAction = iota
	// actionRepeatTouch: an unchanged Alertmanager repeat — slide last_seen only,
	// no new episode, no count, no LLM.
	actionRepeatTouch
	// actionAttach: a new episode inside the horizon with no escalation — record
	// an occurrence and edit the card, no LLM.
	actionAttach
	// actionRejudge: a new episode that tripped an escalation trigger — record the
	// occurrence with its trigger and run a fresh re-judgment.
	actionRejudge
)

func (a attachAction) String() string {
	switch a {
	case actionNewIncident:
		return "new_incident"
	case actionRepeatTouch:
		return "repeat_touch"
	case actionAttach:
		return "attach"
	case actionRejudge:
		return "rejudge"
	default:
		return "unknown"
	}
}

// attachInputs are the pre-computed facts decideAttach needs. Everything the
// store or wall clock provides is resolved by the caller so the decision itself
// is a pure, table-testable function — the trigger matrix is the riskiest logic
// in M1.
type attachInputs struct {
	now                    time.Time
	lastJudgedAt           time.Time // Clock B baseline (caller applies the fallback when last_judged_at is unset)
	lastActivity           time.Time // Clock A anchor: latest occurrence last_seen, else incident last_alert_at
	occurrencesSinceJudged int       // occurrence rows since lastJudgedAt (the cap baseline)
	isNewEpisode           bool      // false = unchanged repeat (caller-computed from incident status + membership)
	incomingSeverityRank   int
	incomingAlertname      string
	baselineSeverityRank   int             // max severity rank across current members
	knownAlertnames        map[string]bool // alertnames across current members
	episodeTimes           []time.Time     // cross-incident episode series within the lookback, ascending
	attachWindow           time.Duration   // Clock A
	judgmentCeiling        time.Duration   // Clock B
	occurrenceCap          int
}

// attachDecision is decideAttach's verdict; trigger is the occurrence
// trigger_kind ("none" for a plain attach).
type attachDecision struct {
	action  attachAction
	trigger string

	// cadenceInterval / cadenceMedian carry the delta decideAttach's cadence
	// check already computed, so the impure half doesn't re-walk episodeTimes
	// and re-sort intervals a second time purely for display. Zero unless
	// trigger == "cadence".
	cadenceInterval time.Duration
	cadenceMedian   time.Duration
}

// decideAttach is the pure heart of F1. Order is load-bearing: repeat detection
// precedes the Clock A check; escalation triggers are evaluated inside the
// horizon before the no-LLM choice; Clock B is the last gate before a plain
// attach. Trigger priority is severity, new alertname, cadence, cap, then the
// ceiling.
func decideAttach(in attachInputs) attachDecision {
	// An unchanged repeat only slides last_seen — never mints, counts, or
	// escalates, even outside Clock A or past the ceiling.
	if !in.isNewEpisode {
		return attachDecision{action: actionRepeatTouch}
	}
	// Clock A: a new episode outside the sliding attach window escalates to a
	// fresh incident (which M2 will triage with recall).
	if in.now.Sub(in.lastActivity) > in.attachWindow {
		return attachDecision{action: actionNewIncident}
	}
	// Inside the horizon: escalation triggers, in priority order.
	if in.incomingSeverityRank > in.baselineSeverityRank {
		return attachDecision{action: actionRejudge, trigger: "severity"}
	}
	if in.incomingAlertname != "" && !in.knownAlertnames[in.incomingAlertname] {
		return attachDecision{action: actionRejudge, trigger: "new_alertname"}
	}
	if newInterval, median, ok := cadenceDelta(in.now, in.episodeTimes); ok {
		return attachDecision{action: actionRejudge, trigger: "cadence", cadenceInterval: newInterval, cadenceMedian: median}
	}
	if in.occurrencesSinceJudged+1 >= in.occurrenceCap {
		return attachDecision{action: actionRejudge, trigger: "cap"}
	}
	// Clock B: a steady flapper that keeps sliding Clock A cannot evade
	// re-examination past the ceiling.
	if in.now.Sub(in.lastJudgedAt) > in.judgmentCeiling {
		return attachDecision{action: actionRejudge, trigger: "ceiling"}
	}
	return attachDecision{action: actionAttach, trigger: "none"}
}

// cadenceDelta reports whether the cadence trigger fires — the newest
// inter-episode interval is below one-eighth of the key's trailing median over
// its last 20 intervals (R6): a slow key suddenly firing fast. ok is false
// (both durations zero) until >=3 historical intervals exist (cold start);
// severity, new-alertname, and the ceiling cover that regime. decideAttach
// calls this once and carries the (newInterval, median) it returns forward on
// attachDecision, so the impure half never needs to recompute it purely for
// display.
func cadenceDelta(now time.Time, episodeTimes []time.Time) (newInterval, median time.Duration, ok bool) {
	if len(episodeTimes) < 4 { // need >= 3 historical intervals
		return 0, 0, false
	}
	intervals := make([]time.Duration, 0, len(episodeTimes)-1)
	for i := 1; i < len(episodeTimes); i++ {
		intervals = append(intervals, episodeTimes[i].Sub(episodeTimes[i-1]))
	}
	if len(intervals) > 20 {
		intervals = intervals[len(intervals)-20:]
	}
	median = medianDuration(intervals)
	if median <= 0 {
		return 0, 0, false
	}
	newInterval = now.Sub(episodeTimes[len(episodeTimes)-1])
	return newInterval, median, newInterval*8 < median
}

// medianDuration returns the median of a duration slice (average of the two
// middle values for even counts). The input is copied before sorting so the
// caller's slice is untouched.
func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(ds))
	copy(cp, ds)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// maybeAttachOccurrence is the impure half of F1: it gathers the facts a firing
// re-fire needs, runs decideAttach, and executes the verdict. It returns
// (handled=true) when the alert was absorbed as a repeat/occurrence/re-judgment,
// or (handled=false) when the caller should open a new incident window. Every
// decision-phase store error is fail-safe: it degrades to a new incident (a
// triage that runs), never to silent collapse (a suppressed page).
func (c *Correlator) maybeAttachOccurrence(ctx context.Context, a store.Alert, gk string) (bool, error) {
	plan, ok := c.planDeliveryRecurrence(ctx, a, gk)
	if !ok {
		return false, nil
	}
	if plan.occurrence == nil {
		return true, c.st.TouchIncidentActivity(ctx, plan.incident.ID, a.ReceivedAt)
	}
	if plan.occurrence.ID > 0 {
		return true, c.st.TouchOccurrenceLastSeen(ctx, plan.occurrence.ID, plan.occurrence.LastSeen)
	}
	return true, c.attachOccurrence(ctx, a, plan.incident, gk, *plan.occurrence)
}

type deliveryRecurrencePlan struct {
	incident   store.Incident
	occurrence *store.Occurrence
}

// planDeliveryRecurrence gathers the durable facts for a recurrence decision.
// Missing ownership, a terminal owner, or any lookup failure takes the safe
// new-Incident path. ApplyCorrelatedDelivery repeats the owner check inside its
// transaction to close the decision/commit race.
func (c *Correlator) planDeliveryRecurrence(ctx context.Context, a store.Alert, gk string) (deliveryRecurrencePlan, bool) {
	now := a.ReceivedAt.UTC()
	candidate, err := c.st.GetRecentJudgedIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return deliveryRecurrencePlan{}, false
	}
	if err != nil {
		c.logger.Warn("correlator: judged-incident lookup failed; treating as new incident", "err", err, "group_key", gk)
		return deliveryRecurrencePlan{}, false
	}
	owner, err := c.st.SituationForIncident(ctx, candidate.ID)
	if err != nil {
		if err != store.ErrNotFound {
			c.logger.Warn("correlator: Situation-owner lookup failed; treating as new incident", "err", err, "incident_id", candidate.ID)
		}
		return deliveryRecurrencePlan{}, false
	}
	if owner.Lifecycle != model.LifecycleActive && owner.Lifecycle != model.LifecycleRecoveryPending {
		return deliveryRecurrencePlan{}, false
	}

	members, err := c.st.GetIncidentAlerts(ctx, candidate.ID)
	if err != nil {
		c.logger.Warn("correlator: member lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	baselineSev, _, known, isMember, candidateDrill := memberBaselines(members, a.Fingerprint)
	if store.IsDrillAlert(a) != candidateDrill {
		return deliveryRecurrencePlan{}, false
	}
	latestOcc, err := c.st.LatestOccurrence(ctx, candidate.ID)
	if err != nil && err != store.ErrNotFound {
		c.logger.Warn("correlator: latest-occurrence lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	if candidate.Status != "resolved" && isMember {
		if latestOcc == nil {
			return deliveryRecurrencePlan{incident: *candidate}, true
		}
		touch := *latestOcc
		touch.LastSeen = now
		return deliveryRecurrencePlan{incident: *candidate, occurrence: &touch}, true
	}

	lastActivity := candidate.LastAlertAt
	if latestOcc != nil {
		lastActivity = latestOcc.LastSeen
	}
	lastJudged := candidate.FirstAlertAt
	if candidate.LastJudgedAt != nil {
		lastJudged = *candidate.LastJudgedAt
	}
	occSince, err := c.st.CountOccurrencesSince(ctx, candidate.ID, lastJudged)
	if err != nil {
		c.logger.Warn("correlator: occurrence-count lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	episodeTimes, err := c.st.KeyEpisodeTimes(ctx, gk, now.Add(-c.cfg.Lookback))
	if err != nil {
		c.logger.Warn("correlator: episode-times lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	decision := decideAttach(attachInputs{
		now: now, lastJudgedAt: lastJudged, lastActivity: lastActivity,
		occurrencesSinceJudged: occSince, isNewEpisode: true,
		incomingSeverityRank: severity.Rank(a.Labels["severity"]), incomingAlertname: a.Labels["alertname"],
		baselineSeverityRank: baselineSev, knownAlertnames: known, episodeTimes: episodeTimes,
		attachWindow: c.cfg.AttachWindow, judgmentCeiling: c.cfg.JudgmentCeiling, occurrenceCap: c.cfg.OccurrenceCap,
	})
	if decision.action == actionNewIncident || decision.action == actionRepeatTouch {
		return deliveryRecurrencePlan{}, false
	}
	occ := recurrenceOccurrence(a, candidate.ID, decision.trigger)
	return deliveryRecurrencePlan{incident: *candidate, occurrence: &occ}, true
}

func recurrenceOccurrence(a store.Alert, incidentID, trigger string) store.Occurrence {
	return store.Occurrence{
		IncidentID: incidentID, OccurredAt: a.ReceivedAt.UTC(), LastSeen: a.ReceivedAt.UTC(),
		Fingerprints: []string{a.Fingerprint},
		Payload:      []store.OccurrenceMember{{Fingerprint: a.Fingerprint, Labels: a.Labels, Annotations: a.Annotations}},
		TriggerKind:  trigger,
	}
}

// memberBaselines derives, in one pass over an incident's current members: the
// max severity rank, the set of known alertnames, whether the incoming
// fingerprint is already a member, and whether the incident is a drill (any
// member carries the marker). Because a higher severity or a new alertname
// always trips a trigger on arrival (advancing last_judged_at), the max over
// current members equals the max as of the last judgment.
func memberBaselines(members []store.Alert, incomingFP string) (maxSev int, maxSevLabel string, known map[string]bool, isMember, isDrill bool) {
	known = make(map[string]bool, len(members))
	for _, m := range members {
		if r := severity.Rank(m.Labels["severity"]); r > maxSev {
			maxSev = r
			maxSevLabel = m.Labels["severity"]
		}
		if an := m.Labels["alertname"]; an != "" {
			known[an] = true
		}
		if m.Fingerprint == incomingFP {
			isMember = true
		}
		if store.IsDrillAlert(m) {
			isDrill = true
		}
	}
	return maxSev, maxSevLabel, known, isMember, isDrill
}

// attachOccurrence is retained only for legacy in-memory fixtures. Durable
// deliveries use ApplyCorrelatedDelivery, which emits a Situation input instead
// of calling notification or re-judgment code inline.
func (c *Correlator) attachOccurrence(ctx context.Context, a store.Alert, inc store.Incident, gk string, occ store.Occurrence) error {
	// One transaction: the occurrence row and its incident_alerts membership
	// commit together, so a partial failure can't leave an orphan occurrence a
	// redelivery would re-count. Mirroring the resolved branch, the alert joins
	// incident_alerts so the member list and alert_count grow and
	// checkAllAlertsResolved stays truthful (an actively-firing occurrence cannot
	// be marked resolved).
	if _, err := c.st.InsertOccurrenceAndAttach(ctx, occ, a.ID, a.ReceivedAt); err != nil {
		return fmt.Errorf("correlator: attach occurrence: %w", err)
	}

	if c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.occurrence_attached", map[string]any{
			"incident_id": inc.ID,
			"group_key":   gk,
			"trigger":     occ.TriggerKind,
		}); err != nil {
			c.logger.Warn("correlator: audit occurrence_attached failed", "err", err, "incident_id", inc.ID)
		}
	}

	stats := c.occurrenceStats(ctx, inc.ID)
	c.logger.Info("correlator: occurrence attached",
		"incident_id", inc.ID, "group_key", gk, "trigger", occ.TriggerKind, "occurrences", stats.Count)
	return nil
}

// occurrenceStats reads the derived occurrence summary for one incident,
// degrading to a zero value (logged) so a stats hiccup never blocks the attach.
func (c *Correlator) occurrenceStats(ctx context.Context, incidentID string) store.OccurrenceStats {
	m, err := c.st.OccurrenceStatsByIncident(ctx, []string{incidentID})
	if err != nil {
		c.logger.Warn("correlator: occurrence stats failed", "err", err, "incident_id", incidentID)
		return store.OccurrenceStats{}
	}
	return m[incidentID]
}

// pruneOldOccurrences deletes occurrence rows past the lookback horizon. It runs
// on the flush ticker (every pruneEvery ticks) — no separate background job.
func (c *Correlator) pruneOldOccurrences(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-c.cfg.Lookback)
	n, err := c.st.PruneOccurrences(ctx, cutoff, 0)
	if err != nil {
		c.logger.Warn("correlator: prune occurrences failed", "err", err)
		return
	}
	if n > 0 {
		c.logger.Info("correlator: pruned occurrences", "removed", n, "before", cutoff)
	}
}
