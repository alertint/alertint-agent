// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/severity"
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

// recurrenceDelta carries the display-only "why" facts from the impure decision
// half (maybeAttachOccurrence) to attachOccurrence, which stamps them onto the
// notify.RecurrenceEvent after reading fresh occurrence stats.
type recurrenceDelta struct {
	priorSeverity string
	newSeverity   string
	newAlertname  string
	newInterval   time.Duration
	priorMedian   time.Duration
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
	now := a.ReceivedAt

	candidate, err := c.st.GetRecentJudgedIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return false, nil
	}
	if err != nil {
		c.logger.Warn("correlator: judged-incident lookup failed; treating as new incident", "err", err, "group_key", gk)
		return false, nil
	}

	// Load members once: they carry the trigger baselines, membership, and the
	// candidate's drill-ness — no separate IncidentDrillFlags query needed.
	members, err := c.st.GetIncidentAlerts(ctx, candidate.ID)
	if err != nil {
		c.logger.Warn("correlator: member lookup failed; treating as new incident", "err", err)
		return false, nil
	}
	baselineSev, baselineSevLabel, known, isMember, candidateDrill := memberBaselines(members, a.Fingerprint)

	// Drill parity: a drill re-fire never attaches to a real incident, or vice
	// versa (salted drill keys make this near-impossible; the check makes it so).
	if store.IsDrillAlert(a) != candidateDrill {
		return false, nil
	}

	latestOcc, err := c.st.LatestOccurrence(ctx, candidate.ID)
	if err != nil && err != store.ErrNotFound {
		c.logger.Warn("correlator: latest-occurrence lookup failed; treating as new incident", "err", err)
		return false, nil
	}

	// A new episode is a genuine re-fire: the condition recovered and returned
	// (the candidate fully resolved), or an alert identity new to the incident
	// joined (rotated fingerprint / new alertname). Otherwise it is an unchanged
	// repeat of an already-firing member. Ingress upserts the alert before the
	// correlator sees it, so the alert row's prior status is gone; the incident
	// status and membership are the durable signals. Bounded gap: a single member
	// of a multi-alert incident that individually resolves and re-fires under the
	// same fingerprint reads as a repeat and is not re-examined until the whole
	// incident resolves (Clock B only fires on a NEW episode, so it does not
	// cover this member-local case). Severity changes alter the fingerprint, so
	// a severity escalation is unaffected.
	isNewEpisode := candidate.Status == "resolved" || !isMember

	// An unchanged repeat only slides last_seen — short-circuit before the
	// cross-incident count/cadence reads, which the common repeat path never
	// needs. Clock B is checked only for new episodes, so a repeat never mints.
	if !isNewEpisode {
		if latestOcc != nil {
			return true, c.st.TouchOccurrenceLastSeen(ctx, latestOcc.ID, now)
		}
		return true, c.st.TouchIncidentActivity(ctx, candidate.ID, now)
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
		return false, nil
	}
	episodeTimes, err := c.st.KeyEpisodeTimes(ctx, gk, now.Add(-c.cfg.Lookback))
	if err != nil {
		c.logger.Warn("correlator: episode-times lookup failed; treating as new incident", "err", err)
		return false, nil
	}

	decision := decideAttach(attachInputs{
		now:                    now,
		lastJudgedAt:           lastJudged,
		lastActivity:           lastActivity,
		occurrencesSinceJudged: occSince,
		isNewEpisode:           true,
		incomingSeverityRank:   severity.Rank(a.Labels["severity"]),
		incomingAlertname:      a.Labels["alertname"],
		baselineSeverityRank:   baselineSev,
		knownAlertnames:        known,
		episodeTimes:           episodeTimes,
		attachWindow:           c.cfg.AttachWindow,
		judgmentCeiling:        c.cfg.JudgmentCeiling,
		occurrenceCap:          c.cfg.OccurrenceCap,
	})

	// Display-only "why" facts for the recurrence event, derived here in the
	// impure half where labels and the episode series are in hand. decideAttach
	// stays pure; these never feed back into the decision.
	var delta recurrenceDelta
	switch decision.trigger {
	case "severity":
		delta.priorSeverity = baselineSevLabel
		delta.newSeverity = a.Labels["severity"]
	case "new_alertname":
		delta.newAlertname = a.Labels["alertname"]
	case "cadence":
		delta.newInterval, delta.priorMedian = decision.cadenceInterval, decision.cadenceMedian
	}

	switch decision.action {
	case actionNewIncident:
		return false, nil
	case actionAttach, actionRejudge:
		return true, c.attachOccurrence(ctx, a, *candidate, gk, decision, delta)
	case actionRepeatTouch:
		// Unreachable: repeats are short-circuited above before decideAttach runs
		// (isNewEpisode is forced true here). Fall through to a safe new incident.
		return false, nil
	default:
		return false, nil
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

// attachOccurrence records one occurrence row (with its trigger), mirrors the
// alert into incident_alerts, audits the attach, fires the collapse notifier,
// and — for an escalation — runs the re-judgment (U4 wires the rejudger). A
// re-judgment failure leaves the prior finding standing; last_judged_at is left
// unreset, so a subsequent triggering attach re-attempts it. Note this is
// retry-per-trigger, not a single retry: a persistently failing re-judgment
// (e.g. a revoked key) re-fires on each new-episode trigger, rate-bounded only
// by the LLM client's own timeout/backoff.
func (c *Correlator) attachOccurrence(ctx context.Context, a store.Alert, inc store.Incident, gk string, decision attachDecision, delta recurrenceDelta) error {
	occ := store.Occurrence{
		IncidentID:   inc.ID,
		OccurredAt:   a.ReceivedAt,
		LastSeen:     a.ReceivedAt,
		Fingerprints: []string{a.Fingerprint},
		Payload: []store.OccurrenceMember{{
			Fingerprint: a.Fingerprint,
			Labels:      a.Labels,
			Annotations: a.Annotations,
		}},
		TriggerKind: decision.trigger,
	}
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
			"trigger":     decision.trigger,
		}); err != nil {
			c.logger.Warn("correlator: audit occurrence_attached failed", "err", err, "incident_id", inc.ID)
		}
	}

	stats := c.occurrenceStats(ctx, inc.ID)
	if c.occNotifier != nil {
		ev := notify.RecurrenceEvent{
			Incident:      inc,
			Stats:         stats,
			Trigger:       decision.trigger,
			Drill:         store.IsDrillAlert(a),
			PriorSeverity: delta.priorSeverity,
			NewSeverity:   delta.newSeverity,
			NewAlertname:  delta.newAlertname,
			NewInterval:   delta.newInterval,
			PriorMedian:   delta.priorMedian,
		}
		if err := c.occNotifier.OnOccurrenceAttached(ctx, ev); err != nil {
			c.logger.Warn("correlator: occurrence notify failed", "err", err, "incident_id", inc.ID)
		}
	}
	c.logger.Info("correlator: occurrence attached",
		"incident_id", inc.ID, "group_key", gk, "trigger", decision.trigger, "occurrences", stats.Count)

	if decision.action == actionRejudge && c.rejudger != nil {
		if err := c.rejudger.Rejudge(ctx, inc, decision.trigger); err != nil {
			c.logger.Error("correlator: re-judgment failed; prior finding stands",
				"err", err, "incident_id", inc.ID, "trigger", decision.trigger)
		}
	}
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
