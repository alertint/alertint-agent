// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix

import (
	"context"
	"fmt"
	"time"
)

// ProblemEpisode is one bounded, source-proven problem/recovery episode for
// a single host+trigger, decoded from event.get (Zabbix 7.0: historical
// resolved events require event.get; problem.get only retains unresolved/
// recently resolved problems — spec.md). Ongoing means the source has not
// yet recorded a recovery event at all; RecoveryUnknown means a recovery
// event id exists but its own clock could not be resolved (an empty or
// inaccessible recovery lookup is unknown, never an inferred duration).
type ProblemEpisode struct {
	EventID         string     `json:"event_id"`
	TriggerID       string     `json:"trigger_id"`
	HostID          string     `json:"host_id"`
	Start           time.Time  `json:"start"`
	Recovery        *time.Time `json:"recovery,omitempty"`
	Ongoing         bool       `json:"ongoing"`
	RecoveryUnknown bool       `json:"recovery_unknown"`
	Severity        string     `json:"severity,omitempty"`
	Acknowledged    bool       `json:"acknowledged"`
	Suppressed      bool       `json:"suppressed"`
	Tags            []KV       `json:"tags,omitempty"`
	CauseEventID    string     `json:"cause_event_id,omitempty"`
}

// ProblemHistoryResult is ProblemHistory's bounded result: bounded episodes,
// whether the window was fully covered, and how many resolved episodes
// could not have their recovery time confirmed.
type ProblemHistoryResult struct {
	Episodes                []ProblemEpisode
	Complete                bool
	Truncated               bool
	UnresolvedRecoveryCount int
}

// ProblemHistory returns host+triggerID's bounded problem/recovery episode
// timeline over [start,end], newest-first, batching the recovery-clock
// lookup for every resolved episode into one secondary event.get call.
// before/after instrument each physical request (the primary query and the
// batched recovery lookup) individually; both may be nil for uninstrumented
// use. A budget-exhausted (or otherwise failing) recovery lookup degrades
// those episodes to RecoveryUnknown rather than failing the whole call —
// spec.md: "a request budget exhausted between problem and recovery
// lookup" must not lose the already-fetched primary evidence.
func (c *Client) ProblemHistory(ctx context.Context, host, triggerID string, start, end time.Time, severityMin string, limit int,
	before func() error, after func(started bool, err error)) (ProblemHistoryResult, error) {
	if limit <= 0 {
		limit = 20
	}
	params := map[string]any{
		"source": 0, "object": 0, "objectids": []string{triggerID}, "value": 1,
		"problem_time_from": start.UTC().Unix(), "problem_time_till": end.UTC().Unix(),
		"output":     []string{"eventid", "objectid", "clock", "r_eventid", "severity", "acknowledged", "suppressed", "cause_eventid"},
		"selectTags": "extend",
		"sortfield":  []string{"clock", "eventid"}, "sortorder": "DESC",
		"limit": limit + 1,
	}
	if severityMin != "" {
		params["severities"] = severitiesFrom(severityMin)
	}

	var rows []struct {
		EventID      string `json:"eventid"`
		ObjectID     string `json:"objectid"`
		Clock        string `json:"clock"`
		REventID     string `json:"r_eventid"`
		Severity     string `json:"severity"`
		Acknowledged string `json:"acknowledged"`
		Suppressed   string `json:"suppressed"`
		CauseEventID string `json:"cause_eventid"`
		Tags         []KV   `json:"tags"`
	}
	if err := c.callInstrumented(ctx, "event.get", params, true, &rows, before, after); err != nil {
		return ProblemHistoryResult{}, err
	}

	truncated := len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}

	var recoveryIDs []string
	for _, r := range rows {
		if r.REventID != "" && r.REventID != "0" {
			recoveryIDs = append(recoveryIDs, r.REventID)
		}
	}
	recoveryClocks := make(map[string]time.Time, len(recoveryIDs))
	if len(recoveryIDs) > 0 {
		var recRows []struct {
			EventID string `json:"eventid"`
			Clock   string `json:"clock"`
		}
		if err := c.callInstrumented(ctx, "event.get", map[string]any{
			"output": []string{"eventid", "clock"}, "eventids": recoveryIDs,
		}, true, &recRows, before, after); err == nil {
			for _, rr := range recRows {
				recoveryClocks[rr.EventID] = unixStr(rr.Clock)
			}
		}
		// A failing (or budget-withheld) recovery batch leaves recoveryClocks
		// empty; every episode below then falls through to RecoveryUnknown
		// rather than failing this whole call.
	}

	unresolvedRecoveryCount := 0
	episodes := make([]ProblemEpisode, 0, len(rows))
	for _, r := range rows {
		ep := ProblemEpisode{
			EventID: r.EventID, TriggerID: r.ObjectID, HostID: host,
			Start: unixStr(r.Clock), Severity: r.Severity,
			Acknowledged: r.Acknowledged == "1", Suppressed: r.Suppressed == "1" || r.Suppressed == "true",
			Tags: r.Tags, CauseEventID: r.CauseEventID,
		}
		switch r.REventID {
		case "", "0":
			ep.Ongoing = true
		default:
			if t, ok := recoveryClocks[r.REventID]; ok {
				ep.Recovery = &t
			} else {
				ep.RecoveryUnknown = true
				unresolvedRecoveryCount++
			}
		}
		episodes = append(episodes, ep)
	}

	return ProblemHistoryResult{
		Episodes: episodes, Complete: !truncated, Truncated: truncated,
		UnresolvedRecoveryCount: unresolvedRecoveryCount,
	}, nil
}

// EventLifecycleResult is EventLifecycle's affirmative state/timing for one
// source event.
type EventLifecycleResult struct {
	EventID         string
	Start           time.Time
	Recovery        *time.Time
	Ongoing         bool
	RecoveryUnknown bool
}

// EventLifecycle resolves one source event's affirmative lifecycle: its
// start clock, and — only if the source has recorded a recovery event —
// that recovery's own clock. An event with no recovery event yet reports
// Ongoing; one whose recovery event exists but could not be read reports
// RecoveryUnknown, never a fabricated or inferred recovery time.
func (c *Client) EventLifecycle(ctx context.Context, eventID string,
	before func() error, after func(started bool, err error)) (EventLifecycleResult, error) {
	var rows []struct {
		EventID  string `json:"eventid"`
		Clock    string `json:"clock"`
		REventID string `json:"r_eventid"`
	}
	if err := c.callInstrumented(ctx, "event.get", map[string]any{
		"output": []string{"eventid", "clock", "r_eventid"}, "eventids": []string{eventID},
	}, true, &rows, before, after); err != nil {
		return EventLifecycleResult{}, err
	}
	if len(rows) == 0 {
		return EventLifecycleResult{}, fmt.Errorf("zabbix: no event matching id %q: %w", eventID, ErrNotFound)
	}

	r := rows[0]
	result := EventLifecycleResult{EventID: r.EventID, Start: unixStr(r.Clock)}
	if r.REventID == "" || r.REventID == "0" {
		result.Ongoing = true
		return result, nil
	}

	var recRows []struct {
		Clock string `json:"clock"`
	}
	if err := c.callInstrumented(ctx, "event.get", map[string]any{
		"output": []string{"clock"}, "eventids": []string{r.REventID},
	}, true, &recRows, before, after); err == nil && len(recRows) > 0 {
		t := unixStr(recRows[0].Clock)
		result.Recovery = &t
	} else {
		result.RecoveryUnknown = true
	}
	return result, nil
}
