// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// ChangeParams carries the change-enrichment tunables from config
// (changes.enrichment). Enabled gates the whole fetch — FetchChanges returns nil
// only when Enabled is false ("we never looked").
type ChangeParams struct {
	Enabled       bool
	WindowMinutes int
	MaxEvents     int
}

// ChangeView is one ranked change rendered into the prompt and persisted.
type ChangeView struct {
	Source              string            `json:"source"`
	Kind                string            `json:"kind"`
	Title               string            `json:"title"`
	Labels              map[string]string `json:"labels"`
	Version             string            `json:"version,omitempty"`
	Link                string            `json:"link,omitempty"`
	OccurredAt          time.Time         `json:"occurred_at"`
	MatchCount          int               `json:"match_count"`
	MatchedOn           map[string]string `json:"matched_on,omitempty"` // the incident labels this change actually matched (rendered + replayed)
	DeltaBeforeIncident string            `json:"delta_before_incident"`
}

// ChangeEnrichment is the recent-change context attached to a triage prompt and
// persisted under the "changes" envelope key. Mirrors LogEnrichment.
type ChangeEnrichment struct {
	Start         time.Time         `json:"start"`
	End           time.Time         `json:"end"`
	MatchedLabels map[string]string `json:"matched_labels"` // incident shared labels matched on (NOT allowlist-filtered)
	Changes       []ChangeView      `json:"changes,omitempty"`
	Note          string            `json:"note,omitempty"`
}

// FetchChanges selects recent changes overlapping the incident's shared labels,
// ranked by (match-count desc, recency desc), capped at MaxEvents. It mirrors
// FetchLogs, but reads LOCAL SQLite (reliable mid-incident — no timeout dance).
//
// Correlation departs from logs on purpose: NO allowlist — match on ANY shared
// label. A deploy emitter doesn't send alert-metadata (alertname/severity), so
// those incident labels self-drop (nothing to match); meanwhile an allowlist
// would hide useful keys (region/cluster/env). The LLM judges relevance from the
// title+labels; the match step's only job is not to hide candidates.
//
// Visibility over silence: returns nil ONLY when disabled. When enabled it
// always returns non-nil — with Changes, or with Changes empty and a Note — so
// the operator and LLM can tell "looked, found nothing" from "never looked".
// incidentID rides every outcome line (ADR-0004) and is the join key the
// operator's agent uses for MCP follow-up.
func FetchChanges(ctx context.Context, st *store.Store, params ChangeParams, alerts []store.Alert, first, last time.Time, incidentID string, logger *slog.Logger) *ChangeEnrichment {
	if !params.Enabled {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	start := first.Add(-time.Duration(params.WindowMinutes) * time.Minute)
	end := last

	shared := sharedLabels(alerts)
	if len(shared) == 0 {
		logger.Info("no shared labels to match changes for this incident", "incident", incidentID)
		return &ChangeEnrichment{Start: start, End: end, Note: "no shared labels to match changes for this incident"}
	}

	all, err := st.ChangesInWindow(ctx, start, end)
	if err != nil {
		logger.Warn("change query failed", "err", err, "incident", incidentID)
		return &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Note: "change query failed: " + err.Error()}
	}

	type ranked struct {
		c         store.Change
		matchedOn map[string]string
	}
	matched := make([]ranked, 0, len(all))
	for _, c := range all {
		m := overlap(c.Labels, shared)
		if len(m) > 0 {
			matched = append(matched, ranked{c: c, matchedOn: m})
		}
	}
	if len(matched) == 0 {
		logger.Info("no changes in window", "window", fmt.Sprintf("%dm", params.WindowMinutes), "incident", incidentID)
		return &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Note: "no changes in window"}
	}

	// (match-count desc, recency desc). Relevance-primary so a flood of
	// barely-related recent changes can't push out the highly-related one;
	// recency breaks ties.
	sort.SliceStable(matched, func(i, j int) bool {
		if len(matched[i].matchedOn) != len(matched[j].matchedOn) {
			return len(matched[i].matchedOn) > len(matched[j].matchedOn)
		}
		return matched[i].c.OccurredAt.After(matched[j].c.OccurredAt)
	})
	if len(matched) > params.MaxEvents {
		matched = matched[:params.MaxEvents]
	}

	views := make([]ChangeView, 0, len(matched))
	for _, m := range matched {
		views = append(views, ChangeView{
			Source:              m.c.Source,
			Kind:                m.c.Kind,
			Title:               m.c.Title,
			Labels:              m.c.Labels,
			Version:             m.c.Version,
			Link:                m.c.Link,
			OccurredAt:          m.c.OccurredAt,
			MatchCount:          len(m.matchedOn),
			MatchedOn:           m.matchedOn,
			DeltaBeforeIncident: deltaHint(m.c.OccurredAt, first),
		})
	}
	logger.Info("changes fetched", "changes", len(views), "window", fmt.Sprintf("%dm", params.WindowMinutes), "incident", incidentID)
	return &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Changes: views}
}

// overlap returns the keys (with values) present in both maps with equal
// values — the exact labels this change correlated on. len(overlap) is the
// match count used for ranking; the map itself is rendered ({matched: …}) and
// persisted so the LLM and MCP replay see the correlation basis.
func overlap(changeLabels, shared map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range shared {
		if changeLabels[k] == v {
			out[k] = v
		}
	}
	return out
}

// deltaHint renders the highest-signal fact for the LLM: how long before (or
// after) incident start the change occurred.
func deltaHint(occurred, first time.Time) string {
	if occurred.Before(first) {
		return "Δ" + humanizeDuration(first.Sub(occurred)) + " before incident start"
	}
	return "Δ" + humanizeDuration(occurred.Sub(first)) + " after incident start"
}

func humanizeDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
