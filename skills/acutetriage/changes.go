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

// FetchChanges surfaces recent changes in the incident's window, ranked by
// (match-count desc, recency desc), capped at MaxEvents. It mirrors FetchLogs,
// but reads LOCAL SQLite (reliable mid-incident — no timeout dance).
//
// ADR-0005 — surface regardless of label match: every in-window change is a
// candidate. Label overlap is computed for RANKING only (matched changes sort
// first), never as an inclusion filter, and a no-shared-labels incident is NOT
// short-circuited — it still gets recent changes by recency. Overshoot beats
// undershoot here because changes are a low-volume trickle (unlike logs, where
// ADR-0002's selector exists precisely because logs are high-volume); MaxEvents
// is the noise bound. Correlation still departs from logs on the matching itself:
// NO allowlist — overlap on ANY shared label, since a deploy emitter doesn't send
// alert-metadata (alertname/severity) and an allowlist would hide useful keys
// (region/cluster/env). The LLM judges relevance from title+labels.
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

	all, err := st.ChangesInWindow(ctx, start, end)
	if err != nil {
		logger.Warn("change query failed", "err", err, "incident", incidentID)
		return &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Note: "change query failed: " + err.Error()}
	}
	// Segregate drill artifacts (ADR-0013/0014): a change event carrying the
	// reserved demo marker is synthetic. It may only enrich a Drill — for a
	// real incident it would be fictional "live evidence" that lifts the
	// metadata-only confidence cap and invites a false causal attribution.
	if !isDrill(alerts) {
		kept := all[:0]
		for _, c := range all {
			if c.Labels[store.DemoMarkerLabel] == store.DemoMarkerValue {
				continue
			}
			kept = append(kept, c)
		}
		if dropped := len(all) - len(kept); dropped > 0 {
			logger.Info("demo changes excluded from real incident", "dropped", dropped, "incident", incidentID)
		}
		all = kept
	}
	if len(all) == 0 {
		// Genuinely empty window — keep the original note so absence of changes
		// is never silently mistaken for "nothing changed".
		logger.Info("no changes in window", "window", fmt.Sprintf("%dm", params.WindowMinutes), "incident", incidentID)
		return &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Note: "no changes in window"}
	}

	// Rank ALL in-window changes: overlap drives the sort key but no longer
	// gates inclusion. (match-count desc, recency desc) so a highly-related
	// change can't be pushed out by a flood of barely-related recent ones;
	// recency breaks ties and orders the unmatched tail.
	type ranked struct {
		c         store.Change
		matchedOn map[string]string
	}
	cands := make([]ranked, 0, len(all))
	for _, c := range all {
		cands = append(cands, ranked{c: c, matchedOn: overlap(c.Labels, shared)})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if len(cands[i].matchedOn) != len(cands[j].matchedOn) {
			return len(cands[i].matchedOn) > len(cands[j].matchedOn)
		}
		return cands[i].c.OccurredAt.After(cands[j].c.OccurredAt)
	})
	if len(cands) > params.MaxEvents {
		cands = cands[:params.MaxEvents]
	}

	views := make([]ChangeView, 0, len(cands))
	for _, m := range cands {
		views = append(views, ChangeView{
			Source:              m.c.Source,
			Kind:                m.c.Kind,
			Title:               m.c.Title,
			Labels:              m.c.Labels,
			Version:             m.c.Version,
			Link:                m.c.Link,
			OccurredAt:          m.c.OccurredAt,
			MatchCount:          len(m.matchedOn),
			MatchedOn:           m.matchedOn, // empty for the unmatched tail
			DeltaBeforeIncident: deltaHint(m.c.OccurredAt, first),
		})
	}

	enr := &ChangeEnrichment{Start: start, End: end, MatchedLabels: shared, Changes: views}
	if len(shared) == 0 {
		// Incident had no shared labels to match on, but the window had changes —
		// show them by recency rather than returning nothing (ADR-0005).
		enr.Note = "no shared labels; showing recent changes by recency"
	}
	logger.Info("changes fetched", "changes", len(views), "window", fmt.Sprintf("%dm", params.WindowMinutes), "incident", incidentID)
	return enr
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
