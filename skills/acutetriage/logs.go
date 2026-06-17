// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"log/slog"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

// LogEnrichment is the recent-log-line context attached to a triage prompt and
// persisted with the finding (incidents.enrichment_json) so the evidence pack
// can replay exactly what the LLM saw. The same value feeds both the prompt and
// persistence — one fetch, two uses.
type LogEnrichment struct {
	Source string      `json:"source"`          // src.Name()
	Query  string      `json:"query,omitempty"` // the native query that ran ("" if none built)
	Start  time.Time   `json:"start"`
	End    time.Time   `json:"end"`
	Lines  []logs.Line `json:"lines,omitempty"` // normalized, newest-first
	Note   string      `json:"note,omitempty"`  // why Lines is empty (queried-empty / timeout / error / no-selector)
}

// LogParams carries the generic enrichment tunables from config (the logs
// section). They are passed in rather than read from the Source so the Source
// interface stays minimal (three methods, no Default*() accessors).
type LogParams struct {
	DefaultRangeMinutes int
	TimeoutSeconds      int
	MaxLines            int
}

// FetchLogs pulls recent log lines for an incident, analogous to FetchMetrics,
// but returns a struct so the same value feeds both the prompt and persistence.
//
// Visibility over silence: it returns nil ONLY when src is nil (logs not
// configured). Whenever logs are configured it returns a non-nil enrichment —
// with Lines, or with Lines empty and a Note explaining the absence — so the
// operator and the LLM can tell "we looked and found nothing / the backend
// failed" apart from "we never looked". It is best-effort and never blocks or
// fails triage.
//
// first/last bound the window: start = first − default_range_minutes, end =
// last (the caller passes now for a still-firing incident). The whole fetch
// (filtered + fallback) shares ONE timeout_seconds deadline, so the worst-case
// latency added to triage is timeout_seconds, not 2×.
func FetchLogs(ctx context.Context, src logs.Source, params LogParams, alerts []store.Alert, first, last time.Time, logger *slog.Logger) *LogEnrichment {
	if src == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	source := src.Name()
	start := first.Add(-time.Duration(params.DefaultRangeMinutes) * time.Minute)
	end := last

	// Generic selector: shared alert labels ∩ AllowedSelectorKeys. No per-backend
	// renaming here — the provider owns translation (ADR-0002).
	sel := buildLogSelector(alerts)
	if len(sel.Labels) == 0 {
		shared := formatLabels(sharedLabels(alerts))
		logger.Info("acutetriage: logs: empty selector — no usable log labels for this incident",
			"source", source, "shared_labels", shared)
		return &LogEnrichment{
			Source: source,
			Start:  start,
			End:    end,
			Note:   "no usable log selector for this incident (shared labels: " + shared + ")",
		}
	}

	// One bounded deadline for the whole operation (both fetch passes).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(params.TimeoutSeconds)*time.Second)
	defer cancel()

	fetched, err := src.FetchRecent(ctx, sel, start, end, params.MaxLines)
	if err != nil {
		// Timeout / network / non-200 / decode — record the gap, keep triaging.
		logger.Warn("acutetriage: logs: backend query failed",
			"source", source, "query", fetched.Query, "err", err)
		return &LogEnrichment{
			Source: source,
			Query:  fetched.Query,
			Start:  start,
			End:    end,
			Note:   "log backend query failed: " + err.Error(),
		}
	}

	lines := logs.Normalize(fetched.Lines, logs.MaxBytes, logs.MaxLineChars)
	if len(lines) == 0 {
		// Queried but empty — the most likely first-run failure (selector/schema
		// mismatch). Name the real query so the operator can fix loki.label_map.
		logger.Info("acutetriage: logs: query returned no lines — check label_map / line_filter",
			"source", source, "query", fetched.Query)
		return &LogEnrichment{
			Source: source,
			Query:  fetched.Query,
			Start:  start,
			End:    end,
			Note:   "log backend returned no lines for this query",
		}
	}

	return &LogEnrichment{
		Source: source,
		Query:  fetched.Query,
		Start:  start,
		End:    end,
		Lines:  lines,
	}
}

// buildLogSelector intersects an incident's shared alert labels with the generic
// allowlist, dropping alert-metadata noise no log backend labels streams by.
func buildLogSelector(alerts []store.Alert) logs.Selector {
	shared := sharedLabels(alerts)
	out := make(map[string]string)
	for _, k := range logs.AllowedSelectorKeys {
		if v, ok := shared[k]; ok && v != "" {
			out[k] = v
		}
	}
	return logs.Selector{Labels: out}
}
