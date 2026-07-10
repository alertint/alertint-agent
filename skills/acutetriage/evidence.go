// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"

	"github.com/alertint/alertint-agent/internal/notify"
)

// Outcome is the structured result of one best-effort enrichment fetch, shared
// by the metric, log, and change sources so the notification evidence line can
// map every source's outcome to a card state uniformly (R8). Sentry keeps its
// own SentryOutcome (reconciliation semantics predate this) and is mapped in
// buildEvidenceSummary. The zero value is fail-safe: an unset Outcome reads as
// "empty" (a 0), never "unreachable".
type Outcome string

const (
	// OutcomeFetched: the backend returned usable items → card renders the count.
	OutcomeFetched Outcome = "fetched"
	// OutcomeEmpty: queried, nothing matched → card renders 0.
	OutcomeEmpty Outcome = "empty"
	// OutcomeNoSelector: no usable selector could be built → card renders 0.
	OutcomeNoSelector Outcome = "no_selector"
	// OutcomeFailed: the backend was unreachable / errored → card renders "unreachable".
	OutcomeFailed Outcome = "failed"
)

// buildEvidenceSummary maps the incident's enrichment outcomes into the always-on
// evidence summary carried on the Finding (R6/R7/R8/R12). A short-circuit finding
// renders one card-level skipped state (no fetch ran, so per-source zeros would be
// a lie — R12/AE10). With no source enrichment at all it renders an explicit
// no-sources state (R6/AE9). Otherwise each non-nil source contributes one entry,
// in a fixed order, with the uniform outcome→state mapping.
func buildEvidenceSummary(shortCircuit bool, m *MetricEnrichment, l *LogEnrichment, c *ChangeEnrichment, se *SentryEnrichment) notify.EvidenceSummary {
	if shortCircuit {
		return notify.EvidenceSummary{Skipped: true}
	}
	var sources []notify.SourceEvidence
	if m != nil {
		sources = append(sources, notify.SourceEvidence{
			Source: "Prometheus", Unit: "metrics", Count: len(m.Snapshots), State: cardState(m.Outcome),
		})
	}
	if l != nil {
		sources = append(sources, notify.SourceEvidence{
			Source: title(l.Source), Unit: "lines", Count: len(l.Lines), State: cardState(l.Outcome),
		})
	}
	if c != nil {
		sources = append(sources, notify.SourceEvidence{
			Source: "Changes", Count: len(c.Changes), State: cardState(c.Outcome),
		})
	}
	if se != nil {
		state := notify.EvidenceCounted
		if se.Outcome == outcomeDegraded {
			state = notify.EvidenceUnreachable
		}
		sources = append(sources, notify.SourceEvidence{
			Source: "Sentry", Unit: "issues", Count: len(se.Issues), State: state,
		})
	}
	if len(sources) == 0 {
		return notify.EvidenceSummary{NoSources: true}
	}
	return notify.EvidenceSummary{Sources: sources}
}

// cardState maps a shared enrichment Outcome to a card state: only a backend
// failure renders as unreachable; queried-empty and no-selector both render as a
// real 0 (R8).
func cardState(o Outcome) notify.EvidenceState {
	if o == OutcomeFailed {
		return notify.EvidenceUnreachable
	}
	return notify.EvidenceCounted
}

// title upper-cases the first letter of a source name for display ("loki" → "Loki").
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
