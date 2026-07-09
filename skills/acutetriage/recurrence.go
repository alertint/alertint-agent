// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// maxRecurrenceTrajectory bounds how many recent occurrences the re-judgment
// prompt lists, keeping the context compact.
const maxRecurrenceTrajectory = 5

// buildRecurrenceContext derives the re-judgment evidence span and the prompt
// context block from the incident's occurrences. The span anchors on the first
// occurrence (falling back to first_alert_at) so metric/log/change/Sentry
// fetches cover the recurrence, not the stale original correlation window. The
// block is deterministic occurrence facts (episode count, cadence, span) plus a
// compact annotation trajectory. M1 renders no recalled-finding memory section —
// that arrives in M2; these are the same class of data (alert annotations)
// already present in the pack, so they need no untrusted-memory notice.
func (s *Skill) buildRecurrenceContext(ctx context.Context, inc store.Incident, trigger string) (spanStart time.Time, prompt string) {
	spanStart = inc.FirstAlertAt

	statsMap, err := s.st.OccurrenceStatsByIncident(ctx, []string{inc.ID})
	if err != nil {
		s.logger.Warn("acutetriage: occurrence stats for re-judgment failed", "incident_id", inc.ID, "err", err)
		return spanStart, ""
	}
	stats := statsMap[inc.ID]
	if !stats.FirstOccurredAt.IsZero() {
		spanStart = stats.FirstOccurredAt
	}

	// Displayed episode count includes the incident's own first firing, which is
	// not an occurrence row (occurrences are the re-fires).
	episodes := stats.Count + 1

	var b strings.Builder
	fmt.Fprintf(&b, "## Recurrence context (re-analysis; trigger: %s)\n", trigger)
	b.WriteString("This already-analyzed incident recurred and is being re-analyzed. Judge it WITH this recurrence history — it is NOT a new, first-time condition.\n")
	fmt.Fprintf(&b, "Seen ×%d over the collapse span %s → now", episodes, spanStart.UTC().Format(time.RFC3339))
	if cadence := occurrenceCadence(stats); cadence != "" {
		fmt.Fprintf(&b, ", roughly every %s", cadence)
	}
	b.WriteString(".\n")

	occs, err := s.st.ListOccurrences(ctx, inc.ID, maxRecurrenceTrajectory)
	if err != nil {
		s.logger.Warn("acutetriage: list occurrences for re-judgment failed", "incident_id", inc.ID, "err", err)
	} else if len(occs) > 0 {
		b.WriteString("Recent occurrences (newest first):\n")
		for _, o := range occs {
			b.WriteString("- " + o.OccurredAt.UTC().Format(time.RFC3339) + ": " + occurrenceSummary(o) + "\n")
		}
	}
	return spanStart, b.String()
}

// occurrenceCadence returns a rounded human phrasing of the average
// inter-occurrence interval, or "" when there are too few occurrences to derive
// one. It is a computed fact from occurrence timestamps, never model phrasing.
func occurrenceCadence(stats store.OccurrenceStats) string {
	if stats.Count < 2 || !stats.LastSeen.After(stats.FirstOccurredAt) {
		return ""
	}
	avg := stats.LastSeen.Sub(stats.FirstOccurredAt) / time.Duration(stats.Count-1)
	return avg.Round(time.Minute).String()
}

// occurrenceSummary pulls a one-line description from an occurrence's payload
// snapshot for the trajectory, preferring the summary annotation.
func occurrenceSummary(o store.Occurrence) string {
	for _, m := range o.Payload {
		if v := strings.TrimSpace(m.Annotations["summary"]); v != "" {
			return v
		}
		if v := strings.TrimSpace(m.Annotations["description"]); v != "" {
			return v
		}
	}
	return "(no annotations)"
}
