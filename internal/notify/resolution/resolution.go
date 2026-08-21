// SPDX-License-Identifier: FSL-1.1-ALv2

// Package resolution implements the legacy per-Incident resolution card
// update.
//
// It is NOT reachable from serve after the Situation cutover: recovery is a
// visible Situation lifecycle state (recovery_pending, then recovered) whose
// one Slack surface is the Situation root, edited by the notification
// worker. This package remains compiled only so the existing
// historical-card fixture tests keep rendering the cards operators already
// have in their channels.
package resolution

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// Notifier wraps existing notifiers to send resolution notifications.
type Notifier struct {
	inner notify.Notifier
	st    *store.Store
}

// New creates a resolution notifier that wraps an existing notifier. st may
// be nil (tests); it is used to re-derive the Drill flag so a resolving
// drill's in-place card update keeps its DRILL banner (ADR-0013).
func New(inner notify.Notifier, st *store.Store) *Notifier {
	return &Notifier{inner: inner, st: st}
}

// OnIncidentResolved renders one legacy resolved Incident card through the
// wrapped notifier. Nothing in serve calls it after the cutover.
func (n *Notifier) OnIncidentResolved(ctx context.Context, inc store.Incident) error {
	// Carry original LLM analysis into the resolved finding when available
	// so notifiers (e.g. Slack) can preserve context in the updated message.
	analysisName := inc.Summary
	if analysisName == "" {
		analysisName = "Incident Resolved"
	}
	overallIssue := inc.RootCause
	if overallIssue == "" {
		overallIssue = "All alerts have recovered. Incident is now resolved."
	}
	confidence := inc.Confidence
	if confidence == 0 {
		confidence = 1.0
	}

	drill := false
	if n.st != nil {
		// Best-effort: a lookup failure must not block the resolution
		// notification; the card just loses the banner in that edge.
		if flags, err := n.st.IncidentDrillFlags(ctx, []string{inc.ID}); err == nil {
			drill = flags[inc.ID]
		}
	}

	f := notify.Finding{
		IncidentID:   inc.ID,
		GroupKey:     inc.GroupKey,
		AnalysisName: analysisName,
		OverallIssue: overallIssue,
		Severity:     "low",
		Confidence:   confidence,
		AlertCount:   inc.AlertCount,
		FirstAlertAt: inc.FirstAlertAt,
		AnalyzedAt:   time.Now().UTC(),
		OutputJSON:   json.RawMessage(`{"status":"resolved"}`),
		Status:       "resolved",
		Drill:        drill,
	}
	if n.st != nil {
		// Best-effort recurrence summary for the resolved card ("resolved after
		// recurring ×N"). A lookup miss/err just omits it.
		if m, err := n.st.OccurrenceStatsByIncident(ctx, []string{inc.ID}); err == nil {
			if s, ok := m[inc.ID]; ok && s.Episodes() > 1 {
				f.Recurrence = &notify.Recurrence{Episodes: s.Episodes(), LastSeen: s.LastSeen}
			}
		}
	}
	return n.inner.Notify(ctx, f)
}
