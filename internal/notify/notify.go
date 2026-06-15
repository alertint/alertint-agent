// SPDX-License-Identifier: FSL-1.1-ALv2

// Package notify defines the Notifier interface and a multi-notifier
// implementation. Concrete notifiers live in sub-packages (stdout, slack).
package notify

import (
	"context"
	"encoding/json"
	"time"
)

// Finding carries the denormalized data needed by every notifier. It is
// populated by the skill after SaveIncidentOutput succeeds.
type Finding struct {
	IncidentID          string          `json:"incident_id"`
	GroupKey            string          `json:"group_key"`
	AnalysisName        string          `json:"analysis_name"`
	OverallIssue        string          `json:"overall_issue"`
	CorrelationFindings []string        `json:"correlation_findings"`
	Severity            string          `json:"severity"`
	Confidence          float64         `json:"confidence"`
	AlertCount          int             `json:"alert_count"`
	FirstAlertAt        time.Time       `json:"first_alert_at"`
	AnalyzedAt          time.Time       `json:"analyzed_at"`
	OutputJSON          json.RawMessage `json:"output_json,omitempty"`
	Status              string          `json:"status,omitempty"` // "ongoing" | "resolved"
}

// Notifier delivers a Finding to some destination.
type Notifier interface {
	Notify(ctx context.Context, f Finding) error
}

// Multi fans a Finding out to all contained notifiers. The first error
// encountered is returned; remaining notifiers are still attempted.
type Multi struct {
	notifiers []Notifier
}

// NewMulti constructs a Multi notifier from the given list.
func NewMulti(nn ...Notifier) *Multi {
	return &Multi{notifiers: nn}
}

// Notify calls every contained notifier and returns the first error.
func (m *Multi) Notify(ctx context.Context, f Finding) error {
	var first error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, f); err != nil && first == nil {
			first = err
		}
	}
	return first
}
