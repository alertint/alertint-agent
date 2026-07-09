// SPDX-License-Identifier: FSL-1.1-ALv2

// Package notify defines the Notifier interface and a multi-notifier
// implementation. Concrete notifiers live in sub-packages (stdout, slack).
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
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
	// Drill marks an incident containing at least one Drill alert
	// (member label alertint_drill="true", ADR-0013). Renderers must make
	// a Drill unmistakably synthetic (e.g. the Slack DRILL banner).
	Drill bool `json:"drill,omitempty"`
}

// Notifier delivers a Finding to some destination. Name returns a stable,
// human-readable label for the sink ("stdout", "card", "slack") used in the
// per-sink notify outcome line owned by Multi; it must not embed per-call
// detail (e.g. a Slack channel) so the label stays constant across findings.
type Notifier interface {
	Notify(ctx context.Context, f Finding) error
	Name() string
}

// Multi fans a Finding out to all contained notifiers and owns the notify
// outcome line(s): silent-but-for-one summary on success, loud and complete on
// failure. It still returns an aggregated error (the first sink failure) so
// callers keep their existing contract — but the at-a-glance per-sink status
// and the full per-sink errors live in the log, not the returned error.
type Multi struct {
	notifiers []Notifier
	logger    *slog.Logger
}

// NewMulti constructs a Multi notifier from the given list. logger may be nil
// (falls back to slog.Default()); it carries the notify outcome lines.
func NewMulti(logger *slog.Logger, nn ...Notifier) *Multi {
	if logger == nil {
		logger = slog.Default()
	}
	return &Multi{notifiers: nn, logger: logger}
}

// Name identifies the fan-out itself. Multi is never a sink token in another
// Multi's summary; this exists only to satisfy the Notifier interface.
func (m *Multi) Name() string { return "multi" }

// Notify calls every contained notifier, logs the outcome, and returns the
// first sink error (nil when all succeeded). After fan-out it emits exactly one
// summary line — INFO "notified" when every sink delivered, WARN "notify
// partial" when some did, ERROR "notify failed" when none did (the finding
// reached nobody) — each carrying a per-sink ok/FAIL token plus status and
// incident. On any failure it additionally emits one WARN "notify sink failed"
// per failing sink, carrying that sink's full wrapped error so an operator can
// act without guessing which destination broke.
func (m *Multi) Notify(ctx context.Context, f Finding) error {
	// One human-readable finding summary per analysis, at INFO in both formats.
	// This is the live-watch view of the result; the full machine JSON is the
	// stdout notifier's job (wired in only for json format or at debug).
	m.logger.Info("finding",
		slog.String("status", statusOrOngoing(f.Status)),
		slog.String("severity", f.Severity),
		slog.String("confidence", fmt.Sprintf("%.0f%%", f.Confidence*100)),
		slog.Int("alerts", f.AlertCount),
		slog.String("incident", f.IncidentID),
		slog.String("name", f.AnalysisName),
	)

	type outcome struct {
		name string
		err  error
	}
	outcomes := make([]outcome, 0, len(m.notifiers))
	var first error
	failed := 0
	for _, n := range m.notifiers {
		err := n.Notify(ctx, f)
		outcomes = append(outcomes, outcome{name: n.Name(), err: err})
		if err != nil {
			failed++
			if first == nil {
				first = err
			}
		}
	}

	if len(m.notifiers) == 0 {
		return nil
	}

	// Summary line: one per-sink ok/FAIL token, in registration order, then
	// status and incident.
	attrs := make([]any, 0, len(outcomes)+2)
	for _, o := range outcomes {
		token := "ok"
		if o.err != nil {
			token = "FAIL"
		}
		attrs = append(attrs, slog.String(o.name, token))
	}
	attrs = append(attrs,
		slog.String("status", statusOrOngoing(f.Status)),
		slog.String("incident", f.IncidentID),
	)

	switch {
	case failed == 0:
		m.logger.Info("notified", attrs...)
	case failed == len(m.notifiers):
		m.logger.Error("notify failed", attrs...)
	default:
		m.logger.Warn("notify partial", attrs...)
	}

	// Detail line per failing sink, carrying the full wrapped error.
	for _, o := range outcomes {
		if o.err != nil {
			m.logger.Warn("notify sink failed",
				slog.String("sink", o.name),
				slog.String("incident", f.IncidentID),
				slog.String("err", o.err.Error()),
			)
		}
	}

	return first
}

// OccurrenceSink is an optional capability: a Notifier that also renders a
// recurrence-collapse occurrence attach (deterministic, zero-LLM). Sinks that
// don't implement it are simply skipped by Multi's fan-out.
type OccurrenceSink interface {
	OnOccurrenceAttached(ctx context.Context, inc store.Incident, stats store.OccurrenceStats, drill bool) error
}

// OnOccurrenceAttached fans an occurrence attach out to every contained notifier
// that implements OccurrenceSink, and returns the first sink error (nil when all
// succeeded or none handle occurrences). This makes *Multi satisfy the
// correlator's occurrence-notifier interface.
func (m *Multi) OnOccurrenceAttached(ctx context.Context, inc store.Incident, stats store.OccurrenceStats, drill bool) error {
	var first error
	for _, n := range m.notifiers {
		s, ok := n.(OccurrenceSink)
		if !ok {
			continue
		}
		if err := s.OnOccurrenceAttached(ctx, inc, stats, drill); err != nil {
			m.logger.Warn("notify occurrence sink failed",
				slog.String("sink", n.Name()),
				slog.String("incident", inc.ID),
				slog.String("err", err.Error()),
			)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// statusOrOngoing defaults an empty Finding status to "ongoing" so the outcome
// line always carries a concrete status token.
func statusOrOngoing(s string) string {
	if s == "" {
		return "ongoing"
	}
	return s
}
