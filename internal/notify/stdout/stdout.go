// SPDX-License-Identifier: FSL-1.1-ALv2

// Package stdout implements a Notifier that writes one canonical JSON line
// per Finding to an io.Writer (typically os.Stdout).
//
// The full JSON line is verbose detail: it is written only when the notifier is
// constructed verbose (the agent wires that to debug level), so the default
// info live view stays a clean one-line action trail. The sink is still an
// active delivery target at any level — it participates in the per-sink
// "notified" outcome line and appends its audit row regardless of verbosity, so
// the audit chain does not depend on log level.
package stdout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// Notifier writes a JSON line for every finding when verbose.
type Notifier struct {
	w       io.Writer
	auditor *audit.Auditor
	verbose bool
	now     func() time.Time
}

// New constructs a stdout Notifier. w is typically os.Stdout. auditor may be
// nil. verbose gates the full JSON line: when false the finding is still
// "delivered" (audited, reported ok) but no JSON is written — reserved for debug.
func New(w io.Writer, auditor *audit.Auditor, verbose bool) *Notifier {
	return &Notifier{
		w:       w,
		auditor: auditor,
		verbose: verbose,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable sink label used in the notify outcome line.
func (n *Notifier) Name() string { return "stdout" }

// line is what gets serialized to stdout.
type line struct {
	Ts      time.Time      `json:"ts"`
	Kind    string         `json:"kind"`
	Finding notify.Finding `json:"finding"`
}

// Notify writes f as a single JSON line to w when verbose; in all cases it
// audits the delivery and returns nil so the sink reports ok in the per-sink
// outcome line.
func (n *Notifier) Notify(ctx context.Context, f notify.Finding) error {
	if n.verbose {
		l := line{
			Ts:      n.now(),
			Kind:    "finding",
			Finding: f,
		}
		b, err := json.Marshal(l)
		if err != nil {
			return fmt.Errorf("stdout notifier: marshal: %w", err)
		}
		if _, err := fmt.Fprintf(n.w, "%s\n", b); err != nil {
			return fmt.Errorf("stdout notifier: write: %w", err)
		}
	}
	if n.auditor != nil {
		_ = n.auditor.Append(ctx, "notify.stdout", "notify.sent", map[string]any{
			"incident_id": f.IncidentID,
			"recipient":   "stdout",
		})
	}
	return nil
}

// occurrenceLine is the JSON shape written for each recurrence-collapse attach.
type occurrenceLine struct {
	Ts          time.Time `json:"ts"`
	Kind        string    `json:"kind"`
	IncidentID  string    `json:"incident_id"`
	GroupKey    string    `json:"group_key"`
	Occurrences int       `json:"occurrences"`
	LastSeen    time.Time `json:"last_seen"`
	Drill       bool      `json:"drill,omitempty"`
}

// OnOccurrenceAttached writes one JSON occurrence line for a recurrence-collapse
// attach — always (not verbose-gated): the occurrence line IS the visible
// collapse signal on stdout (the always-on notifier), zero LLM tokens.
func (n *Notifier) OnOccurrenceAttached(ctx context.Context, inc store.Incident, stats store.OccurrenceStats, drill bool) error {
	l := occurrenceLine{
		Ts:          n.now(),
		Kind:        "occurrence",
		IncidentID:  inc.ID,
		GroupKey:    inc.GroupKey,
		Occurrences: stats.Episodes(),
		LastSeen:    stats.LastSeen.UTC(),
		Drill:       drill,
	}
	b, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("stdout notifier: marshal occurrence: %w", err)
	}
	if _, err := fmt.Fprintf(n.w, "%s\n", b); err != nil {
		return fmt.Errorf("stdout notifier: write occurrence: %w", err)
	}
	if n.auditor != nil {
		_ = n.auditor.Append(ctx, "notify.stdout", "notify.occurrence", map[string]any{
			"incident_id": inc.ID,
			"occurrences": l.Occurrences,
		})
	}
	return nil
}
