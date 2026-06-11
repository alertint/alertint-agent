// SPDX-License-Identifier: FSL-1.1-ALv2

// Package stdout implements a Notifier that writes one canonical JSON line
// per Finding to an io.Writer (typically os.Stdout).
package stdout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
)

// Notifier writes a JSON line for every finding.
type Notifier struct {
	w       io.Writer
	auditor *audit.Auditor
	now     func() time.Time
}

// New constructs a stdout Notifier. w is typically os.Stdout. auditor may be nil.
func New(w io.Writer, auditor *audit.Auditor) *Notifier {
	return &Notifier{
		w:       w,
		auditor: auditor,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// line is what gets serialized to stdout.
type line struct {
	Ts      time.Time      `json:"ts"`
	Kind    string         `json:"kind"`
	Finding notify.Finding `json:"finding"`
}

// Notify serialises f as a single JSON line and writes it to w.
func (n *Notifier) Notify(ctx context.Context, f notify.Finding) error {
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
	if n.auditor != nil {
		_ = n.auditor.Append(ctx, "notify.stdout", "notify.sent", map[string]any{
			"incident_id": f.IncidentID,
			"recipient":   "stdout",
		})
	}
	return nil
}
