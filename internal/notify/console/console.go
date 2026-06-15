// SPDX-License-Identifier: FSL-1.1-ALv2

// Package console implements a human-readable console notifier for incident
// analysis findings. Prints 3-line compact format.
package console

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
)

// Notifier prints 3-line incident analysis output to a writer.
type Notifier struct {
	w       io.Writer
	auditor *audit.Auditor
}

// New creates a console notifier that writes to w.
func New(w io.Writer, auditor *audit.Auditor) *Notifier {
	return &Notifier{w: w, auditor: auditor}
}

// Notify prints a 3-line summary: status header, description, metadata.
func (n *Notifier) Notify(ctx context.Context, f notify.Finding) error {
	status := strings.ToUpper(f.Status)
	if status == "" {
		status = "ONGOING"
	}

	// Line 1: Status banner with severity
	severity := strings.ToUpper(f.Severity)
	statusLine := fmt.Sprintf("▶ INCIDENT %s | severity=%s | id=%s\n", status, severity, f.IncidentID[:8])

	// Line 2: Description (analysis name + root cause)
	descLine := fmt.Sprintf("  %s: %s\n", f.AnalysisName, f.OverallIssue)

	// Line 3: Metadata (confidence, alerts, group, timing)
	metaLine := fmt.Sprintf("  confidence=%.0f%% alerts=%d group=%s at=%s\n",
		f.Confidence*100,
		f.AlertCount,
		f.GroupKey,
		f.AnalyzedAt.Format("15:04:05"),
	)

	_, err := fmt.Fprint(n.w, statusLine+descLine+metaLine)
	return err
}
