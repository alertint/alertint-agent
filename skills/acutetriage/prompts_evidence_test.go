// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
)

// liveLogs is a LogEnrichment carrying at least one line.
func liveLogs() *LogEnrichment {
	return &LogEnrichment{Source: "loki", Lines: []logs.Line{
		{Timestamp: time.Unix(1, 0), Line: "boom"},
	}}
}

// TestUserPrompt_AnnotationsOnlyRendersCalibration is the BUG-2 regression: when
// no live evidence (logs lines, metrics, changes, Sentry issues) was retrieved,
// the prompt must carry an annotations-only calibration directive telling the
// model to hedge causal direction and lower confidence.
func TestUserPrompt_AnnotationsOnlyRendersCalibration(t *testing.T) {
	// Every enrichment absent → annotations-only.
	out := UserPrompt(basePack(), "{}", nil, nil, nil, nil, nil)
	if !strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("annotations-only incident must carry the evidence-basis directive: %s", out)
	}
	if !strings.Contains(out, "0.6") {
		t.Errorf("directive must give a concrete confidence ceiling: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "hypothesis") {
		t.Errorf("directive must frame causal claims as hypothesis: %s", out)
	}
}

// A logs enrichment that was ATTEMPTED but returned no lines (the BUG-1 empty
// selector, or a queried-empty backend) is still annotations-only — the note
// alone is not live evidence.
func TestUserPrompt_EmptyLogsNoteIsStillAnnotationsOnly(t *testing.T) {
	e := &LogEnrichment{Source: "loki", Note: "no usable log selector for this incident"}
	out := UserPrompt(basePack(), "{}", nil, e, nil, nil, nil)
	if !strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("empty (note-only) logs must still trigger the calibration directive: %s", out)
	}
}

func TestUserPrompt_WithLiveLogsNoCalibration(t *testing.T) {
	out := UserPrompt(basePack(), "{}", nil, liveLogs(), nil, nil, nil)
	if strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("live log lines present — calibration directive must be omitted: %s", out)
	}
}

func TestUserPrompt_WithMetricsNoCalibration(t *testing.T) {
	metrics := []MetricSnapshot{{Metric: "up", Instance: "api-1", Value: "0"}}
	out := UserPrompt(basePack(), "{}", metrics, nil, nil, nil, nil)
	if strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("live metrics present — calibration directive must be omitted: %s", out)
	}
}
