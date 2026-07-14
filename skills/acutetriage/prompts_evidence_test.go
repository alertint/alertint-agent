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
	out := UserPrompt(basePack(), "{}", nil, nil, nil, nil, nil, VerificationParams{})
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
	out := UserPrompt(basePack(), "{}", nil, e, nil, nil, nil, VerificationParams{})
	if !strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("empty (note-only) logs must still trigger the calibration directive: %s", out)
	}
}

func TestUserPrompt_WithLiveLogsNoCalibration(t *testing.T) {
	out := UserPrompt(basePack(), "{}", nil, liveLogs(), nil, nil, nil, VerificationParams{})
	if strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("live log lines present — calibration directive must be omitted: %s", out)
	}
}

func TestUserPrompt_WithMetricsNoCalibration(t *testing.T) {
	metrics := &MetricEnrichment{Outcome: OutcomeFetched, Snapshots: []MetricSnapshot{{Metric: "up", Series: `{instance="api-1"}`, Value: "0"}}}
	out := UserPrompt(basePack(), "{}", metrics, nil, nil, nil, nil, VerificationParams{})
	if strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("live metrics present — calibration directive must be omitted: %s", out)
	}
}

// TestUserPrompt_DegradedMetricsExemptFromCap: a metric timeout under load
// (OutcomeDegraded) means the data very likely exists — the fetch was merely
// slow — so it must NOT drag the finding into the annotations-only cap the way a
// genuine outage or empty result does.
func TestUserPrompt_DegradedMetricsExemptFromCap(t *testing.T) {
	m := &MetricEnrichment{Outcome: OutcomeDegraded, Note: "metric backend too slow to answer within the deadline"}
	out := UserPrompt(basePack(), "{}", m, nil, nil, nil, nil, VerificationParams{})
	if strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("degraded metrics must NOT trigger the annotations-only cap directive: %s", out)
	}
}

// A genuine metric failure (OutcomeFailed) is still annotations-only — a down
// backend gives us no data and no reason to believe data exists.
func TestUserPrompt_FailedMetricsStillAnnotationsOnly(t *testing.T) {
	m := &MetricEnrichment{Outcome: OutcomeFailed, Note: "metric backend query failed"}
	out := UserPrompt(basePack(), "{}", m, nil, nil, nil, nil, VerificationParams{})
	if !strings.Contains(out, "ANNOTATIONS ONLY") {
		t.Fatalf("failed metrics must still carry the annotations-only directive: %s", out)
	}
}

func TestRenderMetrics_SeriesAndNote(t *testing.T) {
	var b strings.Builder
	renderMetrics(&b, &MetricEnrichment{Outcome: OutcomeFetched, Snapshots: []MetricSnapshot{
		{Series: `{namespace="checkout",pod="api-7f9x"}`, Metric: "cpu", Value: "0.9"},
	}})
	if !strings.Contains(b.String(), `cpu{namespace="checkout",pod="api-7f9x"} = 0.9`) {
		t.Errorf("metric line missing: %q", b.String())
	}
	// Empty + attempted → a note, like logs.
	b.Reset()
	renderMetrics(&b, &MetricEnrichment{Outcome: OutcomeEmpty, Note: "no metric series matched the incident selector"})
	if !strings.Contains(b.String(), "no metric series matched") {
		t.Errorf("empty note missing: %q", b.String())
	}
}

// TestAnnotationsOnlyBasis_DegradedExemptOthersNot locks the single predicate
// both the prompt directive and the deterministic cap backstop rely on: a
// degraded (slow) metric fetch is exempt from the cap, while genuine failure,
// empty, and no-evidence-at-all are not.
func TestAnnotationsOnlyBasis_DegradedExemptOthersNot(t *testing.T) {
	if annotationsOnlyBasis(&MetricEnrichment{Outcome: OutcomeDegraded}, nil, nil, nil) {
		t.Error("degraded (slow) metrics must be exempt from the annotations-only cap")
	}
	if !annotationsOnlyBasis(&MetricEnrichment{Outcome: OutcomeFailed}, nil, nil, nil) {
		t.Error("a genuine metric failure is annotations-only")
	}
	if !annotationsOnlyBasis(&MetricEnrichment{Outcome: OutcomeEmpty}, nil, nil, nil) {
		t.Error("a queried-empty metric result is annotations-only")
	}
	if !annotationsOnlyBasis(nil, nil, nil, nil) {
		t.Error("no evidence at all is annotations-only")
	}
	if annotationsOnlyBasis(&MetricEnrichment{Snapshots: make([]MetricSnapshot, 1)}, nil, nil, nil) {
		t.Error("live snapshots lift the cap")
	}
}

func TestHasLiveEvidence_MetricsPresenceLiftsCap(t *testing.T) {
	// R10: any snapshot that reaches the prompt is live evidence.
	if !hasLiveEvidence(&MetricEnrichment{Snapshots: make([]MetricSnapshot, 1)}, nil, nil, nil) {
		t.Error("one snapshot must count as live evidence")
	}
	if hasLiveEvidence(&MetricEnrichment{Outcome: OutcomeEmpty}, nil, nil, nil) {
		t.Error("queried-empty must NOT lift the cap")
	}
}
