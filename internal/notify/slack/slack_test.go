// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
)

func testFinding() notify.Finding {
	return notify.Finding{
		IncidentID:   "2805297e-09ad-48d2-8845-ebe4c72ab077",
		GroupKey:     "alertname=DiskFull,host=web1",
		AnalysisName: "DiskFull on web1",
		OverallIssue: "Disk utilisation at 95%",
		Severity:     "high",
		Confidence:   0.85,
		AlertCount:   3,
		FirstAlertAt: time.Now().Add(-10 * time.Minute),
		AnalyzedAt:   time.Now(),
	}
}

// blocksJSON renders Block Kit blocks to JSON so tests can assert on text
// content without walking the slacklib block structs.
func blocksJSON(t *testing.T, blocks []slacklib.Block) string {
	t.Helper()
	b, err := json.Marshal(blocks)
	if err != nil {
		t.Fatalf("marshal blocks: %v", err)
	}
	return string(b)
}

// TestFiringMainBlocksIncludeAgentCTA verifies the headline card carries the
// copy-pasteable MCP-handoff prompt with the FULL incident ID (the downstream
// alertint_get_incident call must resolve unambiguously).
func TestFiringMainBlocksIncludeAgentCTA(t *testing.T) {
	f := testFinding()
	s := blocksJSON(t, firingMainBlocks(f))
	want := "investigate incident " + f.IncidentID + " using alertint"
	if !strings.Contains(s, want) {
		t.Errorf("firing main blocks missing CTA %q:\n%s", want, s)
	}
}

// TestFiringMainBlocksEmptyIncidentID verifies an empty ID renders no CTA and
// does not panic (mirrors the shortID guard).
func TestFiringMainBlocksEmptyIncidentID(t *testing.T) {
	f := testFinding()
	f.IncidentID = ""
	s := blocksJSON(t, firingMainBlocks(f))
	if strings.Contains(s, "investigate incident") {
		t.Errorf("empty incident ID must not render a CTA:\n%s", s)
	}
}

// TestResolvedMainBlocksOmitCTA verifies the resolved (in-place updated) card
// drops the handoff CTA — investigation prompts are for active incidents.
func TestResolvedMainBlocksOmitCTA(t *testing.T) {
	f := testFinding()
	f.Status = "resolved"
	s := blocksJSON(t, resolvedMainBlocks(f))
	if strings.Contains(s, "investigate incident") {
		t.Errorf("resolved card must not carry the CTA:\n%s", s)
	}
}

// TestFiringFallbackStillValid verifies the plain-text fallback for
// non-Block-Kit clients is unaffected by the CTA block.
func TestFiringFallbackStillValid(t *testing.T) {
	s := firingFallback(testFinding())
	if !strings.Contains(s, "INCIDENT DETECTED") || !strings.Contains(s, "HIGH") {
		t.Errorf("firing fallback malformed: %q", s)
	}
}

// TestBelowMinSeverity covers the severity-gate truth table, including the
// off-ladder rule: unclassifiable finding severities always post.
func TestBelowMinSeverity(t *testing.T) {
	cases := []struct {
		finding, gate string
		want          bool // true = suppressed
	}{
		{"low", "", false}, // empty gate = low: post everything
		{"low", "low", false},
		{"medium", "low", false},
		{"high", "low", false},
		{"low", "medium", true},
		{"medium", "medium", false},
		{"low", "high", true},
		{"medium", "high", true},
		{"high", "high", false},
		{"HIGH", "high", false},   // case-insensitive
		{"", "high", false},       // unclassified always posts
		{"urgent", "high", false}, // off-ladder always posts
	}
	for _, tc := range cases {
		n := &Notifier{minSeverity: tc.gate}
		f := notify.Finding{Severity: tc.finding}
		if got := n.belowMinSeverity(f); got != tc.want {
			t.Errorf("belowMinSeverity(sev=%q, gate=%q) = %v, want %v",
				tc.finding, tc.gate, got, tc.want)
		}
	}
}

// TestDrillBannerOnAllSurfaces verifies a Drill finding is unmistakably
// synthetic on every rendered surface (ADR-0013): main cards, thread details,
// and plain-text fallbacks — and that real findings render without it.
func TestDrillBannerOnAllSurfaces(t *testing.T) {
	drill := testFinding()
	drill.Drill = true
	regular := testFinding()

	surfaces := map[string]func(notify.Finding) string{
		"firingMain":       func(f notify.Finding) string { return blocksJSON(t, firingMainBlocks(f)) },
		"firingDetail":     func(f notify.Finding) string { return blocksJSON(t, firingDetailBlocks(f)) },
		"resolvedMain":     func(f notify.Finding) string { return blocksJSON(t, resolvedMainBlocks(f)) },
		"resolvedThread":   func(f notify.Finding) string { return blocksJSON(t, resolvedThreadBlocks(f)) },
		"firingFallback":   firingFallback,
		"resolvedFallback": resolvedFallback,
	}
	for name, render := range surfaces {
		if got := render(drill); !strings.Contains(got, "DRILL") {
			t.Errorf("%s: drill finding missing DRILL banner:\n%s", name, got)
		}
		if got := render(regular); strings.Contains(got, "DRILL") {
			t.Errorf("%s: real finding must not carry DRILL banner:\n%s", name, got)
		}
	}
}

func TestFiringCardBlocks_RecurrenceLine(t *testing.T) {
	f := testFinding()
	if s := blocksJSON(t, firingCardBlocks(f)); strings.Contains(s, "recurred") {
		t.Errorf("first-firing card must have no recurrence line:\n%s", s)
	}
	f.Recurrence = &notify.Recurrence{Episodes: 7, LastSeen: time.Date(2026, 7, 8, 2, 15, 0, 0, time.UTC)}
	s := blocksJSON(t, firingCardBlocks(f))
	if !strings.Contains(s, "recurred ×7") {
		t.Errorf("re-judgment card missing recurrence line:\n%s", s)
	}
}

func TestResolvedMainBlocks_RecurrenceSummary(t *testing.T) {
	f := testFinding()
	f.Status = "resolved"
	if s := blocksJSON(t, resolvedMainBlocks(f)); strings.Contains(s, "recurring ×") {
		t.Errorf("non-recurring resolve must not claim recurrence:\n%s", s)
	}
	f.Recurrence = &notify.Recurrence{Episodes: 14, LastSeen: time.Now()}
	s := blocksJSON(t, resolvedMainBlocks(f))
	if !strings.Contains(s, "recurring ×14 over") {
		t.Errorf("recurring resolve missing summary:\n%s", s)
	}
}

func TestResolvedMainBlocks_SingleEpisodeNoSummary(t *testing.T) {
	f := testFinding()
	f.Status = "resolved"
	f.Recurrence = &notify.Recurrence{Episodes: 1, LastSeen: time.Now()}
	if s := blocksJSON(t, resolvedMainBlocks(f)); strings.Contains(s, "recurring ×") {
		t.Errorf("Episodes<=1 must not render a recurrence summary:\n%s", s)
	}
}

func TestEvidenceLine(t *testing.T) {
	cases := []struct {
		name string
		sum  notify.EvidenceSummary
		want string
	}{
		{"counts+unreachable", notify.EvidenceSummary{Sources: []notify.SourceEvidence{
			{Source: "Prometheus", Unit: "metrics", Count: 21, State: notify.EvidenceCounted},
			{Source: "Loki", Unit: "lines", Count: 0, State: notify.EvidenceCounted},
			{Source: "Changes", Count: 2, State: notify.EvidenceCounted},
			{Source: "Sentry", Unit: "issues", Count: 0, State: notify.EvidenceUnreachable},
		}}, "Prometheus 21 metrics · Loki 0 lines · Changes 2 · Sentry unreachable"},
		{"degraded", notify.EvidenceSummary{Sources: []notify.SourceEvidence{
			{Source: "Prometheus", Unit: "metrics", Count: 0, State: notify.EvidenceDegraded},
		}}, "Prometheus slow"},
		{"skipped", notify.EvidenceSummary{Skipped: true}, "skipped (known issue)"},
		{"no sources", notify.EvidenceSummary{NoSources: true}, "no sources configured"},
	}
	for _, tc := range cases {
		if got := evidenceLine(tc.sum); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
