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
	real := testFinding()

	surfaces := map[string]func(notify.Finding) string{
		"firingMain":     func(f notify.Finding) string { return blocksJSON(t, firingMainBlocks(f)) },
		"firingDetail":   func(f notify.Finding) string { return blocksJSON(t, firingDetailBlocks(f)) },
		"resolvedMain":   func(f notify.Finding) string { return blocksJSON(t, resolvedMainBlocks(f)) },
		"resolvedThread": func(f notify.Finding) string { return blocksJSON(t, resolvedThreadBlocks(f)) },
		"firingFallback": func(f notify.Finding) string { return firingFallback(f) },
		"resolvedFallback": func(f notify.Finding) string {
			return resolvedFallback(f)
		},
	}
	for name, render := range surfaces {
		if got := render(drill); !strings.Contains(got, "DRILL") {
			t.Errorf("%s: drill finding missing DRILL banner:\n%s", name, got)
		}
		if got := render(real); strings.Contains(got, "DRILL") {
			t.Errorf("%s: real finding must not carry DRILL banner:\n%s", name, got)
		}
	}
}
