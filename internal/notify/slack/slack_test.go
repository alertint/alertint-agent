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

// mustTime parses a "YYYY-MM-DD" fixture date, panicking on malformed input —
// test fixtures only, never a production parse path.
func mustTime(s string) time.Time {
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return tm
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

// TestDrillFrameOnMainCards verifies both main-channel cards (firing and
// resolved — the same message edited in place) carry the one-line drill
// explainer, and that real findings never do. The frame is what makes a drill
// self-explanatory to a viewer who did not run the CLI.
func TestDrillFrameOnMainCards(t *testing.T) {
	const frame = "this is a drill"
	drill := testFinding()
	drill.Drill = true
	regular := testFinding()

	surfaces := map[string]func(notify.Finding) []slacklib.Block{
		"firingMain":   firingMainBlocks,
		"resolvedMain": resolvedMainBlocks,
	}
	for name, render := range surfaces {
		if got := blocksJSON(t, render(drill)); !strings.Contains(got, frame) {
			t.Errorf("%s: drill card missing the explainer frame:\n%s", name, got)
		}
		if got := blocksJSON(t, render(regular)); strings.Contains(got, frame) {
			t.Errorf("%s: real finding must not carry the drill frame:\n%s", name, got)
		}
	}
}

// TestUnverifiedWordingDrillAware verifies the unverified caveat explains
// itself on drill cards (missing checks are the expected state there) and
// stays terse on real ones.
func TestUnverifiedWordingDrillAware(t *testing.T) {
	f := testFinding()
	f.Unverified = true
	if got := blocksJSON(t, firingDetailBlocks(f)); !strings.Contains(got, "unverified — checks unavailable") {
		t.Errorf("real unverified finding missing the terse caveat:\n%s", got)
	}
	f.Drill = true
	got := blocksJSON(t, firingDetailBlocks(f))
	if !strings.Contains(got, "expected for a drill") {
		t.Errorf("drill unverified finding missing the drill wording:\n%s", got)
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

func TestFiringDetailBlocks_UnverifiedCaveat(t *testing.T) {
	f := testFinding()

	// Test with Unverified: true
	f.Unverified = true
	s := blocksJSON(t, firingDetailBlocks(f))
	if !strings.Contains(s, "unverified — checks unavailable") {
		t.Errorf("unverified finding missing caveat in detail blocks:\n%s", s)
	}

	// Test with Unverified: false (default)
	f.Unverified = false
	s = blocksJSON(t, firingDetailBlocks(f))
	if strings.Contains(s, "unverified") {
		t.Errorf("verified finding must not contain unverified caveat:\n%s", s)
	}
}

// TestFiringCardHistoryBlock covers the tri-state operator history line and
// the steering ruling line (R9/R13, ADR-0029): first/seen/seen-without-count/
// history/unavailable, plus all ruling outcomes. Surfaces differ on purpose:
// history lines render on the thread detail (context for whoever opens the
// incident), steering ruling lines on the main card (triage signal, must be
// channel-visible).
func TestFiringCardHistoryBlock(t *testing.T) {
	cases := []struct {
		name string
		h    *notify.History
		s    *notify.Steering
		want string // substring that must appear in the rendered card blocks
	}{
		{"first", &notify.History{State: "first"}, nil,
			"🆕 first occurrence — no prior incidents, verdicts, or notes for this failure group"},
		{"seen", &notify.History{State: "seen", Episodes: 4, FirstSeen: mustTime("2026-07-01"), WindowDays: 90}, nil,
			"👀 seen ×4 in the last 90d (since 2026-07-01) — no operator verdict yet"},
		{"seen without count", &notify.History{State: "seen"}, nil,
			"👀 seen before — no operator verdict yet"},
		{"history", &notify.History{State: "history",
			Verdict: &notify.HistoryVerdict{Kind: "correction", Age: "4d ago", Note: "pvc filling"}}, nil,
			"📌 operator correction (4d ago): pvc filling"},
		{"unavailable", &notify.History{State: "unavailable"}, nil,
			"⚠️ operator history unavailable"},
		{"ruling supported", &notify.History{State: "history"},
			&notify.Steering{Ruling: "supported", Basis: "series is filling"},
			"✅ operator correction checked: supported — series is filling"},
		{"ruling contradicted", &notify.History{State: "history"},
			&notify.Steering{Ruling: "contradicted", Basis: "series healthy"},
			"❌ operator correction checked: does not apply now — series healthy"},
		{"ruling unverifiable", &notify.History{State: "history"},
			&notify.Steering{Ruling: "unverifiable", VerdictDate: "2026-07-28"},
			"⚠️ adopted per operator correction of 2026-07-28, not verifiable from current evidence (confidence capped)"},
		{"ruling unverifiable with basis", &notify.History{State: "history"},
			&notify.Steering{Ruling: "unverifiable", VerdictDate: "2026-07-28", Basis: "pvc metric read 3, uninterpretable"},
			"⚠️ adopted per operator correction of 2026-07-28, not verifiable from current evidence (confidence capped) — pvc metric read 3, uninterpretable"},
		{"ruling untested", &notify.History{State: "history"},
			&notify.Steering{Ruling: "untested", VerdictDate: "2026-07-28"},
			"⚠️ operator correction of 2026-07-28 could not be tested — its named evidence returned no usable data this round (confidence capped)"},
		{"ruling unruled", &notify.History{State: "history"},
			&notify.Steering{Ruling: "unruled"},
			"⚠️ operator correction present — check did not complete"},
	}
	for _, tc := range cases {
		f := testFinding()
		f.History, f.Steering = tc.h, tc.s
		render := firingCardBlocks
		if tc.s == nil { // history-only lines live on the thread detail
			render = firingDetailBlocks
		}
		if got := blocksJSON(t, render(f)); !strings.Contains(got, tc.want) {
			t.Errorf("%s: missing %q in:\n%s", tc.name, tc.want, got)
		}
	}
}

// TestFiringCardSlim pins the slim main card: the history line stays OFF the
// channel card (thread-only), while severity and confidence ride the meta
// line so the two numbers an operator triages by are channel-visible.
func TestFiringCardSlim(t *testing.T) {
	f := testFinding()
	f.History = &notify.History{State: "history",
		Verdict: &notify.HistoryVerdict{Kind: "correction", Age: "4d ago", Note: "pvc filling"}}
	card := blocksJSON(t, firingCardBlocks(f))
	if strings.Contains(card, "operator correction (4d ago)") {
		t.Errorf("history note must not render on the main card:\n%s", card)
	}
	if !strings.Contains(card, "· high · 85% ·") {
		t.Errorf("meta line missing severity/confidence:\n%s", card)
	}
}

// TestFiringDetailNotes covers the bounded operator-notes block in the thread
// detail view: the newest notes render verbatim, and overflow beyond the shown
// slice plus the producer-reported NotesMore folds into a single "+N more" tail.
func TestFiringDetailNotes(t *testing.T) {
	f := testFinding()
	f.History = &notify.History{State: "history", Notes: []notify.HistoryNote{
		{Kind: "observation", Age: "5d ago", Note: "canary contained it"},
	}, NotesMore: 2}
	got := blocksJSON(t, firingDetailBlocks(f))
	if !strings.Contains(got, "📝 observation (5d ago): canary contained it") || !strings.Contains(got, "+2 more") {
		t.Errorf("notes render missing:\n%s", got)
	}
}
