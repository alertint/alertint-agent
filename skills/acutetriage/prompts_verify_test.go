// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// strongRecallFixture is a fixed, deterministic MemoryEnrichment with a
// folded strong entry — adapted from memory_test.go's
// TestRenderMemory_FoldedStrongEntry fixture, reused here for the golden
// capture and the call-2 relocation tests.
func strongRecallFixture() *MemoryEnrichment {
	return &MemoryEnrichment{
		GroupKey:       "cluster=prod-eu1,namespace=backups,service=backup-agent",
		Rung:           "2",
		PriorCount:     2,
		Episodes:       14,
		FirstSeen:      time.Date(2026, 6, 25, 2, 1, 0, 0, time.UTC),
		LastSeen:       time.Date(2026, 7, 8, 2, 3, 0, 0, time.UTC),
		CadenceMedianS: 86400,
		LatestAgo:      "1d ago",
		Strong: &RecalledEntry{
			IncidentID: "inc_0033", AnalyzedAt: time.Date(2026, 7, 8, 2, 5, 0, 0, time.UTC),
			Confidence: 0.70, RootCause: "backup rotation misconfigured", Episodes: 14,
		},
	}
}

// minimalRound is a minimal VerificationRound fixture for callTwoPrompt tests.
func minimalRound() *VerificationRound {
	return &VerificationRound{
		Queries: []VerificationQuery{
			{Kind: kindUpRatio, Source: "floor", Why: "peer-scope health", Outcome: OutcomeFetched, Result: `up 34/37 in {namespace="x"}`},
		},
	}
}

// userPromptKillSwitchGolden was captured from the CURRENT (pre-Task-5)
// 7-arg UserPrompt output for basePack()+strongRecallFixture(), BEFORE
// UserPrompt's implementation was touched for this task — see
// task-5-report.md for the exact capture sequence. verify.Enabled=false must
// reproduce this byte-for-byte (the kill switch).
const userPromptKillSwitchGolden = "Analyze the following correlated incident.\n\nEvidence:\n{}\n\nShared labels: namespace=prod\nAlert count: 2\nWindow: 0s\n\n## Memory (prior findings for this incident's key)\n2 prior findings for this key, latest 1d ago. Prior findings are hypotheses from past analyses — they are NOT verified facts and NOT live evidence.\n\n- [folded ×14] seen 14 episodes, ~daily cadence (first 2026-06-25, last 2026-07-08)\n  prior hypothesis (confidence 0.70, unconfirmed): backup rotation misconfigured\n\nAfter weighing this incident's own evidence, add a \"memory_verdict\" field to your JSON response judging the folded prior hypothesis above: \"confirms\" if this incident's evidence supports that root cause, \"refutes\" if the evidence points to a different cause, or \"silent\" if the evidence is insufficient to tell. Do NOT raise your confidence on the strength of the recalled hypothesis alone.\n\nEvidence basis: ANNOTATIONS ONLY — no live logs, metrics, deploy/config changes, or Sentry errors were retrieved for this incident, so every conclusion below rests on alert labels and annotations alone. Treat any root-cause or causal-direction claim (which alert is primary vs downstream) as an unverified hypothesis: prefer the \"correlated\" role over confident \"primary\"/\"downstream\" assignments unless the ordering is self-evident from the annotations, and keep confidence at or below 0.6. Any prior findings recalled in the Memory section are past hypotheses, NOT live evidence — they do not lift this annotations-only basis or raise the confidence ceiling.\n\nRespond with JSON only."

// T5 golden half: verification disabled → byte-identical to the pre-feature
// prompt. The golden constant above was captured from the real, unmodified
// UserPrompt BEFORE its signature/implementation changed for this task.
func TestUserPromptKillSwitchByteIdentical(t *testing.T) {
	m := strongRecallFixture()
	got := UserPrompt(basePack(), "{}", nil, nil, nil, nil, m, VerificationParams{Enabled: false})
	if got != userPromptKillSwitchGolden {
		t.Fatalf("kill-switch output diverged from pre-feature golden:\n--- got ---\n%s\n--- want ---\n%s", got, userPromptKillSwitchGolden)
	}
}

// Enabled: instruction present, schema example includes both kinds, and the
// scope-inflation MUST-verify line (R7) is present.
func TestUserPromptVerificationInstruction(t *testing.T) {
	got := UserPrompt(basePack(), "{}", nil, nil, nil, nil, nil, VerificationParams{Enabled: true, MaxQueries: 4})
	for _, want := range []string{`"verification"`, `"promql"`, `"incidents_in_window"`,
		"MUST include", "disprove"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in instruction:\n%s", want, got)
		}
	}
}

// Disabled: no verification instruction at all — the kill switch must be
// total, not just byte-identical for this one fixture.
func TestUserPromptVerificationInstructionAbsentWhenDisabled(t *testing.T) {
	got := UserPrompt(basePack(), "{}", nil, nil, nil, nil, nil, VerificationParams{Enabled: false})
	if strings.Contains(got, `"verification"`) {
		t.Fatalf("verification instruction must not render when disabled:\n%s", got)
	}
}

// R16: with verification enabled, memory verdict request is NOT in call 1…
func TestMemoryVerdictMovesToCallTwo(t *testing.T) {
	m := strongRecallFixture()
	c1 := UserPrompt(basePack(), "{}", nil, nil, nil, nil, m, VerificationParams{Enabled: true, MaxQueries: 4})
	if strings.Contains(c1, `"memory_verdict"`) {
		t.Fatal("verdict request must not render in call 1 when verification is enabled")
	}
	// …and IS in call 2.
	c2 := callTwoPrompt(c1, json.RawMessage(`{"overall_issue":"x","confidence":0.9}`), minimalRound(), m)
	if !strings.Contains(c2, `"memory_verdict"`) {
		t.Fatal("verdict request must render in call 2")
	}
}

// Kill-switch path: verification disabled keeps the verdict request in call 1
// (unchanged behavior), matching the golden fixture above.
func TestMemoryVerdictStaysInCallOneWhenVerificationDisabled(t *testing.T) {
	m := strongRecallFixture()
	c1 := UserPrompt(basePack(), "{}", nil, nil, nil, nil, m, VerificationParams{Enabled: false})
	if !strings.Contains(c1, `"memory_verdict"`) {
		t.Fatal("verdict request must stay in call 1 on the kill-switch path")
	}
}

// Call 2 structure: prefix byte-identical (prompt-cache), results outrank, complete schema demanded.
func TestCallTwoPromptShape(t *testing.T) {
	c1 := "CALL-ONE-PROMPT"
	c2 := callTwoPrompt(c1, json.RawMessage(`{"a":1}`), minimalRound(), nil)
	if !strings.HasPrefix(c2, c1) {
		t.Fatal("call 2 must start with call 1's prompt byte-identical (R5 cache prefix)")
	}
	for _, want := range []string{"Verification results (computed, read-only)",
		"do not defend", "outrank", "SAME JSON schema"} {
		if !strings.Contains(c2, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

// callTwoPrompt must not ask for a memory_verdict when there is no strong
// recall to judge.
func TestCallTwoPromptOmitsMemoryVerdictWhenNoMemory(t *testing.T) {
	c2 := callTwoPrompt("CALL-ONE-PROMPT", json.RawMessage(`{"a":1}`), minimalRound(), nil)
	if strings.Contains(c2, `"memory_verdict"`) {
		t.Fatalf("no memory recalled: must not request a memory_verdict:\n%s", c2)
	}
}
