// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"
	"testing"
)

func TestRenderSentry_PopulatedSection(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout", Environment: "production",
		Issues: []SentryIssueView{
			{ExceptionType: "KeyError", FileLine: "app/checkout.py:88", Level: "error", UserCount: 7, RatePerMin: "5/min", New: true, Message: "missing tenant_id"},
			{ExceptionType: "TimeoutError", Culprit: "app.svc in call", Level: "error", UserCount: 50, RatePerMin: "12/min", New: false},
		},
		MoreCount: 2,
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if !strings.Contains(out, "Sentry issues (at triage time, project=checkout env=production") {
		t.Fatalf("missing headed section: %s", out)
	}
	// NEW issue first, with its file:line, level, users, rate, and message line.
	iNew := strings.Index(out, "[NEW] KeyError @ app/checkout.py:88")
	iChronic := strings.Index(out, "[chronic] TimeoutError")
	if iNew < 0 || iChronic < 0 || iNew > iChronic {
		t.Fatalf("NEW issue should render first with file:line: %s", out)
	}
	if !strings.Contains(out, "7 users") || !strings.Contains(out, "5/min") {
		t.Errorf("blast-radius fields missing: %s", out)
	}
	if !strings.Contains(out, "missing tenant_id") {
		t.Errorf("message line missing when present: %s", out)
	}
	// Chronic issue with no file:line falls back to its culprit.
	if !strings.Contains(out, "TimeoutError @ app.svc in call") {
		t.Errorf("culprit fallback missing: %s", out)
	}
	if !strings.Contains(out, "+2 more matched") {
		t.Errorf("MoreCount line missing: %s", out)
	}
}

func TestRenderSentry_OmittedWhenNil(t *testing.T) {
	out := UserPrompt(basePack(), "{}", nil, nil, nil, nil, nil, VerificationParams{})
	if strings.Contains(out, "Sentry issues") {
		t.Fatalf("section must be omitted when enrichment is nil: %s", out)
	}
	// Covers AE4: the reconciliation headline is also absent when Sentry is off — the
	// prompt is byte-identical to a Sentry-disabled build.
	if strings.Contains(out, "in-window error") {
		t.Errorf("no reconciliation headline expected when enrichment is nil: %s", out)
	}
}

// Covers AE1: a matched verdict prepends the neutral count headline ABOVE the issue
// list, with N = the FULL corroborating count.
func TestRenderSentry_MatchedHeadlineAboveIssues(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeOK,
		Reconciliation: &Reconciliation{Tag: tagMatched, CorroboratingIssueIDs: []string{"A", "B"}},
		Issues: []SentryIssueView{
			{ID: "A", ExceptionType: "KeyError", FileLine: "app/checkout.py:88", Level: "error", UserCount: 7, New: true},
		},
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	headline := "Sentry: 2 new in-window error(s) correlated"
	iHead := strings.Index(out, headline)
	if iHead < 0 {
		t.Fatalf("matched headline missing: %s", out)
	}
	iIssues := strings.Index(out, "Sentry issues (at triage time")
	if iIssues < 0 || iHead > iIssues {
		t.Errorf("headline must render ABOVE the issue list (head=%d issues=%d): %s", iHead, iIssues, out)
	}
}

// Covers AE3: an infra-only verdict with no chronic issues renders the neutral
// negative headline and no chronic suffix.
func TestRenderSentry_InfraOnlyHeadlineNoChronic(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeOK,
		Reconciliation: &Reconciliation{Tag: tagInfraOnly},
		Note:           "no Sentry issues for project=checkout in window",
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if !strings.Contains(out, "Sentry: no new in-window errors for this scope") {
		t.Fatalf("infra-only headline missing: %s", out)
	}
	if strings.Contains(out, "chronic present") {
		t.Errorf("no chronic suffix expected when chronicInWindow=0: %s", out)
	}
}

// Covers AE2: an infra-only verdict with chronic issues appends the ` (M chronic
// present)` suffix with the FULL pre-cap M, and the chronic issue still renders below.
func TestRenderSentry_InfraOnlyHeadlineWithChronic(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeOK,
		Reconciliation: &Reconciliation{Tag: tagInfraOnly, ChronicCount: 2},
		Issues: []SentryIssueView{
			{ID: "B", ExceptionType: "TimeoutError", Culprit: "app.svc in call", Level: "error", UserCount: 50, New: false},
		},
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if !strings.Contains(out, "Sentry: no new in-window errors for this scope (2 chronic present)") {
		t.Fatalf("infra-only headline with chronic suffix missing/incorrect: %s", out)
	}
	if !strings.Contains(out, "[chronic] TimeoutError") {
		t.Errorf("the chronic issue should still render below the headline: %s", out)
	}
}

// Covers AE5: no verdict (degraded → Reconciliation nil) renders no headline, while
// Spec 2's degraded Note still renders.
func TestRenderSentry_NoHeadlineOnDegraded(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeDegraded,
		Note: "Sentry query unavailable (rate-limited)", // Reconciliation nil
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if strings.Contains(out, "no new in-window errors") || strings.Contains(out, "in-window error(s) correlated") {
		t.Errorf("no reconciliation headline expected on a degraded look: %s", out)
	}
	if !strings.Contains(out, "Sentry query unavailable (rate-limited)") {
		t.Errorf("Spec 2's degraded note should still render: %s", out)
	}
}

// The headline is the prior P1 redaction surface: it must carry NO Sentry-controlled
// string (title/message/culprit/file:line), even with include_message ON (where the
// message legitimately renders in the issue line below, but never in the headline).
func TestRenderSentry_HeadlineCarriesNoSentryControlledStrings(t *testing.T) {
	const pii = "jane.doe@acme.com"
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeOK,
		Reconciliation: &Reconciliation{Tag: tagMatched, CorroboratingIssueIDs: []string{"A"}},
		Issues: []SentryIssueView{
			{ID: "A", ExceptionType: "KeyError", FileLine: "app/x.py:1", Culprit: "app.checkout in pay",
				Level: "error", UserCount: 1, New: true, Message: "missing tenant_id for " + pii},
		},
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	hStart := strings.Index(out, "Sentry: 1 new in-window error(s) correlated")
	iStart := strings.Index(out, "Sentry issues (at triage time")
	if hStart < 0 || iStart < 0 || hStart > iStart {
		t.Fatalf("expected headline above the issue section: %s", out)
	}
	headlineRegion := out[hStart:iStart] // exactly the headline line, before any issue render
	for _, controlled := range []string{"KeyError", "app/x.py:1", "app.checkout in pay", "missing tenant_id", pii} {
		if strings.Contains(headlineRegion, controlled) {
			t.Errorf("headline leaked Sentry-controlled string %q: %q", controlled, headlineRegion)
		}
	}
}

// KTD3: the stable Sentry issue id is persist-only — it rides the at-rest envelope
// and the MCP evidence pack, but must NEVER reach the LLM prompt. This pins the
// invariant as a regression gate (a future edit to renderSentryIssue that surfaced
// the id would re-open the distillation redaction boundary).
func TestRenderSentry_IssueIDNeverRendersIntoPrompt(t *testing.T) {
	const secretID = "issue-id-zzz999"
	e := &SentryEnrichment{
		Project: "checkout", Outcome: outcomeOK,
		Reconciliation: &Reconciliation{Tag: tagMatched, CorroboratingIssueIDs: []string{secretID}},
		Issues: []SentryIssueView{
			{ID: secretID, ExceptionType: "KeyError", FileLine: "app/x.py:1", Level: "error", UserCount: 1, New: true},
		},
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if strings.Contains(out, secretID) {
		t.Errorf("issue id is persist-only (KTD3) and must never render into the prompt: %s", out)
	}
}

// ADR-0011: the verdict is a presented signal, not a directive — no reconciliation
// steer clause may be added to the system prompt.
func TestSystemPrompt_NoReconciliationDirective(t *testing.T) {
	lower := strings.ToLower(SystemPrompt)
	for _, forbidden := range []string{tagMatched, tagInfraOnly, "reconciliation", "corroborat"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("SystemPrompt must carry no reconciliation directive (ADR-0011), found %q", forbidden)
		}
	}
}

func TestRenderSentry_NegativeAndDegradedNotes(t *testing.T) {
	zero := &SentryEnrichment{Project: "checkout", Environment: "production",
		Note: "no Sentry issues for project=checkout env=production in window"}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, zero, nil, VerificationParams{})
	if !strings.Contains(out, "Sentry issues (at triage time): no Sentry issues for project=checkout env=production in window") {
		t.Fatalf("negative-signal note not rendered: %s", out)
	}

	degraded := &SentryEnrichment{Project: "checkout", Note: "Sentry query unavailable (rate-limited)"}
	out = UserPrompt(basePack(), "{}", nil, nil, nil, degraded, nil, VerificationParams{})
	if !strings.Contains(out, "Sentry query unavailable (rate-limited)") {
		t.Fatalf("degraded note not rendered: %s", out)
	}
}

func TestRenderSentry_MessageOmittedWhenToggledOff(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout",
		Issues:  []SentryIssueView{{ExceptionType: "KeyError", FileLine: "a.py:1", Level: "error", UserCount: 1, New: true}}, // Message empty (toggle off)
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e, nil, VerificationParams{})
	if !strings.Contains(out, "[NEW] KeyError @ a.py:1") {
		t.Fatalf("issue line missing: %s", out)
	}
	// No stray indented message line beyond the issue line.
	if strings.Contains(out, "\n    ") {
		t.Errorf("no message line should render when message is empty: %s", out)
	}
}

func TestSystemPrompt_CarriesSentryWeightingClause(t *testing.T) {
	for _, want := range []string{
		"Sentry issues",
		"NEW-in-window issue",
		"file:line is where to look",
		"NOT application-code-driven",
	} {
		if !strings.Contains(SystemPrompt, want) {
			t.Errorf("SystemPrompt missing Sentry weighting fragment %q", want)
		}
	}
}
