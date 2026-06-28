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
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e)
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
	out := UserPrompt(basePack(), "{}", nil, nil, nil, nil)
	if strings.Contains(out, "Sentry issues") {
		t.Fatalf("section must be omitted when enrichment is nil: %s", out)
	}
}

func TestRenderSentry_NegativeAndDegradedNotes(t *testing.T) {
	zero := &SentryEnrichment{Project: "checkout", Environment: "production",
		Note: "no Sentry issues for project=checkout env=production in window"}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, zero)
	if !strings.Contains(out, "Sentry issues (at triage time): no Sentry issues for project=checkout env=production in window") {
		t.Fatalf("negative-signal note not rendered: %s", out)
	}

	degraded := &SentryEnrichment{Project: "checkout", Note: "Sentry query unavailable (rate-limited)"}
	out = UserPrompt(basePack(), "{}", nil, nil, nil, degraded)
	if !strings.Contains(out, "Sentry query unavailable (rate-limited)") {
		t.Fatalf("degraded note not rendered: %s", out)
	}
}

func TestRenderSentry_MessageOmittedWhenToggledOff(t *testing.T) {
	e := &SentryEnrichment{
		Project: "checkout",
		Issues:  []SentryIssueView{{ExceptionType: "KeyError", FileLine: "a.py:1", Level: "error", UserCount: 1, New: true}}, // Message empty (toggle off)
	}
	out := UserPrompt(basePack(), "{}", nil, nil, nil, e)
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
