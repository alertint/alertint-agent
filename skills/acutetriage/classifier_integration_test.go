// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// clsRun is the outcome of one classifierScenario run.
type clsRun struct {
	prompt string       // the triage prompt (with the rendered memory section)
	calls  int          // classifier fake call count
	st     *store.Store // the store, for audit/envelope assertions
	incID  string       // the analyzed incident id
}

// classifierScenario seeds a rung-3a recall: no exact-key priors, one weak
// prefilter candidate that is one group-label off. It runs one triage with the
// given classifier mode + a classifier fake.
func classifierScenario(t *testing.T, mode string, classifierResp json.RawMessage) clsRun {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())

	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-cls", map[string]string{"alertname": "DiskFull", "host": "web1"})

	reader := &stubMemoryReader{prefilter: []store.PriorFinding{
		{
			IncidentID: "inc_weak",
			GroupKey:   inc.GroupKey + ",extra=z", // ensure a different key; delta rendered by the classifier
			AnalyzedAt: time.Now().Add(-48 * time.Hour),
			Confidence: 0.8,
			RootCause:  "orphaned snapshots filling the volume",
		},
	}}
	triageFake := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	classifierFake := &fakeLLM{response: classifierResp}

	skill := acutetriage.New(acutetriage.Config{
		MinAlerts:      1,
		Memory:         reader,
		MemoryParams:   acutetriage.MemoryParams{LookbackDays: 90},
		Classifier:     classifierFake,
		ClassifierMode: mode,
	}, st, triageFake, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return clsRun{prompt: triageFake.lastUser, calls: classifierFake.calls, st: st, incID: inc.ID}
}

func classifierVerdictRows(t *testing.T, st *store.Store) (count int, payload string) {
	t.Helper()
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*), COALESCE(MAX(payload_json),'') FROM audit_log WHERE kind = 'memory.classifier_verdict'`,
	).Scan(&count, &payload); err != nil {
		t.Fatalf("query classifier audit: %v", err)
	}
	return count, payload
}

// TestRun_ClassifierOffMakesNoCall covers AE7 (off half): the default off mode
// makes no classifier call at all, even with a client wired.
func TestRun_ClassifierOffMakesNoCall(t *testing.T) {
	r := classifierScenario(t, "off", json.RawMessage(`{"verdict":"matched"}`))
	if r.calls != 0 {
		t.Errorf("classifier called %d times at mode off, want 0", r.calls)
	}
	if n, _ := classifierVerdictRows(t, r.st); n != 0 {
		t.Errorf("classifier_verdict audit rows = %d at mode off, want 0", n)
	}
	if strings.Contains(r.prompt, "LLM-matched") {
		t.Errorf("off mode must not tag the recall:\n%s", r.prompt)
	}
}

// TestRun_ClassifierShadowStaysDark covers AE7 (shadow half): the classifier runs
// and lands its verdict in the audit log, but the rendered recall is unchanged —
// still the deterministic "one label off" weak entry, never the LLM-matched tag.
func TestRun_ClassifierShadowStaysDark(t *testing.T) {
	r := classifierScenario(t, "shadow", json.RawMessage(`{"verdict":"matched"}`))
	if r.calls != 1 {
		t.Fatalf("classifier called %d times at mode shadow, want 1", r.calls)
	}
	if !strings.Contains(r.prompt, "weak signal") || strings.Contains(r.prompt, "LLM-matched") {
		t.Errorf("shadow render must stay deterministic-3a (weak signal, no LLM-matched tag):\n%s", r.prompt)
	}
	n, payload := classifierVerdictRows(t, r.st)
	if n != 1 {
		t.Fatalf("classifier_verdict audit rows = %d, want 1", n)
	}
	for _, want := range []string{`"verdict":"matched"`, `"candidates":["inc_weak"]`} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload missing %s: %s", want, payload)
		}
	}
}

// memorySection extracts the rendered "## Memory" block from a triage prompt, so
// two prompts for different incidents can be compared on the recall render alone
// (the surrounding evidence carries per-incident ids and timestamps).
func memorySection(prompt string) string {
	start := strings.Index(prompt, "## Memory")
	if start < 0 {
		return ""
	}
	rest := prompt[start:]
	if end := strings.Index(rest, "\n\nEvidence basis:"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// TestRun_ClassifierShadowRenderMatchesOff pins AE7's byte-identical claim: the
// rendered Memory section at mode shadow is exactly the one at mode off. Shadow's
// only durable effect is the audit row, never a change to what the model sees.
func TestRun_ClassifierShadowRenderMatchesOff(t *testing.T) {
	off := classifierScenario(t, "off", json.RawMessage(`{"verdict":"matched"}`))
	shadow := classifierScenario(t, "shadow", json.RawMessage(`{"verdict":"matched"}`))
	if a, b := memorySection(off.prompt), memorySection(shadow.prompt); a != b {
		t.Errorf("shadow memory render differs from off:\n--- off ---\n%s\n--- shadow ---\n%s", a, b)
	}
}

// TestRun_ClassifierOnTagsMatchedRecall covers AE7 (on half): once graduated, a
// matched verdict tags the recall render "LLM-matched, probably related".
func TestRun_ClassifierOnTagsMatchedRecall(t *testing.T) {
	r := classifierScenario(t, "on", json.RawMessage(`{"verdict":"matched"}`))
	if r.calls != 1 {
		t.Fatalf("classifier calls = %d, want 1", r.calls)
	}
	if !strings.Contains(r.prompt, "LLM-matched, probably related") {
		t.Errorf("on + matched must tag the recall render:\n%s", r.prompt)
	}
	// Persist-as-rendered: the tag the model saw is in the at-rest envelope too.
	var enrichmentJSON string
	if err := r.st.DB().QueryRowContext(context.Background(),
		`SELECT COALESCE(enrichment_json,'') FROM incidents WHERE id = ?`, r.incID).Scan(&enrichmentJSON); err != nil {
		t.Fatalf("scan envelope: %v", err)
	}
	if !strings.Contains(enrichmentJSON, "classifier_matched") {
		t.Errorf("matched tag must persist into the envelope:\n%s", enrichmentJSON)
	}
}

// TestRun_ClassifierNotStarvedByDemotedPriors: a key crowded with demoted same-key
// priors fills the rendered weak slots, but the classifier still judges the top
// rung-3a prefilter candidate (via topPrefilter) — the shadow verdict is not
// silently dropped for exactly the noisy keys where fuzzy matching matters most.
func TestRun_ClassifierNotStarvedByDemotedPriors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-starve", map[string]string{"alertname": "DiskFull", "host": "web1"})

	// Two demoted same-key priors (marks >= 2) — enough to fill maxWeakEntries — plus
	// one one-label-off prefilter candidate that the render cap would otherwise drop.
	reader := &stubMemoryReader{
		view: &store.MemoryView{
			GroupKey: inc.GroupKey,
			PriorFindings: []store.PriorFinding{
				{IncidentID: "demoted1", GroupKey: inc.GroupKey, ContradictionMarks: 2, RootCause: "stale a", Confidence: 0.4},
				{IncidentID: "demoted2", GroupKey: inc.GroupKey, ContradictionMarks: 2, RootCause: "stale b", Confidence: 0.4},
			},
		},
		prefilter: []store.PriorFinding{
			{IncidentID: "inc_weak", GroupKey: inc.GroupKey + ",extra=z", RootCause: "the real fuzzy match", Confidence: 0.8},
		},
	}
	classifierFake := &fakeLLM{response: json.RawMessage(`{"verdict":"matched"}`)}
	skill := acutetriage.New(acutetriage.Config{
		MinAlerts: 1, Memory: reader, MemoryParams: acutetriage.MemoryParams{LookbackDays: 90},
		Classifier: classifierFake, ClassifierMode: "shadow",
	}, st, &fakeLLM{response: validLLMResponse([]string{a1.ID})}, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if classifierFake.calls != 1 {
		t.Errorf("classifier calls = %d, want 1 (must not be starved by demoted priors)", classifierFake.calls)
	}
	n, payload := classifierVerdictRows(t, st)
	if n != 1 || !strings.Contains(payload, `"candidates":["inc_weak"]`) {
		t.Errorf("want one verdict row for inc_weak, got n=%d payload=%s", n, payload)
	}
}

// TestRun_ClassifierOnNoMatchLeavesRenderDeterministic: an on-mode no-match keeps
// the deterministic weak render (only a graduated match promotes the entry).
func TestRun_ClassifierOnNoMatchLeavesRenderDeterministic(t *testing.T) {
	r := classifierScenario(t, "on", json.RawMessage(`{"verdict":"no-match"}`))
	if strings.Contains(r.prompt, "LLM-matched") {
		t.Errorf("no-match must not tag the recall:\n%s", r.prompt)
	}
	if !strings.Contains(r.prompt, "weak signal") {
		t.Errorf("no-match keeps the deterministic weak render:\n%s", r.prompt)
	}
}
