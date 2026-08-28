// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
)

// engineWithHint builds a one-rule *rules.Engine matching alertname=TargetDown
// (the alert used by the stage-1 corpus tests) whose then.root_cause_hint
// carries hint — the "steering rule" fixture for the evidence-selection tests.
func engineWithHint(t *testing.T, hint string) *rules.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte("name: test\nversion: \"0.0.1\"\nupdated: \"2026-07-24\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ruleYAML := `rules:
  - id: test.steering-hint
    kind: correlation
    description: Steering hint for TargetDown
    when:
      all:
        - label: alertname
          op: equals
          value: TargetDown
    then:
      root_cause_hint: ` + hint + `
    updated: "2026-07-24"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "01-hint.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := rules.NewEngine(context.Background(), nil, rules.NewLocalDirSource(dir, 0))
	if err != nil {
		t.Fatalf("build rule engine: %v", err)
	}
	return e
}

func TestParseExpectation(t *testing.T) {
	e, err := parseExpectation(json.RawMessage(`{"cause_alert":"NodeNetworkInterfaceFlapping","cause_series":["node_network_up"],"severity_rank":"medium","must_mention":["NIC","worker-14"],"must_not_conclude":["AZ outage"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.CauseAlert != "NodeNetworkInterfaceFlapping" || len(e.MustMention) != 2 {
		t.Fatalf("%+v", e)
	}

	if _, err := parseExpectation(json.RawMessage(`{"cause_alert":"X"}`)); err == nil {
		t.Fatal("expectation with no graded field accepted")
	}
	if _, err := parseExpectation(json.RawMessage(`{"must_mention":["x"],"bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := parseExpectation(nil); err == nil {
		t.Fatal("missing expectation accepted")
	}
}

// R6: MustMention/MustNotConclude are grading vocabulary — even present on
// the input Expectation, they must never surface in the synthesized note
// (which becomes GoverningVerdict.Note and renders straight into the triage
// prompt). CauseAlert is not grading vocabulary and stays.
func TestSynthesizeNote(t *testing.T) {
	e := Expectation{CauseAlert: "NodeNetworkInterfaceFlapping",
		MustMention: []string{"NIC", "worker-14"}, MustNotConclude: []string{"AZ outage"}}
	got := synthesizeNote("correction", e)
	want := "corrected: cause NodeNetworkInterfaceFlapping"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := synthesizeNote("confirmation", Expectation{MustMention: []string{"disk full"}}); got != "confirmed" {
		t.Fatalf("got %q", got)
	}
}

// TestSynthesizeNote_CappedBelowStoreLimit covers a schema-valid expectation
// with a very long cause_alert: the synthesized note alone must never exceed
// the store's write-boundary cap, or an atomic capture fails for a caller who
// never opted into a free-text note. MustMention no longer contributes to the
// note (R6), so the long input has to come from CauseAlert to still exercise
// the truncation path.
func TestSynthesizeNote_CappedBelowStoreLimit(t *testing.T) {
	e := Expectation{CauseAlert: strings.Repeat("x", 6000)}
	got := synthesizeNote("correction", e)
	if n := utf8.RuneCountInString(got); n > store.MaxAnnotationNoteChars {
		t.Fatalf("synthesized note is %d chars, exceeds store cap %d", n, store.MaxAnnotationNoteChars)
	}
}

// Belt and suspenders (R6): a real operator/agent would supply distinctive
// MustMention/MustNotConclude content, not the literal snake_case JSON key
// names — assert the actual strings never surface, not just the keys.
func TestSynthesizeNote_NeverLeaksGradingVocabulary(t *testing.T) {
	e := Expectation{
		MustMention:     []string{"distinctivemention123"},
		MustNotConclude: []string{"distinctiveconclude456"},
	}
	for _, verdict := range []string{"correction", "confirmation"} {
		got := synthesizeNote(verdict, e)
		for _, leaked := range []string{"distinctivemention123", "distinctiveconclude456"} {
			if strings.Contains(got, leaked) {
				t.Errorf("synthesizeNote(%q, ...) = %q leaked grading vocabulary %q", verdict, got, leaked)
			}
		}
	}
}

func TestStage1Corpus_RedWithoutSteeringRule_GreenWith(t *testing.T) {
	alerts := []store.Alert{{ID: "a1", Fingerprint: "f1", Status: "firing",
		Labels:      map[string]string{"alertname": "TargetDown", "namespace": "prod", "instance": "worker-14"},
		Annotations: map[string]string{"summary": "target down"}}}
	inc := store.Incident{ID: "i1", GroupKey: "namespace=prod"}
	e := Expectation{CauseSeries: []string{"node_network_up"},
		MustMention: []string{"worker-14"}, MustNotConclude: []string{"AZ outage"}}

	// No steering rule: node_network_up appears nowhere deterministic → red.
	plain := &Skill{cfg: Config{WindowSeconds: 300}, logger: slog.Default()}
	d := diffExpectationAgainstPack(e, plain.stage1Corpus(inc, alerts, frozenEnvelope{}))
	if len(d.MissingSeries) != 1 || d.MissingSeries[0] != "node_network_up" {
		t.Fatalf("want node_network_up missing, got %+v", d)
	}
	if len(d.MissingSubjects) != 0 { // worker-14 is an alert label value → present
		t.Fatalf("worker-14 should be present: %+v", d)
	}

	// A rules engine whose matched template/hint names the series → green.
	steered := &Skill{cfg: Config{WindowSeconds: 300, Rules: engineWithHint(t, "check node_network_up on the flapping NIC")}, logger: slog.Default()}
	d2 := diffExpectationAgainstPack(e, steered.stage1Corpus(inc, alerts, frozenEnvelope{}))
	if len(d2.MissingSeries) != 0 {
		t.Fatalf("steering rule ignored: %+v", d2)
	}
}

func TestDiffExpectationAgainstFinding(t *testing.T) {
	e := Expectation{SeverityRank: "medium", MustMention: []string{"NIC", "worker-14"}, MustNotConclude: []string{"AZ outage"}}
	good := llmResponse{AnalysisName: "NIC flap on worker-14", OverallIssue: "flapping NIC on worker-14", Severity: "high"}
	miss, bad, warns := diffExpectationAgainstFinding(e, good)
	if len(miss) != 0 || len(bad) != 0 {
		t.Fatalf("good finding graded red: %v %v", miss, bad)
	}
	if len(warns) != 1 {
		t.Fatalf("severity mismatch must warn: %v", warns)
	} // high != medium

	wrong := llmResponse{OverallIssue: "regional AZ outage in eu-west-1"}
	miss, bad, _ = diffExpectationAgainstFinding(e, wrong)
	if len(miss) != 2 || len(bad) != 1 {
		t.Fatalf("wrong finding graded green: %v %v", miss, bad)
	}
}

func TestLintExpectationVerifiable(t *testing.T) {
	e := Expectation{CauseSeries: []string{"node_network_up"}, MustNotConclude: []string{"x"}}
	if w := lintExpectationVerifiable("correction", e, frozenEnvelope{}, nil); len(w) != 1 ||
		!strings.Contains(w[0], "expectation unverifiable") {
		t.Fatalf("lint silent on unverifiable series: %v", w)
	}
	widened := []VerificationQuery{{Kind: "promql", Source: "capture", Expr: `node_network_up{instance="worker-14"}`}}
	if w := lintExpectationVerifiable("correction", e, frozenEnvelope{}, widened); len(w) != 0 {
		t.Fatalf("lint fired though widening covers the series: %v", w)
	}
}

// TestLintExpectationVerifiable_FailedFetchStillUnverifiable covers a
// widening fetch that failed (unreachable Prometheus): the query's Expr
// still names the series, but a failed fetch is not evidence, so the lint
// must still fire — a permanently-unreachable series must never silently
// pass as "verifiable".
func TestLintExpectationVerifiable_FailedFetchStillUnverifiable(t *testing.T) {
	e := Expectation{CauseSeries: []string{"node_network_up"}, MustNotConclude: []string{"x"}}
	failed := []VerificationQuery{{Kind: "promql", Source: "capture", Expr: "node_network_up", Outcome: OutcomeFailed, Result: "unavailable (timeout)"}}
	w := lintExpectationVerifiable("correction", e, frozenEnvelope{}, failed)
	if len(w) != 1 || !strings.Contains(w[0], "expectation unverifiable") {
		t.Fatalf("a failed widening fetch must not satisfy the verifiability lint: %v", w)
	}
}

// TestLintExpectationVerifiable_InvalidQueryNotVerifiable covers the third
// non-evidence Outcome (alongside failed/degraded above): a query that never
// executed at all because it was locally invalid still names the series in
// its Expr, but that is not evidence the series is verifiable — the lint
// must still fire.
func TestLintExpectationVerifiable_InvalidQueryNotVerifiable(t *testing.T) {
	frozen := frozenEnvelope{Verification: &VerificationEnrichment{Rounds: []VerificationRound{{
		Queries: []VerificationQuery{{Expr: "pvc_bytes", Outcome: OutcomeInvalid}},
	}}}}
	warnings := lintExpectationVerifiable("correction", Expectation{CauseSeries: []string{"pvc_bytes"}}, frozen, nil)
	if len(warnings) == 0 {
		t.Fatal("invalid query must not make cause_series verifiable")
	}
}

// TestLintExpectationVerifiable_AnchorlessCorrectionWarns covers Fix 4: a
// correction naming only must_not_conclude (a fully valid expectation per
// parseExpectation) can never generate a single steering query — buildSteeringQueries
// draws exclusively from cause_series/widened evidence — so it permanently
// confidence-caps every future triage on the group key with no way out. The
// operator must be warned about this at capture time.
func TestLintExpectationVerifiable_AnchorlessCorrectionWarns(t *testing.T) {
	e := Expectation{MustNotConclude: []string{"AZ outage"}}
	w := lintExpectationVerifiable("correction", e, frozenEnvelope{}, nil)
	if len(w) != 1 || !strings.Contains(w[0], "no evidence anchors") {
		t.Fatalf("anchorless correction must warn, got: %v", w)
	}
}

// TestLintExpectationVerifiable_AnchorlessConfirmationSilent: the anchorless
// warning is specific to corrections (only a correction steers); a
// confirmation naming no anchors is unremarkable and must not warn.
func TestLintExpectationVerifiable_AnchorlessConfirmationSilent(t *testing.T) {
	e := Expectation{MustNotConclude: []string{"AZ outage"}}
	if w := lintExpectationVerifiable("confirmation", e, frozenEnvelope{}, nil); len(w) != 0 {
		t.Fatalf("an anchorless confirmation must not warn (only corrections steer), got: %v", w)
	}
}

// TestLintExpectationVerifiable_AnchorPresenceSuppressesWarning covers each
// of the three anchor kinds individually: cause_alert alone, cause_series
// alone (backed so the OTHER unverifiable-series warning stays silent too),
// and widened evidence alone — any one of them must suppress the
// no-anchors warning.
func TestLintExpectationVerifiable_AnchorPresenceSuppressesWarning(t *testing.T) {
	base := Expectation{MustNotConclude: []string{"AZ outage"}}

	withCauseAlert := base
	withCauseAlert.CauseAlert = "KubePersistentVolumeFillingUp"
	if w := lintExpectationVerifiable("correction", withCauseAlert, frozenEnvelope{}, nil); anyContains(w, "no evidence anchors") {
		t.Fatalf("cause_alert alone must suppress the no-anchors warning, got: %v", w)
	}

	withCauseSeries := base
	withCauseSeries.CauseSeries = []string{"pvc_bytes"}
	backed := []VerificationQuery{{Kind: "promql", Source: "capture", Expr: "pvc_bytes", Outcome: OutcomeFetched, Result: "0.01"}}
	if w := lintExpectationVerifiable("correction", withCauseSeries, frozenEnvelope{}, backed); anyContains(w, "no evidence anchors") {
		t.Fatalf("cause_series alone must suppress the no-anchors warning, got: %v", w)
	}

	widenedOnly := []VerificationQuery{{Kind: "promql", Source: "capture", Expr: "up"}}
	if w := lintExpectationVerifiable("correction", base, frozenEnvelope{}, widenedOnly); anyContains(w, "no evidence anchors") {
		t.Fatalf("widened evidence alone must suppress the no-anchors warning, got: %v", w)
	}
}

func anyContains(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
