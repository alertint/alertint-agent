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

func TestSynthesizeNote(t *testing.T) {
	e := Expectation{CauseAlert: "NodeNetworkInterfaceFlapping",
		MustMention: []string{"NIC", "worker-14"}, MustNotConclude: []string{"AZ outage"}}
	got := synthesizeNote("correction", e)
	want := "corrected: cause NodeNetworkInterfaceFlapping; must mention NIC, worker-14; not AZ outage"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := synthesizeNote("confirmation", Expectation{MustMention: []string{"disk full"}}); got != "confirmed: must mention disk full" {
		t.Fatalf("got %q", got)
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
	if w := lintExpectationVerifiable(e, frozenEnvelope{}, nil); len(w) != 1 ||
		!strings.Contains(w[0], "expectation unverifiable") {
		t.Fatalf("lint silent on unverifiable series: %v", w)
	}
	widened := []VerificationQuery{{Kind: "promql", Source: "capture", Expr: `node_network_up{instance="worker-14"}`}}
	if w := lintExpectationVerifiable(e, frozenEnvelope{}, widened); len(w) != 0 {
		t.Fatalf("lint fired though widening covers the series: %v", w)
	}
}
