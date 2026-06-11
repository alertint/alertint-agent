// SPDX-License-Identifier: FSL-1.1-ALv2

package rules_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/packs"
)

// staticSource is an in-memory RuleSource for tests.
type staticSource struct {
	name     string
	priority int
	pack     rules.Pack
}

func (s staticSource) Name() string  { return s.name }
func (s staticSource) Priority() int { return s.priority }
func (s staticSource) Load(_ context.Context) (*rules.Pack, error) {
	p := s.pack
	return &p, nil
}

func baselineEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e, err := rules.NewEngine(context.Background(), nil,
		rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0))
	if err != nil {
		t.Fatalf("load embedded baseline: %v", err)
	}
	return e
}

func TestEmbeddedBaseline_LoadsWithZeroConfig(t *testing.T) {
	e := baselineEngine(t)

	if len(e.Rules()) == 0 {
		t.Fatal("baseline pack has no rules")
	}
	for _, tmpl := range []string{"correlated", "single_alert", "storm", "recovery"} {
		if _, ok := e.Template(tmpl); !ok {
			t.Errorf("baseline pack is missing template %q", tmpl)
		}
	}
	if f := e.Flap(); f.WindowSeconds <= 0 || f.MinTransitions <= 0 {
		t.Errorf("flap defaults not loaded: %+v", f)
	}
	labels := strings.Join(e.GroupLabels(), ",")
	for _, want := range []string{"cluster", "service", "env"} {
		if !strings.Contains(labels, want) {
			t.Errorf("GroupLabels() = %q, want it to include %q", labels, want)
		}
	}
}

// TestStreamFixtures runs every synthetic alert-stream fixture against the
// embedded baseline pack. This is the pack QA harness: add a stream file
// and an expectation to cover new rules.
func TestStreamFixtures(t *testing.T) {
	e := baselineEngine(t)
	files, err := filepath.Glob(filepath.Join("testdata", "streams", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no stream fixtures found: %v", err)
	}
	base := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	for _, f := range files {
		fix, err := rules.LoadStreamFixture(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fix.Name, func(t *testing.T) {
			if err := fix.Check(e, base); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestEngine_SourcePriorityOverridesRuleByID(t *testing.T) {
	base := staticSource{name: "low", priority: 0, pack: rules.Pack{
		Meta: rules.PackMeta{Name: "low", Version: "1"},
		Rules: []rules.Rule{{
			ID: "shared.rule", Kind: rules.KindCorrelation, Updated: "2026-06-11",
			When: rules.When{MinAlerts: 1},
			Then: rules.Then{RootCauseHint: "from-low"},
		}},
	}}
	override := staticSource{name: "high", priority: 10, pack: rules.Pack{
		Meta: rules.PackMeta{Name: "high", Version: "1"},
		Rules: []rules.Rule{{
			ID: "shared.rule", Kind: rules.KindCorrelation, Updated: "2026-06-11",
			When: rules.When{MinAlerts: 1},
			Then: rules.Then{RootCauseHint: "from-high"},
		}},
	}}

	e, err := rules.NewEngine(context.Background(), nil, override, base) // order must not matter
	if err != nil {
		t.Fatal(err)
	}
	d := e.EvaluateIncident([]store.Alert{{ID: "a", Status: "firing", Labels: map[string]string{"alertname": "X"}}})
	if d.Rule == nil || d.RootCauseHint != "from-high" {
		t.Fatalf("want rule from high-priority source, got %+v", d)
	}
}

func TestEngine_RejectsInvalidPackWithActionableError(t *testing.T) {
	bad := staticSource{name: "bad", priority: 0, pack: rules.Pack{
		Meta: rules.PackMeta{Name: "bad", Version: "1"},
		Rules: []rules.Rule{{
			ID: "bad.window", Kind: rules.KindCorrelation, Window: "fortnight",
			When: rules.When{MinAlerts: 1}, Updated: "2026-06-11",
		}},
	}}
	_, err := rules.NewEngine(context.Background(), nil, bad)
	if err == nil {
		t.Fatal("want error for invalid rule, got nil")
	}
	for _, want := range []string{"bad.window", "window", "not a valid duration"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
}

func TestEngine_RejectsUnresolvedTemplateReference(t *testing.T) {
	src := staticSource{name: "s", priority: 0, pack: rules.Pack{
		Meta: rules.PackMeta{Name: "s", Version: "1"},
		Rules: []rules.Rule{{
			ID: "needs.template", Kind: rules.KindCorrelation, Updated: "2026-06-11",
			When: rules.When{MinAlerts: 1},
			Then: rules.Then{AnalysisTemplate: "nope"},
		}},
	}}
	_, err := rules.NewEngine(context.Background(), nil, src)
	if err == nil || !strings.Contains(err.Error(), `template "nope" not found`) {
		t.Fatalf("want unresolved-template error, got %v", err)
	}
}

func TestEvaluateIncident_KnownIssueShortCircuit(t *testing.T) {
	src := staticSource{name: "ki", priority: 0, pack: rules.Pack{
		Meta: rules.PackMeta{Name: "ki", Version: "1"},
		Rules: []rules.Rule{{
			ID: "ki.cni-conntrack", Kind: rules.KindKnownIssue, Updated: "2026-06-11",
			When: rules.When{All: []rules.Predicate{{Label: "alertname", Op: "equals", Value: "ConntrackTableFull"}}},
			Then: rules.Then{
				ShortCircuitLLM: true,
				RootCauseHint:   "conntrack table exhaustion; raise nf_conntrack_max",
				Severity:        "high",
				References:      []string{"https://example.org/kb/conntrack"},
			},
			AppliesTo: rules.AppliesTo{Component: "cni", Versions: []string{"1.2.*"}},
		}},
	}}
	e, err := rules.NewEngine(context.Background(), nil, src)
	if err != nil {
		t.Fatal(err)
	}

	matching := []store.Alert{{
		ID: "a1", Status: "firing",
		Labels: map[string]string{"alertname": "ConntrackTableFull", "component": "cni", "version": "1.2.7"},
	}}
	d := e.EvaluateIncident(matching)
	if d.Rule == nil || !d.ShortCircuit || d.RootCauseHint == "" {
		t.Fatalf("want short-circuit decision, got %+v", d)
	}

	wrongVersion := []store.Alert{{
		ID: "a2", Status: "firing",
		Labels: map[string]string{"alertname": "ConntrackTableFull", "component": "cni", "version": "2.0.0"},
	}}
	if d := e.EvaluateIncident(wrongVersion); d.Rule != nil {
		t.Fatalf("applies_to.versions should exclude 2.0.0, got %+v", d)
	}
}

func TestEvaluateIncident_NilEngineIsSafe(t *testing.T) {
	var e *rules.Engine
	if d := e.EvaluateIncident([]store.Alert{{ID: "a"}}); d.Rule != nil {
		t.Fatalf("nil engine must return empty decision, got %+v", d)
	}
}
