// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/packs"
)

func testEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e, err := rules.NewEngine(context.Background(), nil,
		rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSystemPrompt_SelectsPackTemplates(t *testing.T) {
	s := &Skill{cfg: Config{Rules: testEngine(t)}}

	single := s.systemPrompt(rules.Decision{}, 1)
	if !strings.Contains(single, "single firing alert") {
		t.Errorf("1 alert should select the single_alert template, got: %.60s", single)
	}

	multi := s.systemPrompt(rules.Decision{}, 3)
	if !strings.Contains(multi, "correlated group of firing alerts") {
		t.Errorf("multi-alert default should be the correlated template, got: %.60s", multi)
	}

	storm := s.systemPrompt(rules.Decision{TemplateName: "storm"}, 25)
	if !strings.Contains(storm, "alert storm") {
		t.Errorf("decision template must win, got: %.60s", storm)
	}

	// No engine wired: built-in fallback.
	bare := &Skill{cfg: Config{}}
	if got := bare.systemPrompt(rules.Decision{}, 2); got != SystemPrompt {
		t.Error("nil engine must fall back to the built-in prompt")
	}
}

func TestShortCircuitResponse_MatchesLLMSchema(t *testing.T) {
	rule := rules.Rule{
		ID:          "ki.example",
		Kind:        rules.KindKnownIssue,
		Description: "Known conntrack exhaustion",
		Then: rules.Then{
			ShortCircuitLLM: true,
			RootCauseHint:   "conntrack table exhaustion",
			Severity:        "high",
			References:      []string{"https://example.org/kb/1"},
		},
	}
	d := rules.Decision{
		Rule:          &rule,
		ShortCircuit:  true,
		RootCauseHint: rule.Then.RootCauseHint,
		References:    rule.Then.References,
	}
	alerts := []store.Alert{{ID: "a1"}, {ID: "a2"}}

	raw, err := shortCircuitResponse(d, alerts)
	if err != nil {
		t.Fatal(err)
	}
	var resp llmResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("short-circuit output must parse as llmResponse: %v", err)
	}
	if resp.OverallIssue != "conntrack table exhaustion" || resp.Severity != "high" || resp.Confidence != 1.0 {
		t.Errorf("unexpected response: %+v", resp)
	}
	if len(resp.Alerts) != 2 {
		t.Errorf("every member alert must appear, got %d", len(resp.Alerts))
	}
}
