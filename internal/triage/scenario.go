// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Scenario is one drill scenario: a set of synthetic alerts.
type Scenario struct {
	ID     string          `yaml:"id"`
	Alerts []ScenarioAlert `yaml:"alerts"`
}

// ScenarioAlert is one alert spec; Repeat expands it into N alerts.
type ScenarioAlert struct {
	Labels        map[string]string `yaml:"labels"`
	Annotations   map[string]string `yaml:"annotations,omitempty"`
	Repeat        int               `yaml:"repeat,omitempty"`
	Spread        []string          `yaml:"spread,omitempty"`
	OffsetSeconds int               `yaml:"offset_seconds,omitempty"`
}

// ScriptedResponse is one scripted LLM response. MatchPromptHash is optional;
// when omitted, responses are returned in order.
type ScriptedResponse struct {
	MatchPromptHash string          `json:"match_prompt_hash,omitempty"`
	Response        json.RawMessage `json:"response"`
}

// LoadScenario reads a YAML scenario file.
func LoadScenario(path string) (*Scenario, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/QA harness reads caller-chosen paths by design
	if err != nil {
		return nil, fmt.Errorf("triage: read scenario %s: %w", path, err)
	}
	var sc Scenario
	if err := yaml.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("triage: parse scenario %s: %w", path, err)
	}
	return &sc, nil
}

// LoadResponses reads a sidecar JSON array of scripted LLM responses.
func LoadResponses(path string) ([]ScriptedResponse, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/QA harness reads caller-chosen paths by design
	if err != nil {
		return nil, fmt.Errorf("triage: read responses %s: %w", path, err)
	}
	var out []ScriptedResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("triage: parse responses %s: %w", path, err)
	}
	return out, nil
}
