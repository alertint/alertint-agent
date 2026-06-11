// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"fmt"
	"os"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"gopkg.in/yaml.v3"
)

// Fixture harness for rule evaluation: a synthetic alert stream plus the
// decision the rule set is expected to make. Engine tests run every
// fixture under testdata/streams/; the same loader is the QA tool for
// authoring new packs — write a stream, state the expectation, run tests.

// StreamFixture is one synthetic alert-stream scenario.
type StreamFixture struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description,omitempty"`
	Alerts      []FixtureAlert `yaml:"alerts"`
	Expect      Expectation    `yaml:"expect"`
}

// FixtureAlert is a compact alert spec; OffsetSeconds places it on the
// incident timeline relative to the fixture's start.
type FixtureAlert struct {
	Labels        map[string]string `yaml:"labels"`
	Annotations   map[string]string `yaml:"annotations,omitempty"`
	Status        string            `yaml:"status,omitempty"` // default "firing"
	OffsetSeconds int               `yaml:"offset_seconds,omitempty"`
	// Repeat expands this entry into N alerts; "service" label values get
	// a -<i> suffix when Spread is set, so storm fixtures stay short.
	Repeat int      `yaml:"repeat,omitempty"`
	Spread []string `yaml:"spread,omitempty"` // labels to make distinct per repeat
}

// Expectation states the decision the engine must reach for the stream.
type Expectation struct {
	RuleID       string `yaml:"rule_id,omitempty"` // "" = no rule may match
	Template     string `yaml:"template,omitempty"`
	Suppress     bool   `yaml:"suppress,omitempty"`
	ShortCircuit bool   `yaml:"short_circuit,omitempty"`
}

// LoadStreamFixture reads one fixture file.
func LoadStreamFixture(path string) (*StreamFixture, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/QA harness reads caller-chosen fixture files by design
	if err != nil {
		return nil, fmt.Errorf("fixture %s: %w", path, err)
	}
	var f StreamFixture
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("fixture %s: parse: %w", path, err)
	}
	if f.Name == "" {
		return nil, fmt.Errorf("fixture %s: name is required", path)
	}
	if len(f.Alerts) == 0 {
		return nil, fmt.Errorf("fixture %s: alerts must not be empty", path)
	}
	return &f, nil
}

// BuildAlerts expands the fixture into store.Alert values anchored at base.
func (f *StreamFixture) BuildAlerts(base time.Time) []store.Alert {
	var out []store.Alert
	for i, fa := range f.Alerts {
		n := fa.Repeat
		if n <= 0 {
			n = 1
		}
		for j := 0; j < n; j++ {
			labels := make(map[string]string, len(fa.Labels))
			for k, v := range fa.Labels {
				labels[k] = v
			}
			for _, spreadLabel := range fa.Spread {
				if v, ok := labels[spreadLabel]; ok {
					labels[spreadLabel] = fmt.Sprintf("%s-%d", v, j)
				}
			}
			status := fa.Status
			if status == "" {
				status = "firing"
			}
			at := base.Add(time.Duration(fa.OffsetSeconds+j) * time.Second)
			out = append(out, store.Alert{
				ID:          fmt.Sprintf("%s-%d-%d", f.Name, i, j),
				Fingerprint: fmt.Sprintf("%s-%d-%d", f.Name, i, j),
				Status:      status,
				Labels:      labels,
				Annotations: fa.Annotations,
				StartsAt:    at,
				ReceivedAt:  at,
			})
		}
	}
	return out
}

// Check evaluates the fixture against the engine and returns an error
// describing the first mismatch, or nil when the expectation holds.
func (f *StreamFixture) Check(e *Engine, base time.Time) error {
	d := e.EvaluateIncident(f.BuildAlerts(base))
	gotRule := ""
	if d.Rule != nil {
		gotRule = d.Rule.ID
	}
	if gotRule != f.Expect.RuleID {
		return fmt.Errorf("fixture %s: matched rule %q, want %q", f.Name, gotRule, f.Expect.RuleID)
	}
	if d.TemplateName != f.Expect.Template {
		return fmt.Errorf("fixture %s: template %q, want %q", f.Name, d.TemplateName, f.Expect.Template)
	}
	if d.Suppress != f.Expect.Suppress {
		return fmt.Errorf("fixture %s: suppress = %v, want %v", f.Name, d.Suppress, f.Expect.Suppress)
	}
	if d.ShortCircuit != f.Expect.ShortCircuit {
		return fmt.Errorf("fixture %s: short_circuit = %v, want %v", f.Name, d.ShortCircuit, f.Expect.ShortCircuit)
	}
	return nil
}
