// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestHealthDefaults(t *testing.T) {
	d := Defaults()
	if d.Health.LLMIdleProbeAfterSeconds != 300 || d.Health.BroadcastAfterSeconds != 300 {
		t.Fatalf("health defaults = %+v, want 300/300", d.Health)
	}
}

func TestHealthLoadsAndValidates(t *testing.T) {
	yaml := minimalValidYAML + `
health:
  llm_idle_probe_after_seconds: 120
  broadcast_after_seconds: 60
`
	cfg, err := LoadFrom(strings.NewReader(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Health.LLMIdleProbeAfterSeconds != 120 || cfg.Health.BroadcastAfterSeconds != 60 {
		t.Fatalf("health = %+v", cfg.Health)
	}
}

func TestHealthRejectsNonPositive(t *testing.T) {
	for _, body := range []string{
		"health: {llm_idle_probe_after_seconds: 0}",
		"health: {broadcast_after_seconds: -5}",
	} {
		yaml := minimalValidYAML + "\n" + body
		_, err := LoadFrom(strings.NewReader(yaml), "test.yaml")
		if err == nil || !strings.Contains(err.Error(), "health:") || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("body %q: err = %v, want health: ... must be positive", body, err)
		}
	}
}
