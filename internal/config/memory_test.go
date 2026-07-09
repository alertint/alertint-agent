// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestMemory_DefaultsApplied(t *testing.T) {
	d := Defaults().Memory
	if d.AttachWindowMinutes != 30 {
		t.Errorf("AttachWindowMinutes = %d, want 30", d.AttachWindowMinutes)
	}
	if d.JudgmentCeilingHours != 4 {
		t.Errorf("JudgmentCeilingHours = %d, want 4", d.JudgmentCeilingHours)
	}
	if d.OccurrenceCap != 100 {
		t.Errorf("OccurrenceCap = %d, want 100", d.OccurrenceCap)
	}
	if d.LookbackDays != 90 {
		t.Errorf("LookbackDays = %d, want 90", d.LookbackDays)
	}
}

func TestMemory_DefaultsFillWhenBlockOmitted(t *testing.T) {
	cfg, err := LoadFrom(strings.NewReader(minimalValidYAML), "test.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Memory.AttachWindowMinutes != 30 || cfg.Memory.LookbackDays != 90 {
		t.Errorf("memory defaults not filled when block omitted: %+v", cfg.Memory)
	}
}

func TestMemory_RejectsUnknownKey(t *testing.T) {
	yaml := minimalValidYAML + "\nmemory:\n  bogus_key: 5\n"
	if _, err := LoadFrom(strings.NewReader(yaml), "test.yaml"); err == nil {
		t.Fatal("expected unknown key under memory: to be rejected by the strict parser")
	}
}

func TestMemory_RejectsNonPositiveKnobs(t *testing.T) {
	cases := []struct {
		field string
		yaml  string
		want  string
	}{
		{"attach_window_minutes", "  attach_window_minutes: 0", "memory: attach_window_minutes"},
		{"judgment_ceiling_hours", "  judgment_ceiling_hours: -1", "memory: judgment_ceiling_hours"},
		{"occurrence_cap", "  occurrence_cap: 0", "memory: occurrence_cap"},
		{"lookback_days", "  lookback_days: -5", "memory: lookback_days"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			yaml := minimalValidYAML + "\nmemory:\n" + tc.yaml + "\n"
			_, err := LoadFrom(strings.NewReader(yaml), "test.yaml")
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain dotted path %q", err.Error(), tc.want)
			}
		})
	}
}

func TestWarnings_VolatileGroupLabel(t *testing.T) {
	cfg := Defaults()
	cfg.Correlator.GroupLabels = []string{"cluster", "namespace", "pod"}
	warns := cfg.Warnings()
	if len(warns) == 0 {
		t.Fatal("expected a volatile-label warning for group_labels containing pod")
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "pod") {
		t.Errorf("warning does not name the volatile label: %q", joined)
	}
	if !strings.Contains(joined, "rarely match") {
		t.Errorf("warning does not name the consequence (rarely match): %q", joined)
	}
}

func TestWarnings_SilentForDefaultGroupLabels(t *testing.T) {
	cfg := Defaults()
	if warns := cfg.Warnings(); len(warns) != 0 {
		t.Errorf("shipped default group_labels must not warn, got: %v", warns)
	}
}

func TestWarnings_FiresForEachVolatileKind(t *testing.T) {
	for _, label := range []string{"pod", "pod_name", "pod_ip", "instance", "job_name", "container", "container_id", "uid"} {
		cfg := Defaults()
		cfg.Correlator.GroupLabels = []string{"cluster", label}
		if warns := cfg.Warnings(); len(warns) == 0 {
			t.Errorf("expected warning for volatile label %q", label)
		}
	}
}
