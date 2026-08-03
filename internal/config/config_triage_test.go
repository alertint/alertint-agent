// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestExtraSelectorLabelsDefaultEmpty(t *testing.T) {
	cfg := Defaults()
	if len(cfg.Triage.ExtraSelectorLabels) != 0 {
		t.Fatalf("extra_selector_labels must default empty, got %v", cfg.Triage.ExtraSelectorLabels)
	}
}

func TestExtraSelectorLabelsValidation(t *testing.T) {
	cases := []struct {
		name    string
		labels  []string
		wantErr string // "" = must validate cleanly
	}{
		{"valid single", []string{"cluster"}, ""},
		{"valid several", []string{"cluster", "region", "az_zone"}, ""},
		{"invalid name", []string{"cluster-1"},
			`triage: extra_selector_labels: "cluster-1": invalid label name (must match [a-zA-Z_][a-zA-Z0-9_]*)`},
		{"duplicate entry", []string{"cluster", "cluster"},
			`triage: extra_selector_labels: "cluster": duplicate entry`},
		{"duplicates built-in", []string{"namespace"},
			`triage: extra_selector_labels: "namespace": already in the built-in allowlist (namespace, service, job, pod, container, instance)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
			cfg.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
			cfg.Triage.ExtraSelectorLabels = tc.labels
			err := (&cfg).Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want clean validation, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q in error, got %v", tc.wantErr, err)
			}
		})
	}
}
