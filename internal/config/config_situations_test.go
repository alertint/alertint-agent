// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestSituationDefaults(t *testing.T) {
	cfg := Defaults().Situations
	if cfg.Workers != 2 || cfg.ReconcileIntervalSeconds != 1 || cfg.LeaseSeconds != 300 || cfg.LeaseHeartbeatSeconds != 30 {
		t.Fatalf("worker defaults = %+v", cfg)
	}
	if cfg.Budgets.MaxObservationCalls != 6 || cfg.Budgets.MaxL1LLMCalls != 2 || cfg.Budgets.MaxL2LLMCalls != 2 || cfg.Budgets.MaxAttemptsPerInput != 5 {
		t.Fatalf("budget defaults = %+v", cfg.Budgets)
	}
	if cfg.RecoveryGrace.WebhookSeconds != 120 || cfg.EnvelopeReview.ReminderIntervalDays != 30 {
		t.Fatalf("recovery/review defaults = %+v %+v", cfg.RecoveryGrace, cfg.EnvelopeReview)
	}
}

func TestSituationConfigRejectsUnknownAndInvalidValues(t *testing.T) {
	_, err := LoadFrom(strings.NewReader(minimalValidYAML+"\nsituations:\n  mystery: 1\n"), "test.yaml")
	if err == nil || !strings.Contains(err.Error(), "field mystery not found") {
		t.Fatalf("err = %v", err)
	}

	cfg := Defaults()
	cfg.Situations.LeaseHeartbeatSeconds = cfg.Situations.LeaseSeconds
	if err := cfg.ValidateOffline(); err == nil || !strings.Contains(err.Error(), "lease_heartbeat_seconds must be less than lease_seconds") {
		t.Fatalf("err = %v", err)
	}
}

func TestSituationConfigRejectsInvalidOrderingAndScalars(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "positive scalar",
			mutate: func(cfg *Config) {
				cfg.Situations.Workers = 0
			},
			wantErr: "situations.workers must be > 0",
		},
		{
			name: "polling grace range",
			mutate: func(cfg *Config) {
				cfg.Situations.RecoveryGrace.PollingMinSeconds = cfg.Situations.RecoveryGrace.PollingMaxSeconds + 1
			},
			wantErr: "situations.recovery_grace.polling_min_seconds must be less than or equal to polling_max_seconds",
		},
		{
			name: "cadence order",
			mutate: func(cfg *Config) {
				cfg.Situations.Cadence.FastSeconds = cfg.Situations.Cadence.NormalSeconds + 1
			},
			wantErr: "situations.cadence must satisfy fast_seconds <= normal_seconds <= slow_seconds",
		},
		{
			name: "retry range",
			mutate: func(cfg *Config) {
				cfg.Situations.Retry.InitialSeconds = cfg.Situations.Retry.MaximumSeconds + 1
			},
			wantErr: "situations.retry.initial_seconds must be less than or equal to maximum_seconds",
		},
		{
			name: "jitter range",
			mutate: func(cfg *Config) {
				cfg.Situations.Retry.JitterPercent = 101
			},
			wantErr: "situations.retry.jitter_percent must be between 0 and 100",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mutate(&cfg)
			if err := cfg.ValidateOffline(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateOffline() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
