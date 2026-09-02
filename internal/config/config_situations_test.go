// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// situationsBaseYAML is a minimal valid config with the SQLite path
// templated, used as the base for the situations block tests below.
func situationsBaseYAML(t *testing.T) string {
	t.Helper()
	return strings.Replace(minimalValidYAML, "./alertint-agent.db", filepath.Join(t.TempDir(), "agent.db"), 1)
}

// TestSituationsDefaults locks in the exact Plan 2 controller surface: worker
// count, reconcile poll, lease/heartbeat, webhook recovery grace, cadence
// tiers, the fixed L2 call/work-attempt accounting, attempt wall, LLM
// concurrency, and the retry range/jitter. Plan 3/4 settings (connector
// concurrency, envelope review interval, max_l1_llm_calls, ...) are
// deliberately absent.
func TestSituationsDefaults(t *testing.T) {
	cfg := Defaults()
	s := cfg.Situations

	checks := []struct {
		name string
		got  int
		want int
	}{
		{"workers", s.Workers, 2},
		{"reconcile_poll_seconds", s.ReconcilePollSeconds, 1},
		{"lease_seconds", s.LeaseSeconds, 300},
		{"heartbeat_seconds", s.HeartbeatSeconds, 30},
		{"webhook_recovery_grace_seconds", s.WebhookRecoveryGraceSeconds, 120},
		// 120, not 60: Task 9 aligned this default with internal/situation/
		// assessment.go's own hardcoded cadenceFastInterval (2m) — see
		// SituationsCadenceConfig's own doc comment.
		{"cadence.fast_seconds", s.Cadence.FastSeconds, 120},
		{"cadence.normal_seconds", s.Cadence.NormalSeconds, 300},
		{"cadence.slow_seconds", s.Cadence.SlowSeconds, 900},
		{"max_l2_calls_per_attempt", s.MaxL2CallsPerAttempt, 2},
		{"max_work_attempts_per_input", s.MaxWorkAttemptsPerInput, 5},
		{"attempt_wall_seconds", s.AttemptWallSeconds, 180},
		{"llm_concurrency", s.LLMConcurrency, 2},
		{"retry.min_seconds", s.Retry.MinSeconds, 5},
		{"retry.max_seconds", s.Retry.MaxSeconds, 300},
		{"retry.jitter_percent", s.Retry.JitterPercent, 20},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("default %s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestSituationsDefaultsValidateClean proves the shipped defaults pass
// Validate() unmodified (alongside the required top-level fields).
func TestSituationsDefaultsValidateClean(t *testing.T) {
	cfg := Defaults()
	cfg.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
	cfg.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default situations config must validate cleanly: %v", err)
	}
}

// TestSituationsValidation drives the exact validation surface the task
// requires: positive durations/concurrency, heartbeat shorter than lease,
// jitter in [0,100], and the fixed L2 call/work-attempt limits.
func TestSituationsValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*SituationsConfig)
		wantErr bool
	}{
		{"clean defaults", func(s *SituationsConfig) {}, false},
		{"workers zero", func(s *SituationsConfig) { s.Workers = 0 }, true},
		{"workers negative", func(s *SituationsConfig) { s.Workers = -1 }, true},
		{"reconcile_poll_seconds zero", func(s *SituationsConfig) { s.ReconcilePollSeconds = 0 }, true},
		{"lease_seconds zero", func(s *SituationsConfig) { s.LeaseSeconds = 0 }, true},
		{"heartbeat_seconds zero", func(s *SituationsConfig) { s.HeartbeatSeconds = 0 }, true},
		{"webhook_recovery_grace_seconds zero", func(s *SituationsConfig) { s.WebhookRecoveryGraceSeconds = 0 }, true},
		{"cadence.fast_seconds zero", func(s *SituationsConfig) { s.Cadence.FastSeconds = 0 }, true},
		{"cadence.normal_seconds zero", func(s *SituationsConfig) { s.Cadence.NormalSeconds = 0 }, true},
		{"cadence.slow_seconds zero", func(s *SituationsConfig) { s.Cadence.SlowSeconds = 0 }, true},
		{"attempt_wall_seconds zero", func(s *SituationsConfig) { s.AttemptWallSeconds = 0 }, true},
		{"llm_concurrency zero", func(s *SituationsConfig) { s.LLMConcurrency = 0 }, true},
		{"retry.min_seconds zero", func(s *SituationsConfig) { s.Retry.MinSeconds = 0 }, true},
		{"retry.max_seconds zero", func(s *SituationsConfig) { s.Retry.MaxSeconds = 0 }, true},
		{"heartbeat_seconds equal to lease_seconds", func(s *SituationsConfig) {
			s.HeartbeatSeconds = s.LeaseSeconds
		}, true},
		{"heartbeat_seconds greater than lease_seconds", func(s *SituationsConfig) {
			s.HeartbeatSeconds = s.LeaseSeconds + 1
		}, true},
		{"heartbeat_seconds one below lease_seconds", func(s *SituationsConfig) {
			s.HeartbeatSeconds = s.LeaseSeconds - 1
		}, false},
		{"jitter_percent negative", func(s *SituationsConfig) { s.Retry.JitterPercent = -1 }, true},
		{"jitter_percent 101", func(s *SituationsConfig) { s.Retry.JitterPercent = 101 }, true},
		{"jitter_percent zero is allowed", func(s *SituationsConfig) { s.Retry.JitterPercent = 0 }, false},
		{"jitter_percent 100 is allowed", func(s *SituationsConfig) { s.Retry.JitterPercent = 100 }, false},
		{"max_l2_calls_per_attempt below fixed value", func(s *SituationsConfig) { s.MaxL2CallsPerAttempt = 1 }, true},
		{"max_l2_calls_per_attempt above fixed value", func(s *SituationsConfig) { s.MaxL2CallsPerAttempt = 3 }, true},
		{"max_work_attempts_per_input below fixed value", func(s *SituationsConfig) { s.MaxWorkAttemptsPerInput = 4 }, true},
		{"max_work_attempts_per_input above fixed value", func(s *SituationsConfig) { s.MaxWorkAttemptsPerInput = 6 }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
			cfg.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
			cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
			tc.mutate(&cfg.Situations)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("want validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want clean validation, got %v", err)
			}
		})
	}
}

// TestLoad_SituationsRejectsUnknownField proves the situations block strict
// decodes: an unrecognized key under it fails to load.
func TestLoad_SituationsRejectsUnknownField(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  workers: 2
  bogus_field: 1
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for unknown key under situations")
	}
}

// TestLoad_SituationsRejectsMaxL1LLMCalls is the task's binding negative
// case: Plan 2 deliberately never adds situations.budgets.max_l1_llm_calls
// (spec.md 02-controller-triage-coordination "Attempt identity and
// completion" — Acute Triage keeps its shipped five-attempt schedule and a
// parsed budget with no distinct consuming behavior would be removed rather
// than shipped unused). Strict YAML decoding must reject it outright rather
// than silently ignoring it.
func TestLoad_SituationsRejectsMaxL1LLMCalls(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  budgets:
    max_l1_llm_calls: 2
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for situations.budgets.max_l1_llm_calls")
	}
}

func TestLoad_SituationsValidAndDefaults(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  workers: 4
  lease_seconds: 600
  heartbeat_seconds: 45
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Situations.Workers != 4 {
		t.Errorf("workers = %d, want 4", cfg.Situations.Workers)
	}
	if cfg.Situations.LeaseSeconds != 600 {
		t.Errorf("lease_seconds = %d, want 600", cfg.Situations.LeaseSeconds)
	}
	if cfg.Situations.HeartbeatSeconds != 45 {
		t.Errorf("heartbeat_seconds = %d, want 45", cfg.Situations.HeartbeatSeconds)
	}
	// Omitted tunables get defaults.
	if cfg.Situations.AttemptWallSeconds != 180 {
		t.Errorf("default attempt_wall_seconds = %d, want 180", cfg.Situations.AttemptWallSeconds)
	}
	if cfg.Situations.MaxL2CallsPerAttempt != 2 {
		t.Errorf("default max_l2_calls_per_attempt = %d, want 2", cfg.Situations.MaxL2CallsPerAttempt)
	}
}
