// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
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
// concurrency, and the retry range/jitter — plus Plan 4's bounded evidence-
// preparation and semantic-profile-worker defaults (spec.md "Defaults and
// hard limits"). Plan 5 settings (envelope review interval, ...) remain
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
		{"cadence.fast_seconds", s.Cadence.FastSeconds, 60},
		{"cadence.normal_seconds", s.Cadence.NormalSeconds, 300},
		{"cadence.slow_seconds", s.Cadence.SlowSeconds, 900},
		{"max_l2_calls_per_attempt", s.MaxL2CallsPerAttempt, 2},
		{"max_work_attempts_per_input", s.MaxWorkAttemptsPerInput, 5},
		{"attempt_wall_seconds", s.AttemptWallSeconds, 180},
		{"llm_concurrency", s.LLMConcurrency, 2},
		{"retry.min_seconds", s.Retry.MinSeconds, 5},
		{"retry.max_seconds", s.Retry.MaxSeconds, 300},
		{"retry.jitter_percent", s.Retry.JitterPercent, 20},
		{"slack.repage_cooldown_seconds", s.Slack.RepageCooldownSeconds, 900},
		{"preparation.max_source_calls_per_cycle", s.Preparation.MaxSourceCallsPerCycle, 6},
		{"preparation.max_wall_seconds", s.Preparation.MaxWallSeconds, 20},
		{"preparation.refresh_seconds", s.Preparation.RefreshSeconds, 300},
		{"semantic_profiles.workers", s.SemanticProfiles.Workers, 1},
		{"semantic_profiles.max_attempts", s.SemanticProfiles.MaxAttempts, 3},
		{"semantic_profiles.attempt_wall_seconds", s.SemanticProfiles.AttemptWallSeconds, 30},
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
		{"cadence fast equal to normal", func(s *SituationsConfig) { s.Cadence.FastSeconds = s.Cadence.NormalSeconds }, true},
		{"cadence normal slower than slow", func(s *SituationsConfig) { s.Cadence.NormalSeconds = s.Cadence.SlowSeconds + 1 }, true},
		{"cadence strictly ordered custom values", func(s *SituationsConfig) {
			s.Cadence.FastSeconds, s.Cadence.NormalSeconds, s.Cadence.SlowSeconds = 30, 31, 32
		}, false},
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
		{"slack.repage_cooldown_seconds zero", func(s *SituationsConfig) { s.Slack.RepageCooldownSeconds = 0 }, true},
		{"slack.repage_cooldown_seconds negative", func(s *SituationsConfig) { s.Slack.RepageCooldownSeconds = -1 }, true},
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

// TestLoad_SituationsSlackValidAndDefaults proves situations.slack.
// repage_cooldown_seconds loads and overrides the 900-second default.
func TestLoad_SituationsSlackValidAndDefaults(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  slack:
    repage_cooldown_seconds: 600
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Situations.Slack.RepageCooldownSeconds != 600 {
		t.Errorf("slack.repage_cooldown_seconds = %d, want 600", cfg.Situations.Slack.RepageCooldownSeconds)
	}
}

// TestLoad_SituationsSlackRejectsAttemptCeiling proves Plan 3 adds no
// notification-worker attempt-ceiling knob under situations.slack:
// NotificationWorkerConfig retries valid Slack effects indefinitely (plan.md
// Cross-Task Contracts, "It has no maximum attempts field"), so a configured
// ceiling must fail strict decoding rather than being silently accepted and
// ignored.
func TestLoad_SituationsSlackRejectsAttemptCeiling(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  slack:
    max_attempts: 5
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for situations.slack.max_attempts")
	}
}

// TestLoad_SituationsSlackRejectsReadReconciliation proves Plan 3 adds no
// Slack channel-history-read or read-before-redrive reconciliation setting
// (Global Constraints: "Do not request Slack channel-history scopes and do
// not implement read-before-redrive reconciliation").
func TestLoad_SituationsSlackRejectsReadReconciliation(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  slack:
    read_before_redrive: true
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for situations.slack.read_before_redrive")
	}
}

// TestNotifySlackMinSeverityIsInterruptionPriorityFloor documents the
// compatibility contract (spec.md "Publication authority and Interruption
// priority"): notify.slack.min_severity keeps its existing accepted values
// low|medium|high unchanged, but in the Situation path the selected value is
// read only as a minimum deterministic Interruption priority — never Alert
// or model severity. Every accepted min_severity value must therefore
// already be one of model.InterruptionPriority's closed values; "critical"
// is a valid Interruption priority with no min_severity equivalent, so the
// compatibility setting can never select it as a floor.
func TestNotifySlackMinSeverityIsInterruptionPriorityFloor(t *testing.T) {
	for _, v := range []string{"low", "medium", "high"} {
		if err := model.InterruptionPriority(v).Validate(); err != nil {
			t.Errorf("notify.slack.min_severity value %q must be a valid Interruption priority: %v", v, err)
		}
	}
	if err := model.InterruptionPriority("critical").Validate(); err != nil {
		t.Errorf("critical must be a valid Interruption priority: %v", err)
	}
}

// TestLoad_SituationPreparationValidAndDefaults proves
// situations.preparation fields load and override their defaults.
func TestLoad_SituationPreparationValidAndDefaults(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  preparation:
    max_source_calls_per_cycle: 8
    max_wall_seconds: 15
    refresh_seconds: 120
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Situations.Preparation
	if p.MaxSourceCallsPerCycle != 8 {
		t.Errorf("max_source_calls_per_cycle = %d, want 8", p.MaxSourceCallsPerCycle)
	}
	if p.MaxWallSeconds != 15 {
		t.Errorf("max_wall_seconds = %d, want 15", p.MaxWallSeconds)
	}
	if p.RefreshSeconds != 120 {
		t.Errorf("refresh_seconds = %d, want 120", p.RefreshSeconds)
	}
}

// TestLoad_SituationPreparationRejectsOutOfRange proves each Plan 4
// preparation field's exact spec.md range (max_source_calls_per_cycle
// 1-32, max_wall_seconds 1-30, refresh_seconds 60-3600) is enforced, not
// silently clamped.
func TestLoad_SituationPreparationRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"max_source_calls_per_cycle too low", "max_source_calls_per_cycle: 0"},
		{"max_source_calls_per_cycle too high", "max_source_calls_per_cycle: 33"},
		{"max_wall_seconds too low", "max_wall_seconds: 0"},
		{"max_wall_seconds too high", "max_wall_seconds: 31"},
		{"refresh_seconds too low", "refresh_seconds: 59"},
		{"refresh_seconds too high", "refresh_seconds: 3601"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := situationsBaseYAML(t) + "situations:\n  preparation:\n    " + c.yaml + "\n"
			path := writeConfig(t, yaml)
			if _, err := Load(path); err == nil {
				t.Fatalf("expected validation error for %s", c.name)
			}
		})
	}
}

// TestLoad_SituationPreparationRejectsWallOverAttemptWall proves the
// spec.md cross-field rule: preparation.max_wall_seconds must be strictly
// less than situations.attempt_wall_seconds (the preparation wall is
// bounded by the enclosing controller attempt's own wall).
func TestLoad_SituationPreparationRejectsWallOverAttemptWall(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  attempt_wall_seconds: 20
  preparation:
    max_wall_seconds: 20
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error when preparation.max_wall_seconds >= situations.attempt_wall_seconds")
	}
}

// TestLoad_SituationPreparationRejectsUnknownField proves strict decoding
// covers the new preparation block too.
func TestLoad_SituationPreparationRejectsUnknownField(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  preparation:
    bogus_field: 1
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for unknown key under situations.preparation")
	}
}

// TestLoad_SemanticProfilesValidAndDefaults proves
// situations.semantic_profiles fields load and override their defaults.
func TestLoad_SemanticProfilesValidAndDefaults(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  semantic_profiles:
    workers: 2
    max_attempts: 5
    attempt_wall_seconds: 45
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sp := cfg.Situations.SemanticProfiles
	if sp.Workers != 2 {
		t.Errorf("workers = %d, want 2", sp.Workers)
	}
	if sp.MaxAttempts != 5 {
		t.Errorf("max_attempts = %d, want 5", sp.MaxAttempts)
	}
	if sp.AttemptWallSeconds != 45 {
		t.Errorf("attempt_wall_seconds = %d, want 45", sp.AttemptWallSeconds)
	}
}

// TestLoad_SemanticProfilesRejectsOutOfRange proves each Plan 4
// semantic-profile field's exact spec.md range (workers 1-4, max_attempts
// 1-5, attempt_wall_seconds 1-60) is enforced.
func TestLoad_SemanticProfilesRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"workers too low", "workers: 0"},
		{"workers too high", "workers: 5"},
		{"max_attempts too low", "max_attempts: 0"},
		{"max_attempts too high", "max_attempts: 6"},
		{"attempt_wall_seconds too low", "attempt_wall_seconds: 0"},
		{"attempt_wall_seconds too high", "attempt_wall_seconds: 61"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := situationsBaseYAML(t) + "situations:\n  semantic_profiles:\n    " + c.yaml + "\n"
			path := writeConfig(t, yaml)
			if _, err := Load(path); err == nil {
				t.Fatalf("expected validation error for %s", c.name)
			}
		})
	}
}

// TestLoad_SemanticProfilesRejectsUnknownField proves strict decoding
// covers the new semantic_profiles block too.
func TestLoad_SemanticProfilesRejectsUnknownField(t *testing.T) {
	yaml := situationsBaseYAML(t) + `
situations:
  semantic_profiles:
    bogus_field: 1
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for unknown key under situations.semantic_profiles")
	}
}
