// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalValidYAML = `
receivers:
  address: ":9911"
alertmanager:
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
storage:
  sqlite_path: "./alertint-agent.db"
llm:
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
  model: claude-haiku-4-5-20251001
correlator:
  window_seconds: 90
  min_alerts: 2
  group_labels: ["cluster", "namespace", "service"]
notify:
  stdout: true
  slack:
    enabled: false
log_level: info
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestValidate_RulesLocalPackDir(t *testing.T) {
	base := Defaults()
	base.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
	base.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
	base.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")

	t.Run("empty is valid", func(t *testing.T) {
		cfg := base
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("missing directory rejected", func(t *testing.T) {
		cfg := base
		cfg.Rules.LocalPackDir = filepath.Join(t.TempDir(), "nope")
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "rules.local_pack_dir") {
			t.Fatalf("Validate = %v, want rules.local_pack_dir error", err)
		}
	})

	t.Run("directory without pack.yaml rejected", func(t *testing.T) {
		cfg := base
		cfg.Rules.LocalPackDir = t.TempDir()
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "pack.yaml") {
			t.Fatalf("Validate = %v, want pack.yaml error", err)
		}
	})

	t.Run("directory with pack.yaml accepted", func(t *testing.T) {
		cfg := base
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte("name: local\nversion: \"1\"\nupdated: \"2026-06-11\"\n"), 0o600); err != nil {
			t.Fatalf("write pack.yaml: %v", err)
		}
		cfg.Rules.LocalPackDir = dir
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}

func TestLoad_MinimalValidConfig(t *testing.T) {
	// Place the SQLite file inside a writable temp dir.
	yaml := strings.Replace(minimalValidYAML, "./alertint-agent.db", filepath.Join(t.TempDir(), "agent.db"), 1)
	path := writeConfig(t, yaml)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Receivers.Address != ":9911" {
		t.Errorf("Receivers.Address = %q", cfg.Receivers.Address)
	}
	if cfg.Correlator.MinAlerts != 2 {
		t.Errorf("MinAlerts = %d, want 2", cfg.Correlator.MinAlerts)
	}
	if cfg.LLM.Model == "" {
		t.Error("LLM.Model is empty")
	}
}

func TestLoad_AppliesDefaultsForOmittedFields(t *testing.T) {
	yaml := `
receivers:
  address: ":9000"
alertmanager:
  webhook_token_env: TOK
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + filepath.Join(t.TempDir(), "agent.db") + `"
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("default provider not applied: %q", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "claude-sonnet-5" {
		t.Errorf("default model not applied: %q", cfg.LLM.Model)
	}
	if cfg.Correlator.WindowSeconds != 90 {
		t.Errorf("default window_seconds not applied: %d", cfg.Correlator.WindowSeconds)
	}
	if cfg.Correlator.MinAlerts != 1 {
		t.Errorf("default min_alerts not applied: %d", cfg.Correlator.MinAlerts)
	}
	if !cfg.Notify.Stdout {
		t.Error("default notify.stdout=true not applied")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default log_level not applied: %q", cfg.LogLevel)
	}
}

func TestLoad_RejectsUnknownYAMLKeys(t *testing.T) {
	yaml := minimalValidYAML + "\nbogus_field: 1\n"
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown YAML key")
	}
}

func TestValidate_RequiresWebhookToken(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
	// WebhookTokenEnv intentionally unset.
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error when webhook_token_env is missing")
	}
	if !strings.Contains(err.Error(), "webhook_token_env") {
		t.Errorf("error did not mention webhook_token_env: %v", err)
	}
}

func TestDefaults_OnlyAlertmanagerEnabled(t *testing.T) {
	cfg := Defaults()
	if !cfg.Alertmanager.Enabled {
		t.Error("alertmanager should be enabled by default")
	}
	if cfg.Notify.Slack.Enabled || cfg.MCP.Enabled || cfg.PrometheusEnabled() {
		t.Errorf("slack/mcp/prometheus should be disabled by default, got %v/%v/%v",
			cfg.Notify.Slack.Enabled, cfg.MCP.Enabled, cfg.PrometheusEnabled())
	}
}

func TestValidate_AlertmanagerDisabledSkipsRequiredFields(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.Alertmanager.Enabled = false
	// WebhookTokenEnv intentionally unset; keep something to serve.
	cfg.MCP.Enabled = true
	cfg.MCP.TokenEnv = "ALERTINT_MCP_TOKEN"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled alertmanager should not require webhook fields: %v", err)
	}

	tok, err := cfg.WebhookToken()
	if err != nil || tok != "" {
		t.Errorf("WebhookToken() with alertmanager disabled = %q, %v; want empty, nil", tok, err)
	}
}

func TestValidate_RejectsNothingToServe(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.Alertmanager.Enabled = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Fatalf("want nothing-to-serve error, got %v", err)
	}
}

func TestValidate_RejectsNonAnthropicProvider(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.LLM.Provider = "openai"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "anthropic") {
		t.Fatalf("expected error mentioning anthropic, got %v", err)
	}
}

func TestValidate_RejectsBadCorrelatorBounds(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"zero window", func(c *Config) { c.Correlator.WindowSeconds = 0 }, "window_seconds"},
		{"zero min_alerts", func(c *Config) { c.Correlator.MinAlerts = 0 }, "min_alerts"},
		{"empty group_labels", func(c *Config) { c.Correlator.GroupLabels = nil }, "group_labels"},
		{"blank label", func(c *Config) { c.Correlator.GroupLabels = []string{"cluster", " "} }, "group_labels[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
			cfg.Alertmanager.WebhookTokenEnv = "TOK"
			cfg.LLM.APIKeyEnv = "KEY"
			tc.mut(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidate_SlackEnabledRequiresBotTokenAndChannel(t *testing.T) {
	base := func() Config {
		cfg := Defaults()
		cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
		cfg.Alertmanager.WebhookTokenEnv = "TOK"
		cfg.LLM.APIKeyEnv = "KEY"
		cfg.Notify.Slack.Enabled = true
		return cfg
	}

	t.Run("missing bot_token_env", func(t *testing.T) {
		cfg := base()
		cfg.Notify.Slack.Channel = "#alerts"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bot_token_env") {
			t.Fatalf("want bot_token_env error, got %v", err)
		}
	})
	t.Run("missing channel", func(t *testing.T) {
		cfg := base()
		cfg.Notify.Slack.BotTokenEnv = "SLACK_BOT_TOKEN"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "channel") {
			t.Fatalf("want channel error, got %v", err)
		}
	})
}

func TestValidate_RejectsAllNotifiersDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.Notify.Stdout = false
	cfg.Notify.Slack.Enabled = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "notifier") {
		t.Fatalf("want notifier error, got %v", err)
	}
}

func TestValidate_RejectsBadLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.LogLevel = "loud"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Fatalf("want log_level error, got %v", err)
	}
}

func TestDefaults_LogFormatIsAuto(t *testing.T) {
	if got := Defaults().LogFormat; got != "auto" {
		t.Errorf("default log_format = %q, want auto", got)
	}
}

func TestLoad_DefaultsLogFormatToAuto(t *testing.T) {
	yaml := strings.Replace(minimalValidYAML, "./alertint-agent.db", filepath.Join(t.TempDir(), "agent.db"), 1)
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogFormat != "auto" {
		t.Errorf("omitted log_format should default to auto, got %q", cfg.LogFormat)
	}
}

func TestValidate_RejectsBadLogFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	// "text" was removed from the allowed set — it must fail loud, not alias.
	cfg.LogFormat = "text"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "log_format") {
		t.Fatalf("want log_format error, got %v", err)
	}
}

func TestValidate_RejectsUnwritableSQLitePath(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = "/this/path/does/not/exist/agent.db"
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sqlite_path") {
		t.Fatalf("want sqlite_path error, got %v", err)
	}
}

func TestAccessors_ResolveSecretsFromEnv(t *testing.T) {
	t.Setenv("WEBHOOK_TOKEN_X", "secret-token")
	t.Setenv("ANTHROPIC_KEY_X", "sk-test")
	t.Setenv("SLACK_BOT_TOKEN_X", "xoxb-test-token")

	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "WEBHOOK_TOKEN_X"
	cfg.LLM.APIKeyEnv = "ANTHROPIC_KEY_X"
	cfg.Notify.Slack.Enabled = true
	cfg.Notify.Slack.BotTokenEnv = "SLACK_BOT_TOKEN_X"
	cfg.Notify.Slack.Channel = "#alerts"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	tok, err := cfg.WebhookToken()
	if err != nil || tok != "secret-token" {
		t.Errorf("WebhookToken = %q, %v", tok, err)
	}
	key, err := cfg.LLMAPIKey()
	if err != nil || key != "sk-test" {
		t.Errorf("LLMAPIKey = %q, %v", key, err)
	}
	slackTok, err := cfg.SlackBotToken()
	if err != nil || slackTok != "xoxb-test-token" {
		t.Errorf("SlackBotToken = %q, %v", slackTok, err)
	}
}

func TestSlackBotToken_DisabledReturnsEmpty(t *testing.T) {
	cfg := Defaults()
	cfg.Notify.Slack.Enabled = false
	tok, err := cfg.SlackBotToken()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tok != "" {
		t.Errorf("want empty token when disabled, got %q", tok)
	}
}

func TestAccessors_MissingEnvVarErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Alertmanager.WebhookTokenEnv = "DEFINITELY_NOT_SET_ALERTINT_TEST_VAR"
	if _, err := cfg.WebhookToken(); err == nil {
		t.Fatal("expected error when env var is unset")
	}
}

// sentryBaseYAML is a minimal valid config with the SQLite path templated, used
// as the base for the Sentry block tests below.
func sentryBaseYAML(t *testing.T) string {
	t.Helper()
	return strings.Replace(minimalValidYAML, "./alertint-agent.db", filepath.Join(t.TempDir(), "agent.db"), 1)
}

func TestLoad_SentryReleasesValidAndDefaults(t *testing.T) {
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  releases:
    enabled: true
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sentry.BaseURL != "https://sentry.io" || cfg.Sentry.Org != "acme" || cfg.Sentry.TokenEnv != "SENTRY_TOKEN" {
		t.Errorf("connection not parsed: %+v", cfg.Sentry)
	}
	if !cfg.Sentry.Releases.Enabled {
		t.Error("releases.enabled not parsed")
	}
	// Omitted tunables get defaults.
	if cfg.Sentry.TimeoutSeconds != 10 {
		t.Errorf("default timeout_seconds = %d, want 10", cfg.Sentry.TimeoutSeconds)
	}
	if cfg.Sentry.Releases.PollIntervalSeconds != 60 {
		t.Errorf("default poll_interval_seconds = %d, want 60", cfg.Sentry.Releases.PollIntervalSeconds)
	}
	if cfg.Sentry.Releases.InitialLookbackMinutes != 60 {
		t.Errorf("default initial_lookback_minutes = %d, want 60", cfg.Sentry.Releases.InitialLookbackMinutes)
	}
	if cfg.Sentry.Releases.ReleaseScanHorizonDays != 30 {
		t.Errorf("default release_scan_horizon_days = %d, want 30", cfg.Sentry.Releases.ReleaseScanHorizonDays)
	}
}

func TestLoad_SentryRejectsUnknownKey(t *testing.T) {
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  bogus_sentry_field: 1
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for unknown key under sentry")
	}
}

func TestValidate_SentryReleasesRequiresConnection(t *testing.T) {
	for _, field := range []string{"base_url", "org", "token_env"} {
		t.Run("missing "+field, func(t *testing.T) {
			cfg := Defaults()
			cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
			cfg.Alertmanager.WebhookTokenEnv = "TOK"
			cfg.LLM.APIKeyEnv = "KEY"
			cfg.Sentry = SentryConfig{
				BaseURL:        "https://sentry.io",
				Org:            "acme",
				TokenEnv:       "SENTRY_TOKEN",
				TimeoutSeconds: 10,
				Releases: SentryReleasesConfig{
					Enabled:                true,
					PollIntervalSeconds:    60,
					InitialLookbackMinutes: 60,
					ReleaseScanHorizonDays: 30,
				},
			}
			switch field {
			case "base_url":
				cfg.Sentry.BaseURL = ""
			case "org":
				cfg.Sentry.Org = ""
			case "token_env":
				cfg.Sentry.TokenEnv = ""
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for missing %s", field)
			}
			msg := err.Error()
			if !strings.Contains(msg, "sentry:") || !strings.Contains(msg, field) {
				t.Errorf("error %q must be sentry:-prefixed and mention %s", msg, field)
			}
			if msg != strings.ToLower(msg) {
				// the field-level message is lowercase; the wrapping "invalid config" prefix is too
				t.Logf("note: message contains uppercase: %q", msg)
			}
		})
	}
}

// assertSentryTunableRejected seeds the shared connection, applies mutate (which
// enables the relevant feature and zeroes one tunable), and asserts Validate
// rejects it with a sentry: <field> message. Shared by the releases and issues
// non-positive-tunable tables.
func assertSentryTunableRejected(t *testing.T, mutate func(*Config), want string) {
	t.Helper()
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.Sentry.BaseURL = "https://sentry.io"
	cfg.Sentry.Org = "acme"
	cfg.Sentry.TokenEnv = "SENTRY_TOKEN"
	mutate(&cfg)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate = %v, want error mentioning %s", err, want)
	}
}

func TestValidate_SentryReleasesRejectsNonPositiveTunables(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"poll_interval", func(c *Config) { c.Sentry.Releases.Enabled = true; c.Sentry.Releases.PollIntervalSeconds = 0 }, "poll_interval_seconds"},
		{"initial_lookback", func(c *Config) { c.Sentry.Releases.Enabled = true; c.Sentry.Releases.InitialLookbackMinutes = 0 }, "initial_lookback_minutes"},
		{"release_scan_horizon", func(c *Config) { c.Sentry.Releases.Enabled = true; c.Sentry.Releases.ReleaseScanHorizonDays = -1 }, "release_scan_horizon_days"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertSentryTunableRejected(t, tc.mutate, tc.want) })
	}
}

func TestValidate_SentryDisabledValidatesClean(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	// Sentry left at its zero/default (disabled) with an empty connection.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled sentry should validate clean: %v", err)
	}
}

func TestSentryToken(t *testing.T) {
	t.Run("enabled and set returns value", func(t *testing.T) {
		t.Setenv("SENTRY_TOKEN_X", "sntrys-secret")
		cfg := Defaults()
		cfg.Sentry.TokenEnv = "SENTRY_TOKEN_X"
		cfg.Sentry.Releases.Enabled = true
		tok, err := cfg.SentryToken()
		if err != nil || tok != "sntrys-secret" {
			t.Errorf("SentryToken = %q, %v; want sntrys-secret, nil", tok, err)
		}
	})

	t.Run("enabled but unset errors with field name", func(t *testing.T) {
		cfg := Defaults()
		cfg.Sentry.TokenEnv = "DEFINITELY_NOT_SET_SENTRY_TEST_VAR"
		cfg.Sentry.Releases.Enabled = true
		_, err := cfg.SentryToken()
		if err == nil || !strings.Contains(err.Error(), "sentry.token_env") {
			t.Errorf("SentryToken err = %v, want sentry.token_env message", err)
		}
	})

	t.Run("disabled returns empty nil", func(t *testing.T) {
		cfg := Defaults()
		cfg.Sentry.TokenEnv = "WHATEVER"
		cfg.Sentry.Releases.Enabled = false
		tok, err := cfg.SentryToken()
		if err != nil || tok != "" {
			t.Errorf("SentryToken = %q, %v; want empty, nil", tok, err)
		}
	})

	t.Run("issues-only enabled resolves the shared token", func(t *testing.T) {
		t.Setenv("SENTRY_TOKEN_ISSUES", "sntrys-issues")
		cfg := Defaults()
		cfg.Sentry.TokenEnv = "SENTRY_TOKEN_ISSUES"
		cfg.Sentry.Issues.Enabled = true // releases stays off
		tok, err := cfg.SentryToken()
		if err != nil || tok != "sntrys-issues" {
			t.Errorf("SentryToken (issues-only) = %q, %v; want sntrys-issues, nil", tok, err)
		}
	})
}

// --------------------------------------------------------------------------
// Sentry Error source (issues) — Spec 2
// --------------------------------------------------------------------------

func TestLoad_SentryIssuesValidAndDefaults(t *testing.T) {
	// Issues enabled with releases OFF: the shared connection is required and
	// the block validates, exercising the decoupled gating (KTD7).
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  issues:
    enabled: true
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Sentry.Issues.Enabled || cfg.Sentry.Releases.Enabled {
		t.Fatalf("want issues-only enabled, got %+v", cfg.Sentry)
	}
	if !cfg.AnySentryEnabled() {
		t.Error("AnySentryEnabled should be true with issues on")
	}
	if cfg.Sentry.Issues.LookbackMinutes != 30 {
		t.Errorf("default lookback_minutes = %d, want 30", cfg.Sentry.Issues.LookbackMinutes)
	}
	if cfg.Sentry.Issues.MaxIssues != 3 {
		t.Errorf("default max_issues = %d, want 3", cfg.Sentry.Issues.MaxIssues)
	}
	if cfg.Sentry.Issues.FetchTimeoutSeconds != 15 {
		t.Errorf("default fetch_timeout_seconds = %d, want 15", cfg.Sentry.Issues.FetchTimeoutSeconds)
	}
	if cfg.Sentry.Issues.LiveWindowMinutes != 60 {
		t.Errorf("default live_window_minutes = %d, want 60", cfg.Sentry.Issues.LiveWindowMinutes)
	}
	if !cfg.Sentry.Issues.MessageIncluded() {
		t.Error("include_message must default ON (R14)")
	}
}

func TestLoad_SentryIssuesLiveWindowExplicit(t *testing.T) {
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  issues:
    enabled: true
    live_window_minutes: 180
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sentry.Issues.LiveWindowMinutes != 180 {
		t.Errorf("explicit live_window_minutes = %d, want 180", cfg.Sentry.Issues.LiveWindowMinutes)
	}
}

func TestLoad_SentryIssuesIncludeMessageToggle(t *testing.T) {
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  issues:
    enabled: true
    include_message: false
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sentry.Issues.IncludeMessage == nil || *cfg.Sentry.Issues.IncludeMessage {
		t.Errorf("explicit include_message: false must round-trip as off, got %v", cfg.Sentry.Issues.IncludeMessage)
	}
	if cfg.Sentry.Issues.MessageIncluded() {
		t.Error("MessageIncluded should resolve to false when explicitly disabled")
	}
}

func TestLoad_SentryIssuesRejectsUnknownKey(t *testing.T) {
	yaml := sentryBaseYAML(t) + `
sentry:
  base_url: https://sentry.io
  org: acme
  token_env: SENTRY_TOKEN
  issues:
    enabled: true
    bogus_issue_field: 1
`
	path := writeConfig(t, yaml)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict-decode error for unknown key under sentry.issues")
	}
}

func TestValidate_SentryIssuesRequiresConnection(t *testing.T) {
	for _, field := range []string{"base_url", "org", "token_env"} {
		t.Run("missing "+field, func(t *testing.T) {
			cfg := Defaults()
			cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
			cfg.Alertmanager.WebhookTokenEnv = "TOK"
			cfg.LLM.APIKeyEnv = "KEY"
			cfg.Sentry.BaseURL = "https://sentry.io"
			cfg.Sentry.Org = "acme"
			cfg.Sentry.TokenEnv = "SENTRY_TOKEN"
			cfg.Sentry.Issues.Enabled = true // releases off — only issues drives the requirement
			switch field {
			case "base_url":
				cfg.Sentry.BaseURL = ""
			case "org":
				cfg.Sentry.Org = ""
			case "token_env":
				cfg.Sentry.TokenEnv = ""
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for missing %s with issues enabled", field)
			}
			if msg := err.Error(); !strings.Contains(msg, "sentry:") || !strings.Contains(msg, field) {
				t.Errorf("error %q must be sentry:-prefixed and mention %s", msg, field)
			}
		})
	}
}

func TestValidate_SentryIssuesRejectsNonPositiveTunables(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"lookback", func(c *Config) { c.Sentry.Issues.Enabled = true; c.Sentry.Issues.LookbackMinutes = 0 }, "lookback_minutes"},
		{"max_issues", func(c *Config) { c.Sentry.Issues.Enabled = true; c.Sentry.Issues.MaxIssues = 0 }, "max_issues"},
		{"fetch_timeout", func(c *Config) { c.Sentry.Issues.Enabled = true; c.Sentry.Issues.FetchTimeoutSeconds = -1 }, "fetch_timeout_seconds"},
		{"live_window", func(c *Config) { c.Sentry.Issues.Enabled = true; c.Sentry.Issues.LiveWindowMinutes = 0 }, "live_window_minutes"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertSentryTunableRejected(t, tc.mutate, tc.want) })
	}
}

func TestAnySentryEnabled_BothDisabledIsZeroConfig(t *testing.T) {
	cfg := Defaults()
	cfg.Sentry.TokenEnv = "WHATEVER"
	if cfg.AnySentryEnabled() {
		t.Error("AnySentryEnabled should be false with both features off")
	}
	tok, err := cfg.SentryToken()
	if err != nil || tok != "" {
		t.Errorf("SentryToken with both off = %q, %v; want empty, nil", tok, err)
	}
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Alertmanager.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("both-disabled sentry should validate clean: %v", err)
	}
}

func TestValidateOffline_SkipsFilesystemChecks(t *testing.T) {
	base := Defaults()
	base.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
	base.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"

	t.Run("pod-destined sqlite path passes offline, fails online", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "nope", "data", "alertint.db")
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate: want storage.sqlite_path error for missing parent dir, got nil")
		}
		if err := cfg.ValidateOffline(); err != nil {
			t.Fatalf("ValidateOffline: %v", err)
		}
	})

	t.Run("missing local pack dir passes offline, fails online", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
		cfg.Rules.LocalPackDir = filepath.Join(t.TempDir(), "nope")
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate: want rules.local_pack_dir error, got nil")
		}
		if err := cfg.ValidateOffline(); err != nil {
			t.Fatalf("ValidateOffline: %v", err)
		}
	})

	t.Run("offline still rejects invalid fields", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = "/data/alertint.db"
		cfg.LogLevel = "bogus"
		err := cfg.ValidateOffline()
		if err == nil || !strings.Contains(err.Error(), "log_level") {
			t.Fatalf("ValidateOffline = %v, want log_level error", err)
		}
	})

	t.Run("offline still requires sqlite path", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = "  "
		err := cfg.ValidateOffline()
		if err == nil || !strings.Contains(err.Error(), "storage.sqlite_path is required") {
			t.Fatalf("ValidateOffline = %v, want storage.sqlite_path required error", err)
		}
	})
}

func TestValidate_ReservedGroupLabelPrefix(t *testing.T) {
	base := Defaults()
	base.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
	base.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"

	t.Run("alertint_ prefixed group label rejected in both modes", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
		cfg.Correlator.GroupLabels = []string{"cluster", "alertint_demo"}
		for name, validate := range map[string]func() error{"online": cfg.Validate, "offline": cfg.ValidateOffline} {
			err := validate()
			if err == nil || !strings.Contains(err.Error(), "reserved alertint_ label prefix") {
				t.Fatalf("%s = %v, want reserved-prefix error", name, err)
			}
		}
	})

	t.Run("normal group labels accepted", func(t *testing.T) {
		cfg := base
		cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
		cfg.Correlator.GroupLabels = []string{"cluster", "namespace"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}
