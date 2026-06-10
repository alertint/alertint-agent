package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalValidYAML = `
listen:
  webhook_addr: ":9911"
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

func TestLoad_MinimalValidConfig(t *testing.T) {
	// Place the SQLite file inside a writable temp dir.
	yaml := strings.Replace(minimalValidYAML, "./alertint-agent.db", filepath.Join(t.TempDir(), "agent.db"), 1)
	path := writeConfig(t, yaml)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.WebhookAddr != ":9911" {
		t.Errorf("WebhookAddr = %q", cfg.Listen.WebhookAddr)
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
listen:
  webhook_addr: ":9000"
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
	if cfg.LLM.Model != "claude-haiku-4-5-20251001" {
		t.Errorf("default model not applied: %q", cfg.LLM.Model)
	}
	if cfg.Correlator.WindowSeconds != 90 {
		t.Errorf("default window_seconds not applied: %d", cfg.Correlator.WindowSeconds)
	}
	if cfg.Correlator.MinAlerts != 2 {
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

func TestValidate_RejectsNonAnthropicProvider(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.Listen.WebhookTokenEnv = "TOK"
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
			cfg.Listen.WebhookTokenEnv = "TOK"
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
		cfg.Listen.WebhookTokenEnv = "TOK"
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
	cfg.Listen.WebhookTokenEnv = "TOK"
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
	cfg.Listen.WebhookTokenEnv = "TOK"
	cfg.LLM.APIKeyEnv = "KEY"
	cfg.LogLevel = "loud"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Fatalf("want log_level error, got %v", err)
	}
}

func TestValidate_RejectsUnwritableSQLitePath(t *testing.T) {
	cfg := Defaults()
	cfg.Storage.SQLitePath = "/this/path/does/not/exist/agent.db"
	cfg.Listen.WebhookTokenEnv = "TOK"
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
	cfg.Listen.WebhookTokenEnv = "WEBHOOK_TOKEN_X"
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
	cfg.Listen.WebhookTokenEnv = "DEFINITELY_NOT_SET_ALERTINT_TEST_VAR"
	if _, err := cfg.WebhookToken(); err == nil {
		t.Fatal("expected error when env var is unset")
	}
}
