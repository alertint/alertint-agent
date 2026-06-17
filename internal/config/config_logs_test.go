// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// validBaseConfig returns a Config that passes validation, so logs tests can
// toggle only the Logs section.
func validBaseConfig(t *testing.T) Config {
	t.Helper()
	cfg := Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "agent.db")
	cfg.LLM.APIKeyEnv = "ANTHROPIC_API_KEY"
	cfg.Alertmanager.WebhookTokenEnv = "ALERTINT_WEBHOOK_TOKEN"
	return cfg
}

func TestLogs_Defaults(t *testing.T) {
	d := Defaults()
	if d.Logs.TimeoutSeconds != 10 {
		t.Errorf("logs.timeout_seconds default = %d, want 10", d.Logs.TimeoutSeconds)
	}
	if d.Logs.DefaultRangeMinutes != 15 {
		t.Errorf("logs.default_range_minutes default = %d, want 15", d.Logs.DefaultRangeMinutes)
	}
	if d.Logs.MaxLines != 50 {
		t.Errorf("logs.max_lines default = %d, want 50", d.Logs.MaxLines)
	}
	if d.Logs.Loki.Auth.Mode != "none" {
		t.Errorf("logs.loki.auth.mode default = %q, want none", d.Logs.Loki.Auth.Mode)
	}
	if !strings.Contains(d.Logs.Loki.LineFilter, "error") {
		t.Errorf("logs.loki.line_filter default not error-biased: %q", d.Logs.Loki.LineFilter)
	}
}

func TestValidateLogs_DisabledSkipsChecks(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = false
	cfg.Logs.Provider = "" // would be invalid if enabled
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled logs must not validate: %v", err)
	}
}

func TestValidateLogs_ValidLokiNoneAuth(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = "loki"
	cfg.Logs.Loki.BaseURL = "http://loki:3100"
	cfg.Logs.Loki.Auth.Mode = "none"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid loki/none config rejected: %v", err)
	}
}

func TestValidateLogs_UnknownProvider(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = "splunk"
	cfg.Logs.Loki.BaseURL = "http://loki:3100"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("want unknown-provider error, got %v", err)
	}
}

func TestValidateLogs_MissingProvider(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logs.provider is required") {
		t.Fatalf("want provider-required error, got %v", err)
	}
}

func TestValidateLogs_LokiRequiresBaseURL(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = "loki"
	cfg.Logs.Loki.BaseURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logs.loki.base_url is required") {
		t.Fatalf("want base_url-required error, got %v", err)
	}
}

func TestValidateLogs_BadTunables(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = "loki"
	cfg.Logs.Loki.BaseURL = "http://loki:3100"
	cfg.Logs.TimeoutSeconds = 0
	cfg.Logs.DefaultRangeMinutes = 0
	cfg.Logs.MaxLines = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("want errors for non-positive tunables")
	}
	for _, want := range []string{"timeout_seconds", "default_range_minutes", "max_lines"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

func TestValidateLogs_AuthMatrix(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		tokenEnv  string
		username  string
		passEnv   string
		wantError string // substring; "" = valid
	}{
		{"none ok", "none", "", "", "", ""},
		{"bearer ok", "bearer", "LOKI_TOKEN", "", "", ""},
		{"bearer missing token", "bearer", "", "", "", "token_env is required"},
		{"basic ok", "basic", "", "123456", "LOKI_PASS", ""},
		{"basic missing username", "basic", "", "", "LOKI_PASS", "username is required"},
		{"basic missing password", "basic", "", "123456", "", "password_env is required"},
		{"bad mode", "carrierpigeon", "", "", "", "must be one of none, bearer, basic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBaseConfig(t)
			cfg.Logs.Enabled = true
			cfg.Logs.Provider = "loki"
			cfg.Logs.Loki.BaseURL = "http://loki:3100"
			cfg.Logs.Loki.Auth = LokiAuthConfig{
				Mode:        tc.mode,
				TokenEnv:    tc.tokenEnv,
				Username:    tc.username,
				PasswordEnv: tc.passEnv,
			}
			err := cfg.Validate()
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("want error containing %q, got %v", tc.wantError, err)
			}
		})
	}
}

func TestLokiAuthSecret_ResolvesPerMode(t *testing.T) {
	t.Setenv("LOKI_BEARER_X", "bearer-secret")
	t.Setenv("LOKI_PASS_X", "basic-secret")

	mk := func(mode string) *Config {
		cfg := Defaults()
		cfg.Logs.Enabled = true
		cfg.Logs.Provider = "loki"
		cfg.Logs.Loki.BaseURL = "http://loki:3100"
		cfg.Logs.Loki.Auth = LokiAuthConfig{Mode: mode, TokenEnv: "LOKI_BEARER_X", Username: "123", PasswordEnv: "LOKI_PASS_X"}
		return &cfg
	}

	if s, err := mk("none").LokiAuthSecret(); err != nil || s != "" {
		t.Fatalf("none: got (%q,%v), want (\"\",nil)", s, err)
	}
	if s, err := mk("bearer").LokiAuthSecret(); err != nil || s != "bearer-secret" {
		t.Fatalf("bearer: got (%q,%v)", s, err)
	}
	if s, err := mk("basic").LokiAuthSecret(); err != nil || s != "basic-secret" {
		t.Fatalf("basic: got (%q,%v)", s, err)
	}
}

func TestLokiAuthSecret_MissingEnvErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Logs.Enabled = true
	cfg.Logs.Provider = "loki"
	cfg.Logs.Loki.BaseURL = "http://loki:3100"
	cfg.Logs.Loki.Auth = LokiAuthConfig{Mode: "bearer", TokenEnv: "DEFINITELY_UNSET_LOKI_TOKEN"}
	if _, err := cfg.LokiAuthSecret(); err == nil {
		t.Fatal("expected error for unset bearer token env")
	}
}

func TestLokiAuthSecret_DisabledReturnsEmpty(t *testing.T) {
	cfg := Defaults() // logs disabled by default
	cfg.Logs.Loki.Auth.Mode = "bearer"
	cfg.Logs.Loki.Auth.TokenEnv = "WHATEVER"
	if s, err := cfg.LokiAuthSecret(); err != nil || s != "" {
		t.Fatalf("disabled logs: got (%q,%v), want (\"\",nil)", s, err)
	}
}

// TestLogs_LineFilterEmptyVsOmitted verifies the §4.2 distinction survives the
// YAML merge: omitting line_filter keeps the error-biased default; setting it to
// "" explicitly disables filtering.
func TestLogs_LineFilterEmptyVsOmitted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agent.db")
	base := `
alertmanager:
  webhook_addr: ":9911"
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + dbPath + `"
logs:
  enabled: true
  provider: loki
  loki:
    base_url: http://loki:3100
`
	// Omitted line_filter → default.
	cfg, err := Load(writeConfig(t, base))
	if err != nil {
		t.Fatalf("load (omitted): %v", err)
	}
	if !strings.Contains(cfg.Logs.Loki.LineFilter, "error") {
		t.Errorf("omitted line_filter should keep default, got %q", cfg.Logs.Loki.LineFilter)
	}

	// Explicit empty → disabled.
	cfg2, err := Load(writeConfig(t, base+"    line_filter: \"\"\n"))
	if err != nil {
		t.Fatalf("load (explicit empty): %v", err)
	}
	if cfg2.Logs.Loki.LineFilter != "" {
		t.Errorf("explicit empty line_filter should disable, got %q", cfg2.Logs.Loki.LineFilter)
	}
}

func TestLogs_RejectsUnknownKeyUnderLoki(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agent.db")
	yaml := `
alertmanager:
  webhook_addr: ":9911"
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + dbPath + `"
logs:
  enabled: true
  provider: loki
  loki:
    base_url: http://loki:3100
    bogus_loki_key: 1
`
	if _, err := Load(writeConfig(t, yaml)); err == nil {
		t.Fatal("expected strict-mode rejection of unknown logs.loki key")
	}
}

// TestLogs_LabelMapParses confirms the label_map (alert→stream key) decodes,
// including drop-on-empty.
func TestLogs_LabelMapParses(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agent.db")
	yaml := `
alertmanager:
  webhook_addr: ":9911"
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + dbPath + `"
logs:
  enabled: true
  provider: loki
  loki:
    base_url: http://loki:3100
    label_map:
      service: app
      instance: ""
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Logs.Loki.LabelMap["service"] != "app" {
		t.Errorf("label_map service = %q, want app", cfg.Logs.Loki.LabelMap["service"])
	}
	if v, ok := cfg.Logs.Loki.LabelMap["instance"]; !ok || v != "" {
		t.Errorf("label_map instance = (%q,%v), want (\"\",true)", v, ok)
	}
}
