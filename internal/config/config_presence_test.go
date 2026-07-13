// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// The presence-based enablement truth table (one row per HLD case):
//
//	enabled     source present   effective
//	true        any              ON   (explicit wins)
//	false       any              OFF  (explicit opt-out honored)
//	omitted     yes              ON   (presence-based default)
//	omitted     no               OFF  (nothing to connect to)

func TestPrometheusEnabled_TruthTable(t *testing.T) {
	cases := []struct {
		name    string
		enabled *bool
		baseURL string
		want    bool
	}{
		{"explicit true, no url", boolPtr(true), "", true},
		{"explicit false, url set", boolPtr(false), "http://prom:9090", false},
		{"omitted, url set", nil, "http://prom:9090", true},
		{"omitted, no url", nil, "", false},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.Prometheus.Enabled = tc.enabled
		cfg.Prometheus.BaseURL = tc.baseURL
		if got := cfg.PrometheusEnabled(); got != tc.want {
			t.Errorf("%s: PrometheusEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLogsEnabled_TruthTable(t *testing.T) {
	cases := []struct {
		name    string
		enabled *bool
		lokiURL string
		want    bool
	}{
		{"explicit true, no url", boolPtr(true), "", true},
		{"explicit false, url set", boolPtr(false), "http://loki:3100", false},
		{"omitted, url set", nil, "http://loki:3100", true},
		{"omitted, no url", nil, "", false},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.Logs.Enabled = tc.enabled
		cfg.Logs.Loki.BaseURL = tc.lokiURL
		if got := cfg.LogsEnabled(); got != tc.want {
			t.Errorf("%s: LogsEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestChangesEnrichmentEnabled_TruthTable(t *testing.T) {
	cases := []struct {
		name    string
		enabled *bool
		ingress bool
		sentry  bool
		want    bool
	}{
		{"explicit true, no source", boolPtr(true), false, false, true},
		{"explicit false, ingress on", boolPtr(false), true, false, false},
		{"omitted, ingress on", nil, true, false, true},
		{"omitted, sentry releases on", nil, false, true, true},
		{"omitted, both sources off", nil, false, false, false},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.Changes.Enrichment.Enabled = tc.enabled
		cfg.Changes.Ingress.Enabled = tc.ingress
		cfg.Sentry.Releases.Enabled = tc.sentry
		if got := cfg.ChangesEnrichmentEnabled(); got != tc.want {
			t.Errorf("%s: ChangesEnrichmentEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMCPEnabled_TruthTable(t *testing.T) {
	cases := []struct {
		name    string
		enabled *bool
		token   string // value of the env var named by token_env; "" = absent
		want    bool
	}{
		{"explicit true, no token", boolPtr(true), "", true},
		{"explicit false, token set", boolPtr(false), "s3cret", false},
		{"omitted, token set", nil, "s3cret", true},
		{"omitted, no token", nil, "", false},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.MCP.Enabled = tc.enabled
		cfg.MCP.TokenEnv = "MCP_PRESENCE_TEST_TOKEN"
		t.Setenv("MCP_PRESENCE_TEST_TOKEN", tc.token)
		if got := cfg.MCPEnabled(); got != tc.want {
			t.Errorf("%s: MCPEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMCPEnabled_NoTokenEnvName: a blanked token_env can never presence-enable.
func TestMCPEnabled_NoTokenEnvName(t *testing.T) {
	cfg := Defaults()
	cfg.MCP.Enabled = nil
	cfg.MCP.TokenEnv = ""
	if cfg.MCPEnabled() {
		t.Error("MCPEnabled() = true with no token_env name, want false")
	}
}

// TestMCPToken_ExplicitOnWithoutToken: enabled: true without the env var set
// still fails loud at token resolution (unchanged fail-fast behavior).
func TestMCPToken_ExplicitOnWithoutToken(t *testing.T) {
	cfg := Defaults()
	cfg.MCP.Enabled = boolPtr(true)
	cfg.MCP.TokenEnv = "MCP_PRESENCE_TEST_TOKEN_UNSET"
	if _, err := cfg.MCPToken(); err == nil || !strings.Contains(err.Error(), "MCP_PRESENCE_TEST_TOKEN_UNSET") {
		t.Errorf("MCPToken() error = %v, want env-var-not-set error", err)
	}
}

// TestLoad_PresenceEnablesPrometheus verifies the end-to-end YAML path: a
// config that only sets prometheus.base_url validates clean and resolves ON,
// under strict decoding (KnownFields).
func TestLoad_PresenceEnablesPrometheus(t *testing.T) {
	yaml := `
receivers:
  address: ":9000"
alertmanager:
  webhook_token_env: TOK
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + filepath.Join(t.TempDir(), "agent.db") + `"
prometheus:
  base_url: http://localhost:9090
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.PrometheusEnabled() {
		t.Error("prometheus.base_url set + enabled omitted should resolve ON")
	}
	if cfg.LogsEnabled() || cfg.ChangesEnrichmentEnabled() {
		t.Error("unconfigured logs/changes must stay OFF")
	}
}

// TestLoad_ExplicitFalseDecodesAsForceOff verifies the *bool round-trip: an
// explicit `enabled: false` survives the merge over defaults and wins over a
// configured base_url.
func TestLoad_ExplicitFalseDecodesAsForceOff(t *testing.T) {
	yaml := `
receivers:
  address: ":9000"
alertmanager:
  webhook_token_env: TOK
llm:
  api_key_env: ANTHROPIC_API_KEY
storage:
  sqlite_path: "` + filepath.Join(t.TempDir(), "agent.db") + `"
prometheus:
  enabled: false
  base_url: http://localhost:9090
logs:
  enabled: false
  loki:
    base_url: http://loki:3100
`
	path := writeConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrometheusEnabled() {
		t.Error("explicit prometheus.enabled=false must force OFF despite base_url")
	}
	if cfg.LogsEnabled() {
		t.Error("explicit logs.enabled=false must force OFF despite loki.base_url")
	}
}

// TestValidate_ExplicitEnabledWithoutURLStillErrors preserves the pre-existing
// contract: enabled: true with no base_url is a loud validation failure.
func TestValidate_ExplicitEnabledWithoutURLStillErrors(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Prometheus.Enabled = boolPtr(true)
	cfg.Prometheus.BaseURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "prometheus.base_url") {
		t.Errorf("want prometheus.base_url error, got: %v", err)
	}
}

// TestLoad_PresenceEnabledLokiValidates verifies a presence-enabled logs
// section is fully validated (the provider default makes base_url alone
// sufficient, and the loki checks still run).
func TestLoad_PresenceEnabledLokiValidates(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Logs.Loki.BaseURL = "http://loki:3100"
	cfg.Logs.Loki.Auth.Mode = "bearer" // token_env missing → must fail loud
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logs.loki.auth.token_env") {
		t.Errorf("presence-enabled logs must run loki validation, got: %v", err)
	}
}

func TestValidateNotify_MinSeverity(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Notify.Slack.Enabled = true
	cfg.Notify.Slack.BotTokenEnv = "SLACK_BOT_TOKEN"
	cfg.Notify.Slack.Channel = "#alerts"

	for _, ok := range []string{"", "low", "medium", "high", "HIGH"} {
		cfg.Notify.Slack.MinSeverity = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("min_severity %q should validate, got: %v", ok, err)
		}
	}
	cfg.Notify.Slack.MinSeverity = "urgent"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "min_severity") {
		t.Errorf("min_severity=urgent must fail validation, got: %v", err)
	}
}

func TestDefaults_MinSeverityLow(t *testing.T) {
	if got := Defaults().Notify.Slack.MinSeverity; got != "low" {
		t.Errorf("default notify.slack.min_severity = %q, want low", got)
	}
}

func TestValidateNotify_RecurrenceMode(t *testing.T) {
	cfg := validBaseConfig(t)
	cfg.Notify.Slack.Enabled = true
	cfg.Notify.Slack.BotTokenEnv = "SLACK_BOT_TOKEN"
	cfg.Notify.Slack.Channel = "#alerts"

	for _, ok := range []string{"", "change-gated", "off"} {
		cfg.Notify.Slack.RecurrenceMode = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("recurrence_mode %q should validate, got: %v", ok, err)
		}
	}
	cfg.Notify.Slack.RecurrenceMode = "loud"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "recurrence_mode") {
		t.Errorf("recurrence_mode=loud must fail validation, got: %v", err)
	}
}

func TestDefaults_RecurrenceModeChangeGated(t *testing.T) {
	if got := Defaults().Notify.Slack.RecurrenceMode; got != "change-gated" {
		t.Errorf("default notify.slack.recurrence_mode = %q, want change-gated", got)
	}
}
