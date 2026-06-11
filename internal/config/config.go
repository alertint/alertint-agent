// SPDX-License-Identifier: FSL-1.1-ALv2

// Package config defines the on-disk YAML configuration for the alertint
// agent and provides loading, defaulting, and validation.
//
// Design notes:
//   - The YAML schema uses *_env fields (e.g. webhook_token_env) to *name*
//     the env var that holds a secret, never the secret value itself.
//     Accessors like Config.WebhookToken() resolve those env vars at call
//     time so the agent never holds a secret it doesn't currently need.
//   - Defaults are filled in by applyDefaults before validation, so callers
//     only see a fully-populated *Config.
//   - Validation is intentionally strict for v1: unknown YAML fields are
//     rejected so config drift surfaces immediately instead of silently.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the full agent configuration loaded from YAML.
//
// Each integration section (alertmanager, notify.slack, mcp, prometheus)
// carries its own enabled flag so deployments can mix and match sources and
// sinks. Only the Alertmanager webhook receiver is enabled by default.
type Config struct {
	Alertmanager AlertmanagerConfig `yaml:"alertmanager"`
	Storage      StorageConfig      `yaml:"storage"`
	LLM          LLMConfig          `yaml:"llm"`
	Correlator   CorrelatorConfig   `yaml:"correlator"`
	Notify       NotifyConfig       `yaml:"notify"`
	MCP          MCPConfig          `yaml:"mcp"`
	Prometheus   PrometheusConfig   `yaml:"prometheus"`
	LogLevel     string             `yaml:"log_level"`
}

// PrometheusConfig configures the optional Prometheus read connector.
// When enabled, MCP tools can run instant and range PromQL queries against
// the configured Prometheus instance.
type PrometheusConfig struct {
	Enabled             bool   `yaml:"enabled"`
	BaseURL             string `yaml:"base_url"`
	BearerTokenEnv      string `yaml:"bearer_token_env,omitempty"`
	TimeoutSeconds      int    `yaml:"timeout_seconds"`
	DefaultRangeMinutes int    `yaml:"default_range_minutes"`
}

// MCPConfig configures the HTTP MCP server exposed by alertint serve.
// When enabled, alertint serve starts a second HTTP listener (default :9912)
// that MCP clients (Claude Code, Cursor, Windsurf) can reach over the network.
type MCPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	TokenEnv string `yaml:"token_env"`
}

// AlertmanagerConfig configures the inbound Alertmanager webhook receiver.
// It also serves GET /health, so disabling it removes that endpoint too.
type AlertmanagerConfig struct {
	Enabled         bool   `yaml:"enabled"`
	WebhookAddr     string `yaml:"webhook_addr"`
	WebhookTokenEnv string `yaml:"webhook_token_env"`
}

// StorageConfig configures the SQLite store.
type StorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

// LLMConfig configures the LLM provider used by skills.
type LLMConfig struct {
	Provider  string `yaml:"provider"`
	APIKeyEnv string `yaml:"api_key_env"`
	Model     string `yaml:"model"`
}

// CorrelatorConfig configures the time-window correlator.
type CorrelatorConfig struct {
	WindowSeconds int      `yaml:"window_seconds"`
	MinAlerts     int      `yaml:"min_alerts"`
	GroupLabels   []string `yaml:"group_labels"`
}

// NotifyConfig configures notifiers.
type NotifyConfig struct {
	Stdout bool        `yaml:"stdout"`
	Slack  SlackConfig `yaml:"slack"`
}

// SlackConfig configures the optional Slack Bot Token notifier.
type SlackConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"` // env var holding the xoxb- bot token
	Channel     string `yaml:"channel"`       // e.g. "#alerts" or "C1234567890"
}

// Defaults returns a Config populated with v1 defaults. The result is not
// usable on its own (e.g. WebhookTokenEnv must be set by the user) but it
// represents the sensible baseline that Load merges user input into.
func Defaults() Config {
	return Config{
		Alertmanager: AlertmanagerConfig{
			Enabled:     true,
			WebhookAddr: ":9911",
		},
		Storage: StorageConfig{
			SQLitePath: "./alertint-agent.db",
		},
		LLM: LLMConfig{
			Provider: "anthropic",
			Model:    "claude-haiku-4-5-20251001",
		},
		Correlator: CorrelatorConfig{
			WindowSeconds: 90,
			MinAlerts:     2,
			GroupLabels:   []string{"cluster", "namespace", "service"},
		},
		Notify: NotifyConfig{
			Stdout: true,
			Slack: SlackConfig{
				Enabled: false,
			},
		},
		MCP: MCPConfig{
			// Binds all interfaces: the agent targets shared environments
			// and MCP access is gated by the mandatory bearer token.
			Addr: "0.0.0.0:9912",
		},
		Prometheus: PrometheusConfig{
			TimeoutSeconds:      10,
			DefaultRangeMinutes: 60,
		},
		LogLevel: "info",
	}
}

// Load reads a YAML config from path, applies defaults for missing fields,
// and validates the result.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the operator-supplied --config flag; reading it is the point
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return LoadFrom(f, path)
}

// LoadFrom is like Load but reads from an io.Reader. The path argument is
// only used for error messages and writability checks for storage paths;
// pass "" if there is no associated path.
func LoadFrom(r io.Reader, path string) (*Config, error) {
	cfg := Defaults()

	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown YAML keys
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: parse %s: %w", displayPath(path), err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", displayPath(path), err)
	}
	return &cfg, nil
}

// Validate checks the Config is internally consistent and ready for use.
// It does not read environment variables; secret presence is checked by
// the Must* accessors at the moment of need.
func (c *Config) Validate() error {
	var errs []string
	errs = append(errs, c.validateServing()...)
	errs = append(errs, c.validateStorage()...)
	errs = append(errs, c.validateLLM()...)
	errs = append(errs, c.validateCorrelator()...)
	errs = append(errs, c.validateNotify()...)
	errs = append(errs, c.validatePrometheus()...)

	if !validLogLevel(c.LogLevel) {
		errs = append(errs, fmt.Sprintf("log_level %q must be one of debug, info, warn, error", c.LogLevel))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validateServing covers the two listener integrations (alertmanager webhook
// receiver and MCP server) and the requirement that at least one is enabled.
func (c *Config) validateServing() []string {
	var errs []string
	if c.Alertmanager.Enabled {
		if strings.TrimSpace(c.Alertmanager.WebhookAddr) == "" {
			errs = append(errs, "alertmanager.webhook_addr is required when alertmanager is enabled")
		}
		if strings.TrimSpace(c.Alertmanager.WebhookTokenEnv) == "" {
			errs = append(errs, "alertmanager.webhook_token_env is required when alertmanager is enabled (env var name holding the bearer token)")
		}
	}
	if c.MCP.Enabled {
		if strings.TrimSpace(c.MCP.Addr) == "" {
			errs = append(errs, "mcp.addr is required when mcp is enabled")
		}
		if strings.TrimSpace(c.MCP.TokenEnv) == "" {
			errs = append(errs, "mcp.token_env is required when mcp is enabled")
		}
	}
	if !c.Alertmanager.Enabled && !c.MCP.Enabled {
		errs = append(errs, "nothing to serve: enable at least one of alertmanager or mcp")
	}
	return errs
}

func (c *Config) validateStorage() []string {
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return []string{"storage.sqlite_path is required"}
	}
	if err := checkSQLitePathWritable(c.Storage.SQLitePath); err != nil {
		return []string{fmt.Sprintf("storage.sqlite_path: %v", err)}
	}
	return nil
}

func (c *Config) validateLLM() []string {
	var errs []string
	switch strings.ToLower(c.LLM.Provider) {
	case "anthropic":
		// ok
	case "":
		errs = append(errs, "llm.provider is required")
	default:
		errs = append(errs, fmt.Sprintf("llm.provider %q not supported in v1 (only \"anthropic\")", c.LLM.Provider))
	}
	if strings.TrimSpace(c.LLM.APIKeyEnv) == "" {
		errs = append(errs, "llm.api_key_env is required (env var name holding the LLM API key)")
	}
	if strings.TrimSpace(c.LLM.Model) == "" {
		errs = append(errs, "llm.model is required")
	}
	return errs
}

func (c *Config) validateCorrelator() []string {
	var errs []string
	if c.Correlator.WindowSeconds <= 0 {
		errs = append(errs, "correlator.window_seconds must be > 0")
	}
	if c.Correlator.MinAlerts < 1 {
		errs = append(errs, "correlator.min_alerts must be >= 1")
	}
	if len(c.Correlator.GroupLabels) == 0 {
		errs = append(errs, "correlator.group_labels must contain at least one label")
	} else {
		for i, label := range c.Correlator.GroupLabels {
			if strings.TrimSpace(label) == "" {
				errs = append(errs, fmt.Sprintf("correlator.group_labels[%d] is empty", i))
			}
		}
	}
	return errs
}

func (c *Config) validateNotify() []string {
	var errs []string
	if c.Notify.Slack.Enabled {
		if strings.TrimSpace(c.Notify.Slack.BotTokenEnv) == "" {
			errs = append(errs, "notify.slack.bot_token_env is required when slack is enabled")
		}
		if strings.TrimSpace(c.Notify.Slack.Channel) == "" {
			errs = append(errs, "notify.slack.channel is required when slack is enabled")
		}
	}
	if !c.Notify.Stdout && !c.Notify.Slack.Enabled {
		errs = append(errs, "at least one notifier must be enabled (notify.stdout or notify.slack.enabled)")
	}
	return errs
}

func (c *Config) validatePrometheus() []string {
	var errs []string
	if !c.Prometheus.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Prometheus.BaseURL) == "" {
		errs = append(errs, "prometheus.base_url is required when prometheus is enabled")
	}
	if c.Prometheus.TimeoutSeconds <= 0 {
		errs = append(errs, "prometheus.timeout_seconds must be > 0")
	}
	if c.Prometheus.DefaultRangeMinutes <= 0 {
		errs = append(errs, "prometheus.default_range_minutes must be > 0")
	}
	return errs
}

// WebhookToken returns the bearer token for the inbound webhook receiver,
// resolved from the env var named by Alertmanager.WebhookTokenEnv.
// Returns an empty string and nil error when the receiver is disabled.
func (c *Config) WebhookToken() (string, error) {
	if !c.Alertmanager.Enabled {
		return "", nil
	}
	return requireEnv(c.Alertmanager.WebhookTokenEnv, "alertmanager.webhook_token_env")
}

// LLMAPIKey returns the LLM API key, resolved from the env var named by
// LLM.APIKeyEnv.
func (c *Config) LLMAPIKey() (string, error) {
	return requireEnv(c.LLM.APIKeyEnv, "llm.api_key_env")
}

// MCPToken returns the bearer token for the MCP HTTP server, resolved from
// the env var named by MCP.TokenEnv. Returns empty string when MCP is disabled.
func (c *Config) MCPToken() (string, error) {
	if !c.MCP.Enabled {
		return "", nil
	}
	return requireEnv(c.MCP.TokenEnv, "mcp.token_env")
}

// PrometheusToken returns the bearer token for Prometheus when configured,
// resolved from the env var named by Prometheus.BearerTokenEnv.
// Returns empty string and nil error when bearer_token_env is unset or prometheus is disabled.
func (c *Config) PrometheusToken() (string, error) {
	if !c.Prometheus.Enabled || strings.TrimSpace(c.Prometheus.BearerTokenEnv) == "" {
		return "", nil
	}
	return requireEnv(c.Prometheus.BearerTokenEnv, "prometheus.bearer_token_env")
}

// SlackBotToken returns the Slack bot token when Slack is enabled,
// resolved from the env var named by Notify.Slack.BotTokenEnv.
// Returns an empty string and nil error when Slack is disabled.
func (c *Config) SlackBotToken() (string, error) {
	if !c.Notify.Slack.Enabled {
		return "", nil
	}
	return requireEnv(c.Notify.Slack.BotTokenEnv, "notify.slack.bot_token_env")
}

func requireEnv(name, field string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%s is empty", field)
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", fmt.Errorf("%s: env var %q is not set", field, name)
	}
	return v, nil
}

func validLogLevel(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "info", "warn", "warning", "error":
		return true
	}
	return false
}

// checkSQLitePathWritable ensures the parent directory of the SQLite file
// exists and is writable. It does not create the file itself.
func checkSQLitePathWritable(p string) error {
	dir := filepath.Dir(p)
	if dir == "" {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("parent directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("parent path %s is not a directory", dir)
	}
	// Probe writability with a temp file in the same directory.
	probe, err := os.CreateTemp(dir, ".alertint-write-probe-*")
	if err != nil {
		return fmt.Errorf("parent directory %s not writable: %w", dir, err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)
	return nil
}

func displayPath(p string) string {
	if p == "" {
		return "<reader>"
	}
	return p
}
