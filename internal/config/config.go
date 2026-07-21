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
	"net/url"
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
	Receivers    ReceiversConfig    `yaml:"receivers"`
	Alertmanager AlertmanagerConfig `yaml:"alertmanager"`
	Changes      ChangesConfig      `yaml:"changes,omitempty"`
	Storage      StorageConfig      `yaml:"storage"`
	LLM          LLMConfig          `yaml:"llm"`
	Correlator   CorrelatorConfig   `yaml:"correlator"`
	Notify       NotifyConfig       `yaml:"notify"`
	MCP          MCPConfig          `yaml:"mcp"`
	Prometheus   PrometheusConfig   `yaml:"prometheus"`
	Logs         LogsConfig         `yaml:"logs,omitempty"`
	Sentry       SentryConfig       `yaml:"sentry,omitempty"`
	Rules        RulesConfig        `yaml:"rules"`
	Memory       MemoryConfig       `yaml:"memory"`
	Triage       TriageConfig       `yaml:"triage,omitempty"`
	LogLevel     string             `yaml:"log_level"`
	LogFormat    string             `yaml:"log_format"`
}

// RulesConfig configures rule pack loading. The embedded baseline pack is
// always loaded; local_pack_dir optionally adds one local pack directory
// (pack.yaml + rules/*.yaml + templates/*.md) whose rules and templates
// override baseline entries with the same id or name.
type RulesConfig struct {
	LocalPackDir string `yaml:"local_pack_dir,omitempty"`
}

// TriageConfig groups triage-pipeline tunables. Verification (the falsification
// round, ADR-0021/0022) is its first block.
type TriageConfig struct {
	Verification VerificationConfig `yaml:"verification"`
}

// VerificationConfig tunes the verification round. Enabled is a *bool so an
// omitted key means the default (on) while an explicit false is honored —
// resolve via Config.VerificationEnabled, never directly (the Prometheus
// Enabled idiom). max_rounds exists so multi-round is a config change later;
// only 1 is accepted today (rejected loudly, never silently clamped).
type VerificationConfig struct {
	Enabled             *bool `yaml:"enabled,omitempty"`
	MaxQueries          int   `yaml:"max_queries"`
	QueryTimeoutSeconds int   `yaml:"query_timeout_seconds"`
	MaxRounds           int   `yaml:"max_rounds"`
}

// PrometheusConfig configures the optional Prometheus read connector.
// When enabled, MCP tools can run instant and range PromQL queries against
// the configured Prometheus instance.
//
// Enabled is a *bool so presence-based enablement survives the YAML merge:
// an omitted key (nil) means "on when base_url is set", an explicit value is
// honored either way. Resolve it via Config.PrometheusEnabled, never directly.
type PrometheusConfig struct {
	Enabled             *bool  `yaml:"enabled,omitempty"`
	BaseURL             string `yaml:"base_url"`
	BearerTokenEnv      string `yaml:"bearer_token_env,omitempty"`
	TimeoutSeconds      int    `yaml:"timeout_seconds"`
	DefaultRangeMinutes int    `yaml:"default_range_minutes"`
	MaxSeries           int    `yaml:"max_series"` // server-side per-query series cap for metric enrichment
}

// LogsConfig configures the optional log-enrichment connector. When enabled,
// the acute-triage skill pulls recent log lines into the triage prompt and the
// MCP server exposes a native-query passthrough tool. Generic enrichment knobs
// live at the top; provider connection details nest under the named provider
// (only loki in v1). Read-only: the connector never writes logs.
//
// Enabled is a *bool for presence-based enablement: an omitted key (nil)
// means "on when loki.base_url is set", an explicit value is honored either
// way. Resolve it via Config.LogsEnabled, never directly.
type LogsConfig struct {
	Enabled             *bool      `yaml:"enabled,omitempty"`
	Provider            string     `yaml:"provider"`              // only "loki" in v1
	TimeoutSeconds      int        `yaml:"timeout_seconds"`       // TOTAL budget for the whole fetch (filtered + fallback share it)
	DefaultRangeMinutes int        `yaml:"default_range_minutes"` // window before the first alert
	MaxLines            int        `yaml:"max_lines"`             // backend query limit
	Loki                LokiConfig `yaml:"loki,omitempty"`
}

// LokiConfig holds Loki/Grafana-Cloud connection details. The provider owns all
// translation of the generic selector into LogQL via LabelMap and LineFilter.
type LokiConfig struct {
	BaseURL    string            `yaml:"base_url"`
	Auth       LokiAuthConfig    `yaml:"auth,omitempty"`
	OrgID      string            `yaml:"org_id,omitempty"`      // optional X-Scope-OrgID (self-hosted multi-tenant only)
	LineFilter string            `yaml:"line_filter,omitempty"` // default error-biased; "" disables filtering
	LabelMap   map[string]string `yaml:"label_map,omitempty"`   // alert-label key → stream-label key ("" = drop)
}

// LokiAuthConfig selects the Loki auth mode and names the env vars holding any
// secrets. Secrets are never inline; username (basic mode) is an account
// identifier, not a secret, so it is read inline.
type LokiAuthConfig struct {
	Mode        string `yaml:"mode"`                   // none | bearer | basic (default none)
	TokenEnv    string `yaml:"token_env,omitempty"`    // bearer mode: env var holding the token
	Username    string `yaml:"username,omitempty"`     // basic mode: user/instance ID (not a secret)
	PasswordEnv string `yaml:"password_env,omitempty"` // basic mode: env var holding the token/password
}

// SentryConfig configures the optional Sentry change source. The top-level
// fields are the shared read-only connection (base URL, org, token env var,
// timeout) reused by every Sentry feature; per-feature pollers nest under their
// own sub-block. v1 ships the releases/deploys poller (Releases); later specs
// add sibling sub-blocks (e.g. issues) that reuse this same connection. Mirrors
// the logs/loki nesting: shared connection at the top, opt-in poller below.
type SentryConfig struct {
	BaseURL        string               `yaml:"base_url"`        // host root, e.g. https://sentry.io, https://de.sentry.io, or a self-hosted host
	Org            string               `yaml:"org"`             // organization slug
	TokenEnv       string               `yaml:"token_env"`       // env var holding the Internal-Integration token (project:read for releases, event:read for issues)
	TimeoutSeconds int                  `yaml:"timeout_seconds"` // HTTP timeout per request
	Releases       SentryReleasesConfig `yaml:"releases,omitempty"`
	Issues         SentryIssuesConfig   `yaml:"issues,omitempty"`
}

// SentryReleasesConfig configures the release/deploy poller: its own enabled
// flag (per-feature opt-in), poll interval, first-run look-back, the
// release-scan horizon bounding how old a release can be and still have its new
// deploys detected, and an optional project-slug filter. When disabled the
// poller is never constructed and no Sentry calls are made.
type SentryReleasesConfig struct {
	Enabled                bool     `yaml:"enabled"`
	PollIntervalSeconds    int      `yaml:"poll_interval_seconds"`
	InitialLookbackMinutes int      `yaml:"initial_lookback_minutes"`
	ReleaseScanHorizonDays int      `yaml:"release_scan_horizon_days"`
	Projects               []string `yaml:"projects,omitempty"` // optional project-slug filter; empty = org-wide
}

// SentryIssuesConfig configures the Error source: the bounded query-at-triage
// that contributes the distilled `sentry` enrichment section (exception +
// file:line, blast radius, NEW-in-window). Like the releases poller it has its
// own enabled flag (per-feature opt-in) but reuses the shared SentryConfig
// connection. LookbackMinutes sets W = [first_alert − lookback, now]; MaxIssues
// caps the K of the 1+K call budget; FetchTimeoutSeconds bounds the WHOLE 1+K
// fetch (distinct from the per-request timeout_seconds), so one slow event fetch
// can't starve the rest. IncludeMessage is a *bool so default-on survives the
// YAML merge (an omitted key keeps the default; an explicit false overrides),
// the same explicit-vs-omitted reasoning as Loki's LineFilter — resolve it via
// MessageIncluded. LiveWindowMinutes is the default look-back for the live
// sentry_issues_list MCP tool when start/end are omitted (Spec 3 chunk 02, KTD7) —
// a live "what is erroring now" look, distinct from the triage LookbackMinutes.
type SentryIssuesConfig struct {
	Enabled             bool  `yaml:"enabled"`
	LookbackMinutes     int   `yaml:"lookback_minutes"`
	MaxIssues           int   `yaml:"max_issues"`
	FetchTimeoutSeconds int   `yaml:"fetch_timeout_seconds"`
	LiveWindowMinutes   int   `yaml:"live_window_minutes"`
	IncludeMessage      *bool `yaml:"include_message,omitempty"`
}

// MessageIncluded resolves the include_message toggle to a plain bool: an
// omitted key (nil) defaults ON (R14), an explicit value is honored. Off strips
// the exception message from all three surfaces (prompt, at-rest SQLite,
// evidence-pack MCP).
func (s SentryIssuesConfig) MessageIncluded() bool {
	return s.IncludeMessage == nil || *s.IncludeMessage
}

// MCPConfig configures the HTTP MCP server exposed by alertint serve.
// When enabled, alertint serve starts a second HTTP listener (default :9912)
// that MCP clients (Claude Code, Cursor, Windsurf) can reach over the network.
//
// Enabled is a *bool so presence-based enablement survives the YAML merge:
// an omitted key (nil) means "on when the env var named by token_env holds a
// token", an explicit value is honored either way. Resolve it via
// Config.MCPEnabled, never directly.
type MCPConfig struct {
	Enabled  *bool  `yaml:"enabled,omitempty"`
	Addr     string `yaml:"addr"`
	TokenEnv string `yaml:"token_env"`
}

// AlertmanagerConfig configures the inbound Alertmanager webhook receiver. Its
// listen address is the shared receivers.address (see ReceiversConfig).
type AlertmanagerConfig struct {
	Enabled         bool   `yaml:"enabled"`
	WebhookTokenEnv string `yaml:"webhook_token_env"`
}

// ReceiversConfig holds settings shared by every inbound webhook receiver. The
// listen address is a server concern, not a per-receiver one, so all receivers
// (alertmanager, change, later zabbix) mount on this single address.
type ReceiversConfig struct {
	Address string `yaml:"address"`
}

// ChangesConfig is the dual-role change-events namespace: Ingress receives
// change webhooks (write surface); Enrichment uses stored changes (triage +
// MCP). RetentionDays bounds the append-only changes table.
type ChangesConfig struct {
	Ingress       ChangesIngressConfig    `yaml:"ingress"`
	Enrichment    ChangesEnrichmentConfig `yaml:"enrichment"`
	RetentionDays int                     `yaml:"retention_days"`
}

// ChangesIngressConfig configures the inbound change-event webhook receiver
// (write surface).
type ChangesIngressConfig struct {
	Enabled         bool   `yaml:"enabled"`
	WebhookTokenEnv string `yaml:"webhook_token_env"`
}

// ChangesEnrichmentConfig configures using stored changes at triage time and
// over MCP (read surface).
//
// Enabled is a *bool for presence-based enablement: an omitted key (nil)
// means "on when a change source is producing events" (changes.ingress or the
// Sentry releases poller), an explicit value is honored either way. Resolve
// it via Config.ChangesEnrichmentEnabled, never directly.
type ChangesEnrichmentConfig struct {
	Enabled       *bool `yaml:"enabled,omitempty"`
	WindowMinutes int   `yaml:"window_minutes"`
	MaxEvents     int   `yaml:"max_events"`
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
	// MaxTokens is the output-token ceiling for the triage reply. The finding
	// schema emits one entry per member alert, so a large correlated incident
	// needs well over the old 1024 default or the JSON is truncated mid-object
	// and the whole triage fails. Defaults to 4096; raise it for very large
	// correlations.
	MaxTokens int `yaml:"max_tokens"`
	// BaseURL is the root URL of an OpenAI-compatible endpoint (SGLang, vLLM,
	// Ollama, LM Studio). Required for provider "openai-compatible", rejected
	// for "anthropic". A trailing /v1 is accepted and stripped at load — both
	// http://host:11434 and http://host:11434/v1 reach the same endpoint.
	BaseURL string `yaml:"base_url"`
	// ResponseFormat controls enforced-JSON output on "openai-compatible":
	// "json_object" (default — fails loud if the runtime lacks JSON mode) or
	// "off". Rejected for "anthropic".
	ResponseFormat string `yaml:"response_format"`
	// Thinking opts a hybrid-reasoning model (Qwen/DeepSeek-class) into
	// thinking on "openai-compatible": every request carries
	// chat_template_kwargs {"enable_thinking": <value>}. Default false —
	// thinking output competes with the JSON reply for max_tokens; enabling
	// it requires raising llm.max_tokens to 8–16k. Rejected (when true) for
	// "anthropic", which pins thinking disabled in the client.
	Thinking bool `yaml:"thinking"`
	// TimeoutSeconds is the whole-request HTTP timeout for either provider.
	// Default 120 (the previously hardcoded client default). Local endpoints
	// under storm concurrency typically need ~300.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// CorrelatorConfig configures the time-window correlator.
type CorrelatorConfig struct {
	WindowSeconds int      `yaml:"window_seconds"`
	MinAlerts     int      `yaml:"min_alerts"`
	GroupLabels   []string `yaml:"group_labels"`
}

// MemoryConfig tunes incident memory: recurrence collapse (M1) and, in later
// milestones, recall (M2) and the shadow classifier (M3). Collapse and recall
// are deterministic, free, and default-on — these knobs are the control
// surface, not an enable switch. The classifier sub-block lands with M3.
type MemoryConfig struct {
	AttachWindowMinutes  int              `yaml:"attach_window_minutes"`  // Clock A: sliding attach window from the last occurrence
	JudgmentCeilingHours int              `yaml:"judgment_ceiling_hours"` // Clock B: hard ceiling on time since the last LLM judgment
	OccurrenceCap        int              `yaml:"occurrence_cap"`         // re-judge backstop after this many attaches since the last judgment
	LookbackDays         int              `yaml:"lookback_days"`          // occurrence pruning + recall lookback horizon
	Classifier           ClassifierConfig `yaml:"classifier"`             // M3 shadow classifier: dark by default
}

// ClassifierConfig is the M3 shadow-classifier control surface (ADR-0018). The
// classifier is a second, small Haiku call that judges whether a weak-signal
// (one-label-off) prefilter candidate is the same underlying condition. It is
// dark by default: Mode "off" makes no call at all, "shadow" runs the call and
// records every verdict in the audit log while the rendered recall stays
// deterministic, and "on" lets a graduated match tag the recall render. Graduation
// is per-installation — the operator flips shadow→on once their own audit log shows
// the documented precision gate.
type ClassifierConfig struct {
	Mode           ClassifierMode `yaml:"mode"`            // off | shadow | on (default off)
	TimeoutSeconds int            `yaml:"timeout_seconds"` // seconds-scale budget for the classifier's own client
}

// ClassifierMode is the off|shadow|on knob. It has a custom scalar decoder
// because YAML 1.1 resolves bare off/on (and yes/no/true/false) to booleans, so
// `mode: off` unquoted would otherwise fail with "cannot unmarshal !!bool into
// string". Keeping the literal scalar lets the mode be written with or without
// quotes; validateMemory rejects anything outside the enum.
type ClassifierMode string

const (
	ClassifierModeOff    ClassifierMode = "off"
	ClassifierModeShadow ClassifierMode = "shadow"
	ClassifierModeOn     ClassifierMode = "on"
)

// UnmarshalYAML keeps the literal scalar text (off, on, shadow, or an invalid
// value passed through to validation) instead of letting yaml.v3 coerce the
// bool-keyword forms.
func (m *ClassifierMode) UnmarshalYAML(value *yaml.Node) error {
	*m = ClassifierMode(strings.TrimSpace(value.Value))
	return nil
}

// Enabled reports whether the classifier runs at all (mode is shadow or on).
func (c ClassifierConfig) Enabled() bool {
	return c.Mode == ClassifierModeShadow || c.Mode == ClassifierModeOn
}

// NotifyConfig configures notifiers.
type NotifyConfig struct {
	Stdout bool        `yaml:"stdout"`
	Slack  SlackConfig `yaml:"slack"`
}

// SlackConfig configures the optional Slack Bot Token notifier. MinSeverity
// is the channel noise gate: findings whose severity ranks below it are not
// posted to Slack (stdout always emits). The default "low" posts everything —
// visibility over obscurity; raising it later is the off-switch.
type SlackConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"` // env var holding the xoxb- bot token
	Channel     string `yaml:"channel"`       // e.g. "#alerts" or "C1234567890"
	MinSeverity string `yaml:"min_severity"`  // low | medium | high (default low = post everything)
	// RecurrenceMode gates how recurrence-collapse re-fires resurface in Slack
	// (ADR-0020): "change-gated" (default) posts thread replies for
	// real-world-change rungs + milestones (thread-only, never sent to the
	// channel); "off" is the count-bump-only escape. Empty = change-gated.
	RecurrenceMode string `yaml:"recurrence_mode"` // change-gated | off
}

// Defaults returns a Config populated with v1 defaults. The result is not
// usable on its own (e.g. WebhookTokenEnv must be set by the user) but it
// represents the sensible baseline that Load merges user input into.
func Defaults() Config {
	return Config{
		Receivers: ReceiversConfig{
			Address: ":9911",
		},
		Alertmanager: AlertmanagerConfig{
			Enabled: true,
		},
		Changes: ChangesConfig{
			Enrichment: ChangesEnrichmentConfig{
				WindowMinutes: 120,
				MaxEvents:     10,
			},
			RetentionDays: 30,
		},
		Storage: StorageConfig{
			SQLitePath: "./alertint-agent.db",
		},
		LLM: LLMConfig{
			Provider: "anthropic",
			// Sonnet by default: the first finding should come from the
			// strongest reasoning tier in its price class. claude-haiku-4-5
			// stays a one-line opt-in for cost-sensitive deployments.
			Model: "claude-sonnet-5",
			// 4096: a comfortable ceiling for the per-alert finding JSON. The
			// old hardcoded 1024 truncated large correlated incidents mid-reply;
			// this covers realistic incidents and is a config knob for the rest.
			MaxTokens:      4096,
			TimeoutSeconds: 120,
		},
		Correlator: CorrelatorConfig{
			WindowSeconds: 90,
			// 1: a lone first alert still produces a finding. Slack noise is
			// controlled by notify.slack.min_severity, not by dropping triage.
			MinAlerts:   1,
			GroupLabels: []string{"cluster", "namespace", "service"},
		},
		Notify: NotifyConfig{
			Stdout: true,
			Slack: SlackConfig{
				Enabled:        false,
				MinSeverity:    "low",
				RecurrenceMode: "change-gated",
			},
		},
		MCP: MCPConfig{
			// Binds all interfaces: the agent targets shared environments
			// and MCP access is gated by the mandatory bearer token.
			Addr: "0.0.0.0:9912",
			// Named here (not just in the example config) so presence-based
			// enablement has an env var to probe under zero config.
			TokenEnv: "ALERTINT_MCP_TOKEN", // #nosec G101 -- env var NAME, not a credential
		},
		Prometheus: PrometheusConfig{
			TimeoutSeconds:      10,
			DefaultRangeMinutes: 60,
			MaxSeries:           1000,
		},
		Logs: LogsConfig{
			// Only loki exists in v1, so defaulting the provider lets
			// presence-based enablement work from loki.base_url alone.
			Provider:            "loki",
			TimeoutSeconds:      10,
			DefaultRangeMinutes: 15,
			MaxLines:            50,
			Loki: LokiConfig{
				Auth: LokiAuthConfig{Mode: "none"},
				// Error-biased default: operators who omit line_filter get this;
				// setting line_filter: "" explicitly disables filtering. Because
				// the default lives here, that distinction survives the YAML merge
				// (an explicit "" overwrites; an omission keeps this value).
				LineFilter: `|~ "(?i)(error|warn|fatal|panic|fail)"`,
			},
		},
		Sentry: SentryConfig{
			TimeoutSeconds: 10,
			Releases: SentryReleasesConfig{
				PollIntervalSeconds:    60,
				InitialLookbackMinutes: 60,
				ReleaseScanHorizonDays: 30,
			},
			Issues: SentryIssuesConfig{
				// W reaches a precursor error that started minutes before the
				// storm — decoupled from the 90s correlator window (KTD6).
				LookbackMinutes:     30,
				MaxIssues:           3, // the K of the 1+K call budget (KTD5)
				FetchTimeoutSeconds: 15,
				LiveWindowMinutes:   60, // live sentry_issues_list default look-back (Spec 3 chunk 02, KTD7)
				// IncludeMessage left nil → defaults ON via MessageIncluded (R14).
			},
		},
		Triage: TriageConfig{
			Verification: VerificationConfig{
				MaxQueries:          4,
				QueryTimeoutSeconds: 10,
				MaxRounds:           1,
			},
		},
		Memory: MemoryConfig{
			AttachWindowMinutes:  30,
			JudgmentCeilingHours: 4,
			OccurrenceCap:        100,
			LookbackDays:         90,
			Classifier: ClassifierConfig{
				// Dark by default (ADR-0018): no classifier call until the operator
				// opts into gathering their own graduation evidence.
				Mode:           ClassifierModeOff,
				TimeoutSeconds: 10,
			},
		},
		LogLevel:  "info",
		LogFormat: "auto",
	}
}

// Load reads a YAML config from path, applies defaults for missing fields,
// and validates the result.
func Load(path string) (*Config, error) {
	return loadPath(path, false)
}

// LoadOffline is Load with ValidateOffline instead of Validate: the
// environment-coupled filesystem checks are skipped, so a config destined
// for another machine dry-runs cleanly (alertint validate).
func LoadOffline(path string) (*Config, error) {
	return loadPath(path, true)
}

func loadPath(path string, offline bool) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the operator-supplied --config flag; reading it is the point
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return loadFrom(f, path, offline)
}

// LoadFrom is like Load but reads from an io.Reader. The path argument is
// only used for error messages and writability checks for storage paths;
// pass "" if there is no associated path.
func LoadFrom(r io.Reader, path string) (*Config, error) {
	return loadFrom(r, path, false)
}

func loadFrom(r io.Reader, path string, offline bool) (*Config, error) {
	cfg := Defaults()

	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown YAML keys
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: parse %s: %w", displayPath(path), err)
	}

	if err := cfg.validate(offline); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", displayPath(path), err)
	}
	return &cfg, nil
}

// Validate checks the Config is internally consistent and ready for use.
// It does not read environment variables; secret presence is checked by
// the Must* accessors at the moment of need.
func (c *Config) Validate() error {
	return c.validate(false)
}

// ValidateOffline is Validate minus the environment-coupled filesystem
// checks (the storage.sqlite_path parent-dir write probe and the
// rules.local_pack_dir stat), so a config destined for another machine —
// e.g. a pod path like /data/alertint.db — validates cleanly on a laptop
// or CI runner. The result reflects the config's correctness, not the
// validating machine's filesystem.
func (c *Config) ValidateOffline() error {
	return c.validate(true)
}

func (c *Config) validate(offline bool) error {
	var errs []string
	errs = append(errs, c.validateServing()...)
	errs = append(errs, c.validateStorage(offline)...)
	errs = append(errs, c.validateLLM()...)
	errs = append(errs, c.validateCorrelator()...)
	errs = append(errs, c.validateNotify()...)
	errs = append(errs, c.validatePrometheus()...)
	errs = append(errs, c.validateLogs()...)
	errs = append(errs, c.validateSentry()...)
	errs = append(errs, c.validateChanges()...)
	errs = append(errs, c.validateVerification()...)
	errs = append(errs, c.validateMemory()...)
	if !offline {
		errs = append(errs, c.validateRules()...)
	}

	if !validLogLevel(c.LogLevel) {
		errs = append(errs, fmt.Sprintf("log_level %q must be one of debug, info, warn, error", c.LogLevel))
	}
	if !validLogFormat(c.LogFormat) {
		errs = append(errs, fmt.Sprintf("log_format %q must be one of auto, console, json", c.LogFormat))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validateServing covers the inbound webhook host (all receivers share
// receivers.address), the MCP server, and the requirement that at least one of
// them is enabled. NOTE: when the Zabbix integration lands it adds
// `|| c.Zabbix.Ingress.Enabled` to inboundEnabled and the nothing-to-serve
// check — the two specs compose.
func (c *Config) validateServing() []string {
	var errs []string
	inboundEnabled := c.Alertmanager.Enabled || c.Changes.Ingress.Enabled
	if inboundEnabled && strings.TrimSpace(c.Receivers.Address) == "" {
		errs = append(errs, "receivers.address is required when any receiver is enabled (alertmanager or changes.ingress)")
	}
	if c.Alertmanager.Enabled {
		if strings.TrimSpace(c.Alertmanager.WebhookTokenEnv) == "" {
			errs = append(errs, "alertmanager.webhook_token_env is required when alertmanager is enabled (env var name holding the bearer token)")
		}
	}
	if c.Changes.Ingress.Enabled {
		if strings.TrimSpace(c.Changes.Ingress.WebhookTokenEnv) == "" {
			errs = append(errs, "changes: ingress: webhook_token_env is required when enabled (env var name holding the bearer token)")
		}
	}
	if c.MCPEnabled() {
		if strings.TrimSpace(c.MCP.Addr) == "" {
			errs = append(errs, "mcp.addr is required when mcp is enabled")
		}
		if strings.TrimSpace(c.MCP.TokenEnv) == "" {
			errs = append(errs, "mcp.token_env is required when mcp is enabled")
		}
	}
	if !c.Alertmanager.Enabled && !c.Changes.Ingress.Enabled && !c.MCPEnabled() {
		errs = append(errs, "nothing to serve: enable at least one of alertmanager, changes.ingress, or mcp")
	}
	return errs
}

// validateChanges checks the enrichment tunables and retention. Ingress-token
// validation lives in validateServing (it gates the inbound server).
func (c *Config) validateChanges() []string {
	var errs []string
	if c.ChangesEnrichmentEnabled() {
		if c.Changes.Enrichment.WindowMinutes <= 0 {
			errs = append(errs, "changes: enrichment: window_minutes must be > 0")
		}
		if c.Changes.Enrichment.MaxEvents <= 0 {
			errs = append(errs, "changes: enrichment: max_events must be > 0")
		}
	}
	if (c.Changes.Ingress.Enabled || c.ChangesEnrichmentEnabled()) && c.Changes.RetentionDays <= 0 {
		errs = append(errs, "changes: retention_days must be > 0 when changes are enabled")
	}
	return errs
}

func (c *Config) validateStorage(offline bool) []string {
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return []string{"storage.sqlite_path is required"}
	}
	if offline {
		return nil
	}
	if err := checkSQLitePathWritable(c.Storage.SQLitePath); err != nil {
		return []string{fmt.Sprintf("storage.sqlite_path: %v", err)}
	}
	return nil
}

func (c *Config) validateLLM() []string {
	var errs []string
	provider := strings.ToLower(c.LLM.Provider)
	switch provider {
	case "anthropic":
		if strings.TrimSpace(c.LLM.APIKeyEnv) == "" {
			errs = append(errs, "llm.api_key_env is required (env var name holding the LLM API key)")
		}
		if strings.TrimSpace(c.LLM.BaseURL) != "" {
			errs = append(errs, `llm.base_url is only valid for provider "openai-compatible"`)
		}
		if strings.TrimSpace(c.LLM.ResponseFormat) != "" {
			errs = append(errs, `llm.response_format is only valid for provider "openai-compatible"`)
		}
		if c.LLM.Thinking {
			errs = append(errs, `llm.thinking is only valid for provider "openai-compatible" (the anthropic client always disables thinking)`)
		}
	case "openai-compatible":
		errs = append(errs, c.validateLLMBaseURL()...)
		switch c.LLM.ResponseFormat {
		case "":
			c.LLM.ResponseFormat = "json_object" // resolve the default once, here
		case "json_object", "off":
			// ok
		default:
			errs = append(errs, fmt.Sprintf("llm.response_format %q invalid (use \"json_object\" or \"off\")", c.LLM.ResponseFormat))
		}
	case "":
		errs = append(errs, "llm.provider is required")
	default:
		errs = append(errs, fmt.Sprintf("llm.provider %q not supported (use \"anthropic\" or \"openai-compatible\")", c.LLM.Provider))
	}
	if strings.TrimSpace(c.LLM.Model) == "" {
		errs = append(errs, "llm.model is required")
	}
	if c.LLM.MaxTokens <= 0 {
		errs = append(errs, "llm.max_tokens must be > 0")
	}
	if c.LLM.TimeoutSeconds <= 0 {
		errs = append(errs, "llm.timeout_seconds must be > 0")
	}
	return errs
}

// validateLLMBaseURL checks and normalizes llm.base_url for the
// openai-compatible provider: must parse as an http(s) URL; one trailing /v1
// (and any trailing slash) is stripped so both spellings of the same endpoint
// work — the client appends /v1/chat/completions itself.
func (c *Config) validateLLMBaseURL() []string {
	raw := strings.TrimSpace(c.LLM.BaseURL)
	if raw == "" {
		return []string{`llm.base_url is required for provider "openai-compatible" (root URL of the endpoint, e.g. http://localhost:11434)`}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return []string{fmt.Sprintf("llm.base_url %q must be an http(s) URL", raw)}
	}
	if u.User != nil {
		return []string{`llm.base_url must not contain embedded credentials (use llm.api_key_env instead)`}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return []string{`llm.base_url must not contain a query string or fragment (root URL only, e.g. http://localhost:11434)`}
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1")
	u.Path = strings.TrimRight(u.Path, "/")
	c.LLM.BaseURL = u.String()
	return nil
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
		seen := make(map[string]int, len(c.Correlator.GroupLabels))
		for i, label := range c.Correlator.GroupLabels {
			switch {
			case strings.TrimSpace(label) == "":
				errs = append(errs, fmt.Sprintf("correlator.group_labels[%d] is empty", i))
			case label != strings.TrimSpace(label):
				// Padded keys silently never match any alert label.
				errs = append(errs, fmt.Sprintf("correlator.group_labels[%d] %q has surrounding whitespace", i, label))
			case strings.HasPrefix(strings.ToLower(label), "alertint_"):
				// The alertint_ label-key prefix is reserved as AlertINT-owned
				// (e.g. the alertint_drill drill marker) and never participates
				// in grouping.
				errs = append(errs, fmt.Sprintf("correlator.group_labels[%d] %q uses the reserved alertint_ label prefix; alertint_* labels never participate in grouping", i, label))
			default:
				if j, dup := seen[label]; dup {
					// A duplicated key doubles its part in the group key.
					errs = append(errs, fmt.Sprintf("correlator.group_labels[%d] %q duplicates entry %d", i, label, j))
				}
				seen[label] = i
			}
		}
	}
	return errs
}

// validateVerification checks the verification round config.
func (c *Config) validateVerification() []string {
	var errs []string
	if c.Triage.Verification.MaxRounds > 1 {
		errs = append(errs, "triage: verification: max_rounds: multi-round not yet supported")
	}
	if c.Triage.Verification.MaxRounds < 1 {
		errs = append(errs, "triage: verification: max_rounds: must be 1")
	}
	if c.Triage.Verification.MaxQueries < 0 {
		errs = append(errs, "triage: verification: max_queries: must be >= 0")
	}
	if c.Triage.Verification.QueryTimeoutSeconds <= 0 {
		errs = append(errs, "triage: verification: query_timeout_seconds: must be > 0")
	}
	return errs
}

// validateMemory checks the incident-memory horizon knobs. All are strictly
// positive: a zero/negative window, ceiling, cap, or lookback is a
// misconfiguration, not a disable switch (collapse and recall are always on).
func (c *Config) validateMemory() []string {
	var errs []string
	if c.Memory.AttachWindowMinutes <= 0 {
		errs = append(errs, "memory: attach_window_minutes: must be > 0")
	}
	if c.Memory.JudgmentCeilingHours <= 0 {
		errs = append(errs, "memory: judgment_ceiling_hours: must be > 0")
	}
	if c.Memory.OccurrenceCap <= 0 {
		errs = append(errs, "memory: occurrence_cap: must be > 0")
	}
	if c.Memory.LookbackDays <= 0 {
		errs = append(errs, "memory: lookback_days: must be > 0")
	}
	switch c.Memory.Classifier.Mode {
	case ClassifierModeOff, ClassifierModeShadow, ClassifierModeOn:
		// ok
	default:
		errs = append(errs, fmt.Sprintf("memory: classifier: mode %q must be one of off, shadow, on", c.Memory.Classifier.Mode))
	}
	// The timeout only bounds a call that actually runs, so it is required
	// positive only when the classifier is enabled (shadow or on).
	if c.Memory.Classifier.Enabled() && c.Memory.Classifier.TimeoutSeconds <= 0 {
		errs = append(errs, "memory: classifier: timeout_seconds: must be > 0 when mode is shadow or on")
	}
	return errs
}

// volatileGroupLabels are per-instance identity labels that churn on every pod
// restart or job run, so a verbatim group_key rarely repeats. Grouping on one
// means recurrence collapse and recall (which key off group_key) seldom match.
var volatileGroupLabels = map[string]bool{
	"pod": true, "pod_name": true, "pod_ip": true, "instance": true,
	"job_name": true, "container": true, "container_id": true, "uid": true,
}

// Warnings returns non-fatal configuration advisories, surfaced at serve startup
// and by `alertint validate`. Unlike validate(), a warning never blocks startup.
// Today it lints group_labels for volatile per-instance identity (R11): the
// recurrence key is the verbatim group_key with no normalizer, so a volatile
// label quietly defeats collapse and recall rather than being rejected.
func (c *Config) Warnings() []string {
	var warns []string
	for _, label := range c.Correlator.GroupLabels {
		if volatileGroupLabels[strings.ToLower(strings.TrimSpace(label))] {
			warns = append(warns, fmt.Sprintf(
				"correlator.group_labels: %q looks volatile (per-instance identity); recurrence collapse and recall will rarely match for these groups",
				label))
		}
	}
	return warns
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
		if !validSeverity(c.Notify.Slack.MinSeverity) {
			errs = append(errs, fmt.Sprintf("notify.slack.min_severity %q must be one of low, medium, high", c.Notify.Slack.MinSeverity))
		}
		if !validRecurrenceMode(c.Notify.Slack.RecurrenceMode) {
			errs = append(errs, fmt.Sprintf("notify.slack.recurrence_mode %q must be one of change-gated, off", c.Notify.Slack.RecurrenceMode))
		}
	}
	if !c.Notify.Stdout && !c.Notify.Slack.Enabled {
		errs = append(errs, "at least one notifier must be enabled (notify.stdout or notify.slack.enabled)")
	}
	return errs
}

func (c *Config) validatePrometheus() []string {
	var errs []string
	if !c.PrometheusEnabled() {
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
	if c.Prometheus.MaxSeries <= 0 {
		errs = append(errs, "prometheus.max_series must be > 0")
	}
	return errs
}

func (c *Config) validateLogs() []string {
	if !c.LogsEnabled() {
		return nil
	}
	var errs []string
	switch c.Logs.Provider {
	case "loki":
		// ok
	case "":
		errs = append(errs, "logs.provider is required when logs is enabled")
	default:
		errs = append(errs, fmt.Sprintf("logs.provider: unknown provider %q (only \"loki\" in v1)", c.Logs.Provider))
	}
	if c.Logs.TimeoutSeconds <= 0 {
		errs = append(errs, "logs.timeout_seconds must be > 0")
	}
	if c.Logs.DefaultRangeMinutes <= 0 {
		errs = append(errs, "logs.default_range_minutes must be > 0")
	}
	if c.Logs.MaxLines <= 0 {
		errs = append(errs, "logs.max_lines must be > 0")
	}
	if c.Logs.Provider == "loki" {
		errs = append(errs, c.validateLoki()...)
	}
	return errs
}

func (c *Config) validateLoki() []string {
	var errs []string
	if strings.TrimSpace(c.Logs.Loki.BaseURL) == "" {
		errs = append(errs, "logs.loki.base_url is required when logs provider is loki")
	}
	mode := c.Logs.Loki.Auth.Mode
	if mode == "" {
		mode = "none"
	}
	switch mode {
	case "none":
		// no secret fields required
	case "bearer":
		if strings.TrimSpace(c.Logs.Loki.Auth.TokenEnv) == "" {
			errs = append(errs, "logs.loki.auth.token_env is required when auth mode is bearer")
		}
	case "basic":
		if strings.TrimSpace(c.Logs.Loki.Auth.Username) == "" {
			errs = append(errs, "logs.loki.auth.username is required when auth mode is basic")
		}
		if strings.TrimSpace(c.Logs.Loki.Auth.PasswordEnv) == "" {
			errs = append(errs, "logs.loki.auth.password_env is required when auth mode is basic")
		}
	default:
		errs = append(errs, fmt.Sprintf("logs.loki.auth.mode %q must be one of none, bearer, basic", mode))
	}
	return errs
}

// PrometheusEnabled resolves the effective Prometheus on/off state:
// an explicit enabled value wins; when the key is omitted, a configured
// base_url turns the read-only connector on (presence-based enablement).
func (c *Config) PrometheusEnabled() bool {
	if c.Prometheus.Enabled != nil {
		return *c.Prometheus.Enabled
	}
	return strings.TrimSpace(c.Prometheus.BaseURL) != ""
}

// LogsEnabled resolves the effective log-enrichment on/off state:
// an explicit enabled value wins; when the key is omitted, a configured
// loki.base_url turns the read-only connector on (presence-based enablement).
func (c *Config) LogsEnabled() bool {
	if c.Logs.Enabled != nil {
		return *c.Logs.Enabled
	}
	return strings.TrimSpace(c.Logs.Loki.BaseURL) != ""
}

// ChangesEnrichmentEnabled resolves the effective change-enrichment on/off
// state: an explicit enabled value wins; when the key is omitted, enrichment
// turns on as soon as anything can produce change events — the change webhook
// receiver or the Sentry releases poller. Changes has no base_url of its own,
// so "a source is present" is its presence signal.
func (c *Config) ChangesEnrichmentEnabled() bool {
	if c.Changes.Enrichment.Enabled != nil {
		return *c.Changes.Enrichment.Enabled
	}
	return c.Changes.Ingress.Enabled || c.Sentry.Releases.Enabled
}

// MCPEnabled resolves the effective MCP-server on/off state: an explicit
// enabled value wins; when the key is omitted, a token in the env var named
// by token_env turns the server on (presence-based enablement). MCP's only
// prerequisite is its bearer token and secrets live in env, so "the secret
// exists" is its presence signal — the env-var counterpart of the base_url
// probes in PrometheusEnabled/LogsEnabled. Like all secret resolution, the
// result reflects the environment of the process asking.
func (c *Config) MCPEnabled() bool {
	if c.MCP.Enabled != nil {
		return *c.MCP.Enabled
	}
	if name := strings.TrimSpace(c.MCP.TokenEnv); name != "" {
		return strings.TrimSpace(os.Getenv(name)) != ""
	}
	return false
}

// VerificationEnabled resolves the tri-state enabled flag: nil = on.
func (c *Config) VerificationEnabled() bool {
	return c.Triage.Verification.Enabled == nil || *c.Triage.Verification.Enabled
}

// AnySentryEnabled reports whether any Sentry feature is on (the release/deploy
// Change source OR the issue-enrichment Error source). It gates the shared
// connection: the client, token resolution, shared-connection validation, and
// the health check all key off this, while each feature's own work (the poller,
// the triage query) stays gated on its own enabled flag (KTD7).
func (c *Config) AnySentryEnabled() bool {
	return c.Sentry.Releases.Enabled || c.Sentry.Issues.Enabled
}

// validateSentry checks the Sentry connector config. Like validatePrometheus it
// gates on the feature flags: a fully-disabled block validates clean even with
// an empty connection, so zero-config triage is unaffected. The SHARED
// connection (base_url, org, token_env, timeout) is required when EITHER feature
// is enabled (KTD7); the releases- and issues-specific tunables are each gated
// on their own flag.
func (c *Config) validateSentry() []string {
	if !c.AnySentryEnabled() {
		return nil
	}
	var errs []string
	if strings.TrimSpace(c.Sentry.BaseURL) == "" {
		errs = append(errs, "sentry: base_url is required when sentry is enabled")
	}
	if strings.TrimSpace(c.Sentry.Org) == "" {
		errs = append(errs, "sentry: org is required when sentry is enabled")
	}
	if strings.TrimSpace(c.Sentry.TokenEnv) == "" {
		errs = append(errs, "sentry: token_env is required when sentry is enabled (env var name holding the token)")
	}
	if c.Sentry.TimeoutSeconds <= 0 {
		errs = append(errs, "sentry: timeout_seconds must be > 0")
	}
	if c.Sentry.Releases.Enabled {
		if c.Sentry.Releases.PollIntervalSeconds <= 0 {
			errs = append(errs, "sentry: releases: poll_interval_seconds must be > 0")
		}
		if c.Sentry.Releases.InitialLookbackMinutes <= 0 {
			errs = append(errs, "sentry: releases: initial_lookback_minutes must be > 0")
		}
		if c.Sentry.Releases.ReleaseScanHorizonDays <= 0 {
			errs = append(errs, "sentry: releases: release_scan_horizon_days must be > 0")
		}
	}
	if c.Sentry.Issues.Enabled {
		if c.Sentry.Issues.LookbackMinutes <= 0 {
			errs = append(errs, "sentry: issues: lookback_minutes must be > 0")
		}
		if c.Sentry.Issues.MaxIssues <= 0 {
			errs = append(errs, "sentry: issues: max_issues must be > 0")
		}
		if c.Sentry.Issues.FetchTimeoutSeconds <= 0 {
			errs = append(errs, "sentry: issues: fetch_timeout_seconds must be > 0")
		}
		if c.Sentry.Issues.LiveWindowMinutes <= 0 {
			errs = append(errs, "sentry: issues: live_window_minutes must be > 0")
		}
	}
	return errs
}

func (c *Config) validateRules() []string {
	dir := strings.TrimSpace(c.Rules.LocalPackDir)
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return []string{fmt.Sprintf("rules.local_pack_dir: %v", err)}
	}
	if !info.IsDir() {
		return []string{fmt.Sprintf("rules.local_pack_dir %s is not a directory", dir)}
	}
	if _, err := os.Stat(filepath.Join(dir, "pack.yaml")); err != nil {
		return []string{fmt.Sprintf("rules.local_pack_dir %s does not contain pack.yaml: %v", dir, err)}
	}
	return nil
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

// ChangesWebhookToken returns the bearer token for the change webhook receiver,
// resolved from the env var named by Changes.Ingress.WebhookTokenEnv. Returns
// an empty string and nil error when change ingestion is disabled.
func (c *Config) ChangesWebhookToken() (string, error) {
	if !c.Changes.Ingress.Enabled {
		return "", nil
	}
	return requireEnv(c.Changes.Ingress.WebhookTokenEnv, "changes.ingress.webhook_token_env")
}

// LLMAPIKey returns the LLM API key, resolved from the env var named by
// LLM.APIKeyEnv. For provider "openai-compatible" the key is optional: an
// unset api_key_env means an unauthenticated local endpoint and returns "".
func (c *Config) LLMAPIKey() (string, error) {
	if strings.EqualFold(c.LLM.Provider, "openai-compatible") && strings.TrimSpace(c.LLM.APIKeyEnv) == "" {
		return "", nil
	}
	return requireEnv(c.LLM.APIKeyEnv, "llm.api_key_env")
}

// MCPToken returns the bearer token for the MCP HTTP server, resolved from
// the env var named by MCP.TokenEnv. Returns empty string when MCP is disabled.
func (c *Config) MCPToken() (string, error) {
	if !c.MCPEnabled() {
		return "", nil
	}
	return requireEnv(c.MCP.TokenEnv, "mcp.token_env")
}

// PrometheusToken returns the bearer token for Prometheus when configured,
// resolved from the env var named by Prometheus.BearerTokenEnv.
// Returns empty string and nil error when bearer_token_env is unset or prometheus is disabled.
func (c *Config) PrometheusToken() (string, error) {
	if !c.PrometheusEnabled() || strings.TrimSpace(c.Prometheus.BearerTokenEnv) == "" {
		return "", nil
	}
	return requireEnv(c.Prometheus.BearerTokenEnv, "prometheus.bearer_token_env")
}

// SentryToken returns the Internal-Integration token for the Sentry connector,
// resolved from the env var named by Sentry.TokenEnv. Returns an empty string
// and nil error when NO Sentry feature is enabled (mirrors PrometheusToken /
// WebhookToken: the agent never holds a secret it isn't using). It resolves for
// an issues-only deployment too, since the Error source shares this token (KTD7).
func (c *Config) SentryToken() (string, error) {
	if !c.AnySentryEnabled() {
		return "", nil
	}
	return requireEnv(c.Sentry.TokenEnv, "sentry.token_env")
}

// LokiAuthSecret resolves the secret needed for the configured Loki auth mode,
// mirroring PrometheusToken. It reads no secret for none mode, the bearer token
// for bearer mode, and the password for basic mode — each loud if the named env
// var is unset. The basic-mode username is an account identifier, not a secret,
// and is read inline from config (not here).
//
//	none   → ("", nil)
//	bearer → resolve token_env
//	basic  → resolve password_env
func (c *Config) LokiAuthSecret() (string, error) {
	if !c.LogsEnabled() {
		return "", nil
	}
	switch c.Logs.Loki.Auth.Mode {
	case "", "none":
		return "", nil
	case "bearer":
		return requireEnv(c.Logs.Loki.Auth.TokenEnv, "logs.loki.auth.token_env")
	case "basic":
		return requireEnv(c.Logs.Loki.Auth.PasswordEnv, "logs.loki.auth.password_env")
	default:
		return "", fmt.Errorf("logs.loki.auth.mode %q is not supported", c.Logs.Loki.Auth.Mode)
	}
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

// validSeverity accepts the finding-severity ladder used by
// notify.slack.min_severity. An empty value is valid (treated as "low").
func validSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "low", "medium", "high":
		return true
	}
	return false
}

// validRecurrenceMode accepts the two v1 recurrence modes plus empty (which the
// notifier normalizes to change-gated).
func validRecurrenceMode(s string) bool {
	switch s {
	case "", "change-gated", "off":
		return true
	}
	return false
}

func validLogLevel(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "info", "warn", "warning", "error":
		return true
	}
	return false
}

// validLogFormat accepts the format selector set. "text" was removed (it was
// slog's raw key=value renderer); an unknown value — including "text" — fails
// loud at startup rather than silently re-rendering, which would break a
// key=value parser. Resolution of "auto" to a concrete handler happens in
// package logging, off the log writer's TTY-ness.
func validLogFormat(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "console", "json":
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
