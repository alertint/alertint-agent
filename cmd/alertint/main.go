// SPDX-License-Identifier: FSL-1.1-ALv2

// Command alertint is the AlertINT agent binary.
//
// Subcommands:
//
//	alertint serve         (default) run the agent.
//	alertint health        probe GET /health and exit 0 (ok) or 1 (degraded).
//	alertint verify-audit  recompute the audit log hash chain and report
//	                       any tampering. Requires --config.
//	alertint version       print the version. Equivalent to --version.
//
// All subcommands accept --log-level and --log-format. The top-level
// --version flag short-circuits before subcommand dispatch.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/ingress"
	llmanthropic "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/logging"
	internalmcp "github.com/alertint/alertint-agent/internal/mcp"
	"github.com/alertint/alertint-agent/internal/notify"
	notifyconsole "github.com/alertint/alertint-agent/internal/notify/console"
	notifyresolution "github.com/alertint/alertint-agent/internal/notify/resolution"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	notifystdout "github.com/alertint/alertint-agent/internal/notify/stdout"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/packs"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// Empty value means "fall back to debug.ReadBuildInfo()".
var version = ""

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "alertint:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	// Top-level fast paths that don't go through subcommand dispatch.
	if len(args) > 0 {
		switch args[0] {
		case "--version", "-version":
			_, _ = fmt.Fprintln(stdout, resolveVersion())
			return nil
		case "version":
			_, _ = fmt.Fprintln(stdout, resolveVersion())
			return nil
		case "health":
			return runHealth(args[1:], stdout, stderr)
		case "verify-audit":
			return runVerifyAudit(args[1:], stdout, stderr)
		case "serve":
			return runServe(args[1:], stdout, stderr)
		}
	}
	return runServe(args, stdout, stderr)
}

func runServe(args []string, _ io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	webhookAddr := fs.String("webhook-addr", "", "override alertmanager.webhook_addr from config (e.g. 0.0.0.0:9911)")
	mcpAddr := fs.String("mcp-addr", "", "override mcp.addr from config (e.g. 0.0.0.0:9912)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:  *logLevel,
		Format: logging.Format(*logFormat),
		Writer: stderr,
	})
	if err != nil {
		return err
	}
	logging.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("alertint starting",
		slog.String("version", resolveVersion()),
		slog.String("log_level", *logLevel),
		slog.String("log_format", *logFormat),
	)

	if *cfgPath == "" {
		// Without config we can't open the store or know the listen
		// address. v1 keeps the placeholder behavior so existing tests
		// (no flags) still exercise signal handling.
		logger.Warn("--config not provided; running idle until signaled (no webhook)")
		<-ctx.Done()
		logger.Info("alertint stopped", slog.String("reason", ctx.Err().Error()))
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	if *webhookAddr != "" {
		cfg.Alertmanager.WebhookAddr = *webhookAddr
	}
	if *mcpAddr != "" {
		cfg.MCP.Addr = *mcpAddr
	}

	st, err := store.Open(ctx, cfg.Storage.SQLitePath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	auditor := audit.New(st.DB())

	// Load the rule engine. The embedded baseline pack needs zero
	// configuration; future sources (signed feed packs) plug in here.
	ruleEngine, err := rules.NewEngine(ctx, logger, rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0))
	if err != nil {
		return err
	}

	apiKey, err := cfg.LLMAPIKey()
	if err != nil {
		return err
	}
	llmClient := llmanthropic.New(llmanthropicCfg(cfg), auditor, logger)

	notifier := buildNotifier(cfg, st, auditor)

	// Build Prometheus client when enabled. Passed into both the triage skill
	// (metric enrichment for the LLM prompt) and the MCP server (PromQL tools).
	var prom *promclient.Client
	if cfg.Prometheus.Enabled {
		promToken, err := cfg.PrometheusToken()
		if err != nil {
			return err
		}
		prom = promclient.NewClient(promclient.Config{
			BaseURL:             cfg.Prometheus.BaseURL,
			BearerToken:         promToken,
			TimeoutSeconds:      cfg.Prometheus.TimeoutSeconds,
			DefaultRangeMinutes: cfg.Prometheus.DefaultRangeMinutes,
		})
		logger.Info("prometheus connector enabled", slog.String("base_url", cfg.Prometheus.BaseURL))
	}

	skill := acutetriage.New(
		acutetriage.Config{
			WindowSeconds: cfg.Correlator.WindowSeconds,
			MinAlerts:     cfg.Correlator.MinAlerts,
			Prometheus:    prom,
			Rules:         ruleEngine,
		},
		st, llmClient, auditor, notifier, logger,
	)
	_ = apiKey // key is embedded in llmClient via Config.APIKey

	corCfg := correlator.Config{
		WindowSeconds: cfg.Correlator.WindowSeconds,
		GroupLabels:   cfg.Correlator.GroupLabels,
	}
	cor := correlator.New(corCfg, st, incidentSink{skill: skill}, logger)

	cor.SetResolutionNotifier(notifyresolution.New(notifier))

	if err := cor.Start(ctx); err != nil {
		return fmt.Errorf("correlator start: %w", err)
	}
	defer cor.Stop()

	// Probe enabled integrations in the background: quickly (with backoff)
	// while one is failing — at startup a co-deployed dependency may still
	// be booting — then at a steady pace, logging losses and recoveries.
	// Results are cached for GET /health.
	healthReg := buildHealthChecks(cfg, prom)
	go healthReg.Watch(ctx, logger)

	webhookSrv, webhookErrCh, err := startWebhook(cfg, st, auditor, cor, healthReg, logger)
	if err != nil {
		return err
	}

	mcpHTTPSrv, mcpErrCh, err := startMCP(cfg, st, auditor, prom, logger)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining in-flight requests")
	case err := <-webhookErrCh: // nil channel never fires when alertmanager is disabled
		if err != nil {
			return err
		}
		return nil
	case err := <-mcpErrCh: // nil channel never fires when MCP is disabled
		if err != nil {
			return err
		}
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), ingress.DefaultShutdownTimeout)
	defer cancel()
	if webhookSrv != nil {
		if err := webhookSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("webhook graceful shutdown failed", slog.String("err", err.Error()))
		}
	}
	if mcpHTTPSrv != nil {
		if err := mcpHTTPSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("MCP graceful shutdown failed", slog.String("err", err.Error()))
		}
	}
	logger.Info("alertint stopped", slog.String("reason", "signal"))
	return nil
}

// startWebhook starts the Alertmanager webhook receiver when enabled. It
// also serves GET /health, so a deployment with alertmanager disabled has
// no health endpoint. Returns (nil, nil, nil) when disabled — the nil
// error channel never fires in runServe's select.
func startWebhook(cfg *config.Config, st *store.Store, auditor *audit.Auditor, cor *correlator.Correlator, healthReg *health.Registry, logger *slog.Logger) (*http.Server, <-chan error, error) {
	if !cfg.Alertmanager.Enabled {
		logger.Info("alertmanager webhook receiver disabled; /health endpoint not served")
		return nil, nil, nil
	}
	token, err := cfg.WebhookToken()
	if err != nil {
		return nil, nil, err
	}
	hook, err := ingress.New(ingress.Options{
		Store:   st,
		Auditor: auditor,
		Token:   token,
		Logger:  logger,
		Sink:    cor.Accept,
		Health:  healthReg,
	})
	if err != nil {
		return nil, nil, err
	}

	srv := &http.Server{
		Addr:              cfg.Alertmanager.WebhookAddr,
		Handler:           hook.Handler(),
		ReadTimeout:       ingress.DefaultReadTimeout,
		ReadHeaderTimeout: ingress.DefaultReadTimeout,
		WriteTimeout:      ingress.DefaultWriteTimeout,
		IdleTimeout:       ingress.DefaultIdleTimeout,
	}

	ch := make(chan error, 1)
	go func() {
		logger.Info("webhook listening",
			slog.String("addr", cfg.Alertmanager.WebhookAddr),
			slog.String("path", "/webhook/alertmanager"),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ch <- err
		}
		close(ch)
	}()
	return srv, ch, nil
}

// startMCP starts the MCP HTTP server when enabled. MCP clients connect by
// URL (e.g. http://host:9912/mcp) — no subprocess or shared file needed.
// Returns (nil, nil, nil) when disabled.
func startMCP(cfg *config.Config, st *store.Store, auditor *audit.Auditor, prom *promclient.Client, logger *slog.Logger) (*http.Server, <-chan error, error) {
	if !cfg.MCP.Enabled {
		return nil, nil, nil
	}
	mcpToken, err := cfg.MCPToken()
	if err != nil {
		return nil, nil, err
	}
	mcpSrv := internalmcp.NewServer(internalmcp.Config{
		Token:         mcpToken,
		WindowSeconds: cfg.Correlator.WindowSeconds,
		Prometheus:    prom,
	}, st, auditor)
	srv := &http.Server{
		Addr:    cfg.MCP.Addr,
		Handler: mcpSrv.Handler(),
		// WriteTimeout 0: MCP uses long-lived SSE streams for streaming responses.
		ReadTimeout: ingress.DefaultReadTimeout,
		IdleTimeout: ingress.DefaultIdleTimeout,
	}
	ch := make(chan error, 1)
	go func() {
		logger.Info("MCP HTTP listening",
			slog.String("addr", cfg.MCP.Addr),
			slog.String("endpoint", cfg.MCP.Addr+"/mcp"),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ch <- err
		}
		close(ch)
	}()
	return srv, ch, nil
}

func runVerifyAudit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	dbPathFlag := fs.String("db", "", "path to SQLite database (overrides config.storage.sqlite_path)")
	logLevel := fs.String("log-level", "warn", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "text", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:  *logLevel,
		Format: logging.Format(*logFormat),
		Writer: stderr,
	})
	if err != nil {
		return err
	}
	logging.SetDefault(logger)

	dbPath, err := resolveDBPath(*cfgPath, *dbPathFlag)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	auditor := audit.New(s.DB())
	report, verr := auditor.Verify(ctx)
	if verr != nil {
		if report != nil {
			_, _ = fmt.Fprintf(stdout, "audit verification FAILED at seq %d: %s\n", report.FailedSeq, report.Reason)
			_, _ = fmt.Fprintf(stdout, "rows checked before failure: %d\n", report.RowsChecked)
		}
		return verr
	}
	_, _ = fmt.Fprintf(stdout, "audit verification OK: %d row(s) checked\n", report.RowsChecked)
	return nil
}

// runHealth probes GET /health and exits 0 (ok) or 1 (degraded / unreachable).
// Intended for use as a Docker HEALTHCHECK CMD on scratch images that have no
// curl or wget.
func runHealth(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "http://localhost:9911/health", "health endpoint URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(*addr) //nolint:noctx // health probe; no caller context to inherit
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alertint health: %v\n", err)
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		_, _ = fmt.Fprintln(stdout, "ok")
		return nil
	}
	return fmt.Errorf("health probe returned status %d", resp.StatusCode)
}

func resolveDBPath(cfgPath, dbPathFlag string) (string, error) {
	if dbPathFlag != "" {
		return dbPathFlag, nil
	}
	if cfgPath == "" {
		return "", errors.New("verify-audit: either --config or --db is required")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return "", err
	}
	return cfg.Storage.SQLitePath, nil
}

// buildHealthChecks assembles connectivity probes for every enabled
// integration. Returns nil (a no-op registry) when nothing is enabled.
func buildHealthChecks(cfg *config.Config, prom *promclient.Client) *health.Registry {
	var checks []health.Check
	if cfg.Prometheus.Enabled && prom != nil {
		checks = append(checks, health.Check{
			Name:   "prometheus",
			Detail: cfg.Prometheus.BaseURL,
			Probe: func(ctx context.Context) error {
				// A trivial instant query proves the API is reachable,
				// authorized, and serving query results.
				_, err := prom.QueryInstant(ctx, "vector(1)", time.Now())
				return err
			},
		})
	}
	if cfg.Notify.Slack.Enabled {
		checks = append(checks, health.Check{
			Name:   "slack",
			Detail: cfg.Notify.Slack.Channel,
			Probe: func(ctx context.Context) error {
				token, err := cfg.SlackBotToken()
				if err != nil {
					return err
				}
				return notifyslack.Probe(ctx, token)
			},
		})
	}
	if len(checks) == 0 {
		return nil
	}
	return health.NewRegistry(health.DefaultTTL, checks...)
}

// buildNotifier constructs the notify.Multi from the loaded config.
// stdout (JSON) and console (human-readable) are always included; Slack is added when enabled.
func buildNotifier(cfg *config.Config, st *store.Store, auditor *audit.Auditor) notify.Notifier {
	nn := []notify.Notifier{
		notifystdout.New(os.Stdout, auditor),  // JSON output for parsing
		notifyconsole.New(os.Stderr, auditor), // Human-readable output
	}
	if cfg.Notify.Slack.Enabled {
		if token, err := cfg.SlackBotToken(); err == nil && token != "" {
			nn = append(nn, notifyslack.New(token, cfg.Notify.Slack.Channel, st, auditor))
		}
	}
	return notify.NewMulti(nn...)
}

// llmanthropicCfg builds an llm/anthropic.Config from the loaded config.
func llmanthropicCfg(cfg *config.Config) llmanthropic.Config {
	key, _ := cfg.LLMAPIKey()
	return llmanthropic.Config{
		APIKey: key,
		Model:  cfg.LLM.Model,
	}
}

// incidentSink wraps an acutetriage.Skill as a correlator.IncidentSink.
type incidentSink struct {
	skill *acutetriage.Skill
}

func (s incidentSink) OnIncidentReady(ctx context.Context, inc store.Incident) error {
	return s.skill.Run(ctx, inc)
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
