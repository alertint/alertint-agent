// SPDX-License-Identifier: FSL-1.1-ALv2

// Command alertint is the AlertINT agent binary.
//
// Subcommands:
//
//	alertint serve         (default) run the agent.
//	alertint health        probe GET /health and exit 0 (ok) or 1 (degraded).
//	alertint verify-audit  recompute the audit log hash chain and report
//	                       any tampering. Requires --config.
//	alertint validate      dry-run a config file (parse + validate, skipping
//	                       machine-coupled filesystem checks); exit 0/1.
//	alertint drill         fire a built-in Drill scenario at a running
//	                       instance and print the resulting finding.
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/backup"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/llm"
	llmanthropic "github.com/alertint/alertint-agent/internal/llm/anthropic"
	llmopenai "github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/logging"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/logs/loki"
	internalmcp "github.com/alertint/alertint-agent/internal/mcp"
	"github.com/alertint/alertint-agent/internal/notify"
	notifyresolution "github.com/alertint/alertint-agent/internal/notify/resolution"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	notifystdout "github.com/alertint/alertint-agent/internal/notify/stdout"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
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
		case "validate":
			return runValidate(args[1:], stdout, stderr)
		case "drill":
			return runDrill(args[1:], stdout, stderr)
		case "backup":
			return runBackup(args[1:], stdout, stderr)
		case "restore":
			return runRestore(args[1:], stdout, stderr)
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
	receiversAddr := fs.String("receivers-addr", "", "override receivers.address from config (e.g. 0.0.0.0:9911)")
	mcpAddr := fs.String("mcp-addr", "", "override mcp.addr from config (e.g. 0.0.0.0:9912)")
	// Empty sentinel defaults: an unset flag falls through to config, so
	// precedence is CLI flag > config > built-in default (info / auto).
	logLevel := fs.String("log-level", "", "log level: debug, info, warn, error (overrides config log_level)")
	logFormat := fs.String("log-format", "", "log format: auto, console, json (overrides config log_format)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Bootstrap logger from flags/built-in defaults. It covers errors that
	// occur before config is available and the no-config idle path; the real
	// logger is rebuilt once config is loaded so config-driven level/format
	// reach the very first "alertint starting" line.
	bootstrap, level, format, err := buildLogger(*logLevel, *logFormat, "", "", stderr)
	if err != nil {
		return err
	}
	logging.SetDefault(bootstrap)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *cfgPath == "" {
		// Without config we can't open the store or know the listen address.
		// v1 keeps the placeholder behavior so existing tests (no flags) still
		// exercise signal handling; the bootstrap logger renders the startup
		// line for parity with the configured path.
		bootstrap.Info("alertint starting",
			slog.String("version", resolveVersion()),
			slog.String("log_level", level),
			slog.String("log_format", format),
		)
		bootstrap.Warn("--config not provided; running idle until signaled (no webhook)")
		<-ctx.Done()
		bootstrap.Info("alertint stopped", slog.String("reason", ctx.Err().Error()))
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	// Rebuild the logger now that config is known, applying precedence
	// CLI flag > config > default and resolving auto off stderr's TTY-ness.
	logger, level, format, err := buildLogger(*logLevel, *logFormat, cfg.LogLevel, cfg.LogFormat, stderr)
	if err != nil {
		return err
	}
	logging.SetDefault(logger)

	logger.Info("alertint starting",
		slog.String("version", resolveVersion()),
		slog.String("log_level", level),
		slog.String("log_format", format),
	)

	logConfigWarnings(logger, cfg)

	applyServeOverrides(cfg, *receiversAddr, *mcpAddr)

	st, stagedInfo, err := openStoreWithStagedRestore(ctx, cfg.Storage.SQLitePath, logger)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	finalizeStagedRestoreIfApplied(ctx, st, stagedInfo, logger)

	pruneChangesAtStartup(ctx, cfg, st, logger)

	auditor := audit.New(st.DB())

	// Load the rule engine. The embedded baseline pack needs zero
	// configuration; an optional local pack dir overrides it, and future
	// sources (signed feed packs) plug in the same way.
	ruleSources := []rules.RuleSource{rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0)}
	if dir := cfg.Rules.LocalPackDir; dir != "" {
		ruleSources = append(ruleSources, rules.NewLocalDirSource(dir, 100))
	}
	ruleEngine, err := rules.NewEngine(ctx, logger, ruleSources...)
	if err != nil {
		return err
	}

	apiKey, err := cfg.LLMAPIKey()
	if err != nil {
		return err
	}
	llmClient := buildLLMClient(cfg, apiKey, auditor, logger)

	classifierClient := buildClassifierClient(cfg, apiKey, auditor, logger)

	notifier, llmSystemPublisher := buildNotifier(cfg, st, auditor, logger, strings.EqualFold(level, "debug"))

	llmHealth, err := llmhealth.New(ctx, st, llmhealth.Options{
		Logger:         logger,
		Auditor:        auditor,
		BroadcastAfter: time.Duration(cfg.Health.BroadcastAfterSeconds) * time.Second,
		IdleProbeAfter: time.Duration(cfg.Health.LLMIdleProbeAfterSeconds) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("llm health: %w", err)
	}
	llmProber := buildLLMProber(cfg, llmClient, logger)
	logger.Info("llm health: observing",
		slog.Duration("idle_probe_after", time.Duration(cfg.Health.LLMIdleProbeAfterSeconds)*time.Second),
		slog.Duration("broadcast_after", time.Duration(cfg.Health.BroadcastAfterSeconds)*time.Second),
		slog.Bool("probe", llmProber != nil),
		slog.Bool("slack", llmSystemPublisher != nil),
	)

	// LLM health lifecycle. Capability observations come from two producers:
	// correlator triage (synchronous inside the correlator loop, joined by
	// cor.Stop) and Captured-verdict grading (MCP request goroutines, joined
	// by captureEngine.Close). The runner starts here, before both, so the
	// LIFO defers stop them first and the runner's final delivery pass then
	// acknowledges a state nothing can move any more: cor.Stop →
	// captureEngine.Close → runner Stop+join → store close. The runner runs
	// on a never-canceled ctx on purpose: the signal ctx must not abort it
	// before the producers are joined, and a canceled runner never delivers
	// — only Stop does the final pass.
	llmRunner := llmhealth.NewRunner(llmHealth, llmProber, llmSystemPublisher, logger)
	llmRunDone := llmRunner.Start(context.Background())
	defer stopLLMHealthRunner(llmRunner, llmRunDone, logger)

	// Build Prometheus client when enabled. Passed into both the triage skill
	// (metric enrichment for the LLM prompt) and the MCP server (PromQL tools).
	var prom *promclient.Client
	if cfg.PrometheusEnabled() {
		promToken, err := cfg.PrometheusToken()
		if err != nil {
			return err
		}
		prom = promclient.NewClient(promclient.Config{
			BaseURL:             cfg.Prometheus.BaseURL,
			BearerToken:         promToken,
			OrgID:               cfg.Prometheus.OrgID,
			TimeoutSeconds:      cfg.Prometheus.TimeoutSeconds,
			DefaultRangeMinutes: cfg.Prometheus.DefaultRangeMinutes,
		})
		logger.Info("prometheus connected", slog.String("base_url", cfg.Prometheus.BaseURL))
	}

	// Build the log source when enabled. The provider switch lives here in
	// package main (not internal/logs) to avoid an internal/logs ↔
	// internal/logs/loki import cycle. Passed into both the triage skill (prompt
	// enrichment) and the MCP server (native-query passthrough). Unknown
	// provider fails loud at startup.
	var logSrc logs.Source
	if cfg.LogsEnabled() {
		lokiSecret, err := cfg.LokiAuthSecret()
		if err != nil {
			return err
		}
		switch cfg.Logs.Provider {
		case "loki":
			logSrc = loki.NewClient(loki.Config{
				BaseURL:        cfg.Logs.Loki.BaseURL,
				AuthMode:       cfg.Logs.Loki.Auth.Mode,
				Username:       cfg.Logs.Loki.Auth.Username,
				Secret:         lokiSecret,
				OrgID:          cfg.Logs.Loki.OrgID,
				LineFilter:     cfg.Logs.Loki.LineFilter,
				LabelMap:       cfg.Logs.Loki.LabelMap,
				TimeoutSeconds: cfg.Logs.TimeoutSeconds,
			})
		default:
			return fmt.Errorf("logs: unknown provider %q", cfg.Logs.Provider)
		}
		logger.Info("logs connected",
			slog.String("provider", cfg.Logs.Provider),
			slog.String("base_url", cfg.Logs.Loki.BaseURL),
		)
	}

	// Build the Sentry change source when enabled. The client is the shared
	// egress path (also probed by the health check); the poller turns new
	// deploys/releases into change rows in the background. Disabled → nothing
	// constructed, no Sentry calls (zero-config triage unaffected).
	sentryClient, stopSentry, err := startSentryPoller(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	defer stopSentry()

	// Inject the Sentry Error source (true nil interface unless issues is on with
	// a live client — KTD7).
	sentryReader, sentryParams := sentryErrorSource(cfg, sentryClient)

	// Build the Zabbix pull Source when enabled. Read-only: the client issues
	// only *.get methods (ADR-0032). Disabled → nothing constructed, no Zabbix
	// API calls (zero-config triage unaffected).
	zbxClient, err := newZabbixClient(cfg, logger)
	if err != nil {
		return err
	}
	// TRUE nil ZabbixReader interface unless the source is enabled (typed-nil
	// trap: assign only when non-nil, mirrors sentryErrorSource).
	zbxReader, zbxParams := zabbixContextSource(cfg, zbxClient)

	skill := acutetriage.New(
		acutetriage.Config{
			WindowSeconds: cfg.Correlator.WindowSeconds,
			MinAlerts:     cfg.Correlator.MinAlerts,
			Prometheus:    prom,
			MetricParams: acutetriage.MetricParams{
				TimeoutSeconds:      cfg.Prometheus.TimeoutSeconds,
				MaxSeries:           cfg.Prometheus.MaxSeries,
				ExtraSelectorLabels: cfg.Triage.ExtraSelectorLabels,
			},
			Rules:     ruleEngine,
			LogSource: logSrc,
			LogParams: acutetriage.LogParams{
				DefaultRangeMinutes: cfg.Logs.DefaultRangeMinutes,
				MaxWindowMinutes:    cfg.Logs.MaxWindowMinutes,
				TimeoutSeconds:      cfg.Logs.TimeoutSeconds,
				MaxLines:            cfg.Logs.MaxLines,
				ExtraSelectorLabels: cfg.Triage.ExtraSelectorLabels,
			},
			ChangeParams: acutetriage.ChangeParams{
				Enabled:       cfg.ChangesEnrichmentEnabled(),
				WindowMinutes: cfg.Changes.Enrichment.WindowMinutes,
				MaxEvents:     cfg.Changes.Enrichment.MaxEvents,
			},
			Sentry:       sentryReader,
			SentryParams: sentryParams,
			Zabbix:       zbxReader,
			ZabbixParams: zbxParams,
			// Memory recall reads the same store the skill persists to; the
			// concrete *store.Store is always present, so no typed-nil guard is
			// needed. Recall is deterministic and default-on.
			Memory:       st,
			MemoryParams: acutetriage.MemoryParams{LookbackDays: cfg.Memory.LookbackDays},
			// M3 shadow classifier: nil client unless mode is shadow/on. The mode
			// gates the render/audit split inside the skill; the timeout hard-bounds
			// the call's time on the triage path (retries and all).
			Classifier:        classifierClient,
			ClassifierMode:    string(cfg.Memory.Classifier.Mode),
			ClassifierTimeout: time.Duration(cfg.Memory.Classifier.TimeoutSeconds) * time.Second,
			// Verification round (falsification pass, ADR-0021/0022). MaxSeries shares
			// the metric-enrichment server-side bound (prometheus.max_series) — model
			// promql runs under the identical cap.
			Verification: acutetriage.VerificationParams{
				Enabled:             cfg.VerificationEnabled(),
				MaxQueries:          cfg.Triage.Verification.MaxQueries,
				QueryTimeoutSeconds: cfg.Triage.Verification.QueryTimeoutSeconds,
				MaxSeries:           cfg.Prometheus.MaxSeries,
				ExtraSelectorLabels: cfg.Triage.ExtraSelectorLabels,
			},
			PromptCaching: !llmProviderIsOpenAI(cfg),
			Health:        llmHealth,
		},
		st, llmClient, auditor, notifier, logger,
	)
	_ = apiKey // key is embedded in llmClient via Config.APIKey
	captureEngine := acutetriage.NewCaptureEngine(skill)
	defer closeCaptureEngine(captureEngine, logger) // after cor.Stop, before the runner stops

	corCfg := correlator.Config{
		WindowSeconds:   cfg.Correlator.WindowSeconds,
		GroupLabels:     cfg.Correlator.GroupLabels,
		AttachWindow:    time.Duration(cfg.Memory.AttachWindowMinutes) * time.Minute,
		JudgmentCeiling: time.Duration(cfg.Memory.JudgmentCeilingHours) * time.Hour,
		OccurrenceCap:   cfg.Memory.OccurrenceCap,
		Lookback:        time.Duration(cfg.Memory.LookbackDays) * 24 * time.Hour,
	}
	cor := correlator.New(corCfg, st, incidentSink{skill: skill}, logger)

	// SetAuditor/SetRejudger/SetTriageFailureNotifier are safe to wire here,
	// before reconstruction: none of them is reachable from ApplyDelivery's
	// durable-dispatch path (Rejudge is deliberately never called
	// synchronously from a delivery commit; the occurrence-attach audit call
	// and the triage-exhausted notifier both live only on the legacy
	// Accept/handleAlert path and the correlator's own internal ticker loop,
	// neither of which runs during reconstruction). SetResolutionNotifier and
	// SetOccurrenceNotifier are NOT wired here — see startCorrelator below.
	cor.SetAuditor(auditor)
	cor.SetRejudger(skill)
	cor.SetTriageFailureNotifier(notifier)

	// stopCorrelator is called exactly once, however runServe exits: inline,
	// in the right relative position, by foundationStopSequence on the
	// normal shutdown path below, or — for every earlier return between here
	// and there (a receivers/MCP wiring error, etc.) — by this defer acting
	// as the safety net it always has been. sync.Once makes it safe to be
	// both.
	var corStopOnce sync.Once
	stopCorrelator := func() { corStopOnce.Do(cor.Stop) }
	defer stopCorrelator()

	// The durable Situation foundation runtime (Task 8): the dispatch and
	// input workers Tasks 6-7 built, plus the Reconstructor that converges
	// durable state before either worker, or Receivers, ever runs. owner is
	// this process's own lease identity, minted once.
	owner := "alertint-" + uuid.NewString()
	rt := newFoundationRuntime(st, cor, owner, logger)

	// Probe enabled integrations in the background: quickly (with backoff)
	// while one is failing — at startup a co-deployed dependency may still
	// be booting — then at a steady pace, logging losses and recoveries.
	// Results are cached for GET /health.
	healthReg := buildHealthChecks(cfg, prom, logSrc, sentryClient, zbxClient)
	go healthReg.Watch(ctx, logger)

	var recvSrv *http.Server
	var recvErrCh <-chan error
	startupSeq := foundationSequence{
		reconstruct: func(ctx context.Context) error {
			report, err := rt.Reconstruct(ctx)
			if err != nil {
				return fmt.Errorf("situation foundation reconstruction: %w", err)
			}
			logReconstructionReport(logger, report)
			return nil
		},
		// SetResolutionNotifier/SetOccurrenceNotifier are wired here — between
		// reconstruct and cor.Start, never before — because both are
		// synchronously reachable from ApplyDelivery's durable-dispatch path
		// (a queued resolved delivery whose commit settles an Incident calls
		// the resolution notifier; a queued firing delivery that collapses
		// into a recurrence occurrence calls the occurrence notifier). Wiring
		// them before reconstruction would let a plain crash-and-restart with
		// ordinary queued webhook traffic post to Slack from reconstruction —
		// exactly the outward effect this task's Reconstructor must never
		// cause. The Setters' own doc comments require only "after New,
		// before Start", so this ordering is legal; the Correlator's loop
		// itself isn't running yet either.
		startCorrelator: func(ctx context.Context) error {
			cor.SetResolutionNotifier(notifyresolution.New(notifier, st))
			cor.SetOccurrenceNotifier(notifier)
			return cor.Start(ctx)
		},
		startWorkers: rt.Start,
		startReceivers: func() error {
			var err error
			recvSrv, recvErrCh, err = startReceivers(cfg, st, auditor, healthReg, llmHealth, rt.WakeDispatch, logger)
			return err
		},
	}
	if err := startupSeq.run(ctx); err != nil {
		return err
	}

	mcpHTTPSrv, mcpErrCh, err := startMCP(cfg, st, auditor, prom, logSrc, sentryReader, sentryParams, zbxClient, captureEngine, logger)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining in-flight requests")
	case err := <-recvErrCh: // nil channel never fires when no receiver is enabled
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

	// Receivers, then the foundation workers (rt.Stop: dispatch, then
	// input), then the Correlator: Receivers stopping first means no new
	// inbound work can be durably accepted; the queue workers stopping next
	// means nothing already durably queued goes unclaimed mid-drain; the
	// Correlator stopping last — via stopCorrelator, the same
	// sync.Once-guarded call the defer above falls back to on every other
	// exit path — means it keeps serving fixed-window expiry and Triage
	// retry for exactly as long as anything upstream could still be handing
	// it work.
	stopSeq := foundationStopSequence{
		stopReceivers: func() error {
			if recvSrv == nil {
				return nil
			}
			return recvSrv.Shutdown(shutdownCtx)
		},
		stopWorkers:    rt.Stop,
		stopCorrelator: stopCorrelator,
	}
	if err := stopSeq.run(shutdownCtx); err != nil {
		logger.Error("situation foundation shutdown failed", slog.String("err", err.Error()))
	}

	if mcpHTTPSrv != nil {
		if err := mcpHTTPSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("MCP graceful shutdown failed", slog.String("err", err.Error()))
		}
	}
	logger.Info("alertint stopped", slog.String("reason", "signal"))
	return nil
}

// stopLLMHealthRunner stops the LLM health runner — its final delivery pass
// acknowledges the settled state — and waits, bounded by
// llmhealth.DrainTimeout, for it to finish. Call only after every capability
// producer has been joined.
func stopLLMHealthRunner(r *llmhealth.Runner, done <-chan struct{}, logger *slog.Logger) {
	r.Stop()
	select {
	case <-done:
	case <-time.After(llmhealth.DrainTimeout()):
		logger.Warn("llm health runner did not stop within the drain window; abandoning its in-flight delivery")
	}
}

// closeCaptureEngine joins every Captured-verdict / annotation operation
// (MCP request goroutines, which http.Server.Shutdown neither cancels nor
// reliably joins) before the LLM health runner is stopped and the store is
// closed. Grades in progress are canceled — the health tracker ignores
// shutdown-driven cancellation — and persists in progress complete. A join
// that times out means an operation is wedged past every bound it has: the
// process still exits, but not as if the runner's precondition held — the
// runner seals the tracker BEFORE its final pass (the observation cutoff),
// so the pass acknowledges one immutable snapshot, whatever that operation
// reports from then on is dropped, and its store access fails against a
// closed store rather than moving state nobody acknowledged.
func closeCaptureEngine(eng *acutetriage.CaptureEngine, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), ingress.DefaultShutdownTimeout)
	defer cancel()
	if err := eng.Close(ctx); err != nil {
		logger.Error("a verdict capture or annotation did not finish within the shutdown window; "+
			"the health runner seals observation before its final pass, so its late LLM observation will be dropped and its store access will fail",
			slog.String("err", err.Error()))
	}
}

// pruneChangesAtStartup runs a one-shot retention prune so a long-stopped agent
// doesn't carry stale changes. The per-insert prune in changeReceiver bounds the
// table while the agent runs; this closes the gap where it was stopped while
// changes aged out past retention. No-op when changes are disabled.
func pruneChangesAtStartup(ctx context.Context, cfg *config.Config, st *store.Store, logger *slog.Logger) {
	if !cfg.Changes.Ingress.Enabled && !cfg.ChangesEnrichmentEnabled() {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -cfg.Changes.RetentionDays)
	if n, err := st.PruneChanges(ctx, cutoff); err != nil {
		logger.Warn("changes startup prune failed", slog.String("err", err.Error()))
	} else if n > 0 {
		logger.Info("changes pruned at startup", slog.Int64("removed", n), slog.Int("retention_days", cfg.Changes.RetentionDays))
	}
}

// startReceivers starts the inbound webhook host when at least one receiver is
// enabled. The host also serves GET /health. Returns (nil, nil, nil) when no
// receiver is enabled — the nil error channel never fires in runServe's
// select. wake is the durable dispatch worker's wake callback
// (foundationRuntime.WakeDispatch) — a latency optimization only, safe to
// pass nil (both Alertmanager and Zabbix receivers already tolerate a nil
// DeliveryWake): the dispatch worker polls its durable queue regardless.
func startReceivers(cfg *config.Config, st *store.Store, auditor *audit.Auditor, healthReg *health.Registry, llmHealth ingress.LLMHealthReader, wake ingress.DeliveryWake, logger *slog.Logger) (*http.Server, <-chan error, error) {
	var receivers []ingress.Receiver
	if cfg.Alertmanager.Enabled {
		token, err := cfg.WebhookToken()
		if err != nil {
			return nil, nil, err
		}
		receivers = append(receivers, ingress.NewAlertReceiver(st, token, wake, logger))
	}
	if cfg.Changes.Ingress.Enabled {
		token, err := cfg.ChangesWebhookToken()
		if err != nil {
			return nil, nil, err
		}
		receivers = append(receivers, ingress.NewChangeReceiver(st, token, cfg.Changes.RetentionDays, logger))
	}
	if cfg.Zabbix.Ingress.Enabled {
		token, err := cfg.ZabbixWebhookToken()
		if err != nil {
			return nil, nil, err
		}
		receivers = append(receivers, ingress.NewZabbixReceiver(st, token, wake, logger))
	}

	if len(receivers) == 0 {
		logger.Info("no inbound receivers enabled; /health endpoint not served")
		return nil, nil, nil
	}

	host, err := ingress.New(ingress.Options{
		Store:     st,
		Auditor:   auditor,
		Receivers: receivers,
		Logger:    logger,
		Health:    healthReg,
		LLMHealth: llmHealth,
	})
	if err != nil {
		return nil, nil, err
	}

	srv := &http.Server{
		Addr:              cfg.Receivers.Address,
		Handler:           host.Handler(),
		ReadTimeout:       ingress.DefaultReadTimeout,
		ReadHeaderTimeout: ingress.DefaultReadTimeout,
		WriteTimeout:      ingress.DefaultWriteTimeout,
		IdleTimeout:       ingress.DefaultIdleTimeout,
	}

	routes := make([]string, 0, len(receivers))
	for _, r := range receivers {
		routes = append(routes, r.Route())
	}
	ch := make(chan error, 1)
	go func() {
		logger.Info("receivers listening",
			slog.String("addr", cfg.Receivers.Address),
			slog.String("routes", strings.Join(routes, ", ")),
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
func startMCP(cfg *config.Config, st *store.Store, auditor *audit.Auditor, prom *promclient.Client, logSrc logs.Source, sentryReader acutetriage.SentryReader, sentryParams acutetriage.SentryParams, zbxClient *zabbix.Client, captureEngine *acutetriage.CaptureEngine, logger *slog.Logger) (*http.Server, <-chan error, error) {
	if !cfg.MCPEnabled() {
		return nil, nil, nil
	}
	mcpToken, err := cfg.MCPToken()
	if err != nil {
		return nil, nil, err
	}
	mcpCfg := internalmcp.Config{
		Token:                   mcpToken,
		WindowSeconds:           cfg.Correlator.WindowSeconds,
		Prometheus:              prom,
		Logs:                    logSrc,
		LogsDefaultRangeMinutes: cfg.Logs.DefaultRangeMinutes,
		ChangesEnabled:          cfg.ChangesEnrichmentEnabled(),
		ChangesWindowMinutes:    cfg.Changes.Enrichment.WindowMinutes,
		// The live Sentry read tools ride the SAME true-nil reader the triage Error
		// source uses (nil for disabled/releases-only → tools off), and the WHOLE
		// resolved params envelope so the live deadline is the configured value, not
		// zero (KTD8). Never pass a lone IncludeMessage scalar.
		Sentry:                    sentryReader,
		SentryParams:              sentryParams,
		SentryLiveWindowMinutes:   cfg.Sentry.Issues.LiveWindowMinutes,
		ZabbixDefaultRangeMinutes: cfg.Zabbix.API.DefaultRangeMinutes,
		MemoryLookbackDays:        cfg.Memory.LookbackDays,
		Capture:                   captureEngine,
	}
	// zbxClient's field type is an unexported interface in package mcp, so it
	// can't be declared as a typed nil here — assign only when non-nil (typed-nil
	// trap: mirrors the skill-side ZabbixReader wiring above).
	if zbxClient != nil {
		mcpCfg.Zabbix = zbxClient
	}
	mcpSrv := internalmcp.NewServer(mcpCfg, st, auditor)
	srv := &http.Server{
		Addr:    cfg.MCP.Addr,
		Handler: mcpSrv.Handler(),
		// WriteTimeout 0: MCP uses long-lived SSE streams for streaming responses.
		ReadTimeout: ingress.DefaultReadTimeout,
		IdleTimeout: ingress.DefaultIdleTimeout,
	}
	ch := make(chan error, 1)
	go func() {
		logger.Info("mcp listening",
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

// openStoreWithStagedRestore is serve's store-opening path: it applies a
// pending Staged restore BEFORE store.Open — the one moment the agent
// provably holds no database connection (ADR-0030) — then opens the store.
// A rejected staging file is an error: serve exits non-zero once, loudly;
// the staging file has already been set aside, so the next start serves
// normally on the untouched DB.
func openStoreWithStagedRestore(ctx context.Context, dbPath string, logger *slog.Logger) (*store.Store, *backup.RestoreInfo, error) {
	info, err := backup.ApplyStaged(ctx, dbPath)
	if err != nil {
		logger.Error("staged restore failed", slog.String("error", err.Error()))
		return nil, nil, fmt.Errorf("staged restore: %w", err)
	}
	if info != nil {
		logger.Info("staged restore applied",
			slog.String("source", info.SourceFile),
			slog.Int64("source_bytes", info.SourceBytes),
			slog.Int64("installed_bytes", info.InstalledBytes),
			slog.String("safety_copy", info.SafetyCopy),
		)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, nil, err
	}
	return st, info, nil
}

// finalizeStagedRestoreIfApplied verifies and audits a staged restore that
// openStoreWithStagedRestore applied, if any. No-op when info is nil.
// Failures warn only: the store is already open and serving, so a
// verification failure must never abort a successful startup.
func finalizeStagedRestoreIfApplied(ctx context.Context, st *store.Store, info *backup.RestoreInfo, logger *slog.Logger) {
	if info == nil {
		return
	}
	if err := finalizeRestore(ctx, st, info, logger); err != nil {
		logger.Warn("staged restore finalization failed", slog.String("error", err.Error()))
	}
}

func runVerifyAudit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	dbPathFlag := fs.String("db", "", "path to SQLite database (overrides config.storage.sqlite_path)")
	logLevel := fs.String("log-level", "warn", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "auto", "log format: auto, console, json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:  *logLevel,
		Format: logging.Resolve(logging.Format(*logFormat), stderr, nil),
		Writer: stderr,
	})
	if err != nil {
		return err
	}
	logging.SetDefault(logger)

	dbPath, err := resolveDBPath("verify-audit", *cfgPath, *dbPathFlag)
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

// logConfigWarnings emits each non-fatal config advisory (e.g. a volatile
// group label) at WARN so startup surfaces them without blocking.
// applyServeOverrides applies the --receivers-addr/--mcp-addr CLI flags over
// the loaded config, in place. Empty flag values leave the config untouched.
func applyServeOverrides(cfg *config.Config, receiversAddr, mcpAddr string) {
	if receiversAddr != "" {
		cfg.Receivers.Address = receiversAddr
	}
	if mcpAddr != "" {
		cfg.MCP.Addr = mcpAddr
	}
}

func logConfigWarnings(logger *slog.Logger, cfg *config.Config) {
	for _, w := range cfg.Warnings() {
		logger.Warn(w)
	}
}

func resolveDBPath(sub, cfgPath, dbPathFlag string) (string, error) {
	if dbPathFlag != "" {
		return dbPathFlag, nil
	}
	if cfgPath == "" {
		return "", fmt.Errorf("%s: either --config or --db is required", sub)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return "", err
	}
	return cfg.Storage.SQLitePath, nil
}

// sentryErrorSource resolves the triage Error-source reader and params from
// config. It returns a TRUE nil SentryReader interface (not a typed-nil
// *sentry.Client) unless the issues feature is enabled with a live shared client,
// so FetchSentry's r == nil guard fires and unconfigured/releases-only triage is
// unchanged (KTD7). The params carry through regardless (Enabled gates the fetch).
func sentryErrorSource(cfg *config.Config, client *sentry.Client) (acutetriage.SentryReader, acutetriage.SentryParams) {
	params := acutetriage.SentryParams{
		Enabled:             cfg.Sentry.Issues.Enabled,
		LookbackMinutes:     cfg.Sentry.Issues.LookbackMinutes,
		MaxIssues:           cfg.Sentry.Issues.MaxIssues,
		FetchTimeoutSeconds: cfg.Sentry.Issues.FetchTimeoutSeconds,
		IncludeMessage:      cfg.Sentry.Issues.MessageIncluded(),
	}
	if cfg.Sentry.Issues.Enabled && client != nil {
		return client, params
	}
	return nil, params
}

// newSentryClient builds the shared read-only Sentry client when ANY Sentry
// feature is enabled (the release Change source OR the issue Error source),
// resolving the token from its named env var. Returns (nil, nil) when the whole
// connector is disabled so callers can skip all Sentry wiring (KTD7).
func newSentryClient(cfg *config.Config) (*sentry.Client, error) {
	if !cfg.AnySentryEnabled() {
		return nil, nil //nolint:nilnil // a disabled connector legitimately has no client and no error; callers branch on nil
	}
	token, err := cfg.SentryToken()
	if err != nil {
		return nil, err
	}
	return sentry.NewClient(sentry.Config{
		BaseURL:        cfg.Sentry.BaseURL,
		Org:            cfg.Sentry.Org,
		Token:          token,
		TimeoutSeconds: cfg.Sentry.TimeoutSeconds,
	}), nil
}

// newZabbixClient builds the read-only Zabbix pull-Source client when
// zabbix.api is enabled, resolving the token from its named env var. Returns
// (nil, nil) when the source is disabled so callers can skip all Zabbix
// wiring, mirroring newSentryClient.
func newZabbixClient(cfg *config.Config, logger *slog.Logger) (*zabbix.Client, error) {
	if !cfg.ZabbixAPIEnabled() {
		return nil, nil //nolint:nilnil // a disabled source legitimately has no client and no error; callers branch on nil
	}
	token, err := cfg.ZabbixAPIToken()
	if err != nil {
		return nil, err
	}
	client := zabbix.NewClient(zabbix.Config{
		BaseURL:              cfg.Zabbix.API.BaseURL,
		APIToken:             token,
		TimeoutSeconds:       cfg.Zabbix.API.TimeoutSeconds,
		HistoryRetentionDays: cfg.Zabbix.API.HistoryRetentionDays,
		FlapWindowHours:      cfg.Zabbix.API.FlapWindowHours,
	})
	logger.Info("zabbix api connected", slog.String("base_url", cfg.Zabbix.API.BaseURL))
	return client, nil
}

// zabbixContextSource resolves the triage ZabbixReader + params from the built
// client. Returns a TRUE nil ZabbixReader interface (not a typed-nil
// *zabbix.Client) when client is nil, mirroring sentryErrorSource.
func zabbixContextSource(cfg *config.Config, client *zabbix.Client) (acutetriage.ZabbixReader, acutetriage.ZabbixParams) {
	params := acutetriage.ZabbixParams{
		TimeoutSeconds:  cfg.Zabbix.API.TimeoutSeconds,
		HostLabel:       cfg.Zabbix.API.HostLabel,
		FlapWindowHours: cfg.Zabbix.API.FlapWindowHours,
	}
	if client != nil {
		return client, params
	}
	return nil, params
}

// startSentryPoller builds the shared Sentry client when any feature is enabled
// and starts the release/deploy poller ONLY when releases is enabled, returning
// the client (for the Error source + the health check) and a stop func to defer.
// When the whole connector is disabled it returns (nil, no-op, nil) so the caller
// can defer unconditionally. An issues-only deployment gets the shared client
// with no poller goroutine (KTD7). Keeps runServe's branching low.
func startSentryPoller(ctx context.Context, cfg *config.Config, st *store.Store, logger *slog.Logger) (*sentry.Client, func(), error) {
	client, err := newSentryClient(cfg)
	if err != nil {
		return nil, func() {}, err
	}
	if client == nil {
		return nil, func() {}, nil
	}
	logger.Info("sentry connected",
		slog.String("base_url", cfg.Sentry.BaseURL),
		slog.String("org", cfg.Sentry.Org),
	)
	if !cfg.Sentry.Releases.Enabled {
		// Error source only: the shared client is built for triage-time issue
		// enrichment, but no release/deploy poller runs.
		return client, func() {}, nil
	}
	if !cfg.ChangesEnrichmentEnabled() {
		// The poller writes change rows, but only changes.enrichment surfaces them
		// at triage and over MCP — warn so this misconfiguration isn't silent.
		logger.Warn("sentry poller is enabled but changes.enrichment is disabled; polled changes will be stored but not surfaced at triage or over MCP")
	}
	poller := newSentryPoller(cfg, client, st, logger)
	poller.Start(ctx)
	logger.Info("sentry release/deploy poller started",
		slog.Int("interval_seconds", cfg.Sentry.Releases.PollIntervalSeconds),
	)
	return client, poller.Stop, nil
}

// newSentryPoller builds the release/deploy poller from config and the shared
// client. Returns nil when the client is nil (poller disabled). Retention reuses
// the existing change-retention setting (no Sentry-specific retention).
func newSentryPoller(cfg *config.Config, client *sentry.Client, st *store.Store, logger *slog.Logger) *sentry.Poller {
	if client == nil {
		return nil
	}
	rel := cfg.Sentry.Releases
	return sentry.NewPoller(client, st, sentry.PollerConfig{
		BaseURL:            client.BaseURL(),
		Org:                client.Org(),
		Projects:           rel.Projects,
		PollInterval:       time.Duration(rel.PollIntervalSeconds) * time.Second,
		InitialLookback:    time.Duration(rel.InitialLookbackMinutes) * time.Minute,
		ReleaseScanHorizon: time.Duration(rel.ReleaseScanHorizonDays) * 24 * time.Hour,
		RetentionDays:      cfg.Changes.RetentionDays,
	}, logger)
}

// buildHealthChecks assembles connectivity probes for every enabled
// integration. Returns nil (a no-op registry) when nothing is enabled.
func buildHealthChecks(cfg *config.Config, prom *promclient.Client, logSrc logs.Source, sentryClient *sentry.Client, zbxClient *zabbix.Client) *health.Registry {
	var checks []health.Check
	if cfg.PrometheusEnabled() && prom != nil {
		checks = append(checks, health.Check{
			Name:   "prometheus",
			Detail: cfg.Prometheus.BaseURL,
			Probe: func(ctx context.Context) error {
				// A trivial instant query proves the API is reachable,
				// authorized, and serving query results.
				_, err := prom.QueryInstant(ctx, "vector(1)", time.Now(), 0)
				return err
			},
		})
	}
	if cfg.LogsEnabled() && logSrc != nil {
		checks = append(checks, health.Check{
			Name:   logSrc.Name(),
			Detail: cfg.Logs.Loki.BaseURL,
			Probe: func(ctx context.Context) error {
				// A trivial metric LogQL range query proves the API is
				// reachable, authorized, and serving — without needing any
				// stream-label knowledge.
				now := time.Now()
				_, err := logSrc.QueryRange(ctx, "vector(1)", now.Add(-time.Minute), now, 1, "backward")
				return err
			},
		})
	}
	if cfg.AnySentryEnabled() && sentryClient != nil {
		checks = append(checks, health.Check{
			Name:   "sentry",
			Detail: cfg.Sentry.BaseURL,
			Probe: func(ctx context.Context) error {
				// A releases listing proves the API is reachable, the token is
				// valid, and project:read is granted — a read-only GET valid for
				// the Error source (issues-only) too.
				_, _, err := sentryClient.ListReleases(ctx, cfg.Sentry.Releases.Projects, "")
				return err
			},
		})
	}
	if cfg.ZabbixAPIEnabled() && zbxClient != nil {
		checks = append(checks, health.Check{
			Name:   "zabbix",
			Detail: cfg.Zabbix.API.BaseURL,
			Probe: func(ctx context.Context) error {
				// apiinfo.version needs no auth: proves the frontend is
				// reachable and serving. Token validity surfaces on the first
				// real context fetch.
				_, err := zbxClient.APIVersion(ctx)
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

// buildNotifier constructs the notify.Multi from the loaded config and logs the
// active sinks at startup. The human-readable one-line finding summary and the
// per-sink "notified" outcome line are owned by Multi (both at INFO, both
// formats). The sinks themselves:
//
//   - stdout: always an active sink when notify.stdout is set, so a send is
//     confirmed (notified · stdout=ok) at INFO. Its verbose full JSON line is
//     written only at debug level (consistently, in every format).
//   - slack: when enabled and a bot token resolves.
//
// buildNotifier also returns the llmhealth.Publisher for the installation's
// one system-message surface: the same Slack *Notifier when Slack is wired,
// else nil (LLM dependency health then lives in state/audit/logs only).
func buildNotifier(cfg *config.Config, st *store.Store, auditor *audit.Auditor, logger *slog.Logger, debug bool) (*notify.Multi, llmhealth.Publisher) {
	var nn []notify.Notifier
	var sinks []string
	slackWired := false
	var publisher llmhealth.Publisher
	if cfg.Notify.Stdout {
		nn = append(nn, notifystdout.New(os.Stdout, auditor, debug))
		sinks = append(sinks, "stdout")
	}
	if cfg.Notify.Slack.Enabled {
		if token, err := cfg.SlackBotToken(); err == nil && token != "" {
			slackNotifier := notifyslack.New(token, cfg.Notify.Slack.Channel, cfg.Notify.Slack.MinSeverity, cfg.Notify.Slack.RecurrenceMode, st, auditor)
			nn = append(nn, slackNotifier)
			sinks = append(sinks, "slack")
			slackWired = true
			publisher = slackNotifier
		}
	}

	attrs := []any{slog.String("sinks", strings.Join(sinks, ",")), slog.Bool("llm_system_messages", slackWired)}
	if slackWired {
		attrs = append(attrs, slog.String("slack_channel", cfg.Notify.Slack.Channel))
	}
	logger.Info("notifiers ready", attrs...)

	return notify.NewMulti(logger, nn...), publisher
}

// llmProviderIsOpenAI reports whether the configured provider is the
// openai-compatible one (case-insensitive, matching config validation).
func llmProviderIsOpenAI(cfg *config.Config) bool {
	return strings.EqualFold(cfg.LLM.Provider, "openai-compatible")
}

// buildLLMClient constructs the triage LLM client for the configured
// provider. Exactly one provider serves an install (ADR-0026).
func buildLLMClient(cfg *config.Config, apiKey string, auditor *audit.Auditor, logger *slog.Logger) acutetriage.LLMClient {
	if llmProviderIsOpenAI(cfg) {
		return llmopenai.New(llmopenaiCfg(cfg, apiKey, cfg.LLM.TimeoutSeconds, cfg.LLM.Model, cfg.LLM.MaxTokens), auditor, logger)
	}
	return llmanthropic.New(llmanthropicCfg(cfg), auditor, logger)
}

// buildLLMProber type-asserts the primary LLM client into an llm.Prober for
// the idle reachability probe. Both concrete clients satisfy it; a future
// client type that doesn't is a config/wiring gap, not a crash — the idle
// probe just stays off and a WARN says why.
func buildLLMProber(cfg *config.Config, client acutetriage.LLMClient, logger *slog.Logger) llm.Prober {
	p, ok := client.(llm.Prober)
	if !ok {
		logger.Warn("llm health: configured client does not support the idle probe; idle probing disabled",
			slog.String("provider", cfg.LLM.Provider))
		return nil
	}
	return p
}

// llmopenaiCfg builds an openaicompat.Config; model/maxTokens/timeout are
// parameters because the classifier client reuses this with its own values.
func llmopenaiCfg(cfg *config.Config, apiKey string, timeoutSeconds int, model string, maxTokens int) llmopenai.Config {
	return llmopenai.Config{
		BaseURL:         cfg.LLM.BaseURL,
		APIKey:          apiKey,
		Model:           model,
		MaxTokens:       maxTokens,
		ResponseFormat:  cfg.LLM.ResponseFormat,
		Thinking:        cfg.LLM.Thinking,
		ReasoningEffort: cfg.LLM.ReasoningEffort,
		TimeoutSeconds:  timeoutSeconds,
	}
}

// classifierThinkingMaxTokens is the classifier's completion ceiling when
// llm.thinking is on. Reasoning output shares the completion budget on this
// wire format, so the 1024-token verdict default would truncate mid-thought
// and poison the graduation evidence with fail-open "unsure" verdicts.
const classifierThinkingMaxTokens = 8192

// buildClassifierClient builds the shadow classifier's own client. On
// anthropic it keeps the dedicated Haiku model; on openai-compatible it
// reuses llm.model — a single-model local endpoint has nothing cheaper to
// serve, and requesting the Haiku constant there would 404 every call,
// silently poisoning the ADR-0018 graduation evidence with fail-open
// "unsure" verdicts. Returns a true nil interface when the mode is off.
func buildClassifierClient(cfg *config.Config, apiKey string, auditor *audit.Auditor, logger *slog.Logger) acutetriage.LLMClient {
	if !cfg.Memory.Classifier.Enabled() {
		return nil
	}
	if llmProviderIsOpenAI(cfg) {
		logger.Info("memory shadow classifier enabled",
			slog.String("mode", string(cfg.Memory.Classifier.Mode)),
			slog.String("model", cfg.LLM.Model),
		)
		// MaxTokens 0 → the client's 1024 default, mirroring the anthropic
		// classifier client, which also relies on its config default. With
		// llm.thinking on, the inherited reasoning competes with the verdict
		// for that budget, so the ceiling grows to a thinking-sized one.
		maxTokens := 0
		if cfg.LLM.Thinking {
			maxTokens = classifierThinkingMaxTokens
		}
		return llmopenai.New(llmopenaiCfg(cfg, apiKey, cfg.Memory.Classifier.TimeoutSeconds, cfg.LLM.Model, maxTokens), auditor, logger)
	}
	logger.Info("memory shadow classifier enabled",
		slog.String("mode", string(cfg.Memory.Classifier.Mode)),
		slog.String("model", acutetriage.ClassifierModel),
	)
	return llmanthropic.New(llmanthropic.Config{
		APIKey:         apiKey,
		Model:          acutetriage.ClassifierModel,
		TimeoutSeconds: cfg.Memory.Classifier.TimeoutSeconds,
	}, auditor, logger)
}

// llmanthropicCfg builds an llm/anthropic.Config from the loaded config.
func llmanthropicCfg(cfg *config.Config) llmanthropic.Config {
	key, _ := cfg.LLMAPIKey()
	return llmanthropic.Config{
		APIKey:         key,
		Model:          cfg.LLM.Model,
		MaxTokens:      cfg.LLM.MaxTokens,
		TimeoutSeconds: cfg.LLM.TimeoutSeconds,
	}
}

// incidentSink wraps an acutetriage.Skill as a correlator.IncidentSink.
type incidentSink struct {
	skill *acutetriage.Skill
}

func (s incidentSink) OnIncidentReady(ctx context.Context, inc store.Incident) error {
	return s.skill.Run(ctx, inc)
}

// buildLogger constructs the runtime logger applying precedence
// CLI flag > config > built-in default (info / auto) for both level and format,
// resolves the auto format against the writer's TTY-ness, and returns the
// logger plus the concrete level/format strings for the startup line. Passing
// "" for cfgLevel/cfgFormat (the bootstrap case) falls straight through to the
// built-in defaults.
func buildLogger(flagLevel, flagFormat, cfgLevel, cfgFormat string, w io.Writer) (*slog.Logger, string, string, error) {
	level := firstNonEmpty(flagLevel, cfgLevel, "info")
	format := firstNonEmpty(flagFormat, cfgFormat, string(logging.FormatAuto))
	resolved := logging.Resolve(logging.Format(format), w, nil)
	logger, err := logging.New(logging.Options{
		Level:  level,
		Format: resolved,
		Writer: w,
	})
	if err != nil {
		return nil, "", "", err
	}
	return logger, level, string(resolved), nil
}

// firstNonEmpty returns the first argument that is not empty after trimming.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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
