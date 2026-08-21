// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/health"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	notifystdout "github.com/alertint/alertint-agent/internal/notify/stdout"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// slackAuthoritySituationNotifications is the one component allowed to write
// to Slack after the cutover. The runtime records it so the topology itself
// is testable: exactly one authority, never a dual stream.
const slackAuthoritySituationNotifications = "situation_notification_worker"

// workerGroup is the cut-over runtime's durable worker graph. Every member
// claims its own durable queue; none of them hand work to another in memory.
type workerGroup struct {
	Dispatch      *correlator.DispatchWorker
	Inputs        *situation.InputWorker
	Controller    *situation.WorkerPool
	Notifications *situation.NotificationWorker
}

// Start launches every worker. Order matters only for promptness, not
// correctness: each queue is durable, so a later start simply picks work up.
func (g *workerGroup) Start(ctx context.Context) {
	if g == nil {
		return
	}
	if g.Dispatch != nil {
		g.Dispatch.Start(ctx)
	}
	if g.Inputs != nil {
		g.Inputs.Start(ctx)
	}
	if g.Controller != nil {
		g.Controller.Start(ctx)
	}
	if g.Notifications != nil {
		g.Notifications.Start(ctx)
	}
}

// Stop drains in-flight claims within ctx's deadline. Work that does not
// finish stays durable and leased; its lease lapses and the next start
// recovers it.
func (g *workerGroup) Stop(ctx context.Context) error {
	if g == nil {
		return nil
	}
	var errs []error
	if g.Dispatch != nil {
		g.Dispatch.Stop()
	}
	if g.Inputs != nil {
		errs = append(errs, g.Inputs.Stop(ctx))
	}
	if g.Controller != nil {
		errs = append(errs, g.Controller.Stop(ctx))
	}
	if g.Notifications != nil {
		errs = append(errs, g.Notifications.Stop(ctx))
	}
	return errors.Join(errs...)
}

// Wake asks every worker to run a round now — used after an MCP write or a
// newly accepted delivery so the operator does not wait out a poll interval.
func (g *workerGroup) Wake() {
	if g == nil {
		return
	}
	if g.Dispatch != nil {
		g.Dispatch.Wake()
	}
	if g.Inputs != nil {
		g.Inputs.Wake()
	}
	if g.Controller != nil {
		g.Controller.Wake()
	}
	if g.Notifications != nil {
		g.Notifications.Wake()
	}
}

// serveRuntime is serve's assembled Situation topology, separated from the
// HTTP listeners so the wiring itself is testable.
type serveRuntime struct {
	store         *store.Store
	reconstructor *situation.Reconstructor
	workers       *workerGroup
	commands      *situationCommands
	writeHealth   *storeWriteHealth
	correlator    *correlator.Correlator
	// healthSink turns probe transitions into durable dependency-health
	// state; runServe attaches it to the health registry it owns.
	healthSink *situation.DependencyHealthSink

	// Cutover topology, recorded so a test can assert it rather than trusting
	// a comment: the triage skill must carry no notifier (no
	// IncidentSink -> acute triage -> Slack path), the correlator must carry
	// the no-op sink, and slackAuthorities must name exactly one writer.
	acuteNotifierWired bool
	incidentSink       correlator.IncidentSink
	slackAuthorities   []string
}

// storeWriteHealth makes SQLite write health authoritative for readiness. A
// failed authoritative write logs one ERROR, fails readiness, and gates every
// worker: no connector, model, or Slack I/O runs while state cannot be
// persisted, and no in-memory state is ever published in its place. The first
// successful write restores readiness and wakes the durable workers.
type storeWriteHealth struct {
	logger *slog.Logger
	path   string

	mu      sync.Mutex
	lastErr error
	wake    func()
}

func newStoreWriteHealth(path string, logger *slog.Logger) *storeWriteHealth {
	if logger == nil {
		logger = slog.Default()
	}
	return &storeWriteHealth{logger: logger, path: path, wake: func() {}}
}

// SetWake attaches the worker wake-up used when readiness is restored.
func (h *storeWriteHealth) SetWake(wake func()) {
	if wake == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wake = wake
}

// Ready reports whether durable storage is currently writable.
func (h *storeWriteHealth) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastErr == nil
}

// Observe records one round's outcome. It logs exactly once per state change,
// never once per failing round, so a sustained outage does not itself become
// a log storm.
func (h *storeWriteHealth) Observe(_ int, err error) {
	h.mu.Lock()
	previous := h.lastErr
	h.lastErr = err
	wake := h.wake
	h.mu.Unlock()

	switch {
	case err != nil && previous == nil:
		h.logger.Error("sqlite write failed; readiness degraded and situation work is paused",
			slog.String("path", h.path), slog.String("err", err.Error()))
	case err == nil && previous != nil:
		h.logger.Info("sqlite writes recovered; readiness restored", slog.String("path", h.path))
		wake()
	}
}

// Check exposes storage write health as a readiness probe, so GET /health
// reports degraded whenever an authoritative write is failing.
func (h *storeWriteHealth) Check() health.Check {
	return health.Check{
		Name:   "sqlite",
		Detail: h.path,
		Probe: func(context.Context) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.lastErr
		},
	}
}

// acuteInvestigator adapts the acute triage skill to the controller's B+
// dispatch boundary. The finding it produces is durable evidence only: D2
// gives L1 no Attention, publication, or Slack authority.
type acuteInvestigator struct {
	skill *acutetriage.Skill
	store *store.Store
}

func (a acuteInvestigator) Investigate(ctx context.Context, incidentID string) (situation.AcuteResult, error) {
	inc, err := a.store.GetIncidentByID(ctx, incidentID)
	if err != nil {
		return situation.AcuteResult{}, err
	}
	result, err := a.skill.Investigate(ctx, *inc)
	if err != nil {
		return situation.AcuteResult{}, err
	}
	return situation.AcuteResult{
		IncidentID: result.IncidentID, OutputJSON: result.OutputJSON, Summary: result.Summary,
		RootCause: result.RootCause, Confidence: result.Confidence,
		EnrichmentJSON: result.EnrichmentJSON, CompletedAt: result.CompletedAt,
	}, nil
}

// profileReader adapts the semantic profile service to the controller's
// advisory ProfileReader boundary. Profiles only ever widen evidence
// consideration, so a resolution failure is never fatal.
type profileReader struct {
	service *semanticprofile.Service
}

func (p profileReader) ProfileHead(ctx context.Context, signature string) (situation.ProfileHead, bool, error) {
	if p.service == nil {
		return situation.ProfileHead{}, false, nil
	}
	history, err := p.service.Get(ctx, signature)
	if err != nil || history == nil {
		return situation.ProfileHead{}, false, err
	}
	for _, version := range history.Versions {
		if version.Version == history.CurrentVersion {
			return situation.ProfileHead{SignatureKey: history.SignatureKey, Version: version.Version, Profile: version.Profile}, true, nil
		}
	}
	return situation.ProfileHead{}, false, nil
}

// stdoutTransitionObserver emits the one versioned Situation JSON unit that
// replaces the legacy per-L1-finding line — for silent Situations too, since
// stdout presence never implies Slack publication.
type stdoutTransitionObserver struct {
	notifier *notifystdout.Notifier
}

func (o stdoutTransitionObserver) OnSituationTransition(ctx context.Context, sit model.Situation, tr model.Transition, incidentIDs []string, drill bool) {
	if o.notifier == nil {
		return
	}
	ev := notifystdout.SituationStateEvent{
		EventID: tr.ID, SituationID: sit.ID, Handle: sit.PublicHandle, GroupKey: sit.GroupKey,
		Lifecycle: tr.Lifecycle, Attention: tr.Attention, AssessmentSequence: tr.InputVersion,
		ActionContract: tr.ActionContract, IncidentIDs: incidentIDs, Drill: drill, OccurredAt: tr.CreatedAt.UTC(),
	}
	if tr.Assessment != nil {
		ev.SufficientReason = tr.Assessment.SufficientReason
		for _, limitation := range tr.Assessment.Limitations {
			ev.Limitations = append(ev.Limitations, limitation.Code)
		}
	}
	_ = o.notifier.EmitSituationState(ctx, ev)
}

// situationDeps carries the optional connectors and clients serve resolves
// before building the Situation runtime. Every field may be nil: each
// degrades independently rather than blocking the cutover.
type situationDeps struct {
	Skill       *acutetriage.Skill
	Assessor    situation.AssessmentClient
	ProfileLLM  semanticprofile.LLMClient
	Model       string
	Stdout      *notifystdout.Notifier
	SlackClient notifyslack.APIClient
}

// buildSituationRuntime assembles the whole Situation topology: the durable
// store adapter, the controller, the four durable workers, startup
// reconstruction, the confirmed MCP write surface, and the single Slack
// authority. It starts nothing — runServe owns lifecycle.
func buildSituationRuntime(cfg *config.Config, st *store.Store, auditor *audit.Auditor, cor *correlator.Correlator, deps situationDeps, logger *slog.Logger) (*serveRuntime, error) {
	if cfg == nil || st == nil {
		return nil, errors.New("alertint: situation runtime requires config and a store")
	}
	if logger == nil {
		logger = slog.Default()
	}
	clock := func() time.Time { return time.Now().UTC() }
	sc := cfg.Situations

	runtime := store.NewSituationRuntime(st, notifyslack.ClientMessageID, semanticprofile.Signature, clock,
		store.SituationRuntimePolicy{
			MinSeverity:           interruptionFloor(cfg.Notify.Slack.MinSeverity),
			RepageCooldownSeconds: sc.Slack.RepageCooldownSeconds,
			RecurrenceMode:        cfg.Notify.Slack.RecurrenceMode,
			HorizonTier:           situation.HorizonUnknown,
		})
	if deps.Stdout != nil {
		runtime.SetTransitionObserver(stdoutTransitionObserver{notifier: deps.Stdout})
	}

	profiles := semanticprofile.New(st, deps.ProfileLLM, semanticProfilePromptVersion, deps.Model, auditor)

	var acute situation.AcuteInvestigator
	if deps.Skill != nil {
		acute = acuteInvestigator{skill: deps.Skill, store: st}
	}
	// Every capability is registered read-only; adapters stay nil until a
	// connector reducer is wired, which classifies execution as unavailable
	// rather than hiding the capability.
	catalog := observation.DefaultCatalog(observation.Adapters{})
	observations := observation.NewRunner(catalog, sc.Budgets.MaxObservationCalls, sc.Budgets.ConnectorConcurrency)
	controller := situation.NewController(runtime, profileReader{service: profiles}, observations, acute, deps.Assessor, clock,
		situation.Config{
			MaxL2Calls:          sc.Budgets.MaxL2LLMCalls,
			MaxAttemptsPerInput: sc.Budgets.MaxAttemptsPerInput,
			FastCadence:         time.Duration(sc.Cadence.FastSeconds) * time.Second,
			NormalCadence:       time.Duration(sc.Cadence.NormalSeconds) * time.Second,
			SlowCadence:         time.Duration(sc.Cadence.SlowSeconds) * time.Second,
			AllowedCapabilities: capabilityNames(catalog),
			RecoveryGrace: situation.RecoveryGraceConfig{
				WebhookSeconds:    sc.RecoveryGrace.WebhookSeconds,
				PollingMinSeconds: sc.RecoveryGrace.PollingMinSeconds,
				PollingMaxSeconds: sc.RecoveryGrace.PollingMaxSeconds,
			}.RecoveryGrace(),
		})

	writeHealth := newStoreWriteHealth(cfg.Storage.SQLitePath, logger)
	base := situation.WorkerConfig{
		Lease:       time.Duration(sc.LeaseSeconds) * time.Second,
		Interval:    time.Duration(sc.ReconcileIntervalSeconds) * time.Second,
		Concurrency: sc.Workers,
		MaxAttempts: sc.Budgets.MaxAttemptsPerInput,
		Retry: situation.RetryPolicy{
			Initial:       time.Duration(sc.Retry.InitialSeconds) * time.Second,
			Maximum:       time.Duration(sc.Retry.MaximumSeconds) * time.Second,
			JitterPercent: sc.Retry.JitterPercent,
		},
		Ready:   writeHealth.Ready,
		OnRound: writeHealth.Observe,
	}
	instance := uuid.NewString()

	inputCfg := base
	inputCfg.Owner = "situation-inputs:" + instance
	inputs := situation.NewInputWorker(runtime, inputCfg, clock, logger)

	controllerCfg := base
	controllerCfg.Owner = "situation-controller:" + instance
	controllerCfg.IdleCadence = time.Duration(sc.Cadence.NormalSeconds) * time.Second
	pool := situation.NewWorkerPool(runtime, controller, controllerCfg, clock, logger)

	notifyCfg := base
	notifyCfg.Owner = "situation-notifications:" + instance
	var deliverer situation.NotificationDeliverer
	var authorities []string
	if deps.SlackClient != nil && cfg.Notify.Slack.Enabled && strings.TrimSpace(cfg.Notify.Slack.Channel) != "" {
		deliverer = newSituationDeliverer(runtime, deps.SlackClient, cfg.Notify.Slack.Channel, clock)
		authorities = append(authorities, slackAuthoritySituationNotifications)
	}
	notifications := situation.NewNotificationWorker(runtime, deliverer, notifyCfg, clock, logger)

	dispatch := correlator.NewDispatchWorker(st, cor, correlator.DispatchWorkerConfig{
		Owner:        "alert-dispatch:" + instance,
		Lease:        time.Duration(sc.LeaseSeconds) * time.Second,
		PollInterval: time.Duration(sc.ReconcileIntervalSeconds) * time.Second,
		BatchSize:    dispatchBatchSize,
		Retry: correlator.RetryPolicy{
			MaxAttempts:    sc.Budgets.MaxAttemptsPerInput,
			InitialBackoff: time.Duration(sc.Retry.InitialSeconds) * time.Second,
			MaxBackoff:     time.Duration(sc.Retry.MaximumSeconds) * time.Second,
		},
	}, logger)

	workers := &workerGroup{Dispatch: dispatch, Inputs: inputs, Controller: pool, Notifications: notifications}
	writeHealth.SetWake(workers.Wake)

	reconstructor := situation.NewReconstructor(runtime, clock).
		WithReplay(dispatchReplayer{worker: dispatch, store: st}, inputs)

	healthSink := situation.NewDependencyHealthSink(runtime,
		time.Duration(sc.DependencyHealth.BroadcastAfterSeconds)*time.Second)

	return &serveRuntime{
		store: st, reconstructor: reconstructor, workers: workers,
		writeHealth: writeHealth, correlator: cor, healthSink: healthSink,
		commands:           newSituationCommands(runtime, profiles, auditor, clock, workers.Wake),
		acuteNotifierWired: deps.Skill.NotifierWired(),
		incidentSink:       correlator.NopIncidentSink{},
		slackAuthorities:   authorities,
	}, nil
}

// dispatchBatchSize bounds one correlation claim round. It matches the
// Situation workers' own default batch so a burst drains at a comparable pace.
const dispatchBatchSize = 16

// semanticProfilePromptVersion identifies the L0 inference prompt shipped
// with this build; a change to the prompt must change this string.
const semanticProfilePromptVersion = "situation-l0-v1"

// dispatchReplayer adapts the correlation dispatch worker to the
// reconstruction replay boundary.
type dispatchReplayer struct {
	worker *correlator.DispatchWorker
	store  *store.Store
}

func (d dispatchReplayer) Drain(ctx context.Context) (int, error) {
	if d.worker == nil || d.store == nil {
		return 0, nil
	}
	applied := 0
	for round := 0; round < maxReplayRounds; round++ {
		pending, err := d.store.PendingAlertDispatches(ctx)
		if err != nil {
			return applied, err
		}
		if pending == 0 {
			return applied, nil
		}
		if err := d.worker.RunOnce(ctx); err != nil {
			return applied, err
		}
		remaining, err := d.store.PendingAlertDispatches(ctx)
		if err != nil {
			return applied, err
		}
		if remaining >= pending {
			// The round made no progress (every claim failed and was released
			// for a later retry). The ordinary worker owns it from here.
			return applied, nil
		}
		applied += pending - remaining
	}
	return applied, nil
}

// maxReplayRounds bounds startup replay so a pathological backlog cannot
// hold startup open indefinitely; the ordinary workers drain the remainder.
const maxReplayRounds = 64

// capabilityNames lists the read-only capabilities the controller may plan
// against, straight from the catalog so the allowlist cannot drift from it.
func capabilityNames(catalog *observation.Catalog) []string {
	capabilities := catalog.Capabilities()
	out := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		out = append(out, string(capability))
	}
	return out
}

// interruptionFloor maps the configured outward Slack severity floor onto the
// deterministic Interruption priority ladder. An unset or unknown value keeps
// the permissive floor rather than silently withholding pokes.
func interruptionFloor(minSeverity string) model.InterruptionPriority {
	switch strings.ToLower(strings.TrimSpace(minSeverity)) {
	case "critical":
		return model.PriorityCritical
	case "high":
		return model.PriorityHigh
	case "medium", "warning":
		return model.PriorityMedium
	default:
		return model.PriorityLow
	}
}

// buildSlackAPIClient constructs the narrow Situation Slack client when Slack
// is enabled and a bot token resolves. It is the only Slack client serve
// wires after the cutover.
func buildSlackAPIClient(cfg *config.Config, logger *slog.Logger) notifyslack.APIClient {
	if !cfg.Notify.Slack.Enabled {
		return nil
	}
	token, err := cfg.SlackBotToken()
	if err != nil || strings.TrimSpace(token) == "" {
		logger.Warn("slack is enabled but no bot token resolved; situation notifications stay durable and unsent")
		return nil
	}
	return notifyslack.NewHTTPAPIClient(token)
}

// buildSituationStdout constructs the stdout Situation sink when stdout
// notification is configured.
func buildSituationStdout(cfg *config.Config, auditor *audit.Auditor, debug bool) *notifystdout.Notifier {
	if !cfg.Notify.Stdout {
		return nil
	}
	return notifystdout.New(os.Stdout, auditor, debug)
}

// runReconstruction performs startup recovery and logs what it found.
func (r *serveRuntime) runReconstruction(ctx context.Context, logger *slog.Logger) error {
	report, err := r.reconstructor.Run(ctx)
	logger.Info("situation startup reconstruction",
		slog.Int64("recovered_alert_dispatch_leases", report.Leases.AlertDispatches),
		slog.Int64("recovered_situation_input_leases", report.Leases.SituationInputs),
		slog.Int64("recovered_situation_leases", report.Leases.Situations),
		slog.Int("replayed_deliveries", report.ReplayedDeliveries),
		slog.Int("replayed_inputs", report.ReplayedInputs),
		slog.Int("reconstructed_situations", report.Reconstructed),
		slog.Int("attached_incidents", report.AttachedIncidents),
	)
	return err
}

// describe renders the resolved Slack authority for the startup log, so an
// operator can see there is exactly one.
func (r *serveRuntime) describe() string {
	if len(r.slackAuthorities) == 0 {
		return "none (situation notifications stay durable and unsent)"
	}
	return strings.Join(r.slackAuthorities, ",")
}
