// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/logs/loki"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/observation/connectors"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// ----------------------------------------------------------------------
// Plan 4 Task 9: bounded evidence preparation runtime.
//
// productionPreparer is the concrete situation.EvidencePreparer adapter:
// the ONLY place in this process that maps a situation.Claim/SnapshotInput
// onto the narrow observation.Fence Task 2's store methods require
// (spec.md: "Map situation.Claim to the narrow observation Fence only in
// this adapter"). It never trusts its own Prepare() return value as
// evidence — see internal/situation/preparation.go's own doc comment — and
// never blocks a Situation's own lifecycle on a connector failure: only a
// durable STORE failure (BeginPreparation, RunPhase's own commit, refresh
// admission) is returned as a hard error; a per-plan connector failure is
// already durable evidence limitation by construction (Runner.RunPhase's
// own contract).
// ----------------------------------------------------------------------

// productionPreparer implements situation.EvidencePreparer over the real
// store, the real observation.Runner (wired with every configured
// capability's real executor), and the real planner.
type productionPreparer struct {
	st           *store.Store
	runner       *observation.Runner
	capabilities []observation.CapabilityDescriptor
	configDigest string
	prepCfg      config.SituationPreparationConfig
	logger       *slog.Logger
	// auditor is optional — nil disables audit emission, matching
	// internal/situation.Controller's own auditSink convention (there it is
	// an abstract interface guarded by a nil check; here it is the concrete
	// *audit.Auditor cmd/alertint already always constructs, so a nil value
	// only ever occurs in a test that deliberately omits it).
	auditor *audit.Auditor
}

// Prepare runs one bounded phase: coherently derive this Situation's
// expected member subjects, load current profile guidance and the
// per-subject/capability refresh cursor, build this phase's canonical plan
// set, freeze it into a durable cycle (retry-safe — BeginPreparation
// returns the SAME frozen draft on a later attempt for the same input),
// execute it, and record the fresh reads' cadence admission. Returns the
// zero PreparedState on every non-error path — its caller (Controller.
// reconcile) discards it and reloads durable truth instead (preparation.go
// EvidencePreparer's own doc comment), so there is nothing this receipt
// needs to carry.
//
// The preparation wall (situations.preparation.max_wall_seconds) is shared
// by BOTH phases of one Reconcile cycle (spec.md: "The preparation wall
// includes all lifecycle and assessment reads in that attempt"), never
// reset per phase: it is computed from req.Now, the SAME wall-clock anchor
// Task 6's own reconcile() captures once and passes to both its lifecycle-
// and assessment-phase Prepare calls, so a phase that already consumed part
// of the shared budget correctly leaves less of it for the other.
func (p *productionPreparer) Prepare(ctx context.Context, req situation.PreparationRequest) (situation.PreparedState, error) {
	deadline := req.Now.Add(time.Duration(p.prepCfg.MaxWallSeconds) * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	sit := req.Claim.Situation
	fence := model.Fence{SituationID: sit.ID, InputVersion: sit.InputVersion, Owner: req.Claim.ClaimOwner, Token: req.Claim.ClaimToken}

	members := membersFromDeliveries(req.Input)
	if len(members) == 0 {
		return situation.PreparedState{}, nil
	}

	deliveryIDs := make([]string, 0, len(req.Input.Deliveries))
	for _, d := range req.Input.Deliveries {
		deliveryIDs = append(deliveryIDs, d.ID)
	}
	guidance, versionIDs, err := p.st.LoadProfileGuidanceForDeliveries(ctx, deliveryIDs)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load profile guidance: %w", err)
	}

	rawCursors, err := p.st.LoadObservationRefreshCursors(ctx, sit.ID)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load observation refresh cursors: %w", err)
	}
	cursors := make([]observation.RefreshCursor, 0, len(rawCursors))
	for _, c := range rawCursors {
		cursors = append(cursors, observation.RefreshCursor{
			Subject: c.Subject, Capability: model.Capability(c.Capability),
			ScopeDigest: c.ScopeDigest, NextRefreshAt: c.NextRefreshAt,
		})
	}

	refreshInterval := time.Duration(p.prepCfg.RefreshSeconds) * time.Second
	credit, err := p.st.AccrueInvestigationCredit(ctx, sit.ID, req.Now, refreshInterval, p.prepCfg.MaxSourceCallsPerCycle)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: accrue investigation credit: %w", err)
	}

	plans, alloc, err := observation.BuildPlans(observation.PlannerInput{
		Anchor: req.Now, GroupKey: sit.GroupKey, Phase: req.Phase,
		Members: members, Configured: p.capabilities, ProfileGuidance: guidance,
		RefreshCursors: cursors, CycleCap: p.prepCfg.MaxSourceCallsPerCycle,
		InvestigationCredit: credit, RecoveryPending: sit.Lifecycle == situationmodel.LifecycleRecoveryPending,
	})
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: build observation plans: %w", err)
	}
	if len(plans) == 0 {
		return situation.PreparedState{}, nil
	}

	cycle, err := p.st.BeginPreparation(ctx, fence, model.CycleDraft{
		Anchor: req.Now, ConfigDigest: p.configDigest,
		ProfileVersionIDs: versionIDs, ProfileGuidance: guidance,
		Plans: plans, Allocation: alloc.PhaseAllocation,
	}, p.prepCfg.MaxSourceCallsPerCycle)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: begin preparation: %w", err)
	}
	// Audited immediately after the frozen cycle durably commits —
	// BeginPreparation returns the SAME cycle on a later retry for the same
	// input, so this fires again (harmlessly) on a retried attempt, exactly
	// like the reservation/outcome events it sits beside.
	p.auditAppend(ctx, "situation.preparation.cycle_begun", map[string]any{
		"situation_id": sit.ID, "cycle_id": cycle.ID, "generation": cycle.Generation,
		"phase": string(req.Phase), "plan_count": len(plans),
	})

	if err := p.runner.RunPhase(ctx, fence, cycle, req.Phase); err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: run preparation phase: %w", err)
	}

	phasePlans := make([]model.Plan, 0, len(cycle.Draft.Plans))
	for _, plan := range cycle.Draft.Plans {
		if plan.Phase == req.Phase {
			phasePlans = append(phasePlans, plan)
		}
	}
	if err := p.st.RecordObservationRefreshAdmissions(ctx, sit.ID, cycle.ID, phasePlans, refreshInterval, req.Now); err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: record observation refresh admissions: %w", err)
	}

	return situation.PreparedState{CycleID: cycle.ID, Generation: cycle.Generation}, nil
}

// auditAppend is a best-effort audit emission: a failure is logged and
// swallowed, matching internal/situation.Controller.auditAppend and
// semanticprofile.Worker.auditAppend exactly — an audit-log failure must
// never lose the durable state change it describes. A nil auditor (every
// test fixture that omits one) disables emission rather than panicking.
func (p *productionPreparer) auditAppend(ctx context.Context, kind string, payload any) {
	if p.auditor == nil {
		return
	}
	if err := p.auditor.Append(ctx, preparationAuditActor, kind, payload); err != nil {
		p.logger.Warn("cmd/alertint: preparation audit append failed", "kind", kind, "err", err)
	}
}

// preparationAuditActor is the fixed audit actor for every event
// productionPreparer emits.
const preparationAuditActor = "situation.preparer"

// membersFromDeliveries reduces req's deliveries to one MemberSubject per
// distinct Alert (Delivery.AlertID, chronologically-latest delivery wins —
// the same identity/ordering internal/situation's own incidentSymptomStatus
// uses), Firing from that latest delivery's own Status, and
// ObservationDeadlineAt/RecoveryGraceUntil derived from the Situation's own
// current lifecycle timing (situation.BuildSnapshot/ObservationDeadlineAt,
// both exported pure functions) — applied uniformly to every member, since
// this build has no per-Alert observation-deadline concept distinct from
// the Situation's own (Task 6's own resolveLifecycle works the same way
// for its local-only fallback path).
func membersFromDeliveries(in situation.SnapshotInput) []observation.MemberSubject {
	latest := make(map[string]situation.Delivery, len(in.Deliveries))
	for _, d := range in.Deliveries {
		key := d.AlertID
		if key == "" {
			key = "delivery:" + d.ID
		}
		cur, ok := latest[key]
		if !ok || d.ReceivedAt.After(cur.ReceivedAt) {
			latest[key] = d
		}
	}
	if len(latest) == 0 {
		return nil
	}

	snap := situation.BuildSnapshot(in)
	deadline := situation.ObservationDeadlineAt(in.Situation.EffectiveStartedAt, snap.DurationClass)

	keys := make([]string, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	members := make([]observation.MemberSubject, 0, len(keys))
	for _, k := range keys {
		d := latest[k]
		members = append(members, observation.MemberSubject{
			SubjectID: k, Source: d.Source, Labels: d.Labels,
			ObservationDeadlineAt: deadline, RecoveryGraceUntil: in.Situation.GraceUntil,
			Firing: d.Status == situationmodel.DeliveryStatusFiring,
		})
	}
	return members
}

// capabilityDescriptorsFromConfig resolves the currently ENABLED capability
// set, each with a reasonable, versioned-cap-respecting default window/
// limit/request hint — the enablement boundary BuildPlans' own doc comment
// requires ("a capability absent from Configured is never planned
// regardless of what a profile suggests"). store_read is always enabled:
// it is a local SQLite read, never gated behind any external connector
// configuration.
func capabilityDescriptorsFromConfig(cfg *config.Config) []observation.CapabilityDescriptor {
	descs := []observation.CapabilityDescriptor{
		{Capability: model.CapabilityStoreRead, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 0},
	}
	if cfg.PrometheusEnabled() {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: 1000, MaxRequestsHint: 1,
		})
	}
	if cfg.LogsEnabled() {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityLokiQuery, DefaultWindow: time.Hour, DefaultLimit: 200, MaxRequestsHint: 2,
		})
	}
	if cfg.Sentry.Issues.Enabled {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilitySentryIssues, DefaultWindow: 24 * time.Hour, DefaultLimit: 10, MaxRequestsHint: 2,
		})
	}
	if cfg.ChangesEnrichmentEnabled() {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityChangeEvents, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 0,
		})
	}
	if cfg.ZabbixAPIEnabled() {
		descs = append(descs,
			observation.CapabilityDescriptor{Capability: model.CapabilityZabbixMetricRange, DefaultWindow: time.Hour, DefaultLimit: 100, MaxRequestsHint: 1},
			observation.CapabilityDescriptor{Capability: model.CapabilityZabbixProblemHist, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 2},
		)
	}
	return descs
}

// preparationConfigDigest hashes the resolved capability set plus the
// preparation cadence knobs — spec.md: the persisted cycle freezes "its own
// ... configuration digest," so a later config change is at least
// detectable (never itself invalidating an already-frozen cycle: "Retry
// uses those exact values even if ... the configuration ... have
// changed").
func preparationConfigDigest(descs []observation.CapabilityDescriptor, prepCfg config.SituationPreparationConfig) string {
	b, err := json.Marshal(struct { //nolint:musttag // hash input only, never persisted/exchanged — encoding/json's default field-name marshaling is fine for a stable digest
		Descs []observation.CapabilityDescriptor
		Cfg   config.SituationPreparationConfig
	}{descs, prepCfg})
	if err != nil {
		// descs/prepCfg are always plain, marshalable values — unreachable
		// outside a programming-time invariant violation.
		panic(fmt.Sprintf("cmd/alertint: marshal preparation config digest: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// executorsFromClients registers one observation.Executor per currently
// ENABLED capability — a nil client for a capability means it was never
// configured, and Runner.RunPhase's own contract (no registered executor)
// already handles that honestly (vocabulary_unresolved), so this simply
// omits the entry rather than registering a nil-backed one. Every executor
// struct's own Client field is satisfied structurally by the real
// production client type directly (each connector file's own doc comment
// names this: "*prometheus.Client structurally satisfies it", etc.) — no
// adapter shim needed anywhere in this function.
func executorsFromClients(st *store.Store, prom *promclient.Client, lokiClient *loki.Client, sentryClient *sentry.Client, zbxClient *zabbix.Client, now func() time.Time) map[model.Capability]observation.Executor {
	execs := map[model.Capability]observation.Executor{
		model.CapabilityStoreRead:    &connectors.StoreReadExecutor{Store: st, Clock: now},
		model.CapabilityChangeEvents: &connectors.ChangesExecutor{Store: st, Clock: now},
	}
	if prom != nil {
		execs[model.CapabilityPrometheusQuery] = &connectors.PrometheusExecutor{Client: prom, Clock: now}
	}
	if lokiClient != nil {
		execs[model.CapabilityLokiQuery] = &connectors.LokiExecutor{Client: lokiClient, Clock: now}
	}
	if sentryClient != nil {
		execs[model.CapabilitySentryIssues] = &connectors.SentryExecutor{
			Client: sentryClient, ProjectEnv: sentryProjectEnvFromScope, IncludeMessage: false, Clock: now,
		}
	}
	if zbxClient != nil {
		execs[model.CapabilityZabbixMetricRange] = &connectors.ZabbixMetricExecutor{Client: zbxClient, Clock: now}
		execs[model.CapabilityZabbixProblemHist] = &connectors.ZabbixProblemExecutor{Client: zbxClient, Clock: now}
	}
	return execs
}

// sentryProjectEnvFromScope derives (project, env) from a plan's own Scope
// labels — the exact label-key convention skills/acutetriage/sentry.go's
// own unexported sentryScope already established for Acute Triage's Error
// source ("service"|"project"|"app"|"job" for project,
// "environment"|"env" for env), duplicated here as a small, standalone
// lookup (not exported by that package, and this package must not import
// skills/acutetriage for one four-line function) since Scope already
// carries one member's own labels directly — no "shared across multiple
// alerts" reduction is needed the way Acute Triage's own sharedLabels does.
func sentryProjectEnvFromScope(scope model.Scope) (project, env string, ok bool) {
	for _, k := range []string{"service", "project", "app", "job"} {
		if v := scope.Labels[k]; v != "" {
			project = v
			break
		}
	}
	for _, k := range []string{"environment", "env"} {
		if v := scope.Labels[k]; v != "" {
			env = v
			break
		}
	}
	return project, env, project != ""
}

// buildPreparationRuntime resolves the semantic-profile worker's own
// one-shot L0 boundary (the SAME configured provider client Acute Triage/
// Assessment use — llm.anthropic.Client/llm.openaicompat.Client already
// implement semanticprofile.CompletionClient's identical CompleteOnce
// shape, exactly like buildAssessmentClient's own type assertion) and the
// concrete *loki.Client FetchRecentBounded needs (recovered from logSrc's
// own logs.Source interface value — nil when logs are disabled, or
// configured with a future non-Loki provider), constructs the ONE shared
// llm.InferenceLimiter L2 dispatch and every profile worker acquire from
// (never a second, independently-bounded pool), builds the full
// preparation runtime, and wires the resulting EvidencePreparer/limiter
// into crt — the construction runServe used to inline directly.
//
// Both of newPreparationRuntime's own error cases (llmClient not
// implementing CompleteOnce, an empty owner) are unreachable by the time
// runServe calls this: llmClient already passed buildAssessmentClient's
// IDENTICAL structural check inside the already-succeeded
// buildControllerRuntime call this always follows, and owner is the same
// non-empty identity newControllerRuntime's own panic guard already
// validated. Panicking on them here (rather than threading a THIRD
// "impossible in production" error return through runServe) keeps
// runServe's own golangci-lint gocyclo complexity under the repo's
// threshold — Task 9 fix round, Finding #3's own established convention,
// applied to a call-site invariant instead of a closure.
func buildPreparationRuntime(
	st *store.Store, cfg *config.Config, owner string, llmClient acutetriage.LLMClient, llmHealth *llmhealth.Tracker,
	prom *promclient.Client, logSrc logs.Source, sentryClient *sentry.Client, zbxClient *zabbix.Client,
	crt *controllerRuntime, auditor *audit.Auditor, logger *slog.Logger,
) *preparationRuntime {
	profileClient, ok := llmClient.(semanticprofile.CompletionClient)
	if !ok {
		panic(fmt.Sprintf("cmd/alertint: configured LLM client %T does not implement CompleteOnce; the semantic profile worker cannot dispatch L0 work", llmClient))
	}
	lokiClient, _ := logSrc.(*loki.Client)
	limiter := llm.NewInferenceLimiter(cfg.Situations.LLMConcurrency)

	prt, preparer, err := newPreparationRuntime(st, cfg, owner, prom, lokiClient, sentryClient, zbxClient,
		profileClient, limiter, llmHealthProfileObserver{tracker: llmHealth}, auditor, logger)
	if err != nil {
		panic(fmt.Sprintf("cmd/alertint: build preparation runtime: %v", err))
	}
	crt.SetEvidencePreparer(preparer)
	crt.SetInferenceLimiter(limiter)
	return prt
}

// newPreparationRuntime wires the full Plan 4 Task 9 preparation runtime:
// the concrete EvidencePreparer adapter (returned separately so the caller
// can inject it into every controller — situation.ControllerWorker.
// SetEvidencePreparer — since profile inference never imports internal/
// situation and cannot do that wiring itself), the semantic-profile
// inference workers (cfg.SemanticProfiles.Workers of them, sharing ONE
// llm.InferenceLimiter with the Situation controller's own L2 dispatch),
// and the three bounded sweeps (profile-change fan-out, active-mapping
// backfill, ten-day detail cleanup). owner must be the SAME non-empty,
// per-process identity foundationRuntime/controllerRuntime derive their own
// lease-owner suffixes from.
func newPreparationRuntime(
	st *store.Store, cfg *config.Config, owner string,
	prom *promclient.Client, lokiClient *loki.Client, sentryClient *sentry.Client, zbxClient *zabbix.Client,
	profileClient semanticprofile.CompletionClient, limiter *llm.InferenceLimiter,
	health semanticprofile.HealthObserver, auditor *audit.Auditor, logger *slog.Logger,
) (*preparationRuntime, situation.EvidencePreparer, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, nil, fmt.Errorf("cmd/alertint: preparation runtime requires a non-empty owner")
	}
	if logger == nil {
		logger = slog.Default()
	}
	now := func() time.Time { return time.Now().UTC() }

	prepCfg := cfg.Situations.Preparation
	descs := capabilityDescriptorsFromConfig(cfg)
	execs := executorsFromClients(st, prom, lokiClient, sentryClient, zbxClient, now)
	runner := observation.NewRunner(st, execs, now)
	preparer := &productionPreparer{
		st: st, runner: runner, capabilities: descs,
		configDigest: preparationConfigDigest(descs, prepCfg), prepCfg: prepCfg, logger: logger, auditor: auditor,
	}

	profileCfg := cfg.Situations.SemanticProfiles
	workerCount := profileCfg.Workers
	if workerCount <= 0 {
		workerCount = 1
	}
	workers := make([]*semanticprofile.Worker, 0, workerCount)
	for i := 0; i < workerCount; i++ {
		w := semanticprofile.NewWorker(st, profileClient, limiter, semanticprofile.WorkerConfig{
			Owner:       fmt.Sprintf("%s:profile:%d", owner, i),
			Lease:       time.Duration(cfg.Situations.LeaseSeconds) * time.Second,
			Heartbeat:   time.Duration(cfg.Situations.HeartbeatSeconds) * time.Second,
			Interval:    time.Duration(cfg.Situations.ReconcilePollSeconds) * time.Second,
			AttemptWall: time.Duration(profileCfg.AttemptWallSeconds) * time.Second,
			Provider:    llmProviderName(cfg),
		}, nil, logger)
		w.SetHealthObserver(health)
		w.SetAuditSink(auditor)
		workers = append(workers, w)
	}

	sweepInterval := time.Duration(prepCfg.RefreshSeconds) * time.Second
	if sweepInterval <= 0 {
		sweepInterval = 5 * time.Minute
	}
	sweeps := []*preparationSweep{
		newPreparationSweep("semantic_profile_fanout", 10*time.Second, func(ctx context.Context, now time.Time) (int, error) {
			n, err := st.DeliverSemanticProfileChanges(ctx, now, 100)
			if err == nil && n > 0 && auditor != nil {
				_ = auditor.Append(ctx, preparationAuditActor, "semantic_profile.change_delivered", map[string]any{"delivered_count": n})
			}
			return n, err
		}, now, logger),
		newPreparationSweep("semantic_profile_backfill", sweepInterval, func(ctx context.Context, now time.Time) (int, error) {
			return st.BackfillActiveSemanticMappings(ctx, now, 100)
		}, now, logger),
		newPreparationSweep("observation_detail_cleanup", time.Hour, func(ctx context.Context, now time.Time) (int, error) {
			return st.PruneUnusedObservationDetails(ctx, now, 100)
		}, now, logger),
	}

	rt := &preparationRuntime{st: st, workers: workers, sweeps: sweeps, logger: logger}
	return rt, preparer, nil
}

// llmProviderName names the shared primary provider for durably recorded
// semantic_profile_versions/call_outcomes rows — resolved the same way
// buildAssessmentClient's own doc comment describes the L2 boundary: the
// SAME configured provider Acute Triage/Assessment use, never a second
// independently-configured one.
func llmProviderName(cfg *config.Config) string {
	return strings.ToLower(strings.TrimSpace(cfg.LLM.Provider))
}

// ----------------------------------------------------------------------
// preparationRuntime: bundles the preparer's dependent Runner/executors,
// the semantic-profile inference workers, and the bounded sweep loops
// (profile-change fan-out, active-mapping backfill, ten-day detail
// cleanup) — mirroring controllerRuntime's own construction/Recover/Start/
// Drain/Stop shape.
// ----------------------------------------------------------------------

type preparationRuntime struct {
	st      *store.Store
	workers []*semanticprofile.Worker
	sweeps  []*preparationSweep
	logger  *slog.Logger
}

// Recover runs the startup-only recovery pass: release stranded semantic-
// inference job leases (RecoverSemanticInference — a worker process that
// died mid-attempt), and backfill any missed delivery-to-signature
// attachment for active/recovery_pending followers (BackfillActiveSemanticMappings
// — an interrupted ApplySituationInput crash, or a pre-Task-7 upgrade).
// Both are zero-outward-effect, safe to call repeatedly, and must run
// before any profile worker starts claiming jobs.
func (r *preparationRuntime) Recover(ctx context.Context) error {
	now := time.Now().UTC()
	recovered, err := r.st.RecoverSemanticInference(ctx, now)
	if err != nil {
		return fmt.Errorf("cmd/alertint: recover semantic inference: %w", err)
	}
	backfilled, err := r.st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		return fmt.Errorf("cmd/alertint: backfill active semantic mappings: %w", err)
	}
	r.logger.Info("semantic profile preparation recovered",
		slog.Int("inference_jobs_recovered", recovered),
		slog.Int("active_mappings_backfilled", backfilled),
	)
	return nil
}

// Start launches every semantic-profile worker, then every bounded sweep,
// each on its own background schedule.
func (r *preparationRuntime) Start(ctx context.Context) {
	for _, w := range r.workers {
		w.Start(ctx)
	}
	for _, s := range r.sweeps {
		s.Start(ctx)
	}
}

// Drain runs every worker's and every sweep's due work to quiescence,
// mirroring controllerRuntime.Drain's own "repeat until zero, ctx bounds
// it, only a genuine error propagates" contract.
func (r *preparationRuntime) Drain(ctx context.Context) (int, error) {
	handled := 0
	for _, w := range r.workers {
		n, err := w.Drain(ctx)
		handled += n
		if err != nil && !isShutdownErr(err) {
			return handled, fmt.Errorf("cmd/alertint: drain semantic profile worker: %w", err)
		}
	}
	for _, s := range r.sweeps {
		n, err := s.Drain(ctx)
		handled += n
		if err != nil && !isShutdownErr(err) {
			return handled, fmt.Errorf("cmd/alertint: drain preparation sweep %s: %w", s.name, err)
		}
	}
	return handled, nil
}

// Stop stops every sweep, then every semantic-profile worker (the reverse
// of Start's own order), each waiting for its current round to finish.
func (r *preparationRuntime) Stop(ctx context.Context) error {
	var errs []error
	for _, s := range r.sweeps {
		if err := s.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("preparation sweep %s stop: %w", s.name, err))
		}
	}
	for _, w := range r.workers {
		if err := w.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("semantic profile worker stop: %w", err))
		}
	}
	return joinErrors(errs)
}

func isShutdownErr(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded //nolint:errorlint // both workers/sweeps return these sentinels bare, never wrapped
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// preparationSweep runs a bounded, idempotent store primitive (profile-
// change fan-out, active-mapping backfill, ten-day detail cleanup) on its
// own schedule — the generic shape every one of Task 9's "bounded sweeps"
// shares, factored out once rather than duplicated three times.
type preparationSweep struct {
	name     string
	interval time.Duration
	run      func(ctx context.Context, now time.Time) (int, error)
	now      func() time.Time
	logger   *slog.Logger

	wakeCh    chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	startOnce sync.Once
}

func newPreparationSweep(name string, interval time.Duration, run func(ctx context.Context, now time.Time) (int, error), now func() time.Time, logger *slog.Logger) *preparationSweep {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &preparationSweep{
		name: name, interval: interval, run: run, now: now, logger: logger,
		wakeCh: make(chan struct{}, 1), stopCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
}

// RunOnce runs the sweep's own primitive exactly once, returning how many
// rows it handled.
func (s *preparationSweep) RunOnce(ctx context.Context) (int, error) {
	return s.run(ctx, s.now())
}

// Drain runs RunOnce repeatedly until a round handles zero rows or ctx is
// done — the same "repeat to quiescence" contract every worker's own Drain
// uses.
func (s *preparationSweep) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := s.RunOnce(ctx)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

func (s *preparationSweep) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		go s.run_(ctx)
	})
}

func (s *preparationSweep) run_(ctx context.Context) {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if _, err := s.Drain(ctx); err != nil && !isShutdownErr(err) {
			s.logger.Error("preparation sweep failed", "sweep", s.name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
		case <-s.wakeCh:
		}
	}
}

func (s *preparationSweep) Stop(ctx context.Context) error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	select {
	case <-s.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
