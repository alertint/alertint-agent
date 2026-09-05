// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// ----------------------------------------------------------------------
// Situation controller runtime (Task 9)
//
// controllerRuntime bundles the two background workers Task 8/7 built but
// nothing previously ran in production: the Situation controller worker
// (Reconcile) and the Acute Triage worker. It mirrors foundationRuntime's
// own shape (situation_foundation.go) — construction, a startup recovery
// pass, Start, Drain, Stop — composed alongside it, never folded into it:
// main.go owns exactly one foundationRuntime and one controllerRuntime, and
// wires them together via the extended foundationSequence/
// foundationStopSequence in situation_foundation.go.
// ----------------------------------------------------------------------

// situationsTriageStartupHorizon is the one-hour startup horizon (ADR-0045)
// — see internal/store/triage_controller.go's own
// ExhaustOverdueUnclaimedIncidentTriage doc comment for the full rationale.
// Kept here, not in internal/store, because it is a runtime policy constant
// (how stale is "too stale to dispatch at boot"), not a store-layer
// invariant — the store primitive takes it as a plain parameter.
const situationsTriageStartupHorizon = time.Hour

// controllerRuntime bundles the Situation controller worker and the Acute
// Triage worker, plus the startup-only recovery/backfill pass both depend
// on having already run. main constructs exactly one per process.
type controllerRuntime struct {
	worker *situation.ControllerWorker
	triage *situation.TriageWorker
	st     *store.Store
	// auditSink/logger back RecoverAndBackfill's own startup-horizon audit
	// emission (Task 9 fix round, Finding #2) — retained here (rather than
	// only passed into the worker/triage constructors above) because
	// RecoverAndBackfill runs BEFORE either worker starts, outside both of
	// their own audit-emitting call paths.
	auditSink situation.AuditSink
	logger    *slog.Logger
}

// newControllerRuntime wires the controller runtime against a real store, the
// configured one-shot provider-neutral L2 boundary (buildAssessmentClient;
// installation LLM health is wired separately, on the controller's own
// typed-outcome seam — see llmHealthAssessmentObserver), and the
// refactored Acute Triage skill (which structurally satisfies
// situation.AcuteAnalyzer, situation.AfterCommitter, and
// situation.ExhaustionNotifier all three — skills/acutetriage.Skill's own
// Analyze/AfterCommit/OnTriageExhausted methods, Task 7). owner must be the
// SAME non-empty, per-process identity foundationRuntime derives its own
// lease-owner suffixes from — the controller and Triage workers derive
// theirs ("<owner>:controller", "<owner>:triage") so no two workers from the
// same process, or from foundationRuntime's own dispatch/input workers, can
// ever fence each other's claims.
func newControllerRuntime(
	st *store.Store,
	assessClient situation.AssessmentClient,
	skill *acutetriage.Skill,
	cfg config.SituationsConfig,
	owner string,
	auditSink situation.AuditSink,
	logger *slog.Logger,
) *controllerRuntime {
	if strings.TrimSpace(owner) == "" {
		panic("cmd/alertint: controller runtime requires a non-empty owner")
	}
	controllerCfg, workerCfg := situationsConfigToControllerConfig(cfg, owner)

	worker := situation.NewControllerWorker(st, st, assessClient, controllerCfg, workerCfg, nil, auditSink, logger)

	triageStore := &triageAttemptStoreAdapter{Store: st}
	triageLister := &triageScheduleListerAdapter{Store: st}
	triageCfg := situation.TriageWorkerConfig{
		Owner:     owner + ":triage",
		Lease:     time.Duration(cfg.LeaseSeconds) * time.Second,
		Heartbeat: time.Duration(cfg.HeartbeatSeconds) * time.Second,
		Interval:  time.Duration(cfg.ReconcilePollSeconds) * time.Second,
	}
	triage := situation.NewTriageWorker(triageStore, triageLister, skill, skill, skill, triageCfg, logger)
	triage.SetAuditSink(auditSink)

	if logger == nil {
		logger = slog.Default()
	}
	return &controllerRuntime{worker: worker, triage: triage, st: st, auditSink: auditSink, logger: logger}
}

// buildControllerRuntime resolves the controller's own one-shot L2
// assessment client (buildAssessmentClient) and constructs the fully wired
// controller runtime — the construction runServe used to inline directly.
// Extracted out of runServe itself (Task 9 fix round, Finding #3: this,
// together with runControllerRecovery/runFoundationReconstruction below and
// in situation_foundation.go, keeps runServe's own golangci-lint gocyclo
// complexity under the repo's threshold). It also wires both installation
// LLM-health seams: the dependency-recovery waker and the L2 typed-outcome
// observer (llmHealthAssessmentObserver).
func buildControllerRuntime(
	st *store.Store,
	llmClient acutetriage.LLMClient,
	llmHealth *llmhealth.Tracker,
	skill *acutetriage.Skill,
	cfg config.SituationsConfig,
	owner string,
	auditSink situation.AuditSink,
	logger *slog.Logger,
) (*controllerRuntime, error) {
	assessClient, err := buildAssessmentClient(llmClient)
	if err != nil {
		return nil, fmt.Errorf("situation controller: %w", err)
	}
	crt := newControllerRuntime(st, assessClient, skill, cfg, owner, auditSink, logger)
	crt.SetDependencyRecoveryWaker(llmHealthDependencyWaker{tracker: llmHealth, st: st})
	crt.SetAssessmentHealthObserver(llmHealthAssessmentObserver{tracker: llmHealth})
	return crt, nil
}

// situationsConfigToControllerConfig maps config.SituationsConfig onto
// situation.ControllerConfig/situation.ControllerWorkerConfig exactly per
// Task 8's own documented mapping (Task 8 report): Workers -> Workers,
// ReconcilePollSeconds -> Interval, LeaseSeconds -> Lease, HeartbeatSeconds
// -> Heartbeat, WebhookRecoveryGraceSeconds -> ControllerConfig.
// WebhookRecoveryGrace, Cadence.{Fast,Normal,Slow}Seconds -> Cadence,
// MaxL2CallsPerAttempt/MaxWorkAttemptsPerInput pass straight through,
// AttemptWallSeconds -> AttemptWall, LLMConcurrency -> L2Concurrency,
// Retry.{Min,Max,JitterPercent}Seconds -> RetryConfig.
// PollingIntervalSeconds has no config.SituationsConfig source (no polling
// connector exists in this build) and is left at its zero-value default —
// see ControllerConfig's own doc comment.
func situationsConfigToControllerConfig(cfg config.SituationsConfig, owner string) (situation.ControllerConfig, situation.ControllerWorkerConfig) {
	controllerCfg := situation.ControllerConfig{
		Cadence: situation.CadenceTempo{
			Fast:   time.Duration(cfg.Cadence.FastSeconds) * time.Second,
			Normal: time.Duration(cfg.Cadence.NormalSeconds) * time.Second,
			Slow:   time.Duration(cfg.Cadence.SlowSeconds) * time.Second,
		},
		MaxL2CallsPerAttempt:    cfg.MaxL2CallsPerAttempt,
		MaxWorkAttemptsPerInput: cfg.MaxWorkAttemptsPerInput,
		AttemptWall:             time.Duration(cfg.AttemptWallSeconds) * time.Second,
		WebhookRecoveryGrace:    time.Duration(cfg.WebhookRecoveryGraceSeconds) * time.Second,
		Retry: situation.RetryConfig{
			Min:           time.Duration(cfg.Retry.MinSeconds) * time.Second,
			Max:           time.Duration(cfg.Retry.MaxSeconds) * time.Second,
			JitterPercent: cfg.Retry.JitterPercent,
		},
	}
	workerCfg := situation.ControllerWorkerConfig{
		Owner:         owner + ":controller",
		Lease:         time.Duration(cfg.LeaseSeconds) * time.Second,
		Heartbeat:     time.Duration(cfg.HeartbeatSeconds) * time.Second,
		Interval:      time.Duration(cfg.ReconcilePollSeconds) * time.Second,
		Workers:       cfg.Workers,
		L2Concurrency: cfg.LLMConcurrency,
	}
	return controllerCfg, workerCfg
}

// controllerRecovery is the startup-only recovery/backfill pass's report,
// for logReconstructionReport's own sibling logging call.
type controllerRecovery struct {
	TriageBackfilled              int
	AssessmentCallsRecovered      int
	TriageAttemptsRecovered       int
	TriageStartupHorizonExhausted int
}

// RecoverAndBackfill runs the startup-only, zero-outward-effect recovery
// pass this plan's own startup sequence requires between foundation
// reconstruction and starting any worker: Triage migration backfill
// (BackfillUpgradedIncidentTriageSchedule), interrupted Assessment-call
// recovery (RecoverInterruptedAssessmentCalls), interrupted Triage-attempt
// recovery (RecoverExpiredIncidentTriageAttempts — TriageWorker.RunOnce
// would also call this on its own first round, but starting a worker is
// asynchronous, so this explicit call guarantees it has already run before
// ANY worker's claim poll, matching RecoverInterruptedAssessmentCalls' own
// "never concurrently with live controller work" contract), and the
// one-hour startup horizon (ExhaustOverdueUnclaimedIncidentTriage — ADR-0045,
// continued over the controller-gated schedule; see that primitive's own doc
// comment in internal/store/triage_controller.go for why Task 9 owns
// closing this gap). Callers must not start the controller or Triage
// workers — or anything else that could concurrently claim controller/Triage
// work — if this returns a non-nil error.
func (r *controllerRuntime) RecoverAndBackfill(ctx context.Context, now time.Time) (controllerRecovery, error) {
	var report controllerRecovery

	backfilled, err := r.st.BackfillUpgradedIncidentTriageSchedule(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation controller: backfill upgraded incident triage schedule: %w", err)
	}
	report.TriageBackfilled = backfilled

	recoveredCalls, err := r.st.RecoverInterruptedAssessmentCalls(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation controller: recover interrupted assessment calls: %w", err)
	}
	report.AssessmentCallsRecovered = recoveredCalls

	recoveredAttempts, err := r.st.RecoverExpiredIncidentTriageAttempts(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation controller: recover expired incident triage attempts: %w", err)
	}
	report.TriageAttemptsRecovered = recoveredAttempts

	exhausted, err := r.st.ExhaustOverdueUnclaimedIncidentTriage(ctx, now, situationsTriageStartupHorizon)
	if err != nil {
		return report, fmt.Errorf("situation controller: exhaust overdue unclaimed incident triage: %w", err)
	}
	report.TriageStartupHorizonExhausted = len(exhausted)
	// OUTSIDE the store: every one of ExhaustOverdueUnclaimedIncidentTriage's
	// own per-row transactions has already committed by the time it returns
	// above — auditing here satisfies the Global Constraint ("No connector,
	// LLM, Slack, notifier, audit sink, or OTel exporter call occurs inside a
	// database transaction") by construction, not by care taken at each call
	// site.
	r.auditStartupHorizonExhaustions(ctx, exhausted)

	return report, nil
}

// auditStartupHorizonExhaustions emits one incident.triage_exhausted audit
// row per Incident ExhaustOverdueUnclaimedIncidentTriage closed out at boot
// — restoring the operator-visible signal the deleted pre-Plan-2
// applyStartupHorizon/exhaustTriage produced (internal/correlator/
// triage_retry.go, deleted by Task 7) and spec.md's own 13-event audit
// taxonomy names, which Task 9's new ExhaustOverdueUnclaimedIncidentTriage
// primitive had none of at all (Task 9 fix round, Finding #2).
//
// This is a direct audit append, never routed through TriageWorker's own
// ExhaustionNotifier hook (skills/acutetriage.Skill.OnTriageExhausted): that
// hook exists for a LIVE worker's genuine five-attempt exhaustion — no
// worker has claimed, let alone run, a single attempt against any of these
// rows at all — not a boot-time horizon sweep that never even created an
// attempt ledger row. The payload's own "reason"/code matches the deleted
// applyStartupHorizon's own convention exactly
// ("startup_retry_window_expired"), the same value
// ExhaustOverdueUnclaimedIncidentTriage already persists as last_error_code.
func (r *controllerRuntime) auditStartupHorizonExhaustions(ctx context.Context, exhausted []store.ExhaustedTriageIncident) {
	if r.auditSink == nil {
		return
	}
	for _, e := range exhausted {
		payload := map[string]any{
			"situation_id": e.SituationID, "incident_id": e.IncidentID, "group_key": e.GroupKey,
			"attempts": e.Attempts, "code": "startup_retry_window_expired",
			"reason": "startup_retry_window_expired",
		}
		if err := r.auditSink.Append(ctx, "situation.controller_runtime", "incident.triage_exhausted", payload); err != nil {
			r.logger.Warn("situation controller: startup horizon exhaustion audit append failed",
				"incident_id", e.IncidentID, "err", err)
		}
	}
}

// logControllerRecoveryReport logs one RecoverAndBackfill pass's report at
// startup — the Task 9 sibling of situation_foundation.go's own
// logReconstructionReport.
func logControllerRecoveryReport(logger *slog.Logger, report controllerRecovery) {
	logger.Info("situation controller recovered",
		slog.Int("triage_schedule_backfilled", report.TriageBackfilled),
		slog.Int("assessment_calls_recovered", report.AssessmentCallsRecovered),
		slog.Int("triage_attempts_recovered", report.TriageAttemptsRecovered),
		slog.Int("triage_startup_horizon_exhausted", report.TriageStartupHorizonExhausted),
	)
}

// runControllerRecovery runs one controllerRuntime.RecoverAndBackfill pass
// and logs its report — the backfillAndRecoverControllerWork step of
// runServe's own startupSeq. A named function, not a closure (Task 9 fix
// round, Finding #3): its own `if err != nil` branch would otherwise count
// toward runServe's own golangci-lint gocyclo complexity purely because of
// Go's lexical nesting rules for closures, despite having nothing to do with
// runServe's own control flow — mirrors logReconstructionReport's own
// established "factored out to keep runServe's branching count where it
// belongs" convention (situation_foundation.go), extended here to the
// branch that convention alone could not itself absorb.
func runControllerRecovery(ctx context.Context, crt *controllerRuntime, logger *slog.Logger) error {
	report, err := crt.RecoverAndBackfill(ctx, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("situation controller recovery: %w", err)
	}
	logControllerRecoveryReport(logger, report)
	return nil
}

// SetDependencyRecoveryWaker wires the pre-poll dependency-recovery wake
// step onto the controller worker (situation.ControllerWorker.
// SetDependencyRecoveryWaker's own doc comment) — a thin pass-through so
// main.go's own wiring reads as "configure the runtime", never "reach
// through it into its worker".
func (r *controllerRuntime) SetDependencyRecoveryWaker(waker situation.DependencyRecoveryWaker) {
	r.worker.SetDependencyRecoveryWaker(waker)
}

// SetAssessmentHealthObserver wires the L2 typed-outcome health observer
// onto the controller worker (situation.ControllerWorker.
// SetAssessmentHealthObserver) — the same thin pass-through shape as
// SetDependencyRecoveryWaker.
func (r *controllerRuntime) SetAssessmentHealthObserver(o situation.AssessmentHealthObserver) {
	r.worker.SetAssessmentHealthObserver(o)
}

// Start launches the controller worker, then the Triage worker, each on its
// own background schedule. Call only after RecoverAndBackfill has succeeded
// (and, transitively, after foundationRuntime.Reconstruct — the controller
// depends on coherently reconstructed deliveries/inputs).
func (r *controllerRuntime) Start(ctx context.Context) {
	r.worker.Start(ctx)
	r.triage.Start(ctx)
}

// Drain runs both workers' due work to quiescence (repeat until a round
// handles zero items, or ctx is done) and reports how many items they
// handled in total, for the shutdown sequence's own "drain due controller/
// Triage work and its resulting inputs to quiescence" loop
// (foundationStopSequence, situation_foundation.go) — called BEFORE Stop,
// while both background loops are still able to claim and process due
// work, and interleaved with foundationRuntime.Drain so whatever Situation
// inputs a Triage completion or a controller commit produces are applied
// in the next round rather than merely queued (any not yet consumed by the
// time shutdown proceeds simply wait, recoverable, for the next startup's
// reconstruction pass — spec.md's own "leave remaining durable work
// recoverable"). Bounded by ctx; a ctx deadline mid-drain is not itself an
// error worth surfacing to the caller; a genuine store error is.
func (r *controllerRuntime) Drain(ctx context.Context) (int, error) {
	handled := 0
	n, err := r.worker.Drain(ctx)
	handled += n
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return handled, fmt.Errorf("situation controller: drain controller worker: %w", err)
	}
	n, err = r.triage.Drain(ctx)
	handled += n
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return handled, fmt.Errorf("situation controller: drain triage worker: %w", err)
	}
	return handled, nil
}

// Stop stops the Triage worker, then the controller worker — the reverse of
// Start's own order, mirroring foundationRuntime.Stop's own
// stop-in-reverse-of-start discipline — each waiting for its current round
// to finish before the next Stop call proceeds. Call after Drain, and after
// foundationRuntime.Stop's own dispatch/input workers have stopped
// accepting new claims.
func (r *controllerRuntime) Stop(ctx context.Context) error {
	var errs []error
	if err := r.triage.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("triage worker stop: %w", err))
	}
	if err := r.worker.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("controller worker stop: %w", err))
	}
	return errors.Join(errs...)
}

// ----------------------------------------------------------------------
// triageAttemptStoreAdapter / triageScheduleListerAdapter — the thin
// store-shape adapters Task 7's own header comment names as Task 9's
// runtime-wiring job: converting store.ClaimedTriageAttempt/TriageFinding/
// TriageCompletionResult (and store's own sentinel errors) into this
// package's transport-neutral situation.TriageAttemptClaim/
// TriageFindingInput/TriageCompletionOutcome shapes, and projecting
// []store.IncidentTriage down to the bare []string of Incident IDs
// TriageScheduleLister needs. *store.Store already satisfies
// situation.TriageAttemptStore's other five methods directly (identical
// primitive-typed signatures — ExtendIncidentTriageLease,
// BackoffIncidentTriageAttempt, ExhaustIncidentTriageAttempt,
// CompleteIncidentTriageAttemptAsCleanSkip, RecoverExpiredIncidentTriageAttempts),
// promoted here via embedding; only Claim/Complete need a real shim.
// ----------------------------------------------------------------------

type triageAttemptStoreAdapter struct {
	*store.Store
}

func (a *triageAttemptStoreAdapter) ClaimIncidentTriageAttempt(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
	claimed, err := a.Store.ClaimIncidentTriageAttempt(ctx, incidentID, owner, now, lease)
	if err != nil {
		return situation.TriageAttemptClaim{}, mapTriageStoreError(err)
	}
	return situation.TriageAttemptClaim{
		AttemptID:            claimed.AttemptID,
		IncidentID:           claimed.IncidentID,
		AttemptNumber:        claimed.AttemptNumber,
		SituationID:          claimed.SituationID,
		DecisionInputVersion: claimed.DecisionInputVersion,
		MembershipDigest:     claimed.MembershipDigest,
		IncidentInputDigest:  claimed.IncidentInputDigest,
		MemberDeliveryIDs:    claimed.MemberDeliveryIDs,
		StartedAt:            claimed.StartedAt,
		LeaseOwner:           claimed.LeaseOwner,
		LeaseExpiresAt:       claimed.LeaseExpiresAt,
		ClaimToken:           claimed.ClaimToken,
	}, nil
}

func (a *triageAttemptStoreAdapter) CompleteIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
	result, err := a.Store.CompleteIncidentTriageAttempt(ctx, attemptID, incidentID, store.TriageFinding{
		OutputJSON: finding.OutputJSON, Summary: finding.Summary, RootCause: finding.RootCause,
		Confidence: finding.Confidence, EnrichmentJSON: finding.EnrichmentJSON, EvidencePackDigest: finding.EvidencePackDigest,
	}, now)
	if err != nil {
		return "", mapTriageStoreError(err)
	}
	return situation.TriageCompletionOutcome(result.Outcome), nil
}

// mapTriageStoreError maps internal/store's own Triage sentinel errors onto
// this package's situation-native mirrors (internal/situation/triage_worker.go's
// own doc comment: "mapping store's own ErrTriageNotDue/ErrTriageNotDecided/
// ErrTriageAttemptLeaseLost/ErrTriageAttemptCompletedDifferently onto this
// file's situation-native sentinels"). model.ErrNotFound is already a shared
// value (store.ErrNotFound is a value alias of it), so it needs no mapping
// here — it passes through unchanged.
func mapTriageStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrTriageNotDue):
		return situation.ErrTriageAttemptNotDue
	case errors.Is(err, store.ErrTriageNotDecided):
		return situation.ErrTriageAttemptNotDecided
	case errors.Is(err, store.ErrTriageAttemptLeaseLost):
		return situation.ErrTriageAttemptLeaseLost
	case errors.Is(err, store.ErrTriageAttemptCompletedDifferently):
		return situation.ErrTriageAttemptCompletedDifferently
	default:
		return err
	}
}

type triageScheduleListerAdapter struct {
	*store.Store
}

func (a *triageScheduleListerAdapter) ListDueIncidentTriage(ctx context.Context, now time.Time) ([]string, error) {
	due, err := a.Store.ListDueIncidentTriage(ctx, now)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(due))
	for _, d := range due {
		ids = append(ids, d.IncidentID)
	}
	return ids, nil
}

// ----------------------------------------------------------------------
// LLM health wiring: the L2 (Situation Assessment) typed-outcome observer
// and the dependency-recovery waker adapter. Both live here, in
// cmd/alertint, because internal/llmhealth cannot be imported from
// internal/situation (llmhealth imports internal/store, which already
// imports internal/situation — see situation.DependencyRecoveryWaker's own
// doc comment for the identical constraint).
// ----------------------------------------------------------------------

// llmHealthAssessmentObserver implements situation.AssessmentHealthObserver
// over the installation LLM-health tracker for the controller's own L2
// calls — the sibling wiring to Acute Triage's own L1 (CapabilityTriageDraft)
// observations, already wired inside skills/acutetriage via its
// Config.Health. It observes each dispatch's FINAL typed outcome, after the
// controller has validated and classified the proposal, with the Situation
// ID as the observation subject — so a malformed or policy-invalid
// proposal is a content-class failure (corroborated across two distinct
// Situations before the capability turns unhealthy, exactly like Acute
// Triage's own malformed-response rule), a transport failure is a
// dependency-class failure, and a stale-basis outcome (a real call that
// succeeded but was correctly discarded because a newer input landed
// mid-cycle — Task 9's "treat a late/stale completion race as stale, not
// provider failure") is a success. An earlier wiring decorated CompleteOnce
// instead and so reported every parseable-but-invalid response as healthy
// and every observation under one empty subject, which made the two-
// Situation corroboration rule unsatisfiable.
type llmHealthAssessmentObserver struct {
	tracker *llmhealth.Tracker
}

func (o llmHealthAssessmentObserver) BeginAssessmentCall(situationID string) situation.AssessmentCallObservation {
	return llmHealthAssessmentObservation{obs: o.tracker.Begin(llmhealth.CapabilityAssessment, situationID)}
}

type llmHealthAssessmentObservation struct {
	obs *llmhealth.Observation
}

func (o llmHealthAssessmentObservation) Finish(outcome situation.L2Outcome, transportErr error) {
	o.obs.Finish(assessmentHealthError(outcome, transportErr))
}

// assessmentHealthError maps one final L2 outcome onto the error shape
// llmhealth.Classify reads: nil for a healthy call (accepted, contradicted,
// or a correctly discarded stale completion), the real transport error for
// a dependency-class failure, and a reason-bearing content-class error for
// a malformed (ErrResponseMalformed) or contract-violating
// (llm.ErrSchemaViolation) proposal.
func assessmentHealthError(outcome situation.L2Outcome, transportErr error) error {
	switch outcome {
	case situation.L2OutcomeAccepted, situation.L2OutcomeContradicted, situation.L2OutcomeStaleBasis:
		return nil
	case situation.L2OutcomeTransportFailure, situation.L2OutcomeRateLimited:
		if transportErr != nil {
			return transportErr
		}
		return errors.New("assessment: transport-class outcome without a typed transport error")
	case situation.L2OutcomeMalformed:
		return fmt.Errorf("%w: assessment proposal did not parse as the required semantic proposal shape", llmhealth.ErrResponseMalformed)
	case situation.L2OutcomePolicyRejected, situation.L2OutcomeCapabilityRejected:
		return fmt.Errorf("%w: assessment proposal %s", llm.ErrSchemaViolation, outcome)
	default:
		return fmt.Errorf("%w: unrecognized assessment outcome %q", llm.ErrSchemaViolation, outcome)
	}
}

// buildAssessmentClient resolves the controller's own one-shot,
// provider-neutral L2 boundary from the SAME configured LLM client Acute
// Triage uses (buildLLMClient) — both llm/anthropic.Client and
// llm/openaicompat.Client already implement CompleteOnce alongside the
// hidden-retry Complete method acutetriage.LLMClient itself declares
// (mirrors buildLLMProber's own type-assertion pattern for llm.Prober). A
// client that does not implement it is a genuine wiring/config error: unlike
// the idle probe (optional, WARN-and-disable), L2 dispatch is not optional
// for a running controller, so this fails loud rather than degrading
// silently. Installation LLM health is NOT layered here — it observes the
// controller's typed outcome, not the transport (llmHealthAssessmentObserver).
func buildAssessmentClient(client acutetriage.LLMClient) (situation.AssessmentClient, error) {
	oneShot, ok := client.(situation.AssessmentClient)
	if !ok {
		return nil, fmt.Errorf("cmd/alertint: configured LLM client %T does not implement CompleteOnce; the Situation controller cannot dispatch L2 work", client)
	}
	return oneShot, nil
}

// llmHealthDependencyWaker implements situation.DependencyRecoveryWaker by
// combining internal/llmhealth.Tracker.Snapshot().OutageGeneration (once
// healthy) with store.WakeDependencyRecoveredSituations — exactly the seam
// situation.DependencyRecoveryWaker's own doc comment names as Task 9's
// runtime-wiring job. Calling WakeDependencyRecoveredSituations while NOT
// healthy would be premature (spec.md: a recovery generation only opens a
// new retry epoch once the dependency is actually healthy again), so this
// no-ops (0, nil) whenever the tracker does not currently report healthy —
// the store primitive's own outageGeneration<=0 guard is a second,
// independent line of defense, not relied on alone.
type llmHealthDependencyWaker struct {
	tracker *llmhealth.Tracker
	st      *store.Store
}

func (w llmHealthDependencyWaker) WakeDependencyRecoveredSituations(ctx context.Context, now time.Time) (int, error) {
	snap := w.tracker.Snapshot()
	if snap.State != llmhealth.StateHealthy {
		return 0, nil
	}
	return w.st.WakeDependencyRecoveredSituations(ctx, snap.OutageGeneration, now)
}
