// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/alertint/alertint-agent/internal/llm"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// ----------------------------------------------------------------------
// Plan 4 Task 8: Worker — claims one durable semantic-profile inference job
// at a time, dispatches exactly one bounded CompleteOnce call against it
// (no hidden provider retry, no immediate repair), and commits a typed
// outcome. Mirrors internal/situation's own InputWorker/ControllerWorker
// claim/heartbeat/wake/drain shape deliberately closely — this package must
// never import internal/situation (or internal/llmhealth, or internal/
// store): every dependency below is a narrow, locally-declared interface a
// concrete type structurally satisfies from the outside (Task 9's own
// wiring).
// ----------------------------------------------------------------------

// ProfileStore is the narrow persistence surface Worker depends on —
// *store.Store satisfies it structurally via the methods Task 7 built.
type ProfileStore interface {
	ClaimSemanticInferenceJob(ctx context.Context, owner string, now time.Time, lease time.Duration) (profilemodel.JobClaim, bool, error)
	ReserveSemanticInferenceCall(ctx context.Context, jobID, owner string, token int64, now time.Time) (string, int, error)
	CompleteSemanticInference(ctx context.Context, callID, owner string, token int64, result profilemodel.InferenceResult, now time.Time, retryAt *time.Time) error
	ExtendSemanticInferenceJobLease(ctx context.Context, jobID, owner string, token int64, now time.Time, lease time.Duration) error
}

// ErrAttemptsExhausted is the locally-declared counterpart of internal/
// store's own ErrSemanticInferenceAttemptsExhausted — this package cannot
// import internal/store to reference that sentinel directly, so Worker
// recognizes it by errors.Is against THIS value; a ProfileStore
// implementation (Task 9's adapter) must return this exact sentinel (or
// wrap it) from ReserveSemanticInferenceCall for the exhausted case.
var ErrAttemptsExhausted = errors.New("semanticprofile: inference job attempts exhausted")

// CompletionClient is the locally-declared one-shot LLM call boundary —
// structurally identical to internal/situation.AssessmentClient, declared
// separately here so this package never imports internal/situation. The
// shared primary client (cmd/alertint, Task 9) satisfies both.
type CompletionClient interface {
	CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error)
}

// InferenceCallObservation ends one HealthObserver observation — err is nil
// on a successful (accepted OR store-downgraded-to-stale — see
// classifyCompletion's own doc comment) call, non-nil for a transport
// failure or a malformed/invalid model response. A stale CAS loss is
// healthy transport: the model itself answered correctly, only the durable
// commit lost a race that has nothing to do with LLM health.
type InferenceCallObservation interface {
	Finish(err error)
}

// HealthObserver is the locally-declared installation-LLM-health hook —
// structurally identical in spirit to internal/situation.
// AssessmentHealthObserver. cmd/alertint (Task 9) implements it by calling
// llmhealth.Tracker.Begin(llmhealth.CapabilitySemanticProfile, signature).
type HealthObserver interface {
	BeginInferenceCall(signature string) InferenceCallObservation
}

// AuditSink is the narrow audit-append surface Worker emits to —
// structurally identical to internal/situation.AuditSink (this package
// cannot import internal/situation): *audit.Auditor satisfies it directly.
// A nil sink (the default) disables audit emission.
type AuditSink interface {
	Append(ctx context.Context, actor, kind string, payload any) error
}

type noopInferenceCallObservation struct{}

func (noopInferenceCallObservation) Finish(error) {}

type noopHealthObserver struct{}

func (noopHealthObserver) BeginInferenceCall(string) InferenceCallObservation {
	return noopInferenceCallObservation{}
}

// RetryConfig bounds the backoff schedule for a non-accepted outcome that
// still has attempts remaining — the transport-neutral counterpart of
// config.SituationsConfig.Retry, duplicated here (never imported from
// internal/situation) exactly like internal/situation.RetryConfig's own
// shape.
type RetryConfig struct {
	Min, Max      time.Duration
	JitterPercent int
}

// WorkerConfig controls Worker's claim lease, heartbeat, schedule, attempt
// wall, and retry backoff. Zero-valued fields fall back to the documented
// defaults, mirroring every worker config in internal/situation.
type WorkerConfig struct {
	// Owner identifies this worker instance to the store's lease fencing.
	// Required — there is no default.
	Owner string

	// Lease is how long a claimed job is held before another worker may
	// reclaim it as expired. Default 60s.
	Lease time.Duration

	// Heartbeat is how often a claimed job's lease is renewed while its one
	// CompleteOnce call is still in flight. Default 10s — well under Lease.
	Heartbeat time.Duration

	// Interval is how often Start's background loop wakes on its own,
	// absent an explicit Wake(). Default 2s.
	Interval time.Duration

	// AttemptWall bounds one dispatch's own wall-clock budget (the shared
	// limiter wait plus the CompleteOnce call itself). Default 30s
	// (config.SituationsConfig.SemanticProfiles.AttemptWallSeconds's own
	// default).
	AttemptWall time.Duration

	// Retry bounds the backoff schedule for a non-accepted outcome with
	// attempts remaining. Default Min=5s, Max=300s, JitterPercent=20 — the
	// same defaults internal/situation.ControllerConfig.Retry uses.
	Retry RetryConfig

	// Provider is the shared primary client's provider name, recorded
	// verbatim on every committed Version/outcome row. No default — Task 9
	// sets it from the same config the shared client itself is built from.
	Provider string

	// Now is the clock RunOnce/heartbeat read. Default: the UTC wall clock.
	Now func() time.Time
}

const (
	defaultWorkerLease       = 60 * time.Second
	defaultWorkerHeartbeat   = 10 * time.Second
	defaultWorkerInterval    = 2 * time.Second
	defaultWorkerAttemptWall = 30 * time.Second

	defaultWorkerRetryMin           = 5 * time.Second
	defaultWorkerRetryMax           = 300 * time.Second
	defaultWorkerRetryJitterPercent = 20
)

func (c WorkerConfig) withDefaults() WorkerConfig {
	if c.Lease <= 0 {
		c.Lease = defaultWorkerLease
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = defaultWorkerHeartbeat
	}
	if c.Interval <= 0 {
		c.Interval = defaultWorkerInterval
	}
	if c.AttemptWall <= 0 {
		c.AttemptWall = defaultWorkerAttemptWall
	}
	if c.Retry.Min <= 0 {
		c.Retry.Min = defaultWorkerRetryMin
	}
	if c.Retry.Max <= 0 {
		c.Retry.Max = defaultWorkerRetryMax
	}
	if c.Retry.JitterPercent <= 0 {
		c.Retry.JitterPercent = defaultWorkerRetryJitterPercent
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return c
}

// retryBackoff derives a jittered backoff for attempt (1-based) from cfg —
// byte-for-byte the same formula internal/situation.retryBackoff uses,
// duplicated here per this package's own no-cross-import constraint.
func retryBackoff(cfg RetryConfig, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 30 {
		shift = 30
	}
	d := cfg.Min * time.Duration(uint64(1)<<uint(shift)) // #nosec G115 -- shift bounded to <=30 immediately above
	if d <= 0 || d > cfg.Max {
		d = cfg.Max
	}
	if cfg.JitterPercent > 0 {
		frac := float64(cfg.JitterPercent) / 100
		jitter := time.Duration(float64(d) * frac * (rand.Float64()*2 - 1)) // #nosec G404 -- retry-backoff jitter is timing scatter, not security-sensitive
		d += jitter
	}
	if d <= 0 {
		d = cfg.Min
	}
	return d
}

// Worker claims durable semantic-profile inference jobs (ProfileStore.
// ClaimSemanticInferenceJob) one at a time and dispatches each with a
// fenced lease heartbeat. It is safe for exactly one Start/Stop lifecycle;
// RunOnce and Drain may additionally be called directly (tests, or a
// one-shot CLI drain) without ever calling Start.
type Worker struct {
	store   ProfileStore
	client  CompletionClient
	limiter *llm.InferenceLimiter
	cfg     WorkerConfig
	logger  *slog.Logger
	health  HealthObserver
	audit   AuditSink

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
}

// NewWorker constructs a Worker. limiter is the SHARED llm.InferenceLimiter
// every CompleteOnce dispatch acquires from with llm.InferenceProfile
// priority (the same pool internal/situation.ControllerWorker's own L2
// dispatch shares via SetInferenceLimiter) — required, never nil. Passing
// nil for auditSink is reserved for a later task; nil for logger falls back
// to slog.Default().
func NewWorker(store ProfileStore, client CompletionClient, limiter *llm.InferenceLimiter, cfg WorkerConfig, clock func() time.Time, logger *slog.Logger) *Worker {
	cfg = cfg.withDefaults()
	if clock != nil {
		cfg.Now = clock
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		store:   store,
		client:  client,
		limiter: limiter,
		cfg:     cfg,
		logger:  logger,
		health:  noopHealthObserver{},
		wakeCh:  make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// SetHealthObserver wires the installation LLM-health observer. Optional:
// the default is a no-op. Not safe to call concurrently with Start/RunOnce;
// call once, right after construction.
func (w *Worker) SetHealthObserver(h HealthObserver) {
	if h != nil {
		w.health = h
	}
}

// SetAuditSink wires the audit log. Optional: nil (the default) disables
// audit emission. Not safe to call concurrently with Start/RunOnce; call
// once, right after construction.
func (w *Worker) SetAuditSink(a AuditSink) {
	w.audit = a
}

// auditAppend is a best-effort audit emission: a failure is logged and
// swallowed, exactly like internal/situation.Controller.auditAppend — an
// audit-log failure must never lose the durable state change it describes.
func (w *Worker) auditAppend(ctx context.Context, kind string, payload any) {
	if w.audit == nil {
		return
	}
	if err := w.audit.Append(ctx, workerAuditActor, kind, payload); err != nil {
		w.logger.Warn("semanticprofile: worker audit append failed", "kind", kind, "err", err)
	}
}

// workerAuditActor is the fixed audit actor for every event this package
// emits.
const workerAuditActor = "semantic_profile.worker"

func detachedWorkerContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// RunOnce claims at most one due job and dispatches it. It returns 1 (job
// handled — regardless of the outcome's own success/failure) or 0 (no due
// job). A claim error, or a per-job failure that leaves the job's own lease
// state ambiguous (context cancellation or profilemodel.ErrLeaseLost), is
// returned directly; any other per-job failure is logged and swallowed —
// RunOnce always reports the job as handled once claimed, since ownership
// of retry/backoff bookkeeping belongs entirely to processOne/the store.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	claim, found, err := w.store.ClaimSemanticInferenceJob(ctx, w.cfg.Owner, w.cfg.Now(), w.cfg.Lease)
	if err != nil {
		return 0, fmt.Errorf("semanticprofile: claim inference job: %w", err)
	}
	if !found {
		return 0, nil
	}

	if err := w.processOne(ctx, claim); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, profilemodel.ErrLeaseLost) {
			w.logger.Warn("semanticprofile: worker round stopped", "job_id", claim.JobID, "signature", claim.Signature, "err", err)
			return 0, err
		}
		w.logger.Error("semanticprofile: worker process job failed", "job_id", claim.JobID, "signature", claim.Signature, "err", err)
	}
	return 1, nil
}

// processOne reserves exactly one dispatch slot, runs it with a fenced
// lease heartbeat, and commits its typed outcome. A reservation that comes
// back ErrAttemptsExhausted means the store already marked the job
// exhausted (plan.md: "Claiming does not spend a call... reserve exactly
// one CompleteOnce dispatch per attempt before the request") — nothing
// left to dispatch this round.
func (w *Worker) processOne(ctx context.Context, claim profilemodel.JobClaim) error {
	now := w.cfg.Now()
	callID, attempt, err := w.store.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		if errors.Is(err, ErrAttemptsExhausted) {
			return nil
		}
		return fmt.Errorf("semanticprofile: reserve inference call: %w", err)
	}
	// Audited immediately after the reservation durably commits — the
	// dispatch slot is spent whether or not the physical call below ever
	// starts, mirroring situation.Controller's own
	// "situation.assessment_call_dispatched" ordering.
	w.auditAppend(ctx, "semantic_profile.call_dispatched", map[string]any{
		"signature": claim.Signature, "job_id": claim.JobID, "call_id": callID, "attempt": attempt,
	})

	prompt, err := BuildInferencePrompt(claim.FrozenInputJSON)
	if err != nil {
		return fmt.Errorf("semanticprofile: build inference prompt: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, w.cfg.AttemptWall)
	var leaseLost atomic.Bool
	hbDone := make(chan struct{})
	go w.heartbeatLoop(callCtx, cancel, claim, &leaseLost, hbDone)

	// One span per consumed dispatch slot, started only AFTER the durable
	// call row committed above — it wraps only the out-of-transaction
	// provider I/O and classification, nothing durable (mirrors
	// situation.SpanAssessmentDispatch's own contract exactly).
	callCtx, span := tracer().Start(callCtx, SpanSemanticInference, trace.WithAttributes(
		AttrJobID.String(claim.JobID), AttrCallID.String(callID), AttrAttempt.Int(attempt),
	))

	release, acquireErr := w.limiter.Acquire(callCtx, llm.InferenceProfile)
	var result profilemodel.InferenceResult
	if acquireErr != nil {
		// Never invoked the client — no health observation either: this is
		// a queueing delay, not an attempted call (plan.md: "Cancellation
		// while waiting must not invoke the client").
		result, _ = classifyCompletion(llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusFalse}, acquireErr, w.cfg.Provider)
	} else {
		obs := w.health.BeginInferenceCall(claim.Signature)
		oneShot, callErr := w.client.CompleteOnce(callCtx, "", prompt, nil)
		release()
		var classifyErr error
		result, classifyErr = classifyCompletion(oneShot, callErr, w.cfg.Provider)
		obs.Finish(classifyErr)
	}
	span.SetAttributes(AttrResultClass.String(result.Outcome))
	span.End()

	cancel()
	<-hbDone

	if leaseLost.Load() {
		return profilemodel.ErrLeaseLost
	}

	var retryAt *time.Time
	if result.Outcome != profilemodel.InferenceOutcomeAccepted {
		at := now.Add(retryBackoff(w.cfg.Retry, attempt))
		retryAt = &at
	}
	if err := w.store.CompleteSemanticInference(ctx, callID, claim.Owner, claim.Token, result, w.cfg.Now(), retryAt); err != nil {
		return fmt.Errorf("semanticprofile: complete inference: %w", err)
	}
	// Audited from the worker's OWN pre-CAS classification of result.Outcome
	// — the durable outcome CompleteSemanticInference actually committed may
	// differ (an accepted result downgraded to stale by a winning
	// correction/sibling job), which is by design not a worker- or
	// health-visible distinction (spec.md's "stale-CAS-loss is healthy
	// transport"). The true persisted outcome, including any such downgrade,
	// always remains readable from semantic_profile_call_outcomes itself.
	w.auditAppend(ctx, "semantic_profile.call_completed", map[string]any{
		"signature": claim.Signature, "job_id": claim.JobID, "call_id": callID, "outcome": result.Outcome,
	})
	if result.Outcome == profilemodel.InferenceOutcomeAccepted {
		w.auditAppend(ctx, "semantic_profile.head_advanced", map[string]any{
			"signature": claim.Signature, "job_id": claim.JobID,
		})
	}
	return nil
}

// classifyCompletion reduces one CompleteOnce outcome (or an
// InferenceLimiter.Acquire failure, treated identically to a call that was
// never dispatched) to the closed InferenceResult/error pair processOne
// commits and reports to health. InferenceOutcomeRejected and
// InferenceOutcomeStale are never returned here: profiles carry no policy
// dimension a response could be "rejected" against (unlike Assessment's
// SufficientReason/capability checks), and "stale" is decided
// transactionally by CompleteSemanticInference's own expected-head CAS
// check, never by the worker (see this package's own worker_test.go: "a
// stale successful CAS loss is healthy transport" — the classification
// here reflects only what the MODEL did, not whether the store's later
// commit won its race).
func classifyCompletion(oneShot llm.OneShotCompletion, callErr error, provider string) (profilemodel.InferenceResult, error) {
	base := profilemodel.InferenceResult{
		RequestStarted: string(oneShot.RequestStarted), Provider: provider, Model: oneShot.Model,
		UsageInputTokens: oneShot.InputTokens, UsageOutputTokens: oneShot.OutputTokens,
		PromptVersion: profilemodel.PromptVersion,
	}
	if callErr != nil {
		base.Outcome = profilemodel.InferenceOutcomeFailed
		return base, callErr
	}
	profile, err := ParseProfile(oneShot.Raw)
	if err != nil {
		base.Outcome = profilemodel.InferenceOutcomeMalformed
		return base, err
	}
	base.Outcome = profilemodel.InferenceOutcomeAccepted
	base.Profile = &profile
	return base, nil
}

// heartbeatLoop renews claim's lease every cfg.Heartbeat until ctx is done
// — byte-for-byte the same shape internal/situation.ControllerWorker's own
// heartbeatLoop uses. If a renewal ever fails, it marks leaseLost and
// cancels cancel so the in-flight call is abandoned rather than allowed to
// keep running under a lease it no longer holds.
func (w *Worker) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, claim profilemodel.JobClaim, leaseLost *atomic.Bool, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(w.cfg.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			extendCtx, extendCancel := detachedWorkerContext()
			err := w.store.ExtendSemanticInferenceJobLease(extendCtx, claim.JobID, claim.Owner, claim.Token, w.cfg.Now(), w.cfg.Lease) //nolint:contextcheck // by design: extendCtx is detachedWorkerContext, independent of the possibly-canceled call context
			extendCancel()
			if err != nil {
				w.logger.Warn("semanticprofile: worker heartbeat lease extend failed; canceling dispatch",
					"job_id", claim.JobID, "signature", claim.Signature, "err", err)
				leaseLost.Store(true)
				cancel()
				return
			}
		}
	}
}

// Drain runs RunOnce repeatedly until a round handles zero jobs (the queue
// is caught up) or a round returns an error. It returns the total handled
// across every round.
func (w *Worker) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := w.RunOnce(ctx)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

// Start launches the background loop and returns immediately. It runs one
// Drain pass right away, then blocks until the next of: cfg.Interval
// elapsing, an explicit Wake(), or shutdown (ctx or Stop). Safe to call at
// most once per Worker; later calls are no-ops.
func (w *Worker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		go w.run(ctx)
	})
}

func (w *Worker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if _, err := w.Drain(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("semanticprofile: worker drain", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
	}
}

// Wake nudges the background loop to run another round immediately instead
// of waiting for the next interval tick. Never blocks: a Wake() arriving
// while one is already pending is silently coalesced into it.
func (w *Worker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit after its current round and
// waits for it to finish. Returns nil once the loop has drained, or ctx's
// error if ctx is done first — the loop keeps running in that case.
func (w *Worker) Stop(ctx context.Context) error {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	select {
	case <-w.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
