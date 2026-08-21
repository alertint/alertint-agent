// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Worker defaults. Every one is deliberately conservative: a durable queue
// that is drained slightly slower than it could be is correct, a queue that
// loses its lease mid-work is not.
const (
	defaultWorkerLease       = 60 * time.Second
	defaultWorkerInterval    = 2 * time.Second
	defaultWorkerBatch       = 16
	defaultWorkerConcurrency = 4
	defaultWorkerAttempts    = 8
	// defaultHeartbeatInterval must stay well under defaultWorkerLease so a
	// long reconciliation keeps ownership without racing its own expiry.
	defaultHeartbeatInterval = 15 * time.Second
	// defaultIdleCadence mirrors the controller's normal checkpoint cadence.
	defaultIdleCadence = 5 * time.Minute
)

// WorkerConfig holds the shared tunables of every durable Situation worker.
// Zero values normalize to the constants above.
type WorkerConfig struct {
	// Owner is this process's durable lease identity. It must be unique per
	// running worker so a fence can tell two claimants apart.
	Owner string
	// Lease is how long a claim stays owned without a heartbeat.
	Lease time.Duration
	// Interval is the idle poll cadence; a Wake shortcuts it.
	Interval time.Duration
	// Batch bounds one claim round.
	Batch int
	// Concurrency bounds simultaneous in-flight units (WorkerPool only).
	Concurrency int
	// MaxAttempts is the retry budget before a work item becomes an
	// operator-visible dead letter. It never carries lifecycle authority.
	MaxAttempts int
	// Retry is the shared backoff-with-jitter formula.
	Retry RetryPolicy
	// IdleCadence is how far ahead a Situation is rescheduled when its
	// reconciliation committed nothing (the current fact hash was already
	// covered). Without it the aggregate would stay perpetually due and the
	// pool would re-claim it in a tight loop. WorkerPool only.
	IdleCadence time.Duration
	// Ready gates a round on durable storage being writable. While it
	// returns false no round starts, so no connector, model, or Slack I/O
	// runs against state that could not be persisted first.
	//
	// It is therefore the ONLY thing that still executes while storage is
	// unwritable, which makes it the one place recovery can live: an
	// implementation that gates on storage health MUST be able to re-test
	// that health from inside Ready and return true again. Gating on a
	// cached verdict that only a completed round could clear would latch the
	// runtime off permanently. Ready receives the round's context so its
	// re-test can be bounded and cancelled. nil is always-ready.
	Ready func(ctx context.Context) bool
	// OnRound observes each completed round's outcome — never a skipped one,
	// which is not an outcome. It is how storage write health becomes
	// authoritative for readiness: a failing round degrades health, and a
	// later successful one restores it. nil is no-op.
	OnRound func(handled int, err error)
}

func (c WorkerConfig) normalized() WorkerConfig {
	if strings.TrimSpace(c.Owner) == "" {
		c.Owner = "alertint"
	}
	if c.Lease <= 0 {
		c.Lease = defaultWorkerLease
	}
	if c.Interval <= 0 {
		c.Interval = defaultWorkerInterval
	}
	if c.Batch <= 0 {
		c.Batch = defaultWorkerBatch
	}
	if c.Concurrency <= 0 {
		c.Concurrency = defaultWorkerConcurrency
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultWorkerAttempts
	}
	if c.IdleCadence <= 0 {
		c.IdleCadence = defaultIdleCadence
	}
	if c.Ready == nil {
		c.Ready = func(context.Context) bool { return true }
	}
	if c.OnRound == nil {
		c.OnRound = func(int, error) {}
	}
	return c
}

// gatedRound wraps one worker round with the readiness gate and the outcome
// observer, so every worker in this file honors storage write health
// identically: nothing outward is attempted while storage is unwritable, and
// each round's outcome is what makes readiness authoritative. Every worker
// entry point (RunOnce, Drain, and the background loop) goes through it, so
// there is no ungated way to reach a round body.
func (c WorkerConfig) gatedRound(round func(context.Context) (int, error)) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		if !c.Ready(ctx) {
			return 0, nil
		}
		handled, err := round(ctx)
		c.OnRound(handled, err)
		return handled, err
	}
}

// loop is the shared claim/poll body every worker in this file runs: it wakes
// on demand, otherwise ticks, and exits cleanly on stop or context end.
type loop struct {
	interval time.Duration
	logger   *slog.Logger
	name     string

	once   sync.Once
	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}
}

func newLoop(name string, interval time.Duration, logger *slog.Logger) *loop {
	if logger == nil {
		logger = slog.Default()
	}
	return &loop{
		name: name, interval: interval, logger: logger,
		wakeCh: make(chan struct{}, 1), stopCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
}

// Wake asks the loop to run a round immediately instead of waiting out the
// idle interval. It never blocks.
func (l *loop) Wake() {
	select {
	case l.wakeCh <- struct{}{}:
	default:
	}
}

func (l *loop) start(ctx context.Context, round func(context.Context) (int, error)) {
	l.once.Do(func() { go l.run(ctx, round) })
}

func (l *loop) run(ctx context.Context, round func(context.Context) (int, error)) {
	defer close(l.doneCh)
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		handled, err := round(ctx)
		if err != nil {
			l.logger.Error(l.name+" round failed", slog.String("err", err.Error()))
		}
		if handled > 0 {
			// More work may already be waiting; keep going without pausing.
			select {
			case <-ctx.Done():
				return
			case <-l.stopCh:
				return
			default:
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-l.wakeCh:
		case <-ticker.C:
		}
	}
}

// stop signals the loop and waits for the in-flight round to finish, bounded
// by ctx so shutdown cannot hang past its timeout.
func (l *loop) stop(ctx context.Context) error {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
	select {
	case <-l.doneCh:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("situation: %s did not drain before shutdown deadline: %w", l.name, ctx.Err())
	}
}

// retryAt computes the next attempt instant, and whether the budget is spent.
// Exhaustion parks or dead-letters work; it never carries lifecycle authority.
func retrySchedule(cfg WorkerConfig, attemptCount int, now time.Time) (time.Time, bool) {
	if attemptCount >= cfg.MaxAttempts {
		return time.Time{}, true
	}
	return now.Add(cfg.Retry.Next(attemptCount+1, rand.Float64())), false //nolint:gosec // scheduling jitter, not a security decision
}

// --------------------------------------------------------------------------
// Situation input worker
// --------------------------------------------------------------------------

// InputClaim is one lease-fenced durable Incident-to-Situation handoff. It
// mirrors store.SituationInput's identity without importing internal/store
// (which already imports this package).
type InputClaim struct {
	ID           string
	IncidentID   string
	GroupKey     string
	Kind         string
	ClaimOwner   string
	ClaimToken   int64
	AttemptCount int
}

// InputStore is the narrow durable boundary the input worker needs.
type InputStore interface {
	ClaimSituationInputs(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]InputClaim, error)
	ApplySituationInput(ctx context.Context, claim InputClaim) error
	RetrySituationInput(ctx context.Context, claim InputClaim, class string, retryAt time.Time, terminal bool) error
}

// InputWorker claims pending Situation inputs and applies each one through
// the store's atomic attach/version transaction. It performs no connector,
// model, or Slack I/O: applying an input only makes a Situation due.
type InputWorker struct {
	store InputStore
	cfg   WorkerConfig
	clock func() time.Time
	loop  *loop
	// hook is the crash-boundary test seam (replay.go). nil in every
	// production construction; only SetBoundaryHookForTest sets it.
	hook boundaryHook
}

// NewInputWorker constructs an InputWorker. clock nil uses UTC wall time.
func NewInputWorker(store InputStore, cfg WorkerConfig, clock func() time.Time, logger *slog.Logger) *InputWorker {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	normalized := cfg.normalized()
	return &InputWorker{store: store, cfg: normalized, clock: clock, loop: newLoop("situation input worker", normalized.Interval, logger)}
}

// Start launches the background claim loop. It must be called at most once.
func (w *InputWorker) Start(ctx context.Context) { w.loop.start(ctx, w.RunOnce) }

// Stop drains the in-flight round within ctx's deadline.
func (w *InputWorker) Stop(ctx context.Context) error { return w.loop.stop(ctx) }

// Wake asks for an immediate round.
func (w *InputWorker) Wake() { w.loop.Wake() }

// RunOnce claims and applies one batch, returning how many inputs were
// applied. A retryable apply failure releases the claim for a later attempt;
// an exhausted budget records an operator-visible dead letter. It runs
// through the readiness gate, so it is a no-op while storage is unwritable.
func (w *InputWorker) RunOnce(ctx context.Context) (int, error) {
	return w.cfg.gatedRound(w.runOnce)(ctx)
}

func (w *InputWorker) runOnce(ctx context.Context) (int, error) {
	if w.store == nil {
		return 0, errors.New("situation: input worker requires a durable store")
	}
	now := w.clock().UTC()
	claims, err := w.store.ClaimSituationInputs(ctx, w.cfg.Owner, now, w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: claim situation inputs: %w", err)
	}
	applied := 0
	var failures []error
	for _, claim := range claims {
		if err := w.store.ApplySituationInput(ctx, claim); err != nil {
			retryAt, terminal := retrySchedule(w.cfg, claim.AttemptCount, now)
			if retryErr := w.store.RetrySituationInput(ctx, claim, errorClass(err), retryAt, terminal); retryErr != nil {
				failures = append(failures, fmt.Errorf("situation: release situation input %s: %w", claim.ID, retryErr))
			}
			continue
		}
		applied++
		if hookErr := runBoundaryHook(w.hook, "situation_input_commit"); hookErr != nil {
			// The apply above already committed durably; a crash here only
			// abandons the rest of this claim batch, which stays leased and
			// becomes claimable again once that lease lapses.
			return applied, hookErr
		}
	}
	return applied, errors.Join(failures...)
}

// Drain replays every currently pending input, satisfying Replayer for
// startup reconstruction. It stops as soon as a round claims nothing.
func (w *InputWorker) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		applied, err := w.RunOnce(ctx)
		total += applied
		if err != nil {
			return total, err
		}
		if applied == 0 {
			return total, nil
		}
	}
}

// --------------------------------------------------------------------------
// Controller worker pool
// --------------------------------------------------------------------------

// DueClaim is one lease-fenced due Situation aggregate.
type DueClaim struct {
	SituationID string
	ClaimOwner  string
	ClaimToken  int64
}

// ControllerStore is the narrow durable boundary the reconciliation pool
// needs. It claims due aggregates, heartbeats the lease while work runs, and
// releases a claim whose reconciliation failed.
type ControllerStore interface {
	LeaseExtender
	ClaimDueSituations(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]DueClaim, error)
	// ReleaseSituation drops a claim whose reconciliation failed, recording
	// the failure class and when to try again.
	ReleaseSituation(ctx context.Context, claim DueClaim, class string, retryAt time.Time) error
	// CompleteSituation releases a claim whose reconciliation succeeded. When
	// the reconciliation committed a transition the aggregate has already
	// released its own lease and set its own next_assessment_at, and this is a
	// no-op; when it committed nothing (a covered fact hash) this is what
	// stops the aggregate from staying perpetually due.
	CompleteSituation(ctx context.Context, claim DueClaim, nextAt time.Time) error
}

// Reconciler is the controller boundary the pool drives. *Controller
// satisfies it.
type Reconciler interface {
	Reconcile(ctx context.Context, situationID string) error
}

// WorkerPool claims due Situations in deterministic priority order and
// reconciles each under a lease heartbeat, bounded by global concurrency.
type WorkerPool struct {
	store      ControllerStore
	reconciler Reconciler
	cfg        WorkerConfig
	clock      func() time.Time
	loop       *loop
	heartbeat  time.Duration
}

// NewWorkerPool constructs a WorkerPool. clock nil uses UTC wall time.
func NewWorkerPool(store ControllerStore, reconciler Reconciler, cfg WorkerConfig, clock func() time.Time, logger *slog.Logger) *WorkerPool {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	normalized := cfg.normalized()
	heartbeat := defaultHeartbeatInterval
	if heartbeat >= normalized.Lease {
		heartbeat = normalized.Lease / 3
	}
	if heartbeat <= 0 {
		heartbeat = time.Second
	}
	return &WorkerPool{
		store: store, reconciler: reconciler, cfg: normalized, clock: clock,
		loop: newLoop("situation controller pool", normalized.Interval, logger), heartbeat: heartbeat,
	}
}

// Start launches the background claim loop. It must be called at most once.
func (p *WorkerPool) Start(ctx context.Context) { p.loop.start(ctx, p.RunOnce) }

// Stop drains the in-flight round within ctx's deadline.
func (p *WorkerPool) Stop(ctx context.Context) error { return p.loop.stop(ctx) }

// Wake asks for an immediate round.
func (p *WorkerPool) Wake() { p.loop.Wake() }

// RunOnce claims and reconciles one batch of due Situations, returning how
// many were handled. A reconciliation failure releases the claim with a
// backoff so the aggregate stays durable and claimable. It runs through the
// readiness gate, so it is a no-op while storage is unwritable.
func (p *WorkerPool) RunOnce(ctx context.Context) (int, error) {
	return p.cfg.gatedRound(p.runOnce)(ctx)
}

func (p *WorkerPool) runOnce(ctx context.Context) (int, error) {
	if p.store == nil || p.reconciler == nil {
		return 0, errors.New("situation: controller pool requires a durable store and reconciler")
	}
	now := p.clock().UTC()
	claims, err := p.store.ClaimDueSituations(ctx, p.cfg.Owner, now, p.cfg.Lease, p.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: claim due situations: %w", err)
	}
	if len(claims) == 0 {
		return 0, nil
	}

	var (
		mu       sync.Mutex
		failures []error
		wg       sync.WaitGroup
	)
	slots := make(chan struct{}, p.cfg.Concurrency)
	for _, claim := range claims {
		wg.Add(1)
		slots <- struct{}{}
		go func(claim DueClaim) {
			defer wg.Done()
			defer func() { <-slots }()
			if err := p.reconcileClaim(ctx, claim, now); err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}(claim)
	}
	wg.Wait()
	return len(claims), errors.Join(failures...)
}

func (p *WorkerPool) reconcileClaim(ctx context.Context, claim DueClaim, now time.Time) error {
	err := RunWithLeaseHeartbeat(ctx, p.store, claim.SituationID, claim.ClaimOwner, claim.ClaimToken,
		p.heartbeat, p.cfg.Lease, func(workCtx context.Context) error {
			return p.reconciler.Reconcile(workCtx, claim.SituationID)
		})
	if err == nil {
		return p.store.CompleteSituation(ctx, claim, now.Add(p.cfg.IdleCadence))
	}
	retryAt := now.Add(p.cfg.Retry.Next(1, rand.Float64())) //nolint:gosec // scheduling jitter, not a security decision
	if releaseErr := p.store.ReleaseSituation(ctx, claim, errorClass(err), retryAt); releaseErr != nil {
		return errors.Join(err, fmt.Errorf("situation: release situation %s: %w", claim.SituationID, releaseErr))
	}
	return nil
}

// --------------------------------------------------------------------------
// Notification worker
// --------------------------------------------------------------------------

// NotificationStore is the narrow durable boundary the notification worker
// needs. Claiming advances the intent's retry_at lease deadline rather than
// introducing a new status, so an abandoned claim becomes claimable again the
// moment its deadline passes.
type NotificationStore interface {
	ClaimNotificationIntents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]model.NotificationIntent, error)
	MarkNotificationDelivered(ctx context.Context, id, channel, messageTS string, deliveredAt time.Time) error
	RetryNotificationIntent(ctx context.Context, id, class string, retryAt time.Time, terminal bool) error
}

// NotificationDelivery is the outward coordinates one delivered intent
// produced. A root create returns freshly minted coordinates; an edit returns
// the coordinates it targeted.
type NotificationDelivery struct {
	Channel   string
	MessageTS string
}

// NotificationDeliverer performs the one outward effect a durable intent
// promised. The concrete implementation (Slack renderers plus the narrow API
// client, and the stdout Situation sink) lives in cmd/alertint wiring: this
// package never imports internal/notify/slack, which imports internal/store,
// which imports this package.
type NotificationDeliverer interface {
	Deliver(ctx context.Context, intent model.NotificationIntent) (NotificationDelivery, error)
}

// RetryTimingError lets a deliverer surface the server's own retry timing
// (Slack's Retry-After) so a rate-limited retry honors it instead of guessing.
type RetryTimingError interface {
	error
	NotificationRetryAfter() time.Duration
}

// ErrNotificationUnroutable marks an intent that can never succeed as
// addressed (an unknown channel, a revoked surface). It dead-letters
// immediately rather than consuming its whole retry budget.
var ErrNotificationUnroutable = errors.New("situation: notification intent is unroutable")

// NotificationWorker claims pending notification intents and performs their
// one outward effect. A failed effect stays a durable pending or failed
// intent and retries with the exact same identity — never a rewritten one.
type NotificationWorker struct {
	store     NotificationStore
	deliverer NotificationDeliverer
	cfg       WorkerConfig
	clock     func() time.Time
	loop      *loop
	// hook is the crash-boundary test seam (replay.go). nil in every
	// production construction; only SetBoundaryHookForTest sets it.
	hook boundaryHook
}

// NewNotificationWorker constructs a NotificationWorker. A nil deliverer
// leaves every intent durably pending — an installation with no Slack sink
// still records exactly what it owed.
func NewNotificationWorker(store NotificationStore, deliverer NotificationDeliverer, cfg WorkerConfig, clock func() time.Time, logger *slog.Logger) *NotificationWorker {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	normalized := cfg.normalized()
	return &NotificationWorker{
		store: store, deliverer: deliverer, cfg: normalized, clock: clock,
		loop: newLoop("situation notification worker", normalized.Interval, logger),
	}
}

// Start launches the background claim loop. It must be called at most once.
func (w *NotificationWorker) Start(ctx context.Context) {
	w.loop.start(ctx, w.cfg.gatedRound(w.RunOnce))
}

// Stop drains the in-flight round within ctx's deadline.
func (w *NotificationWorker) Stop(ctx context.Context) error { return w.loop.stop(ctx) }

// Wake asks for an immediate round.
func (w *NotificationWorker) Wake() { w.loop.Wake() }

// RunOnce claims and delivers one batch of intents, returning how many were
// delivered. It runs through the readiness gate, so no Slack call is
// attempted while storage cannot record its outcome.
func (w *NotificationWorker) RunOnce(ctx context.Context) (int, error) {
	return w.cfg.gatedRound(w.runOnce)(ctx)
}

func (w *NotificationWorker) runOnce(ctx context.Context) (int, error) {
	if w.store == nil {
		return 0, errors.New("situation: notification worker requires a durable store")
	}
	if w.deliverer == nil {
		return 0, nil
	}
	now := w.clock().UTC()
	intents, err := w.store.ClaimNotificationIntents(ctx, now, w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: claim notification intents: %w", err)
	}
	delivered := 0
	var failures []error
	for _, intent := range intents {
		out, deliverErr := w.deliverer.Deliver(ctx, intent)
		if hookErr := runBoundaryHook(w.hook, "slack_post_timeout"); hookErr != nil {
			// The outward Slack effect (or its attempt) already happened by
			// the time this fires; a crash right here loses only the local
			// record of what the response said. The intent stays leased
			// pending/failed and the next claim replays the identical
			// client_msg_id, so a real Slack post is never duplicated.
			return delivered, hookErr
		}
		if deliverErr == nil {
			if hookErr := runBoundaryHook(w.hook, coordinateCommitBoundary(intent.Kind)); hookErr != nil {
				// Slack accepted the post/edit/reply; a crash here loses only
				// the local coordinate commit, not the outward effect.
				return delivered, hookErr
			}
			if markErr := w.store.MarkNotificationDelivered(ctx, intent.ID, out.Channel, out.MessageTS, w.clock().UTC()); markErr != nil {
				failures = append(failures, fmt.Errorf("situation: record delivered notification %s: %w", intent.ID, markErr))
				continue
			}
			delivered++
			continue
		}
		retryAt, terminal := notificationRetry(w.cfg, intent, deliverErr, now)
		if retryErr := w.store.RetryNotificationIntent(ctx, intent.ID, errorClass(deliverErr), retryAt, terminal); retryErr != nil {
			failures = append(failures, fmt.Errorf("situation: release notification intent %s: %w", intent.ID, retryErr))
		}
	}
	return delivered, errors.Join(failures...)
}

// notificationRetry resolves the next attempt instant, preferring the
// server's own retry timing when it supplied one.
func notificationRetry(cfg WorkerConfig, intent model.NotificationIntent, err error, now time.Time) (time.Time, bool) {
	if errors.Is(err, ErrNotificationUnroutable) {
		return time.Time{}, true
	}
	var timed RetryTimingError
	if errors.As(err, &timed) && timed.NotificationRetryAfter() > 0 {
		return now.Add(timed.NotificationRetryAfter()), false
	}
	return retrySchedule(cfg, intent.AttemptCount, now)
}

// errorClass renders one durable, operator-readable failure class. It is
// deliberately the error text, bounded: a closed enum would collapse exactly
// the detail an operator needs to act on a dead letter.
func errorClass(err error) string {
	if err == nil {
		return "unknown"
	}
	class := strings.TrimSpace(err.Error())
	if class == "" {
		return "unknown"
	}
	const maxErrorClassBytes = 200
	if len(class) > maxErrorClassBytes {
		class = class[:maxErrorClassBytes]
	}
	return class
}
