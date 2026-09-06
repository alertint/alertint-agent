// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Plan 3 Task 9: the stdout Transition stream.
//
// spec.md ("MCP, audit, logs, OTel, and stdout"): "Stdout emits one
// versioned machine-readable Situation Transition event after durable
// commit. It does not imply Slack delivery. Silent and withheld Situations
// still emit state, and consumers deduplicate by Transition ID."
//
// This worker is the consumer of migration 0017's
// situation_transition_stream outbox, which the same fenced controller
// commit that writes a Transition also writes one row of. It is deliberately
// the mirror image of the Situation notification worker with three
// differences, all of them consequences of stdout being a local pipe rather
// than an external provider:
//
//  1. it is never gated by the Slack Delivery gap — an unreachable Slack
//     must not be able to stop the authoritative state stream;
//  2. it has no root dependency and no per-Situation head-of-queue rule, so
//     one Situation's backlog never blocks another's; and
//  3. its only permanent outcome is a durable row this build cannot
//     serialize at all. An unavailable writer retries, indefinitely.
//
// Delivery is at-least-once BY CONSTRUCTION: the line is written before the
// acknowledgement commits, so a crash in between replays the same
// Transition. That is the documented contract — a duplicate line is
// permitted, a lost one after a committed Transition is not — and it is why
// the line carries the Transition's immutable ID as its deduplication key.
//
// The line carries identities, closed codes, hashes, counters, and instants
// only: no journal headline or detail prose, no Assessment body, no Slack
// coordinate, and no token. A consumer that wants the prose reads it from
// MCP or Slack; stdout is the state stream.
// ----------------------------------------------------------------------

const (
	// TransitionStreamKind is the stable `kind` discriminator every stream
	// line carries, so a consumer multiplexing this stdout with the Finding
	// lines Notifier writes can tell them apart without guessing.
	TransitionStreamKind = "situation.transition"
	// TransitionStreamVersion is the stream envelope's own schema version.
	// It changes only when a field's meaning changes, never when a purely
	// additive field appears.
	TransitionStreamVersion = 1

	// auditActor identifies this worker in the hash-chained audit log.
	auditActor = "situation.transition_stream"

	// streamErrorUnavailable is the bounded error class an unwritable
	// stdout records; streamErrorInvalid is the one permanent class.
	streamErrorUnavailable = "stdout_unavailable"
	streamErrorInvalid     = "invalid_transition"
)

// AuditTransitionStreamEmitted records one durably acknowledged stdout
// line; AuditTransitionStreamFailed records the one permanent outcome this
// worker has, a durable row it cannot render. Both are aliases of
// internal/audit's own catalog, which is where the names are checked for
// completeness and non-collision.
const (
	AuditTransitionStreamEmitted = audit.KindTransitionStreamEmitted
	AuditTransitionStreamFailed  = audit.KindTransitionStreamFailed
)

const (
	defaultStreamPoll         = time.Second
	defaultStreamLease        = 120 * time.Second
	defaultStreamBatch        = 50
	defaultStreamRetryInitial = 2 * time.Second
	defaultStreamRetryMax     = 60 * time.Second
)

// TransitionStreamStore is exactly the durable surface this worker drives.
// *store.Store implements it (asserted in the runtime wiring).
type TransitionStreamStore interface {
	RecoverExpiredTransitionStreamClaims(ctx context.Context, now time.Time) (int, error)
	ClaimTransitionStream(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]store.TransitionStreamClaim, error)
	MarkTransitionStreamDelivered(ctx context.Context, claim store.TransitionStreamClaim, now time.Time) error
	RetryTransitionStreamEntry(ctx context.Context, claim store.TransitionStreamClaim, errorClass string, retryAt time.Time) error
	FailTransitionStreamEntry(ctx context.Context, claim store.TransitionStreamClaim, errorClass string, now time.Time) error
	ReleaseTransitionStreamClaim(ctx context.Context, claim store.TransitionStreamClaim) error
}

// TransitionStreamAuditSink is the narrow audit-append surface this worker
// emits to. *audit.Auditor satisfies it.
type TransitionStreamAuditSink interface {
	Append(ctx context.Context, actor, kind string, payload any) error
}

// TransitionStreamConfig controls lease fencing, poll cadence, batch size,
// and the retry schedule. Like every other Plan 3 delivery ledger it has NO
// maximum-attempts field.
type TransitionStreamConfig struct {
	// Owner identifies this worker to the store's lease fencing. Required.
	Owner string
	// Poll is how often the background loop wakes. Default 1s.
	Poll time.Duration
	// Lease is how long a claimed row is held. Default 120s.
	Lease time.Duration
	// Batch bounds one round. Default 50, clamped by the store's own page
	// bound.
	Batch int
	// RetryInitial and RetryMax bound the exponential retry schedule.
	// Defaults 2s and 60s.
	RetryInitial time.Duration
	RetryMax     time.Duration
}

func (c TransitionStreamConfig) withDefaults() TransitionStreamConfig {
	if c.Poll <= 0 {
		c.Poll = defaultStreamPoll
	}
	if c.Lease <= 0 {
		c.Lease = defaultStreamLease
	}
	if c.Batch <= 0 {
		c.Batch = defaultStreamBatch
	}
	if c.RetryInitial <= 0 {
		c.RetryInitial = defaultStreamRetryInitial
	}
	if c.RetryMax <= 0 {
		c.RetryMax = defaultStreamRetryMax
	}
	return c
}

// TransitionStreamStats is the bounded counter set this worker exposes for
// logs. Plan 3 adds no OTel metric instruments (R8).
type TransitionStreamStats struct {
	Claimed    int64
	Emitted    int64
	Retried    int64
	Failed     int64
	ClaimsLost int64
}

// transitionStreamLine is the canonical JSON object one stream row emits.
// Every field is an identity, a closed code, a hash, a counter, or an
// instant. Adding a prose field here would break the payload-absence
// contract this package's own test pins.
type transitionStreamLine struct {
	Kind                 string     `json:"kind"`
	Version              int        `json:"version"`
	EmittedAt            time.Time  `json:"emitted_at"`
	SituationID          string     `json:"situation_id"`
	PublicHandle         string     `json:"public_handle,omitempty"`
	TransitionID         string     `json:"transition_id"`
	Sequence             int        `json:"sequence"`
	SummaryVersion       int        `json:"summary_version"`
	InputVersion         int        `json:"input_version"`
	MaterialFactHash     string     `json:"material_fact_hash"`
	AssessmentID         *string    `json:"assessment_id,omitempty"`
	Lifecycle            string     `json:"lifecycle"`
	Attention            string     `json:"attention"`
	NextActor            string     `json:"next_actor"`
	NextUpdateAt         *time.Time `json:"next_update_at,omitempty"`
	Reason               string     `json:"reason"`
	JournalKind          string     `json:"journal_kind"`
	InterruptionPriority string     `json:"interruption_priority,omitempty"`
	Actor                string     `json:"actor"`
	Drill                bool       `json:"drill"`
	EvidenceRefCount     int        `json:"evidence_ref_count"`
	RecurrenceCount      int        `json:"recurrence_count"`
	EffectiveStartedAt   time.Time  `json:"effective_started_at"`
	RecoveryObservedAt   *time.Time `json:"recovery_observed_at,omitempty"`
	TerminalAt           *time.Time `json:"terminal_at,omitempty"`
	TerminalReason       string     `json:"terminal_reason,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// TransitionStreamWorker claims durable stream rows, writes one canonical
// JSON line per Transition, and acknowledges the real outcome under the
// store's own fencing.
//
// It is safe for exactly one Start/Stop lifecycle; RunOnce may additionally
// be called directly (tests, or a one-shot drain) without ever calling
// Start.
type TransitionStreamWorker struct {
	w       io.Writer
	store   TransitionStreamStore
	auditor TransitionStreamAuditSink
	cfg     TransitionStreamConfig
	now     func() time.Time
	logger  *slog.Logger

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool

	mu sync.Mutex
	// inflight holds every claim this worker currently owns, so Stop can
	// release whatever the final pass was still holding (R6).
	inflight map[string]store.TransitionStreamClaim
	// writeMu serializes writes to w: one line must never interleave with
	// another, and this writer is shared with the Finding Notifier.
	writeMu sync.Mutex

	statsMu sync.Mutex
	stats   TransitionStreamStats
}

// NewTransitionStreamWorker constructs the worker. w is typically os.Stdout;
// auditor may be nil; a nil clock falls back to the UTC wall clock and a nil
// logger to slog.Default.
func NewTransitionStreamWorker(w io.Writer, st TransitionStreamStore, cfg TransitionStreamConfig,
	auditor TransitionStreamAuditSink, clock func() time.Time, logger *slog.Logger) *TransitionStreamWorker {
	if strings.TrimSpace(cfg.Owner) == "" {
		panic("notify/stdout: transition stream worker requires a non-empty owner")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TransitionStreamWorker{
		w:        w,
		store:    st,
		auditor:  auditor,
		cfg:      cfg.withDefaults(),
		now:      clock,
		logger:   logger,
		wakeCh:   make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		inflight: map[string]store.TransitionStreamClaim{},
	}
}

// Stats returns a snapshot of the worker's bounded counters.
func (w *TransitionStreamWorker) Stats() TransitionStreamStats {
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	return w.stats
}

func (w *TransitionStreamWorker) count(f func(*TransitionStreamStats)) {
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	f(&w.stats)
}

// RunOnce runs one full round: sweep abandoned leases, then claim and emit
// up to cfg.Batch rows in durable commit order. It returns how many rows it
// acknowledged an outcome for.
func (w *TransitionStreamWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.now().UTC()
	if n, err := w.store.RecoverExpiredTransitionStreamClaims(ctx, now); err != nil {
		w.logger.Error("situation: transition stream: recover expired claims failed", "err", err)
	} else if n > 0 {
		w.logger.Info("situation: transition stream: recovered abandoned claims", "count", n)
	}

	claims, err := w.store.ClaimTransitionStream(ctx, w.cfg.Owner, now, w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: transition stream: claim rows: %w", err)
	}
	handled := 0
	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			w.release(claim) //nolint:contextcheck // by design: release uses its own detached context; ctx is already done here
			return handled, err
		}
		w.count(func(s *TransitionStreamStats) { s.Claimed++ })
		w.track(claim)
		w.emitAndAcknowledge(ctx, claim)
		w.untrack(claim)
		handled++
	}
	return handled, nil
}

// emitAndAcknowledge writes one line and records its outcome under one
// span (R8: situation.transition_stream.emit, on internal/situation's tracer
// scope via situation.Tracer(), never a second scope of this package's own).
// The span starts AFTER the claim is durable and covers only the write plus
// the outcome class, so no exporter call ever happens inside a database
// transaction.
func (w *TransitionStreamWorker) emitAndAcknowledge(ctx context.Context, claim store.TransitionStreamClaim) {
	startedAt := time.Now()
	spanCtx, span := situation.Tracer().Start(ctx, situation.SpanTransitionStreamEmit, trace.WithAttributes(
		situation.AttrSituationID.String(claim.Transition.SituationID),
		situation.AttrTransitionID.String(claim.Transition.ID),
		situation.AttrTransitionSequence.Int(claim.Transition.Sequence),
		situation.AttrSummaryVersion.Int(claim.Transition.Sequence),
	))
	defer span.End()

	emitErr := w.emit(w.w, claim)
	ackErr := w.acknowledge(spanCtx, claim, emitErr)
	span.SetAttributes(
		situation.AttrResultClass.String(streamResultClass(emitErr, ackErr)),
		situation.AttrDurationMS.Int64(time.Since(startedAt).Milliseconds()),
	)
	if ackErr != nil && !errors.Is(ackErr, store.ErrTransitionStreamClaimLost) {
		w.logger.Error("situation: transition stream: acknowledge failed",
			append([]any{"stream_id", claim.StreamID, "transition_id", claim.Transition.ID, "err", ackErr},
				situation.SpanLogAttrs(span)...)...)
		return
	}
	if emitErr == nil && ackErr == nil {
		w.logger.Debug("situation: transition stream emitted",
			append([]any{"transition_id", claim.Transition.ID, "sequence", claim.Transition.Sequence},
				situation.SpanLogAttrs(span)...)...)
	}
}

// streamResultClass maps one attempt's outcome onto the closed span result
// classes.
func streamResultClass(emitErr, ackErr error) string {
	var invalid *invalidStreamPayloadError
	switch {
	case ackErr != nil:
		return situation.StreamResultRetried
	case emitErr == nil:
		return situation.StreamResultEmitted
	case errors.As(emitErr, &invalid):
		return situation.StreamResultFailed
	default:
		return situation.StreamResultRetried
	}
}

// emit writes exactly one canonical JSON line for claim. A durable row this
// build cannot render at all is reported as an invalidStreamPayloadError error,
// the only permanent outcome; every other failure is an ordinary writer
// failure and retries.
func (w *TransitionStreamWorker) emit(out io.Writer, claim store.TransitionStreamClaim) error {
	line, err := transitionStreamLineFrom(claim.Transition, w.now().UTC())
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		return &invalidStreamPayloadError{err: fmt.Errorf("notify/stdout: marshal transition stream line: %w", err)}
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("notify/stdout: write transition stream line: %w", err)
	}
	return nil
}

// acknowledge records the durable outcome of one emit attempt: delivered,
// retried (an unavailable writer), or failed (an unrenderable durable row).
// It runs AFTER the line has already been written, which is what makes the
// stream at-least-once rather than at-most-once.
func (w *TransitionStreamWorker) acknowledge(ctx context.Context, claim store.TransitionStreamClaim, emitErr error) error {
	now := w.now().UTC()
	var invalid *invalidStreamPayloadError
	switch {
	case emitErr == nil:
		if err := w.store.MarkTransitionStreamDelivered(ctx, claim, now); err != nil {
			w.noteClaimLoss(err)
			return err
		}
		w.count(func(s *TransitionStreamStats) { s.Emitted++ })
		w.audit(ctx, AuditTransitionStreamEmitted, claim, "")
		return nil
	case errors.As(emitErr, &invalid):
		if err := w.store.FailTransitionStreamEntry(ctx, claim, streamErrorInvalid, now); err != nil {
			w.noteClaimLoss(err)
			return err
		}
		w.count(func(s *TransitionStreamStats) { s.Failed++ })
		w.logger.Error("situation: transition stream: durable row cannot be rendered; failed pending operator attention",
			"stream_id", claim.StreamID, "transition_id", claim.Transition.ID, "err", emitErr)
		w.audit(ctx, AuditTransitionStreamFailed, claim, streamErrorInvalid)
		return nil
	default:
		// The row's own durable attempt count, never the Transition's
		// sequence: sequence is an ordering position with no relationship to
		// how many times THIS row has failed.
		delay := streamRetryDelay(claim.AttemptCount, w.cfg.RetryInitial, w.cfg.RetryMax)
		if err := w.store.RetryTransitionStreamEntry(ctx, claim, streamErrorUnavailable, now.Add(delay)); err != nil {
			w.noteClaimLoss(err)
			return err
		}
		w.count(func(s *TransitionStreamStats) { s.Retried++ })
		w.logger.Warn("situation: transition stream: stdout write failed; retrying",
			"stream_id", claim.StreamID, "transition_id", claim.Transition.ID, "err", emitErr)
		return nil
	}
}

func (w *TransitionStreamWorker) noteClaimLoss(err error) {
	if errors.Is(err, store.ErrTransitionStreamClaimLost) {
		w.count(func(s *TransitionStreamStats) { s.ClaimsLost++ })
	}
}

// audit appends one bounded audit row. The payload carries identities and
// closed codes only — never the Transition's journal prose.
func (w *TransitionStreamWorker) audit(ctx context.Context, kind string, claim store.TransitionStreamClaim, errorClass string) {
	if w.auditor == nil {
		return
	}
	payload := map[string]any{
		"situation_id":  claim.Transition.SituationID,
		"transition_id": claim.Transition.ID,
		"sequence":      claim.Transition.Sequence,
		"stream_id":     claim.StreamID,
	}
	if errorClass != "" {
		payload["error_class"] = errorClass
	}
	if err := w.auditor.Append(ctx, auditActor, kind, payload); err != nil {
		w.logger.Warn("situation: transition stream: audit append failed",
			"transition_id", claim.Transition.ID, "err", err)
	}
}

// Start launches the background loop and returns immediately. Safe to call
// at most once; later calls are no-ops.
func (w *TransitionStreamWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		w.started.Store(true)
		go w.run(ctx)
	})
}

func (w *TransitionStreamWorker) run(ctx context.Context) {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.cfg.Poll)
	defer ticker.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: transition stream: round failed", "err", err)
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

// Wake nudges the background loop to run another round immediately. Never
// blocks; a coalesced Wake is harmless because due rows poll again anyway.
func (w *TransitionStreamWorker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop ends the background loop, then runs ONE bounded final pass under ctx
// and releases every claim still held (R6). This worker never joins Plan 2's
// shutdown drain rounds: it consumes already-committed history, and rows
// left pending are simply reclaimed at the next startup.
//
// Stopping a worker that was never started still runs the final pass and the
// release. Stop is idempotent.
func (w *TransitionStreamWorker) Stop(ctx context.Context) error {
	w.stopOnce.Do(func() { close(w.stopCh) })

	var loopErr error
	if w.started.Load() {
		select {
		case <-w.doneCh:
		case <-ctx.Done():
			loopErr = ctx.Err()
		}
	}
	if loopErr == nil {
		if _, err := w.RunOnce(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: transition stream: final pass failed", "err", err)
		}
	}
	for _, claim := range w.heldClaims() {
		w.release(claim) //nolint:contextcheck // by design: release uses its own detached context, so shutdown still releases when ctx is done
	}
	return loopErr
}

func (w *TransitionStreamWorker) track(claim store.TransitionStreamClaim) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inflight[claim.StreamID] = claim
}

func (w *TransitionStreamWorker) untrack(claim store.TransitionStreamClaim) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.inflight, claim.StreamID)
}

func (w *TransitionStreamWorker) heldClaims() []store.TransitionStreamClaim {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]store.TransitionStreamClaim, 0, len(w.inflight))
	for _, claim := range w.inflight {
		out = append(out, claim)
	}
	return out
}

// release hands one still-held claim straight back. It deliberately takes no
// caller context: it runs on the shutdown path, where that context is
// usually already done, and a canceled release would leave the row waiting
// out its whole lease.
func (w *TransitionStreamWorker) release(claim store.TransitionStreamClaim) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 5*time.Second)
	defer cancel()
	if err := w.store.ReleaseTransitionStreamClaim(ctx, claim); err != nil &&
		!errors.Is(err, store.ErrTransitionStreamClaimLost) {
		w.logger.Warn("situation: transition stream: release claim failed",
			"stream_id", claim.StreamID, "err", err)
	}
	w.untrack(claim)
}

// invalidStreamPayloadError marks the one permanent outcome: a durable row this
// build cannot render at all, however many times it retries.
type invalidStreamPayloadError struct{ err error }

func (e *invalidStreamPayloadError) Error() string { return e.err.Error() }
func (e *invalidStreamPayloadError) Unwrap() error { return e.err }

// transitionStreamLineFrom projects one immutable Transition onto the
// canonical stream line. A Transition that does not satisfy its own
// Validate is a hand-corrupted durable row: it can never be rendered, so it
// is reported as permanently invalid rather than retried forever.
func transitionStreamLineFrom(t model.Transition, now time.Time) (transitionStreamLine, error) {
	if err := t.Validate(); err != nil {
		return transitionStreamLine{}, &invalidStreamPayloadError{err: fmt.Errorf("notify/stdout: transition stream row: %w", err)}
	}
	line := transitionStreamLine{
		Kind:      TransitionStreamKind,
		Version:   TransitionStreamVersion,
		EmittedAt: now,
		// The Episode fold advances the summary by exactly one version per
		// Transition (migration 0017's situation_episode_summaries_monotonic
		// trigger) and Transition sequences are contiguous from one, so the
		// Episode-summary version a Transition produced IS its sequence.
		// Both are emitted because they answer different questions: the
		// sequence orders history, the summary version names the projection
		// a root card would render.
		SituationID:        t.SituationID,
		TransitionID:       t.ID,
		Sequence:           t.Sequence,
		SummaryVersion:     t.Sequence,
		InputVersion:       t.InputVersion,
		MaterialFactHash:   t.MaterialFactHash,
		AssessmentID:       t.AssessmentID,
		Lifecycle:          string(t.Lifecycle),
		Attention:          string(t.Attention),
		NextActor:          string(t.ActionContract.NextActor),
		NextUpdateAt:       t.ActionContract.NextUpdateAt,
		Reason:             string(t.Reason),
		JournalKind:        string(t.JournalKind),
		Actor:              string(t.Actor),
		Drill:              t.Drill,
		EvidenceRefCount:   len(t.EvidenceRefs),
		RecurrenceCount:    t.Journal.RecurrenceCount,
		EffectiveStartedAt: t.Projection.EffectiveStartedAt,
		RecoveryObservedAt: t.Projection.RecoveryObservedAt,
		TerminalAt:         t.Projection.TerminalAt,
		CreatedAt:          t.CreatedAt,
	}
	if t.InterruptionPriority != nil {
		line.InterruptionPriority = string(*t.InterruptionPriority)
	}
	if t.Projection.PublicHandle != nil {
		line.PublicHandle = *t.Projection.PublicHandle
	}
	if t.Projection.TerminalReason != nil {
		line.TerminalReason = string(*t.Projection.TerminalReason)
	}
	return line, nil
}

// streamRetryDelay is the bounded exponential retry schedule. It has no
// terminal value at any attempt count: an unavailable stdout is retried, not
// dead-lettered.
func streamRetryDelay(attempt int, initial, maxDelay time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := maxDelay
	if shift := attempt - 1; shift < 32 {
		if scaled := initial << uint(shift); scaled > 0 && scaled < maxDelay { // #nosec G115 -- shift < 32 checked immediately above
			delay = scaled
		}
	}
	return delay
}
