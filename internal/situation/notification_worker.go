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
	"sync/atomic"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 7: the Situation notification delivery worker — the single
// reachable Slack writer for Situation history.
//
// It owns exactly four things: claiming durable notification intents under
// a fenced lease, calling the deliverer once per claim, acknowledging the
// real outcome durably, and driving the installation-level Delivery-gap
// state machine (ordinary delay -> open generation -> replaying ->
// complete). It decides no publication policy (that is Task 4's
// BuildTransitions/PlanNotificationIntents inside the authoritative
// commit), renders nothing (Task 6), and never supersedes a root
// projection itself: root supersession happens inside Task 5's fenced
// controller commit, and this worker only ever DETECTS that it lost a
// claim to one (R4).
//
// Valid effects retry indefinitely. There is no attempt ceiling anywhere
// in this file: only an invalid durable intent (a programming/data error
// the deliverer proves) becomes `failed`, and even that is explicitly
// operator-redriveable.
// ----------------------------------------------------------------------

var (
	// ErrNotificationClaimLost means a fenced acknowledgement named a
	// claim that is no longer the intent's current one: the lease expired
	// and was swept or reclaimed, the intent was released, or another
	// holder's token superseded this one. The write changed zero rows.
	ErrNotificationClaimLost = errors.New("situation: notification claim lost")

	// ErrNotificationIntentSuperseded means the claimed root projection was
	// superseded by a newer one inside a concurrent authoritative commit
	// while this worker was mid-flight (R4). It is the expected outcome of
	// that race, not a delivery failure: the newer projection renders what
	// this one would have, and a superseded intent can never become
	// delivered.
	ErrNotificationIntentSuperseded = errors.New("situation: notification intent superseded")
)

// NotificationClaim is one durable notification intent leased to this
// worker, together with the fencing pair every acknowledgement must carry.
type NotificationClaim struct {
	Intent     model.NotificationIntent
	ClaimOwner string
	ClaimToken int64
}

// NotificationDelivery is the durable Slack coordinate and delivery mode one
// completed Deliver call reports.
//
// NotificationDelivery, not Delivery: situation.Delivery is Plan 2's alert
// delivery type in snapshot.go (R7).
type NotificationDelivery struct {
	Channel     string
	MessageTS   string
	DeliveredAs string // root | thread | broadcast | delayed_thread | system
}

// SlackDeliveryState is the bounded installation-level Slack delivery health
// snapshot the worker reads once per round to decide whether to probe, open
// a gap, or reactivate configuration-blocked work.
type SlackDeliveryState struct {
	// FirstFailureAt anchors the current CONTINUOUS failure window. Nil
	// means Slack delivery is currently healthy. It is set by the first
	// retryable/configuration failure and cleared by any success — it never
	// slides forward while failures continue.
	FirstFailureAt *time.Time
	LastSuccessAt  *time.Time
	// OpenGapGeneration is the generation currently open or replaying, nil
	// when none is. OpenGapStatus is that generation's status ("open" or
	// "replaying"), empty when there is none.
	OpenGapGeneration *string
	OpenGapStatus     string
	// ConfigurationGeneration is the durable Slack-configuration generation.
	// Startup with corrected configuration increments it and returns
	// blocked intents to pending.
	ConfigurationGeneration int64
	// BlockedConfigurationCount is how many intents are currently held in
	// blocked_configuration.
	BlockedConfigurationCount int
	LastWarningAt             *time.Time
	UpdatedAt                 time.Time
}

// NotificationStore is the durable notification-intent and Delivery-gap
// surface the worker drives. *store.Store implements it.
//
// The first fourteen methods are the plan's Cross-Task contract verbatim.
// GetSlackDeliveryState and CompleteDeliveryGap are additive: the worker
// cannot decide "probe while a failure window or gap exists" or "mark the
// generation complete only when no replayable intent remains" without
// them, and both are bounded reads/writes over the same two tables.
//
//nolint:interfacebloat // one durable ledger's whole lifecycle, deliberately: splitting it would let a partial implementation claim work it cannot acknowledge.
type NotificationStore interface {
	RecoverExpiredNotificationClaims(ctx context.Context, now time.Time) (int, error)
	HeartbeatNotificationClaim(ctx context.Context, claim NotificationClaim, now time.Time, lease time.Duration) error
	ReleaseNotificationClaim(ctx context.Context, claim NotificationClaim, now time.Time) error
	ReactivateConfigurationBlocked(ctx context.Context, configurationGeneration int64, now time.Time) (int, error)
	RedriveFailedNotificationIntent(ctx context.Context, intentID string, now time.Time) error
	ObserveSlackFailure(ctx context.Context, errorClass string, now time.Time) error
	ObserveSlackSuccess(ctx context.Context, now time.Time) error
	OpenDueDeliveryGap(ctx context.Context, now time.Time, threshold time.Duration) (bool, error)
	RecoverDeliveryGap(ctx context.Context, now time.Time) (string, bool, error)
	ClaimNotificationIntents(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]NotificationClaim, error)
	MarkNotificationDelivered(ctx context.Context, claim NotificationClaim, delivery NotificationDelivery, now time.Time) error
	RetryNotificationIntent(ctx context.Context, claim NotificationClaim, errorClass string, retryAt time.Time) error
	BlockNotificationConfiguration(ctx context.Context, claim NotificationClaim, errorClass string, now time.Time) error
	FailNotificationIntent(ctx context.Context, claim NotificationClaim, errorClass string, now time.Time) error

	GetSlackDeliveryState(ctx context.Context) (SlackDeliveryState, error)
	CompleteDeliveryGap(ctx context.Context, now time.Time) (string, bool, error)
}

// NotificationDeliverer renders and sends exactly one Slack call per intent
// and reports Slack readiness. cmd/alertint's SituationDeliverer (Task 6)
// implements it; it writes no Store state of its own.
type NotificationDeliverer interface {
	Probe(ctx context.Context) error
	Deliver(ctx context.Context, intent model.NotificationIntent) (NotificationDelivery, error)
}

// ----------------------------------------------------------------------
// Failure classification.
// ----------------------------------------------------------------------

// DeliveryErrorClass is the closed classification the worker resolves every
// failed Deliver/Probe call into. It mirrors the Slack client's own
// classification (internal/notify/slack.ErrorClass) without this package
// depending on it: the deliverer adapter, which already owns the Slack
// wire, translates.
type DeliveryErrorClass string

const (
	// DeliveryRetryable covers transport failures, 5xx, rate limiting, and
	// every uncertain outcome. It retries indefinitely.
	DeliveryRetryable DeliveryErrorClass = "retryable"
	// DeliveryConfigurationBlocking covers a definite token/scope/channel/
	// authentication rejection. It is durable, keeps its attempts, and
	// waits for a corrected configuration generation — never exhausted.
	DeliveryConfigurationBlocking DeliveryErrorClass = "configuration_blocking"
	// DeliveryInvalid covers an invalid durable intent or another
	// non-recoverable programming/data error this build proved. It is the
	// only class that becomes `failed`, and even that is redriveable.
	DeliveryInvalid DeliveryErrorClass = "invalid"
)

// DeliveryFailure is the classification a deliverer error may carry. An
// error that does not implement it is treated as retryable: this worker
// never dead-letters durable operator history on an error it cannot prove
// is permanent.
type DeliveryFailure interface {
	error
	// DeliveryErrorClass reports which closed outcome this failure is.
	DeliveryErrorClass() DeliveryErrorClass
	// DeliveryErrorCode is the bounded, lowercase-identifier error class
	// recorded on the intent (never raw error text or a provider body).
	DeliveryErrorCode() string
	// DeliveryRetryAfter is the provider-requested wait, or zero.
	DeliveryRetryAfter() time.Duration
}

// classifyDeliveryFailure resolves err into (class, bounded code, retry
// hint). An unclassified error is retryable with the generic code
// "delivery_failed" — nothing that cannot prove itself permanent may ever
// close a delivery obligation.
func classifyDeliveryFailure(err error) (DeliveryErrorClass, string, time.Duration) {
	var failure DeliveryFailure
	if errors.As(err, &failure) {
		code := boundedErrorCode(failure.DeliveryErrorCode())
		switch failure.DeliveryErrorClass() {
		case DeliveryConfigurationBlocking:
			return DeliveryConfigurationBlocking, code, 0
		case DeliveryInvalid:
			return DeliveryInvalid, code, 0
		case DeliveryRetryable:
			return DeliveryRetryable, code, failure.DeliveryRetryAfter()
		default:
			// An unknown class is not proof of a permanent condition.
			return DeliveryRetryable, code, failure.DeliveryRetryAfter()
		}
	}
	return DeliveryRetryable, defaultDeliveryErrorCode, 0
}

// defaultDeliveryErrorCode is what an unclassified or unusable error code
// records as.
const defaultDeliveryErrorCode = "delivery_failed"

// maxDeliveryErrorCode mirrors the store's own last_error_class bound.
const maxDeliveryErrorCode = 64

// boundedErrorCode coerces a deliverer's error code into the closed
// lowercase-identifier shape the durable last_error_class column accepts,
// so no deliverer — including a third-party one — can ever make an
// acknowledgement unwritable, and no raw error text can reach the column.
func boundedErrorCode(code string) string {
	out := make([]rune, 0, len(code))
	for _, r := range strings.ToLower(strings.TrimSpace(code)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
		if len(out) == maxDeliveryErrorCode {
			break
		}
	}
	if len(out) == 0 || out[0] < 'a' || out[0] > 'z' {
		return defaultDeliveryErrorCode
	}
	return string(out)
}

// ----------------------------------------------------------------------
// Deterministic gap identities.
// ----------------------------------------------------------------------

// NewGapGenerationID derives the stable identity of the Delivery-gap
// generation opening over the continuous failure window that began at
// firstFailureAt. Deriving it from the window's own anchor (rather than a
// fresh random ID) makes gap opening idempotent: two racing openers compute
// the same primary key, so exactly one row can exist per outage window.
func NewGapGenerationID(firstFailureAt time.Time) string {
	return intentIdentity("slack_delivery_gap:" + firstFailureAt.UTC().Format(time.RFC3339Nano))
}

// GapRecoveryIntent builds the one bounded ADR-0042 System notice that
// precedes gapGeneration's backlog replay. Its identity is derived from the
// generation, so recovering the same generation twice can only ever produce
// the same row.
func GapRecoveryIntent(gapGeneration string, now time.Time) (model.NotificationIntent, error) {
	key := boundedText("installation_gap_recovery:"+gapGeneration, maxHistoryIdentifier)
	generation := gapGeneration
	intent := model.NotificationIntent{
		ID:              intentIdentity("intent:" + key),
		IdempotencyKey:  key,
		EffectClass:     model.EffectInstallationGapRecovery,
		GapGeneration:   &generation,
		ClientMessageID: intentIdentity("client_message:" + key),
		Status:          model.IntentPending,
		CreatedAt:       now.UTC(),
	}
	if err := intent.Validate(); err != nil {
		return model.NotificationIntent{}, fmt.Errorf("situation: gap recovery intent: %w", err)
	}
	return intent, nil
}

// ----------------------------------------------------------------------
// Worker configuration.
// ----------------------------------------------------------------------

const (
	defaultNotificationPoll         = time.Second
	defaultNotificationLease        = 300 * time.Second
	defaultNotificationHeartbeat    = 30 * time.Second
	defaultNotificationBatch        = 25
	defaultNotificationRetryInitial = 5 * time.Second
	defaultNotificationRetryMax     = 300 * time.Second
	defaultNotificationJitter       = 0.2
	// defaultDeliveryGapThreshold is the spec's fixed five continuous
	// minutes of failure before a durable Delivery gap opens. It is a
	// constant of the protocol, not an operator knob; the field exists so
	// tests can compress it.
	defaultDeliveryGapThreshold = 5 * time.Minute
	// notificationWarnCadence paces the bounded retry WARNs while an
	// outage continues, so an hour-long Slack outage costs a handful of
	// lines rather than one per attempt.
	notificationWarnCadence = time.Minute
)

// NotificationWorkerConfig controls the worker's lease fencing, poll
// cadence, batch size, retry schedule, and gap threshold. It deliberately
// has NO maximum-attempts field: valid Slack effects retry indefinitely.
type NotificationWorkerConfig struct {
	// Owner identifies this worker instance to the store's lease fencing.
	// Required — there is no default.
	Owner string
	// Poll is how often the background loop wakes on its own. Default 1s.
	Poll time.Duration
	// Lease is how long a claimed intent is held before another worker (or
	// this worker's own recovery sweep) may reclaim it. Default 300s.
	Lease time.Duration
	// Heartbeat is how often an in-flight claim's lease is renewed.
	// Default 30s, well under Lease.
	Heartbeat time.Duration
	// Batch bounds how many intents one round claims. Default 25.
	Batch int
	// RetryInitial and RetryMax bound the exponential retry schedule.
	// Defaults 5s and 300s.
	RetryInitial time.Duration
	RetryMax     time.Duration
	// JitterFraction spreads each retry by +/- this fraction. Default 0.2.
	JitterFraction float64
	// GapThreshold is how long failures must stay continuous before a
	// durable Delivery gap opens. Default 5m.
	GapThreshold time.Duration
	// Rand is the [0,1) source the retry jitter reads. Default rand.Float64.
	Rand func() float64
}

func (c NotificationWorkerConfig) withDefaults() NotificationWorkerConfig {
	if c.Poll <= 0 {
		c.Poll = defaultNotificationPoll
	}
	if c.Lease <= 0 {
		c.Lease = defaultNotificationLease
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = defaultNotificationHeartbeat
	}
	if c.Batch <= 0 {
		c.Batch = defaultNotificationBatch
	}
	if c.RetryInitial <= 0 {
		c.RetryInitial = defaultNotificationRetryInitial
	}
	if c.RetryMax <= 0 {
		c.RetryMax = defaultNotificationRetryMax
	}
	if c.JitterFraction < 0 || c.JitterFraction >= 1 {
		c.JitterFraction = defaultNotificationJitter
	}
	if c.GapThreshold <= 0 {
		c.GapThreshold = defaultDeliveryGapThreshold
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	return c
}

// NotificationWorkerStats is the bounded counter set the worker exposes for
// logs and (Task 9) MCP delivery-state fields. Plan 3 adds no OTel metric
// instruments (R8), so these are the operational signal.
type NotificationWorkerStats struct {
	Claimed       int64
	Delivered     int64
	Retried       int64
	Blocked       int64
	Failed        int64
	Superseded    int64
	ClaimsLost    int64
	Probes        int64
	ProbeFailures int64
	GapsOpened    int64
	GapsRecovered int64
	GapsCompleted int64
	Reactivated   int64
}

// NotificationWorker polls the durable notification-intent ledger, claims
// due intents under a fenced lease, delivers each one exactly once per
// claim, and drives the Delivery-gap state machine.
//
// It is safe for exactly one Start/Stop lifecycle; RunOnce may additionally
// be called directly (tests, or a one-shot drain) without ever calling
// Start.
type NotificationWorker struct {
	store     NotificationStore
	deliverer NotificationDeliverer
	cfg       NotificationWorkerConfig
	now       Clock
	logger    *slog.Logger

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	// configurationReactivated is this PROCESS's one-shot guard for the
	// startup configuration reactivation. See ReactivateConfiguration.
	configurationReactivated atomic.Bool

	mu sync.Mutex
	// inflight holds every claim this worker currently owns, so Stop can
	// release whatever the final pass was still holding (R6).
	inflight map[string]NotificationClaim
	// probeFailures drives the probe's own backoff, and lastProbeAt/
	// lastWarnAt pace probing and retry WARNs. All worker-local: the
	// durable record of the outage is slack_delivery_state.
	probeFailures int
	lastProbeAt   time.Time
	lastWarnAt    time.Time
	probedOnce    bool

	stats   NotificationWorkerStats
	statsMu sync.Mutex
}

// NewNotificationWorker creates a NotificationWorker. A nil clock falls back
// to the UTC wall clock; a nil logger falls back to slog.Default.
func NewNotificationWorker(store NotificationStore, deliverer NotificationDeliverer,
	cfg NotificationWorkerConfig, clock Clock, logger *slog.Logger) *NotificationWorker {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &NotificationWorker{
		store:     store,
		deliverer: deliverer,
		cfg:       cfg.withDefaults(),
		now:       clock,
		logger:    logger,
		wakeCh:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		inflight:  map[string]NotificationClaim{},
	}
}

// Stats returns a snapshot of the worker's bounded counters.
func (w *NotificationWorker) Stats() NotificationWorkerStats {
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	return w.stats
}

func (w *NotificationWorker) count(f func(*NotificationWorkerStats)) {
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	f(&w.stats)
}

// RunOnce runs one full delivery round: recover abandoned claims, advance
// the Delivery-gap state machine, then claim and deliver up to cfg.Batch
// intents sequentially. It returns how many intents it actually delivered
// an acknowledgement for.
func (w *NotificationWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.now().UTC()

	if n, err := w.store.RecoverExpiredNotificationClaims(ctx, now); err != nil {
		w.logger.Error("situation: notification worker: recover expired claims failed", "err", err)
	} else if n > 0 {
		w.logger.Info("situation: notification worker: recovered abandoned claims", "count", n)
	}

	state, err := w.store.GetSlackDeliveryState(ctx)
	if err != nil {
		return 0, fmt.Errorf("situation: notification worker: read slack delivery state: %w", err)
	}
	w.advanceGapState(ctx, state, now)

	claims, err := w.store.ClaimNotificationIntents(ctx, w.cfg.Owner, now, w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, fmt.Errorf("situation: notification worker: claim notification intents: %w", err)
	}
	handled := 0
	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			w.releaseClaim(claim) //nolint:contextcheck // by design: releaseClaim uses its own detachedWriteContext; ctx is already done here
			return handled, err
		}
		w.count(func(s *NotificationWorkerStats) { s.Claimed++ })
		w.processOne(ctx, claim)
		handled++
	}
	return handled, nil
}

// advanceGapState drives the whole gap lifecycle for one round: probe while
// a failure window or gap exists, open a generation once failures have been
// continuous for the threshold, recover it once Slack answers again, and
// complete it once nothing replayable remains.
func (w *NotificationWorker) advanceGapState(ctx context.Context, state SlackDeliveryState, now time.Time) {
	if w.shouldProbe(state, now) {
		w.probe(ctx, state, now)
	}
	if state.FirstFailureAt != nil {
		opened, err := w.store.OpenDueDeliveryGap(ctx, now, w.cfg.GapThreshold)
		if err != nil {
			w.logger.Error("situation: notification worker: open delivery gap failed", "err", err)
		} else if opened {
			w.count(func(s *NotificationWorkerStats) { s.GapsOpened++ })
			w.logger.Warn("situation: notification worker: slack delivery gap opened",
				"first_failure_at", state.FirstFailureAt.Format(time.RFC3339),
				"continuous_for", now.Sub(*state.FirstFailureAt).String())
		}
	}
	// Bounded: at most one completion per round keeps this cheap, and a
	// second finished generation completes on the next tick.
	if generation, done, err := w.store.CompleteDeliveryGap(ctx, now); err != nil {
		w.logger.Error("situation: notification worker: complete delivery gap failed", "err", err)
	} else if done {
		w.count(func(s *NotificationWorkerStats) { s.GapsCompleted++ })
		w.logger.Info("situation: notification worker: slack delivery gap replay complete", "gap_generation", generation)
	}
}

// shouldProbe answers the spec's "probe while configuration is blocked or a
// failure window/gap exists", plus exactly one probe on the worker's first
// round so corrected startup configuration is noticed without waiting for a
// delivery to fail again. Probes back off with the same exponential
// schedule retries use, so an hour-long outage costs a handful of calls.
func (w *NotificationWorker) shouldProbe(state SlackDeliveryState, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.probedOnce {
		return true
	}
	// A REPLAYING generation is a recovered one: its own deliveries prove
	// Slack health. Durably blocked configuration justifies probing only
	// until this process has applied its startup correction — after that a
	// probe can no longer change the outcome (only a restart with corrected
	// configuration can), and probing on it forever is the treadmill this
	// worker must not run.
	blockedStillMatters := state.BlockedConfigurationCount > 0 && !w.configurationReactivated.Load()
	if state.FirstFailureAt == nil && state.OpenGapStatus != "open" && !blockedStillMatters {
		return false
	}
	wait := notificationRetryDelay(w.probeFailures, 0, w.cfg.RetryInitial, w.cfg.RetryMax, 0, 0)
	return !now.Before(w.lastProbeAt.Add(wait))
}

// probe asks the deliverer whether Slack is usable and applies the outcome:
// a success clears the failure window, reactivates configuration-blocked
// intents, and moves any open gap into replay; a failure keeps the window
// continuous.
func (w *NotificationWorker) probe(ctx context.Context, state SlackDeliveryState, now time.Time) {
	w.mu.Lock()
	w.probedOnce = true
	w.lastProbeAt = now
	w.mu.Unlock()
	w.count(func(s *NotificationWorkerStats) { s.Probes++ })

	if err := w.deliverer.Probe(ctx); err != nil {
		w.mu.Lock()
		w.probeFailures++
		w.mu.Unlock()
		w.count(func(s *NotificationWorkerStats) { s.ProbeFailures++ })
		class, code, _ := classifyDeliveryFailure(err)
		if class != DeliveryInvalid {
			w.observeFailure(ctx, state, code, now)
		}
		return
	}

	w.mu.Lock()
	w.probeFailures = 0
	w.mu.Unlock()
	if err := w.store.ObserveSlackSuccess(ctx, now); err != nil {
		w.logger.Error("situation: notification worker: record slack success failed", "err", err)
	}
	if _, err := w.ReactivateConfiguration(ctx); err != nil {
		w.logger.Error("situation: notification worker: reactivate configuration-blocked intents failed", "err", err)
	}
	if generation, recovered, err := w.store.RecoverDeliveryGap(ctx, now); err != nil {
		w.logger.Error("situation: notification worker: recover delivery gap failed", "err", err)
	} else if recovered {
		w.count(func(s *NotificationWorkerStats) { s.GapsRecovered++ })
		w.logger.Warn("situation: notification worker: slack delivery recovered; replaying gap",
			"gap_generation", generation)
	}
}

// ReactivateConfiguration applies corrected Slack configuration exactly ONCE
// per process: it advances the durable configuration generation and returns
// every eligible blocked_configuration intent to pending. It reports how
// many it reactivated, and (0, nil) once this process has already done it.
//
// Once per process, not once per successful probe, because Probe is only
// auth.test — it proves the TOKEN works and says nothing about the channel.
// With a valid token and a misconfigured channel, reactivating on every
// probe is a permanent loop: reactivate, claim, get channel_not_found, block,
// reactivate. That grows the configuration generation and every intent's
// attempt count without bound, and resets the continuous-failure window each
// cycle so a real Delivery gap can never open. spec.md ties this to startup —
// "Startup with corrected configuration increments a durable configuration
// generation" — and only a restart can actually change the configuration a
// blocked intent is blocked on.
//
// The worker calls this itself on its first successful probe (its startup
// probe). It is exported and idempotent so Task 9's startup sequence can
// instead drive it explicitly at step 5 of spec.md's startup order, before
// Receivers start; whichever runs first applies the correction.
func (w *NotificationWorker) ReactivateConfiguration(ctx context.Context) (int, error) {
	if w.configurationReactivated.Swap(true) {
		return 0, nil
	}
	state, err := w.store.GetSlackDeliveryState(ctx)
	if err != nil {
		return 0, fmt.Errorf("situation: notification worker: read slack delivery state: %w", err)
	}
	if state.BlockedConfigurationCount == 0 {
		return 0, nil
	}
	generation := state.ConfigurationGeneration + 1
	n, err := w.store.ReactivateConfigurationBlocked(ctx, generation, w.now().UTC())
	if err != nil {
		return 0, fmt.Errorf("situation: notification worker: reactivate configuration-blocked intents: %w", err)
	}
	if n > 0 {
		w.count(func(s *NotificationWorkerStats) { s.Reactivated += int64(n) })
		w.logger.Info("situation: notification worker: slack configuration corrected; reactivated blocked intents",
			"count", n, "configuration_generation", generation)
	}
	return n, nil
}

// observeFailure records one Slack failure against the continuous window and
// emits the bounded WARNs the console action trail expects: one on the first
// failure of a window, then paced retry WARNs — never one per attempt.
func (w *NotificationWorker) observeFailure(ctx context.Context, state SlackDeliveryState, code string, now time.Time) {
	if err := w.store.ObserveSlackFailure(ctx, code, now); err != nil {
		w.logger.Error("situation: notification worker: record slack failure failed", "err", err)
		return
	}
	if state.FirstFailureAt == nil {
		w.mu.Lock()
		w.lastWarnAt = now
		w.mu.Unlock()
		w.logger.Warn("situation: notification worker: slack delivery failing; effects are delayed",
			"error_class", code)
		return
	}
	w.mu.Lock()
	due := now.Sub(w.lastWarnAt) >= notificationWarnCadence
	if due {
		w.lastWarnAt = now
	}
	w.mu.Unlock()
	if due {
		w.logger.Warn("situation: notification worker: slack delivery still failing",
			"error_class", code, "continuous_for", now.Sub(*state.FirstFailureAt).String())
	}
}

// processOne delivers exactly one claimed intent and acknowledges the real
// outcome. The Slack call happens outside every database transaction, under
// a heartbeat that abandons the attempt if the lease moves on.
func (w *NotificationWorker) processOne(ctx context.Context, claim NotificationClaim) {
	w.trackClaim(claim)
	defer w.untrackClaim(claim)

	deliverCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var leaseLost atomic.Bool
	hbDone := make(chan struct{})
	go w.heartbeatLoop(deliverCtx, cancel, claim, &leaseLost, hbDone)

	delivery, deliverErr := w.deliverer.Deliver(deliverCtx, claim.Intent)

	cancel()
	<-hbDone

	if leaseLost.Load() {
		// The lease moved on mid-flight (a sweep reclaimed it, or a
		// concurrent commit superseded this root projection). Acknowledging
		// now would race whatever owns the row; the durable outcome is
		// whatever that owner writes.
		w.count(func(s *NotificationWorkerStats) { s.ClaimsLost++ })
		w.logger.Warn("situation: notification worker: lease lost mid-delivery; abandoning claim",
			"intent_id", claim.Intent.ID, "effect_class", string(claim.Intent.EffectClass))
		return
	}

	// The acknowledgement must land even when the delivery context was
	// canceled, or a completed Slack call would be replayed forever.
	writeCtx, writeCancel := detachedWriteContext()
	defer writeCancel()
	now := w.now().UTC()

	if deliverErr == nil {
		w.acknowledgeDelivered(writeCtx, claim, delivery, now) //nolint:contextcheck // by design: detached from the possibly-canceled delivery context
		return
	}
	w.acknowledgeFailure(writeCtx, claim, deliverErr, now) //nolint:contextcheck // by design: detached from the possibly-canceled delivery context
}

func (w *NotificationWorker) acknowledgeDelivered(ctx context.Context, claim NotificationClaim,
	delivery NotificationDelivery, now time.Time) {
	// Slack answered, so the dependency is healthy regardless of whether
	// this particular intent's row was still ours to write.
	if err := w.store.ObserveSlackSuccess(ctx, now); err != nil {
		w.logger.Error("situation: notification worker: record slack success failed", "err", err)
	}
	err := w.store.MarkNotificationDelivered(ctx, claim, delivery, now)
	switch {
	case err == nil:
		w.count(func(s *NotificationWorkerStats) { s.Delivered++ })
	case errors.Is(err, ErrNotificationIntentSuperseded):
		// R4: a newer root projection replaced this one mid-flight. The
		// message that just went out is the older projection's; the newer
		// one edits the same root next round. Expected, not a failure.
		w.count(func(s *NotificationWorkerStats) { s.Superseded++ })
		w.logger.Info("situation: notification worker: root projection superseded mid-delivery",
			"intent_id", claim.Intent.ID, "situation_id", derefString(claim.Intent.SituationID))
	case errors.Is(err, ErrNotificationClaimLost):
		w.count(func(s *NotificationWorkerStats) { s.ClaimsLost++ })
		w.logger.Warn("situation: notification worker: delivered acknowledgement lost its claim",
			"intent_id", claim.Intent.ID)
	default:
		w.logger.Error("situation: notification worker: acknowledge delivery failed",
			"intent_id", claim.Intent.ID, "err", err)
	}
}

func (w *NotificationWorker) acknowledgeFailure(ctx context.Context, claim NotificationClaim, deliverErr error, now time.Time) {
	class, code, retryAfter := classifyDeliveryFailure(deliverErr)

	state, stateErr := w.store.GetSlackDeliveryState(ctx)
	if stateErr != nil {
		w.logger.Error("situation: notification worker: read slack delivery state failed", "err", stateErr)
	}
	if class != DeliveryInvalid {
		// An invalid payload is this build's own bug, not a Slack outage:
		// it must never open a Delivery gap.
		w.observeFailure(ctx, state, code, now)
	}

	var ackErr error
	switch class {
	case DeliveryRetryable:
		ackErr = w.retryClaim(ctx, claim, code, retryAfter, now)
	case DeliveryConfigurationBlocking:
		ackErr = w.store.BlockNotificationConfiguration(ctx, claim, code, now)
		if ackErr == nil {
			w.count(func(s *NotificationWorkerStats) { s.Blocked++ })
			w.logger.Warn("situation: notification worker: slack configuration rejected the effect; blocking until corrected",
				"intent_id", claim.Intent.ID, "error_class", code)
		}
	case DeliveryInvalid:
		ackErr = w.store.FailNotificationIntent(ctx, claim, code, now)
		if ackErr == nil {
			w.count(func(s *NotificationWorkerStats) { s.Failed++ })
			w.logger.Error("situation: notification worker: invalid durable intent; failed pending operator redrive",
				"intent_id", claim.Intent.ID, "error_class", code)
		}
	default:
		ackErr = w.retryClaim(ctx, claim, code, retryAfter, now)
	}
	switch {
	case ackErr == nil:
	case errors.Is(ackErr, ErrNotificationIntentSuperseded), errors.Is(ackErr, ErrNotificationClaimLost):
		w.count(func(s *NotificationWorkerStats) { s.ClaimsLost++ })
	default:
		w.logger.Error("situation: notification worker: acknowledge failure outcome failed",
			"intent_id", claim.Intent.ID, "err", ackErr)
	}
}

// retryClaim schedules the next indefinite retry for one failed claim.
func (w *NotificationWorker) retryClaim(ctx context.Context, claim NotificationClaim, code string,
	retryAfter time.Duration, now time.Time) error {
	delay := notificationRetryDelay(claim.Intent.AttemptCount, retryAfter,
		w.cfg.RetryInitial, w.cfg.RetryMax, w.cfg.JitterFraction, w.cfg.Rand())
	err := w.store.RetryNotificationIntent(ctx, claim, code, now.Add(delay))
	if err == nil {
		w.count(func(s *NotificationWorkerStats) { s.Retried++ })
	}
	return err
}

// heartbeatLoop renews claim's lease until ctx is done. A failed renewal
// marks the lease lost and cancels the in-flight Slack call rather than
// letting it complete under a lease this worker no longer holds.
func (w *NotificationWorker) heartbeatLoop(ctx context.Context, cancel context.CancelFunc,
	claim NotificationClaim, leaseLost *atomic.Bool, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(w.cfg.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beatCtx, beatCancel := detachedWriteContext()
			err := w.store.HeartbeatNotificationClaim(beatCtx, claim, w.now().UTC(), w.cfg.Lease) //nolint:contextcheck // by design: detached from the possibly-canceled delivery context
			beatCancel()
			if err != nil {
				w.logger.Warn("situation: notification worker: heartbeat failed; abandoning claim",
					"intent_id", claim.Intent.ID, "err", err)
				leaseLost.Store(true)
				cancel()
				return
			}
		}
	}
}

func (w *NotificationWorker) trackClaim(claim NotificationClaim) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inflight[claim.Intent.ID] = claim
}

func (w *NotificationWorker) untrackClaim(claim NotificationClaim) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.inflight, claim.Intent.ID)
}

// releaseClaim hands one still-held claim straight back, so a shutdown never
// leaves a durable obligation waiting out a full lease. It deliberately
// takes no caller context: it runs on the shutdown/cancellation path, where
// the caller's context is usually already done, and a release that gets
// canceled would leave the intent waiting out its whole lease.
func (w *NotificationWorker) releaseClaim(claim NotificationClaim) {
	ctx, cancel := detachedWriteContext()
	defer cancel()
	if err := w.store.ReleaseNotificationClaim(ctx, claim, w.now().UTC()); err != nil &&
		!errors.Is(err, ErrNotificationClaimLost) && !errors.Is(err, ErrNotificationIntentSuperseded) {
		w.logger.Warn("situation: notification worker: release claim failed",
			"intent_id", claim.Intent.ID, "err", err)
	}
	w.untrackClaim(claim)
}

// Start launches the background loop and returns immediately. Safe to call
// at most once; later calls are no-ops.
func (w *NotificationWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		w.started.Store(true)
		go w.run(ctx)
	})
}

func (w *NotificationWorker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Poll)
	defer ticker.Stop()

	for {
		if _, err := w.RunOnce(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: notification worker: round failed", "err", err)
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
func (w *NotificationWorker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop ends the background loop, then runs ONE bounded final pass under ctx
// and releases every claim still held (R6). The notification worker never
// joins Plan 2's shutdown drain rounds: an external Slack outage must never
// hold shutdown open, and committed intents left pending are simply
// reclaimed at the next startup.
//
// Stopping a worker that was never started still runs the final pass and
// the release, rather than waiting out ctx for a loop that does not exist.
// Stop is idempotent.
func (w *NotificationWorker) Stop(ctx context.Context) error {
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
			w.logger.Error("situation: notification worker: final pass failed", "err", err)
		}
	}
	for _, claim := range w.heldClaims() {
		w.releaseClaim(claim) //nolint:contextcheck // by design: releaseClaim uses its own detachedWriteContext, so shutdown still releases when ctx is done
	}
	return loopErr
}

func (w *NotificationWorker) heldClaims() []NotificationClaim {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]NotificationClaim, 0, len(w.inflight))
	for _, claim := range w.inflight {
		out = append(out, claim)
	}
	return out
}

// notificationRetryDelay is the indefinite retry schedule: exponential from
// initial, doubling per consumed attempt, capped at maxDelay, then spread by
// +/- jitter, and finally overridden by a LONGER provider-requested
// Retry-After. It has no terminal value at any attempt count — attempt 1,
// 100, and 100000 all return a finite, bounded delay.
func notificationRetryDelay(attempt int, retryAfter, initial, maxDelay time.Duration,
	jitter, rnd float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := maxDelay
	if shift := attempt - 1; shift < 32 {
		if scaled := initial << uint(shift); scaled > 0 && scaled < maxDelay { // #nosec G115 -- shift < 32 checked immediately above
			delay = scaled
		}
	}
	if jitter > 0 {
		delay = time.Duration(float64(delay) * (1 + jitter*(2*rnd-1)))
	}
	if delay < time.Duration(0) {
		delay = initial
	}
	if retryAfter > delay {
		delay = retryAfter
	}
	return delay
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
