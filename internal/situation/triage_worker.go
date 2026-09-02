// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 7: separate Acute Analysis from its durable dispatch, and add the
// worker that owns dispatch from the new gated Triage schedule (Task 6,
// internal/store/triage_controller.go). This file is the transport-neutral
// (no internal/store import — see controller.go's own header comment: Task 6
// already made internal/store import internal/situation, so the reverse
// would cycle) contract between:
//
//   - AcuteAnalyzer (skills/acutetriage.Skill.Analyze): loads exactly the
//     bounded, immutable input a claimed attempt froze, calls the Acute
//     Triage LLM(s), and returns AcuteResult — no durable write, no outward
//     notification.
//   - AfterCommitter (skills/acutetriage.Skill.AfterCommit): best-effort
//     compatibility memory/notifier/audit effects, run only AFTER the
//     store's own completion transaction has actually committed a success.
//   - TriageWorker (this file): polls the durable schedule, claims one due
//     attempt at a time, heartbeats the lease while Analyze runs, and
//     completes/backs off/exhausts the attempt against the real result.
//
// TriageAttemptStore/TriageScheduleLister are phrased entirely in this
// package's own types (plus stdlib) so *store.Store cannot satisfy them
// directly for the three methods whose store.* return/parameter types this
// package cannot reference (ClaimIncidentTriageAttempt, CompleteIncident-
// TriageAttempt, ListDueIncidentTriage) — a thin adapter converting between
// store.ClaimedTriageAttempt/TriageFinding/TriageCompletionResult and this
// file's TriageAttemptClaim/TriageFindingInput/TriageCompletionOutcome (and
// mapping store's own ErrTriageNotDue/ErrTriageNotDecided/
// ErrTriageAttemptLeaseLost/ErrTriageAttemptCompletedDifferently onto this
// file's situation-native sentinels below; ErrNotFound is already a shared
// value via internal/situation/model, no mapping needed there) is Task 9's
// runtime-wiring job — see the Task 7 report for why that boundary is
// unavoidable, not a shortcut.
// ----------------------------------------------------------------------

// TriageAttemptClaim is the situation-native mirror of Task 6's
// store.ClaimedTriageAttempt (internal/store/triage_controller.go) — the
// frozen input Analyze receives for one claimed Acute Triage attempt.
//
// Field-shape deviations from plan.md's literal Cross-Task-Contract snippet
// (ClaimOwner, ClaimToken int64, MembershipDigest, IncidentInputDigest,
// MemberIDs, DeliveryIDs []string, LeaseExpiresAt), made because Task 6
// already built and shipped the real store-layer shape this task must match
// (see the Task 7 report for the full investigation):
//
//   - ClaimOwner -> LeaseOwner: matches ClaimedTriageAttempt's own field
//     name — this is the fenced lease's owner, not a bare tag.
//   - MemberIDs, DeliveryIDs []string (two fields) -> MemberDeliveryIDs
//     []string (one field): ClaimedTriageAttempt's memberDeliveryIDsTx
//     freezes the sorted bounded set of every alert_deliveries.id currently
//     attached to the Incident — NOT deduplicated per Alert (Task 4's
//     MembershipDigest member identity) and NOT split into a separate
//     Alert-identity list. There is no data available at claim time to
//     further split this into a distinct "member" (Alert) list without an
//     additional store query Task 6 did not build and this task's Files
//     list does not authorize adding to internal/store.
//   - StartedAt added: present on ClaimedTriageAttempt, carried through for
//     parity even though Analyze does not currently need it.
type TriageAttemptClaim struct {
	AttemptID            string
	IncidentID           string
	AttemptNumber        int
	SituationID          string
	DecisionInputVersion int
	MembershipDigest     string
	IncidentInputDigest  string
	MemberDeliveryIDs    []string
	StartedAt            time.Time
	LeaseOwner           string
	LeaseExpiresAt       time.Time
	ClaimToken           int64
}

// AcuteResult is everything one Analyze call produces: the durable Finding
// content a successful completion persists, plus the bounded, typed
// post-commit compatibility effects AfterCommit applies once the store has
// actually committed that success.
type AcuteResult struct {
	IncidentID         string
	EvidencePackDigest string
	OutputJSON         json.RawMessage
	AnalysisName       string
	Summary            string
	RootCause          string
	Confidence         float64
	EnrichmentJSON     string
	AlertRoles         map[string]string
	PostCommit         PostCommitData
}

// MemoryUpdate is one bounded, typed post-commit memory action. Operation is
// a closed, package-private-by-convention code (see
// skills/acutetriage/result.go's memoryOpIncrementRefuteMarks/
// memoryOpClearRefuteMarks) that AfterCommit interprets — never free text,
// never a raw store call embedded in the value itself.
type MemoryUpdate struct {
	IncidentID string
	Operation  string
}

// AuditRecord is one sanitized, already-bounded audit entry Analyze derived
// but did not itself append (it is not "terminal" audit state — see the
// Task 7 report) — AfterCommit appends it only once the corresponding
// durable effect (a persisted Finding, a memory mark) has actually landed.
type AuditRecord struct {
	Actor   string
	Kind    string
	Payload json.RawMessage
}

// PostCommitData contains only bounded, typed memory actions, sanitized
// audit records, and a bounded JSON encoding of the already-derived
// compatibility Finding — never model evidence, never a provider body. This
// keeps internal/situation independent of internal/notify and
// internal/store, avoiding an import cycle: CompatibilityFindingJSON is
// opaque bytes to this package. skills/acutetriage both writes it (Analyze,
// by marshaling a package-local DTO) and reads it back (AfterCommit).
type PostCommitData struct {
	CompatibilityFindingJSON json.RawMessage
	MemoryUpdates            []MemoryUpdate
	AuditRecords             []AuditRecord
}

// AcuteAnalyzer loads a claimed attempt's frozen input, calls the Acute
// Triage LLM(s), and returns AcuteResult. It must never itself write durable
// Triage/Finding state or call outward (notifier, audit sink) — Global
// Constraint: "No connector, LLM, Slack, notifier, audit sink, or OTel
// exporter call occurs inside a database transaction," and Analyze runs
// entirely outside any transaction, before the store's own completion
// commits. skills/acutetriage.Skill implements this via its Analyze method.
type AcuteAnalyzer interface {
	Analyze(context.Context, TriageAttemptClaim) (AcuteResult, error)
}

// AfterCommitter runs best-effort compatibility memory/notifier/audit
// effects for one AcuteResult, after the store's own completion transaction
// has committed a genuine success. It must never be called for a stale
// completion (spec.md: a stale attempt "persists no Finding, first-judgment
// time, Incident output projection, role, memory action, or notifier
// effect") — TriageWorker enforces that by construction: it only calls
// AfterCommit when CompleteIncidentTriageAttempt itself reports
// TriageCompletionSuccess. skills/acutetriage.Skill implements this via its
// AfterCommit method. May be nil (post-commit effects disabled — tests
// only); TriageWorker treats a nil AfterCommitter as a no-op.
type AfterCommitter interface {
	AfterCommit(ctx context.Context, result AcuteResult) error
}

// ErrCleanSkip is AcuteAnalyzer's typed "nothing to analyze" outcome — a
// deterministic clean skip (too few member alerts to trigger analysis),
// never a transient failure. Analyze returns this explicitly rather than a
// zero AcuteResult with a nil error, so every caller (skills/acutetriage's
// own Run compatibility wrapper, and TriageWorker) must branch on it
// instead of silently treating "nothing happened" as success. Defined here
// (not in skills/acutetriage) so TriageWorker can recognize it with
// errors.Is without importing skills/acutetriage, which would cycle back
// through this package (skills/acutetriage already imports
// internal/situation for AcuteResult/TriageAttemptClaim/AcuteAnalyzer
// itself). skills/acutetriage/result.go aliases this as its own
// acutetriage.ErrCleanSkip for ergonomic use at that call site.
var ErrCleanSkip = errors.New("situation: acute triage found nothing to analyze")

// ----------------------------------------------------------------------
// Store-facing contract (situation-native types only).
// ----------------------------------------------------------------------

// TriageFindingInput is the bounded Finding content CompleteIncidentTriage-
// Attempt persists on a current-compatible success — the situation-native
// mirror of store.TriageFinding (Task 6), field-for-field.
type TriageFindingInput struct {
	OutputJSON         string
	Summary            string
	RootCause          string
	Confidence         float64
	EnrichmentJSON     string
	EvidencePackDigest string
}

// TriageCompletionOutcome is the situation-native mirror of
// store.TriageCompletionOutcome — a closed set of plain string values, so no
// store import is needed to share them; the values match exactly.
type TriageCompletionOutcome string

const (
	TriageCompletionSuccess            TriageCompletionOutcome = "success"
	TriageCompletionStaleMembership    TriageCompletionOutcome = "stale_membership"
	TriageCompletionStaleIncidentInput TriageCompletionOutcome = "stale_incident_input"
)

// Sentinel errors a TriageAttemptStore implementation must return (wrapped
// or bare, checkable with errors.Is) for the outcomes store.
// ClaimIncidentTriageAttempt/CompleteIncidentTriageAttempt distinguish that
// this package cannot share directly. model.ErrNotFound (already a shared
// value: internal/store.ErrNotFound is a value alias of it) covers the
// "no such claimable row" / "not found" case — no situation-native
// duplicate is needed for that one.
var (
	// ErrTriageAttemptNotDue mirrors store.ErrTriageNotDue: the row exists
	// and is claimable, just not yet.
	ErrTriageAttemptNotDue = errors.New("situation: incident triage attempt not yet due")
	// ErrTriageAttemptNotDecided mirrors store.ErrTriageNotDecided: the row
	// has never received a controller decision (e.g. a migrated legacy row
	// before Task 6's startup backfill has run).
	ErrTriageAttemptNotDecided = errors.New("situation: incident triage attempt has no controller decision to claim against")
	// ErrTriageAttemptLeaseLost mirrors store.ErrTriageAttemptLeaseLost: a
	// fenced write named a lease that no longer matches the current holder.
	ErrTriageAttemptLeaseLost = errors.New("situation: incident triage attempt lease lost")
	// ErrTriageAttemptCompletedDifferently mirrors
	// store.ErrTriageAttemptCompletedDifferently: a replayed completion
	// named an attempt already completed with different content.
	ErrTriageAttemptCompletedDifferently = errors.New("situation: incident triage attempt already completed with different content")
)

// TriageAttemptStore is the narrow claim/extend/complete/backoff/exhaust
// surface TriageWorker depends on, phrased entirely in this package's own
// types so it never needs to import internal/store. Every method here
// mirrors one of Task 6's internal/store/triage_controller.go methods
// exactly in intent; RecoverExpiredIncidentTriageAttempts/
// ExtendIncidentTriageLease/BackoffIncidentTriageAttempt/
// ExhaustIncidentTriageAttempt already use only primitive types, so
// *store.Store satisfies those four directly — only Claim/Complete need a
// real adapter (see this file's header comment).
type TriageAttemptStore interface {
	// ClaimIncidentTriageAttempt claims incidentID's due pending/backoff
	// row. Returns model.ErrNotFound if the row is not currently
	// pending/backoff for a ready Incident, ErrTriageAttemptNotDue if it is
	// pending/backoff but not yet due, or ErrTriageAttemptNotDecided if it
	// has never received a controller decision.
	ClaimIncidentTriageAttempt(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (TriageAttemptClaim, error)

	// ExtendIncidentTriageLease renews a claimed attempt's lease. Returns
	// ErrTriageAttemptLeaseLost if the (incident, attempt, owner) triple no
	// longer matches the current lease holder.
	ExtendIncidentTriageLease(ctx context.Context, attemptID, incidentID, owner string, now time.Time, lease time.Duration) error

	// CompleteIncidentTriageAttempt is the fenced, idempotent completion
	// boundary: it persists finding as a current-compatible success, or
	// (when the frozen digests no longer match current Incident state)
	// records a stale attempt output with no Finding written at all.
	CompleteIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, finding TriageFindingInput, now time.Time) (TriageCompletionOutcome, error)

	// BackoffIncidentTriageAttempt completes attemptID with a bounded typed
	// failure and returns the schedule to backoff at nextAt.
	BackoffIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, nextAt time.Time, code, detail string, now time.Time) error

	// ExhaustIncidentTriageAttempt completes attemptID with a bounded typed
	// failure and closes the schedule out terminally.
	ExhaustIncidentTriageAttempt(ctx context.Context, attemptID, incidentID, code, detail string, now time.Time) error

	// RecoverExpiredIncidentTriageAttempts resolves every in_flight row
	// whose lease has expired (a crash mid-attempt, or a heartbeat that
	// stopped arriving) into backoff or exhausted. TriageWorker calls this
	// at the start of every RunOnce, per store.
	// RecoverExpiredIncidentTriageAttempts's own doc comment ("call before
	// any worker resumes claiming, or periodically as a heartbeat-loss
	// sweep").
	RecoverExpiredIncidentTriageAttempts(ctx context.Context, now time.Time) (int, error)
}

// TriageScheduleLister lists Incident IDs whose Triage schedule is currently
// due, soonest-due first. store.Store's own pre-Plan-2 ListDueIncidentTriage
// (internal/store/triage.go) already satisfies this need unchanged — it
// queries `WHERE phase IN ('pending','backoff') AND next_at <= ?` against
// the SAME incident_triage table Task 6 rebuilt (migration 0016), with no
// filter on decision_origin, so it returns due rows for the NEW gated
// schedule exactly as it did for the old one (see the Task 7 report for the
// investigation confirming this). The adapter only needs to project
// []store.IncidentTriage down to []string of incident IDs.
type TriageScheduleLister interface {
	ListDueIncidentTriage(ctx context.Context, now time.Time) ([]string, error)
}

// ----------------------------------------------------------------------
// TriageWorker.
// ----------------------------------------------------------------------

// TriageWorkerConfig controls TriageWorker's claim lease, heartbeat,
// schedule, batch size, and attempt ceiling.
type TriageWorkerConfig struct {
	// Owner identifies this worker instance to the store's lease fencing.
	// Required — there is no default.
	Owner string

	// Lease is how long a claimed attempt is held before another worker (or
	// this worker's own crash-recovery sweep) may reclaim it as expired.
	// Default 5m — generous enough for an LLM call plus an optional
	// verification round.
	Lease time.Duration

	// Heartbeat is how often a claimed attempt's lease is renewed while
	// Analyze is still running. Must be, and defaults to, well under Lease
	// (default 90s) so a heartbeat miss or two never loses the lease
	// mid-analysis.
	Heartbeat time.Duration

	// Interval is how often Start's background loop wakes on its own,
	// absent an explicit Wake(). Default 5s.
	Interval time.Duration

	// Batch bounds how many due attempts one RunOnce call claims and
	// processes. Default 4 — Acute Triage attempts are LLM calls, not cheap
	// row writes, so this stays modest.
	Batch int

	// MaxAttempts is the attempt number (inclusive) at which a still-failing
	// claim is exhausted instead of backed off. Default 5, matching
	// migration 0016's own attempt_number/attempts CHECK constraints — do
	// not raise this without a migration change.
	MaxAttempts int

	// Now is the clock RunOnce reads. Default: the UTC wall clock.
	Now func() time.Time
}

const (
	defaultTriageWorkerLease       = 5 * time.Minute
	defaultTriageWorkerHeartbeat   = 90 * time.Second
	defaultTriageWorkerInterval    = 5 * time.Second
	defaultTriageWorkerBatch       = 4
	defaultTriageWorkerMaxAttempts = 5
)

func (c TriageWorkerConfig) withDefaults() TriageWorkerConfig {
	if c.Lease <= 0 {
		c.Lease = defaultTriageWorkerLease
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = defaultTriageWorkerHeartbeat
	}
	if c.Interval <= 0 {
		c.Interval = defaultTriageWorkerInterval
	}
	if c.Batch <= 0 {
		c.Batch = defaultTriageWorkerBatch
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultTriageWorkerMaxAttempts
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return c
}

// triageBackoffDelays is the backoff schedule for a failed attempt,
// preserving the pre-Plan-2 dispatch chain's own schedule (internal/
// correlator/triage_retry.go's triageRetryDelays, now removed) — the Global
// Constraint "Interrupted Acute Triage attempts consume the existing
// five-attempt durable schedule" reads as "the existing schedule", not just
// "the existing attempt count", so this task carries the timing forward
// too. Five attempts in total (len+1), matching migration 0016's
// attempt_number/attempts CHECK constraints (<= 5).
var triageBackoffDelays = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	8 * time.Minute,
	32 * time.Minute,
}

func triageBackoffDelay(attemptNumber int) time.Duration {
	i := attemptNumber - 1
	if i < 0 {
		i = 0
	}
	if i >= len(triageBackoffDelays) {
		i = len(triageBackoffDelays) - 1
	}
	return triageBackoffDelays[i]
}

// TriageWorker polls the durable, controller-gated Triage schedule (Task 6),
// claims due attempts, calls an AcuteAnalyzer with a fenced lease heartbeat,
// and completes/backs off/exhausts each attempt against the real result. It
// replaces the pre-Plan-2 Correlator-tick dispatch chain (internal/
// correlator/triage_retry.go, removed by this task) — due Triage dispatch is
// now a dedicated worker with periodic polling plus optional wake-up, per
// spec.md.
//
// It is safe for exactly one Start/Stop lifecycle; RunOnce and Drain may
// additionally be called directly (tests, or a one-shot CLI drain) without
// ever calling Start.
type TriageWorker struct {
	store       TriageAttemptStore
	lister      TriageScheduleLister
	analyzer    AcuteAnalyzer
	afterCommit AfterCommitter
	cfg         TriageWorkerConfig
	logger      *slog.Logger

	wakeCh chan struct{}
	stopCh chan struct{}
	doneCh chan struct{}

	startOnce sync.Once
}

// NewTriageWorker creates a TriageWorker. afterCommit may be nil (post-commit
// effects disabled — tests only). Passing nil for logger falls back to
// slog.Default(). Call Start to run it on a schedule, or drive it directly
// with RunOnce/Drain.
func NewTriageWorker(store TriageAttemptStore, lister TriageScheduleLister, analyzer AcuteAnalyzer, afterCommit AfterCommitter, cfg TriageWorkerConfig, logger *slog.Logger) *TriageWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &TriageWorker{
		store:       store,
		lister:      lister,
		analyzer:    analyzer,
		afterCommit: afterCommit,
		cfg:         cfg.withDefaults(),
		logger:      logger,
		wakeCh:      make(chan struct{}, 1),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// RunOnce recovers any expired in-flight lease, lists every currently due
// Incident, and claims/processes up to cfg.Batch of them sequentially. It
// returns how many it actually claimed and processed (a listed ID that
// raced away before this worker's own claim attempt does not count).
func (w *TriageWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.cfg.Now()

	if n, err := w.store.RecoverExpiredIncidentTriageAttempts(ctx, now); err != nil {
		w.logger.Error("situation: triage worker: recover expired attempts failed", "err", err)
	} else if n > 0 {
		w.logger.Info("situation: triage worker: recovered expired in-flight attempts", "count", n)
	}

	due, err := w.lister.ListDueIncidentTriage(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("situation: triage worker: list due incident triage: %w", err)
	}

	handled := 0
	for _, incidentID := range due {
		if handled >= w.cfg.Batch {
			break
		}
		if err := ctx.Err(); err != nil {
			return handled, err
		}
		if w.processOne(ctx, incidentID) {
			handled++
		}
	}
	return handled, nil
}

// Drain runs RunOnce repeatedly until a round handles zero items (the due
// schedule is caught up) or a round returns an error.
func (w *TriageWorker) Drain(ctx context.Context) (int, error) {
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
// most once per TriageWorker; later calls are no-ops.
func (w *TriageWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() { go w.run(ctx) })
}

func (w *TriageWorker) run(ctx context.Context) {
	defer close(w.doneCh)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		if _, err := w.Drain(ctx); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.logger.Error("situation: triage worker: drain", "err", err)
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
func (w *TriageWorker) Wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit after its current round and
// waits for it to finish, or returns ctx's error if ctx is done first.
func (w *TriageWorker) Stop(ctx context.Context) error {
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

// processOne claims incidentID's due attempt (if it is still claimable) and
// runs it to completion. It returns true when a claim was actually taken
// (regardless of the attempt's ultimate outcome), false when there was
// nothing left to do (the row raced away, was not yet due, or has no
// controller decision yet).
func (w *TriageWorker) processOne(ctx context.Context, incidentID string) bool {
	claim, err := w.store.ClaimIncidentTriageAttempt(ctx, incidentID, w.cfg.Owner, w.cfg.Now(), w.cfg.Lease)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrNotFound), errors.Is(err, ErrTriageAttemptNotDue):
			// Benign race: another worker claimed it, or the listing ran
			// slightly ahead of the claim's own due check.
		case errors.Is(err, ErrTriageAttemptNotDecided):
			w.logger.Warn("situation: triage worker: due row has no controller decision yet; skipping",
				"incident_id", incidentID)
		default:
			w.logger.Error("situation: triage worker: claim failed", "incident_id", incidentID, "err", err)
		}
		return false
	}

	analyzeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var leaseLost atomic.Bool
	hbDone := make(chan struct{})
	go w.heartbeatLoop(analyzeCtx, cancel, claim, &leaseLost, hbDone)

	result, analyzeErr := w.analyzer.Analyze(analyzeCtx, claim)

	cancel()
	<-hbDone

	if leaseLost.Load() {
		// The lease moved on mid-analysis (another worker's crash-recovery
		// sweep already reclaimed this row): completing against attemptID
		// now could race a fresh in-flight attempt. Abandon rather than
		// write back — nothing durable to reconcile here, the row already
		// belongs to whatever reclaimed it.
		w.logger.Warn("situation: triage worker: lease lost mid-analysis; abandoning stale attempt",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID)
		return true
	}

	w.completeAttempt(claim, result, analyzeErr)
	return true
}

// heartbeatLoop renews claim's lease every cfg.Heartbeat until ctx is done.
// If a renewal ever fails, it marks leaseLost and cancels cancel so the
// in-flight Analyze call is abandoned rather than allowed to keep running
// (and later complete) under a lease it no longer holds.
func (w *TriageWorker) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, claim TriageAttemptClaim, leaseLost *atomic.Bool, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(w.cfg.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			extendCtx, extendCancel := detachedWriteContext()
			err := w.store.ExtendIncidentTriageLease(extendCtx, claim.AttemptID, claim.IncidentID, w.cfg.Owner, w.cfg.Now(), w.cfg.Lease)
			extendCancel()
			if err != nil {
				w.logger.Warn("situation: triage worker: heartbeat lease extend failed; canceling attempt",
					"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
				leaseLost.Store(true)
				cancel()
				return
			}
		}
	}
}

// detachedWriteContext returns a short-lived context independent of the
// (possibly already-canceled) analysis context, for the terminal
// complete/backoff/exhaust write-back — mirroring skills/acutetriage's own
// "must never be dropped because ctx was canceled" pattern (ar.health.Finish
// et al.) so a canceled attempt still records why, rather than silently
// leaking a claim for the next crash-recovery sweep to find.
func detachedWriteContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// completeAttempt resolves one claimed attempt against Analyze's outcome:
// current-compatible success (complete + best-effort AfterCommit), a stale
// completion (complete only — spec.md: no post-commit effect), a clean skip
// (ErrCleanSkip), or a genuine failure (backoff or exhaust).
func (w *TriageWorker) completeAttempt(claim TriageAttemptClaim, result AcuteResult, analyzeErr error) {
	writeCtx, cancel := detachedWriteContext()
	defer cancel()
	now := w.cfg.Now()

	switch {
	case analyzeErr == nil:
		w.completeSuccessOrStale(writeCtx, claim, result, now)
	case errors.Is(analyzeErr, ErrCleanSkip):
		w.completeCleanSkip(writeCtx, claim, now)
	default:
		w.completeFailure(writeCtx, claim, analyzeErr, now)
	}
}

func (w *TriageWorker) completeSuccessOrStale(ctx context.Context, claim TriageAttemptClaim, result AcuteResult, now time.Time) {
	finding := TriageFindingInput{
		OutputJSON:         string(result.OutputJSON),
		Summary:            result.Summary,
		RootCause:          result.RootCause,
		Confidence:         result.Confidence,
		EnrichmentJSON:     result.EnrichmentJSON,
		EvidencePackDigest: result.EvidencePackDigest,
	}
	outcome, err := w.store.CompleteIncidentTriageAttempt(ctx, claim.AttemptID, claim.IncidentID, finding, now)
	if err != nil {
		w.logger.Error("situation: triage worker: complete attempt failed",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
		return
	}
	if outcome != TriageCompletionSuccess {
		// stale_membership / stale_incident_input: the atomic completion
		// boundary already restored the Incident to ready and the schedule
		// to awaiting_decision. spec.md: "It persists no Finding,
		// first-judgment time, Incident output projection, role, memory
		// action, or notifier effect" — so AfterCommit must NOT run here.
		w.logger.Info("situation: triage worker: attempt completed stale; schedule restored to awaiting_decision",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "outcome", outcome)
		return
	}
	if w.afterCommit == nil {
		return
	}
	if err := w.afterCommit.AfterCommit(ctx, result); err != nil {
		// Best-effort: the durable Finding already committed successfully.
		// A notify/audit/memory failure here is logged, never retried as if
		// the attempt itself failed (that would double-analyze).
		w.logger.Warn("situation: triage worker: post-commit effects failed (best-effort)",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
	}
}

// completeCleanSkip closes a claimed attempt that found nothing to analyze
// (ErrCleanSkip).
//
// Known gap (flagged, not silently patched): Task 6's store API has no
// "skip a claimed attempt" completion distinct from Exhaust/Backoff/
// Complete — unlike the pre-Plan-2 dispatch chain's SkipIncidentTriage,
// which returned the Incident to "ready" and closed the schedule
// terminally without failure semantics. ExhaustIncidentTriageAttempt is the
// closest available primitive (terminal, no further attempts wasted on a
// condition retrying will not change), but it marks the Incident "failed"
// rather than restoring it to "ready" the way the old clean-skip did. A
// dedicated skip-completion method in internal/store would close this gap
// properly; adding one is out of this task's Files list. See the Task 7
// report.
func (w *TriageWorker) completeCleanSkip(ctx context.Context, claim TriageAttemptClaim, now time.Time) {
	const code = "clean_skip"
	const detail = "acute triage found nothing to analyze (below the minimum member alert count)"
	if err := w.store.ExhaustIncidentTriageAttempt(ctx, claim.AttemptID, claim.IncidentID, code, detail, now); err != nil {
		w.logger.Error("situation: triage worker: close clean-skip attempt failed",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
	}
}

// completeFailure classifies a genuine Analyze failure and either schedules
// the next attempt (backoff) or, once the five-attempt schedule is spent,
// closes the Incident out terminally (exhaust) — mirroring the removed
// pre-Plan-2 dispatch chain's triageFailed/exhaustTriage split exactly,
// against the new fenced attempt ledger instead of the old bare schedule
// row.
func (w *TriageWorker) completeFailure(ctx context.Context, claim TriageAttemptClaim, cause error, now time.Time) {
	code, detail := classifyAttemptError(cause)
	if claim.AttemptNumber >= w.cfg.MaxAttempts {
		if err := w.store.ExhaustIncidentTriageAttempt(ctx, claim.AttemptID, claim.IncidentID, code, detail, now); err != nil {
			w.logger.Error("situation: triage worker: exhaust attempt failed",
				"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
		}
		return
	}
	next := now.Add(triageBackoffDelay(claim.AttemptNumber))
	if err := w.store.BackoffIncidentTriageAttempt(ctx, claim.AttemptID, claim.IncidentID, next, code, detail, now); err != nil {
		w.logger.Error("situation: triage worker: backoff attempt failed",
			"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID, "err", err)
		return
	}
	w.logger.Warn("situation: triage worker: attempt failed; will retry",
		"incident_id", claim.IncidentID, "attempt_id", claim.AttemptID,
		"attempt", claim.AttemptNumber, "max_attempts", w.cfg.MaxAttempts,
		"retry_in", next.Sub(now), "err", cause)
}

// classifyAttemptError produces the bounded, sanitized code/detail persisted
// on a failed attempt. This is a deliberately coarser classification than
// the pre-Plan-2 dispatch chain's llmhealth-aware classifyTriageError
// (internal/correlator/triage_retry.go, removed by this task):
// internal/llmhealth imports internal/store (for its Tracker persistence),
// and internal/store already imports internal/situation, so importing
// llmhealth here would cycle the same way importing internal/store
// directly would. Richer LLM-health-aware classification — "typed LLM
// outcomes to installation-level LLM health" per spec.md — is Task 8/9's
// wiring concern; skills/acutetriage's Analyze already reports every LLM
// call outcome to its configured llmhealth.Tracker regardless of caller
// (Run, Rejudge, or this worker), so that requirement is met independently
// of this classifier's coarseness. See the Task 7 report.
func classifyAttemptError(err error) (code, detail string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", sanitizeAttemptDetail(err.Error())
	case errors.Is(err, context.Canceled):
		return "canceled", sanitizeAttemptDetail(err.Error())
	default:
		return "acute_triage_failed", sanitizeAttemptDetail(err.Error())
	}
}

// maxAttemptDetailBytes bounds the persisted, sanitized failure detail —
// the stable code is authoritative, detail is diagnostic only. Matches
// internal/store/triage.go's own maxTriageDetailBytes bound.
const maxAttemptDetailBytes = 256

// sanitizeAttemptDetail bounds a raw error string for durable persistence.
// The store layer (internal/store/triage.go's sanitizeTriageDetail, run
// again on write) already strips CR/LF and invalid UTF-8, so this is a
// simple length cap here — good enough for what this package controls
// before handing off, and belt-and-suspenders with the store's own
// sanitization.
func sanitizeAttemptDetail(s string) string {
	if len(s) <= maxAttemptDetailBytes {
		return s
	}
	return s[:maxAttemptDetailBytes]
}
