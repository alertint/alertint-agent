// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
)

var (
	runnerTick   = time.Minute
	probeTimeout = 10 * time.Second
	// deliveryTimeout bounds every single Slack Publisher call made by
	// Deliver. The Runner is one goroutine: a Slack endpoint that accepts
	// the connection and never answers would otherwise wedge kicks, retry
	// edits and idle probes for good. A timed-out POST is a transport
	// failure with an unknown outcome and so becomes indeterminate; a
	// timed-out edit simply retries on the next step.
	deliveryTimeout = 15 * time.Second
	// deliveryBudget bounds one whole Deliver phase (the episode's own call
	// plus however many late-root edits are queued): a backlog of stalled
	// edits must not cost N × deliveryTimeout before the idle probe runs.
	// Whatever did not fit stays queued for the next step.
	deliveryBudget = 45 * time.Second
	// persistTimeout bounds every store write and audit append the tracker
	// makes on its own context.Background() (they must land even when the
	// caller's ctx is gone).
	persistTimeout = 5 * time.Second
	// drainMargin is scheduling headroom on top of the worst-case chain
	// DrainTimeout adds up.
	drainMargin = 5 * time.Second
)

// Runner drives the one-minute cadence: Slack delivery, then an idle probe
// when one is due. Run is meant to be the only goroutine calling Step, so a
// probe never runs concurrently with another Step.
type Runner struct {
	t      *Tracker
	prober llm.Prober
	pub    Publisher
	logger *slog.Logger

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewRunner builds a Runner. prober and pub may be nil (no probing / no
// Slack delivery, respectively); logger nil defaults to slog.Default().
func NewRunner(t *Tracker, prober llm.Prober, pub Publisher, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{t: t, prober: prober, pub: pub, logger: logger, stopCh: make(chan struct{})}
}

// DrainTimeout is how long an owner should wait for the channel returned by
// Start after calling Stop. It is derived from the longest chain Stop can
// still have to run, every link individually bounded. First the tail of a
// step already in progress:
//
//	detached root POST                       deliveryTimeout
//	post-result audit + persist              2 × persistTimeout
//	idle probe due in the same step: the probe itself fails at once on a
//	done ctx, but ObserveProbe still persists and audits
//	                                         2 × persistTimeout
//	a real call recovering while the POST is out holds the lock across
//	two audits and a persist, and the returning POST then adopts the
//	stale root with one more audit and persist
//	                                         5 × persistTimeout
//
// then the final delivery pass Stop runs against the settled state:
//
//	one whole Deliver phase (root post or edit plus queued late-root
//	edits; whatever does not fit stays durable for the next start)
//	                                         deliveryBudget
//	its last result's audit + persist        2 × persistTimeout
//	+ scheduling margin                      drainMargin
//
// The owner must have stopped every observation producer before Stop, or
// the final pass acknowledges a state that is still moving. Stopping short
// of this chain leaves the write-ahead marker "indeterminate" for good and a
// root Slack did accept without the coordinates needed to edit it again.
func DrainTimeout() time.Duration {
	return deliveryTimeout + 11*persistTimeout + deliveryBudget + drainMargin
}

// Start runs Run on its own goroutine and returns a channel that is closed
// once Run has returned. Owners stop it with Stop (not by canceling ctx —
// that is the hard-abort path, which skips the final delivery pass) and must
// keep the store open until the channel closes, bounded by DrainTimeout: an
// unjoined Runner exits with its in-flight delivery abandoned.
func (r *Runner) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	return done
}

// Stop asks Run to exit after one final delivery pass against the settled
// durable state. Kicks are only hints (buffered, one deep, sent on aggregate
// transitions); a stop racing the last producer's kick could otherwise win
// the select and leave the episode's root unposted, or standing at
// "unavailable" with the recovery already durable, until the next start.
// The pass runs on a live, bounded ctx — a done ctx never delivers — and
// skips the idle probe, which could move the state after the last
// acknowledgment. It is safe to call more than once and before Start.
//
// Contract for owners: every capability producer has been joined before
// Stop, so once the channel from Start closes every transition the final
// state implies has been attempted and its outcome recorded (delivered,
// pending retry, or indeterminate) — nothing is left for a restart that a
// live process could still have done. The pass ends by sealing the Tracker:
// an owner whose join timed out on a wedged producer proceeds knowing that
// whatever it still reports is dropped, never a transition nobody
// acknowledged.
func (r *Runner) Stop() { r.stopOnce.Do(func() { close(r.stopCh) }) }

// finalDeliver is Stop's acknowledgment pass. Deliver applies its own
// per-call and whole-phase bounds; the outer bound only keeps a wedged
// publisher from holding the owner past DrainTimeout. The Tracker is sealed
// once the pass has recorded its outcomes.
func (r *Runner) finalDeliver() {
	ctx, cancel := context.WithTimeout(context.Background(), deliveryBudget+deliveryTimeout)
	defer cancel()
	r.t.Deliver(ctx, r.pub)
	r.t.Seal()
}

// Run loops until Stop is called (final delivery pass, then return) or ctx
// is done (hard abort, no pass), calling Step on every tick and immediately
// after every Tracker.Kick (a state or Slack-delivery-relevant transition),
// so a recovery edit does not wait for the next full-minute tick.
func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.t == nil {
		return
	}
	// Steps run on a ctx that Stop cancels too: the owner's ctx is usually
	// never canceled (Stop is the shutdown path), and a step in progress
	// must still be cut to the tail DrainTimeout accounts for — a stalled
	// edit or a slow probe must not run to its own bound before the final
	// pass can start. The final pass then gets its own live ctx.
	stepCtx, cancelStep := context.WithCancel(ctx)
	defer cancelStep()
	go func() {
		select {
		case <-r.stopCh:
			cancelStep()
		case <-stepCtx.Done():
		}
	}()
	ticker := time.NewTicker(runnerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			r.finalDeliver() //nolint:contextcheck // by design: the pass needs a live ctx, and ctx may already be done
			return
		case <-ticker.C:
		case <-r.t.Kick():
		}
		r.Step(stepCtx, r.t.now())
	}
}

// Step delivers any due Slack change, then runs an idle probe if one is due.
// A probe never runs from Deliver and is bounded by probeTimeout regardless
// of ctx's own deadline.
func (r *Runner) Step(ctx context.Context, now time.Time) {
	r.t.Deliver(ctx, r.pub)
	if r.prober == nil || !r.t.ProbeDue(now) {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	res := r.prober.Probe(pctx)
	cancel()
	// ObserveProbe persists with its own bounded context.Background() by
	// design (Task 6 contract): an observation must never be dropped because
	// the caller's ctx was canceled mid-persist.
	r.t.ObserveProbe(res) //nolint:contextcheck
}
