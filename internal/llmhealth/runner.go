// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"context"
	"log/slog"
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
}

// NewRunner builds a Runner. prober and pub may be nil (no probing / no
// Slack delivery, respectively); logger nil defaults to slog.Default().
func NewRunner(t *Tracker, prober llm.Prober, pub Publisher, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{t: t, prober: prober, pub: pub, logger: logger}
}

// DrainTimeout is how long an owner should wait for the channel returned by
// Start after canceling ctx. It is derived from the longest chain one Step
// can still run past the post fence, every link individually bounded:
//
//	detached root POST                       deliveryTimeout
//	post-result audit + persist              2 × persistTimeout
//	idle probe due in the same step: the probe itself fails at once on the
//	canceled ctx, but ObserveProbe still persists and audits
//	                                         2 × persistTimeout
//	+ scheduling margin                      drainMargin
//
// Everything else in the step (late-root edits, the probe HTTP call) is
// bound to ctx and returns immediately once it is canceled. Stopping short
// of this chain leaves the write-ahead marker "indeterminate" for good and a
// root Slack did accept without the coordinates needed to edit it again.
func DrainTimeout() time.Duration {
	return deliveryTimeout + 4*persistTimeout + drainMargin
}

// Start runs Run on its own goroutine and returns a channel that is closed
// once Run has returned. Owners must keep the store open until it closes
// (bounded by DrainTimeout): an unjoined Runner exits with its in-flight
// delivery abandoned.
func (r *Runner) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	return done
}

// Run loops until ctx is done, calling Step on every tick and immediately
// after every Tracker.Kick (a state or Slack-delivery-relevant transition),
// so a recovery edit does not wait for the next full-minute tick.
func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.t == nil {
		return
	}
	ticker := time.NewTicker(runnerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.t.Kick():
		}
		r.Step(ctx, r.t.now())
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
