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
