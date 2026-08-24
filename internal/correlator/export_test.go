// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"time"
)

// FlushExpired runs one flush tick synchronously. Tests call it instead of
// Start so the triage retry schedule can be driven with a fake clock.
func (c *Correlator) FlushExpired(ctx context.Context) error { return c.flushExpired(ctx) }

// Recover runs the startup recovery pass without launching the loop goroutine.
func (c *Correlator) Recover(ctx context.Context) error { return c.recover(ctx) }

// SetNow replaces the clock flushExpired reads. Call before any FlushExpired.
func (c *Correlator) SetNow(now func() time.Time) { c.now = now }

// TriageRetryDelays exposes the backoff schedule to tests.
var TriageRetryDelays = triageRetryDelays

// StartupRetryWindow exposes the startup recovery cutoff to tests.
const StartupRetryWindow = startupRetryWindow
