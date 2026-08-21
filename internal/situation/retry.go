// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "time"

// defaultRetryInitial and defaultRetryMaximum mirror the strict config
// defaults (situations.retry.initial_seconds/maximum_seconds) so a
// zero-value RetryPolicy is still safe to use directly.
const (
	defaultRetryInitial = 5 * time.Second
	defaultRetryMaximum = 300 * time.Second
)

// RetryPolicy is the deterministic exponential-backoff-with-jitter formula
// shared by every retryable durable work item — Situation reconciliation
// attempts and notification intent delivery alike (spec: "Retryable
// failures use exponential backoff with +/-20% jitter").
type RetryPolicy struct {
	Initial       time.Duration
	Maximum       time.Duration
	JitterPercent int
}

func (p RetryPolicy) normalized() RetryPolicy {
	if p.Initial <= 0 {
		p.Initial = defaultRetryInitial
	}
	if p.Maximum <= 0 {
		p.Maximum = defaultRetryMaximum
	}
	if p.Maximum < p.Initial {
		p.Maximum = p.Initial
	}
	if p.JitterPercent < 0 {
		p.JitterPercent = 0
	}
	if p.JitterPercent > 100 {
		p.JitterPercent = 100
	}
	return p
}

// Next returns the backoff duration before the given attempt (1-indexed:
// Next(1, ...) is the delay before the first retry after attempt 1 failed),
// doubling from Initial up to Maximum and then applying up to
// +/-JitterPercent% jitter. randomUnit is a caller-supplied uniform value in
// [0,1) (e.g. rand.Float64()) so the formula stays deterministic and
// testable: 0 applies the full negative jitter, 1 the full positive jitter,
// and 0.5 applies none. Out-of-range inputs are clamped rather than
// rejected — this is a scheduling formula, not a validated contract.
func (p RetryPolicy) Next(attempt int, randomUnit float64) time.Duration {
	cfg := p.normalized()
	if attempt < 1 {
		attempt = 1
	}
	backoff := cfg.Initial
	for i := 1; i < attempt && backoff < cfg.Maximum; i++ {
		backoff *= 2
	}
	if backoff > cfg.Maximum {
		backoff = cfg.Maximum
	}
	if randomUnit < 0 {
		randomUnit = 0
	}
	if randomUnit > 1 {
		randomUnit = 1
	}
	jitter := float64(cfg.JitterPercent) / 100
	multiplier := 1 + jitter*(2*randomUnit-1)
	result := time.Duration(float64(backoff) * multiplier)
	if result < 0 {
		result = 0
	}
	return result
}
