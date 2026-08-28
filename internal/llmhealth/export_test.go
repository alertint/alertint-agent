// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import "time"

// IdleSince exposes the tracker's idle clock for tests.
func (t *Tracker) IdleSince() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.idleSince
}

// SetRunnerTickForTest overrides the Runner's ticker interval for tests.
func SetRunnerTickForTest(d time.Duration) { runnerTick = d }

// SetProbeTimeoutForTest overrides the Runner's per-probe timeout for tests.
func SetProbeTimeoutForTest(d time.Duration) { probeTimeout = d }

// SetDeliveryTimeoutForTest overrides the per-Slack-call delivery timeout.
func SetDeliveryTimeoutForTest(d time.Duration) { deliveryTimeout = d }

// SetDeliveryBudgetForTest overrides the whole-Deliver-phase budget.
func SetDeliveryBudgetForTest(d time.Duration) { deliveryBudget = d }
