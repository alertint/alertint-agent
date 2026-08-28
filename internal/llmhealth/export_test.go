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

// DeliveryTimeoutForTest / PersistTimeoutForTest expose the bounds
// DrainTimeout is derived from.
func DeliveryTimeoutForTest() time.Duration { return deliveryTimeout }
func PersistTimeoutForTest() time.Duration  { return persistTimeout }

// SetTimeoutsForTest shrinks the per-call delivery, persistence and drain
// margin bounds together and returns a restore func.
func SetTimeoutsForTest(delivery, persist, margin time.Duration) func() {
	d, p, m := deliveryTimeout, persistTimeout, drainMargin
	deliveryTimeout, persistTimeout, drainMargin = delivery, persist, margin
	return func() { deliveryTimeout, persistTimeout, drainMargin = d, p, m }
}
