// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestSourceLifecycleMixedDeliveryAndPreparedResolutionGrace(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	for _, interval := range []int{30, 180, 900} {
		wantGrace := 2 * time.Duration(interval) * time.Second
		if wantGrace < 120*time.Second {
			wantGrace = 120 * time.Second
		}
		if wantGrace > 600*time.Second {
			wantGrace = 600 * time.Second
		}
		in := ctBaseSnapshotInput()
		in.Deliveries[0].Status = model.DeliveryStatusResolved
		in.Deliveries[0].AcquisitionMode = "webhook"
		in.Deliveries[0].ReceivedAt = now
		poll := ctDelivery("poll", "incident-1", true, "warning")
		in.Deliveries = append(in.Deliveries, poll)
		in.Prepared = situation.PreparedState{CycleID: "cycle-mixed", Generation: 1, Lifecycle: []situation.SourceObservation{
			{AlertID: poll.AlertID, State: situation.SourceStateResolved, ObservedAt: now, AcquisitionMode: "poll", PollIntervalSeconds: interval},
		}}

		// Exercise the real public reducer with both acquisition paths, then
		// require controller reconciliation to produce the same recovery grace.
		observations := append([]situation.SourceObservation(nil), in.Prepared.Lifecycle...)
		observations = append(observations,
			situation.SourceObservation{AlertID: in.Deliveries[0].AlertID, State: situation.SourceStateResolved, ObservedAt: now, AcquisitionMode: "webhook"},
			situation.SourceObservation{AlertID: poll.AlertID, State: situation.SourceStateFiring, ObservedAt: poll.ReceivedAt, AcquisitionMode: "webhook"},
		)
		fold := situation.ReduceSourceLifecycle(observations, []string{in.Deliveries[0].AlertID, poll.AlertID}, now, 120*time.Second)
		if !fold.AllResolved || !fold.AnyResolved || fold.AnyFiring || fold.ClosureDue || fold.Grace != wantGrace {
			t.Fatalf("interval=%d: mixed-source reduction = %+v, want all resolved with grace %s", interval, fold, wantGrace)
		}
		got := reconcileDeliveryLifecycle(t, in, now)
		if got.Lifecycle != model.LifecycleRecoveryPending || got.GraceUntil == nil || !got.GraceUntil.Equal(now.Add(wantGrace)) {
			t.Fatalf("interval=%d: controller lifecycle=%s grace=%v, want recovery_pending until %v", interval, got.Lifecycle, got.GraceUntil, now.Add(wantGrace))
		}
	}
}
