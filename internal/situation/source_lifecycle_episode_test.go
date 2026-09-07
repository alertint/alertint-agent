// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Check both fold orders and both acquisition paths through the real reducer
// and Controller.Reconcile: episode precedence must not depend on which path
// supplied the newer source episode.
func assertEpisodeLifecycle(t *testing.T, a, b situation.SourceObservation, want model.Lifecycle) {
	t.Helper()
	now := ctBaseTime.Add(time.Hour)
	for _, observations := range [][]situation.SourceObservation{{a, b}, {b, a}} {
		fold := situation.ReduceSourceLifecycle(observations, []string{"delivery-1"}, now, 120*time.Second)
		wantFiring := want == model.LifecycleActive
		if fold.AnyFiring != wantFiring || fold.AllResolved == wantFiring || fold.ClosureDue {
			t.Errorf("first=%s/%s: fold=%+v, want lifecycle %s", observations[0].EpisodeKey, observations[0].State, fold, want)
		}
		in := ctBaseSnapshotInput()
		in.Prepared = situation.PreparedState{CycleID: "cycle-source-episode", Generation: 1, Lifecycle: observations[:1]}
		d := &in.Deliveries[0]
		o := observations[1]
		d.Status, d.ReceivedAt = model.DeliveryStatus(o.State), o.ObservedAt
		d.Source, d.EpisodeKey = o.Source, o.EpisodeKey
		d.SourceStartedAt, d.SourceResolvedAt = o.EventStartedAt, o.EventResolvedAt
		d.AcquisitionMode, d.PollIntervalSeconds = o.AcquisitionMode, o.PollIntervalSeconds
		got := reconcileDeliveryLifecycle(t, in, now)
		if got.Lifecycle != want {
			t.Errorf("prepared=%s/%s delivery=%s/%s: lifecycle=%s, want %s", observations[0].EpisodeKey, observations[0].State, o.EpisodeKey, o.State, got.Lifecycle, want)
		}
	}
}

func TestSourceLifecycleCrossPathOlderEpisodeResolutionCannotRecoverRefire(t *testing.T) {
	startA, endA, startB := ctBaseTime, ctBaseTime.Add(time.Minute), ctBaseTime.Add(2*time.Minute)
	firing := situation.SourceObservation{
		AlertID: "delivery-1", Source: "alertmanager", EpisodeKey: "B", State: situation.SourceStateFiring,
		EventStartedAt: &startB, ObservedAt: startB, AcquisitionMode: "poll", PollIntervalSeconds: 60,
	}
	resolved := situation.SourceObservation{
		AlertID: "delivery-1", Source: "alertmanager", EpisodeKey: "A", State: situation.SourceStateResolved,
		EventStartedAt: &startA, EventResolvedAt: &endA, ObservedAt: startB.Add(time.Minute), AcquisitionMode: "webhook",
	}
	assertEpisodeLifecycle(t, firing, resolved, model.LifecycleActive)
}

func TestSourceLifecycleCrossPathResolutionEndBeforeRefireProvesOldEpisode(t *testing.T) {
	endA, startB := ctBaseTime.Add(time.Minute), ctBaseTime.Add(2*time.Minute)
	firing := situation.SourceObservation{
		AlertID: "delivery-1", State: situation.SourceStateFiring,
		EventStartedAt: &startB, ObservedAt: startB, AcquisitionMode: "poll", PollIntervalSeconds: 60,
	}
	// Some resolutions carry an end time but no episode start or key. The
	// end preceding the new start still proves this is an older episode.
	resolved := situation.SourceObservation{
		AlertID: "delivery-1", State: situation.SourceStateResolved,
		EventResolvedAt: &endA, ObservedAt: startB.Add(time.Minute), AcquisitionMode: "webhook",
	}
	assertEpisodeLifecycle(t, firing, resolved, model.LifecycleActive)
}

func TestSourceLifecycleCrossPathPreservesObservationOrderingWithinEpisode(t *testing.T) {
	start, end, laterStart := ctBaseTime, ctBaseTime.Add(time.Minute), ctBaseTime.Add(2*time.Minute)
	zero := time.Time{}
	cases := []struct {
		name   string
		change func(firing, resolved *situation.SourceObservation)
		want   model.Lifecycle
	}{
		{"latest same episode resolution", func(f, r *situation.SourceObservation) {}, model.LifecycleRecoveryPending},
		{"latest same episode live polling firing", func(f, r *situation.SourceObservation) {
			f.ObservedAt = r.ObservedAt.Add(time.Minute)
		}, model.LifecycleActive},
		{"same episode observation tie prefers firing", func(f, r *situation.SourceObservation) {
			f.ObservedAt = r.ObservedAt
		}, model.LifecycleActive},
		{"equal start without episode keys retains live polling", func(f, r *situation.SourceObservation) {
			f.EpisodeKey, r.EpisodeKey = "", ""
			f.ObservedAt = r.ObservedAt.Add(time.Minute)
		}, model.LifecycleActive},
		{"unproven episode ordering retains live polling", func(f, r *situation.SourceObservation) {
			f.EpisodeKey, r.EpisodeKey = "B", "A"
			f.EventStartedAt, r.EventStartedAt = nil, nil
			f.ObservedAt = r.ObservedAt.Add(time.Minute)
		}, model.LifecycleActive},
		{"zero start is not episode ordering proof", func(f, r *situation.SourceObservation) {
			f.EpisodeKey, r.EpisodeKey = "", ""
			r.EventStartedAt = &zero
		}, model.LifecycleRecoveryPending},
		{"newer resolved episode overrides late old firing", func(f, r *situation.SourceObservation) {
			f.EpisodeKey, r.EpisodeKey = "A", "B"
			r.EventStartedAt, r.EventResolvedAt = &laterStart, nil
			f.ObservedAt = r.ObservedAt.Add(time.Minute)
		}, model.LifecycleRecoveryPending},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			firing := situation.SourceObservation{
				AlertID: "delivery-1", EpisodeKey: "A", State: situation.SourceStateFiring,
				EventStartedAt: &start, ObservedAt: start, AcquisitionMode: "poll", PollIntervalSeconds: 60,
			}
			resolved := situation.SourceObservation{
				AlertID: "delivery-1", EpisodeKey: "A", State: situation.SourceStateResolved,
				EventStartedAt: &start, EventResolvedAt: &end, ObservedAt: end, AcquisitionMode: "webhook",
			}
			tt.change(&firing, &resolved)
			assertEpisodeLifecycle(t, firing, resolved, tt.want)
		})
	}
}
