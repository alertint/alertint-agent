// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func reconcileDeliveryLifecycle(t *testing.T, in situation.SnapshotInput, now time.Time) situation.ControllerCommit {
	t.Helper()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)
	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	return store.commits[0]
}

func TestControllerLifecyclePreparedCycleDeliveryResolutionClosesAfterGrace(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	in := ctBaseSnapshotInput()
	in.Prepared = situation.PreparedState{CycleID: "cycle-delivery-resolution", Generation: 1}
	resolved := in.Deliveries[0]
	resolved.ID = "resolution"
	resolved.Status = model.DeliveryStatusResolved
	resolved.ReceivedAt = now.Add(-time.Second)
	resolved.AcquisitionMode = "webhook"
	in.Deliveries = append(in.Deliveries, resolved)

	first := reconcileDeliveryLifecycle(t, in, now)
	if first.Lifecycle != model.LifecycleRecoveryPending {
		t.Fatalf("lifecycle = %s, want recovery_pending from latest resolved delivery", first.Lifecycle)
	}
	if first.RecoveryObservedAt == nil || !first.RecoveryObservedAt.Equal(now) || first.GraceUntil == nil || !first.GraceUntil.After(now) {
		t.Fatalf("recovery must start a grace clock: observed=%v grace=%v", first.RecoveryObservedAt, first.GraceUntil)
	}
	in.Situation.Lifecycle = first.Lifecycle
	in.Situation.RecoveryObservedAt = first.RecoveryObservedAt
	in.Situation.GraceUntil = first.GraceUntil
	beforeExpiry := reconcileDeliveryLifecycle(t, in, first.GraceUntil.Add(-time.Second))
	if beforeExpiry.Lifecycle != model.LifecycleRecoveryPending || !beforeExpiry.GraceUntil.Equal(*first.GraceUntil) {
		t.Fatalf("must retain original grace until expiry: %+v", beforeExpiry)
	}
	closed := reconcileDeliveryLifecycle(t, in, *first.GraceUntil)
	if closed.Lifecycle != model.LifecycleRecovered || closed.TerminalAt == nil || !closed.TerminalAt.Equal(*first.GraceUntil) || closed.TerminalReason != nil {
		t.Fatalf("clean grace expiry must recover: lifecycle=%s terminal=%v reason=%v", closed.Lifecycle, closed.TerminalAt, closed.TerminalReason)
	}
}

func TestControllerLifecycleDeliveryAndPreparedPrecedence(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	delivery := func(id, alert string, firing bool, at time.Time) situation.Delivery {
		d := ctDelivery(id, "incident-1", firing, "warning")
		d.AlertID, d.ReceivedAt, d.AcquisitionMode = alert, at, "webhook"
		return d
	}
	firing := delivery("firing", "a", true, now.Add(-time.Minute))
	resolved := delivery("resolved", "a", false, now.Add(-time.Second))
	oldResolved := delivery("old-resolved", "a", false, now.Add(-2*time.Minute))
	tiedResolved := delivery("z-resolved", "a", false, firing.ReceivedAt)
	sibling := delivery("sibling", "b", true, now.Add(-time.Minute))
	// A late resolution from a previous source episode cannot end a refire.
	refire := firing
	refire.SourceStartedAt = &firing.ReceivedAt
	lateOldEpisode := resolved
	lateOldEpisode.SourceStartedAt = &oldResolved.ReceivedAt
	prepared := func(state string, at time.Time) []situation.SourceObservation {
		return []situation.SourceObservation{{AlertID: "a", State: state, ObservedAt: at, AcquisitionMode: "webhook"}}
	}
	cases := []struct {
		name         string
		deliveries   []situation.Delivery
		observations []situation.SourceObservation
		want         model.Lifecycle
	}{
		{"partial delivery resolve", []situation.Delivery{firing, resolved, sibling}, nil, model.LifecycleActive},
		{"partial prepared resolve", []situation.Delivery{firing, sibling}, prepared(situation.SourceStateResolved, now), model.LifecycleActive},
		{"stale delivery resolve", []situation.Delivery{firing, oldResolved}, nil, model.LifecycleActive},
		{"late old source episode resolve", []situation.Delivery{refire, lateOldEpisode}, nil, model.LifecycleActive},
		{"tied deliveries prefer firing over row ID", []situation.Delivery{firing, tiedResolved}, nil, model.LifecycleActive},
		{"new delivery resolves old prepared firing", []situation.Delivery{firing, resolved}, prepared(situation.SourceStateFiring, firing.ReceivedAt), model.LifecycleRecoveryPending},
		{"new delivery refires old prepared resolve", []situation.Delivery{firing}, prepared(situation.SourceStateResolved, oldResolved.ReceivedAt), model.LifecycleActive},
		{"new prepared resolve supersedes delivery firing", []situation.Delivery{firing}, prepared(situation.SourceStateResolved, now), model.LifecycleRecoveryPending},
		{"new prepared firing supersedes delivery resolve", []situation.Delivery{resolved}, prepared(situation.SourceStateFiring, now), model.LifecycleActive},
		{"tied prepared firing wins", []situation.Delivery{resolved}, prepared(situation.SourceStateFiring, resolved.ReceivedAt), model.LifecycleActive},
		{"tied delivery firing wins", []situation.Delivery{firing}, prepared(situation.SourceStateResolved, firing.ReceivedAt), model.LifecycleActive},
		{"new prepared uncertainty retains deadline", []situation.Delivery{resolved}, []situation.SourceObservation{{AlertID: "a", State: situation.SourceStateUnobserved, ObservedAt: now, DeadlineAt: now.Add(time.Hour)}}, model.LifecycleActive},
		{"new prepared uncertainty past deadline", []situation.Delivery{firing}, []situation.SourceObservation{{AlertID: "a", State: situation.SourceStateUnobserved, ObservedAt: now, DeadlineAt: now.Add(-time.Second)}}, model.LifecycleClosedUnknown},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Database row order must not decide whether a Situation closes.
			for _, reverse := range []bool{false, true} {
				in := ctBaseSnapshotInput()
				in.Prepared = situation.PreparedState{CycleID: "cycle-precedence", Generation: 1, Lifecycle: tt.observations}
				in.Deliveries = append([]situation.Delivery(nil), tt.deliveries...)
				if reverse {
					for i, j := 0, len(in.Deliveries)-1; i < j; i, j = i+1, j-1 {
						in.Deliveries[i], in.Deliveries[j] = in.Deliveries[j], in.Deliveries[i]
					}
				}
				got := reconcileDeliveryLifecycle(t, in, now)
				if got.Lifecycle != tt.want {
					t.Fatalf("reverse=%v: lifecycle=%s, want %s", reverse, got.Lifecycle, tt.want)
				}
			}
		})
	}
}

func TestControllerLifecycleDeliveryRefireCancelsPreparedRecovery(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	in := ctBaseSnapshotInput()
	d := &in.Deliveries[0]
	d.Status, d.AcquisitionMode, d.PollIntervalSeconds = model.DeliveryStatusResolved, "poll", 180
	d.ReceivedAt = now.Add(-time.Minute)
	in.Prepared = situation.PreparedState{CycleID: "cycle-refire", Generation: 1}
	first := reconcileDeliveryLifecycle(t, in, now)
	if first.Lifecycle != model.LifecycleRecoveryPending || first.GraceUntil == nil || !first.GraceUntil.Equal(now.Add(360*time.Second)) {
		t.Fatalf("delivery polling interval must determine recovery grace: lifecycle=%s grace=%v", first.Lifecycle, first.GraceUntil)
	}
	in.Situation.Lifecycle = first.Lifecycle
	in.Situation.RecoveryObservedAt, in.Situation.GraceUntil = first.RecoveryObservedAt, first.GraceUntil
	in.Prepared.Lifecycle = []situation.SourceObservation{{AlertID: d.AlertID, State: situation.SourceStateResolved, ObservedAt: now, AcquisitionMode: "poll", PollIntervalSeconds: 180}}
	refire := *d
	refire.ID, refire.Status, refire.ReceivedAt = "refire", model.DeliveryStatusFiring, now.Add(time.Minute)
	in.Deliveries = append(in.Deliveries, refire)
	for _, at := range []time.Time{refire.ReceivedAt, *first.GraceUntil} {
		got := reconcileDeliveryLifecycle(t, in, at)
		if got.Lifecycle != model.LifecycleActive || got.RecoveryObservedAt != nil || got.GraceUntil != nil || got.TerminalAt != nil || got.TerminalReason != nil {
			t.Fatalf("refire must cancel recovery even at grace expiry: lifecycle=%s recovery=%v grace=%v terminal=%v", got.Lifecycle, got.RecoveryObservedAt, got.GraceUntil, got.TerminalAt)
		}
	}
}
