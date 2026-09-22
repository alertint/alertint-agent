// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"
)

func TestPreparedLifecycleCannotRecoverAFiringSibling(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", EpisodeKey: "a:1", Source: "alertmanager", State: "firing",
			ObservedAt: now, DeadlineAt: now.Add(24 * time.Hour), AcquisitionMode: "webhook"},
		{AlertID: "b", EpisodeKey: "b:1", Source: "zabbix", State: "resolved",
			ObservedAt: now, DeadlineAt: now.Add(24 * time.Hour), AcquisitionMode: "poll", PollIntervalSeconds: 300},
	}
	got := ReduceSourceLifecycle(obs, []string{"a", "b"}, now, 120*time.Second)
	if !got.AnyFiring || got.AllResolved || got.ClosureDue {
		t.Fatalf("partial resolve became recovery: %+v", got)
	}
	obs[0].State = "resolved"
	got = ReduceSourceLifecycle(obs, []string{"a", "b"}, now, 120*time.Second)
	if !got.AllResolved || got.Grace != 600*time.Second {
		t.Fatalf("mixed-source grace: %+v", got)
	}
}

func TestReduceSourceLifecycleOlderResolveCannotOverrideNewerFiring(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now.Add(-time.Minute), AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
		{AlertID: "a", State: "firing", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a"}, now, 120*time.Second)
	if !got.AnyFiring || got.AllResolved {
		t.Fatalf("older API resolve overrode a newer firing delivery: %+v", got)
	}
}

func TestReduceSourceLifecycleEqualTimeConflictPrefersFiring(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
		{AlertID: "a", State: "firing", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a"}, now, 120*time.Second)
	if !got.AnyFiring {
		t.Fatalf("an equal-time ordering conflict must prefer firing: %+v", got)
	}
}

func TestReduceSourceLifecycleMissingMemberBlocksClosure(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
	}
	// "b" is expected but has no observation at all — unknown deadline never
	// counts as "passed".
	got := ReduceSourceLifecycle(obs, []string{"a", "b"}, now, 120*time.Second)
	if got.AllResolved || got.ClosureDue {
		t.Fatalf("a missing expected member must block both AllResolved and ClosureDue: %+v", got)
	}
}

func TestReduceSourceLifecycleClosureDueOncePastDeadlineAndNoFiring(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", State: "unobserved", ObservedAt: now.Add(-25 * time.Hour), DeadlineAt: now.Add(-time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a"}, now, 120*time.Second)
	if !got.ClosureDue {
		t.Fatalf("expected ClosureDue once the only member's deadline has passed with no firing: %+v", got)
	}
}

func TestReduceSourceLifecyclePendingDeadlineBlocksClosureAndReportsNext(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	deadline := now.Add(2 * time.Hour)
	obs := []SourceObservation{
		{AlertID: "a", State: "unobserved", ObservedAt: now.Add(-time.Hour), DeadlineAt: deadline},
	}
	got := ReduceSourceLifecycle(obs, []string{"a"}, now, 120*time.Second)
	if got.ClosureDue {
		t.Fatal("a still-pending deadline must not permit closure")
	}
	if got.NextDeadlineAt == nil || !got.NextDeadlineAt.Equal(deadline) {
		t.Fatalf("expected NextDeadlineAt = %v, got %+v", deadline, got)
	}
}

func TestReduceSourceLifecycleTruncatedMemberSetStillBlocksOnMissing(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	// Two observations arrive but three members are expected — the third's
	// silence is not itself evidence of resolution.
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
		{AlertID: "b", State: "resolved", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a", "b", "c"}, now, 120*time.Second)
	if got.AllResolved {
		t.Fatal("a truncated/incomplete member set must not report AllResolved")
	}
}

func TestReduceSourceLifecycleExplicitResolveThenUnavailablePollingRetainsResolution(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	// The member resolved via an explicit source event; a later poll simply
	// failed to observe anything new (never reported here as a fresh
	// "unobserved" state overriding the resolution — the caller retains the
	// prior resolved observation when polling fails, so ReduceSourceLifecycle
	// only ever sees the still-resolved state).
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now.Add(-time.Minute), AcquisitionMode: "poll", PollIntervalSeconds: 60, DeadlineAt: now.Add(time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a"}, now, 120*time.Second)
	if !got.AllResolved {
		t.Fatalf("expected the retained resolution to still report AllResolved: %+v", got)
	}
	if got.Grace != minPollingGrace {
		t.Fatalf("grace = %v, want the clamped floor %v for a 60s poll interval", got.Grace, minPollingGrace)
	}
}

func TestExpectedAlertIDsDedupesAndSortsByAlertIDFallingBackToDeliveryID(t *testing.T) {
	deliveries := []Delivery{
		{ID: "d1", AlertID: "alert-b"},
		{ID: "d2", AlertID: "alert-a"},
		{ID: "d3", AlertID: "alert-b"}, // a repeat delivery of the same Alert.
		{ID: "d4"},                     // no AlertID: counts as its own Alert (test-fixture-only case).
	}
	got := expectedAlertIDs(deliveries)
	want := []string{"alert-a", "alert-b", "delivery:d4"}
	if len(got) != len(want) {
		t.Fatalf("expectedAlertIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expectedAlertIDs = %v, want %v", got, want)
		}
	}
}

func TestReduceSourceLifecycleEmptyExpectedSetIsZeroValue(t *testing.T) {
	got := ReduceSourceLifecycle(nil, nil, time.Now(), 120*time.Second)
	if got.AnyFiring || got.AllResolved || got.ClosureDue {
		t.Fatalf("empty expected set must be the zero value: %+v", got)
	}
}

// AnyResolved must track "at least one member has an explicit resolved
// observation" independently of AllResolved — Reconcile's controller.go
// needs this to pick ClosedUnknownReason (resolution_missing vs.
// observation_deadline) even when closure happens with a MIXED member set
// (one resolved, one that simply timed out unobserved), not only once every
// member has resolved.
func TestReduceSourceLifecycleAnyResolvedTracksAtLeastOneMemberIndependentlyOfAllResolved(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	obs := []SourceObservation{
		{AlertID: "a", State: "resolved", ObservedAt: now, AcquisitionMode: "webhook", DeadlineAt: now.Add(time.Hour)},
	}
	got := ReduceSourceLifecycle(obs, []string{"a", "b"}, now, 120*time.Second)
	if !got.AnyResolved {
		t.Fatalf("expected AnyResolved once at least one member resolved, got %+v", got)
	}
	if got.AllResolved {
		t.Fatalf("member b has no observation at all: AllResolved must stay false, got %+v", got)
	}

	gotNone := ReduceSourceLifecycle(nil, []string{"a"}, now, 120*time.Second)
	if gotNone.AnyResolved {
		t.Fatalf("no observation at all must not report AnyResolved: %+v", gotNone)
	}
}
