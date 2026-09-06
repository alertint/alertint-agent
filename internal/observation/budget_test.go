// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

func candidate(subject string, capability model.Capability, maxReq int, lastServed time.Time) Candidate {
	return Candidate{Subject: subject, Capability: capability, MaxRequests: maxReq, LastServedAt: lastServed}
}

func TestAllocateFairlyTimeSensitiveFirstUnlimited(t *testing.T) {
	now := time.Now()
	var ts []Candidate
	for i := 0; i < 4; i++ {
		ts = append(ts, candidate("m", model.CapabilityPrometheusQuery, 1, now))
	}
	alloc := allocateFairly(4, 0, ts, nil, nil)
	if len(alloc.Admitted) != 4 {
		t.Fatalf("admitted = %d, want 4", len(alloc.Admitted))
	}
	if alloc.TimeSensitiveRequests != 4 {
		t.Fatalf("time-sensitive requests = %d, want 4", alloc.TimeSensitiveRequests)
	}
}

func TestAllocateFairlyProtectsOptionalWhenAffordable(t *testing.T) {
	now := time.Now()
	optional := []Candidate{candidate("m", model.CapabilityZabbixMetricRange, 2, now)}
	routine := []Candidate{
		candidate("a", model.CapabilityStoreRead, 1, now.Add(-time.Hour)),
		candidate("b", model.CapabilityStoreRead, 1, now.Add(-time.Hour)),
		candidate("c", model.CapabilityStoreRead, 1, now.Add(-time.Hour)),
	}
	// Cap 4: 2 for the optional plan (affordable at credit>=6), 2 for routine.
	alloc := allocateFairly(4, 6, nil, optional, routine)
	if alloc.OptionalRequests != 2 {
		t.Fatalf("optional requests = %d, want 2", alloc.OptionalRequests)
	}
	if alloc.OptionalPlanID == "" {
		t.Fatal("expected an admitted optional plan id")
	}
	if alloc.RoutineLifecycleRequests != 2 {
		t.Fatalf("routine requests = %d, want 2 (remaining capacity after optional)", alloc.RoutineLifecycleRequests)
	}
	if len(alloc.Deferred) != 1 {
		t.Fatalf("deferred = %d, want 1 (the routine candidate that could not fit)", len(alloc.Deferred))
	}
}

func TestAllocateFairlyDefersOptionalWhenInsufficientCredit(t *testing.T) {
	now := time.Now()
	optional := []Candidate{candidate("m", model.CapabilityZabbixMetricRange, 2, now)}
	alloc := allocateFairly(6, 3, nil, optional, nil) // needs 2*3=6 credit, only 3 available
	if alloc.OptionalRequests != 0 {
		t.Fatalf("optional requests = %d, want 0 (insufficient credit)", alloc.OptionalRequests)
	}
	if len(alloc.Deferred) != 1 {
		t.Fatalf("deferred = %d, want 1", len(alloc.Deferred))
	}
}

func TestAllocateFairlyDefersOptionalWhenExceedsCapacity(t *testing.T) {
	now := time.Now()
	ts := []Candidate{candidate("m1", model.CapabilityPrometheusQuery, 5, now)}
	optional := []Candidate{candidate("m2", model.CapabilityZabbixMetricRange, 2, now)}
	// Cap 6: time-sensitive takes 5, only 1 left — the 2-request optional
	// plan cannot fragment into a single leftover slot.
	alloc := allocateFairly(6, 100, ts, optional, nil)
	if alloc.OptionalRequests != 0 {
		t.Fatalf("optional requests = %d, want 0 (does not fit remaining capacity)", alloc.OptionalRequests)
	}
}

func TestAllocateFairlyRoutineLeastRecentlyServedFirst(t *testing.T) {
	now := time.Now()
	routine := []Candidate{
		candidate("recent", model.CapabilityStoreRead, 1, now),
		candidate("oldest", model.CapabilityStoreRead, 1, now.Add(-time.Hour)),
		candidate("middle", model.CapabilityStoreRead, 1, now.Add(-30*time.Minute)),
	}
	alloc := allocateFairly(2, 0, nil, nil, routine)
	if len(alloc.Admitted) != 2 {
		t.Fatalf("admitted = %d, want 2", len(alloc.Admitted))
	}
	if alloc.Admitted[0].Subject != "oldest" && alloc.Admitted[1].Subject != "oldest" {
		t.Fatalf("least-recently-served candidate was not admitted: %+v", alloc.Admitted)
	}
	if alloc.Admitted[0].Subject == "recent" || alloc.Admitted[1].Subject == "recent" {
		t.Fatalf("most-recently-served candidate was admitted ahead of an older one: %+v", alloc.Admitted)
	}
}

func TestAccrualDueRules(t *testing.T) {
	now := time.Now()
	if !AccrualDue(nil, now, time.Minute) {
		t.Fatal("expected accrual due when never accrued")
	}
	recent := now.Add(-30 * time.Second)
	if AccrualDue(&recent, now, time.Minute) {
		t.Fatal("expected accrual not due within the refresh interval")
	}
	old := now.Add(-2 * time.Minute)
	if !AccrualDue(&old, now, time.Minute) {
		t.Fatal("expected accrual due after the refresh interval elapsed")
	}
}
