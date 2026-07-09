// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"testing"
	"time"
)

var drillGroupLabels = []string{"cluster", "namespace", "service"}

func drillCand(id, salt, status string, drill bool, lastAlert time.Time) drillCandidate {
	// Mirrors materializeScenario: cluster is the salted (first) label; namespace
	// and service take their canned values. Group key is sorted k=v.
	gk := "cluster=drill-cluster-" + salt + ",namespace=drill-shop,service=drill-checkout"
	return drillCandidate{ID: id, GroupKey: gk, Status: status, Drill: drill, LastAlertAt: lastAlert}
}

func TestDrillRerunSalt_ReusesSaltInHorizon(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillCandidate{drillCand("inc1", "abc123", "analyzed", true, now.Add(-5*time.Minute))}
	id, salt, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute)
	if !ok || id != "inc1" || salt != "abc123" {
		t.Fatalf("got (%q, %q, %v), want (inc1, abc123, true)", id, salt, ok)
	}
}

func TestDrillRerunSalt_OutsideHorizonMintsFresh(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillCandidate{drillCand("inc1", "abc123", "analyzed", true, now.Add(-31*time.Minute))}
	if _, _, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute); ok {
		t.Fatal("matched a candidate outside Clock A, want fresh salt")
	}
}

func TestDrillRerunSalt_ResolvedStillMatches(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillCandidate{drillCand("inc1", "abc123", "resolved", true, now.Add(-2*time.Minute))}
	if _, salt, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute); !ok || salt != "abc123" {
		t.Fatalf("resolved drill not matched: salt=%q ok=%v (attach-to-resolved is valid)", salt, ok)
	}
}

func TestDrillRerunSalt_NoPriorMintsFresh(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	if _, _, ok := drillRerunSalt(nil, drillGroupLabels, now, 30*time.Minute); ok {
		t.Fatal("matched with no candidates, want fresh salt")
	}
}

func TestDrillRerunSalt_NonDrillIgnored(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillCandidate{drillCand("inc1", "abc123", "analyzed", false, now.Add(-2*time.Minute))}
	if _, _, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute); ok {
		t.Fatal("matched a non-drill incident, want drill parity to reject it")
	}
}

func TestDrillRerunSalt_DifferentScenarioIgnored(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	// A drill incident whose non-salted labels differ (another scenario/target).
	cands := []drillCandidate{{
		ID: "inc1", Status: "analyzed", Drill: true, LastAlertAt: now.Add(-2 * time.Minute),
		GroupKey: "cluster=drill-cluster-abc123,namespace=drill-other,service=drill-checkout",
	}}
	if _, _, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute); ok {
		t.Fatal("matched a different scenario (non-salted label mismatch)")
	}
}

func TestDrillRerunSalt_MostRecentWins(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillCandidate{
		drillCand("old", "salt-old", "analyzed", true, now.Add(-20*time.Minute)),
		drillCand("new", "salt-new", "analyzed", true, now.Add(-3*time.Minute)),
	}
	id, salt, ok := drillRerunSalt(cands, drillGroupLabels, now, 30*time.Minute)
	if !ok || id != "new" || salt != "salt-new" {
		t.Fatalf("got (%q, %q), want the most recent (new, salt-new)", id, salt)
	}
}
