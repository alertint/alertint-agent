// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"testing"
	"time"
)

var drillGroupLabels = []string{"cluster", "namespace", "service"}

func drillCand(id, salt, lifecycle string, lastUpdated time.Time) drillSituationCandidate {
	// Mirrors materializeScenario: cluster is the salted (first) label; namespace
	// and service take their canned values. Group key is sorted k=v.
	gk := "cluster=drill-cluster-flagship-" + salt + ",namespace=drill-shop,service=drill-checkout"
	return drillSituationCandidate{ID: id, GroupKey: gk, Lifecycle: lifecycle, UpdatedAt: lastUpdated}
}

func TestDrillRerunSalt_ReusesSaltInHorizon(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{drillCand("sit1", "abc123", "active", now.Add(-5*time.Minute))}
	id, lifecycle, salt, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute)
	if !ok || id != "sit1" || lifecycle != "active" || salt != "abc123" {
		t.Fatalf("got (%q, %q, %q, %v), want (sit1, active, abc123, true)", id, lifecycle, salt, ok)
	}
}

func TestDrillRerunSalt_ReceiverGroupingMode(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{{
		ID: "sit1", Lifecycle: "active", UpdatedAt: now.Add(-5 * time.Minute),
		GroupKey: "cluster=drill-cluster-flagship-abc123,host=drill-node-01,namespace=drill-shop,service=drill-checkout",
	}}
	id, _, salt, ok := drillRerunSalt(cands, nil, "flagship", now, 30*time.Minute)
	if !ok || id != "sit1" || salt != "abc123" {
		t.Fatalf("got (%q, %q, %v), want Receiver-mode rerun match", id, salt, ok)
	}
}

func TestDrillRerunSalt_OutsideHorizonMintsFresh(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{drillCand("sit1", "abc123", "active", now.Add(-31*time.Minute))}
	if _, _, _, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute); ok {
		t.Fatal("matched a candidate outside Clock A, want fresh salt")
	}
}

// TestDrillRerunSalt_RecoveryPendingStillMatches: spec — "Reruns inside
// recovery grace may reuse the exact key" — a recovery_pending owner inside
// the window is still a valid reuse target (the server-side refire path
// takes it from there).
func TestDrillRerunSalt_RecoveryPendingStillMatches(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{drillCand("sit1", "abc123", "recovery_pending", now.Add(-2*time.Minute))}
	id, lifecycle, salt, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute)
	if !ok || id != "sit1" || lifecycle != "recovery_pending" || salt != "abc123" {
		t.Fatalf("recovery_pending owner not matched: id=%q lifecycle=%q salt=%q ok=%v", id, lifecycle, salt, ok)
	}
}

// TestDrillRerunSalt_TerminalRecoveredStillMatchesForLinking: spec — "a
// rerun after terminal recovery creates a new linked Drill Situation". The
// matcher itself does not reject a terminal owner: it hands its lifecycle
// back to the caller, which re-fetches the exact group key after firing and
// confirms the runtime minted a fresh, correctly-linked Situation
// (isNewLinkedDrill) rather than attaching into the terminal one.
func TestDrillRerunSalt_TerminalRecoveredStillMatchesForLinking(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{drillCand("sit1", "abc123", "recovered", now.Add(-2*time.Minute))}
	id, lifecycle, salt, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute)
	if !ok || id != "sit1" || lifecycle != "recovered" || salt != "abc123" {
		t.Fatalf("terminal owner not matched: id=%q lifecycle=%q salt=%q ok=%v", id, lifecycle, salt, ok)
	}
}

func TestDrillRerunSalt_NoPriorMintsFresh(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	if _, _, _, ok := drillRerunSalt(nil, drillGroupLabels, "flagship", now, 30*time.Minute); ok {
		t.Fatal("matched with no candidates, want fresh salt")
	}
}

func TestDrillRerunSalt_DifferentScenarioIgnored(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	// A drill Situation whose non-salted labels differ (another target's labels).
	cands := []drillSituationCandidate{{
		ID: "sit1", Lifecycle: "active", UpdatedAt: now.Add(-2 * time.Minute),
		GroupKey: "cluster=drill-cluster-flagship-abc123,namespace=drill-other,service=drill-checkout",
	}}
	if _, _, _, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute); ok {
		t.Fatal("matched a different scenario (non-salted label mismatch)")
	}
}

func TestDrillRerunSalt_CrossScenarioMintsFresh(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	// A storm rerun must not collapse into a fresh flagship Situation: the
	// scenario key in the salted label keeps otherwise-identical group labels
	// apart.
	cands := []drillSituationCandidate{drillCand("sit1", "abc123", "active", now.Add(-2*time.Minute))}
	if _, _, _, ok := drillRerunSalt(cands, drillGroupLabels, "storm", now, 30*time.Minute); ok {
		t.Fatal("storm rerun matched a flagship Situation, want fresh salt")
	}
}

func TestDrillRerunSalt_MostRecentWins(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	cands := []drillSituationCandidate{
		drillCand("old", "salt-old", "active", now.Add(-20*time.Minute)),
		drillCand("new", "salt-new", "active", now.Add(-3*time.Minute)),
	}
	id, _, salt, ok := drillRerunSalt(cands, drillGroupLabels, "flagship", now, 30*time.Minute)
	if !ok || id != "new" || salt != "salt-new" {
		t.Fatalf("got (%q, %q), want the most recent (new, salt-new)", id, salt)
	}
}

// TestPostTerminalRerunUsesLinkedNewSituation: the brief's canonical example
// — a fresh Situation whose previous_situation_id points back at a terminal
// prior is recognized as the expected post-terminal-rerun link.
func TestPostTerminalRerunUsesLinkedNewSituation(t *testing.T) {
	prior := drillSituation("sit-old", "recovered", "")
	next := drillSituation("sit-new", "active", "sit-old")
	if !isNewLinkedDrill(prior, next) {
		t.Fatalf("prior=%+v next=%+v", prior, next)
	}
}

func TestIsNewLinkedDrill_SameIDIsNotNew(t *testing.T) {
	prior := drillSituation("sit-1", "recovered", "")
	next := drillSituation("sit-1", "recovered", "")
	if isNewLinkedDrill(prior, next) {
		t.Fatal("the same Situation id must never count as a new linked Situation")
	}
}

func TestIsNewLinkedDrill_UnlinkedNextRejected(t *testing.T) {
	prior := drillSituation("sit-old", "recovered", "")
	next := drillSituation("sit-new", "active", "") // no previous_situation_id at all
	if isNewLinkedDrill(prior, next) {
		t.Fatal("a next Situation with no previous_situation_id must not be treated as linked")
	}
}

func TestIsNewLinkedDrill_NonterminalPriorRejected(t *testing.T) {
	// A link claim against a nonterminal prior is never trusted — only a
	// terminal owner can legitimately force a fresh linked Situation.
	prior := drillSituation("sit-old", "active", "")
	next := drillSituation("sit-new", "active", "sit-old")
	if isNewLinkedDrill(prior, next) {
		t.Fatal("a nonterminal prior must not be accepted as the source of a link")
	}
}

func TestIsTerminalLifecycle(t *testing.T) {
	cases := map[string]bool{
		"active": false, "recovery_pending": false, "recovered": true, "closed_unknown": true, "": false,
	}
	for lifecycle, want := range cases {
		if got := isTerminalLifecycle(lifecycle); got != want {
			t.Errorf("isTerminalLifecycle(%q) = %v, want %v", lifecycle, got, want)
		}
	}
}
