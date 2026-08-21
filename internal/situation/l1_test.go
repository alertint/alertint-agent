// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func trustedAssessment(hash string) TrustedAssessment {
	return TrustedAssessment{Sequence: 4, FactHash: hash, Trustworthy: true}
}

// TestBPlusSkipsOnlyCoveredUnchangedFacts verifies the B+ gate skips only
// when a trustworthy Assessment already covers the exact current material
// hash, and requests L1 the moment the hash changes.
func TestBPlusSkipsOnlyCoveredUnchangedFacts(t *testing.T) {
	covered := sampleSnapshot()
	covered.MaterialHash = "sha256:same"
	if got := DecideL1(covered, trustedAssessment("sha256:same")); got.Status != L1StatusNotRequested {
		t.Fatalf("decision=%+v", got)
	}
	if got := DecideL1(covered, trustedAssessment("sha256:same")); got.DecisionReason != L1ReasonCoveredUnchanged {
		t.Fatalf("decision reason=%q", got.DecisionReason)
	}

	changed := covered
	changed.MaterialHash = "sha256:changed"
	if got := DecideL1(changed, trustedAssessment("sha256:same")); got.Status != L1StatusPlanned {
		t.Fatalf("decision=%+v", got)
	}
}

// TestBPlusRequiresTrustworthyPriorAssessment verifies an untrustworthy prior
// Assessment (e.g. a degraded deterministic-floor attempt) never justifies a
// skip, even when its covered hash matches exactly.
func TestBPlusRequiresTrustworthyPriorAssessment(t *testing.T) {
	snap := sampleSnapshot()
	snap.MaterialHash = "sha256:same"
	untrustworthy := TrustedAssessment{Sequence: 2, FactHash: "sha256:same", Trustworthy: false}
	got := DecideL1(snap, untrustworthy)
	if got.Status != L1StatusPlanned {
		t.Fatalf("decision=%+v, want planned for an untrustworthy prior", got)
	}
}

// TestBPlusFirstAssessmentHasNoCoveredHash verifies the very first
// reconciliation (no prior Assessment at all) always plans L1.
func TestBPlusFirstAssessmentHasNoCoveredHash(t *testing.T) {
	snap := sampleSnapshot()
	snap.MaterialHash = "sha256:first"
	got := DecideL1(snap, TrustedAssessment{})
	if got.Status != L1StatusPlanned || got.DecisionReason != L1ReasonMaterialChange {
		t.Fatalf("decision=%+v", got)
	}
}

// TestBPlusReasonNamesEligibleTrigger verifies the decision reason names the
// most specific already-eligible category rather than a generic fallback.
func TestBPlusReasonNamesEligibleTrigger(t *testing.T) {
	snap := sampleSnapshot()
	snap.MaterialHash = "sha256:novel"
	snap.EligibleReasons = []model.ReasonCandidate{{Code: "novel_symptom"}}
	got := DecideL1(snap, TrustedAssessment{})
	if got.DecisionReason != L1ReasonNovelOrChangedSymptom {
		t.Fatalf("decision reason=%q, want %q", got.DecisionReason, L1ReasonNovelOrChangedSymptom)
	}
}

// TestNormalizeL1WastedRunKeepsMaterialFindingUnchanged verifies two acute
// investigations that reach the same classified conclusion (root cause
// identified, similar confidence band) normalize to the identical material
// L1Finding — a "wasted" re-run must not force L2 reassessment by itself.
func TestNormalizeL1WastedRunKeepsMaterialFindingUnchanged(t *testing.T) {
	first := NormalizeL1(AcuteResult{Summary: "disk saturation", RootCause: "disk is full", Confidence: 0.9})
	second := NormalizeL1(AcuteResult{Summary: "different prose, same conclusion", RootCause: "disk remains full", Confidence: 0.95})

	base := baseSnapshotInput()
	base.L1 = &first
	snapA, err := BuildSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	base.L1 = &second
	snapB, err := BuildSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	if MaterialFactHash(snapA) != MaterialFactHash(snapB) {
		t.Fatal("a wasted L1 re-run (same classified conclusion) changed the material fact hash")
	}
}

// TestNormalizeL1MaterialChangeOnNewConclusion verifies a genuinely different
// classified conclusion (root cause found vs. still unknown) DOES change the
// material fact hash — L1 evidence still counts when it materially moves.
func TestNormalizeL1MaterialChangeOnNewConclusion(t *testing.T) {
	unresolved := NormalizeL1(AcuteResult{Summary: "still investigating", RootCause: "", Confidence: 0.3})
	resolved := NormalizeL1(AcuteResult{Summary: "found it", RootCause: "disk is full", Confidence: 0.9})

	base := baseSnapshotInput()
	base.L1 = &unresolved
	snapA, err := BuildSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	base.L1 = &resolved
	snapB, err := BuildSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	if MaterialFactHash(snapA) == MaterialFactHash(snapB) {
		t.Fatal("a materially different L1 conclusion left the material fact hash unchanged")
	}
}
