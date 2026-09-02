// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"
)

func TestEligibleReasonsCatalogOnlyEmitsReachableCodes(t *testing.T) {
	in := baseSnapshotInput(t)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))

	reserved := map[string]bool{
		reasonCodeConfirmedSevereImpact:  true,
		reasonCodeExpandingBlastRadius:   true,
		reasonCodeUrgentPolicy:           true,
		reasonCodeEnvelopeViolation:      true,
		reasonCodeOperatorJudgmentNeeded: true,
	}
	allowed := map[string]bool{
		reasonCodeCriticalAnchor:      true,
		reasonCodeDurationOutlier:     true,
		reasonCodeNovelSymptom:        true,
		reasonCodeTerminalUncertainty: true,
	}

	for _, r := range EligibleReasons(in, symptoms, class) {
		if reserved[r.Code] {
			t.Fatalf("reserved code %q must never be emitted", r.Code)
		}
		if !allowed[r.Code] {
			t.Fatalf("unknown reason code %q", r.Code)
		}
	}
}

func TestEligibleReasonsCriticalAnchorUnreachableGivenCurrentData(t *testing.T) {
	// situation.Delivery carries no severity signal at all (Task 3
	// deliberately excluded labels/annotations as SQL-facing internals),
	// so "confirmed active critical source severity" can never be proven
	// from this task's inputs. Documented, not a bug — see
	// criticalAnchorEligible's doc comment.
	in := baseSnapshotInput(t)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeCriticalAnchor {
			t.Fatal("critical_anchor must not be reachable given current SnapshotInput data")
		}
	}
}

func TestEligibleReasonsNovelSymptomUnreachableGivenCurrentData(t *testing.T) {
	// CompletedSituation carries no persisted symptom history, so "local
	// history proves confirmed absence" can never be proven — not even
	// with zero prior Situations, which might look like "confirmed
	// absence" but is really "no data either way".
	in := baseSnapshotInput(t)
	in.PriorSituations = nil
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeNovelSymptom {
			t.Fatal("novel_symptom must not be reachable given current SnapshotInput data")
		}
	}
}

func TestEligibleReasonsTerminalUncertaintyUnreachableGivenCurrentData(t *testing.T) {
	// No source-aware lifecycle-observation-deadline machinery is
	// available to this task's pure inputs (that formula belongs to Task
	// 8's lifecycle.go) — even an implausibly long elapsed duration must
	// not manufacture eligibility.
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(365 * 24 * time.Hour)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeTerminalUncertainty {
			t.Fatal("terminal_uncertainty must not be reachable given current SnapshotInput data")
		}
	}
}

func TestEligibleReasonsDurationOutlierRequiresFiveComparableSituations(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(10 * time.Hour) // way longer than any prior
	in.PriorSituations = fiveShortPriorSituations(in.Situation.GroupKey, in.Situation.EffectiveStartedAt)[:4]
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeDurationOutlier {
			t.Fatal("duration_outlier must require at least five comparable completed Situations")
		}
	}
}

func TestEligibleReasonsDurationOutlierEligibleWithFiveShortPriorsAndLongCurrent(t *testing.T) {
	in := baseSnapshotInput(t)
	start := in.Situation.EffectiveStartedAt
	in.Now = start.Add(10 * time.Hour) // 36000s, far beyond p95=300s and 2*median=600s
	in.PriorSituations = fiveShortPriorSituations(in.Situation.GroupKey, start)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))

	found := false
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeDurationOutlier {
			found = true
			if r.DeterministicFloor {
				t.Fatal("duration_outlier must not be a deterministic floor")
			}
			if r.CatalogVersion != reasonCatalogVersion {
				t.Fatalf("CatalogVersion = %d, want %d", r.CatalogVersion, reasonCatalogVersion)
			}
			if r.PredicateVersion != predicateVersionDurationOutlier {
				t.Fatalf("PredicateVersion = %d, want %d", r.PredicateVersion, predicateVersionDurationOutlier)
			}
			if len(r.EvidenceRefs) == 0 {
				t.Fatal("duration_outlier candidate must carry supporting evidence references")
			}
		}
	}
	if !found {
		t.Fatal("expected duration_outlier to be eligible with 5 comparable short prior Situations and a much longer current elapsed duration")
	}
}

func TestEligibleReasonsDurationOutlierIneligibleWhenNotAnOutlier(t *testing.T) {
	in := baseSnapshotInput(t)
	start := in.Situation.EffectiveStartedAt
	in.Now = start.Add(6 * time.Minute) // close to the 5-minute priors, not an outlier
	in.PriorSituations = fiveShortPriorSituations(in.Situation.GroupKey, start)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	for _, r := range EligibleReasons(in, symptoms, class) {
		if r.Code == reasonCodeDurationOutlier {
			t.Fatal("duration_outlier must not be eligible when elapsed duration is comparable to prior history")
		}
	}
}

func TestEligibleReasonsOrderIndependentOfPriorSituationRowOrder(t *testing.T) {
	in := baseSnapshotInput(t)
	start := in.Situation.EffectiveStartedAt
	in.Now = start.Add(10 * time.Hour)
	priors := fiveShortPriorSituations(in.Situation.GroupKey, start)
	in.PriorSituations = priors
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	a := EligibleReasons(in, symptoms, class)

	shuffled := append([]CompletedSituation{}, priors...)
	shuffled[0], shuffled[len(shuffled)-1] = shuffled[len(shuffled)-1], shuffled[0]
	in.PriorSituations = shuffled
	b := EligibleReasons(in, symptoms, class)

	if len(a) != len(b) {
		t.Fatalf("reason set size changed under shuffled prior situation row order: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Code != b[i].Code {
			t.Fatal("reason order/content changed under shuffled prior situation row order")
		}
	}
}

func TestEligibleReasonsCandidateIDStableAndNonEmpty(t *testing.T) {
	in := baseSnapshotInput(t)
	start := in.Situation.EffectiveStartedAt
	in.Now = start.Add(10 * time.Hour)
	in.PriorSituations = fiveShortPriorSituations(in.Situation.GroupKey, start)
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))

	a := EligibleReasons(in, symptoms, class)
	b := EligibleReasons(in, symptoms, class)
	if len(a) == 0 {
		t.Fatal("expected at least one eligible reason for this fixture")
	}
	for i := range a {
		if a[i].ID == "" {
			t.Fatal("reason candidate ID must not be empty")
		}
		if a[i].ID != b[i].ID {
			t.Fatal("reason candidate ID not stable across identical calls")
		}
	}
}

func TestEligibleReasonsEmptyWhenNoPredicateProven(t *testing.T) {
	in := baseSnapshotInput(t) // no priors, short elapsed, no severity/finding data
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	got := EligibleReasons(in, symptoms, class)
	if len(got) != 0 {
		t.Fatalf("want zero eligible reasons for a minimal fixture, got %+v", got)
	}
}
