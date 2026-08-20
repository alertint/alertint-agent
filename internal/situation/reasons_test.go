// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"reflect"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReasonCatalogEligibility(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{9 * time.Minute, 10 * time.Minute, 11 * time.Minute, 10 * time.Minute, 12 * time.Minute}, 30*time.Minute)
	reasons := EligibleReasons(s)
	r := requireReason(t, reasons, "duration_outlier")
	if r.PredicateVersion != 1 || len(r.EvidenceRefs) < 2 {
		t.Fatalf("reason=%+v", r)
	}
	if got := DeriveInterruptionPriority(assessmentFor(r, model.AttentionInvestigate, model.NextActorAlertint)); got != model.PriorityMedium {
		t.Fatalf("priority=%s", got)
	}
}

func TestEligibleReasonsEmitsAllNineEvidenceBoundCodes(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{5 * time.Minute, 6 * time.Minute, 7 * time.Minute, 8 * time.Minute, 9 * time.Minute}, 20*time.Minute)
	s.Symptoms = []Symptom{
		{ID: "critical", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", Novel: true, EvidenceRefs: []string{"delivery:critical", "history:symptoms"}},
	}
	s.Impact = []ImpactFact{{Kind: "availability", Severity: "severe", Confirmed: true, EvidenceRefs: []string{"fact:availability"}}}
	s.BlastRadius = &BlastRadius{Previous: 2, Current: 4, UrgentBoundary: 3, EvidenceRefs: []string{"fact:scope-before", "fact:scope-now"}}
	s.UrgentPolicies = []UrgentPolicy{{ID: "policy:1", Active: true, Scoped: true, EvidenceRefs: []string{"policy:1"}}}
	s.Envelope = &model.EnvelopeEvaluation{Result: model.EnvelopeEvaluationViolation, Violations: []string{"duration"}, Observability: []string{"fact:duration"}}
	s.SemanticChoice = &SemanticChoice{Code: "owning_team", State: model.ActionStatusExhausted, EvidenceRefs: []string{"run:ownership"}}
	s.TerminalUncertainty = &TerminalUncertainty{DeadlineCrossed: true, Actionable: true, Reason: model.TerminalReasonSourceUnavailable, EvidenceRefs: []string{"fact:lifecycle", "deadline:lifecycle"}}

	got := EligibleReasons(s)
	codes := make([]string, len(got))
	for i := range got {
		codes[i] = got[i].Code
		if got[i].ID == "" || got[i].CatalogVersion != ReasonCatalogVersion || len(got[i].EvidenceRefs) == 0 {
			t.Fatalf("unbound reason = %+v", got[i])
		}
	}
	want := []string{"confirmed_severe_impact", "critical_anchor", "duration_outlier", "envelope_violation", "expanding_blast_radius", "novel_symptom", "operator_judgment_needed", "terminal_uncertainty", "urgent_policy"}
	if !reflect.DeepEqual(codes, want) {
		t.Fatalf("codes = %v, want %v", codes, want)
	}
	for _, code := range []string{"critical_anchor", "confirmed_severe_impact", "expanding_blast_radius", "urgent_policy"} {
		if !requireReason(t, got, code).DeterministicFloor {
			t.Fatalf("%s is not a floor", code)
		}
	}
}

func TestReasonCandidatesAreReplayStableAndEvidenceBound(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{9 * time.Minute, 10 * time.Minute, 11 * time.Minute, 10 * time.Minute, 12 * time.Minute}, 30*time.Minute)
	a := requireReason(t, EligibleReasons(s), "duration_outlier")
	s.CompletedEpisodes[0], s.CompletedEpisodes[4] = s.CompletedEpisodes[4], s.CompletedEpisodes[0]
	b := requireReason(t, EligibleReasons(s), "duration_outlier")
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay changed candidate:\n%+v\n%+v", a, b)
	}
	s.CompletedEpisodes[0].EvidenceRefs = []string{"episode:changed"}
	c := requireReason(t, EligibleReasons(s), "duration_outlier")
	if a.ID == c.ID {
		t.Fatal("material evidence change retained candidate id")
	}
}

func TestCriticalCandidateAggregatesEvidenceIndependentOfSymptomOrder(t *testing.T) {
	s := sampleSnapshot()
	s.Symptoms = []Symptom{
		{ID: "b", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", EvidenceRefs: []string{"delivery:b"}},
		{ID: "a", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", EvidenceRefs: []string{"delivery:a"}},
	}
	a := requireReason(t, EligibleReasons(s), "critical_anchor")
	s.Symptoms[0], s.Symptoms[1] = s.Symptoms[1], s.Symptoms[0]
	b := requireReason(t, EligibleReasons(s), "critical_anchor")
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a.EvidenceRefs, []string{"delivery:a", "delivery:b"}) {
		t.Fatalf("critical evidence depends on order:\n%+v\n%+v", a, b)
	}
}

func TestWeakOrUnboundSignalsProduceNoReason(t *testing.T) {
	s := sampleSnapshot()
	s.Symptoms = []Symptom{{ID: "new-incident-alert-name", Lifecycle: model.DeliveryStatusFiring, Severity: "high", Novel: true}}
	s.L1 = &L1Finding{Summary: "model thinks this is important", ConfidenceClass: "high"}
	s.SemanticChoice = &SemanticChoice{Code: "owning_team", State: model.ActionStatusBlocked, EvidenceRefs: []string{"run:ownership"}}
	if got := EligibleReasons(s); len(got) != 0 {
		t.Fatalf("weak signals produced reasons: %+v", got)
	}
}

func TestDurationOutlierRequiresFiveComparableAndStrictThresholds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		history []time.Duration
		current time.Duration
	}{
		{"four episodes", []time.Duration{9 * time.Minute, 10 * time.Minute, 11 * time.Minute, 12 * time.Minute}, 30 * time.Minute},
		{"equal twice median", []time.Duration{9 * time.Minute, 10 * time.Minute, 10 * time.Minute, 11 * time.Minute, 12 * time.Minute}, 20 * time.Minute},
		{"not above p95", []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute, 20 * time.Minute}, 19 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EligibleReasons(snapshotWithCompletedDurations(tc.history, tc.current)); hasReason(got, "duration_outlier") {
				t.Fatalf("duration outlier admitted: %+v", got)
			}
		})
	}
}

func snapshotWithCompletedDurations(history []time.Duration, current time.Duration) Snapshot {
	s := sampleSnapshot()
	s.ElapsedSeconds = int64(current / time.Second)
	s.DurationClass = "long"
	s.CurrentDurationEvidenceRefs = []string{"fact:current-duration"}
	s.CompletedEpisodes = make([]CompletedEpisode, len(history))
	for i, duration := range history {
		s.CompletedEpisodes[i] = CompletedEpisode{ID: string(rune('a' + i)), DurationSeconds: int64(duration / time.Second), Comparable: true, EvidenceRefs: []string{"episode:" + string(rune('a'+i))}}
	}
	return s
}

func requireReason(t *testing.T, reasons []model.ReasonCandidate, code string) model.ReasonCandidate {
	t.Helper()
	for _, reason := range reasons {
		if reason.Code == code {
			return reason
		}
	}
	t.Fatalf("reason %q not found in %+v", code, reasons)
	return model.ReasonCandidate{}
}

func hasReason(reasons []model.ReasonCandidate, code string) bool {
	for _, reason := range reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}
