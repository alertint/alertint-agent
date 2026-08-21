// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReasonCatalogEligibility(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{9 * time.Minute, 10 * time.Minute, 11 * time.Minute, 10 * time.Minute, 12 * time.Minute}, 30*time.Minute)
	reasons := EligibleReasons(s)
	r := requireReason(t, reasons, "duration_outlier")
	if r.PredicateVersion != 2 || len(r.EvidenceRefs) < 2 {
		t.Fatalf("reason=%+v", r)
	}
	if got := DeriveInterruptionPriority(assessmentFor(r, model.AttentionInvestigate, model.NextActorAlertint)); got != model.PriorityMedium {
		t.Fatalf("priority=%s", got)
	}
}

func TestEligibleReasonsEmitsAllNineEvidenceBoundCodes(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{5 * time.Minute, 6 * time.Minute, 7 * time.Minute, 8 * time.Minute, 9 * time.Minute}, 20*time.Minute)
	s.Symptoms = []Symptom{
		{ID: "critical", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", Novel: true, EvidenceRefs: []string{"delivery:critical"}, NoveltyEvidenceRefs: []string{"history:symptoms"}},
	}
	s.Impact = []ImpactFact{{Kind: "availability", Severity: "severe", Confirmed: true, EvidenceRefs: []string{"fact:availability"}}}
	s.BlastRadius = &BlastRadius{Previous: 2, Current: 4, UrgentBoundary: 3, EvidenceRefs: []string{"fact:scope-before", "fact:scope-now"}}
	s.UrgentPolicies = []UrgentPolicy{{ID: "policy:1", Active: true, Scoped: true, EvidenceRefs: []string{"policy:1"}}}
	s.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 1, Result: model.EnvelopeEvaluationViolation,
		Violations: []string{"duration"}, Observability: []string{"mandatory_signals_observable"}, EvidenceRefs: []string{"fact:duration"}}
	s.Facts = append(s.Facts,
		semanticFact("fact:critical", "symptom_state", "critical", `{"lifecycle":"firing","severity":"critical"}`, "delivery:critical"),
		semanticFactWithStatus("history:symptoms", "symptom_history", "critical", `{"absent":true,"comparable":true}`, observationmodel.ResultStatusConfirmedEmpty),
		semanticFact("fact:availability", "impact", "availability", `{"confirmed":true,"kind":"availability","severity":"severe"}`),
		semanticFact("fact:blast-radius", "blast_radius", s.SituationID, `{"current":4,"previous":2,"urgent_boundary":3}`, "fact:scope-before", "fact:scope-now"),
		semanticFact("policy:1", "urgent_policy", "policy:1", `{"active":true,"scoped":true}`),
		semanticFact("fact:duration", "envelope_evaluation", "envelope:1", `{"envelope_version":1,"matched_fields":[],"observability":["mandatory_signals_observable"],"quieting_authority":false,"result":"violation","violations":["duration"]}`),
		semanticFact("run:ownership", "semantic_choice", "owning_team", `{"state":"exhausted"}`),
		semanticFact("fact:lifecycle", "terminal_uncertainty", s.SituationID, `{"actionable":true,"deadline_crossed":true,"reason":"source_unavailable"}`, "deadline:lifecycle"),
	)
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
	for i := range s.Facts {
		if s.Facts[i].Subject == s.CompletedEpisodes[0].ID {
			s.Facts[i].EvidenceRefs = []string{"episode:changed"}
		}
	}
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
	s.Facts = []observationmodel.Fact{
		semanticFact("fact:b", "symptom_state", "b", `{"lifecycle":"firing","severity":"critical"}`, "delivery:b"),
		semanticFact("fact:a", "symptom_state", "a", `{"lifecycle":"firing","severity":"critical"}`, "delivery:a"),
	}
	a := requireReason(t, EligibleReasons(s), "critical_anchor")
	s.Symptoms[0], s.Symptoms[1] = s.Symptoms[1], s.Symptoms[0]
	b := requireReason(t, EligibleReasons(s), "critical_anchor")
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a.EvidenceRefs, []string{"delivery:a", "delivery:b", "fact:a", "fact:b"}) {
		t.Fatalf("critical evidence depends on order:\n%+v\n%+v", a, b)
	}
}

func TestWeakOrUnboundSignalsProduceNoReason(t *testing.T) {
	s := sampleSnapshot()
	s.Symptoms = []Symptom{{ID: "new-incident-alert-name", Lifecycle: model.DeliveryStatusFiring, Severity: "high", Novel: true}}
	s.SemanticChoice = &SemanticChoice{Code: "owning_team", State: model.ActionStatusBlocked, EvidenceRefs: []string{"run:ownership"}}
	if got := EligibleReasons(s); len(got) != 0 {
		t.Fatalf("weak signals produced reasons: %+v", got)
	}
}

func TestNovelSymptomRequiresComparableHistoryAbsenceEvidence(t *testing.T) {
	s := sampleSnapshot()
	s.Symptoms = []Symptom{{ID: "new-symptom", Lifecycle: model.DeliveryStatusFiring, Novel: true, EvidenceRefs: []string{"delivery:new"}}}
	if got := EligibleReasons(s); hasReason(got, "novel_symptom") {
		t.Fatalf("novel symptom admitted without history-absence evidence: %+v", got)
	}
}

func TestEnvelopeViolationRequiresObservabilityEvidence(t *testing.T) {
	s := sampleSnapshot()
	s.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 2,
		Result: model.EnvelopeEvaluationViolation, Violations: []string{"duration"}, Observability: []string{"mandatory_signals_observable"}}
	if got := EligibleReasons(s); hasReason(got, "envelope_violation") {
		t.Fatalf("envelope labels admitted without evidence: %+v", got)
	}
}

func TestNovelAndEnvelopeEvidenceReferencesMustResolveToFacts(t *testing.T) {
	novel := sampleSnapshot()
	novel.Symptoms = []Symptom{{ID: "new-symptom", Lifecycle: model.DeliveryStatusFiring, Novel: true,
		EvidenceRefs: []string{"delivery:new"}, NoveltyEvidenceRefs: []string{"fact:missing-history"}}}
	if got := EligibleReasons(novel); hasReason(got, "novel_symptom") {
		t.Fatalf("unresolved novelty evidence admitted: %+v", got)
	}
	novel.Facts = []observationmodel.Fact{semanticFact("fact:missing-history", "unrelated", "new-symptom", `{"present":true}`)}
	if got := EligibleReasons(novel); hasReason(got, "novel_symptom") {
		t.Fatalf("unrelated novelty evidence admitted: %+v", got)
	}
	novel.Facts = []observationmodel.Fact{
		semanticFact("fact:new-symptom", "symptom_state", "new-symptom", `{"lifecycle":"firing","severity":""}`, "delivery:new"),
		semanticFactWithStatus("fact:missing-history", "symptom_history", "new-symptom", `{"absent":true,"comparable":true}`, observationmodel.ResultStatusConfirmedEmpty),
	}
	if got := EligibleReasons(novel); !hasReason(got, "novel_symptom") {
		t.Fatalf("resolved novelty evidence rejected: %+v", got)
	}

	envelope := sampleSnapshot()
	envelope.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 2,
		Result: model.EnvelopeEvaluationViolation, Violations: []string{"duration"}, Observability: []string{"duration_observed"},
		EvidenceRefs: []string{"fact:missing-duration"}}
	if got := EligibleReasons(envelope); hasReason(got, "envelope_violation") {
		t.Fatalf("unresolved envelope evidence admitted: %+v", got)
	}
	envelope.Facts = []observationmodel.Fact{semanticFact("fact:missing-duration", "unrelated", "envelope:1", `{"present":true}`)}
	if got := EligibleReasons(envelope); hasReason(got, "envelope_violation") {
		t.Fatalf("unrelated envelope evidence admitted: %+v", got)
	}
	envelope.Facts = []observationmodel.Fact{semanticFact("fact:missing-duration", "envelope_evaluation", "envelope:1",
		`{"envelope_version":2,"matched_fields":[],"observability":["duration_observed"],"quieting_authority":false,"result":"violation","violations":["duration"]}`)}
	if got := EligibleReasons(envelope); !hasReason(got, "envelope_violation") {
		t.Fatalf("resolved envelope evidence rejected: %+v", got)
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

func TestDurationOutlierEvenMedianKeepsHalfSecondThreshold(t *testing.T) {
	s := snapshotWithCompletedDurations([]time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second, 11 * time.Second, 11 * time.Second, 12 * time.Second}, 21*time.Second)
	if got := EligibleReasons(s); hasReason(got, "duration_outlier") {
		t.Fatalf("duration equal to twice exact median admitted: %+v", got)
	}
}

func snapshotWithCompletedDurations(history []time.Duration, current time.Duration) Snapshot {
	s := sampleSnapshot()
	s.ElapsedSeconds = int64(current / time.Second)
	s.DurationClass = "long"
	s.CurrentDurationEvidenceRefs = []string{"fact:current-duration"}
	s.Facts = []observationmodel.Fact{semanticFact("fact:current-duration", "current_duration", s.SituationID,
		`{"duration_class":"long","elapsed_seconds":`+timeSeconds(current)+`}`)}
	s.CompletedEpisodes = make([]CompletedEpisode, len(history))
	for i, duration := range history {
		id := string(rune('a' + i))
		ref := "episode:" + id
		s.CompletedEpisodes[i] = CompletedEpisode{ID: id, DurationSeconds: int64(duration / time.Second), Comparable: true, EvidenceRefs: []string{ref}}
		s.Facts = append(s.Facts, semanticFact(ref, "completed_episode", id,
			`{"comparable":true,"duration_seconds":`+timeSeconds(duration)+`}`))
	}
	return s
}

func TestEveryReasonRequiresFreshConfirmedMaterialSemanticEvidence(t *testing.T) {
	codes := []string{"critical_anchor", "confirmed_severe_impact", "expanding_blast_radius", "urgent_policy", "duration_outlier", "novel_symptom", "envelope_violation", "operator_judgment_needed", "terminal_uncertainty"}
	for _, code := range codes {
		t.Run(code+" valid", func(t *testing.T) {
			s, target := snapshotForReasonEvidence(code)
			if !hasReason(EligibleReasons(s), code) {
				t.Fatalf("valid %s semantic evidence rejected; target=%s", code, target)
			}
		})
		for _, abuse := range []struct {
			name   string
			mutate func(*observationmodel.Fact)
		}{
			{"unavailable", func(f *observationmodel.Fact) { f.ResultStatus = observationmodel.ResultStatusUnavailable }},
			{"unconfirmed", func(f *observationmodel.Fact) { f.ResultStatus = observationmodel.ResultStatusUnconfirmedEmpty }},
			{"stale", func(f *observationmodel.Fact) { f.Freshness = observationmodel.FreshnessStale }},
			{"nonmaterial", func(f *observationmodel.Fact) { f.Material = false }},
			{"unrelated kind", func(f *observationmodel.Fact) { f.Kind = "unrelated" }},
			{"unrelated subject", func(f *observationmodel.Fact) { f.Subject = "other" }},
			{"wrong situation", func(f *observationmodel.Fact) { f.SituationID = "s-other" }},
			{"wrong input", func(f *observationmodel.Fact) { f.InputVersion++ }},
			{"contradictory value", func(f *observationmodel.Fact) { f.Value = []byte(`{}`) }},
		} {
			t.Run(code+" "+abuse.name, func(t *testing.T) {
				s, target := snapshotForReasonEvidence(code)
				for i := range s.Facts {
					if s.Facts[i].ID == target {
						abuse.mutate(&s.Facts[i])
					}
				}
				if got := EligibleReasons(s); hasReason(got, code) {
					t.Fatalf("%s admitted with %s evidence: %+v", code, abuse.name, got)
				}
			})
		}
	}
}

func snapshotForReasonEvidence(code string) (Snapshot, string) {
	s := sampleSnapshot()
	s.Facts = nil
	switch code {
	case "critical_anchor":
		s.Symptoms = []Symptom{{ID: "critical", Lifecycle: model.DeliveryStatusFiring, Severity: "critical", EvidenceRefs: []string{"delivery:critical"}}}
		s.Facts = []observationmodel.Fact{semanticFact("fact:critical", "symptom_state", "critical", `{"lifecycle":"firing","severity":"critical"}`, "delivery:critical")}
		return s, "fact:critical"
	case "confirmed_severe_impact":
		s.Impact = []ImpactFact{{Kind: "availability", Severity: "severe", Confirmed: true, EvidenceRefs: []string{"fact:availability"}}}
		s.Facts = []observationmodel.Fact{semanticFact("fact:availability", "impact", "availability", `{"confirmed":true,"kind":"availability","severity":"severe"}`)}
		return s, "fact:availability"
	case "expanding_blast_radius":
		s.BlastRadius = &BlastRadius{Previous: 1, Current: 3, UrgentBoundary: 2, EvidenceRefs: []string{"fact:scope-before", "fact:scope-now"}}
		s.Facts = []observationmodel.Fact{semanticFact("fact:blast", "blast_radius", s.SituationID, `{"current":3,"previous":1,"urgent_boundary":2}`, "fact:scope-before", "fact:scope-now")}
		return s, "fact:blast"
	case "urgent_policy":
		s.UrgentPolicies = []UrgentPolicy{{ID: "policy:1", Active: true, Scoped: true, EvidenceRefs: []string{"policy:1"}}}
		s.Facts = []observationmodel.Fact{semanticFact("policy:1", "urgent_policy", "policy:1", `{"active":true,"scoped":true}`)}
		return s, "policy:1"
	case "duration_outlier":
		s = snapshotWithCompletedDurations([]time.Duration{5 * time.Minute, 6 * time.Minute, 7 * time.Minute, 8 * time.Minute, 9 * time.Minute}, 20*time.Minute)
		return s, "fact:current-duration"
	case "novel_symptom":
		s.Symptoms = []Symptom{{ID: "novel", Lifecycle: model.DeliveryStatusFiring, Novel: true, EvidenceRefs: []string{"delivery:novel"}, NoveltyEvidenceRefs: []string{"fact:novel-history"}}}
		s.Facts = []observationmodel.Fact{
			semanticFact("fact:novel", "symptom_state", "novel", `{"lifecycle":"firing","severity":""}`, "delivery:novel"),
			semanticFactWithStatus("fact:novel-history", "symptom_history", "novel", `{"absent":true,"comparable":true}`, observationmodel.ResultStatusConfirmedEmpty),
		}
		return s, "fact:novel-history"
	case "envelope_violation":
		s.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 2, Result: model.EnvelopeEvaluationViolation,
			Violations: []string{"duration"}, Observability: []string{"duration_observed"}, EvidenceRefs: []string{"fact:envelope"}}
		s.Facts = []observationmodel.Fact{semanticFact("fact:envelope", "envelope_evaluation", "envelope:1",
			`{"envelope_version":2,"matched_fields":[],"observability":["duration_observed"],"quieting_authority":false,"result":"violation","violations":["duration"]}`)}
		return s, "fact:envelope"
	case "operator_judgment_needed":
		s = snapshotWithCompletedDurations([]time.Duration{5 * time.Minute, 6 * time.Minute, 7 * time.Minute, 8 * time.Minute, 9 * time.Minute}, 20*time.Minute)
		s.SemanticChoice = &SemanticChoice{Code: "owning_team", State: model.ActionStatusExhausted, EvidenceRefs: []string{"fact:choice"}}
		s.Facts = append(s.Facts, semanticFact("fact:choice", "semantic_choice", "owning_team", `{"state":"exhausted"}`))
		return s, "fact:choice"
	case "terminal_uncertainty":
		s.TerminalUncertainty = &TerminalUncertainty{DeadlineCrossed: true, Actionable: true, Reason: model.TerminalReasonSourceUnavailable, EvidenceRefs: []string{"fact:terminal"}}
		s.Facts = []observationmodel.Fact{semanticFact("fact:terminal", "terminal_uncertainty", s.SituationID, `{"actionable":true,"deadline_crossed":true,"reason":"source_unavailable"}`)}
		return s, "fact:terminal"
	default:
		panic("unknown reason code")
	}
}

func semanticFact(id, kind, subject, value string, refs ...string) observationmodel.Fact {
	f := fact(id, kind, value)
	f.Subject = subject
	f.EvidenceRefs = append([]string(nil), refs...)
	return f
}

func semanticFactWithStatus(id, kind, subject, value string, status observationmodel.ResultStatus, refs ...string) observationmodel.Fact {
	f := semanticFact(id, kind, subject, value, refs...)
	f.ResultStatus = status
	return f
}

func timeSeconds(value time.Duration) string {
	return strconv.FormatInt(int64(value/time.Second), 10)
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
