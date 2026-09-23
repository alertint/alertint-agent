// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Lead decision B (round 2, 2026-09-09): a bounded identity list is never an
// exact count; the count is known only when the complete frozen union was
// resolved before truncation.
// ----------------------------------------------------------------------

func ewNow(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
}

func ewDeliveries(n int) ([]Delivery, []string) {
	var ds []Delivery
	var frozen []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("alert-%03d", i)
		ds = append(ds, Delivery{ID: id, AlertID: id, Labels: map[string]string{"alertname": id}})
		frozen = append(frozen, id)
	}
	return ds, frozen
}

func ewExecutedIncident(frozen []string) []IncidentState {
	return []IncidentState{{ID: "inc", Triage: TriageState{ActiveAttempt: &TriageExecution{AttemptID: "a1", MemberDeliveryIDs: frozen}}}}
}

// The lead's boundary probe, retained in repo form: eight legacy IDs with no
// recorded count could mean eight or ninety.
func TestInvestigatedInputCountLegacyBoundedListIsUnknown(t *testing.T) {
	w := model.WorkProjection{ExecutionStarted: true, InvestigatedAlertIDs: []string{"a", "b", "c", "d", "e", "f", "g", "h"}}
	if got := investigatedInputCount(w); got != 0 {
		t.Fatalf("legacy bounded list presented as exact count=%d; completeness is unknown", got)
	}
	// A count without the completeness flag is equally unknown: nine
	// identities under the new sixty-four bound prove nothing either.
	w = model.WorkProjection{ExecutionStarted: true, InvestigatedCount: 9}
	if got := investigatedInputCount(w); got != 0 {
		t.Fatalf("a count recorded without completeness presented as exact=%d", got)
	}
}

func TestInvestigatedAlertInputsCountsNineKnownAndBoundsNamesVisibly(t *testing.T) {
	ds, frozen := ewDeliveries(9)
	ids, names, count, known := investigatedAlertInputs(ewExecutedIncident(frozen), ds)
	if count != 9 || !known {
		t.Fatalf("count=%d known=%v, want 9 known", count, known)
	}
	if len(ids) != 9 || len(names) != 8 {
		t.Fatalf("ids=%d names=%d, want 9 identities and 8 display names", len(ids), len(names))
	}
	// The eight-name display bound stays visible as a bound, never implying
	// all names were displayed: the ninth identity is still present.
	if ids[8] != "alert-008" {
		t.Fatalf("ninth identity lost: %v", ids)
	}
}

func TestInvestigatedAlertInputsOverSixtyFourDistinctInputsKeepsExactCount(t *testing.T) {
	ds, frozen := ewDeliveries(70)
	ids, names, count, known := investigatedAlertInputs(ewExecutedIncident(frozen), ds)
	if count != 70 || !known {
		t.Fatalf("count=%d known=%v, want 70 known", count, known)
	}
	if len(ids) != investigatedIdentityLimit || len(names) != investigatedNameLimit {
		t.Fatalf("ids=%d names=%d, want %d/%d bounded lists under an exact count", len(ids), len(names), investigatedIdentityLimit, investigatedNameLimit)
	}
}

func TestInvestigatedAlertInputsDuplicatesCountOnce(t *testing.T) {
	// Two frozen delivery rows for the SAME Alert (a routine re-send) and a
	// repeated delivery id are one input, not three.
	ds := []Delivery{
		{ID: "d1", AlertID: "alert-a", Labels: map[string]string{"alertname": "A"}},
		{ID: "d2", AlertID: "alert-a", Labels: map[string]string{"alertname": "A"}},
		{ID: "d3", AlertID: "alert-b", Labels: map[string]string{"alertname": "B"}},
	}
	incidents := []IncidentState{
		{ID: "i1", Triage: TriageState{LastExecution: &TriageExecution{AttemptID: "a1", MemberDeliveryIDs: []string{"d1", "d2", "d1"}}}},
		{ID: "i2", Triage: TriageState{LastExecution: &TriageExecution{AttemptID: "a2", MemberDeliveryIDs: []string{"d3", "d2"}}}},
	}
	ids, _, count, known := investigatedAlertInputs(incidents, ds)
	if count != 2 || !known || len(ids) != 2 {
		t.Fatalf("count=%d known=%v ids=%v, want 2 known distinct inputs", count, known, ids)
	}
}

func TestInvestigatedAlertInputsUnresolvedFrozenDeliveryMakesCountUnknown(t *testing.T) {
	ds, frozen := ewDeliveries(9)
	// One frozen member delivery this Situation no longer carries: the
	// resolved list is still eight, but the count must not claim exactness.
	ds = ds[:8]
	ids, _, count, known := investigatedAlertInputs(ewExecutedIncident(frozen), ds)
	if known {
		t.Fatalf("an unresolved frozen input must leave completeness false: count=%d ids=%d", count, len(ids))
	}
	if len(ids) != 8 {
		t.Fatalf("resolved identities are still provenance: %d", len(ids))
	}
	if got := investigatedInputCount(model.WorkProjection{InvestigatedCount: count, InvestigatedCountKnown: known}); got != 0 {
		t.Fatalf("an incomplete union reported as exact %d", got)
	}
}

func TestInvestigatedAlertInputsNoRecordedInputsIsUnknownNotZero(t *testing.T) {
	// A pre-ledger claim that fell back to incident_alerts recorded no
	// member deliveries at all: unknown, never a known zero.
	_, _, count, known := investigatedAlertInputs(ewExecutedIncident(nil), nil)
	if count != 0 || known {
		t.Fatalf("count=%d known=%v, want 0 unknown", count, known)
	}
	// No execution at all is not an input count either.
	_, _, count, known = investigatedAlertInputs([]IncidentState{{ID: "inc"}}, nil)
	if count != 0 || known {
		t.Fatalf("no execution: count=%d known=%v, want 0 unknown", count, known)
	}
}

func TestInvestigatedInputCountLegacyJSONReadsUnknown(t *testing.T) {
	// Accepted B2 persisted only a bounded identity list; that JSON carries
	// neither the count nor the completeness flag.
	var w model.WorkProjection
	if err := json.Unmarshal([]byte(`{"phase":"executing","execution_started":true,"investigated_alert_ids":["a","b","c","d","e","f","g","h"],"investigated_names":["a","b","c","d","e","f","g","h"],"remaining_incidents":1}`), &w); err != nil {
		t.Fatal(err)
	}
	if w.InvestigatedCountKnown || investigatedInputCount(w) != 0 {
		t.Fatalf("legacy JSON must read as an unknown count: %+v", w)
	}
	if w.EndedWorkKnown || w.EndedWork != nil {
		t.Fatalf("legacy JSON must read as unknown ended work, not empty: %+v", w)
	}
}

func TestFirstExecutionAssuranceOmitsUnqualifiedCountWhenUnknown(t *testing.T) {
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Total: 12})
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Total: 12, Work: model.WorkProjection{
		ExecutionStarted: true, InvestigatedAlertIDs: []string{"a", "b", "c", "d", "e", "f", "g", "h"}, InvestigatedNames: []string{"a", "b", "c", "d", "e", "f", "g", "h"},
	}})
	c := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateFirstExecutionAssurance)
	if c == nil || c.Members == nil {
		t.Fatal("expected a first_execution_assurance candidate")
	}
	if c.Members.CountKnown || c.Members.FiringCount != 0 {
		t.Fatalf("an unknown count must not be reported as a number: %+v", c.Members)
	}
	if c.Members.Total != 12 {
		t.Fatalf("Total stays the Situation total, never the analyzed count: %+v", c.Members)
	}
}

// ----------------------------------------------------------------------
// Lead decision C: the coverage-gap limitation has a complete lifecycle and
// is independent of a contract obstacle in the same cycle.
// ----------------------------------------------------------------------

func TestAbilityChangedCoverageLimitationClearsOnlyWhenTheGapEnds(t *testing.T) {
	lim := func(unavailableBefore, unavailableAfter int) []model.MaterialCandidate {
		p := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Unavailable: unavailableBefore})
		c := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Unavailable: unavailableAfter})
		return MaterialCandidates(&p, c)
	}
	got := hasCandidate(lim(1, 0), model.CandidateAbilityChanged)
	if got == nil || got.Limitation == nil || !got.Limitation.Cleared || got.Limitation.Code != model.LimitationInvestigationUnavailable {
		t.Fatalf("previously communicated coverage loss cannot clear: %+v", got)
	}
	if got := hasCandidate(lim(2, 1), model.CandidateAbilityChanged); got != nil {
		t.Fatalf("a partial fall must not claim clearance while unavailable work remains: %+v", got.Limitation)
	}
	if got := hasCandidate(lim(1, 1), model.CandidateAbilityChanged); got != nil {
		t.Fatalf("an unchanged gap is not a new limitation: %+v", got.Limitation)
	}
	got = hasCandidate(lim(0, 2), model.CandidateAbilityChanged)
	if got == nil || got.Limitation == nil || got.Limitation.Cleared || got.Limitation.Code != model.LimitationInvestigationUnavailable {
		t.Fatalf("a new coverage gap must be reported under its stable code: %+v", got)
	}
}

func TestAbilityChangedContractBlockAndCoverageGapAreIndependentCandidates(t *testing.T) {
	blocked := model.AlertINTStatusBlocked
	running := model.AlertINTStatusRunning
	reason := model.WaitReason("assessment_parked")
	// Same cycle: the contract block clears AND coverage is lost. Neither
	// fact may hide the other behind switch precedence.
	p := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Unavailable: 0})
	p.ActionContract = model.ActionContract{AlertINTStatus: &blocked, WaitReason: &reason}
	c := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Unavailable: 1})
	c.ActionContract = model.ActionContract{AlertINTStatus: &running}
	var codes []string
	for _, cand := range MaterialCandidates(&p, c) {
		if cand.Kind == model.CandidateAbilityChanged && cand.Limitation != nil {
			codes = append(codes, fmt.Sprintf("%s:cleared=%v", cand.Limitation.Code, cand.Limitation.Cleared))
		}
	}
	want := []string{"assessment_parked:cleared=true", model.LimitationInvestigationUnavailable + ":cleared=false"}
	if strings.Join(codes, ",") != strings.Join(want, ",") {
		t.Fatalf("ability candidates = %v, want both %v", codes, want)
	}
}

// ----------------------------------------------------------------------
// Lead decision D: completion provenance. BuildWorkProjection projects
// EndedWork from durable per-incident facts.
// ----------------------------------------------------------------------

func ewCompleted(attemptID, code string, at time.Time, ev *TriageCompletionEvidence) *TriageExecution {
	return &TriageExecution{AttemptID: attemptID, AttemptNumber: 1, StartedAt: at.Add(-time.Minute), MemberDeliveryIDs: []string{"d1"},
		ResultCode: code, OutputDigest: "sha256:out-" + attemptID, CompletedAt: &at, Evidence: ev}
}

func TestBuildWorkProjectionEndedWorkCarriesCompletionProvenance(t *testing.T) {
	now := ewNow(t)
	judged := now.Add(-time.Second)
	skipReason := DecisionReasonCleanSkip
	inc := []IncidentState{
		// Accepted completion (schedule row deleted, status analyzed) with a
		// positively matched empty hypothesis.
		{ID: "inc-settled", Status: "analyzed", Triage: TriageState{LastExecution: ewCompleted("a-settled", "success", now,
			&TriageCompletionEvidence{Hypothesis: "", Observations: []string{"Pod events checked", "  ", "Application errors checked"}, VerificationLimit: "logs_source_unavailable", VerificationGaps: 2, JudgedAt: &judged})}},
		// Typed exhaustion: result code retained, no checks retained.
		{ID: "inc-exhausted", Status: "failed", Triage: TriageState{Phase: "exhausted", Attempts: 5, LastExecution: ewCompleted("a-exhausted", "provider_error", now, nil)}},
		// Pre-claim clean skip: no attempt was ever claimed.
		{ID: "inc-skipped", Status: "ready", Triage: TriageState{Phase: "skipped", DecisionReason: &skipReason}},
		// Still running: not ended.
		{ID: "inc-running", Status: "processing", Triage: TriageState{Phase: "in_flight", Attempts: 1, ActiveAttempt: &TriageExecution{AttemptID: "a-run"}}},
	}
	got := BuildWorkProjection(inc, nil, nil)
	if !got.EndedWorkKnown {
		t.Fatal("a projection built with provenance must mark ended work known")
	}
	if len(got.EndedWork) != 3 {
		t.Fatalf("EndedWork = %+v, want the three ended schedules only", got.EndedWork)
	}
	byID := map[string]model.IncidentWorkOutcome{}
	for _, o := range got.EndedWork {
		byID[o.IncidentID] = o
	}
	settled := byID["inc-settled"]
	if settled.Phase != model.WorkPhaseSettled || settled.AttemptID != "a-settled" || settled.ResultCode != "success" || !settled.EvidenceKnown || settled.Finding == nil {
		t.Fatalf("settled outcome lost provenance: %+v", settled)
	}
	if settled.Finding.Hypothesis != "" || len(settled.Finding.Observations) != 2 || settled.Finding.AnalyzedAt == nil || !settled.Finding.AnalyzedAt.Equal(judged) {
		t.Fatalf("settled finding facts: %+v", settled.Finding)
	}
	if strings.Join(settled.Finding.Unknowns, "|") != "logs_source_unavailable|2 verification checks unavailable or invalid" {
		t.Fatalf("unknowns must use the shared verification wording: %v", settled.Finding.Unknowns)
	}
	exhausted := byID["inc-exhausted"]
	if exhausted.Phase != model.WorkPhaseExhausted || exhausted.AttemptID != "a-exhausted" || exhausted.ResultCode != "provider_error" || exhausted.EvidenceKnown || exhausted.Finding != nil || exhausted.CompletedAt == nil {
		t.Fatalf("exhausted outcome: %+v", exhausted)
	}
	skipped := byID["inc-skipped"]
	if skipped.Phase != model.WorkPhaseSettled || skipped.SkipReason != "prior_coverage" || skipped.AttemptID != "" || skipped.ResultCode != "" {
		t.Fatalf("a pre-claim clean skip must carry no execution identity: %+v", skipped)
	}
	// Deterministic order, so a reload compares byte-identical projections.
	if got.EndedWork[0].IncidentID != "inc-exhausted" || got.EndedWork[2].IncidentID != "inc-skipped" {
		t.Fatalf("EndedWork must be ordered by incident id: %+v", got.EndedWork)
	}
}

func TestBuildWorkProjectionEndedWorkIgnoresAnUnfinishedLastExecution(t *testing.T) {
	// An Incident analyzed before the attempt ledger existed (no attempt) and
	// one whose last ledger row is still in flight both carry no completion.
	inc := []IncidentState{
		{ID: "legacy", Status: "analyzed"},
		{ID: "open", Status: "analyzed", Triage: TriageState{LastExecution: &TriageExecution{AttemptID: "a-open"}}},
	}
	got := BuildWorkProjection(inc, nil, nil)
	for _, o := range got.EndedWork {
		if o.AttemptID != "" || o.ResultCode != "" || o.EvidenceKnown {
			t.Fatalf("no completed attempt may be attributed: %+v", o)
		}
	}
	if len(got.EndedWork) != 2 {
		t.Fatalf("both settled schedules are still ended work: %+v", got.EndedWork)
	}
}

func TestBuildWorkProjectionEndedWorkBoundsTextWithinEachRecord(t *testing.T) {
	now := ewNow(t)
	huge := strings.Repeat("evidence ", 200)
	var many []string
	for i := 0; i < 10; i++ {
		many = append(many, fmt.Sprintf("%d %s", i, huge))
	}
	inc := []IncidentState{{ID: "inc", Status: "analyzed", Triage: TriageState{LastExecution: ewCompleted("a", "success", now,
		&TriageCompletionEvidence{Hypothesis: huge, Observations: many})}}}
	got := BuildWorkProjection(inc, nil, nil)
	f := got.EndedWork[0].Finding
	if len(f.Hypothesis) > 500 || len(f.Observations) != 6 {
		t.Fatalf("record text not bounded: hypothesis=%d observations=%d", len(f.Hypothesis), len(f.Observations))
	}
	for _, o := range f.Observations {
		if len(o) > 400 {
			t.Fatalf("observation not bounded: %d", len(o))
		}
	}
}

// ----------------------------------------------------------------------
// Lead decision D: candidates from completion provenance.
// ----------------------------------------------------------------------

func ewSettledOutcome(incidentID, attemptID, hypothesis string, at time.Time) model.IncidentWorkOutcome {
	return model.IncidentWorkOutcome{
		IncidentID: incidentID, AttemptID: attemptID, Phase: model.WorkPhaseSettled, ResultCode: "success",
		CompletedAt: &at, EvidenceKnown: true,
		Finding: &model.FindingFacts{IncidentID: incidentID, Hypothesis: hypothesis, Observations: []string{"Pod events checked", "Application errors checked"}, Unknowns: []string{"metrics_source_unavailable"}, AnalyzedAt: &at},
	}
}

func ewBriefing(phase model.WorkPhase, ended ...model.IncidentWorkOutcome) *model.OperatorBriefing {
	checkpoint := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	return &model.OperatorBriefing{Firing: 3, Total: 3, Work: model.WorkProjection{
		Phase: phase, ExecutionStarted: true, EndedWork: ended, EndedWorkKnown: true, StatusCheckpointAt: &checkpoint,
	}}
}

// The canonical slide-4 "investigation-inconclusive" example, now with the
// provenance it needs: an ACCEPTED settled completion that recorded checks
// but no causal hypothesis.
func TestEndedWorkAcceptedCompletionWithoutHypothesisIsInconclusive(t *testing.T) {
	now := ewNow(t)
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-1", "a-1", "", now)))
	cands := MaterialCandidates(&prior, tr)
	c := hasCandidate(cands, model.CandidateInconclusiveCompletion)
	if c == nil || c.Finding == nil || c.Outcome == nil {
		t.Fatalf("settled accepted completion with no hypothesis must be an inconclusive completion: %v", candidateKinds(cands))
	}
	if c.Finding.IncidentID != "inc-1" || strings.Join(c.Finding.Observations, ";") != "Pod events checked;Application errors checked" || len(c.Finding.Unknowns) != 1 {
		t.Fatalf("the candidate must carry the attempt's own recorded checks and unknowns: %+v", c.Finding)
	}
	if c.Outcome.AttemptID != "a-1" || c.Outcome.ResultCode != "success" || !c.Outcome.EvidenceKnown || c.Outcome.Finding != nil {
		t.Fatalf("outcome provenance: %+v", c.Outcome)
	}
	if c.Next.Kind != model.NextStepStatusCheck {
		t.Fatalf("next step must be the recorded checkpoint, not a fabricated retry: %+v", c.Next)
	}
	if hasCandidate(cands, model.CandidateUsefulFinding) != nil {
		t.Fatalf("no hypothesis means no useful finding: %v", candidateKinds(cands))
	}
	// Repeated reconciliation / reload of the same ended work stays quiet.
	if quiet := MaterialCandidates(&tr, tr); hasCandidate(quiet, model.CandidateInconclusiveCompletion) != nil {
		t.Fatalf("a reload of the same completion must not repeat it: %v", candidateKinds(quiet))
	}
}

// The old aggregate-only shape is retained as the negative case: aggregate
// phase alone names no completion, so nothing may be attributed.
func TestEndedWorkAggregateOnlySettlementStaysSilent(t *testing.T) {
	p := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting}})
	c := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseSettled}})
	if got := hasCandidate(MaterialCandidates(&p, c), model.CandidateInconclusiveCompletion); got != nil {
		t.Fatalf("insufficient facts must not become an inconclusive finding: %+v", got)
	}
	// Even with the current side carrying provenance, an unknown prior means
	// no per-incident completion can be shown to be new.
	c2 := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-1", "a-1", "", ewNow(t))))
	if got := hasCandidate(MaterialCandidates(&p, c2), model.CandidateInconclusiveCompletion); got != nil {
		t.Fatalf("legacy prior provenance must not manufacture a retrospective completion: %+v", got)
	}
}

func TestEndedWorkUsefulResultAlreadyProjectedSuppressesFalseInconclusive(t *testing.T) {
	now := ewNow(t)
	// Cycle N: incident A completed with a useful hypothesis while B still
	// runs; the accepted result is already projected (and in the overview).
	analysis := model.IncidentAnalysis{IncidentID: "inc-a", Summary: "Deployment broke checkout", Findings: []string{"Crashes followed deployment"}}
	first := ewBriefing(model.WorkPhaseExecuting, ewSettledOutcome("inc-a", "a-a", "Deployment broke checkout", now))
	first.Analyses = []model.IncidentAnalysis{analysis}
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	tr := mcTransition(model.LifecycleActive, first)
	cands := MaterialCandidates(&prior, tr)
	if hasCandidate(cands, model.CandidateInconclusiveCompletion) != nil {
		t.Fatalf("a useful accepted result is never inconclusive: %v", candidateKinds(cands))
	}
	if n := len(candidateKinds(cands)); hasCandidate(cands, model.CandidateUsefulFinding) == nil || n != 1 {
		t.Fatalf("exactly one useful_finding from the overview, never a duplicate from ended work: %v", candidateKinds(cands))
	}
	// Cycle N+1: the aggregate settles because B settles usefully too —
	// A's completion must not resurface as inconclusive.
	second := ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-a", "a-a", "Deployment broke checkout", now), ewSettledOutcome("inc-b", "a-b", "Cache eviction storm", now.Add(time.Minute)))
	second.Analyses = []model.IncidentAnalysis{analysis, {IncidentID: "inc-b", Summary: "Cache eviction storm"}}
	later := MaterialCandidates(&tr, mcTransition(model.LifecycleActive, second))
	if hasCandidate(later, model.CandidateInconclusiveCompletion) != nil {
		t.Fatalf("aggregate settlement must not re-report an earlier useful completion: %v", candidateKinds(later))
	}
}

func TestEndedWorkUsefulEvidenceOutsideTopThreeIsReportedFromItsOwnAttempt(t *testing.T) {
	now := ewNow(t)
	var ended []model.IncidentWorkOutcome
	var overview []model.IncidentAnalysis
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("inc-%d", i)
		ended = append(ended, ewSettledOutcome(id, "a-"+id, "Hypothesis "+id, now))
		if i > 0 { // the overview is bounded to three; inc-0 fell out of it
			overview = append(overview, model.IncidentAnalysis{IncidentID: id, Summary: "Hypothesis " + id})
		}
	}
	cur := ewBriefing(model.WorkPhaseSettled, ended...)
	cur.Analyses = overview
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	cands := MaterialCandidates(&prior, mcTransition(model.LifecycleActive, cur))
	var useful []string
	for _, c := range cands {
		if c.Kind == model.CandidateUsefulFinding && c.Finding != nil {
			useful = append(useful, c.Finding.IncidentID)
		}
	}
	if strings.Join(useful, ",") != "inc-1,inc-2,inc-3,inc-0" {
		t.Fatalf("useful findings = %v, want the three overview findings plus inc-0 from its own matched attempt", useful)
	}
	if hasCandidate(cands, model.CandidateInconclusiveCompletion) != nil {
		t.Fatalf("useful completions are never inconclusive: %v", candidateKinds(cands))
	}
	for _, c := range cands {
		if c.Kind == model.CandidateUsefulFinding && c.Finding.IncidentID == "inc-0" && (c.Outcome == nil || c.Outcome.AttemptID != "a-inc-0") {
			t.Fatalf("the out-of-overview finding must carry its own attempt provenance: %+v", c.Outcome)
		}
	}
}

func TestEndedWorkCompletionWhileAnotherIncidentStillRuns(t *testing.T) {
	now := ewNow(t)
	// The aggregate stays executing (B runs), but A's accepted completion
	// without a hypothesis is its own event.
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting, ewSettledOutcome("inc-a", "a-a", "", now)))
	c := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateInconclusiveCompletion)
	if c == nil || c.Outcome == nil || c.Outcome.IncidentID != "inc-a" {
		t.Fatalf("a completion must not wait for the aggregate to settle: %+v", c)
	}
	// Another investigation's retry stays separately visible as the next step.
	retry := now.Add(10 * time.Minute)
	tr.Projection.Briefing.Work.RetryEligibleAt = &retry
	c = hasCandidate(MaterialCandidates(&prior, tr), model.CandidateInconclusiveCompletion)
	if c == nil || c.Next.Kind != model.NextStepRetryEligible {
		t.Fatalf("a recorded retry for other work must be stated, not denied: %+v", c)
	}
}

func TestEndedWorkSecondCompletionForTheSameIncidentIsANewEvent(t *testing.T) {
	now := ewNow(t)
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-a", "a-1", "", now)))
	tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-a", "a-2", "", now.Add(time.Hour))))
	c := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateInconclusiveCompletion)
	if c == nil || c.Outcome == nil || c.Outcome.AttemptID != "a-2" {
		t.Fatalf("a second attempt's completion is not the first one repeated: %+v", c)
	}
}

func TestEndedWorkCleanSkipsAndUnattributableEndsStayQuiet(t *testing.T) {
	now := ewNow(t)
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	postClaim := model.IncidentWorkOutcome{IncidentID: "inc-post", AttemptID: "a-post", Phase: model.WorkPhaseSettled, SkipReason: "eligibility_policy", ResultCode: "clean_skip", CompletedAt: &now}
	preClaim := model.IncidentWorkOutcome{IncidentID: "inc-pre", Phase: model.WorkPhaseSettled, SkipReason: "prior_coverage"}
	legacy := model.IncidentWorkOutcome{IncidentID: "inc-legacy", Phase: model.WorkPhaseSettled}
	unmatched := model.IncidentWorkOutcome{IncidentID: "inc-unmatched", AttemptID: "a-u", Phase: model.WorkPhaseSettled, ResultCode: "success", CompletedAt: &now}
	tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, postClaim, preClaim, legacy, unmatched))
	if cands := MaterialCandidates(&prior, tr); hasCandidate(cands, model.CandidateInconclusiveCompletion) != nil || hasCandidate(cands, model.CandidateUsefulFinding) != nil {
		t.Fatalf("clean skips, attempt-less ends and unmatched evidence must not masquerade as findings: %v", candidateKinds(cands))
	}
}

func TestEndedWorkStaleAndOwnerTerminalOutcomesAreNotPromoted(t *testing.T) {
	now := ewNow(t)
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExecuting))
	for _, code := range []string{"stale_membership", "stale_incident_input", "owner_terminal"} {
		o := model.IncidentWorkOutcome{IncidentID: "inc", AttemptID: "a-" + code, Phase: model.WorkPhaseExhausted, ResultCode: code, CompletedAt: &now}
		tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseExhausted, o))
		if got := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateInconclusiveCompletion); got != nil {
			t.Fatalf("%s must not become an accepted inconclusive finding: %+v", code, got)
		}
	}
}

func TestEndedWorkExhaustionStatesItsOwnAttemptAndRetainedLimit(t *testing.T) {
	now := ewNow(t)
	other := model.IncidentAnalysis{IncidentID: "other", Summary: "Deployment explains checkout errors", Findings: []string{"Crashes followed deployment"}}
	p := ewBriefing(model.WorkPhaseExecuting)
	p.Analyses = []model.IncidentAnalysis{other}
	c := ewBriefing(model.WorkPhaseExhausted, model.IncidentWorkOutcome{IncidentID: "inc-x", AttemptID: "a-5", Phase: model.WorkPhaseExhausted, ResultCode: "provider_error", CompletedAt: &now})
	c.Analyses = []model.IncidentAnalysis{other}
	priorTr := mcTransition(model.LifecycleActive, p)
	got := hasCandidate(MaterialCandidates(&priorTr, mcTransition(model.LifecycleActive, c)), model.CandidateInconclusiveCompletion)
	if got == nil || got.Outcome == nil || got.Finding == nil {
		t.Fatal("expected an inconclusive_completion for the exhausted schedule")
	}
	if got.Outcome.IncidentID != "inc-x" || got.Outcome.AttemptID != "a-5" || got.Outcome.ResultCode != "provider_error" || got.Outcome.EvidenceKnown {
		t.Fatalf("exhaustion must name its own attempt and recorded result: %+v", got.Outcome)
	}
	if len(got.Finding.Observations) != 0 || got.Finding.IncidentID != "inc-x" || got.Finding.Hypothesis != "" {
		t.Fatalf("checks were not retained, so none may be stated or borrowed: %+v", got.Finding)
	}
	if got.Next.Kind != model.NextStepStatusCheck {
		t.Fatalf("next step is the recorded checkpoint: %+v", got.Next)
	}
}

func TestFindingCandidatesRequireARecordedHypothesis(t *testing.T) {
	prior := mcTransition(model.LifecycleActive, &model.OperatorBriefing{})
	tr := mcTransition(model.LifecycleActive, &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{
		{IncidentID: "titled", Title: "Checkout analysis"},
		{IncidentID: "caused", Title: "Checkout analysis", Summary: "Deployment broke checkout"},
	}})
	var useful []string
	for _, c := range MaterialCandidates(&prior, tr) {
		if c.Kind == model.CandidateUsefulFinding {
			useful = append(useful, c.Finding.IncidentID)
		}
	}
	if strings.Join(useful, ",") != "caused" {
		t.Fatalf("an analysis title is not a causal hypothesis: useful=%v", useful)
	}
}

// ----------------------------------------------------------------------
// Lead round-3 review (2026-09-09).
//
// R1: decision B's complete-union rule is per EXECUTION, not per resolved
// identity — one execution that recorded no frozen inputs makes the count
// unknown even while another execution resolves completely.
// R2: an accepted result outside the top-three overview must clear the same
// structural materiality bar the overview applies (canonical slide 3 revised
// node, slide 4 row 577: "Neither paraphrasing nor an evidence enum change
// earns a reply"), independently of which path reports it.
// ----------------------------------------------------------------------

func TestInvestigatedAlertInputsMixedIncompleteExecutionIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		legacy IncidentState
	}{
		// A recorded attempt row whose frozen member list is empty: the
		// pre-ledger fallback claim, which analyzed inputs this projection
		// cannot name.
		{"empty_ledger_inputs", IncidentState{ID: "legacy", Triage: TriageState{Attempts: 1, LastExecution: &TriageExecution{AttemptID: "legacy-attempt"}}}},
		// A counted attempt with no ledger row at all.
		{"counter_without_ledger", IncidentState{ID: "legacy", Triage: TriageState{Attempts: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds, frozen := ewDeliveries(9)
			incidents := append(ewExecutedIncident(frozen), tc.legacy)
			ids, _, count, known := investigatedAlertInputs(incidents, ds)
			if known {
				t.Fatalf("an execution with no frozen input provenance still claimed an exact count=%d", count)
			}
			// The identities the complete execution did resolve stay
			// provenance a later reader can check: only the numeric claim goes.
			if len(ids) != 9 {
				t.Fatalf("resolved identities must survive as partial facts: %d", len(ids))
			}
			if got := investigatedInputCount(model.WorkProjection{InvestigatedCount: count, InvestigatedCountKnown: known}); got != 0 {
				t.Fatalf("an incomplete union reported as exact %d", got)
			}
		})
	}
}

func TestInvestigatedAlertInputsTwoCompleteExecutionsStayKnown(t *testing.T) {
	ds, frozen := ewDeliveries(4)
	incidents := make([]IncidentState, 0, 3)
	incidents = append(incidents,
		IncidentState{ID: "inc-a", Triage: TriageState{Attempts: 1, LastExecution: &TriageExecution{AttemptID: "a1", MemberDeliveryIDs: frozen[:2]}}},
		IncidentState{ID: "inc-b", Triage: TriageState{Attempts: 2, LastExecution: &TriageExecution{AttemptID: "b1", MemberDeliveryIDs: frozen[2:]}}},
	)
	_, _, count, known := investigatedAlertInputs(incidents, ds)
	if count != 4 || !known {
		t.Fatalf("count=%d known=%v, want the complete four-input union", count, known)
	}
	// A member that never ran is not missing provenance: it contributes no
	// inputs and leaves the union complete.
	incidents = append(incidents, IncidentState{ID: "inc-c", Triage: TriageState{Phase: "ready"}})
	if _, _, count, known = investigatedAlertInputs(incidents, ds); count != 4 || !known {
		t.Fatalf("an unexecuted member made the union unknown: count=%d known=%v", count, known)
	}
}

// ewOverview is a stable three-item analysis overview naming other
// incidents, so the incident under test is outside the bound in both
// transitions and nothing else in the projection changes.
func ewOverview() []model.IncidentAnalysis {
	return []model.IncidentAnalysis{
		{IncidentID: "other1", Summary: "Other hypothesis 1"},
		{IncidentID: "other2", Summary: "Other hypothesis 2"},
		{IncidentID: "other3", Summary: "Other hypothesis 3"},
	}
}

func TestEndedWorkOutsideOverviewWordingOnlyRepeatStaysQuiet(t *testing.T) {
	now := ewNow(t)
	a := ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("outside", "attempt-1", "Deployment broke checkout", now))
	b := ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("outside", "attempt-2", "Checkout affected by the deployment", now.Add(time.Minute)))
	a.Analyses, b.Analyses = ewOverview(), ewOverview()
	prior := mcTransition(model.LifecycleActive, a)
	cands := MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b))
	if c := hasCandidate(cands, model.CandidateUsefulFinding); c != nil {
		t.Fatalf("a re-run that only rephrased the same retained checks is not a new finding: %+v", c.Finding)
	}
	if c := hasCandidate(cands, model.CandidateInconclusiveCompletion); c != nil {
		t.Fatalf("an accepted result that recorded a cause is never inconclusive: %+v", c.Finding)
	}
}

func TestEndedWorkOutsideOverviewChangedEvidenceIsStillReported(t *testing.T) {
	now := ewNow(t)
	for _, tc := range []struct {
		name   string
		mutate func(*model.IncidentWorkOutcome)
	}{
		{"new_observation", func(o *model.IncidentWorkOutcome) {
			o.Finding.Observations = append(o.Finding.Observations, "Database saturation checked")
		}},
		{"unknown_resolved", func(o *model.IncidentWorkOutcome) { o.Finding.Unknowns = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("outside", "attempt-1", "Deployment broke checkout", now))
			current := ewSettledOutcome("outside", "attempt-2", "Deployment broke checkout", now.Add(time.Minute))
			tc.mutate(&current)
			b := ewBriefing(model.WorkPhaseSettled, current)
			a.Analyses, b.Analyses = ewOverview(), ewOverview()
			prior := mcTransition(model.LifecycleActive, a)
			c := hasCandidate(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b)), model.CandidateUsefulFinding)
			if c == nil || c.Outcome == nil || c.Outcome.AttemptID != "attempt-2" {
				t.Fatalf("changed retained evidence outside the overview is a real finding: %+v", c)
			}
		})
	}
}

func TestEndedWorkOutsideOverviewComparesAgainstThePriorOverview(t *testing.T) {
	// The incident WAS in the prior overview with exactly these structured
	// facts and has now fallen out of it. The result is not new merely
	// because the comparison moved to the completion path.
	now := ewNow(t)
	outcome := ewSettledOutcome("outside", "attempt-1", "Deployment broke checkout", now)
	a := ewBriefing(model.WorkPhaseExecuting)
	a.Analyses = []model.IncidentAnalysis{{
		IncidentID: "outside", Summary: "Deployment broke checkout",
		Findings: append([]string(nil), outcome.Finding.Observations...), VerificationLimit: "metrics_source_unavailable",
	}}
	b := ewBriefing(model.WorkPhaseSettled, outcome)
	b.Analyses = ewOverview()
	prior := mcTransition(model.LifecycleActive, a)
	cands := MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b))
	if c := ewUsefulFor(cands, "outside"); c != nil {
		t.Fatalf("the same known result leaving the overview is not a new finding: %+v", c.Finding)
	}
	// The three analyses that newly entered the overview are still reported:
	// this gate is per incident, not a blanket silence.
	if ewUsefulFor(cands, "other1") == nil {
		t.Fatalf("a genuinely new overview finding was suppressed: %v", candidateKinds(cands))
	}
}

// ewUsefulFor returns the useful_finding candidate for one incident, or nil
// when this cycle emitted none for it.
func ewUsefulFor(cands []model.MaterialCandidate, incidentID string) *model.MaterialCandidate {
	for i := range cands {
		if cands[i].Kind == model.CandidateUsefulFinding && cands[i].Finding != nil && cands[i].Finding.IncidentID == incidentID {
			return &cands[i]
		}
	}
	return nil
}

func TestEndedWorkRepeatedWordingDoesNotSuppressADistinctInconclusiveCompletion(t *testing.T) {
	// Materiality gates the useful-finding path only: a second accepted
	// completion that recorded NO cause is its own event even when the
	// retained checks are identical, because the operator was never told
	// this attempt ended.
	now := ewNow(t)
	prior := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-a", "a-1", "", now)))
	tr := mcTransition(model.LifecycleActive, ewBriefing(model.WorkPhaseSettled, ewSettledOutcome("inc-a", "a-2", "", now.Add(time.Hour))))
	c := hasCandidate(MaterialCandidates(&prior, tr), model.CandidateInconclusiveCompletion)
	if c == nil || c.Outcome == nil || c.Outcome.AttemptID != "a-2" {
		t.Fatalf("a distinct inconclusive completion identity must survive the materiality gate: %+v", c)
	}
}

// ----------------------------------------------------------------------
// R2 continued (lead review round 4, 2026-09-09): materiality must not
// depend on WHICH path displays a result, and a display bound must never
// read as an evidence change. The overview keeps three observations and
// bounds a limitation to a hundred bytes; a completion keeps six and carries
// the limitation whole. Comparison provenance is the pre-truncation
// EvidenceFingerprint the loader and the matched completion both record;
// where it is missing the comparison falls back to what the two displays can
// prove, and a list shorter than any bound proves itself complete.
// ----------------------------------------------------------------------

// The lead's probe in repo form: an unchanged accepted result whose incident
// re-enters the three-item overview. The prior overview lookup is nil, but
// the prior EndedWork already reported exactly this evidence.
func TestMaterialityUnchangedResultReturningToOverviewStaysQuiet(t *testing.T) {
	now := ewNow(t)
	o := ewSettledOutcome("target", "attempt-1", "Deployment broke checkout", now)
	a, b := ewBriefing(model.WorkPhaseSettled, o), ewBriefing(model.WorkPhaseSettled, o)
	a.Analyses = ewOverview()
	// A legitimate member delta reorders the overview: "target" takes the
	// third slot from "other3" with the same evidence it already reported.
	b.Analyses = []model.IncidentAnalysis{a.Analyses[0], a.Analyses[1], {
		IncidentID: "target", Summary: o.Finding.Hypothesis,
		Findings: append([]string(nil), o.Finding.Observations...), VerificationLimit: "metrics_source_unavailable",
	}}
	prior := mcTransition(model.LifecycleActive, a)
	cands := MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b))
	if c := ewUsefulFor(cands, "target"); c != nil {
		t.Fatalf("the same reported result re-entering the overview became a new finding: %+v", c.Finding)
	}
	// Per incident, not a blanket silence: the same movement with actually
	// changed observations is still a finding.
	b.Analyses[2].Findings = []string{"Pod events checked", "Config rollout compared"}
	cands = MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b))
	if c := ewUsefulFor(cands, "target"); c == nil {
		t.Fatalf("changed observations on the returning incident were suppressed: %v", candidateKinds(cands))
	}
}

// The lead's second probe in repo form: the prior overview retained three of
// the four observations the completion carries. Its omission of the fourth is
// display, not proof the fourth was absent.
func TestMaterialityDisplayBoundsAreNotEvidenceChanges(t *testing.T) {
	now := ewNow(t)
	observations := []string{"check one", "check two", "check three", "check four"}
	a := ewBriefing(model.WorkPhaseExecuting)
	a.Analyses = []model.IncidentAnalysis{{IncidentID: "target", Summary: "Known hypothesis", Findings: observations[:model.AnalysisFindingsBound]}}
	o := ewSettledOutcome("target", "attempt-2", "Known hypothesis", now)
	o.Finding.Observations, o.Finding.Unknowns = observations, nil
	b := ewBriefing(model.WorkPhaseSettled, o)
	b.Analyses = ewOverview()
	prior := mcTransition(model.LifecycleActive, a)
	if c := ewUsefulFor(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b)), "target"); c != nil {
		t.Fatalf("a three-item display against a four-item completion fabricated a change: %+v", c.Finding)
	}
	// A list shorter than every display bound was never cut, so a new
	// observation added to it is a real change and must still be reported.
	a.Analyses[0].Findings = observations[:2]
	o.Finding.Observations = observations[:3]
	b = ewBriefing(model.WorkPhaseSettled, o)
	b.Analyses = ewOverview()
	prior = mcTransition(model.LifecycleActive, a)
	if c := ewUsefulFor(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b)), "target"); c == nil {
		t.Fatalf("an observation added to a complete two-item list is a real change and was suppressed")
	}
}

// The differing text bounds: the overview marks its hundred-byte cut with an
// ellipsis, the completion carries the same limitation whole.
func TestMaterialityLimitationTextBoundIsNotAnEvidenceChange(t *testing.T) {
	now := ewNow(t)
	limit := "metrics_source_unavailable: " + strings.Repeat("the recorded degradation reason keeps going ", 4)
	o := ewSettledOutcome("outside", "attempt-1", "Deployment broke checkout", now)
	o.Finding.Unknowns = verificationUnknowns(limit, 0)
	a := ewBriefing(model.WorkPhaseExecuting)
	a.Analyses = []model.IncidentAnalysis{model.BoundIncidentAnalysis(model.IncidentAnalysis{
		IncidentID: "outside", Summary: "Deployment broke checkout",
		Findings: append([]string(nil), o.Finding.Observations...), VerificationLimit: limit,
	})}
	if got := a.Analyses[0].VerificationLimit; !strings.HasSuffix(got, "…") || len(got) > 100 {
		t.Fatalf("fixture must exercise the real hundred-byte overview bound: %q", got)
	}
	b := ewBriefing(model.WorkPhaseSettled, o)
	b.Analyses = ewOverview()
	prior := mcTransition(model.LifecycleActive, a)
	if c := ewUsefulFor(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b)), "outside"); c != nil {
		t.Fatalf("a bounded limitation against the whole one fabricated a change: %+v", c.Finding)
	}
	// A genuinely different limitation is still a change.
	o.Finding.Unknowns = verificationUnknowns("logs_source_unavailable", 0)
	b = ewBriefing(model.WorkPhaseSettled, o)
	b.Analyses = ewOverview()
	if c := ewUsefulFor(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, b)), "outside"); c == nil {
		t.Fatalf("a different recorded limitation is a real change and was suppressed")
	}
}

// Comparison provenance is what preserves a change the overview cannot show:
// the same three displayed observations, a different fourth one.
func TestMaterialityFingerprintPreservesChangesBeyondTheOverviewBound(t *testing.T) {
	now := ewNow(t)
	shown := []string{"check one", "check two", "check three"}
	recorded := append(append([]string(nil), shown...), "check four")
	changed := append(append([]string(nil), shown...), "check four, rerun")

	// The prior transition reported the completion; the incident then enters
	// the overview, where only the first three observations are displayed.
	priorFor := func(observations []string) *model.OperatorBriefing {
		o := ewSettledOutcome("target", "attempt-1", "Known hypothesis", now)
		o.Finding.Observations, o.Finding.Unknowns = observations, nil
		o.Finding.EvidenceFingerprint = model.EvidenceFingerprint(observations, "", 0)
		p := ewBriefing(model.WorkPhaseSettled, o)
		p.Analyses = ewOverview()
		return p
	}
	current := func(observations []string) *model.OperatorBriefing {
		b := ewBriefing(model.WorkPhaseSettled)
		b.Analyses = []model.IncidentAnalysis{{
			IncidentID: "target", Summary: "Known hypothesis", Findings: shown,
			EvidenceFingerprint: model.EvidenceFingerprint(observations, "", 0),
		}}
		return b
	}

	prior := mcTransition(model.LifecycleActive, priorFor(recorded))
	if c := ewUsefulFor(MaterialCandidates(&prior, mcTransition(model.LifecycleActive, current(recorded))), "target"); c != nil {
		t.Fatalf("unchanged evidence displayed through a different bound became a finding: %+v", c.Finding)
	}
	cands := MaterialCandidates(&prior, mcTransition(model.LifecycleActive, current(changed)))
	c := ewUsefulFor(cands, "target")
	if c == nil {
		t.Fatalf("a changed fourth observation the overview cannot display was suppressed: %v", candidateKinds(cands))
	}
	// Comparison provenance stays in B3: the candidate handed downstream
	// carries the operator-visible facts only.
	if c.Finding.EvidenceFingerprint != "" {
		t.Fatalf("a material candidate must not carry comparison provenance: %+v", c.Finding)
	}
}
