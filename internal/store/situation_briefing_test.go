// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReconciliationCarriesStoredAnalysisWithoutExposingRawOutput(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "briefing", now)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='analyzed', summary=?, root_cause=?, output_json=?, enrichment_json=?, last_judged_at=? WHERE id=?`,
		"Checkout errors after deployment", "A deployment may have broken checkout.",
		`{"correlation_findings":["Errors and restarts began together"],"private_extra":"RAW_OUTPUT_MUST_NOT_LEAK"}`,
		`{"verification":{"outcome":"degraded","degradation_reason":"verification_source_unavailable"}}`, now.Format(time.RFC3339Nano), "inc-briefing")
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "briefing-test", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in.Analyses)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Checkout errors after deployment", "A deployment may have broken checkout.", "Errors and restarts began together", "degraded"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("reconciliation discarded operator analysis %q", want)
		}
	}
	if strings.Contains(string(raw), "RAW_OUTPUT_MUST_NOT_LEAK") {
		t.Fatal("raw output escaped the bounded analysis projection")
	}
}

// Resolved is the normal persisted state after recovery. An overall supported
// verification result must not hide invalid or unavailable constituent checks.
func TestBriefingResolvedAnalysisRetainsVerificationGaps(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "resolved-briefing", now)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='resolved',summary='Checkout deployment errors',root_cause='Deployment may explain errors',output_json=?,enrichment_json=?,last_judged_at=? WHERE id=?`,
		`{"analysis_name":"Checkout deployment errors","overall_issue":"Deployment may explain errors","correlation_findings":["Restarts began together"],"severity":"critical","confidence":0.8}`,
		`{"verification":{"outcome":"supported","rounds":[{"queries":[{"outcome":"fetched"},{"outcome":"invalid","params":{"secret":"DO_NOT_PERSIST"}},{"outcome":"failed"}]}]}}`, now.Format(time.RFC3339Nano), "inc-resolved-briefing")
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "briefing", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	b := situation.BuildOperatorBriefing(in, model.LifecycleRecovered)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"historical":true`, `"verification":"supported"`, `"verification_gaps":2`, "Deployment may explain errors"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s in %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "DO_NOT_PERSIST") {
		t.Fatal("query parameters leaked")
	}
}

func TestBriefingSnapshotBoundsAndMissingProvenance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "bounds", now)
	huge := strings.Repeat("evidence ", 10000)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='analyzed',summary=?,root_cause=?,output_json=?,enrichment_json='malformed',last_judged_at=NULL WHERE id='inc-bounds'`, huge, huge, `{"correlation_findings":["`+huge+`","second","third","fourth"],"secret":"PRIVATE_OUTPUT"}`)
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "bounds", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in.Analyses)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 2500 || strings.Contains(string(raw), "PRIVATE_OUTPUT") || strings.Contains(string(raw), "fourth") {
		t.Fatalf("snapshot analysis not bounded: %d bytes", len(raw))
	}
	if !strings.Contains(string(raw), "…") {
		t.Fatalf("truncation is silent: %s", raw)
	}
	if len(in.Analyses) != 1 || !in.Analyses[0].Stale || in.Analyses[0].AnalyzedAt != nil || in.Analyses[0].Verification != "" {
		t.Fatalf("invented missing provenance: %s", raw)
	}
}

func TestBriefingSelectionReportsTotalCompletedAnalyses(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "selection", now)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("selected-%d", i)
		if err := st.InsertIncident(context.Background(), Incident{ID: id, GroupKey: id, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='resolved',summary='Completed analysis',root_cause='Possible deployment failure',last_judged_at=? WHERE id=?`, now.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano), id); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(context.Background(), `INSERT INTO situation_incidents (situation_id,incident_id,attached_at) VALUES (?,?,?)`, sid, id, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	claim := claimSituation(t, st, sid, "selection", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	b := situation.BuildOperatorBriefing(in, model.LifecycleRecovered)
	if len(in.Analyses) != 3 || b.AnalysisCount != 4 || in.Analyses[0].IncidentID != "selected-3" {
		t.Fatalf("selection must be newest 3 with honest total: %+v", b)
	}
}

// B0 compatibility port: the coherent load carries each immutable delivery's
// already-decoded labels into situation.Delivery.Labels (the same row
// Severity/Drill are read from), so the briefing can name scope and alerts
// without the pure package ever parsing labels_json.
func TestLoadReconciliationInputCarriesDeliveryLabels(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := seedReconcileSituation(t, st, "labels", now)
	claim := claimSituation(t, st, sid, "labels-test", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Deliveries) == 0 {
		t.Fatal("seeded situation has no deliveries")
	}
	for _, d := range in.Deliveries {
		if d.Labels == nil || d.Labels["severity"] != d.Severity {
			t.Fatalf("delivery %s labels not loaded coherently with severity: %+v", d.ID, d.Labels)
		}
	}
}

// shParkedTriageContract is a valid nonterminal contract in which AlertINT's
// own work is blocked under a recorded, operator-visible reason.
func shParkedTriageContract(next time.Time) model.ActionContract {
	c := shRunningTriageContract(next)
	blocked, parked := model.AlertINTStatusBlocked, model.WaitReasonAssessmentParked
	c.AlertINTStatus, c.WaitReason = &blocked, &parked
	return c
}

// A reply composed hours later reads these facts back from the row, not from
// mutable current state, so the repaired candidate provenance has to survive
// real derivation against the STORED prior transition, the fenced commit and
// reload: the cleared limitation's own code (R4), the scope/urgency change
// that moved no member (R2), and the exact investigation input count kept
// apart from the bounded display list (R3).
func TestCommittedTransitionPersistsMaterialCandidateProvenance(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-candidate-provenance", now)
	claim := claimSituation(t, st, sitID, "controller-candidates", now)

	// Cycle 1: parked under a recorded reason, narrow scope, nothing running.
	first := shPrepare(t, claim, shParkedTriageContract(now.Add(time.Minute)),
		model.LifecycleActive, model.AttentionObserve, now)
	first.Change.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 9, Total: 12}
	if err := st.CommitController(ctx, claim, shDerive(t, first)); err != nil {
		t.Fatalf("first CommitController: %v", err)
	}

	// Cycle 2: the block cleared, the scope widened, urgency rose, and the
	// investigation actually started against nine frozen inputs.
	later := now.Add(time.Minute)
	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim2 := claimSituation(t, st, sitID, "controller-candidates", later)
	in, err := st.LoadReconciliationInput(ctx, claim2, later)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if in.PriorTransition == nil {
		t.Fatal("second cycle must read the committed prior transition")
	}

	var ids, names []string
	for i := 0; i < 9; i++ {
		ids = append(ids, fmt.Sprintf("alert-%02d", i))
		if i < 8 {
			names = append(names, fmt.Sprintf("Alert %02d", i))
		}
	}
	second := shPrepare(t, claim2, shRunningTriageContract(later.Add(time.Minute)),
		model.LifecycleActive, model.AttentionUrgent, later)
	second.Change.PriorTransition = in.PriorTransition
	second.Change.PriorSummary = in.CurrentSummary
	second.Change.Projection.Briefing = &model.OperatorBriefing{
		Scope: "checkout and payments", Firing: 9, Total: 12,
		Work: model.WorkProjection{
			ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
			InvestigatedAlertIDs: ids, InvestigatedNames: names, InvestigatedCount: 9, InvestigatedCountKnown: true,
		},
	}
	commit := shDerive(t, second)
	if err := st.CommitController(ctx, claim2, commit); err != nil {
		t.Fatalf("second CommitController: %v", err)
	}

	stored, err := st.GetSituationTransition(ctx, commit.History.Transitions[0].ID)
	if err != nil {
		t.Fatalf("GetSituationTransition: %v", err)
	}
	if stored.Projection.Briefing == nil || stored.Projection.Briefing.Work.InvestigatedCount != 9 {
		t.Fatalf("exact investigation input count lost in persistence: %+v", stored.Projection.Briefing)
	}
	if got := len(stored.Projection.Briefing.Work.InvestigatedNames); got != 8 {
		t.Fatalf("bounded display names = %d, want 8 alongside the exact count", got)
	}
	if stored.Projection.OperatorDelta == nil {
		t.Fatal("operator delta lost in persistence")
	}
	byKind := map[model.CandidateKind]model.MaterialCandidate{}
	for _, c := range stored.Projection.OperatorDelta.Candidates {
		byKind[c.Kind] = c
	}
	assurance, ok := byKind[model.CandidateFirstExecutionAssurance]
	if !ok || assurance.Members == nil || assurance.Members.FiringCount != 9 || !assurance.Members.CountKnown {
		t.Fatalf("assurance count must reload as the actual nine inputs: %+v", assurance.Members)
	}
	ability, ok := byKind[model.CandidateAbilityChanged]
	if !ok || ability.Limitation == nil || !ability.Limitation.Cleared ||
		ability.Limitation.Code != string(model.WaitReasonAssessmentParked) {
		t.Fatalf("cleared limitation identity must reload for B5 to match it: %+v", ability.Limitation)
	}
	members, ok := byKind[model.CandidateMembersChanged]
	if !ok || members.Members == nil || members.Members.PreviousScope != "checkout" ||
		members.Members.Scope != "checkout and payments" {
		t.Fatalf("scope change must reload: %+v", members.Members)
	}
	if members.Members.PreviousUrgency != string(model.AttentionObserve) ||
		members.Members.Urgency != string(model.AttentionUrgent) {
		t.Fatalf("urgency change must reload: %+v", members.Members)
	}
}

// ----------------------------------------------------------------------
// Lead decisions B/D (round 2, 2026-09-09): provenance through the REAL
// frozen-claim load → projection → commit → reload path. Nothing below
// hand-builds a WorkProjection; every fact comes from the store's own
// claim/completion writers and LoadReconciliationInput.
// ----------------------------------------------------------------------

// ewpFixture is newTriageFixture with n immutable deliveries linked to one
// ready Incident attached to the group's Situation, so a claim freezes n
// member delivery ids.
func ewpFixture(t *testing.T, st *Store, groupKey, incidentSuffix string, n int, now time.Time) triageFixture {
	t.Helper()
	ctx := context.Background()
	var inputs []DeliveryInput
	for i := 0; i < n; i++ {
		fp := fmt.Sprintf("fp-%s-%s-%02d", groupKey, incidentSuffix, i)
		inputs = append(inputs, deliveryFixture("delivery-"+fp, fp, now.Add(time.Duration(i)*time.Second)))
	}
	dels, err := st.AcceptDeliveries(ctx, inputs)
	if err != nil || len(dels) != n {
		t.Fatalf("accept deliveries: %v (%d)", err, len(dels))
	}
	incidentID := "inc-" + groupKey + "-" + incidentSuffix
	if err := st.InsertIncident(ctx, Incident{ID: incidentID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	for _, d := range dels {
		if _, err := st.db.ExecContext(ctx, `INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`, incidentID, d.ID, canonicalTime(now)); err != nil {
			t.Fatalf("link delivery: %v", err)
		}
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	inputID := "input-" + incidentID
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'membership_changed', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, dels[0].ID, groupKey, canonicalTime(now)); err != nil {
		t.Fatalf("insert situation input: %v", err)
	}
	claim := claimOneInput(t, st, "seed:"+incidentID, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	var situationID string
	var count int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situations WHERE group_key = ?`, groupKey).Scan(&count); err != nil || count != 1 {
		t.Fatalf("situations for group %s = %d (%v), want exactly one shared Situation", groupKey, count, err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&situationID); err != nil {
		t.Fatalf("find situation: %v", err)
	}
	membership, incidentInput := digestsForTest(t, st, incidentID)
	return triageFixture{IncidentID: incidentID, SituationID: situationID, GroupKey: groupKey, DeliveryID: dels[0].ID,
		MembershipDigest: membership, IncidentInputDigest: incidentInput}
}

// ewpCycle runs one real controller cycle for sitID: claim, coherent load,
// the exported committed projection, fenced commit, and a reload of the
// committed Transition — returning both the Transition as persisted and the
// loaded input it was derived from. A cycle whose committed projection is
// materially unchanged records NO Transition at all (history.go's
// selectControllerReason); ewpCycle then returns the zero Transition, which
// ewpCandidates reads as carrying no candidates.
func ewpCycle(t *testing.T, st *Store, sitID, owner string, now time.Time, contract model.ActionContract) (model.Transition, situation.SnapshotInput) {
	t.Helper()
	ctx := context.Background()
	shMakeDue(t, st, sitID, now.Add(-time.Second))
	claim := claimSituation(t, st, sitID, owner, now)
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	cycle := shPrepare(t, claim, contract, model.LifecycleActive, model.AttentionObserve, now)
	cycle.Change.PriorTransition = in.PriorTransition
	cycle.Change.PriorSummary = in.CurrentSummary
	cycle.Change.Projection.Briefing = situation.CommittedOperatorBriefing(in, cycle.Commit)
	commit := shDerive(t, cycle)
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	if commit.History == nil || len(commit.History.Transitions) > 1 {
		t.Fatalf("expected at most one committed transition, got %+v", commit.History)
	}
	if len(commit.History.Transitions) == 0 {
		return model.Transition{}, in
	}
	stored, err := st.GetSituationTransition(ctx, commit.History.Transitions[0].ID)
	if err != nil {
		t.Fatalf("GetSituationTransition: %v", err)
	}
	return stored, in
}

func ewpCandidates(tr model.Transition, kind model.CandidateKind) []model.MaterialCandidate {
	var out []model.MaterialCandidate
	if tr.Projection.OperatorDelta == nil {
		return nil
	}
	for _, c := range tr.Projection.OperatorDelta.Candidates {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

func ewpEndedWork(tr model.Transition, incidentID string) (model.IncidentWorkOutcome, bool) {
	if tr.Projection.Briefing == nil {
		return model.IncidentWorkOutcome{}, false
	}
	for _, o := range tr.Projection.Briefing.Work.EndedWork {
		if o.IncidentID == incidentID {
			return o, true
		}
	}
	return model.IncidentWorkOutcome{}, false
}

// Nine frozen claim-time inputs, counted from the REAL attempt row's member
// delivery ids resolved through the coherent load — never the eight-name
// display list — survive projection, commit and reload with completeness.
func TestFrozenClaimCountProvenanceSurvivesLoadProjectionCommitReload(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	f := ewpFixture(t, st, "ewp-count", "a", 9, now)

	// Cycle 1: nothing has executed yet.
	first, _ := ewpCycle(t, st, f.SituationID, "controller-count", now, shRunningTriageContract(now.Add(time.Minute)))
	if first.Projection.Briefing == nil || first.Projection.Briefing.Work.ExecutionStarted {
		t.Fatalf("cycle 1 must precede any execution: %+v", first.Projection.Briefing)
	}

	// The worker claims the decided schedule: the attempt row freezes the
	// nine member delivery ids.
	claimed := mustClaim(t, st, f, now.Add(time.Minute))
	if len(claimed.MemberDeliveryIDs) != 9 {
		t.Fatalf("frozen member deliveries = %d, want 9", len(claimed.MemberDeliveryIDs))
	}

	// Cycle 2: the coherent load resolves the frozen union through the
	// Situation's own deliveries and the projection records the exact count.
	later := now.Add(2 * time.Minute)
	second, in := ewpCycle(t, st, f.SituationID, "controller-count", later, shRunningTriageContract(later.Add(time.Minute)))
	if len(in.Incidents) != 1 || in.Incidents[0].Triage.ActiveAttempt == nil || in.Incidents[0].Triage.ActiveAttempt.AttemptID != claimed.AttemptID {
		t.Fatalf("load must carry the in-flight attempt: %+v", in.Incidents)
	}
	w := second.Projection.Briefing.Work
	if !w.ExecutionStarted || w.InvestigatedCount != 9 || !w.InvestigatedCountKnown {
		t.Fatalf("reloaded projection count provenance: %+v", w)
	}
	if len(w.InvestigatedAlertIDs) != 9 || len(w.InvestigatedNames) != 8 {
		t.Fatalf("identities=%d names=%d, want 9 identities and the bounded eight names", len(w.InvestigatedAlertIDs), len(w.InvestigatedNames))
	}
	assurance := ewpCandidates(second, model.CandidateFirstExecutionAssurance)
	if len(assurance) != 1 || assurance[0].Members == nil || assurance[0].Members.FiringCount != 9 || !assurance[0].Members.CountKnown {
		t.Fatalf("assurance must reload as the known nine inputs: %+v", assurance)
	}
}

// An accepted completion that recorded checks but no root cause: the load
// matches the incident output to the attempt's own digest, the projection
// records a known empty hypothesis, and the committed Transition carries
// exactly one inconclusive completion keyed on that attempt. A reload of the
// same state stays quiet.
func TestAcceptedCompletionWithoutHypothesisBecomesInconclusiveCandidate(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	f := ewpFixture(t, st, "ewp-inconclusive", "a", 3, now)
	claimed := mustClaim(t, st, f, now)

	// Cycle 1: the attempt is running.
	first, _ := ewpCycle(t, st, f.SituationID, "controller-inc", now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)))
	if !first.Projection.Briefing.Work.EndedWorkKnown || len(first.Projection.Briefing.Work.EndedWork) != 0 {
		t.Fatalf("cycle 1 ended work: %+v", first.Projection.Briefing.Work)
	}

	finding := TriageFinding{
		OutputJSON:         `{"analysis_name":"Checkout analysis","correlation_findings":["Pod events checked","Application errors checked"]}`,
		Summary:            "Checkout analysis",
		RootCause:          "",
		Confidence:         0.35,
		EnrichmentJSON:     `{"verification":{"outcome":"degraded","degradation_reason":"logs_source_unavailable","rounds":[{"queries":[{"outcome":"fetched"},{"outcome":"failed"}]}]}}`,
		EvidencePackDigest: "sha256:evidence-inconclusive",
	}
	completedAt := now.Add(90 * time.Second)
	result, err := st.CompleteIncidentTriageAttempt(ctx, claimed.AttemptID, f.IncidentID, finding, completedAt)
	if err != nil || result.Outcome != TriageCompletionSuccess {
		t.Fatalf("complete: %+v %v", result, err)
	}

	// Cycle 2: the completion is loaded with matched evidence.
	later := now.Add(3 * time.Minute)
	second, in := ewpCycle(t, st, f.SituationID, "controller-inc", later, shRunningTriageContract(later.Add(time.Minute)))
	ewpAssertMatchedLoad(t, in, claimed.AttemptID, result.OutputDigest, completedAt)
	ewpAssertInconclusiveCommit(t, second, f.IncidentID, claimed.AttemptID)

	// Cycle 3: nothing changed — a reload of the same completion is quiet
	// (materially unchanged, so no Transition is recorded at all).
	third, _ := ewpCycle(t, st, f.SituationID, "controller-inc", later.Add(time.Minute), shRunningTriageContract(later.Add(2*time.Minute)))
	if third.ID != "" {
		t.Fatalf("a reload of unchanged ended work recorded a new transition: %+v", third.Projection.OperatorDelta)
	}
	if got := ewpCandidates(third, model.CandidateInconclusiveCompletion); len(got) != 0 {
		t.Fatalf("a repeated reconciliation must not repeat the completion: %+v", got)
	}
	if got := ewpCandidates(third, model.CandidateUsefulFinding); len(got) != 0 {
		t.Fatalf("reload produced a phantom finding: %+v", got)
	}
}

func ewpAssertMatchedLoad(t *testing.T, in situation.SnapshotInput, attemptID, outputDigest string, completedAt time.Time) {
	t.Helper()
	exec := in.Incidents[0].Triage.LastExecution
	if exec == nil || exec.AttemptID != attemptID || exec.ResultCode != "success" || exec.OutputDigest != outputDigest || exec.CompletedAt == nil || !exec.CompletedAt.Equal(completedAt) {
		t.Fatalf("last execution completion metadata: %+v", exec)
	}
	if exec.Evidence == nil {
		t.Fatal("accepted output must be matched to its own attempt through the recorded digest")
	}
	if exec.Evidence.Hypothesis != "" || strings.Join(exec.Evidence.Observations, ";") != "Pod events checked;Application errors checked" ||
		exec.Evidence.VerificationLimit != "logs_source_unavailable" || exec.Evidence.VerificationGaps != 1 || exec.Evidence.JudgedAt == nil {
		t.Fatalf("matched evidence: %+v", exec.Evidence)
	}
}

func ewpAssertInconclusiveCommit(t *testing.T, tr model.Transition, incidentID, attemptID string) {
	t.Helper()
	outcome, ok := ewpEndedWork(tr, incidentID)
	if !ok || outcome.AttemptID != attemptID || outcome.Phase != model.WorkPhaseSettled || outcome.ResultCode != "success" || !outcome.EvidenceKnown || outcome.Finding == nil || outcome.Finding.Hypothesis != "" {
		t.Fatalf("reloaded ended work: %+v", outcome)
	}
	inconclusive := ewpCandidates(tr, model.CandidateInconclusiveCompletion)
	if len(inconclusive) != 1 || inconclusive[0].Outcome == nil || inconclusive[0].Outcome.AttemptID != attemptID || inconclusive[0].Finding == nil {
		t.Fatalf("expected exactly one inconclusive completion for the accepted attempt: %+v", inconclusive)
	}
	if strings.Join(inconclusive[0].Finding.Observations, ";") != "Pod events checked;Application errors checked" ||
		strings.Join(inconclusive[0].Finding.Unknowns, ";") != "logs_source_unavailable;1 verification checks unavailable or invalid" {
		t.Fatalf("candidate must carry the attempt's own checks and unknowns: %+v", inconclusive[0].Finding)
	}
	if got := ewpCandidates(tr, model.CandidateUsefulFinding); len(got) != 0 {
		t.Fatalf("a title without a root cause is not a useful finding: %+v", got)
	}
}

// Evidence is matched to the attempt, never borrowed from whatever the
// incident row says now: an output rewritten after the attempt no longer
// reproduces the recorded digest, so the completion's evidence is unknown
// and nothing is attributed.
func TestCompletionEvidenceUnmatchedAfterOutputRewriteAttributesNothing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	f := ewpFixture(t, st, "ewp-unmatched", "a", 1, now)
	claimed := mustClaim(t, st, f, now)
	ewpCycle(t, st, f.SituationID, "controller-unmatched", now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)))
	if _, err := st.CompleteIncidentTriageAttempt(ctx, claimed.AttemptID, f.IncidentID, TriageFinding{OutputJSON: `{}`, Summary: "Checkout analysis", Confidence: 0.2}, now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE incidents SET root_cause = 'Rewritten by a later path' WHERE id = ?`, f.IncidentID); err != nil {
		t.Fatal(err)
	}
	later := now.Add(3 * time.Minute)
	second, in := ewpCycle(t, st, f.SituationID, "controller-unmatched", later, shRunningTriageContract(later.Add(time.Minute)))
	if in.Incidents[0].Triage.LastExecution == nil || in.Incidents[0].Triage.LastExecution.Evidence != nil {
		t.Fatalf("rewritten output must not match the attempt: %+v", in.Incidents[0].Triage.LastExecution)
	}
	outcome, ok := ewpEndedWork(second, f.IncidentID)
	if !ok || outcome.EvidenceKnown || outcome.Finding != nil || outcome.AttemptID != claimed.AttemptID {
		t.Fatalf("ended work must record unmatched evidence: %+v", outcome)
	}
	if got := ewpCandidates(second, model.CandidateInconclusiveCompletion); len(got) != 0 {
		t.Fatalf("unmatched evidence establishes no inconclusive result: %+v", got)
	}
}

// Four accepted useful completions in one Situation: the overview keeps
// three, but every attempt's own matched evidence is loaded, so the fourth
// is reported from its own attempt rather than dropped.
func TestUsefulCompletionOutsideTopThreeKeepsItsOwnMatchedEvidence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	var fixtures []triageFixture
	for i := 0; i < 4; i++ {
		fixtures = append(fixtures, ewpFixture(t, st, "ewp-overview", fmt.Sprintf("%d", i), 1, now.Add(time.Duration(i)*time.Second)))
	}
	sitID := fixtures[0].SituationID
	first, in := ewpCycle(t, st, sitID, "controller-overview", now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)))
	if len(in.Incidents) != 4 || first.Projection.Briefing.Total < 4 {
		t.Fatalf("all four incidents must share the Situation: incidents=%d briefing=%+v", len(in.Incidents), first.Projection.Briefing)
	}
	for i, f := range fixtures {
		claimed := mustClaim(t, st, f, now.Add(2*time.Minute))
		finding := TriageFinding{OutputJSON: `{"correlation_findings":["Observation ` + f.IncidentID + `"]}`, Summary: "Analysis " + f.IncidentID, RootCause: "Hypothesis " + f.IncidentID, Confidence: 0.6}
		if _, err := st.CompleteIncidentTriageAttempt(ctx, claimed.AttemptID, f.IncidentID, finding, now.Add(3*time.Minute).Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("complete %s: %v", f.IncidentID, err)
		}
	}
	later := now.Add(10 * time.Minute)
	second, in := ewpCycle(t, st, sitID, "controller-overview", later, shRunningTriageContract(later.Add(time.Minute)))
	if len(in.Analyses) != 3 || in.AnalysisCount != 4 {
		t.Fatalf("overview selection: %d of %d", len(in.Analyses), in.AnalysisCount)
	}
	for _, inc := range in.Incidents {
		if inc.Triage.LastExecution == nil || inc.Triage.LastExecution.Evidence == nil || inc.Triage.LastExecution.Evidence.Hypothesis != "Hypothesis "+inc.ID {
			t.Fatalf("evidence must be matched independently of the overview: %s %+v", inc.ID, inc.Triage.LastExecution)
		}
	}
	useful := make([]string, 0, 4)
	for _, c := range ewpCandidates(second, model.CandidateUsefulFinding) {
		useful = append(useful, c.Finding.IncidentID)
	}
	if len(useful) != 4 {
		t.Fatalf("useful findings = %v, want all four accepted completions", useful)
	}
	if got := ewpCandidates(second, model.CandidateInconclusiveCompletion); len(got) != 0 {
		t.Fatalf("useful completions are never inconclusive: %+v", got)
	}
}

// A post-claim clean skip and a typed exhaustion in the same Situation: the
// skip stays quiet under its own recorded disposition; the exhaustion is one
// inconclusive completion naming its own attempt and result code, with no
// checks invented.
func TestPostClaimCleanSkipStaysQuietAndTypedExhaustionNamesItsAttempt(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	skipped := ewpFixture(t, st, "ewp-ends", "skip", 1, now)
	exhausted := ewpFixture(t, st, "ewp-ends", "fail", 1, now.Add(time.Second))
	ewpCycle(t, st, skipped.SituationID, "controller-ends", now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)))

	skipClaim := mustClaim(t, st, skipped, now.Add(2*time.Minute))
	if err := st.CompleteIncidentTriageAttemptAsCleanSkip(ctx, skipClaim.AttemptID, skipped.IncidentID, "clean_skip", "too few members", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	failClaim := mustClaim(t, st, exhausted, now.Add(2*time.Minute))
	if err := st.ExhaustIncidentTriageAttempt(ctx, failClaim.AttemptID, exhausted.IncidentID, "provider_error", "upstream unavailable", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	later := now.Add(5 * time.Minute)
	second, _ := ewpCycle(t, st, skipped.SituationID, "controller-ends", later, shRunningTriageContract(later.Add(time.Minute)))
	skipOutcome, ok := ewpEndedWork(second, skipped.IncidentID)
	if !ok || skipOutcome.Phase != model.WorkPhaseSettled || skipOutcome.SkipReason != "eligibility_policy" || skipOutcome.AttemptID != skipClaim.AttemptID || skipOutcome.ResultCode != "clean_skip" {
		t.Fatalf("post-claim clean skip outcome: %+v", skipOutcome)
	}
	failOutcome, ok := ewpEndedWork(second, exhausted.IncidentID)
	if !ok || failOutcome.Phase != model.WorkPhaseExhausted || failOutcome.AttemptID != failClaim.AttemptID || failOutcome.ResultCode != "provider_error" || failOutcome.EvidenceKnown || failOutcome.Finding != nil {
		t.Fatalf("exhaustion outcome: %+v", failOutcome)
	}
	inconclusive := ewpCandidates(second, model.CandidateInconclusiveCompletion)
	if len(inconclusive) != 1 || inconclusive[0].Outcome == nil || inconclusive[0].Outcome.IncidentID != exhausted.IncidentID || inconclusive[0].Outcome.AttemptID != failClaim.AttemptID {
		t.Fatalf("exactly one inconclusive completion, for the exhausted attempt only: %+v", inconclusive)
	}
	if inconclusive[0].Finding == nil || len(inconclusive[0].Finding.Observations) != 0 || inconclusive[0].Outcome.EvidenceKnown {
		t.Fatalf("checks were not retained and must not be invented: %+v", inconclusive[0].Finding)
	}
}

// Two attempts for one Incident: a backoff attempt then an accepted
// completion. The ended work names the attempt that actually ended the
// schedule, and the evidence is matched to that attempt.
func TestSecondAttemptCompletionIsAttributedToItsOwnAttempt(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	f := ewpFixture(t, st, "ewp-two-attempts", "a", 2, now)
	firstClaim := mustClaim(t, st, f, now)
	if err := st.BackoffIncidentTriageAttempt(ctx, firstClaim.AttemptID, f.IncidentID, now.Add(time.Minute), "provider_timeout", "slow", now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	ewpCycle(t, st, f.SituationID, "controller-two", now.Add(45*time.Second), shRunningTriageContract(now.Add(2*time.Minute)))
	secondClaim, err := st.ClaimIncidentTriageAttempt(ctx, f.IncidentID, "worker-2", now.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if secondClaim.AttemptNumber != 2 {
		t.Fatalf("attempt number = %d, want 2", secondClaim.AttemptNumber)
	}
	if _, err := st.CompleteIncidentTriageAttempt(ctx, secondClaim.AttemptID, f.IncidentID, TriageFinding{OutputJSON: `{"correlation_findings":["Second attempt checked pod events"]}`, Summary: "Checkout analysis", Confidence: 0.3}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(5 * time.Minute)
	tr, in := ewpCycle(t, st, f.SituationID, "controller-two", later, shRunningTriageContract(later.Add(time.Minute)))
	exec := in.Incidents[0].Triage.LastExecution
	if exec == nil || exec.AttemptID != secondClaim.AttemptID || exec.AttemptNumber != 2 || exec.Evidence == nil {
		t.Fatalf("last execution must be the second attempt with its own evidence: %+v", exec)
	}
	outcome, ok := ewpEndedWork(tr, f.IncidentID)
	if !ok || outcome.AttemptID != secondClaim.AttemptID {
		t.Fatalf("ended work must name the attempt that ended the schedule: %+v", outcome)
	}
	inconclusive := ewpCandidates(tr, model.CandidateInconclusiveCompletion)
	if len(inconclusive) != 1 || inconclusive[0].Outcome.AttemptID != secondClaim.AttemptID || strings.Join(inconclusive[0].Finding.Observations, ";") != "Second attempt checked pod events" {
		t.Fatalf("candidate must carry the second attempt's own evidence: %+v", inconclusive)
	}
}

// ----------------------------------------------------------------------
// R2 continued (lead review round 4, 2026-09-09): the real load →
// projection → commit → reload path, where the analysis overview and the
// matched completion evidence pass through DIFFERENT display bounds.
// Nothing below hand-builds an analysis or a FindingFacts.
// ----------------------------------------------------------------------

// One Incident whose accepted completion recorded FOUR observations and a
// limitation longer than the overview's hundred-byte bound: the overview
// keeps three and marks its cut, the matched completion keeps all four
// whole. Both projections record the same pre-truncation comparison
// provenance, so the display difference is never an evidence change — while a
// later attempt that changes only the FOURTH observation, which the overview
// cannot display at all, is still reported.
func TestEvidenceComparisonSeparatesDisplayBoundsFromEvidence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	f := ewpFixture(t, st, "ewp-bounds", "a", 2, now)
	claimed := mustClaim(t, st, f, now)
	ewpCycle(t, st, f.SituationID, "controller-bounds", now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)))

	limit := "metrics_source_unavailable: " + strings.Repeat("the recorded degradation reason keeps going ", 3)
	complete := func(fixture triageFixture, attemptID string, observations []string, at time.Time) {
		t.Helper()
		finding := TriageFinding{
			OutputJSON:     `{"analysis_name":"Checkout analysis","correlation_findings":["` + strings.Join(observations, `","`) + `"]}`,
			Summary:        "Checkout analysis",
			RootCause:      "Deployment broke checkout",
			Confidence:     0.7,
			EnrichmentJSON: `{"verification":{"outcome":"degraded","degradation_reason":"` + limit + `","rounds":[{"queries":[{"outcome":"failed"}]}]}}`,
		}
		result, err := st.CompleteIncidentTriageAttempt(ctx, attemptID, fixture.IncidentID, finding, at)
		if err != nil || result.Outcome != TriageCompletionSuccess {
			t.Fatalf("complete %s: %+v %v", attemptID, result, err)
		}
	}
	recorded := []string{"check one", "check two", "check three", "check four"}
	complete(f, claimed.AttemptID, recorded, now.Add(90*time.Second))

	// Cycle 2: the accepted result is reported once. The two projections
	// disagree about what to DISPLAY and agree about what was recorded.
	later := now.Add(3 * time.Minute)
	second, in := ewpCycle(t, st, f.SituationID, "controller-bounds", later, shRunningTriageContract(later.Add(time.Minute)))
	if len(in.Analyses) != 1 || len(in.Analyses[0].Findings) != model.AnalysisFindingsBound || !strings.HasSuffix(in.Analyses[0].VerificationLimit, "…") {
		t.Fatalf("the overview must apply its own list and text bounds: %+v", in.Analyses)
	}
	exec := in.Incidents[0].Triage.LastExecution
	if exec == nil || exec.Evidence == nil || len(exec.Evidence.Observations) != 4 || exec.Evidence.VerificationLimit != limit {
		t.Fatalf("the matched completion keeps the whole recorded evidence: %+v", exec)
	}
	an := ewpAnalysis(t, second, f.IncidentID)
	outcome, ok := ewpEndedWork(second, f.IncidentID)
	if !ok || outcome.Finding == nil {
		t.Fatalf("ended work must carry the matched evidence: %+v", outcome)
	}
	if an.EvidenceFingerprint == "" || outcome.Finding.EvidenceFingerprint != an.EvidenceFingerprint {
		t.Fatalf("the two projections must record the same pre-truncation provenance: overview=%q completion=%q",
			an.EvidenceFingerprint, outcome.Finding.EvidenceFingerprint)
	}
	if useful := ewpCandidates(second, model.CandidateUsefulFinding); len(useful) != 1 || useful[0].Finding.IncidentID != f.IncidentID {
		t.Fatalf("the accepted result must be reported exactly once: %+v", useful)
	} else if useful[0].Finding.EvidenceFingerprint != "" {
		t.Fatalf("a candidate must not carry comparison provenance downstream: %+v", useful[0].Finding)
	}

	// Cycle 3: a second Incident joins the Situation — a real material
	// change that records a Transition — while the first Incident's evidence
	// is unchanged. Its three-item overview entry must not read as different
	// evidence from the four-item completion it already reported.
	ewpFixture(t, st, "ewp-bounds", "b", 1, now.Add(time.Second))
	third := now.Add(6 * time.Minute)
	joined, _ := ewpCycle(t, st, f.SituationID, "controller-bounds", third, shRunningTriageContract(third.Add(time.Minute)))
	if joined.ID == "" {
		t.Fatal("a new member is a material change and must record a transition")
	}
	for _, c := range ewpCandidates(joined, model.CandidateUsefulFinding) {
		if c.Finding.IncidentID == f.IncidentID {
			t.Fatalf("unchanged evidence displayed through a different bound became a new finding: %+v", c.Finding)
		}
	}

	// Cycle 4: a real second attempt whose only change is the FOURTH
	// observation — invisible in the overview, and still a material change.
	if _, err := st.db.ExecContext(ctx, `UPDATE incidents SET status='ready' WHERE id=?`, f.IncidentID); err != nil {
		t.Fatalf("reopen incident for a second analysis: %v", err)
	}
	rerunFixture := f
	rerunFixture.MembershipDigest, rerunFixture.IncidentInputDigest = digestsForTest(t, st, f.IncidentID)
	// The re-analysis schedule is seeded directly, carrying the attempt the
	// first analysis already spent: this chunk owns no re-open writer, and
	// everything after it — decision, claim, completion, load, projection,
	// commit and reload — is the real path.
	reopenedAt := now.Add(7 * time.Minute)
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at) VALUES (?, 'awaiting_decision', 1, ?)`,
		f.IncidentID, canonicalTime(reopenedAt)); err != nil {
		t.Fatalf("seed re-analysis schedule: %v", err)
	}
	applyDecisionsTx(t, st, []situation.TriageDecision{requestDecisionFor(rerunFixture, "test_fixture", reopenedAt)}, reopenedAt)
	rerun := mustClaimExisting(t, st, rerunFixture, reopenedAt)
	complete(rerunFixture, rerun.AttemptID, []string{"check one", "check two", "check three", "check four, rerun"}, now.Add(8*time.Minute))
	fourth := now.Add(9 * time.Minute)
	reported, _ := ewpCycle(t, st, f.SituationID, "controller-bounds", fourth, shRunningTriageContract(fourth.Add(time.Minute)))
	changed := 0
	for _, c := range ewpCandidates(reported, model.CandidateUsefulFinding) {
		if c.Finding.IncidentID == f.IncidentID {
			changed++
		}
	}
	// Exactly one: the Incident is inside the overview, so the analysis path
	// reports it and the completion path defers, as it does for any
	// in-overview result.
	if changed != 1 {
		t.Fatalf("a changed observation beyond the overview's bound was reported %d times: %+v", changed, reported.Projection.OperatorDelta)
	}
	rerunOutcome, ok := ewpEndedWork(reported, f.IncidentID)
	if !ok || rerunOutcome.AttemptID != rerun.AttemptID || rerunOutcome.Finding == nil ||
		strings.Join(rerunOutcome.Finding.Observations, ";") != "check one;check two;check three;check four, rerun" {
		t.Fatalf("the change must come from the second attempt's own matched evidence: %+v", rerunOutcome)
	}
	if rerunOutcome.Finding.EvidenceFingerprint == an.EvidenceFingerprint {
		t.Fatalf("changed evidence must not reproduce the first attempt's fingerprint: %q", an.EvidenceFingerprint)
	}
}

func ewpAnalysis(t *testing.T, tr model.Transition, incidentID string) model.IncidentAnalysis {
	t.Helper()
	if tr.Projection.Briefing != nil {
		for _, a := range tr.Projection.Briefing.Analyses {
			if a.IncidentID == incidentID {
				return a
			}
		}
	}
	t.Fatalf("committed briefing carries no analysis for %s", incidentID)
	return model.IncidentAnalysis{}
}

func TestOperatorUsefulnessStoredChecksReachBriefing(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "specific-checks", now)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='analyzed',summary='Frontend errors',root_cause='Isolated failure',output_json='{"correlation_findings":["Only frontend affected"]}',enrichment_json=?,last_judged_at=? WHERE id='inc-specific-checks'`,
		`{"verification":{"outcome":"degraded","degradation_reason":"llm_call_failed","rounds":[{"queries":[{"kind":"promql","why":"Check payment errors","outcome":"empty","expr":"PRIVATE_QUERY"},{"kind":"incidents_in_window","outcome":"fetched","result":"2 incidents on other group keys (60m): service=payment; service=checkout"}]}]}}`, now.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "checks", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in.Analyses)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Check payment errors", "no data", "service=payment", "relationship"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %q: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "PRIVATE_QUERY") {
		t.Fatal("raw query leaked")
	}
}

func TestOperatorUsefulnessFreezesBudgetReason(t *testing.T) {
	in := situation.SnapshotInput{}
	in.ControllerParked.Reason = situation.ParkedReasonBudget
	b := situation.BuildOperatorBriefing(in, model.LifecycleActive)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"blocked_reason":"budget_deferred"`) {
		t.Fatal(string(raw))
	}
}
