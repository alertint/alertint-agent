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
			InvestigatedAlertIDs: ids, InvestigatedNames: names, InvestigatedCount: 9,
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
	if !ok || assurance.Members == nil || assurance.Members.FiringCount != 9 {
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
