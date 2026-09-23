// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// D1 (lead reviews 2026-09-10, rounds 2 and 3): §5.3's obsolete-start
// supersession used to key on the investigation_started journal LABEL, and
// the canonical order never wears it. A Situation that REQUESTS triage in
// one cycle and STARTS it in the next records the real execution start as
// operator_contract_changed, so the guard refused to retire exactly the
// reply it exists to retire and the operator received a content-free start
// claim after the finding that replaced it.
//
// Every test below drives real controller cycles through CommitController,
// so the fixture's journal kind and candidate list are DERIVED by the
// product rather than asserted into place. situation_obsolete_start_
// supersession_test.go keeps the pre-D1 label path covered; this file adds
// the order the canonical slide-5 replay actually walks.
//
// These tests are also the store-package half of the mutation control the
// lead required: widening the Go predicate while leaving migration 0022's
// trigger installed does not merely fail to suppress — it aborts the whole
// finding commit, and before this file no store regression noticed.
// ----------------------------------------------------------------------

// oscPlannedTriageContract is run_acute_triage/PLANNED: triage is
// authorized but not yet running. investigationCurrent already treats this
// as investigating, which is why the NEXT cycle — the one that actually
// starts execution — can no longer earn ReasonInvestigationStarted.
func oscPlannedTriageContract(next time.Time) model.ActionContract {
	c := shRunningTriageContract(next)
	planned := model.AlertINTStatusPlanned
	c.AlertINTStatus = &planned
	return c
}

func oscQueuedBriefing(scope string) *model.OperatorBriefing {
	return &model.OperatorBriefing{Scope: scope, Firing: 1, Total: 1,
		Work: model.WorkProjection{Phase: model.WorkPhaseQueued}}
}

func oscExecutingBriefing(scope string, firing, total int) *model.OperatorBriefing {
	return &model.OperatorBriefing{Scope: scope, Firing: firing, Total: total,
		Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
			InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"},
			InvestigatedCount: 1, InvestigatedCountKnown: true}}
}

func oscFindingBriefing(scope string, firing, total int) *model.OperatorBriefing {
	b := oscExecutingBriefing(scope, firing, total)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment broke checkout",
		Findings: []string{"Errors began after deploy"}}}
	return b
}

// oscCandidateKinds names, in order, the material facts a Transition
// recorded.
func oscCandidateKinds(tr model.Transition) []model.CandidateKind {
	if tr.Projection.OperatorDelta == nil {
		return nil
	}
	out := make([]model.CandidateKind, 0, len(tr.Projection.OperatorDelta.Candidates))
	for _, c := range tr.Projection.OperatorDelta.Candidates {
		out = append(out, c.Kind)
	}
	return out
}

// oscCanonicalStart runs the canonical monitor -> planned -> running order
// and returns the Transition that records the real execution start. It
// asserts the D1 preconditions itself: the start is journalled
// operator_contract_changed, NOT investigation_started, and its recorded
// candidate list is exactly the one transient assurance. If the controller
// ever starts labelling this Transition investigation_started, these tests
// stop testing D1 and say so instead of quietly passing.
func oscCanonicalStart(t *testing.T, st *Store, sitID string, now time.Time, scope string, firing, total int) model.Transition {
	t.Helper()
	osCycle(t, st, sitID, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	requested := osCycle(t, st, sitID, now.Add(time.Minute), oscPlannedTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, oscQueuedBriefing("checkout"), true)
	if requested.JournalKind != model.JournalInvestigationStarted {
		t.Fatalf("the REQUEST cycle is journalled %s, want investigation_started — "+
			"D1's premise is that this label lands on the request, not the start", requested.JournalKind)
	}
	if kinds := oscCandidateKinds(requested); len(kinds) != 0 {
		t.Fatalf("the request cycle recorded candidates %v, want none: authorization is not execution", kinds)
	}

	start := osCycle(t, st, sitID, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, oscExecutingBriefing(scope, firing, total), true)
	if start.JournalKind == model.JournalInvestigationStarted {
		t.Fatalf("the execution start is journalled investigation_started; the canonical D1 order no longer " +
			"reproduces and this test must be rewritten rather than trusted")
	}
	if start.JournalKind != model.JournalOperatorContractChanged {
		t.Fatalf("the execution start is journalled %s, want operator_contract_changed", start.JournalKind)
	}
	return start
}

// TestObsoleteStartSupersededOnTheCanonicalPlannedThenRunningOrder is the
// D1 regression: on the order the slide-5 replay walks, a live start
// assurance IS retired by the finding that overtakes it, in the finding's
// own fenced transaction, with its lease fences cleared and its
// replacement named.
func TestObsoleteStartSupersededOnTheCanonicalPlannedThenRunningOrder(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-canonical", now)

	start := oscCanonicalStart(t, st, sitID, now, "checkout", 1, 1)
	if kinds := oscCandidateKinds(start); len(kinds) != 1 || kinds[0] != model.CandidateFirstExecutionAssurance {
		t.Fatalf("the execution start recorded candidates %v, want exactly [first_execution_assurance]", kinds)
	}
	if info := osIntentDetail(t, st, sitID, start.Sequence); info.Status != "pending" {
		t.Fatalf("assurance reply status = %s, want pending before the finding arrives", info.Status)
	}

	// Deliver the start's own root edit so the reply beneath it becomes
	// claimable, then let a worker claim it: the finding now overtakes a
	// reply with a LIVE lease, which is the fence this must clear.
	rootEdit := snClaimOne(t, st, now.Add(2*time.Minute+20*time.Second))
	if rootEdit.Intent.EffectClass != model.EffectRootSync {
		t.Fatalf("claim after the start = %s, want the root edit first", rootEdit.Intent.EffectClass)
	}
	snDeliver(t, st, rootEdit, "100.1", now.Add(2*time.Minute+25*time.Second))
	replyClaim := snClaimOne(t, st, now.Add(2*time.Minute+30*time.Second))
	if replyClaim.Intent.EffectClass != model.EffectThreadAppend {
		t.Fatalf("second claim = %s, want the assurance reply", replyClaim.Intent.EffectClass)
	}
	var owner, lease sql.NullString
	if err := st.db.QueryRowContext(ctx,
		`SELECT claim_owner, lease_expires_at FROM notification_intents WHERE id = ?`,
		replyClaim.Intent.ID).Scan(&owner, &lease); err != nil {
		t.Fatal(err)
	}
	if !owner.Valid || !lease.Valid {
		t.Fatalf("the claim did not take a lease: owner=%v lease=%v", owner, lease)
	}

	finding := osCycle(t, st, sitID, now.Add(3*time.Minute), shRunningTriageContract(now.Add(4*time.Minute)),
		model.LifecycleActive, oscFindingBriefing("checkout", 1, 1), true)

	got := osIntentDetail(t, st, sitID, start.Sequence)
	if got.Status != "superseded" {
		t.Fatalf("assurance reply status after the finding = %s, want superseded — D1 has regressed", got.Status)
	}
	if got.Reason != SupersessionReasonFinding {
		t.Fatalf("supersession_reason = %q, want %q", got.Reason, SupersessionReasonFinding)
	}
	findingReply := osIntentDetail(t, st, sitID, finding.Sequence)
	if got.Replacement != findingReply.ID {
		t.Fatalf("replacement_intent_id = %q, want the finding's own reply %q", got.Replacement, findingReply.ID)
	}
	if findingReply.Status != "pending" {
		t.Fatalf("the finding's own reply status = %s, want pending", findingReply.Status)
	}

	// Lease fencing: a superseded row holds no claim, no lease and no
	// retry, so no worker can resurrect it.
	var retry sql.NullString
	if err := st.db.QueryRowContext(ctx,
		`SELECT claim_owner, lease_expires_at, retry_at FROM notification_intents WHERE id = ?`,
		got.ID).Scan(&owner, &lease, &retry); err != nil {
		t.Fatal(err)
	}
	if owner.Valid || lease.Valid || retry.Valid {
		t.Fatalf("superseded assurance still fenced to a worker: owner=%v lease=%v retry=%v", owner, lease, retry)
	}

	// The Transition itself is untouched history: D1 retires a REPLY, never
	// a journal entry, and relabels nothing.
	stored, err := st.GetSituationTransition(ctx, start.ID)
	if err != nil {
		t.Fatalf("re-read the start transition: %v", err)
	}
	if stored.JournalKind != model.JournalOperatorContractChanged {
		t.Fatalf("the start transition's journal_kind is now %s; the repair rewrote history", stored.JournalKind)
	}
	if kinds := oscCandidateKinds(stored); len(kinds) != 1 || kinds[0] != model.CandidateFirstExecutionAssurance {
		t.Fatalf("the start transition's candidates are now %v; the repair rewrote its projection", kinds)
	}
	assertNoForeignKeyViolations(ctx, t, st)
}

// TestObsoleteStartMixedMaterialOnTheCanonicalOrderSurvives is the
// counterweight the lead required: broadening eligibility must not let a
// row carrying real member/scope history disappear. This is the same
// canonical order, with a membership change riding along on the start.
func TestObsoleteStartMixedMaterialOnTheCanonicalOrderSurvives(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-canonical-mixed", now)

	start := oscCanonicalStart(t, st, sitID, now, "checkout + payments", 2, 2)
	kinds := oscCandidateKinds(start)
	var sawAssurance, sawMaterial bool
	for _, k := range kinds {
		if k == model.CandidateFirstExecutionAssurance {
			sawAssurance = true
			continue
		}
		sawMaterial = true
	}
	if !sawAssurance || !sawMaterial {
		t.Fatalf("the mixed fixture recorded %v, want the assurance AND at least one material candidate", kinds)
	}
	before := osIntentDetail(t, st, sitID, start.Sequence)
	if before.Status != "pending" {
		t.Fatalf("mixed reply status = %s, want pending before the finding", before.Status)
	}

	osCycle(t, st, sitID, now.Add(3*time.Minute), shRunningTriageContract(now.Add(4*time.Minute)),
		model.LifecycleActive, oscFindingBriefing("checkout + payments", 2, 2), true)

	after := osIntentDetail(t, st, sitID, start.Sequence)
	if after.Status == "superseded" {
		t.Fatalf("the finding retired a reply carrying %v — its member/scope history is not disposable", kinds)
	}
	if after.Status != "pending" {
		t.Fatalf("mixed reply status after the finding = %s, want pending", after.Status)
	}
	if after.Reason != "" || after.Replacement != "" {
		t.Fatalf("a live reply carries supersession bookkeeping: reason=%q replacement=%q", after.Reason, after.Replacement)
	}
	assertNoForeignKeyViolations(ctx, t, st)
}

// TestLiveTransientAssuranceIsBoundedByTheOvertakingSequence pins the
// strict ordering bound added with the D1 repair: only a reply from an
// EARLIER Transition than the overtaking one is eligible. The assurance
// candidate is emitted at most once per Situation, so this narrows nothing
// observed today; it makes "an earlier message cannot be retired by an
// earlier one" structural instead of incidental.
func TestLiveTransientAssuranceIsBoundedByTheOvertakingSequence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	situationID := "sit-assurance-bound"
	insertOperationalIncident(ctx, t, st, "inc-assurance-bound", "group-assurance-bound")
	if err := insertSituation(ctx, st, situationRow{
		id: situationID, groupKey: "group-assurance-bound", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	pure := assuranceParityCase{
		journalKind:    "operator_contract_changed",
		projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"}]}}`,
	}
	early := seedAssuranceParityRow(ctx, t, st, situationID, 2, pure)
	late := seedAssuranceParityRow(ctx, t, st, situationID, 7, pure)

	eligible := func(beforeSequence int) []string {
		t.Helper()
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		ids, err := liveTransientAssuranceIntentIDsTx(ctx, tx, situationID, beforeSequence)
		if err != nil {
			t.Fatalf("liveTransientAssuranceIntentIDsTx(before=%d): %v", beforeSequence, err)
		}
		return ids
	}

	if got := eligible(0); len(got) != 2 {
		t.Fatalf("unbounded eligibility named %v, want both live assurances", got)
	}
	got := eligible(5)
	if len(got) != 1 || got[0] != early {
		t.Fatalf("eligibility bounded at sequence 5 named %v, want only the earlier reply %q", got, early)
	}
	if got := eligible(2); len(got) != 0 {
		t.Fatalf("eligibility bounded at the reply's own sequence named %v, want none: the bound is strict", got)
	}
	if got := eligible(8); len(got) != 2 {
		t.Fatalf("eligibility bounded above both named %v, want both (%q and %q)", got, early, late)
	}
}
