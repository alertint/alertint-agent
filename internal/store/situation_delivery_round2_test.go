// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-2 repair regressions (lead review 2026-09-09, R2/R3/R4/R5),
// exercised against the real SQLite store, the real derivation/planner and
// the real fenced CommitController transaction.
//
// R2: only a DELIVERED root version's own work provenance, or a DELIVERED
//     reply that actually carried the assurance, conveys it. The current
//     Episode summary and the legacy investigation_started journal label
//     both answer a different question.
// R3: a start reply that also carries material member/scope history is not
//     disposable; only a purely transient assurance is.
// R4: the commit that publishes the first root queues no thread echo.
// R5: an obstacle still OWED to the operator keeps its correction alive.
// ----------------------------------------------------------------------

func b5r2Brief() *model.OperatorBriefing {
	return &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}
}

// b5r2Executing is a briefing whose work projection records that execution
// ACTUALLY started — the accepted Briefing.Work.ExecutionStarted fact, not
// a triage authorization.
func b5r2Executing() *model.OperatorBriefing {
	b := b5r2Brief()
	b.Work = model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
		InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"AlertA"},
		InvestigatedCount: 1, InvestigatedCountKnown: true}
	return b
}

func b5r2Finding() *model.OperatorBriefing {
	b := b5r2Executing()
	b.Analyses = []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deploy broke checkout",
		Findings: []string{"Errors began after deploy"}}}
	return b
}

// b5r2History reads the delivery-aware history the planner would see now.
func b5r2History(t *testing.T, st *Store, situationID string) situation.DeliveredHistory {
	t.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	h, err := loadDeliveredHistoryTx(ctx, tx, situationID, true)
	if err != nil {
		t.Fatalf("loadDeliveredHistoryTx: %v", err)
	}
	return h
}

// b5r2PendingReplies counts the still-deliverable replies one Transition
// created.
func b5r2PendingReplies(t *testing.T, st *Store, situationID, transitionID string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM notification_intents
		WHERE situation_id = ? AND transition_id = ?
		  AND effect_class IN ('thread_append','broadcast_handoff') AND status = 'pending'`,
		situationID, transitionID).Scan(&n); err != nil {
		t.Fatalf("count pending replies: %v", err)
	}
	return n
}

// R2/1: the root edit that would show execution is still queued. Nothing on
// the operator's screen says work started, so the assurance is not conveyed.
func TestB5UndeliveredRootEditDoesNotConveyTheAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-undelivered-edit", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second)) // only the awaiting root reached Slack

	osCycle(t, st, id, now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r2Executing(), true)

	if h := b5r2History(t, st, id); h.AssuranceConveyed {
		t.Fatal("a pending root edit and a pending assurance reply were counted as communicated")
	}
}

// R2/2: a delivered root whose own version recorded actual execution DOES
// convey it — the positive half of the same rule.
func TestB5DeliveredExecutingRootConveysTheAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-delivered-edit", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	osCycle(t, st, id, now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r2Executing(), true)
	// Deliver the root edit that carries the executing work projection.
	snDeliver(t, st, snClaimOne(t, st, now.Add(70*time.Second)), "100.1", now.Add(71*time.Second))

	if h := b5r2History(t, st, id); !h.AssuranceConveyed {
		t.Fatal("a delivered root version recording actual execution must convey the assurance")
	}
}

// R2/3: a delivered root for QUEUED (authorized but not started) work must
// not consume the one assurance the later actual execution earns.
func TestB5DeliveredQueuedRootDoesNotConsumeTheAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-queued-root", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	queued := b5r2Brief()
	queued.Work.Phase = model.WorkPhaseQueued
	contract := shRunningTriageContract(now.Add(2 * time.Minute))
	planned := model.AlertINTStatusPlanned
	contract.AlertINTStatus = &planned
	osCycle(t, st, id, now.Add(time.Minute), contract, model.LifecycleActive, queued, true)
	snDeliver(t, st, snClaimOne(t, st, now.Add(80*time.Second)), "100.1", now.Add(81*time.Second))

	if h := b5r2History(t, st, id); h.AssuranceConveyed {
		t.Fatal("queued work is an authorization, not execution: it must not convey the assurance")
	}

	tr := osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Executing(), true)
	found := false
	for _, c := range tr.Projection.OperatorDelta.Candidates {
		if c.Kind == model.CandidateFirstExecutionAssurance {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture lost its actual-execution candidate: %+v", tr.Projection.OperatorDelta)
	}
	if n := b5r2PendingReplies(t, st, id, tr.ID); n != 1 {
		t.Fatalf("actual first execution earned %d replies, want exactly 1", n)
	}
}

// R3: a start reply that ALSO carries a member/scope change is material
// history. A finding may replace the transient assurance; it may not erase
// the scope change that rode with it.
func TestB5MixedMaterialStartSurvivesSupersession(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-mixed-start", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	mixed := b5r2Executing()
	mixed.Scope = "checkout + payments"
	start := osCycle(t, st, id, now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, mixed, true)
	members, assurance := false, false
	for _, c := range start.Projection.OperatorDelta.Candidates {
		switch c.Kind { //nolint:exhaustive // the fixture only asserts that these two rode the same transition.
		case model.CandidateMembersChanged:
			members = true
		case model.CandidateFirstExecutionAssurance:
			assurance = true
		}
	}
	if !members || !assurance || start.JournalKind != model.JournalInvestigationStarted {
		t.Fatalf("fixture is not a combined start+scope change: %+v", start)
	}

	found := b5r2Finding()
	found.Scope = "checkout + payments"
	osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, found, true)

	if info := osIntentDetail(t, st, id, start.Sequence); info.Status == "superseded" {
		t.Fatalf("the whole start+scope reply was superseded (%s), losing its member/scope history", info.Reason)
	}
}

// R3 guard: a PURELY transient start — assurance and nothing else — is
// still disposable when a finding overtakes it.
func TestB5PurelyTransientStartIsStillSuperseded(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-pure-start", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	start := osCycle(t, st, id, now.Add(time.Minute), shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive, b5r2Executing(), true)
	for _, c := range start.Projection.OperatorDelta.Candidates {
		if c.Kind != model.CandidateFirstExecutionAssurance {
			t.Fatalf("fixture is not a purely transient start: %+v", start.Projection.OperatorDelta.Candidates)
		}
	}
	osCycle(t, st, id, now.Add(2*time.Minute), shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Finding(), true)

	if info := osIntentDetail(t, st, id, start.Sequence); info.Status != "superseded" {
		t.Fatalf("an overtaken transient start must still be superseded, got %s", info.Status)
	}
}

// R4: the commit that publishes the FIRST root renders current truth. It
// queues no thread echo of its own — the canonical late-first-root rule.
func TestB5FirstRootPublicationQueuesNoThreadEcho(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-first-root", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	terminal := osCycle(t, st, id, now.Add(time.Minute), osTerminalContract(), model.LifecycleClosedUnknown, b5r2Brief(), false)

	if n := b5r2PendingReplies(t, st, id, terminal.ID); n != 0 {
		t.Fatalf("a delayed first terminal root also queued %d thread echoes", n)
	}
}

// R5: an obstacle queued during a delivery gap is still owed. Its clearance
// must survive planning, or the stale obstacle publishes later with no
// correction behind it.
func TestB5OwedObstacleKeepsItsClearanceReply(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-owed-obstacle", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	limited := b5r2Brief()
	limited.Unavailable = 1
	obstacle := osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, limited, true)
	if n := b5r2PendingReplies(t, st, id, obstacle.ID); n != 1 {
		t.Fatalf("fixture: the obstacle earned %d replies, want 1 pending", n)
	}

	cleared := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)

	if b5r2PendingReplies(t, st, id, obstacle.ID) == 1 && b5r2PendingReplies(t, st, id, cleared.ID) == 0 {
		t.Fatal("the obstacle is still owed but its correction was dropped as unreported")
	}
	if n := b5r2PendingReplies(t, st, id, cleared.ID); n != 1 {
		t.Fatalf("the clearance earned %d replies, want exactly 1", n)
	}
}

// R5 negative control: a genuinely unreported transient obstacle — never
// delivered, never queued, because it appeared and cleared inside one
// commit — still earns nothing. Only an owed or delivered obstacle does.
func TestB5TrulyUnreportedObstacleClearanceStaysQuiet(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-unreported", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	h := b5r2History(t, st, id)
	if len(h.OwedLimitationCodes) != 0 || len(h.CommunicatedLimitationCodes) != 0 {
		t.Fatalf("fixture: nothing should be owed or communicated yet: %+v", h)
	}
}

// R1/R5 boundary, real store: the delivery-time read the Slack deliverer
// makes is bounded to what the operator had BEFORE the reply being sent.
// The obstacle's own reply must not see itself as already communicated, and
// the clearance that follows it must.
func TestB5CommunicatedHistoryIsBoundedToWhatCameBefore(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-bounded-history", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	limited := b5r2Brief()
	limited.Unavailable = 1
	obstacle := osCycle(t, st, id, now.Add(time.Minute), osMonitoringContract(now.Add(2*time.Minute)),
		model.LifecycleActive, limited, true)

	before, err := st.GetCommunicatedHistory(ctx, id, obstacle.Sequence)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	if len(before.CommunicatedLimitationCodes) != 0 {
		t.Fatalf("the obstacle reply must not see its own limitation as communicated: %+v", before)
	}

	// Deliver the root edit, then the obstacle reply itself.
	snDeliver(t, st, snClaimOne(t, st, now.Add(70*time.Second)), "100.1", now.Add(71*time.Second))
	snDeliver(t, st, snClaimOne(t, st, now.Add(72*time.Second)), "100.2", now.Add(73*time.Second))

	cleared := osCycle(t, st, id, now.Add(2*time.Minute), osMonitoringContract(now.Add(3*time.Minute)),
		model.LifecycleActive, b5r2Brief(), true)
	after, err := st.GetCommunicatedHistory(ctx, id, cleared.Sequence)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	if !containsCode(after.CommunicatedLimitationCodes, model.LimitationInvestigationUnavailable) {
		t.Fatalf("the clearance reply must see the delivered obstacle as communicated: %+v", after)
	}

	// Deliver the clearance too. The bound is what keeps the answer stable:
	// asked again for the same reply, history must still be the state that
	// preceded it, not the state its own delivery produced.
	snDeliver(t, st, snClaimOne(t, st, now.Add(140*time.Second)), "100.1", now.Add(141*time.Second))
	snDeliver(t, st, snClaimOne(t, st, now.Add(142*time.Second)), "100.3", now.Add(143*time.Second))

	replay, err := st.GetCommunicatedHistory(ctx, id, cleared.Sequence)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	if !containsCode(replay.CommunicatedLimitationCodes, model.LimitationInvestigationUnavailable) {
		t.Fatalf("a redelivery of the clearance must still see the obstacle it corrects: %+v", replay)
	}
	whole, err := st.GetCommunicatedHistory(ctx, id, 0)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	if containsCode(whole.CommunicatedLimitationCodes, model.LimitationInvestigationUnavailable) {
		t.Fatalf("the unbounded net history must show the obstacle cleared: %+v", whole)
	}
}

func containsCode(list []string, code string) bool {
	for _, v := range list {
		if v == code {
			return true
		}
	}
	return false
}

// R2, the reply half of the same rule: a DELIVERED reply whose Transition
// merely wears the investigation_started journal label — the legacy
// action-contract fold sets it for PLANNED triage — has not told the
// operator that execution began. Only a delivered reply that actually
// carried the first_execution_assurance candidate has.
func TestB5DeliveredPlannedTriageReplyDoesNotConveyTheAssurance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r2-planned-reply", now)

	osCycle(t, st, id, now, osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, b5r2Brief(), false)
	snDeliver(t, st, snClaimOne(t, st, now), "100.1", now.Add(time.Second))

	// Authorized but not started, and the membership scope moved — so the
	// cycle earns a reply of its own while carrying no assurance.
	queued := b5r2Brief()
	queued.Work.Phase = model.WorkPhaseQueued
	queued.Scope = "checkout + payments"
	contract := shRunningTriageContract(now.Add(2 * time.Minute))
	planned := model.AlertINTStatusPlanned
	contract.AlertINTStatus = &planned
	tr := osCycle(t, st, id, now.Add(time.Minute), contract, model.LifecycleActive, queued, true)
	if tr.JournalKind != model.JournalInvestigationStarted {
		t.Skipf("fixture no longer produces the legacy planned-triage journal label: %s", tr.JournalKind)
	}
	for _, c := range tr.Projection.OperatorDelta.Candidates {
		if c.Kind == model.CandidateFirstExecutionAssurance {
			t.Fatalf("fixture: planned triage must not carry an assurance candidate: %+v", tr.Projection.OperatorDelta.Candidates)
		}
	}
	if n := b5r2PendingReplies(t, st, id, tr.ID); n != 1 {
		t.Fatalf("fixture: the scope change must earn one reply, got %d", n)
	}
	// Deliver the root edit and that reply.
	snDeliver(t, st, snClaimOne(t, st, now.Add(70*time.Second)), "100.1", now.Add(71*time.Second))
	snDeliver(t, st, snClaimOne(t, st, now.Add(72*time.Second)), "100.2", now.Add(73*time.Second))

	if h := b5r2History(t, st, id); h.AssuranceConveyed {
		t.Fatal("a delivered reply wearing the investigation_started label conveyed an assurance it never carried")
	}
}
