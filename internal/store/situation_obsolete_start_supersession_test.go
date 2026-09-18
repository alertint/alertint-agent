// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 (earned delivery / communicated history): obsolete-start suppression
// (B0 integration contract §5.3). A later commit that plans a
// useful_finding, inconclusive_completion or terminal_end reply while a
// first-execution assurance reply is still undelivered must, in the SAME
// fenced CommitController transaction, mark that live assurance row
// superseded — never a second, separately-committed write, and never
// touching a reply that already delivered (ADR 0042/0052: material history
// is never superseded; only the one transient start assurance is).
// ----------------------------------------------------------------------

// osMonitoringContract is a valid nonterminal contract that is NOT
// investigating (model.AlertINTActionMonitorSituation), so the following
// cycle's shift to shRunningTriageContract (AlertINTActionRunAcuteTriage)
// is a genuine investigationCurrent false->true edge for BuildTransitions'
// own ReasonInvestigationStarted derivation.
func osMonitoringContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   timePtrValue(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
}

// osTerminalContract is a valid terminal contract (no next_update_at/on,
// next_actor none) for a closed_unknown cycle.
func osTerminalContract() model.ActionContract {
	return model.ActionContract{NextActor: model.NextActorNone}
}

// osOwner is the single claim owner every osCycle call in this file uses.
const osOwner = "os-owner"

// osCycle runs one real controller cycle for sitID via CommitController,
// with explicit control over RootPublished — the ewpCycle helper always
// leaves it at the zero value, which this test cannot use since it needs a
// durably published root before the assurance can earn its own reply.
func osCycle(t *testing.T, st *Store, sitID string, now time.Time, contract model.ActionContract,
	lifecycle model.Lifecycle, briefing *model.OperatorBriefing, rootPublished bool) model.Transition {
	t.Helper()
	ctx := context.Background()
	shMakeDue(t, st, sitID, now.Add(-time.Second))
	claim := claimSituation(t, st, sitID, osOwner, now)
	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	cycle := shPrepare(t, claim, contract, lifecycle, model.AttentionObserve, now)
	cycle.Change.PriorTransition = in.PriorTransition
	cycle.Change.PriorSummary = in.CurrentSummary
	cycle.Change.Projection.Briefing = briefing
	cycle.Publish.RootPublished = rootPublished
	cycle.Publish.DeliveredHistory = in.DeliveredHistory
	if in.PriorTransition != nil {
		cycle.Publish.PriorTransition = in.PriorTransition
	}
	commit := shDerive(t, cycle)
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	if commit.History == nil || len(commit.History.Transitions) != 1 {
		t.Fatalf("expected exactly one committed transition, got %+v", commit.History)
	}
	stored, err := st.GetSituationTransition(ctx, commit.History.Transitions[0].ID)
	if err != nil {
		t.Fatalf("GetSituationTransition: %v", err)
	}
	return stored
}

// osIntentInfo is one thread_append notification_intent's current
// identity/status/supersession fields.
type osIntentInfo struct {
	ID, Status, Reason, Replacement string
}

// osIntentDetail reads one thread_append notification_intent's current
// identity/status/supersession fields directly.
func osIntentDetail(t *testing.T, st *Store, situationID string, transitionSequence int) osIntentInfo {
	t.Helper()
	var info osIntentInfo
	var r, rep sql.NullString
	err := st.db.QueryRowContext(context.Background(), `
		SELECT id, status, COALESCE(supersession_reason,''), COALESCE(replacement_intent_id,'')
		FROM notification_intents
		WHERE situation_id = ? AND transition_sequence = ? AND effect_class = 'thread_append'`,
		situationID, transitionSequence).Scan(&info.ID, &info.Status, &r, &rep)
	if err != nil {
		t.Fatalf("read intent status: %v", err)
	}
	info.Reason, info.Replacement = r.String, rep.String
	return info
}

func TestObsoleteStartAssuranceSupersededByFinding(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-finding", now)

	// Cycle 1: publish the root — no work yet.
	osCycle(t, st, sitID, now,
		osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)

	// Cycle 2: execution starts against the root that already exists — earns
	// one undelivered assurance reply.
	assuranceTr := osCycle(t, st, sitID, now.Add(time.Minute),
		shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true}},
		true)
	if assuranceTr.JournalKind != model.JournalInvestigationStarted {
		t.Fatalf("cycle 2 journal_kind = %s, want investigation_started", assuranceTr.JournalKind)
	}
	if info := osIntentDetail(t, st, sitID, assuranceTr.Sequence); info.Status != "pending" {
		t.Fatalf("assurance reply status = %s, want pending before the finding arrives", info.Status)
	}

	// Cycle 3: a useful finding arrives while the assurance is still
	// undelivered — same fenced transaction must supersede it.
	findingTr := osCycle(t, st, sitID, now.Add(2*time.Minute),
		shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseSettled,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true},
			Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment broke checkout", Findings: []string{"Errors began after deploy"}}}},
		true)

	assuranceInfo := osIntentDetail(t, st, sitID, assuranceTr.Sequence)
	if assuranceInfo.Status != "superseded" {
		t.Fatalf("assurance reply status after the finding = %s, want superseded", assuranceInfo.Status)
	}
	if assuranceInfo.Reason != "superseded_by_finding" {
		t.Fatalf("supersession_reason = %q, want superseded_by_finding", assuranceInfo.Reason)
	}
	findingInfo := osIntentDetail(t, st, sitID, findingTr.Sequence)
	if findingInfo.Status != "pending" {
		t.Fatalf("the finding's own reply status = %s, want pending", findingInfo.Status)
	}
	if assuranceInfo.Replacement != findingInfo.ID {
		t.Fatalf("replacement_intent_id = %q, want the finding's own reply id %q", assuranceInfo.Replacement, findingInfo.ID)
	}

	assertNoForeignKeyViolations(context.Background(), t, st)
}

// TestObsoleteStartAssuranceNeverSupersedesADeliveredReply pins ADR 0042/
// 0052: once the assurance actually delivered, it is material history and
// must never be touched, even when a later finding arrives.
func TestObsoleteStartAssuranceNeverSupersedesADeliveredReply(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-delivered", now)

	osCycle(t, st, sitID, now,
		osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)
	assuranceTr := osCycle(t, st, sitID, now.Add(time.Minute),
		shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true}},
		true)

	// Mark the assurance reply DELIVERED before the finding arrives.
	var assuranceID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM notification_intents WHERE situation_id = ? AND transition_sequence = ? AND effect_class = 'thread_append'`,
		sitID, assuranceTr.Sequence).Scan(&assuranceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', delivered_as = 'thread', channel = 'C', message_ts = 'ts', delivered_at = ?
		WHERE id = ?`, canonicalTime(now.Add(90*time.Second)), assuranceID); err != nil {
		t.Fatal(err)
	}

	osCycle(t, st, sitID, now.Add(2*time.Minute),
		shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseSettled,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true},
			Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment broke checkout", Findings: []string{"Errors began after deploy"}}}},
		true)

	if info := osIntentDetail(t, st, sitID, assuranceTr.Sequence); info.Status != "delivered" {
		t.Fatalf("a DELIVERED assurance reply must stay delivered, got %s", info.Status)
	}
	assertNoForeignKeyViolations(ctx, t, st)
}

// TestObsoleteStartAssuranceSupersededByTerminalEnd covers the second
// overtaking kind §5.3 names: a terminal end (here closed_unknown) must
// supersede a still-live assurance the same way a finding does, with its
// own distinct supersession_reason.
func TestObsoleteStartAssuranceSupersededByTerminalEnd(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-terminal", now)

	osCycle(t, st, sitID, now,
		osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)
	assuranceTr := osCycle(t, st, sitID, now.Add(time.Minute),
		shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true}},
		true)

	terminalTr := osCycle(t, st, sitID, now.Add(2*time.Minute),
		osTerminalContract(), model.LifecycleClosedUnknown,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseSettled,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true}},
		true)

	assuranceInfo := osIntentDetail(t, st, sitID, assuranceTr.Sequence)
	if assuranceInfo.Status != "superseded" {
		t.Fatalf("assurance reply status after the terminal end = %s, want superseded", assuranceInfo.Status)
	}
	if assuranceInfo.Reason != "superseded_by_terminal_end" {
		t.Fatalf("supersession_reason = %q, want superseded_by_terminal_end", assuranceInfo.Reason)
	}
	terminalInfo := osIntentDetail(t, st, sitID, terminalTr.Sequence)
	if assuranceInfo.Replacement != terminalInfo.ID {
		t.Fatalf("replacement_intent_id = %q, want the terminal end's own reply id %q", assuranceInfo.Replacement, terminalInfo.ID)
	}
	assertNoForeignKeyViolations(context.Background(), t, st)
}

// TestObsoleteStartAssuranceClaimedThenSupersededIsAnUncertainSend pins
// ADR 0049: a worker may have already CLAIMED the assurance reply (a real
// attempt is in flight, its outcome possibly uncertain — Slack may have
// already accepted it) when a later commit supersedes it. The row still
// becomes superseded under that live claim token exactly like a root_sync
// does (supersedeLiveRootSyncTx's own documented case), so the eventual
// acknowledgement resolves to ErrNotificationIntentSuperseded — never a
// silent overwrite, and never a second reply for the same content. A rare
// duplicate delivery already accepted by Slack is the accepted external
// at-least-once artifact this store never claims to prevent.
func TestObsoleteStartAssuranceClaimedThenSupersededIsAnUncertainSend(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "obsolete-start-claimed", now)

	osCycle(t, st, sitID, now,
		osMonitoringContract(now.Add(time.Minute)), model.LifecycleActive, &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}, false)
	// Deliver the root so the assurance reply becomes claimable.
	rootClaim := snClaimOne(t, st, now)
	if rootClaim.Intent.EffectClass != model.EffectRootSync {
		t.Fatalf("first claim = %s, want root_sync", rootClaim.Intent.EffectClass)
	}
	snDeliver(t, st, rootClaim, "100.1", now.Add(time.Second))

	assuranceTr := osCycle(t, st, sitID, now.Add(time.Minute),
		shRunningTriageContract(now.Add(2*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true}},
		true)

	// Root edits are always claimed ahead of a reply for the same Situation
	// (root-before-reply ordering); deliver cycle 2's own root edit first so
	// the assurance reply beneath it becomes claimable.
	rootEditClaim := snClaimOne(t, st, now.Add(80*time.Second))
	if rootEditClaim.Intent.EffectClass != model.EffectRootSync {
		t.Fatalf("root-edit claim = %s, want root_sync", rootEditClaim.Intent.EffectClass)
	}
	snDeliver(t, st, rootEditClaim, "100.1", now.Add(85*time.Second))

	// A worker claims the assurance reply — an attempt is now live.
	assuranceClaim := snClaimOne(t, st, now.Add(90*time.Second))
	if assuranceClaim.Intent.EffectClass != model.EffectThreadAppend {
		t.Fatalf("second claim = %s, want thread_append", assuranceClaim.Intent.EffectClass)
	}
	if assuranceClaim.Intent.TransitionID == nil || *assuranceClaim.Intent.TransitionID != assuranceTr.ID {
		t.Fatalf("claimed the wrong intent: %+v", assuranceClaim.Intent)
	}

	// The finding arrives WHILE that claim is still live and supersedes it.
	osCycle(t, st, sitID, now.Add(2*time.Minute),
		shRunningTriageContract(now.Add(3*time.Minute)),
		model.LifecycleActive,
		&model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
			Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseSettled,
				InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"a"}, InvestigatedCount: 1, InvestigatedCountKnown: true},
			Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment broke checkout", Findings: []string{"Errors began after deploy"}}}},
		true)

	// Slack had already accepted the claimed attempt (an uncertain send):
	// acknowledging it now must resolve to superseded, never silently
	// succeed or post a second reply.
	err := st.MarkNotificationDelivered(ctx, assuranceClaim,
		situation.NotificationDelivery{Channel: "C-sit", MessageTS: "200.1", DeliveredAs: "thread"}, now.Add(3*time.Minute))
	if !errors.Is(err, ErrNotificationIntentSuperseded) {
		t.Fatalf("ack of a claimed-then-superseded assurance = %v, want ErrNotificationIntentSuperseded", err)
	}
	if got := snIntent(t, st, assuranceClaim.Intent.ID).Status; got != model.IntentSuperseded {
		t.Fatalf("claimed assurance row status = %s, want superseded (never delivered)", got)
	}
	assertNoForeignKeyViolations(ctx, t, st)
}
