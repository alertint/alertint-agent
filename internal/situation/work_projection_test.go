// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B2 — S1-05, S2-01, S2-02, S2-03, S2-07: aggregate work projection.
//
// wpNow anchors every fixture below to one fixed instant so relative
// due/retry times are readable without re-deriving a clock per test.
// ----------------------------------------------------------------------

func wpNow(t *testing.T) time.Time {
	t.Helper()
	return mustTime(t, "2026-09-08T12:00:00Z")
}

func wpIncident(id, phase string, attempts int, nextAt *time.Time, reason *string) IncidentState {
	return IncidentState{
		ID:     id,
		Status: "ready",
		Triage: TriageState{Phase: phase, Attempts: attempts, NextAt: nextAt, DecisionReason: reason},
	}
}

// ----------------------------------------------------------------------
// S2-02: "Retry due ≠ status checkpoint" — a request REFRESH on an
// already-decided pending/backoff row must never re-project it as a fresh
// "due now" promotion, and a committed skip must never still project as
// outstanding awaiting-decision work.
// ----------------------------------------------------------------------

func TestAggregateTriagePhaseRefreshPreservesBackoffPhaseAndDue(t *testing.T) {
	// Plan 3 form of the preserved diagnostic probe
	// (evaluation/plan3-situation_test.go: refresh_preserves_backoff_phase_and_due).
	now := wpNow(t)
	due := now.Add(2 * time.Minute)
	inc := []IncidentState{wpIncident("i", "backoff", 3, &due, nil)}
	ds := []TriageDecision{{IncidentID: "i", Decision: TriageDecisionRequest}}

	gotPhase, gotDue := aggregateTriagePhase(inc, ds), earliestTriageDue(inc, ds, now)
	if gotPhase != TriagePhaseBackoff {
		t.Fatalf("aggregateTriagePhase = %v, want TriagePhaseBackoff — a refresh must not force a backoff row back to pending", gotPhase)
	}
	if gotDue == nil || !gotDue.Equal(due) {
		t.Fatalf("earliestTriageDue = %v, want the persisted backoff due %s (a refresh must not override it with now)", gotDue, due)
	}
}

func TestAggregateTriagePhaseCommittedSkipRemovesOutstandingWork(t *testing.T) {
	// Plan 3 form of the preserved diagnostic probe
	// (evaluation/plan3-situation_test.go: committed_skip_removes_outstanding_work).
	inc := []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}
	ds := []TriageDecision{{IncidentID: "i", Decision: TriageDecisionSkip}}

	if got := aggregateTriagePhase(inc, ds); got != TriagePhaseNone {
		t.Fatalf("aggregateTriagePhase = %v, want TriagePhaseNone — a committed skip must not still read as awaiting-decision work", got)
	}
	if got := earliestTriageDue(inc, ds, wpNow(t)); got != nil {
		t.Fatalf("earliestTriageDue = %v, want nil — a skipped schedule has no outstanding due time", got)
	}
}

func TestAggregateTriagePhaseFreshRequestIsDueNow(t *testing.T) {
	// Regression guard: a genuine first promotion (awaiting_decision ->
	// pending) must still project as due immediately — only a REFRESH on an
	// already-pending/backoff row is exempt.
	now := wpNow(t)
	inc := []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}
	ds := []TriageDecision{{IncidentID: "i", Decision: TriageDecisionRequest}}

	if got := aggregateTriagePhase(inc, ds); got != TriagePhaseAwaitingDecision {
		t.Fatalf("aggregateTriagePhase = %v, want TriagePhaseAwaitingDecision", got)
	}
	gotDue := earliestTriageDue(inc, ds, now)
	if gotDue == nil || !gotDue.Equal(now) {
		t.Fatalf("earliestTriageDue = %v, want now (%s) for a fresh promotion", gotDue, now)
	}
}

// ----------------------------------------------------------------------
// S2-01: "Queued · not yet executing" — distinguish collecting, decision,
// queue, actual execution, retry wait and no outstanding work using
// recorded facts; never infer execution from a request.
// ----------------------------------------------------------------------

func TestBuildWorkProjectionQueuedIsNotExecuting(t *testing.T) {
	// Plan 3 form of the preserved diagnostic probe
	// (evaluation/plan3-situation_test.go / situation_test.go:
	// queued_before_any_execution_is_observed), expressed against the new
	// WorkProjection instead of the retired ActionContract-sniffing path.
	inc := []IncidentState{wpIncident("i", "pending", 0, nil, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseQueued {
		t.Fatalf("Phase = %v, want WorkPhaseQueued", got.Phase)
	}
	if got.ExecutionStarted {
		t.Fatal("ExecutionStarted = true for a queued request that was never claimed")
	}
}

func TestBuildWorkProjectionAwaitingDecisionIsNotExecuting(t *testing.T) {
	inc := []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseAwaitingDecision {
		t.Fatalf("Phase = %v, want WorkPhaseAwaitingDecision", got.Phase)
	}
	if got.ExecutionStarted {
		t.Fatal("ExecutionStarted = true before any decision was even made")
	}
}

func TestBuildWorkProjectionRunningIsExecuting(t *testing.T) {
	inc := []IncidentState{wpIncident("i", "in_flight", 1, nil, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseExecuting {
		t.Fatalf("Phase = %v, want WorkPhaseExecuting", got.Phase)
	}
	if !got.ExecutionStarted {
		t.Fatal("ExecutionStarted = false for a claimed, in-flight attempt")
	}
}

// TestBuildWorkProjectionMixedIncidentsAggregateToExecuting is the
// "exhausted-other-running" canonical Slack example (2026-09-07 state map,
// slide 4): one exhausted schedule plus one currently running schedule must
// still aggregate to Investigating, not settle into Monitoring merely
// because one incident's own schedule is done.
func TestBuildWorkProjectionMixedIncidentsAggregateToExecuting(t *testing.T) {
	inc := []IncidentState{
		wpIncident("exhausted-1", "exhausted", 5, nil, nil),
		wpIncident("running-1", "in_flight", 1, nil, nil),
	}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseExecuting {
		t.Fatalf("Phase = %v, want WorkPhaseExecuting — a sibling still running must dominate an already-exhausted schedule", got.Phase)
	}
	if !got.ExecutionStarted {
		t.Fatal("ExecutionStarted = false with a claimed attempt among the incidents")
	}
	if got.RemainingIncidents != 1 {
		t.Fatalf("RemainingIncidents = %d, want 1 (only running-1 still has outstanding work)", got.RemainingIncidents)
	}
}

// ----------------------------------------------------------------------
// S2-07: "Exhausted · visible end of analysis" — truthful inability and
// retry eligibility; analysis ending is independent of source monitoring.
// ----------------------------------------------------------------------

func TestBuildWorkProjectionExhaustedHasNoRetryEligibility(t *testing.T) {
	inc := []IncidentState{wpIncident("i", "exhausted", 5, nil, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseExhausted {
		t.Fatalf("Phase = %v, want WorkPhaseExhausted", got.Phase)
	}
	if got.RetryEligibleAt != nil {
		t.Fatalf("RetryEligibleAt = %v, want nil — an exhausted schedule has no automatic retry", got.RetryEligibleAt)
	}
	if got.RemainingIncidents != 0 {
		t.Fatalf("RemainingIncidents = %d, want 0 — exhausted is not outstanding work", got.RemainingIncidents)
	}
}

func TestBuildWorkProjectionCompletionWithoutUsefulFindingStaysExhausted(t *testing.T) {
	// "Completion without useful finding" (traceability.json S2-07 test):
	// an incident that ran to its final failure, with a sibling that never
	// executed, must not read as if the exhausted schedule alone settles
	// the whole Situation into Monitoring while real undecided work remains.
	due := wpNow(t)
	inc := []IncidentState{
		wpIncident("exhausted-1", "exhausted", 5, nil, nil),
		wpIncident("fresh-1", "awaiting_decision", 0, nil, nil),
	}
	got := BuildWorkProjection(inc, nil, &due)
	if got.Phase != model.WorkPhaseAwaitingDecision {
		t.Fatalf("Phase = %v, want WorkPhaseAwaitingDecision — a genuinely undecided sibling outranks an already-exhausted one", got.Phase)
	}
	if got.StatusCheckpointAt == nil || !got.StatusCheckpointAt.Equal(due) {
		t.Fatalf("StatusCheckpointAt = %v, want the threaded-through Operator contract checkpoint %s", got.StatusCheckpointAt, due)
	}
}

// TestBuildWorkProjectionAnalyzedIncidentWithoutScheduleIsSettled is R1
// (lead review 2026-09-09): a successful completion DELETES the
// incident_triage row (triage_controller.go completeSuccessTx), so a bare
// Phase=="" must not read identically to "never reached ready" — the
// Incident's own durable Status distinguishes them. ExecutionStarted must
// also survive the Attempts counter resetting to 0 once that row is gone,
// via LastExecution.
func TestBuildWorkProjectionAnalyzedIncidentWithoutScheduleIsSettled(t *testing.T) {
	started := wpNow(t)
	inc := []IncidentState{{
		ID:     "i",
		Status: "analyzed",
		Triage: TriageState{
			Phase:         "",
			Attempts:      0,
			LastExecution: &TriageExecution{AttemptID: "a1", AttemptNumber: 1, StartedAt: started, MemberDeliveryIDs: []string{"d1"}},
		},
	}}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseSettled {
		t.Fatalf("Phase = %v, want WorkPhaseSettled — an analyzed Incident with a closed schedule is settled work, not collecting", got.Phase)
	}
	if !got.ExecutionStarted {
		t.Fatal("ExecutionStarted = false, want true — LastExecution proves a real attempt ran even though Attempts reset to 0")
	}
	if got.RemainingIncidents != 0 {
		t.Fatalf("RemainingIncidents = %d, want 0", got.RemainingIncidents)
	}
}

// TestBuildWorkProjectionCollectingIncidentNeverReachedReadyStaysCollecting
// is the negative control: Phase=="" with no LastExecution and a Status
// that never reached "analyzed" is genuinely still collecting, not settled.
func TestBuildWorkProjectionCollectingIncidentNeverReachedReadyStaysCollecting(t *testing.T) {
	inc := []IncidentState{{ID: "i", Status: "collecting", Triage: TriageState{Phase: ""}}}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseCollecting {
		t.Fatalf("Phase = %v, want WorkPhaseCollecting", got.Phase)
	}
	if got.ExecutionStarted {
		t.Fatal("ExecutionStarted = true, want false — nothing has ever executed here")
	}
}

// ----------------------------------------------------------------------
// S2-03: "Prior coverage OR eligibility policy" — coverage reuse and
// eligibility/minimum-members skip retain distinct actual reasons.
// ----------------------------------------------------------------------

func TestBuildWorkProjectionSkipReasonPriorCoverage(t *testing.T) {
	reason := DecisionReasonCleanSkip
	inc := []IncidentState{wpIncident("i", "skipped", 0, nil, &reason)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.Phase != model.WorkPhaseSettled {
		t.Fatalf("Phase = %v, want WorkPhaseSettled", got.Phase)
	}
	if got.SkipReason != "prior_coverage" {
		t.Fatalf("SkipReason = %q, want %q", got.SkipReason, "prior_coverage")
	}
}

func TestBuildWorkProjectionSkipReasonEligibilityPolicy(t *testing.T) {
	reason := DecisionReasonEligibilityPolicyMinimumMembers
	inc := []IncidentState{wpIncident("i", "skipped", 0, nil, &reason)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.SkipReason != "eligibility_policy" {
		t.Fatalf("SkipReason = %q, want %q — a policy skip must not read as coverage reuse", got.SkipReason, "eligibility_policy")
	}
}

// TestCommittedBriefingInputDoesNotKeepAnOldRequestReasonUnderANewSkip is
// plan.md checklist item 4's exact scenario: an incident that was
// awaiting_decision (no reason recorded yet) is decided SKIP this cycle;
// the presentation copy must carry THIS cycle's skip reason, never a stale
// or empty one left over from the raw pre-commit read.
func TestCommittedBriefingInputDoesNotKeepAnOldRequestReasonUnderANewSkip(t *testing.T) {
	in := SnapshotInput{Incidents: []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}}
	reason := DecisionReasonEligibilityPolicyMinimumMembers
	decisions := []TriageDecision{{IncidentID: "i", Decision: TriageDecisionSkip, DecisionReason: reason}}

	got := committedBriefingInput(in, decisions)
	tr := got.Incidents[0].Triage
	if tr.Phase != "skipped" {
		t.Fatalf("Phase = %q, want skipped", tr.Phase)
	}
	if tr.DecisionReason == nil || *tr.DecisionReason != reason {
		t.Fatalf("DecisionReason = %v, want %q", tr.DecisionReason, reason)
	}
	if tr.SkipReason != "eligibility_policy" {
		t.Fatalf("SkipReason = %q, want %q", tr.SkipReason, "eligibility_policy")
	}
}

// ----------------------------------------------------------------------
// R3 (lead review 2026-09-09): the committed Assessment-level retry
// (situations.retry_at, ControllerCommit.RetryAt — contract §3's "next_at /
// retry_at") must reach WorkProjection.RetryEligibleAt, truthfully distinct
// from a per-incident Triage backoff and from a status checkpoint.
// BuildWorkProjection's own 3-parameter shape is a pinned external test
// boundary, so committedOperatorBriefing carries it instead — see its own
// doc comment.
// ----------------------------------------------------------------------

func TestCommittedOperatorBriefingProjectsAssessmentRetryEvenWithoutTriageBackoff(t *testing.T) {
	due := wpNow(t).Add(time.Minute)
	commit := ControllerCommit{Lifecycle: model.LifecycleActive, RetryAt: &due}
	b := CommittedOperatorBriefing(SnapshotInput{}, commit)
	if b.Work.RetryEligibleAt == nil || !b.Work.RetryEligibleAt.Equal(due) {
		t.Fatalf("RetryEligibleAt = %v, want the committed Assessment retry %s", b.Work.RetryEligibleAt, due)
	}
}

func TestCommittedOperatorBriefingRetryEligibleAtIsTheEarlierOfTriageBackoffAndAssessmentRetry(t *testing.T) {
	now := wpNow(t)
	triageBackoff := now.Add(30 * time.Minute)
	assessmentRetry := now.Add(5 * time.Minute)
	in := SnapshotInput{Incidents: []IncidentState{wpIncident("i", "backoff", 1, &triageBackoff, nil)}}
	commit := ControllerCommit{Lifecycle: model.LifecycleActive, RetryAt: &assessmentRetry}
	b := CommittedOperatorBriefing(in, commit)
	if b.Work.RetryEligibleAt == nil || !b.Work.RetryEligibleAt.Equal(assessmentRetry) {
		t.Fatalf("RetryEligibleAt = %v, want the earlier assessment retry %s — a later triage backoff must not shadow it", b.Work.RetryEligibleAt, assessmentRetry)
	}
}

func TestCommittedOperatorBriefingRetryEligibleAtPrefersEarlierTriageBackoffOverLaterAssessmentRetry(t *testing.T) {
	now := wpNow(t)
	triageBackoff := now.Add(2 * time.Minute)
	assessmentRetry := now.Add(30 * time.Minute)
	in := SnapshotInput{Incidents: []IncidentState{wpIncident("i", "backoff", 1, &triageBackoff, nil)}}
	commit := ControllerCommit{Lifecycle: model.LifecycleActive, RetryAt: &assessmentRetry}
	b := CommittedOperatorBriefing(in, commit)
	if b.Work.RetryEligibleAt == nil || !b.Work.RetryEligibleAt.Equal(triageBackoff) {
		t.Fatalf("RetryEligibleAt = %v, want the earlier triage backoff %s — a later assessment retry must not shadow it", b.Work.RetryEligibleAt, triageBackoff)
	}
}

// ----------------------------------------------------------------------
// S1-05: lifecycle and per-Incident work coexist; A dispatch and B feedback
// are not lifecycle transitions, and Slack delivery cannot hold lifecycle
// progress.
// ----------------------------------------------------------------------

// TestDeriveOrientationAllClearWhilstWorkStillRuns is the "all-clear while
// work runs" S1-05 scenario: spec.md's accepted contract orders terminal,
// then Confirming recovery, then actual aggregate work — recovery grace
// must win even while an investigation genuinely still has outstanding work.
func TestDeriveOrientationAllClearWhilstWorkStillRuns(t *testing.T) {
	tr := model.Transition{
		Lifecycle: model.LifecycleRecoveryPending,
		Projection: model.ProjectionFacts{
			Briefing: &model.OperatorBriefing{Work: model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true}},
		},
	}
	if got := DeriveOrientation(model.EpisodeSummary{}, tr); got != OrientationConfirmingRecovery {
		t.Fatalf("orientation = %q, want %q — recovery grace must not be hidden by still-running work", got, OrientationConfirmingRecovery)
	}
}

// TestDeriveOrientationIsPureOfDeliveryHistory is the "delayed first root"
// S1-05 scenario: DeriveOrientation must read the CURRENT committed
// Lifecycle/Work alone, never publication/sequence history, so a delayed
// first root can never hold orientation at an earlier phase than the
// current truth.
func TestDeriveOrientationIsPureOfDeliveryHistory(t *testing.T) {
	tr := model.Transition{
		Sequence:  1, // this would be the very first, not-yet-delivered root
		Lifecycle: model.LifecycleActive,
		Projection: model.ProjectionFacts{
			Briefing: &model.OperatorBriefing{Work: model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true}},
		},
	}
	if got := DeriveOrientation(model.EpisodeSummary{}, tr); got != OrientationInvestigating {
		t.Fatalf("orientation = %q, want %q — a delayed first root must still show current truth, not Observed", got, OrientationInvestigating)
	}
}

func TestDeriveOrientationFromWorkProjection(t *testing.T) {
	active := func(w model.WorkProjection) model.Transition {
		return model.Transition{
			Lifecycle:  model.LifecycleActive,
			Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Work: w}},
		}
	}
	cases := []struct {
		name string
		work model.WorkProjection
		want Orientation
	}{
		{"queued before any execution", model.WorkProjection{Phase: model.WorkPhaseQueued, ExecutionStarted: false}, OrientationObserved},
		{"awaiting decision", model.WorkProjection{Phase: model.WorkPhaseAwaitingDecision}, OrientationObserved},
		// R2 repair (lead review 2026-09-09): a stale completion can restore
		// awaiting_decision while attempts remain spent (completeStaleTx), or
		// a sibling Incident in this Situation may already have executed —
		// either way outstanding work after execution began is still
		// Investigating, never Observed.
		{"awaiting decision after execution began", model.WorkProjection{Phase: model.WorkPhaseAwaitingDecision, ExecutionStarted: true}, OrientationInvestigating},
		{"executing", model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true}, OrientationInvestigating},
		{"retry wait", model.WorkProjection{Phase: model.WorkPhaseRetryWait, ExecutionStarted: true}, OrientationInvestigating},
		{"settled skip, no execution", model.WorkProjection{Phase: model.WorkPhaseSettled}, OrientationMonitoring},
		{"exhausted", model.WorkProjection{Phase: model.WorkPhaseExhausted, ExecutionStarted: true}, OrientationMonitoring},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveOrientation(model.EpisodeSummary{}, active(c.work)); got != c.want {
				t.Fatalf("orientation = %q, want %q", got, c.want)
			}
		})
	}
}

// ----------------------------------------------------------------------
// G1 (lead final review 2026-09-10): "Queued analysis, with a known
// readiness/due time or actual waiting reason." A queued schedule's
// incident_triage.next_at IS its recorded eligibility — the moment a worker
// may claim it — and the projection carried only the retry_wait reading of
// that column, so the queued activity line had nothing to state.
// ----------------------------------------------------------------------

func TestBuildWorkProjectionQueuedCarriesItsRecordedEligibility(t *testing.T) {
	now := wpNow(t)
	early := now.Add(30 * time.Second)
	late := now.Add(5 * time.Minute)
	inc := []IncidentState{
		wpIncident("later", "pending", 0, &late, nil),
		wpIncident("earlier", "pending", 0, &early, nil),
	}
	got := BuildWorkProjection(inc, nil, nil)
	if !got.QueuedEligibilityKnown {
		t.Fatal("QueuedEligibilityKnown = false on a projection this build produced")
	}
	if got.QueuedEligibleAt == nil || !got.QueuedEligibleAt.Equal(early) {
		t.Fatalf("QueuedEligibleAt = %v, want the earliest queued eligibility %s", got.QueuedEligibleAt, early)
	}
	if got.RetryEligibleAt != nil {
		t.Fatalf("RetryEligibleAt = %v, want nil — a queued schedule is not a retry", got.RetryEligibleAt)
	}
}

// A retry_wait schedule's next_at is a RETRY time. The two eligibilities are
// different facts about different states and neither may be read as the
// other (S4-08: "retry eligibility is not an execution ETA").
func TestBuildWorkProjectionRetryWaitIsNotQueuedEligibility(t *testing.T) {
	now := wpNow(t)
	retry := now.Add(4 * time.Minute)
	inc := []IncidentState{wpIncident("i", "backoff", 2, &retry, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.QueuedEligibleAt != nil {
		t.Fatalf("QueuedEligibleAt = %v, want nil — a backoff schedule is waiting on a retry, not a claim", got.QueuedEligibleAt)
	}
	if got.RetryEligibleAt == nil || !got.RetryEligibleAt.Equal(retry) {
		t.Fatalf("RetryEligibleAt = %v, want %s", got.RetryEligibleAt, retry)
	}
	if !got.QueuedEligibilityKnown {
		t.Fatal("QueuedEligibilityKnown = false — the field is recorded even when nothing is queued")
	}
}

// An undecided schedule has no readiness time to record: that absence is the
// waiting reason, not a missing fact.
func TestBuildWorkProjectionAwaitingDecisionHasNoQueuedEligibility(t *testing.T) {
	inc := []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}
	got := BuildWorkProjection(inc, nil, nil)
	if got.QueuedEligibleAt != nil {
		t.Fatalf("QueuedEligibleAt = %v, want nil before any decision is committed", got.QueuedEligibleAt)
	}
	if !got.QueuedEligibilityKnown {
		t.Fatal("QueuedEligibilityKnown = false on a projection this build produced")
	}
}

// TestCommittedBriefingInputCarriesTheRequestedEligibility pins the
// presentation overlay against the durable write it copies: the same commit
// that moves a schedule from awaiting_decision to pending stamps its next_at
// with this cycle's instant, so the projection must not report "no readiness
// time" for a schedule the transaction is recording one for.
func TestCommittedBriefingInputCarriesTheRequestedEligibility(t *testing.T) {
	now := wpNow(t)
	in := SnapshotInput{Incidents: []IncidentState{wpIncident("i", "awaiting_decision", 0, nil, nil)}}
	ds := []TriageDecision{{IncidentID: "i", Decision: TriageDecisionRequest, DecisionReason: "new_work", DecidedAt: now}}

	committed := committedBriefingInput(in, ds)
	if got := committed.Incidents[0].Triage.Phase; got != "pending" {
		t.Fatalf("overlaid phase = %q, want pending", got)
	}
	at := committed.Incidents[0].Triage.NextAt
	if at == nil || !at.Equal(now) {
		t.Fatalf("overlaid NextAt = %v, want this cycle's instant %s — the same value applyRequestFromAwaitingDecisionTx writes", at, now)
	}
	w := BuildWorkProjection(committed.Incidents, nil, nil)
	if w.QueuedEligibleAt == nil || !w.QueuedEligibleAt.Equal(now) {
		t.Fatalf("QueuedEligibleAt = %v, want %s", w.QueuedEligibleAt, now)
	}
	// A refresh on an already-pending row keeps its own recorded time: the
	// overlay must never restamp it (S2-02).
	persisted := now.Add(-3 * time.Minute)
	in2 := SnapshotInput{Incidents: []IncidentState{wpIncident("i", "pending", 0, &persisted, nil)}}
	committed2 := committedBriefingInput(in2, []TriageDecision{{IncidentID: "i", Decision: TriageDecisionRequest, DecidedAt: now}})
	if at := committed2.Incidents[0].Triage.NextAt; at == nil || !at.Equal(persisted) {
		t.Fatalf("refreshed NextAt = %v, want the persisted %s", at, persisted)
	}
}
