// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B4 repair regressions — lead review 2026-09-09 (R1–R4).
//
// R1: candidate facts must render independently of the legacy delta
// booleans and of the bounded Analyses overview.
// R2: the root must state the ACTUAL recorded investigation input
// (canonical slide 4 "first-root-running": "Investigating [recorded count]
// alerts for [recorded scope]: [alert names]"; row 576: "Count the actual
// investigation inputs, not every Situation member").
// R3: "Confirming recovery" must disclose still-outstanding execution and
// its own timing (canonical "recovery-with-work").
// R4: an operator Action is rendered only from a RECORDED request or its
// explicit withdrawal (canonical "Add a concrete Action: only when the
// operator contract requires one"; "action-required"/"action-withdrawn").
// ----------------------------------------------------------------------

func bcNow(t *testing.T) time.Time {
	t.Helper()
	return rsMustTime(t, "2026-09-09T10:00:00Z")
}

func bcBriefing() *model.OperatorBriefing {
	return &model.OperatorBriefing{Scope: "checkout", Firing: 3, Total: 4}
}

// bcRoot builds a coherent root input around one contract and briefing.
func bcRoot(t *testing.T, lifecycle model.Lifecycle, attention model.Attention,
	c model.ActionContract, b *model.OperatorBriefing) SituationRootInput {
	t.Helper()
	now := bcNow(t)
	sum := rsSummary(1, "Checkout errors", attention, c, now.Add(-time.Hour), now)
	tr := rsTransition(1, lifecycle, attention, c, model.ReasonFirstAuthoritativeState,
		model.JournalEvidenceConclusion, model.JournalData{Headline: "Update", OccurredAt: now},
		rsProjection(now.Add(-time.Hour), rsAssessment(model.CausalityUnknown, model.ImpactNoneObserved)), now)
	sum.Briefing, tr.Projection.Briefing = b, b
	deadline := c.NextUpdateAt
	if lifecycle.Terminal() {
		// A terminal Situation carries its own end instant and no contract
		// deadline at all (model.ActionContract's terminal shape rule).
		terminalAt := now
		sum.TerminalAt, tr.Projection.TerminalAt = &terminalAt, &terminalAt
		sum.FinalOutcome = "Tracking ended without confirmed recovery"
		deadline = nil
	}
	return SituationRootInput{Summary: sum, SourceTransition: tr, ContractDeadlineAt: deadline, Now: now}
}

// bcJournal builds an Active journal-carrying transition around one
// briefing and delta. Lifecycle-edge journals (recovery, terminal end) go
// through bcRoot's transition instead, which carries their own instants.
func bcJournal(t *testing.T, c model.ActionContract,
	b *model.OperatorBriefing, d *model.OperatorDelta) model.Transition {
	t.Helper()
	now := bcNow(t)
	tr := rsTransition(1, model.LifecycleActive, model.AttentionObserve, c, model.ReasonFirstAuthoritativeState,
		model.JournalEvidenceConclusion, model.JournalData{Headline: "Update", OccurredAt: now},
		rsProjection(now.Add(-time.Hour), rsAssessment(model.CausalityUnknown, model.ImpactNoneObserved)), now)
	tr.Projection.Briefing, tr.Projection.OperatorDelta = b, d
	return tr
}

// bcBothSurfaces asserts a fact reaches the plain-text fallback AND the
// Block Kit body — a candidate rendered into only one surface is still lost
// to half the operators who receive it.
func bcBothSurfaces(t *testing.T, msg RenderedMessage, want ...string) {
	t.Helper()
	blocks := rsFallbackBlocksText(msg)
	for _, w := range want {
		if !strings.Contains(msg.Text, w) {
			t.Errorf("fallback text lost %q:\n%s", w, msg.Text)
		}
		if !strings.Contains(blocks, w) {
			t.Errorf("block kit lost %q:\n%s", w, blocks)
		}
	}
}

func bcObserveMonitorContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusWaiting
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   rsTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
}

// ----------------------------------------------------------------------
// R1 — candidate facts render independently of the legacy flags.
// ----------------------------------------------------------------------

// A useful finding whose Incident sits outside the bounded three-entry
// overview reaches materiality as a candidate only. Rendering nothing for
// it drops the whole finding (S4-04, canonical "evidence-map"/"reply").
func TestJournalRendersCandidateOnlyUsefulFinding(t *testing.T) {
	now := bcNow(t)
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind: model.CandidateUsefulFinding,
		Finding: &model.FindingFacts{
			IncidentID:   "incident-outside-overview",
			Hypothesis:   "Deployment rollout exhausted the connection pool",
			Observations: []string{"Pod events checked", "Application errors checked"},
			Unknowns:     []string{"Upstream latency metrics unavailable"},
			AnalyzedAt:   rsTimePtr(now),
		},
		Next: model.NextStepFacts{Kind: model.NextStepWorkEnded},
	}}}
	tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)

	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg,
		"Deployment rollout exhausted the connection pool",
		"Pod events checked",
		"Application errors checked",
		"Upstream latency metrics unavailable",
	)
}

// The same fact through the completion path: an inconclusive completion is
// a candidate with no legacy AnalysisFailed flag behind it (S4-05).
func TestJournalRendersCandidateOnlyInconclusiveCompletion(t *testing.T) {
	now := bcNow(t)
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind: model.CandidateInconclusiveCompletion,
		Finding: &model.FindingFacts{
			IncidentID:   "incident-inconclusive",
			Observations: []string{"Pod events checked", "Application errors checked"},
			Unknowns:     []string{"Database saturation could not be measured"},
		},
		Outcome: &model.IncidentWorkOutcome{IncidentID: "incident-inconclusive", AttemptID: "attempt-7",
			Phase: model.WorkPhaseSettled, ResultCode: "success", EvidenceKnown: true},
		Next: model.NextStepFacts{Kind: model.NextStepWorkEnded},
	}}}
	tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)

	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg,
		"Investigation inconclusive",
		"Pod events checked",
		"Database saturation could not be measured",
		"No further analysis retry is scheduled",
	)
}

// Both forms of the same Incident's evidence must not print twice: the
// overview entry already carries it (lead review R1: "avoid duplicate
// content when both forms are present").
func TestJournalDoesNotDuplicateFindingCarriedByBothForms(t *testing.T) {
	now := bcNow(t)
	analysis := model.IncidentAnalysis{
		IncidentID: "incident-in-overview",
		Summary:    "Deployment rollout exhausted the connection pool",
		Findings:   []string{"Pod events checked"},
	}
	d := &model.OperatorDelta{
		Analyses: []model.IncidentAnalysis{analysis},
		Candidates: []model.MaterialCandidate{{
			Kind: model.CandidateUsefulFinding,
			Finding: &model.FindingFacts{
				IncidentID:   "incident-in-overview",
				Hypothesis:   "Deployment rollout exhausted the connection pool",
				Observations: []string{"Pod events checked"},
			},
			Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))},
		}},
	}
	tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)

	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(msg.Text, "Pod events checked"); n != 1 {
		t.Errorf("observation rendered %d times, want exactly 1:\n%s", n, msg.Text)
	}
}

// A previously reported obstacle clearing has NO legacy delta boolean of
// its own (AbilityLost only ever marks a loss), so a candidate-only
// clearance disappeared entirely (canonical "capability-restored").
func TestJournalRendersAbilityChangeWithoutLegacyFlag(t *testing.T) {
	now := bcNow(t)
	for _, tc := range []struct {
		name    string
		cleared bool
		want    string
	}{
		{"lost", false, "could not be retrieved"},
		{"restored", true, "available again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind:       model.CandidateAbilityChanged,
				Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable, Cleared: tc.cleared},
				Next:       model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))},
			}}}
			tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)
			msg, err := RenderSituationJournal(tr)
			if err != nil {
				t.Fatal(err)
			}
			bcBothSurfaces(t, msg, tc.want)
		})
	}
}

// An action withdrawal arrives as a candidate; the legacy
// HumanRequestChanged boolean stays false when a delta was built without
// one (canonical "action-withdrawn").
func TestJournalRendersActionWithdrawalWithoutLegacyFlag(t *testing.T) {
	now := bcNow(t)
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind:   model.CandidateActionChanged,
		Action: &model.ActionFacts{Withdrawn: true, Action: model.OperatorActionInvestigateSituation},
		Next:   model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))},
	}}}
	tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)

	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "no longer needed")
}

// The first actual execution's assurance is a candidate too, and row 576
// requires the actual input count and recognizable names.
func TestJournalRendersFirstExecutionAssurance(t *testing.T) {
	now := bcNow(t)
	for _, tc := range []struct {
		name       string
		countKnown bool
		count      int
		want       []string
		absent     []string
	}{
		{"known count", true, 9, []string{"9 alerts", "PodCrashLooping", "LatencyP99"}, nil},
		{"unknown count", false, 0, []string{"PodCrashLooping", "LatencyP99"}, []string{"Investigating 2 alerts", "Investigating 4 alerts"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind: model.CandidateFirstExecutionAssurance,
				Members: &model.MemberFacts{
					NowFiring:   []string{"PodCrashLooping", "LatencyP99"},
					FiringCount: tc.count, CountKnown: tc.countKnown, Total: 4,
				},
				Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))},
			}}}
			c := rsRunningTriageContract(now.Add(time.Minute))
			tr := bcJournal(t, c, bcBriefing(), d)
			msg, err := RenderSituationJournal(tr)
			if err != nil {
				t.Fatal(err)
			}
			bcBothSurfaces(t, msg, tc.want...)
			for _, bad := range tc.absent {
				if strings.Contains(msg.Text, bad) {
					t.Errorf("unknown count fabricated %q:\n%s", bad, msg.Text)
				}
			}
		})
	}
}

// ----------------------------------------------------------------------
// R2 — the root states the actual execution scope.
// ----------------------------------------------------------------------

func TestRootRendersActualExecutionScope(t *testing.T) {
	now := bcNow(t)
	c := rsRunningTriageContract(now.Add(time.Minute))
	b := bcBriefing()
	b.Work = model.WorkProjection{
		Phase: model.WorkPhaseExecuting, ExecutionStarted: true,
		InvestigatedCount: 9, InvestigatedCountKnown: true,
		InvestigatedNames: []string{"PodCrashLooping", "LatencyP99"},
	}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, c, b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "9 alerts", "checkout", "PodCrashLooping", "LatencyP99")
}

// Missing count provenance stays unknown: neither the Situation total (4),
// the firing count (3) nor the bounded name-list length (2) may stand in
// for the investigated count.
func TestRootExecutionScopeKeepsUnknownCountUnknown(t *testing.T) {
	now := bcNow(t)
	c := rsRunningTriageContract(now.Add(time.Minute))
	b := bcBriefing()
	b.Work = model.WorkProjection{
		Phase: model.WorkPhaseExecuting, ExecutionStarted: true,
		InvestigatedNames: []string{"PodCrashLooping", "LatencyP99"},
	}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, c, b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "PodCrashLooping", "LatencyP99", "not recorded")
	// The alert-state line legitimately says "3/4 alerts firing", so the
	// guard is anchored to the investigation claim itself.
	for _, bad := range []string{"Investigating 2 alerts", "Investigating 3 alerts", "Investigating 4 alerts"} {
		if strings.Contains(msg.Text, bad) {
			t.Errorf("substituted %q for the unknown investigated count:\n%s", bad, msg.Text)
		}
	}
}

// ----------------------------------------------------------------------
// R3 — confirming recovery discloses outstanding execution.
// ----------------------------------------------------------------------

func TestRootRecoveryKeepsOutstandingWorkAndItsOwnTiming(t *testing.T) {
	now := bcNow(t)
	grace := now.Add(10 * time.Minute)
	c := rsMonitoringContract(now.Add(time.Minute))
	b := bcBriefing()
	b.Firing, b.Resolved = 0, 4
	b.Work = model.WorkProjection{
		Phase: model.WorkPhaseExecuting, ExecutionStarted: true,
		RemainingIncidents: 1, SourceGraceUntil: rsTimePtr(grace),
		StatusCheckpointAt: c.NextUpdateAt,
	}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, c, b))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(msg.Text)
	if !strings.Contains(lower, "investigation is still running") {
		t.Errorf("recovery confirmation hides outstanding execution:\n%s", msg.Text)
	}
	bcBothSurfaces(t, msg, "Watching for sustained recovery", SlackDateToken(grace, "{time}"), "Next status check")
	if SlackDateToken(grace, "{time}") == SlackDateToken(*c.NextUpdateAt, "{time}") {
		t.Fatal("fixture must keep the grace deadline and status checkpoint distinct")
	}
}

// ----------------------------------------------------------------------
// R4 — an Action is only ever a recorded request.
// ----------------------------------------------------------------------

func TestRootActionOnlyFromRecordedRequest(t *testing.T) {
	now := bcNow(t)
	investigate := model.OperatorActionInvestigateSituation
	blocked := model.AlertINTStatusBlocked
	triage := model.AlertINTActionRunAcuteTriage

	requested := bcObserveMonitorContract(now.Add(time.Minute))
	requested.OperatorActionRequired = &investigate
	requested.NextActor = model.NextActorOperator

	blockedContract := bcObserveMonitorContract(now.Add(time.Minute))
	blockedContract.AlertINTAction, blockedContract.AlertINTStatus = &triage, &blocked

	for _, tc := range []struct {
		name      string
		contract  model.ActionContract
		attention model.Attention
		wantReq   bool
	}{
		{"recorded request", requested, model.AttentionInvestigate, true},
		{"firing alerts alone", bcObserveMonitorContract(now.Add(time.Minute)), model.AttentionObserve, false},
		{"raised attention alone", bcObserveMonitorContract(now.Add(time.Minute)), model.AttentionUrgent, false},
		{"blocked automatic work alone", blockedContract, model.AttentionObserve, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, tc.attention, tc.contract, bcBriefing()))
			if err != nil {
				t.Fatal(err)
			}
			hasRequest := strings.Contains(msg.Text, "On-call: ")
			if hasRequest != tc.wantReq {
				t.Errorf("recorded request %v, rendered request %v:\n%s", tc.wantReq, hasRequest, msg.Text)
			}
			if !strings.Contains(msg.Text, "*Action:*") {
				t.Errorf("action line disappeared entirely:\n%s", msg.Text)
			}
		})
	}
}

// A withdrawal must correct the earlier request rather than silently
// dropping to a generic "none required" (canonical "action-withdrawn":
// "do not leave obsolete instructions uncorrected").
func TestRootActionWithdrawalCorrectsTheEarlierRequest(t *testing.T) {
	now := bcNow(t)
	c := rsMonitoringContract(now.Add(time.Minute))
	b := bcBriefing()
	b.Firing, b.Resolved = 0, 4
	in := bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, c, b)
	in.SourceTransition.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind:   model.CandidateActionChanged,
		Action: &model.ActionFacts{Withdrawn: true, Action: model.OperatorActionInvestigateSituation},
		Next:   model.NextStepFacts{Kind: model.NextStepGraceDeadline, At: rsTimePtr(now.Add(10 * time.Minute))},
	}}}
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "no longer needed")
	if strings.Contains(msg.Text, "On-call: ") {
		t.Errorf("withdrawal still renders a request:\n%s", msg.Text)
	}
}

// ----------------------------------------------------------------------
// Handoff coverage: multiple ended outcomes, the three distinct time
// promises, exhausted-but-firing, and the no-placeholder guard.
// ----------------------------------------------------------------------

// Each ended schedule is its own completion, keyed by its own incident and
// attempt identity (B0 §4 Outcome). Collapsing them to one aggregate line
// hides an investigation that actually ran and ended.
func TestJournalRendersEveryEndedCompletion(t *testing.T) {
	now := bcNow(t)
	completion := func(incident, attempt, check string) model.MaterialCandidate {
		return model.MaterialCandidate{
			Kind:    model.CandidateInconclusiveCompletion,
			Finding: &model.FindingFacts{IncidentID: incident, Observations: []string{check}},
			Outcome: &model.IncidentWorkOutcome{IncidentID: incident, AttemptID: attempt,
				Phase: model.WorkPhaseSettled, ResultCode: "success", EvidenceKnown: true},
			Next: model.NextStepFacts{Kind: model.NextStepWorkEnded},
		}
	}
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		completion("incident-a", "attempt-a", "Pod events checked"),
		completion("incident-b", "attempt-b", "Ingress logs checked"),
	}}
	tr := bcJournal(t, bcObserveMonitorContract(now.Add(time.Minute)), bcBriefing(), d)

	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Pod events checked", "Ingress logs checked")
	if n := strings.Count(msg.Text, "Investigation inconclusive"); n != 2 {
		t.Errorf("expected 2 completions, rendered %d:\n%s", n, msg.Text)
	}
}

// S4-08: a retry eligibility time, a recovery grace deadline and a status
// checkpoint are three different promises and must never be shown as one
// ("A retry eligibility time is neither of the above").
func TestRootSeparatesRetryGraceAndStatusTimes(t *testing.T) {
	now := bcNow(t)
	checkpoint := now.Add(time.Minute)
	retry := now.Add(5 * time.Minute)
	grace := now.Add(20 * time.Minute)
	c := rsMonitoringContract(checkpoint)
	b := bcBriefing()
	b.Firing, b.Resolved = 0, 4
	b.Work = model.WorkProjection{
		Phase: model.WorkPhaseRetryWait, ExecutionStarted: true,
		RetryEligibleAt: rsTimePtr(retry), SourceGraceUntil: rsTimePtr(grace),
		StatusCheckpointAt: rsTimePtr(checkpoint),
	}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, c, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"sustained recovery through " + SlackDateToken(grace, "{time}"),
		"retry is eligible at " + SlackDateToken(retry, "{time}"),
		"Next status check: " + SlackDateToken(checkpoint, "{time}"),
	} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("lost the distinct time promise %q:\n%s", want, msg.Text)
		}
	}
	if strings.Contains(msg.Text, "update by") || strings.Contains(msg.Text, "update overdue") {
		t.Errorf("a status checkpoint must not borrow enforceable update-by wording:\n%s", msg.Text)
	}
}

// Exhausted automatic attempts while alerts still fire: the limitation stays
// visible, no retry is promised, and exhaustion is not a human request
// (canonical "investigation:exhausted": "no separate human action
// requested").
func TestRootExhaustedWithAlertsStillFiring(t *testing.T) {
	now := bcNow(t)
	triage := model.AlertINTActionRunAcuteTriage
	exhausted := model.AlertINTStatusExhausted
	c := bcObserveMonitorContract(now.Add(time.Minute))
	c.AlertINTAction, c.AlertINTStatus = &triage, &exhausted
	b := bcBriefing()
	b.Work = model.WorkProjection{Phase: model.WorkPhaseExhausted, ExecutionStarted: true}

	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, c, b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Automatic attempts are exhausted", "No automatic retry is scheduled", "3/4 alerts firing")
	if strings.Contains(msg.Text, "On-call: ") {
		t.Errorf("exhaustion alone invented an operator request:\n%s", msg.Text)
	}
}

// The canonical slides write their examples with bracketed placeholders
// ("[recorded checkpoint]", "[accepted finding]"). None of that notation may
// ever reach a rendered payload.
func TestRenderedOutputCarriesNoCanonicalPlaceholders(t *testing.T) {
	now := bcNow(t)
	d := &model.OperatorDelta{
		StateChanged: true, PreviousFiring: 4, PreviousTotal: 4,
		ClearedAlerts: []string{"Queue backlog"},
		Candidates: []model.MaterialCandidate{
			{Kind: model.CandidateUsefulFinding, Finding: &model.FindingFacts{
				IncidentID: "incident-a", Hypothesis: "Deployment rollout exhausted the connection pool",
				Observations: []string{"Pod events checked"}, Unknowns: []string{"Upstream latency unavailable"}},
				Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))}},
			{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable},
				Next: model.NextStepFacts{Kind: model.NextStepRetryEligible, At: rsTimePtr(now.Add(5 * time.Minute))}},
			{Kind: model.CandidateFirstExecutionAssurance, Members: &model.MemberFacts{
				NowFiring: []string{"PodCrashLooping"}, FiringCount: 4, CountKnown: true, Total: 4},
				Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(now.Add(time.Minute))}},
		},
	}
	c := rsRunningTriageContract(now.Add(time.Minute))
	b := bcBriefing()
	b.Work = model.WorkProjection{Phase: model.WorkPhaseExecuting, ExecutionStarted: true,
		InvestigatedCount: 4, InvestigatedCountKnown: true, InvestigatedNames: []string{"PodCrashLooping", "LatencyP99"}}

	in := bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, c, b)
	in.SourceTransition.Projection.OperatorDelta = d
	root, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := RenderSituationJournal(in.SourceTransition)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []RenderedMessage{root, journal} {
		for _, text := range []string{msg.Text, rsFallbackBlocksText(msg)} {
			for _, bad := range []string{"[recorded", "[accepted", "[affected", "[specific", "[new recorded"} {
				if strings.Contains(text, bad) {
					t.Errorf("canonical placeholder %q leaked into output:\n%s", bad, text)
				}
			}
		}
	}
}

// ----------------------------------------------------------------------
// Readable samples. Not an assertion suite: this renders the canonical
// slide-4/5 examples under their own stated assumptions and prints the
// exact fallback text and Block Kit body, so a reviewer can judge the copy
// the way an operator reads it (`go test -run TestB4ReadableSamples -v`).
// It still fails if a render returns an error.
// ----------------------------------------------------------------------

func TestB4ReadableSamples(t *testing.T) {
	now := bcNow(t)
	checkpoint := now.Add(time.Minute)
	grace := now.Add(20 * time.Minute)
	retry := now.Add(5 * time.Minute)

	executing := model.WorkProjection{
		Phase: model.WorkPhaseExecuting, ExecutionStarted: true,
		InvestigatedCount: 9, InvestigatedCountKnown: true,
		InvestigatedNames:  []string{"PodCrashLooping", "LatencyP99", "HighErrorRate"},
		StatusCheckpointAt: rsTimePtr(checkpoint),
	}

	type sample struct {
		name      string
		lifecycle model.Lifecycle
		attention model.Attention
		contract  model.ActionContract
		briefing  func(*model.OperatorBriefing)
		delta     *model.OperatorDelta
	}

	investigate := model.OperatorActionInvestigateSituation
	requested := bcObserveMonitorContract(checkpoint)
	requested.OperatorActionRequired, requested.NextActor = &investigate, model.NextActorOperator

	for _, s := range []sample{
		{
			name: "first-root-running", lifecycle: model.LifecycleActive, attention: model.AttentionInvestigate,
			contract: rsRunningTriageContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) { b.Work = executing },
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind: model.CandidateFirstExecutionAssurance,
				Members: &model.MemberFacts{NowFiring: executing.InvestigatedNames,
					FiringCount: 9, CountKnown: true, Total: 4},
				Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(checkpoint)},
			}}},
		},
		{
			name: "investigation-inconclusive", lifecycle: model.LifecycleActive, attention: model.AttentionObserve,
			contract: bcObserveMonitorContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) { b.Work = model.WorkProjection{Phase: model.WorkPhaseSettled} },
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind: model.CandidateInconclusiveCompletion,
				Finding: &model.FindingFacts{IncidentID: "incident-a",
					Observations: []string{"Pod events checked", "Application errors checked"},
					Unknowns:     []string{"Database saturation could not be measured"}},
				Outcome: &model.IncidentWorkOutcome{IncidentID: "incident-a", AttemptID: "attempt-3",
					Phase: model.WorkPhaseSettled, ResultCode: "success", EvidenceKnown: true},
				Next: model.NextStepFacts{Kind: model.NextStepWorkEnded},
			}}},
		},
		{
			name: "useful-finding-outside-overview", lifecycle: model.LifecycleActive, attention: model.AttentionObserve,
			contract: bcObserveMonitorContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) { b.Work = model.WorkProjection{Phase: model.WorkPhaseSettled} },
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind: model.CandidateUsefulFinding,
				Finding: &model.FindingFacts{IncidentID: "incident-d",
					Hypothesis:   "Deployment rollout exhausted the connection pool",
					Observations: []string{"Pod events checked", "Application errors checked"},
					Unknowns:     []string{"Upstream latency metrics unavailable"}},
				Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(checkpoint)},
			}}},
		},
		{
			name: "capability-lost", lifecycle: model.LifecycleActive, attention: model.AttentionObserve,
			contract: bcObserveMonitorContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) {
				b.Unavailable = 1
				b.Work = model.WorkProjection{Phase: model.WorkPhaseRetryWait, ExecutionStarted: true, RetryEligibleAt: rsTimePtr(retry)}
			},
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind:       model.CandidateAbilityChanged,
				Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable},
				Next:       model.NextStepFacts{Kind: model.NextStepRetryEligible, At: rsTimePtr(retry)},
			}}},
		},
		{
			name: "capability-restored", lifecycle: model.LifecycleActive, attention: model.AttentionObserve,
			contract: rsRunningTriageContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) { b.Work = executing },
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind:       model.CandidateAbilityChanged,
				Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable, Cleared: true},
				Next:       model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(checkpoint)},
			}}},
		},
		{
			name: "recovery-with-work", lifecycle: model.LifecycleRecoveryPending, attention: model.AttentionObserve,
			contract: rsMonitoringContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) {
				b.Firing, b.Resolved = 0, 4
				w := executing
				w.RemainingIncidents, w.SourceGraceUntil = 1, rsTimePtr(grace)
				b.Work = w
			},
			delta: &model.OperatorDelta{StateChanged: true, PreviousFiring: 4, PreviousTotal: 4,
				ClearedAlerts: []string{"PodCrashLooping", "LatencyP99", "HighErrorRate", "QueueBacklog"},
				Candidates: []model.MaterialCandidate{{
					Kind:    model.CandidateAllClear,
					Members: &model.MemberFacts{Cleared: []string{"PodCrashLooping"}, FiringCount: 0, Total: 4},
					Next:    model.NextStepFacts{Kind: model.NextStepGraceDeadline, At: rsTimePtr(grace)},
				}}},
		},
		{
			name: "action-required", lifecycle: model.LifecycleActive, attention: model.AttentionInvestigate,
			contract: requested,
			briefing: func(b *model.OperatorBriefing) { b.Work = model.WorkProjection{Phase: model.WorkPhaseSettled} },
			delta: &model.OperatorDelta{HumanRequestChanged: true, Candidates: []model.MaterialCandidate{{
				Kind:   model.CandidateActionChanged,
				Action: &model.ActionFacts{Introduced: true, Action: investigate},
				Next:   model.NextStepFacts{Kind: model.NextStepStatusCheck, At: rsTimePtr(checkpoint)},
			}}},
		},
		{
			name: "action-withdrawn", lifecycle: model.LifecycleRecoveryPending, attention: model.AttentionObserve,
			contract: rsMonitoringContract(checkpoint),
			briefing: func(b *model.OperatorBriefing) {
				b.Firing, b.Resolved = 0, 4
				b.Work = model.WorkProjection{Phase: model.WorkPhaseSettled, SourceGraceUntil: rsTimePtr(grace)}
			},
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind:   model.CandidateActionChanged,
				Action: &model.ActionFacts{Withdrawn: true, Action: investigate},
				Next:   model.NextStepFacts{Kind: model.NextStepGraceDeadline, At: rsTimePtr(grace)},
			}}},
		},
		{
			name: "tracking-ended-recovery-unconfirmed", lifecycle: model.LifecycleClosedUnknown, attention: model.AttentionObserve,
			contract: rsTerminalContract(),
			briefing: func(b *model.OperatorBriefing) {
				b.Work = model.WorkProjection{Phase: model.WorkPhaseExhausted, ExecutionStarted: true}
			},
			delta: &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
				Kind: model.CandidateTerminalEnd,
				Next: model.NextStepFacts{Kind: model.NextStepTrackingEnded},
			}}},
		},
	} {
		t.Run(s.name, func(t *testing.T) {
			b := bcBriefing()
			s.briefing(b)
			in := bcRoot(t, s.lifecycle, s.attention, s.contract, b)
			in.SourceTransition.Projection.OperatorDelta = s.delta
			root, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatalf("root: %v", err)
			}
			journal, err := RenderSituationJournal(in.SourceTransition)
			if err != nil {
				t.Fatalf("journal: %v", err)
			}
			t.Logf("\n===== %s =====\n--- root · fallback text ---\n%s\n--- root · block kit ---\n%s\n--- journal · fallback text ---\n%s\n--- journal · block kit ---\n%s",
				s.name, root.Text, rsFallbackBlocksText(root), journal.Text, rsFallbackBlocksText(journal))
		})
	}
}
