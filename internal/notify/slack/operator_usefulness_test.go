// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestOperatorUsefulnessNoInventedActionRow(t *testing.T) {
	b := bcBriefing()
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.Text, "*Action:*") {
		t.Fatalf("unrequested action row: %s", msg.Text)
	}
}

func TestOperatorUsefulnessRecoveryLabelsHistoricalValues(t *testing.T) {
	b := bcBriefing()
	b.Historical = true
	b.Alerts = []model.BriefingAlert{{Name: "Errors", State: "resolved", SourceSummary: "100% over 1m"}}
	got := briefingAnalysis(b, false)
	if !strings.Contains(got, "Historical source report") || !strings.Contains(got, "not a current measurement") {
		t.Fatal(got)
	}
}

func TestOperatorUsefulnessRetainedDraftDoesNotAssertObservations(t *testing.T) {
	a := model.IncidentAnalysis{Summary: "Failure isolated to frontend", Findings: []string{"No other services affected"}, Verification: "degraded", VerificationLimit: "llm_call_failed"}
	got := strings.Join(briefingEvidence(a), "\n")
	if strings.Contains(got, "*Observed*") || !strings.Contains(got, "not reconciled") {
		t.Fatal(got)
	}
}

func TestOperatorUsefulnessTerminalObstacleDoesNotClaimRestoration(t *testing.T) {
	b := bcBriefing()
	b.Historical = true
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: string(model.WaitReasonAssessmentParked), Cleared: true}, Next: model.NextStepFacts{Kind: model.NextStepTrackingEnded}}}}
	got := strings.Join(briefingAbilityChangeLines(d, b), " ")
	if strings.Contains(got, "limitation cleared") || !strings.Contains(got, "did not resume") {
		t.Fatal(got)
	}
}

func TestOperatorUsefulnessBudgetReasonAndActualRetry(t *testing.T) {
	b := bcBriefing()
	raw := `{"blocked_reason":"budget_deferred","assessment_retry_at":"2026-09-09T10:01:00Z"}`
	if err := json.Unmarshal([]byte(raw), b); err != nil {
		t.Fatal(err)
	}
	status := model.AlertINTStatusBlocked
	c := bcObserveMonitorContract(bcNow(t))
	c.AlertINTStatus = &status
	got := briefingWork(c, b, bcNow(t))
	for _, want := range []string{"budget cannot admit", "retried at"} {
		if !strings.Contains(got, want) {
			t.Fatal(got)
		}
	}
	b.Historical = true
	got = briefingWork(c, b, bcNow(t))
	if !strings.Contains(got, "retried at") {
		t.Fatalf("recovery grace erased a real retry: %s", got)
	}
}

func TestOperatorUsefulnessAssuranceHasOneCheckpoint(t *testing.T) {
	now := bcNow(t)
	next := now.Add(time.Minute)
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{Kind: model.CandidateFirstExecutionAssurance, Members: &model.MemberFacts{NowFiring: []string{"Errors"}, CountKnown: true, FiringCount: 1}, Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: &next}}}}
	tr := bcJournal(t, rsRunningTriageContract(next), bcBriefing(), d)
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(msg.Text, SlackDateToken(next, "{time}")); n != 1 {
		t.Fatalf("checkpoint repeated %d times: %s", n, msg.Text)
	}
}

func TestOperatorUsefulnessGeneratedNotesAreNotSourceEvidence(t *testing.T) {
	a := model.IncidentAnalysis{Summary: "A shared dependency may be failing", Findings: []string{"Every user is failing; no other service has alerts"}}
	raw := `{"observations":["Log sample at 08:02 UTC: Payment request failed. Invalid token."]}`
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(briefingEvidence(a), "\n") + strings.Join(briefingFinding(a, false), "\n")
	if strings.Contains(got, "Every user is failing") || !strings.Contains(got, "Log sample at") {
		t.Fatal(got)
	}
}

func TestOperatorUsefulnessBudgetReplyStatesReasonOnce(t *testing.T) {
	b := bcBriefing()
	b.BlockedReason = "budget_deferred"
	now := bcNow(t)
	next := now.Add(time.Minute)
	c := bcObserveMonitorContract(next)
	status := model.AlertINTStatusBlocked
	reason := model.WaitReasonAssessmentParked
	c.AlertINTStatus = &status
	c.WaitReason = &reason
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: string(reason)}, Next: model.NextStepFacts{Kind: model.NextStepStatusCheck, At: &next}}}}
	tr := bcJournal(t, c, b, d)
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(msg.Text, "configured budget cannot admit"); n != 1 {
		t.Fatalf("reason repeated %d times: %s", n, msg.Text)
	}
}

func TestOperatorUsefulnessLongThreadKeepsLastCheck(t *testing.T) {
	b := bcBriefing()
	b.Alerts = []model.BriefingAlert{{Name: "one", State: "resolved", SourceSummary: strings.Repeat("s", 240)}, {Name: "two", State: "resolved", SourceSummary: strings.Repeat("s", 240)}, {Name: "three", State: "resolved", SourceSummary: strings.Repeat("s", 240)}}
	b.Analyses = []model.IncidentAnalysis{{Summary: strings.Repeat("h", 240), Observations: []string{strings.Repeat("o", 400)}, VerificationNotes: []string{strings.Repeat("a", 480), strings.Repeat("b", 480), strings.Repeat("c", 480), strings.Repeat("d", 480), "last check must reach operator"}}}
	msg, err := RenderSituationJournal(bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "last check must reach operator")
}

func TestOperatorUsefulnessTerminalClearanceWithoutCandidateNext(t *testing.T) {
	b := bcBriefing()
	b.BlockedReason = "budget_deferred"
	d := &model.OperatorDelta{Candidates: []model.MaterialCandidate{{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{Code: string(model.WaitReasonAssessmentParked), Cleared: true}}}}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, d)
	tr.Lifecycle = model.LifecycleRecovered
	_, got := briefingJournal(tr)
	if strings.Contains(got, "limitation cleared") {
		t.Fatal(got)
	}
}

func TestCompactRootKeepsDetailsInThreadAndDatesEveryMessage(t *testing.T) {
	b := bcBriefing()
	b.Analyses = []model.IncidentAnalysis{{Title: "Payment failures affecting checkout", Summary: "Payment failures may explain checkout errors", Observations: []string{"unique source sample"}, VerificationNotes: []string{"unique missing check"}}}
	b.AnalysisCount = 1
	b.Work.Phase = model.WorkPhaseSettled
	b.Alerts = []model.BriefingAlert{{Name: "Errors", State: "firing", SourceSummary: "Checkout error ratio: 50% over 1 minute"}}
	in := bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b)
	in.Summary.EffectiveStartedAt = in.Now.Add(-90 * time.Second)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "*Duration:* 1m30s")
	bcBothSurfaces(t, msg, "Payment failures may explain checkout errors")
	bcBothSurfaces(t, msg, "Analysis completed. Monitoring for changes.")
	for _, unwanted := range []string{"unique source sample", "unique missing check", "Hypothesis:", "Impact unknown"} {
		if strings.Contains(msg.Text, unwanted) {
			t.Errorf("root contains %q: %s", unwanted, msg.Text)
		}
	}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	tr.Projection.EffectiveStartedAt = tr.CreatedAt.Add(-90 * time.Second)
	reply, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, reply, "unique missing check")
	bcBothSurfaces(t, reply, "*Duration:* 1m30s")
	headline, _ := briefingJournal(tr)
	if strings.Contains(headline, "Payment failures") {
		t.Fatal(headline)
	}
}

func TestCompactRootDoesNotPromoteRetainedDraftToCompletion(t *testing.T) {
	for _, reason := range []string{"llm_call_failed", "llm_response_invalid", "budget_deferred"} {
		b := bcBriefing()
		b.Work.Phase = model.WorkPhaseSettled
		b.Analyses = []model.IncidentAnalysis{{Title: "Draft cause", VerificationLimit: reason}}
		msg := renderBriefingRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
		if strings.Contains(msg.Text, "Analysis completed") {
			t.Errorf("draft promoted for %s: %s", reason, msg.Text)
		}
	}
}

func TestReadableEvidencePreservesCompleteChecksAndRootFinding(t *testing.T) {
	b := bcBriefing()
	note := strings.Repeat("Check the service latency and request error counts. ", 12) + "LAST COMPLETE CHECK: returned no data; this check establishes neither health nor failure."
	b.Analyses = []model.IncidentAnalysis{{Title: "Checkout errors", Summary: "Payment failures may explain checkout errors.", VerificationNotes: []string{note, "Peer service health: returned no data; this check establishes neither health nor failure."}}}
	in := bcRoot(t, model.LifecycleRecovered, model.AttentionUrgent, rsTerminalContract(), b)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "*Finding:* Payment failures may explain checkout errors.")
	reply, err := RenderSituationJournal(bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, reply, "LAST COMPLETE CHECK")
	if strings.Count(reply.Text, "establishes neither health nor failure") > 1 {
		t.Fatal(reply.Text)
	}
	if strings.Contains(reply.Text, "…") {
		t.Fatal(reply.Text)
	}
}

func TestReadableLongEvidenceSectionsDoNotTruncate(t *testing.T) {
	text := briefingComplete(strings.Repeat("Latency < threshold & healthy. ", 180) + "END OF FULL CHECK")
	msg := RenderedMessage{Blocks: briefingSections(text)}
	if got := strings.ReplaceAll(rsFallbackBlocksText(msg), "\n", ""); !strings.Contains(got, "END OF FULL CHECK") || strings.Contains(got, truncationMarker) {
		t.Fatal(got)
	}
}

func TestReadableReplyKeepsActivityWithinSlackBlockBudget(t *testing.T) {
	b := bcBriefing()
	b.Analyses = []model.IncidentAnalysis{{Summary: strings.Repeat("A complete evidence sentence. ", 6000)}}
	msg, err := RenderSituationJournal(bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Blocks) > 50 {
		t.Fatalf("%d blocks exceed Slack limit", len(msg.Blocks))
	}
	bcBothSurfaces(t, msg, "*AlertINT:*")
}

func TestReadableRootRetainsObservedFactWhenReviewWasBudgetBlocked(t *testing.T) {
	b := bcBriefing()
	b.Analyses = []model.IncidentAnalysis{{Title: "Every gold user fails", Summary: "Unsupported causal draft", Observations: []string{"Log sample at 10:16 UTC: Payment request failed. Invalid token."}, VerificationLimit: "budget_deferred"}}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleRecovered, model.AttentionUrgent, rsTerminalContract(), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment request failed. Invalid token.")
	bcBothSurfaces(t, msg, "verification review")
	if strings.Contains(msg.Text, "Unsupported causal draft") || strings.Contains(msg.Text, "Every gold user") {
		t.Fatal(msg.Text)
	}
}
