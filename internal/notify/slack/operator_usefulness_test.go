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
