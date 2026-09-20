// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestExpectedBehaviorRootRetainsFindingOrderAndAddsCompactContext(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "Reconciliation job is driving CPU load", Findings: []string{"CPU load remains elevated on db-prod-1."}, Verification: "supported"}}
	boundary := bcNow(t).Add(time.Hour)
	b.ExpectedBehavior = &model.ExpectedBehaviorProjection{EnvelopeID: "env-1", Version: 1, AssertedOperator: "Janis", Disposition: model.ExpectedBehaviorDispositionMatched, Boundary: &boundary}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	want := "*Operator:* Expected schedule applies until " + SlackDateToken(boundary, "{time}") + " · Janis"
	if !strings.Contains(msg.Text, want) {
		t.Fatalf("root missing %q:\n%s", want, msg.Text)
	}
	if finding, operator := strings.Index(msg.Text, "*Finding:*"), strings.Index(msg.Text, "*Operator:*"); finding < 0 || operator <= finding {
		t.Fatalf("root order finding=%d operator=%d:\n%s", finding, operator, msg.Text)
	}
}

func TestExpectedBehaviorStoppedReasonsAndWithdrawalUseSimpleText(t *testing.T) {
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), canonicalFixture(t), nil)
	tr.Actor = model.ActorAttributedOperator
	tr.Journal.ExpectedBehaviorChange = model.ExpectedBehaviorChangeWithdrawn
	tr.Journal.AttributedActor = "Janis"
	msg, err := RenderSituationJournal(tr)
	if err != nil || msg.Text != "Janis removed the expected schedule. Normal assessment resumes." {
		t.Fatalf("withdrawal=%q err=%v", msg.Text, err)
	}
	boundary := bcNow(t).Add(time.Hour)
	tr.Journal.ExpectedBehaviorChange = model.ExpectedBehaviorChangeApplied
	tr.Journal.ExpectedBehaviorBoundary = &boundary
	msg, err = RenderSituationJournal(tr)
	wantApplied := "This condition matches Janis's expected schedule until " + SlackDateToken(boundary, "{time}") + ". Monitoring continues."
	if err != nil || msg.Text != wantApplied {
		t.Fatalf("applied=%q want=%q err=%v", msg.Text, wantApplied, err)
	}
	tr.Journal.NoLongerCurrent = true
	msg, err = RenderSituationJournal(tr)
	if err != nil || !strings.Contains(msg.Text, "This schedule is no longer active.") {
		t.Fatalf("stale applied=%q err=%v", msg.Text, err)
	}
	tr.Actor = model.ActorDeterministicController
	tr.Journal.AttributedActor = ""
	tr.Journal.NoLongerCurrent = false
	tr.Journal.ExpectedBehaviorChange = model.ExpectedBehaviorChangeStopped
	tr.Journal.ExpectedBehaviorReason = model.ExpectedBehaviorReasonPrimaryDefinitionChanged
	tr.Journal.Detail = "The Zabbix rule changed."
	msg, err = RenderSituationJournal(tr)
	if err != nil || msg.Text != "The expected schedule no longer applies because the Zabbix rule changed. Normal assessment resumes." {
		t.Fatalf("stopped=%q err=%v", msg.Text, err)
	}
	tr.Journal.Detail = "AlertINT cannot verify the Zabbix rule."
	msg, _ = RenderSituationJournal(tr)
	if !strings.Contains(msg.Text, "because AlertINT cannot verify the Zabbix rule") {
		t.Fatal(msg.Text)
	}
	tr.Journal.Detail = "An unexpected alert is firing."
	msg, _ = RenderSituationJournal(tr)
	if !strings.Contains(msg.Text, "because an unexpected alert is firing") {
		t.Fatal(msg.Text)
	}
}
