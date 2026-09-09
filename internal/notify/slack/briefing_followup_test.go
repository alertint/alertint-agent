// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// A completed investigation must not override the current monitoring contract.
func TestBriefingFollowupPhaseMatchesCurrentWork(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":3,"total":4}}`)
	in.Summary.InvestigationStarted = true
	c := rsMonitoringContract(in.Now.Add(time.Minute))
	action := model.AlertINTActionMonitorSituation
	c.AlertINTAction = &action
	in.SourceTransition.ActionContract = c
	for _, started := range []bool{true, false} {
		in.Summary.InvestigationStarted = started
		msg := renderBriefingRoot(in)
		if !strings.Contains(msg.Text, "· *▸ Monitoring* ·") || !strings.Contains(msg.Text, "Monitoring alert changes.") || strings.Contains(msg.Text, "*▸ Investigating*") {
			t.Errorf("phase and current work disagree (started=%v): %s", started, msg.Text)
		}
	}
	action = model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	in.SourceTransition.ActionContract.AlertINTStatus = &status
	msg := renderBriefingRoot(in)
	if !strings.Contains(msg.Text, "*▸ Investigating*") || !strings.Contains(msg.Text, "*AlertINT:* Investigating.") {
		t.Errorf("renewed investigation not reflected: %s", msg.Text)
	}
}

func TestBriefingFollowupLegacyMonitoringDoesNotInventRecovery(t *testing.T) {
	in := briefingRootFixture(t, `{}`)
	c := rsMonitoringContract(in.Now.Add(time.Minute))
	action := model.AlertINTActionMonitorSituation
	c.AlertINTAction = &action
	in.SourceTransition.ActionContract, in.Summary.ActionContract = c, c
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	text := rsFallbackBlocksText(msg)
	if !strings.Contains(text, "*▸ Monitoring*") || !strings.Contains(text, "Monitoring alert changes") || strings.Contains(text, "Watching for sustained recovery") {
		t.Errorf("active legacy monitoring invents recovery: %s", text)
	}
}

// Actions describe recorded needs, not a nonexistent acknowledgement workflow
// or hypothetical user reports; clearance does not establish service impact.
func TestBriefingFollowupActionsUseRecordedState(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1}}`)
	for _, lifecycle := range []model.Lifecycle{model.LifecycleActive, model.LifecycleRecoveryPending, model.LifecycleRecovered, model.LifecycleClosedUnknown} {
		tr := in.SourceTransition
		tr.Lifecycle = lifecycle
		b := *in.Summary.Briefing
		if lifecycle == model.LifecycleRecovered || lifecycle == model.LifecycleRecoveryPending {
			tr.Attention = model.AttentionObserve
			b.Firing, b.Resolved = 0, 1
		}
		got := briefingAction(&b, tr)
		if !strings.Contains(strings.ToLower(got), "on-call") {
			t.Errorf("action has no audience: %s", got)
		}
		for _, bad := range []string{"ownership", "Confirm service health if", "If users", "impact persists"} {
			if strings.Contains(got, bad) {
				t.Errorf("unsupported instruction %q: %s", bad, got)
			}
		}
		if lifecycle == model.LifecycleRecovered || lifecycle == model.LifecycleRecoveryPending {
			if got != "None required from on-call; alerts resolved." {
				t.Errorf("clearance invents a follow-up: %s", got)
			}
		}
	}
}

// Titles must carry incident meaning even when detached from the card body.
func TestBriefingFollowupDescriptiveTitles(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":3,"resolved":1,"total":4,"symptoms":["Checkout errors","Pod crashes"],"analyses":[{"title":"Deployment crash cascade","summary":"Deployment may explain failures."}]}}`)
	root := renderBriefingRoot(in)
	title := strings.Split(root.Text, "\n")[0]
	if !strings.Contains(title, "Hypothesis: Deployment crash cascade") || !strings.Contains(title, "checkout") {
		t.Errorf("root title lacks qualified finding: %s", title)
	}
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{StateChanged: true, PreviousFiring: 4, PreviousTotal: 4, ClearedAlerts: []string{"Queue backlog"}}
	headline, _ := briefingJournal(tr)
	if !strings.Contains(headline, "Queue backlog cleared") || !strings.Contains(headline, "3/4") {
		t.Errorf("partial title lacks changed fact: %s", headline)
	}
	for _, lifecycle := range []model.Lifecycle{model.LifecycleRecoveryPending, model.LifecycleRecovered, model.LifecycleClosedUnknown} {
		tr.Lifecycle = lifecycle
		headline, _ = briefingJournal(tr)
		if !strings.Contains(headline, "checkout") || !strings.Contains(headline, "Hypothesis: Deployment crash cascade") {
			t.Errorf("outcome title lacks incident context: %s", headline)
		}
	}
	in.Summary.Briefing.Analyses = nil
	title = strings.Split(renderBriefingRoot(in).Text, "\n")[0]
	if !strings.Contains(title, "Checkout errors, Pod crashes") {
		t.Errorf("pre-analysis title loses observed symptoms: %s", title)
	}
	in.Summary.Briefing.Analyses = []model.IncidentAnalysis{{Title: "<@U123> *cause*\n" + strings.Repeat("\u754c", 300)}}
	title = strings.Split(renderBriefingRoot(in).Text, "\n")[0]
	if strings.Contains(title, "<@U123>") || strings.Contains(title, "*cause*") || len(title) > 500 {
		t.Errorf("untrusted title is unsafe or unbounded: %s", title)
	}
	tr.Lifecycle = model.LifecycleActive
	tr.Projection.OperatorDelta = &model.OperatorDelta{Analyses: []model.IncidentAnalysis{{Title: "New finding"}}}
	headline, _ = briefingJournal(tr)
	if !strings.Contains(headline, "Evidence update") || !strings.Contains(headline, "Hypothesis: New finding") || strings.Contains(headline, "Deployment crash cascade") {
		t.Errorf("evidence title does not describe the new finding: %s", headline)
	}
}

func TestBriefingFollowupCombinedRecoveryAndEvidenceTitle(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":3,"resolved":1,"total":4}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{
		StateChanged: true, PreviousFiring: 4, PreviousTotal: 4,
		ClearedAlerts: []string{"Queue backlog"},
		Analyses:      []model.IncidentAnalysis{{Title: "Updated deployment hypothesis", Summary: "New evidence"}},
	}
	headline, _ := briefingJournal(tr)
	for _, want := range []string{"Partial recovery", "Queue backlog cleared", "3/4", "Evidence update", "Hypothesis: Updated deployment hypothesis"} {
		if !strings.Contains(headline, want) {
			t.Errorf("combined title loses %q: %s", want, headline)
		}
	}
}
