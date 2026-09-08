// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// These assertions catch a duplicated report, a low-contrast command, and a
// status indicator that mistakes source clearance for confirmed recovery.
func TestBriefingRevisionOverviewAndStatus(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout · production · internal-cluster","display_scope":"checkout · production","firing":4,"total":4,"critical":2,"analyses":[{"title":"Deployment crash cascade","summary":"The deployment may explain checkout failures.","findings":["Crashes followed deployment","SECOND OBSERVATION"],"verification":"supported","verification_gaps":1}]}}`)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"🔴", "*Urgent · checkout · production — Hypothesis: Deployment crash cascade*", "*Likely cause:*", "*Supporting observations:*", "Verification limited", "*AlertINT:*", "*Action:*"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("missing %q:\n%s", want, msg.Text)
		}
	}
	for _, bad := range []string{"internal-cluster", "SECOND OBSERVATION", "Historical finding", "causality unproven;", "More context via MCP"} {
		if strings.Contains(msg.Text, bad) {
			t.Errorf("overview repeats report %q:\n%s", bad, msg.Text)
		}
	}
	raw, err := json.Marshal(msg.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []struct {
		Type string `json:"type"`
		Text struct {
			Text string `json:"text"`
		} `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		t.Fatal(err)
	}
	command := "get situation checkout-42 using alertint"
	commandSection := false
	for _, b := range blocks {
		if b.Type == "section" && strings.Contains(b.Text.Text, "\n"+command) {
			commandSection = true
		}
	}
	if !commandSection {
		t.Fatalf("copyable command must use normal body text: %s", raw)
	}
	for _, tc := range []struct {
		lifecycle model.Lifecycle
		attention model.Attention
		marker    string
	}{
		{model.LifecycleActive, model.AttentionObserve, "🔵"},
		{model.LifecycleRecoveryPending, model.AttentionObserve, "🔵"},
		{model.LifecycleRecovered, model.AttentionObserve, "🟢"},
		{model.LifecycleClosedUnknown, model.AttentionObserve, "🔴"},
	} {
		tr := in.SourceTransition
		tr.Lifecycle, tr.Attention = tc.lifecycle, tc.attention
		if tc.lifecycle.Terminal() {
			tr.ActionContract.NextUpdateAt = nil
			in.ContractDeadlineAt = nil
		}
		in.SourceTransition = tr
		// Direct renderer isolates styling from the existing lifecycle validator.
		if out := renderBriefingRoot(in); !strings.Contains(out.Text, tc.marker) {
			t.Errorf("%s must show %s: %s", tc.lifecycle, tc.marker, out.Text)
		}
	}
}

func TestBriefingRevisionEvidenceAndPartialRecoveryReplies(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":3,"total":4,"resolved":1,"alerts":[{"id":"a","name":"Pod crash loop","state":"resolved"},{"id":"b","name":"High error rate","state":"firing"},{"id":"c","name":"High latency","state":"firing"},{"id":"d","name":"Queue backlog","state":"firing"}],"analyses":[{"summary":"OLD ROOT FINDING"}]}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.ActionContract = rsMonitoringContract(in.Now.Add(time.Minute))
	monitor := model.AlertINTActionMonitorSituation
	tr.ActionContract.AlertINTAction = &monitor
	if err := json.Unmarshal([]byte(`{"operator_delta":{"state_changed":true,"previous_firing":4,"previous_total":4,"cleared_alerts":["Pod crash loop"]}}`), &tr.Projection); err != nil {
		t.Fatal(err)
	}
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Partial recovery", "3/4", "*Cleared:* Pod crash loop", "*Still firing:*", "High error rate", "High latency", "Queue backlog", "*AlertINT:*", "*Action:*", "<!date^"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("partial recovery lacks %q:\n%s", want, msg.Text)
		}
	}
	if strings.Contains(msg.Text, "OLD ROOT FINDING") || strings.Contains(msg.Text, "🟢") {
		t.Fatalf("partial recovery must not repeat analysis or declare recovery: %s", msg.Text)
	}
	tr.Projection.OperatorDelta = nil
	if err := json.Unmarshal([]byte(`{"operator_delta":{"analyses":[{"title":"Deployment crash cascade","summary":"Deployment may explain crashes.","findings":["Panic appears in payment logs","Errors rose after deployment"],"verification":"degraded","verification_gaps":1}]}}`), &tr.Projection); err != nil {
		t.Fatal(err)
	}
	msg, err = RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Evidence update", "*Observed*", "• Panic appears", "• Errors rose", "*Interpretation:*", "*Still unknown:*", "*AlertINT:*", "*Action:*"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("evidence reply lacks %q:\n%s", want, msg.Text)
		}
	}
	if strings.Contains(msg.Text, "3/4 alerts firing") || strings.Contains(msg.Text, "OLD ROOT FINDING") {
		t.Fatalf("evidence reply repeats overview: %s", msg.Text)
	}
}

// A reconsideration deadline is not a work retry. Every branch must say which
// activity is scheduled, and preserve the actual later retry when one exists.
func TestBriefingRevisionNextStepUsesRecordedWork(t *testing.T) {
	for _, tc := range []struct{ name, action, status, wait, retry, want, forbidden string }{
		{"monitor", "monitor_situation", "waiting", "source_change", "", "Monitoring alert changes", "Retrying verification"},
		{"triage backoff", "run_acute_triage", "waiting", "acute_triage_backoff", "2026-09-07T10:02:00Z", "Investigation retry scheduled", "Retrying verification"},
		{"assessment backoff", "retry_situation_assessment", "waiting", "assessment_retry", "2026-09-07T10:02:00Z", "Assessment retry scheduled", "health check"},
		{"missing retry time", "run_acute_triage", "waiting", "acute_triage_backoff", "", "retry time is unavailable", "retry scheduled for"},
		{"parked", "retry_situation_assessment", "blocked", "assessment_parked", "", "No automatic retry is scheduled", "Retry scheduled"},
		{"exhausted", "run_acute_triage", "exhausted", "", "", "No automatic retry is scheduled", "Monitoring alert changes"},
		{"running", "run_acute_triage", "running", "", "", "Investigating", "is waiting on monitoring"},
		{"planned", "run_acute_triage", "planned", "", "", "Investigation is queued", "Investigating."},
		{"assessment queued", "retry_situation_assessment", "planned", "", "", "Assessment is queued", "back-off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1,"analyses":[{"summary":"Cause remains uncertain","verification":"degraded"}]}}`)
			c := rsMonitoringContract(in.Now.Add(time.Minute))
			a, s := model.AlertINTAction(tc.action), model.AlertINTStatus(tc.status)
			c.AlertINTAction, c.AlertINTStatus = &a, &s
			c.WaitReason = nil
			if tc.wait != "" {
				w := model.WaitReason(tc.wait)
				c.WaitReason = &w
			}
			in.SourceTransition.ActionContract = c
			in.SourceTransition.Projection.Briefing = in.Summary.Briefing
			if tc.retry != "" {
				if err := json.Unmarshal([]byte(`{"retry_at":"`+tc.retry+`"}`), in.Summary.Briefing); err != nil {
					t.Fatal(err)
				}
			}
			root, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := RenderSituationJournal(in.SourceTransition)
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range []string{root.Text, journal.Text} {
				if !strings.Contains(out, tc.want) || strings.Contains(out, tc.forbidden) || !strings.Contains(out, "Next status check:") {
					t.Errorf("wrong next step:\n%s", out)
				}
				if tc.retry != "" && !strings.Contains(out, "<!date^1788775320^") {
					t.Errorf("lost actual 10:02 retry; 10:01 checkpoint must not replace it: %s", out)
				}
			}
		})
	}
}

func TestBriefingRevisionInconclusiveEvidenceAndLongReplyKeepNextStep(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1,"analyses":[{"summary":"Cause remains unknown","verification":"degraded"}]}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.ActionContract = rsMonitoringContract(in.Now.Add(time.Minute))
	monitor := model.AlertINTActionMonitorSituation
	tr.ActionContract.AlertINTAction = &monitor
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"No supporting observations were recorded", "does not establish that the service is healthy", "*Still unknown:*", "Monitoring alert changes", "No verification retry is recorded", "*Action:*"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("inconclusive result lost %q: %s", want, msg.Text)
		}
	}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Analyses: []model.IncidentAnalysis{
		{Summary: "First hypothesis", Findings: []string{strings.Repeat("e", 400), strings.Repeat("f", 400), strings.Repeat("g", 400)}},
		{Summary: "Second hypothesis", Findings: []string{strings.Repeat("h", 400), strings.Repeat("i", 400), strings.Repeat("j", 400)}},
		{Summary: "Third hypothesis", Findings: []string{strings.Repeat("k", 400), strings.Repeat("l", 400), strings.Repeat("m", 400)}},
	}}
	msg, err = RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	blocks := rsFallbackBlocksText(msg)
	for _, want := range []string{"First hypothesis", "Second hypothesis", "Third hypothesis", "*AlertINT:*", "*Action:*", "Next status check:"} {
		if !strings.Contains(blocks, want) {
			t.Errorf("long evidence truncated %q: %s", want, blocks)
		}
	}
}

func TestBriefingRevisionVerificationChangeAndPartialAvailability(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":2,"total":2,"pending":1,"unavailable":1,"analyses":[{"summary":"Deployment hypothesis","verification":"supported"}]}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{AbilityLost: true, Analyses: in.Summary.Briefing.Analyses}
	for _, tc := range []struct{ verification, want string }{{"supported", "Verification supports the hypothesis"}, {"revised", "Verification revised the hypothesis"}} {
		tr.Projection.OperatorDelta.Analyses[0].Verification = tc.verification
		msg, err := RenderSituationJournal(tr)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{tc.want, "Analysis unavailable for 1 incident(s)", "Investigating."} {
			if !strings.Contains(msg.Text, want) {
				t.Errorf("lost scoped change %q: %s", want, msg.Text)
			}
		}
		if strings.Contains(msg.Text, "cannot continue its current work") {
			t.Errorf("partial unavailability became global loss of work: %s", msg.Text)
		}
	}
}

// State changes and evidence may arrive in the same committed transition.
// Per-block truncation must not hide the qualification of the new hypothesis.
func TestBriefingRevisionCombinedDeltaPreservesEvidenceLimitations(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":8,"total":16,"resolved":8}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	d := &model.OperatorDelta{StateChanged: true, PreviousFiring: 8, PreviousTotal: 16, Analyses: []model.IncidentAnalysis{{Summary: "New hypothesis", Findings: []string{strings.Repeat("e", 400), strings.Repeat("f", 400), strings.Repeat("g", 400)}, Verification: "degraded", VerificationLimit: "verification_source_unavailable", VerificationGaps: 7}}}
	for i := 0; i < 8; i++ {
		d.ClearedAlerts = append(d.ClearedAlerts, "Cleared "+strings.Repeat("a", 230))
		d.NewFiringAlerts = append(d.NewFiringAlerts, "Firing "+strings.Repeat("b", 230))
		tr.Projection.Briefing.Alerts = append(tr.Projection.Briefing.Alerts, model.BriefingAlert{ID: string(rune('a' + i)), Name: "Firing " + strings.Repeat("b", 230), State: "firing"})
	}
	tr.Projection.OperatorDelta = d
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"New hypothesis", "verification source unavailable", "7 verification checks unavailable or invalid", "*Still firing:*", "*AlertINT:*", "*Action:*"} {
		if !strings.Contains(rsFallbackBlocksText(msg), want) {
			t.Errorf("combined update cut off %q: %s", want, rsFallbackBlocksText(msg))
		}
	}
}
