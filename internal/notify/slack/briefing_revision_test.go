// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
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

// S3-03 (B0 integration contract §4): a newer alert delivery arriving after
// analysis (Stale) alone does not invalidate the hypothesis. Keep the
// AnalyzedAt date and the honest "Earlier hypothesis" label; never claim
// reduced relevance from the timestamp comparison alone.
func TestBriefingRevisionStaleAloneDoesNotInvalidateHypothesis(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1,"analyses":[{"summary":"Deployment may explain errors","findings":["Restarts and errors began together"],"verification":"supported","stale":true,"analyzed_at":"2026-09-07T09:00:00Z"}]}}`)
	root, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, txt := range []string{root.Text, rsFallbackBlocksText(root)} {
		if !strings.Contains(txt, "Earlier hypothesis") || !strings.Contains(txt, "Finding at") {
			t.Errorf("stale finding lost its honest label or date: %s", txt)
		}
		if strings.Contains(txt, "limit relevance") {
			t.Errorf("newer alert timestamp alone must not claim invalidated relevance: %s", txt)
		}
	}
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{Analyses: in.Summary.Briefing.Analyses}
	reply, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reply.Text, "limit relevance") {
		t.Errorf("detailed evidence reply must not claim a stale-alone relevance loss: %s", reply.Text)
	}
}

// S4-09 (B0 integration contract §4): introduce/revise/withdraw are
// distinguished in the reply text — a withdrawal explicitly says the
// earlier request is no longer needed, never the same generic "changed"
// wording for both directions.
func TestBriefingRevisionActionChangeDistinguishesIntroducedAndWithdrawn(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{
		HumanRequestChanged: true,
		Candidates:          []model.MaterialCandidate{{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Introduced: true, Action: action}}},
	}
	introduced, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(introduced.Text, "Operator action newly required") {
		t.Errorf("introduced action must say a new request now applies: %s", introduced.Text)
	}
	if strings.Contains(introduced.Text, "no longer needed") {
		t.Errorf("introduced action must not claim a withdrawal: %s", introduced.Text)
	}

	tr.Projection.OperatorDelta = &model.OperatorDelta{
		HumanRequestChanged: true,
		Candidates:          []model.MaterialCandidate{{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Withdrawn: true, Action: action}}},
	}
	withdrawn, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withdrawn.Text, "earlier operator action request is no longer needed") {
		t.Errorf("withdrawn action must correct the earlier request: %s", withdrawn.Text)
	}
	if strings.Contains(withdrawn.Text, "newly required") {
		t.Errorf("withdrawn action must not claim a new introduction: %s", withdrawn.Text)
	}
}

// S4-05 (B0 integration contract §4): an investigation newly reaching
// Exhausted with no useful finding earns one structured inconclusive-
// completion reply — actual checks, decision-relevant unknowns and an
// explicit no-retry next step, never a silent or generic "coverage
// incomplete" line alone.
func TestBriefingRevisionInconclusiveCompletionIsStructured(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Projection.OperatorDelta = &model.OperatorDelta{
		AnalysisFailed: true,
		Candidates: []model.MaterialCandidate{{
			Kind:    model.CandidateInconclusiveCompletion,
			Finding: &model.FindingFacts{Observations: []string{"Checked pod events and application errors"}},
			Next:    model.NextStepFacts{Kind: model.NextStepWorkEnded},
		}},
	}
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Investigation inconclusive", "Checked pod events and application errors", "No further analysis retry is scheduled"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("inconclusive completion lost %q: %s", want, msg.Text)
		}
	}
	if strings.Contains(msg.Text, "coverage is incomplete") {
		t.Errorf("structured inconclusive reply must not fall back to the generic line: %s", msg.Text)
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

// R1 (lead review 2026-09-09): the inconclusive-completion helper must keep
// the decision-relevant unknowns it was handed and read the candidate's own
// recorded next step instead of always denying a retry.
func TestBriefingInconclusiveKeepsUnknownsAndRecordedNextStep(t *testing.T) {
	withNext := func(next model.NextStepFacts) *model.OperatorDelta {
		return &model.OperatorDelta{Candidates: []model.MaterialCandidate{{
			Kind: model.CandidateInconclusiveCompletion,
			Finding: &model.FindingFacts{
				Observations: []string{"Pod events checked"},
				Unknowns:     []string{"Application errors unavailable"},
			},
			Next: next,
		}}}
	}

	ended := briefingInconclusiveLine(withNext(model.NextStepFacts{Kind: model.NextStepWorkEnded}))
	for _, want := range []string{"Pod events checked", "Application errors unavailable", "No further analysis retry is scheduled"} {
		if !strings.Contains(ended, want) {
			t.Errorf("inconclusive line lost %q: %s", want, ended)
		}
	}

	retrying := briefingInconclusiveLine(withNext(model.NextStepFacts{Kind: model.NextStepRetryEligible}))
	if strings.Contains(retrying, "No further analysis retry is scheduled") {
		t.Errorf("a recorded retry must not be denied: %s", retrying)
	}
	if !strings.Contains(retrying, "retry") {
		t.Errorf("a recorded retry must be stated: %s", retrying)
	}

	legacy := briefingInconclusiveLine(&model.OperatorDelta{})
	if legacy != "Analysis failed; coverage is incomplete." {
		t.Errorf("a delta with no candidate keeps the legacy wording: %s", legacy)
	}
}

// Lead decision D (round 2, 2026-09-09): an exhaustion whose attempt retained
// its result code but not the checks it ran must state that limit, never
// invent checked sources or claim what the evidence showed.
func TestBriefingInconclusiveStatesRetainedLimitWhenEvidenceUnknown(t *testing.T) {
	line := briefingInconclusiveLine(&model.OperatorDelta{Candidates: []model.MaterialCandidate{{
		Kind:    model.CandidateInconclusiveCompletion,
		Finding: &model.FindingFacts{IncidentID: "inc-x"},
		Outcome: &model.IncidentWorkOutcome{IncidentID: "inc-x", AttemptID: "a-5", Phase: model.WorkPhaseExhausted, ResultCode: "provider_error"},
		Next:    model.NextStepFacts{Kind: model.NextStepStatusCheck},
	}}})
	// briefingText escapes the underscore for mrkdwn safety; the code is
	// still legible, so match its stem.
	for _, want := range []string{"Investigation inconclusive", "result provider", "were not retained", "No further analysis retry is scheduled"} {
		if !strings.Contains(line, want) {
			t.Errorf("exhaustion line lost %q: %s", want, line)
		}
	}
	if strings.Contains(line, "did not establish a cause") || strings.Contains(line, "No supporting observations were recorded") {
		t.Errorf("unknown evidence must not be described as examined evidence: %s", line)
	}
}

// S4-08 (canonical slide 4, "Two different time promises"): a status
// checkpoint may happen quietly and is never a reply promise. "Update
// by"/"update overdue" wording is reserved for an actual enforceable
// notification commitment; nothing in this minimal renderer enforces one
// for the compact overview or its replies, so that vocabulary must never
// appear on the "Next status check:" line.
func TestBriefingNextStepStatusCheckIsNeverAPromise(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1}}`)
	root, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(root.Text, "Next status check:") {
		t.Fatalf("root lost the status checkpoint: %s", root.Text)
	}
	for _, bad := range []string{"update by", "update overdue"} {
		if strings.Contains(root.Text, bad) {
			t.Fatalf("root status checkpoint must never use promise wording %q: %s", bad, root.Text)
		}
	}

	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	journal, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(journal.Text, "Next status check:") {
		t.Fatalf("reply lost the status checkpoint: %s", journal.Text)
	}
	for _, bad := range []string{"update by", "update overdue"} {
		if strings.Contains(journal.Text, bad) {
			t.Fatalf("reply status checkpoint must never use promise wording %q: %s", bad, journal.Text)
		}
	}
}

// S1-04/S4-11: a closed_unknown outcome alone is not a concrete concern.
// Requesting an MCP/human-health check unconditionally for every
// closed_unknown invents a generic request the canonical slide explicitly
// forbids ("no generic MCP/human-health request without concrete concern").
// Only a recorded OperatorActionRequired earns one; the terminal line must
// say tracking ended, never an ambiguous "stopped".
func TestBriefingActionAndNextStepClosedUnknownWithoutConcreteConcern(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":0,"total":1,"resolved":1}}`)
	tr := in.SourceTransition
	tr.Lifecycle = model.LifecycleClosedUnknown
	tr.ActionContract.OperatorActionRequired = nil
	tr.ActionContract.AlertINTStatus = nil
	tr.ActionContract.NextUpdateAt = nil

	action := briefingAction(in.Summary.Briefing, tr)
	if strings.Contains(action, "check current service health") || strings.Contains(action, "via MCP") {
		t.Errorf("closed_unknown without a recorded action must not invent an MCP/health request: %s", action)
	}
	if !strings.Contains(strings.ToLower(action), "on-call") {
		t.Errorf("action has no audience: %s", action)
	}

	step := briefingNextStep(tr, in.Summary.Briefing, nil, in.Now)
	for _, want := range []string{"Recovery could not be confirmed", "tracking for this Situation has ended"} {
		if !strings.Contains(step, want) {
			t.Errorf("closed_unknown next step lost %q: %s", want, step)
		}
	}

	// A concrete recorded action still earns the MCP request.
	concreteAction := model.OperatorActionInvestigateSituation
	tr.ActionContract.OperatorActionRequired = &concreteAction
	action = briefingAction(in.Summary.Briefing, tr)
	if !strings.Contains(action, "via MCP") {
		t.Errorf("a recorded concrete action must still earn an MCP request: %s", action)
	}
}

// ----------------------------------------------------------------------
// G1 (lead final review 2026-09-10): the queued activity line must state a
// known readiness/due time or the actual waiting reason. Slide 2's queued
// example is "Analysis queued; eligible after [recorded readiness/due
// condition]. This is not an execution guarantee." Before this repair the
// line could only say the work had not started.
//
// P2-1/P2-3 (lead review of the final repairs, 2026-09-10): that repair
// then had to separate two facts the contract's single "planned" status
// collapses — an undecided schedule is not a queued request — and stop the
// earliest queued eligibility from dating every outstanding investigation.
// ----------------------------------------------------------------------

func TestBriefingQueuedLineStatesRecordedEligibility(t *testing.T) {
	eligible := rsMustTime(t, "2026-09-07T10:05:00Z") // after the fixture's 10:00 now
	past := rsMustTime(t, "2026-09-07T09:57:00Z")
	for _, tc := range []struct {
		name      string
		work      model.WorkProjection
		want      []string
		forbidden []string
	}{
		{
			name: "not yet eligible states the recorded time",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 1,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &eligible,
			},
			want: []string{"Investigation is queued; it has not started yet.", "It becomes eligible after <!date^1788775500^"},
		},
		{
			name: "already eligible says so as of the recorded time",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 1,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &past,
			},
			want: []string{"Investigation is queued; it has not started yet.", "It is eligible for a claim as of <!date^1788775020^"},
		},
		{
			name:      "queued with no recorded readiness time says that",
			work:      model.WorkProjection{Phase: model.WorkPhaseQueued, RemainingIncidents: 1, QueuedEligibilityKnown: true},
			want:      []string{"Investigation is queued; it has not started yet.", "No readiness time is recorded for it."},
			forbidden: []string{"eligible"},
		},
		{
			// Two outstanding schedules: the recorded time is the EARLIEST
			// of them, so an unqualified "it" would date work the record
			// never dated.
			name: "the earliest of several queued times is qualified as one of them",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 2,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &eligible,
			},
			want:      []string{"The earliest queued investigation becomes eligible after <!date^1788775500^"},
			forbidden: []string{"It becomes eligible"},
		},
		{
			name: "an already-reached earliest time speaks for one schedule",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 2,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &past,
			},
			want:      []string{"At least one queued investigation is eligible for a claim as of <!date^1788775020^"},
			forbidden: []string{"It is eligible for a claim"},
		},
		{
			name:      "several queued schedules with no recorded time say so of all of them",
			work:      model.WorkProjection{Phase: model.WorkPhaseQueued, RemainingIncidents: 2, QueuedEligibilityKnown: true},
			want:      []string{"No readiness time is recorded for any queued investigation."},
			forbidden: []string{"eligible", "recorded for it"},
		},
		{
			// The defect P2-1 names: "planned" covers both dispositions, and
			// reading it as queued asserted a request nothing committed —
			// then denied it in the very next clause.
			name:      "an undecided schedule states its wait and is never called queued",
			work:      model.WorkProjection{Phase: model.WorkPhaseAwaitingDecision, RemainingIncidents: 1, QueuedEligibilityKnown: true},
			want:      []string{"Awaiting an investigation decision; no request is committed yet."},
			forbidden: []string{"queued", "eligible"},
		},
		{
			// A transition predating the field recorded no eligibility at
			// all. Unknown is not "eligible now": the line claims nothing.
			name:      "a legacy projection claims nothing",
			work:      model.WorkProjection{Phase: model.WorkPhaseQueued, RemainingIncidents: 1},
			want:      []string{"Investigation is queued; it has not started yet. Next status check:"},
			forbidden: []string{"eligible"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1}}`)
			c := rsMonitoringContract(in.Now.Add(time.Minute))
			a, s := model.AlertINTActionRunAcuteTriage, model.AlertINTStatusPlanned
			c.AlertINTAction, c.AlertINTStatus, c.WaitReason = &a, &s, nil
			in.SourceTransition.ActionContract = c
			in.Summary.Briefing.Work = tc.work
			in.SourceTransition.Projection.Briefing = in.Summary.Briefing

			root, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := RenderSituationJournal(in.SourceTransition)
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range []string{root.Text, rsFallbackBlocksText(root), journal.Text} {
				for _, want := range tc.want {
					if !strings.Contains(out, want) {
						t.Errorf("queued line lacks %q:\n%s", want, out)
					}
				}
				for _, bad := range tc.forbidden {
					if strings.Contains(out, bad) {
						t.Errorf("queued line must not contain %q:\n%s", bad, out)
					}
				}
				// Eligibility is a claim time, never a promise that
				// execution or a reply happens then.
				for _, bad := range []string{"update by", "will start", "starts at"} {
					if strings.Contains(strings.ToLower(out), bad) {
						t.Errorf("queued line promises execution (%q):\n%s", bad, out)
					}
				}
			}
			// The status checkpoint is its own recorded time and must
			// survive beside the eligibility.
			if !strings.Contains(root.Text, "Next status check: <!date^1788775260^") {
				t.Errorf("eligibility replaced the status checkpoint:\n%s", root.Text)
			}
		})
	}
}

// TestBriefingRecoveryDisclosesQueuedEligibility covers the second place the
// same outstanding-work sentence appears: the disclosure a Situation
// confirming recovery carries. Leaving the recorded eligibility off this one
// would reproduce G1 on a different surface, and P2-2/P2-3 proved this
// surface owes the same undecided wait and the same aggregate qualification
// the activity line does.
func TestBriefingRecoveryDisclosesQueuedEligibility(t *testing.T) {
	eligible := rsMustTime(t, "2026-09-07T10:05:00Z")
	past := rsMustTime(t, "2026-09-07T09:57:00Z")
	for _, tc := range []struct {
		name      string
		work      model.WorkProjection
		want      []string
		forbidden []string
	}{
		{
			name: "one queued schedule discloses its own recorded eligibility",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 1,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &past,
			},
			want:      []string{"it has not started yet. It is eligible for a claim as of <!date^1788775020^"},
			forbidden: []string{"In total"},
		},
		{
			name: "beside more outstanding work the earliest time speaks for one schedule",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 2,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &past,
			},
			want: []string{
				"At least one queued investigation is eligible for a claim as of <!date^1788775020^",
				"In total, 2 member investigations have outstanding work.",
			},
			forbidden: []string{"It is eligible for a claim"},
		},
		{
			name: "a future earliest time is qualified the same way",
			work: model.WorkProjection{
				Phase: model.WorkPhaseQueued, RemainingIncidents: 2,
				QueuedEligibilityKnown: true, QueuedEligibleAt: &eligible,
			},
			want:      []string{"The earliest queued investigation becomes eligible after <!date^1788775500^"},
			forbidden: []string{"It becomes eligible"},
		},
		{
			name: "an undecided schedule discloses the decision it waits on",
			work: model.WorkProjection{
				Phase: model.WorkPhaseAwaitingDecision, RemainingIncidents: 2,
				QueuedEligibilityKnown: true,
			},
			want: []string{
				"Investigation work is still outstanding. Awaiting an investigation decision; no request is committed yet.",
				"In total, 2 member investigations have outstanding work.",
			},
			forbidden: []string{"eligible", "queued"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":0,"total":2,"resolved":2}}`)
			in.SourceTransition.ActionContract = rsMonitoringContract(in.Now.Add(time.Minute))
			in.Summary.Briefing.Work = tc.work
			in.SourceTransition.Projection.Briefing = in.Summary.Briefing

			root, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range []string{root.Text, rsFallbackBlocksText(root)} {
				if !strings.Contains(out, "Watching for sustained recovery") {
					t.Fatalf("lost the recovery sentence:\n%s", out)
				}
				for _, want := range tc.want {
					if !strings.Contains(out, want) {
						t.Errorf("recovery disclosure lacks %q:\n%s", want, out)
					}
				}
				for _, bad := range tc.forbidden {
					if strings.Contains(out, bad) {
						t.Errorf("recovery disclosure must not contain %q:\n%s", bad, out)
					}
				}
			}
		})
	}
}

// TestBriefingWorkReadsTheBuiltProjectionNotTheContract drives the same three
// repairs through the REAL projection builder rather than a hand-written
// WorkProjection, which is what the lead's saved probes at f2871df did: the
// defects were only visible because BuildWorkProjection's own output, fed to
// these renderers, contradicted itself. Wording is asserted semantically —
// what the sentence may and may not claim — so the copy can be revised
// without silently losing the fact.
func TestBriefingWorkReadsTheBuiltProjectionNotTheContract(t *testing.T) {
	now := rsMustTime(t, "2026-09-10T12:00:00Z")
	early, late := now.Add(time.Minute), now.Add(time.Hour)
	planned := func(w model.WorkProjection) string {
		a, s := model.AlertINTActionRunAcuteTriage, model.AlertINTStatusPlanned
		return briefingWork(model.ActionContract{AlertINTAction: &a, AlertINTStatus: &s}, &model.OperatorBriefing{Work: w}, now)
	}

	t.Run("an undecided schedule is not a queued request", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "undecided", Triage: situation.TriageState{Phase: "awaiting_decision"}},
		}, nil, nil)
		if w.Phase != model.WorkPhaseAwaitingDecision {
			t.Fatalf("fixture built phase %s, want awaiting_decision", w.Phase)
		}
		for _, got := range []string{planned(w), briefingOutstandingWork(&model.OperatorBriefing{Work: w}, now)} {
			if strings.Contains(got, "queued") {
				t.Errorf("no request is committed, but the line claims a queue:\n%s", got)
			}
			if !strings.Contains(strings.ToLower(got), "decision") {
				t.Errorf("the recorded waiting reason is missing:\n%s", got)
			}
		}
	})

	t.Run("the earliest of two queued times never dates both", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "early", Triage: situation.TriageState{Phase: "pending", NextAt: &early}},
			{ID: "late", Triage: situation.TriageState{Phase: "pending", NextAt: &late}},
		}, nil, nil)
		if w.QueuedEligibleAt == nil || !w.QueuedEligibleAt.Equal(early) || w.RemainingIncidents != 2 {
			t.Fatalf("fixture built %+v, want the earlier time and two outstanding", w)
		}
		for _, got := range []string{planned(w), briefingOutstandingWork(&model.OperatorBriefing{Work: w}, now)} {
			if !strings.Contains(got, "earliest") && !strings.Contains(got, "At least one") {
				t.Errorf("the earliest time is presented as aggregate eligibility:\n%s", got)
			}
			if strings.Contains(got, SlackDateToken(late, "{time}")) {
				t.Errorf("only the earliest queued time is a recorded projection fact:\n%s", got)
			}
		}
	})

	t.Run("one queued schedule still states its own recorded eligibility", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "only", Triage: situation.TriageState{Phase: "pending", NextAt: &early}},
		}, nil, nil)
		for _, got := range []string{planned(w), briefingOutstandingWork(&model.OperatorBriefing{Work: w}, now)} {
			if !strings.Contains(got, SlackDateToken(early, "{time}")) {
				t.Errorf("a single queued schedule lost its recorded eligibility:\n%s", got)
			}
			if !strings.Contains(got, "not an execution guarantee") {
				t.Errorf("eligibility must never read as a start promise:\n%s", got)
			}
		}
	})
}

// ----------------------------------------------------------------------
// Mixed queued/back-off work (lead renderer review 2026-09-10, contract
// §59): aggregateWorkPhase ranks a queued schedule above retry_wait once
// some other member schedule has executed, so the queued phase also covers
// a Situation whose immutable attempts ledger records a claimed attempt.
// Both work surfaces denied that execution ever happened.
//
// ExecutionStarted is a past fact, so withdrawing the denial may not become
// a claim that work is running now — and nothing needs to replace it, since
// executing outranks queued in that same aggregation.
// ----------------------------------------------------------------------

func TestBriefingQueuedWorkDoesNotDenyRecordedExecution(t *testing.T) {
	now := rsMustTime(t, "2026-09-10T12:00:00Z")
	due := now.Add(time.Minute)
	planned := func(w model.WorkProjection) string {
		a, s := model.AlertINTActionRunAcuteTriage, model.AlertINTStatusPlanned
		return briefingWork(model.ActionContract{AlertINTAction: &a, AlertINTStatus: &s}, &model.OperatorBriefing{Work: w}, now)
	}
	surfaces := func(w model.WorkProjection) map[string]string {
		return map[string]string{
			"activity": planned(w),
			"recovery": briefingOutstandingWork(&model.OperatorBriefing{Work: w}, now),
		}
	}

	t.Run("a queued schedule beside a back-off one denies no recorded attempt", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "queued", Triage: situation.TriageState{Phase: "pending", NextAt: &due}},
			{ID: "retry", Triage: situation.TriageState{Phase: "backoff", Attempts: 1, NextAt: &due}},
		}, nil, nil)
		if !w.ExecutionStarted || w.Phase != model.WorkPhaseQueued || w.RemainingIncidents != 2 {
			t.Fatalf("fixture built %+v, want a queued aggregate with a recorded attempt and two outstanding", w)
		}
		for surface, got := range surfaces(w) {
			if strings.Contains(got, "has not started yet") {
				t.Errorf("%s surface denies the attempt the ledger records:\n%s", surface, got)
			}
			// Withdrawing the denial is not permission to assert the
			// opposite: the queued aggregate proves nothing is in flight.
			for _, bad := range []string{"is running", "Investigating", "still running"} {
				if strings.Contains(got, bad) {
					t.Errorf("%s surface claims current execution from a past fact (%q):\n%s", surface, bad, got)
				}
			}
			if !strings.Contains(got, "The earliest queued investigation becomes eligible after "+SlackDateToken(due, "{time}")) {
				t.Errorf("%s surface lost the qualified queued eligibility:\n%s", surface, got)
			}
		}
		if got := surfaces(w)["recovery"]; !strings.Contains(got, "Investigation work is still outstanding.") ||
			!strings.Contains(got, "In total, 2 member investigations have outstanding work.") {
			t.Errorf("the recovery surface lost its outstanding-work statement:\n%s", got)
		}
		if got := surfaces(w)["activity"]; !strings.Contains(got, "Investigation is queued.") {
			t.Errorf("the activity surface lost the queued statement:\n%s", got)
		}
	})

	t.Run("work that has never executed still says it has not started", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "queued", Triage: situation.TriageState{Phase: "pending", NextAt: &due}},
		}, nil, nil)
		if w.ExecutionStarted || w.Phase != model.WorkPhaseQueued {
			t.Fatalf("fixture built %+v, want a queued aggregate with no recorded attempt", w)
		}
		for surface, got := range surfaces(w) {
			if !strings.Contains(got, "it has not started yet.") {
				t.Errorf("%s surface dropped a true not-started statement:\n%s", surface, got)
			}
			if !strings.Contains(got, SlackDateToken(due, "{time}")) {
				t.Errorf("%s surface lost the recorded eligibility:\n%s", surface, got)
			}
		}
	})

	t.Run("one queued schedule that already claimed an attempt keeps its own time", func(t *testing.T) {
		w := situation.BuildWorkProjection([]situation.IncidentState{
			{ID: "requeued", Triage: situation.TriageState{Phase: "pending", Attempts: 1, NextAt: &due}},
		}, nil, nil)
		if !w.ExecutionStarted || w.RemainingIncidents != 1 {
			t.Fatalf("fixture built %+v, want one outstanding schedule with a recorded attempt", w)
		}
		for surface, got := range surfaces(w) {
			if strings.Contains(got, "has not started yet") {
				t.Errorf("%s surface denies this schedule's own recorded attempt:\n%s", surface, got)
			}
			if !strings.Contains(got, "It becomes eligible after "+SlackDateToken(due, "{time}")) {
				t.Errorf("%s surface lost the single schedule's recorded eligibility:\n%s", surface, got)
			}
		}
	})
}

// TestBriefingRecoveryWithStartedWorkKeepsItsOwnTimes renders the mixed case
// through the whole message rather than the two helpers, because the review
// requires the grace deadline and the status checkpoint — both independent
// of the work phase — to survive the correction on the rendered surface.
func TestBriefingRecoveryWithStartedWorkKeepsItsOwnTimes(t *testing.T) {
	now := rsMustTime(t, "2026-09-07T10:00:00Z")
	due := now.Add(5 * time.Minute)
	grace := now.Add(10 * time.Minute)
	w := situation.BuildWorkProjection([]situation.IncidentState{
		{ID: "queued", Triage: situation.TriageState{Phase: "pending", NextAt: &due}},
		{ID: "retry", Triage: situation.TriageState{Phase: "backoff", Attempts: 1, NextAt: &due}},
	}, &grace, nil)

	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":0,"total":2,"resolved":2}}`)
	in.SourceTransition.ActionContract = rsMonitoringContract(in.Now.Add(time.Minute))
	in.Summary.Briefing.Work = w
	in.SourceTransition.Projection.Briefing = in.Summary.Briefing

	root, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{root.Text, rsFallbackBlocksText(root)} {
		if strings.Contains(out, "has not started yet") {
			t.Errorf("the rendered surface denies the recorded attempt:\n%s", out)
		}
		for _, want := range []string{
			"Watching for sustained recovery through " + SlackDateToken(grace, "{time}"),
			"Investigation work is still outstanding.",
			"The earliest queued investigation becomes eligible after " + SlackDateToken(due, "{time}"),
			"In total, 2 member investigations have outstanding work.",
			"Next status check: <!date^1788775260^",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rendered surface lacks %q:\n%s", want, out)
			}
		}
	}
}
