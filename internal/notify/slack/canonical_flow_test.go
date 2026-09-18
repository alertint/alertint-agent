// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func canonicalFixture(t *testing.T) *model.OperatorBriefing {
	t.Helper()
	var b model.OperatorBriefing
	err := json.Unmarshal([]byte(`{
 "scope":"payments · lab","display_scope":"payments · lab","firing":3,"total":3,
 "alerts":[{"id":"p","name":"ServiceErrorRateHigh · payment","state":"firing"},{"id":"c","name":"ServiceErrorRateHigh · checkout","state":"firing"},{"id":"db","name":"DatabaseUnavailable · payments-db","state":"firing"}],
 "work":{"phase":"collecting"},
 "flow":{"first_received_at":"2026-09-09T09:59:50Z","correlation_opened_at":"2026-09-09T09:59:50Z","correlation_closes_at":"2026-09-09T10:00:20Z","group_key":"environment=lab,dependency_group=payments","grouping_rule":"Same environment and configured dependency group"}
 }`), &b)
	if err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestCanonicalRootShowsExpectedJudgmentAfterFinding(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "Reconciliation job is driving CPU load", Summary: "Sustained CPU load on db-prod-1.", Findings: []string{"CPU load remains elevated on db-prod-1."}, Verification: "supported"}}
	until := bcNow(t).Add(time.Hour)
	b.ExpectedJudgment = &model.ExpectedJudgmentProjection{Revision: 2, AssertedOperator: "Janis", ValidUntil: until}
	in := bcRoot(t, model.LifecycleActive, model.AttentionInvestigate, bcObserveMonitorContract(bcNow(t)), b)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "*Operator:* Expected until " + SlackDateToken(until, "{time}") + " · Janis"
	if !strings.Contains(msg.Text, want) {
		t.Fatalf("root missing %q:\n%s", want, msg.Text)
	}
	titleAt := strings.Index(msg.Text, "Monitoring · payments · lab")
	statusAt := strings.Index(msg.Text, "Observed · Correlating")
	findingAt := strings.Index(msg.Text, "*Finding:*")
	operatorAt := strings.Index(msg.Text, "*Operator:*")
	if !(titleAt >= 0 && titleAt < statusAt && statusAt < findingAt && findingAt < operatorAt) {
		t.Fatalf("root order title=%d status=%d finding=%d operator=%d:\n%s", titleAt, statusAt, findingAt, operatorAt, msg.Text)
	}
}

func TestExpectedJudgmentThreadTransitionsAreAttributedAndTruthful(t *testing.T) {
	b := canonicalFixture(t)
	until := bcNow(t).Add(time.Hour)
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	tr.Journal.JudgmentChange = model.JudgmentChangeRecorded
	tr.Journal.AttributedActor = "Janis"
	tr.Journal.JudgmentValidUntil = &until
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	want := "Janis marked the current condition as expected until " + SlackDateToken(until, "{time}") + ". Monitoring continues."
	if !strings.Contains(msg.Text, want) {
		t.Fatalf("thread = %q, want %q", msg.Text, want)
	}

	tr.Journal.JudgmentChange = model.JudgmentChangeRevoked
	tr.Journal.JudgmentValidUntil = nil
	msg, err = RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "Janis withdrew expectedness. Normal assessment resumes.") {
		t.Fatal(msg.Text)
	}

	action := model.OperatorActionInvestigateSituation
	tr.ActionContract.NextActor = model.NextActorOperator
	tr.ActionContract.OperatorActionRequired = &action
	msg, err = RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "Operator action required: investigate this Situation.") {
		t.Fatalf("withdrawal handoff = %q, want the resumed operator action", msg.Text)
	}
}

// Losing the phase, names or receipt clock makes distinct incidents indistinguishable.
func TestCanonicalRootCorrelationHasMembershipAndDeterministicClocks(t *testing.T) {
	b := canonicalFixture(t)
	in := bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b)
	in.Summary.EffectiveStartedAt = in.Now.Add(-42 * time.Second)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Correlating · payments · lab", "Observed · *▸ Correlating* · Investigating · Monitoring · Confirming recovery · Recovered", "ServiceErrorRateHigh · payment", "ServiceErrorRateHigh · checkout", "DatabaseUnavailable · payments-db", "*Alert age:* 42s", "*Since first receipt:* 10s", "Start investigation in ~20s")
	for _, unwanted := range []string{"Grouping rule:", "Sources:", "Duration:", "Cause not confirmed", "Hypothesis:"} {
		if strings.Contains(msg.Text, unwanted) {
			t.Errorf("root repeats detail %q: %s", unwanted, msg.Text)
		}
	}
}

// A root's terminal age must not keep increasing each time its delivery is retried.
func TestCanonicalRecoveredFreezesClocksRetainsResultAndUsage(t *testing.T) {
	b := canonicalFixture(t)
	b.Firing = 0
	b.Resolved = 3
	b.Work.Phase = model.WorkPhaseSettled
	for i := range b.Alerts {
		b.Alerts[i].State = "resolved"
	}
	b.Analyses = []model.IncidentAnalysis{{Title: "Database connection failures affected payment and checkout", Summary: "Requests failed while connecting to payments-db.", Verification: "supported"}}
	b.Flow.FirstReceivedAt = time.Date(2026, 9, 9, 9, 58, 15, 0, time.UTC)
	started := b.Flow.FirstReceivedAt.Add(30 * time.Second)
	completed := started.Add(20 * time.Second)
	b.Flow.InvestigationStartedAt = &started
	b.Flow.InvestigationCompletedAt = &completed
	b.Flow.AnalysisUsage = model.AnalysisUsage{Calls: 4, CallsKnown: true, InputTokens: 12400, InputTokensKnown: true, OutputTokens: 1850, OutputTokensKnown: true}
	in := bcRoot(t, model.LifecycleRecovered, model.AttentionUrgent, rsTerminalContract(), b)
	in.SourceTransition.Projection.Assessment.Causality = model.CausalitySupported
	in.Summary.EffectiveStartedAt = in.Now.Add(-115 * time.Second)
	in.Now = in.Now.Add(time.Hour)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Recovered · payments · lab — Database connection failures affected payment and checkout", "Recovery confirmed · 1m45s after first receipt", "Requests failed while connecting", "*MCP:*")
	for _, unwanted := range []string{"monitoring for this episode has ended", "Cause not confirmed", "Duration:", "Sources:"} {
		if strings.Contains(msg.Text, unwanted) {
			t.Errorf("unexpected recovered root content %q", unwanted)
		}
	}
}

// A weak model explanation must not become a causal claim when its disclaimer is removed.
func TestCanonicalFindingDoesNotPromoteUnsupportedCausality(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "Expired key caused all failures", Summary: "An expired key caused all failures.", Observations: []string{"Payment log sample: invalid token"}, Verification: "degraded"}}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment log sample: invalid token")
	for _, bad := range []string{"expired key", "Expired key", "Cause not confirmed", "Open question:"} {
		if strings.Contains(msg.Text, bad) {
			t.Errorf("unsupported assertion %q: %s", bad, msg.Text)
		}
	}
}

// The analysis result and next step must survive long evidence and empty sources.
func TestCanonicalAnalysisReplyOrdersResultsBeforeSourceDetails(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "Database connections refused", Summary: "Requests failed while connecting to payments-db.", Verification: "supported", Observations: []string{"Payment failed-request sample: connection refused"}}}
	b.Flow.SourceChecks = []model.SourceCheck{
		{Source: "Prometheus", Check: "errors by customer tier", Outcome: model.SourceCheckEmpty, Calls: 1, CallsKnown: true, RecordsKnown: true, Detail: "Query succeeded; 0 series matched. No retry scheduled."},
		{Source: "Loki", Check: "failed requests", Outcome: model.SourceCheckReturned, Calls: 2, CallsKnown: true, Records: 400, RecordsKnown: true, Detail: "400 log lines returned; selected samples reviewed."},
		{Source: "Zabbix", Check: "database availability", Outcome: model.SourceCheckFailed, Calls: 2, CallsKnown: true, Detail: "Unreachable after 2 attempts; no retry scheduled."},
		{Source: "Changes", Check: "deployment history", Outcome: model.SourceCheckSkipped, CallsKnown: true, Detail: "Disabled for lab."},
	}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	tr.Projection.Assessment.Causality = model.CausalitySupported
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "🔴 Analysis completed", "*Finding:*", "*Checks:*", "errors by customer tier", "0 series matched", "Loki", "400", "Unreachable after 2 attempts", "Changes", "Disabled for lab", "Monitoring alert changes.", "*Since first receipt:*")
	if strings.Index(msg.Text, "*Finding:*") > strings.Index(msg.Text, "*Checks:*") {
		t.Fatal("evidence precedes result")
	}
	for _, bad := range []string{"Causality remains unproven", "Cause not confirmed", "Open question:", "Duration:", "…"} {
		if strings.Contains(msg.Text, bad) {
			t.Errorf("unwanted %q", bad)
		}
	}
}

// Successful background log lines must not replace the recorded failing symptom.
func TestCanonicalFindingKeepsFailureSymptomWhenSamplesAreRoutine(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Alerts[0].SourceSummary = "Payment error ratio 50% over 1 minute"
	b.Analyses = []model.IncidentAnalysis{{Title: "Token failure", Summary: "A shared key must have expired.", Observations: []string{"order confirmation email sent"}, Verification: "degraded"}}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "*Alert reported:* Payment error ratio 50% over 1 minute")
	if strings.Contains(msg.Text, "order confirmation email sent") {
		t.Fatal(msg.Text)
	}
}

// Two durable effects on one transition must remain distinct operator developments.
func TestCanonicalSplitRepliesKeepAnalysisSeparateFromClearance(t *testing.T) {
	b := canonicalFixture(t)
	b.Firing = 0
	b.Resolved = 3
	b.Work.Phase = model.WorkPhaseSettled
	for i := range b.Alerts {
		b.Alerts[i].State = "resolved"
	}
	b.Analyses = []model.IncidentAnalysis{{IncidentID: "i", Summary: "Database request failed: connection refused", Verification: "supported"}}
	in := bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, bcObserveMonitorContract(bcNow(t)), b)
	tr := in.SourceTransition
	tr.Projection.Assessment.Causality = model.CausalitySupported
	tr.Projection.OperatorDelta = &model.OperatorDelta{Analyses: b.Analyses, StateChanged: true, PreviousFiring: 3}
	analysis, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyAnalysisCompleted})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyRecoveryObserved})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, analysis, "Analysis completed", "connection refused")
	bcBothSurfaces(t, recovery, "Recovery observed", "ServiceErrorRateHigh · payment", "DatabaseUnavailable · payments-db")
	if strings.Contains(recovery.Text, "*Finding:*") || strings.Contains(recovery.Text, "connection refused") {
		t.Fatal("analysis repeated inside clearance", recovery.Text)
	}
	if strings.Contains(analysis.Text, "*Resolved:*") {
		t.Fatal("clearance mixed into analysis", analysis.Text)
	}
}

func TestCanonicalUniqueAlertRetainsServiceIdentity(t *testing.T) {
	b := canonicalFixture(t)
	raw := `[{"id":"db","name":"DatabaseUnavailable","context":"payments-db","state":"firing"}]`
	if err := json.Unmarshal([]byte(raw), &b.Alerts); err != nil {
		t.Fatal(err)
	}
	b.Total = 1
	b.Firing = 1
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "DatabaseUnavailable · payments-db")
}

// Splitting a failed completion must preserve its failure and retry disposition.
func TestCanonicalAnalysisReplyPreservesInconclusiveOutcome(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseExhausted
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, &model.OperatorDelta{AnalysisFailed: true})
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyAnalysisCompleted})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Analysis failed")
	if strings.Contains(msg.Text, "🔴 Analysis completed") {
		t.Fatal("failed attempt labeled completed analysis", msg.Text)
	}
}

func TestCanonicalSupportedVerificationIsNotCausalAuthority(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "Expired key caused all failures", Summary: "An expired key caused all failures.", Observations: []string{"Payment log sample: invalid token"}, Verification: "supported"}}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment log sample: invalid token")
	if strings.Contains(msg.Text, "expired key") || strings.Contains(msg.Text, "Expired key") {
		t.Fatal(msg.Text)
	}
}

func TestCanonicalCompleteLongFindingSurvivesInThread(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	long := strings.Repeat("Recorded failed connections to payments-db with retry errors; ", 10) + "FINAL SUPPORTED MECHANISM."
	b.Analyses = []model.IncidentAnalysis{{Title: "Database connections refused", Summary: long, Verification: "supported"}}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	tr.Projection.Assessment.Causality = model.CausalitySupported
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "FINAL SUPPORTED MECHANISM.")
}

func TestCanonicalStartNamesActualFrozenInputs(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseExecuting
	b.Work.InvestigatedNames = []string{"OldAlert · old-service"}
	b.Work.InvestigatedCount = 1
	b.Work.InvestigatedCountKnown = true
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyInvestigationStarted})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "*Investigated inputs:*", "OldAlert · old-service")
}

func TestCanonicalRecoveryNamesNewAndPriorClearance(t *testing.T) {
	b := canonicalFixture(t)
	b.Firing = 0
	b.Resolved = 3
	for i := range b.Alerts {
		b.Alerts[i].State = "resolved"
	}
	tr := bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, bcObserveMonitorContract(bcNow(t)), b).SourceTransition
	tr.Projection.OperatorDelta = &model.OperatorDelta{StateChanged: true, PreviousFiring: 2, ClearedAlerts: []string{"ServiceErrorRateHigh · payment", "ServiceErrorRateHigh · checkout"}}
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyRecoveryObserved})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "🔹 ServiceErrorRateHigh · payment · just recovered", "🔹 ServiceErrorRateHigh · checkout · just recovered", "🔹 DatabaseUnavailable · payments-db · resolved earlier")
}

func TestCanonicalRootCountsUnobservedMembers(t *testing.T) {
	b := canonicalFixture(t)
	b.Firing = 0
	b.Total = 1
	b.Unknown = 1
	b.Alerts = []model.BriefingAlert{{Name: "Missing source state", State: "unknown"}}
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionObserve, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "1 unobserved")
}

func TestCanonicalObservedFindingSurvivesUnknownCause(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Title: "An expired key caused failures", Summary: "An expired key caused failures.", Findings: []string{"Payment logs recorded invalid-token rejections for failed requests."}, Verification: "supported"}}
	tr := bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b)
	msg, err := RenderSituationRoot(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment logs recorded invalid-token rejections for failed requests.")
	if strings.Contains(msg.Text, "expired key") {
		t.Fatal(msg.Text)
	}
	journal, err := RenderSituationJournal(tr.SourceTransition)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, journal, "Payment logs recorded invalid-token rejections for failed requests.")
}

func TestCanonicalFrozenScopeDoesNotBorrowNewLabel(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseExecuting
	b.Work.InvestigatedAlertIDs = []string{"p"}
	b.Work.InvestigatedNames = []string{"Prior payment alert name"}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyInvestigationStarted})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "*Investigated inputs:* Prior payment alert name")
}

// A verified causal conclusion leads the reply without a second label that
// presents a paraphrase of the observed failure as additional explanation.
func TestCanonicalAnalysisIntegratesSupportedCauseWithoutDuplicateLabel(t *testing.T) {
	for _, example := range []struct{ summary, observation string }{
		{"Payment requests failed because database connections were refused.", "Payment requests failed connecting to the database."},
		{"An expired signing key rejected payment tokens after rotation.", "Payment logs recorded invalid-token rejections."},
	} {
		t.Run(example.summary, func(t *testing.T) {
			summary := example.summary
			b := canonicalFixture(t)
			b.Work.Phase = model.WorkPhaseSettled
			b.Analyses = []model.IncidentAnalysis{{Summary: summary, Findings: []string{example.observation}, Verification: "supported"}}
			tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
			tr.Projection.Assessment.Causality = model.CausalitySupported
			msg, err := RenderSituationJournal(tr)
			if err != nil {
				t.Fatal(err)
			}
			bcBothSurfaces(t, msg, "*Finding:* "+summary, example.observation)
			if strings.Contains(msg.Text, "*Cause:*") {
				t.Fatal("supported conclusion duplicated under a separate cause label")
			}
		})
	}
}

func TestCanonicalMultipleAnalysesDoNotShareCausalAuthorization(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{
		{IncidentID: "a", Summary: "An expired signing key caused failures.", Findings: []string{"Payment logs recorded invalid-token rejections."}, Verification: "supported"},
		{IncidentID: "b", Summary: "A database restart caused failures.", Findings: []string{"Checkout logs recorded connection refusals."}, Verification: "supported"},
	}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	tr.Projection.Assessment.Causality = model.CausalitySupported
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment logs recorded invalid-token rejections.", "Checkout logs recorded connection refusals.")
	for _, a := range b.Analyses {
		if strings.Contains(msg.Text, a.Summary) {
			t.Errorf("global assessment promoted unrelated hypothesis: %s", a.Summary)
		}
	}
}
