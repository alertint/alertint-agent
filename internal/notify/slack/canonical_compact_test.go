// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Presentation must preserve source failures and retry facts while removing duplicate outcomes.
func TestCompactSourceOutcomes(t *testing.T) {
	checks := []model.SourceCheck{
		{Source: "Changes", Check: "collection", Outcome: model.SourceCheckEmpty, RecordsKnown: true, CallsKnown: true, Calls: 1, Detail: "no changes in window"},
		{Source: "Loki", Check: "collection", Outcome: model.SourceCheckConfigured, Detail: "Configured; awaiting collection result"},
		{Source: "Prometheus", Check: "error rate", Outcome: model.SourceCheckEmpty, Detail: "(no data)"},
		{Source: "Zabbix", Check: "availability", Outcome: model.SourceCheckFailed, CallsKnown: true, Calls: 2, Detail: "Unreachable; retry at 12:30"},
	}
	got := strings.Join(canonicalSourceLines(checks), "\n")
	for _, want := range []string{"✓ *Changes:* query succeeded · no records in the checked window", "· *Loki:* awaiting results", "∅ *Prometheus — error rate:* query succeeded · empty result", "✕ *Zabbix — availability:* query failed · 2 attempts · Unreachable; retry at 12:30"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
	for _, bad := range []string{"— collection", "configured", "0 matches", "1 calls"} {
		if strings.Contains(got, bad) {
			t.Errorf("noise %q: %s", bad, got)
		}
	}
}

// Losing the lead activity under Slack's evidence limit conceals the actual next action.
func TestCompactAnalysisActivitySurvivesOversizedEvidence(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Observations: []string{"Payment request failed: invalid token", strings.Repeat("large evidence ", 12000)}}}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyAnalysisCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(msg.Text, "Monitoring") > strings.Index(msg.Text, "*Finding:*") {
		t.Fatal("activity buried after evidence")
	}
	bcBothSurfaces(t, msg, "Monitoring", "Next status check")
	if len(msg.Blocks) > 50 {
		t.Fatalf("too many blocks: %d", len(msg.Blocks))
	}
}

// The same observation is not both a conclusion and its own duplicated supporting evidence.
func TestCompactFindingAndEvidence(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseSettled
	b.Analyses = []model.IncidentAnalysis{{Observations: []string{"Log sample at 2026-09-17 16:51:32 UTC: Payment request failed. Invalid token. demo.user_context.loyalty_level=gold"}}}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyAnalysisCompleted})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "Payment request failed. Invalid token.")
	for _, bad := range []string{"loyalty_level", "cause remains unconfirmed", "Cause not confirmed"} {
		if strings.Contains(msg.Text, bad) {
			t.Errorf("noise %q", bad)
		}
	}
	if strings.Count(msg.Text, "Payment request failed. Invalid token.") != 1 {
		t.Fatal("observation repeated", msg.Text)
	}
}

func TestCompactPendingRootHasNoEmptyFinding(t *testing.T) {
	b := canonicalFixture(t)
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.Text, "*Finding:*") || strings.Contains(msg.Text, "*Cause:*") {
		t.Fatal(msg.Text)
	}
}

func TestCompactRecoveredMovesMetadataToReply(t *testing.T) {
	b := canonicalFixture(t)
	b.Firing = 0
	b.Resolved = 3
	b.Work.Phase = model.WorkPhaseSettled
	b.Flow.AnalysisUsage = model.AnalysisUsage{CallsKnown: true, Calls: 2}
	started := b.Flow.FirstReceivedAt
	b.Flow.InvestigationStartedAt = &started
	in := bcRoot(t, model.LifecycleRecovered, model.AttentionObserve, rsTerminalContract(), b)
	root, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(root.Text, "Analysis usage") || strings.Contains(root.Text, "Alert age at closure") {
		t.Fatal("metadata still on root", root.Text)
	}
	reply, err := RenderSituationReply(SituationReplyInput{Transition: in.SourceTransition, ReplyKind: model.ReplyRecovered})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, reply, "*Alert age at closure:*", "2 calls", "unavailable", "*MCP:*")
	// Thread details use normal text; only the channel overview is visually secondary.
	for _, block := range reply.Blocks {
		raw, err := json.Marshal(block)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "Analysis usage") && block.BlockType() != "section" {
			t.Fatal("usage is not normal section text", string(raw))
		}
	}
}

func TestCompactCanonicalSupersededStartRetainsFrozenScope(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseExecuting
	b.Work.InvestigatedNames = []string{"OldAlert · old-service"}
	b.Work.InvestigatedCountKnown = true
	b.Work.InvestigatedCount = 1
	tr := bcJournal(t, rsRunningTriageContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyInvestigationStarted, ExecutionSuperseded: true})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "OldAlert · old-service", supersededExecutionStep)
}

func TestCompactChecksDoNotMergeDifferentOrUnknownScopes(t *testing.T) {
	checks := []model.SourceCheck{
		{Source: "Verification", Kind: "incidents_in_window", Check: "first rationale", QueryScope: "same", Outcome: model.SourceCheckReturned, Detail: "checkout alert (60m)"},
		{Source: "Verification", Kind: "incidents_in_window", Check: "second rationale", QueryScope: "same", Outcome: model.SourceCheckReturned, Detail: "checkout alert (60m)"},
		{Source: "Verification", Kind: "incidents_in_window", Check: "different window", QueryScope: "different", Outcome: model.SourceCheckReturned, Detail: "checkout alert (10m)"},
		{Source: "Verification", Kind: "incidents_in_window", Check: "legacy one", Outcome: model.SourceCheckReturned, Detail: "checkout alert"},
		{Source: "Verification", Kind: "incidents_in_window", Check: "legacy two", Outcome: model.SourceCheckReturned, Detail: "checkout alert"},
	}
	got := strings.Join(canonicalSourceLines(checks), "\n")
	if strings.Count(got, "checkout alert") != 4 {
		t.Fatal("incorrect scope consolidation", got)
	}
	if strings.Contains(got, "rationale") || !strings.Contains(got, "Other alerts") {
		t.Fatal("model rationale used as label", got)
	}
}

func TestCompactRecoveryKeepsDistinctDeadlinesAndDeferredExplanation(t *testing.T) {
	b := canonicalFixture(t)
	grace := bcNow(t).Add(30 * time.Second)
	b.Work.SourceGraceUntil = &grace
	b.BlockedReason = "policy_rejected"
	in := bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, bcObserveMonitorContract(grace), b)
	for _, delta := range []time.Duration{0, 10 * time.Second} {
		check := grace.Add(delta)
		in.SourceTransition.ActionContract.NextUpdateAt = &check
		got := compactRecoveryDeadline("Watching for sustained recovery through "+SlackDateToken(grace, "{time}")+". Deferred explanation unchanged. Next status check: "+SlackDateToken(check, "{time}")+".", in.SourceTransition, b)
		if !strings.Contains(got, "Deferred explanation unchanged.") || !strings.Contains(got, SlackDateToken(grace, "{time_secs}")) {
			t.Fatal(got)
		}
		if delta != 0 && !strings.Contains(got, SlackDateToken(check, "{time}")) {
			t.Fatal("lost separate checkpoint", got)
		}
		if delta == 0 && strings.Contains(got, "Next status check:") {
			t.Fatal("duplicate deadline", got)
		}
	}
}

func TestCompactRunningScopeIsStatedOnceForMultipleInputs(t *testing.T) {
	b := canonicalFixture(t)
	b.Work.Phase = model.WorkPhaseExecuting
	b.Work.InvestigatedNames = []string{"ErrorRate · payment", "Latency · checkout"}
	b.Work.InvestigatedCountKnown = true
	b.Work.InvestigatedCount = 2
	tr := bcJournal(t, rsRunningTriageContract(bcNow(t)), b, nil)
	msg, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyInvestigationStarted})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range b.Work.InvestigatedNames {
		if strings.Count(msg.Text, name) != 1 {
			t.Fatal("scope repeated or lost", msg.Text)
		}
	}
	bcBothSurfaces(t, msg, "2 alerts")
}

func TestCompactLogExcerptKeepsDiagnosticMessageWithoutAttributeTail(t *testing.T) {
	got := compactObservation("Log sample at 2026-09-17 16:51:32 UTC: Connection refused to db-primary. customer_tier=gold request_id=123")
	if got != "Log sample: Connection refused to db-primary." {
		t.Fatal(got)
	}
	// A structured identifier inside the message is not a metadata-only tail.
	withID := "Log sample at 2026-09-17 16:51:32 UTC: Connection to host=db-primary failed."
	if !strings.Contains(compactObservation(withID), "host=db-primary") {
		t.Fatal("diagnostic identifier lost")
	}
	observation := "Failures were observed for customer_tier=gold"
	if compactObservation(observation) != observation {
		t.Fatal("non-log evidence changed")
	}
}

func TestCompactRecoveryListsEachAlertState(t *testing.T) {
	b := canonicalFixture(t)
	b.Alerts = []model.BriefingAlert{{Name: "CPU load", State: "resolved"}, {Name: "memory", State: "firing"}, {Name: "inodes in use", State: "firing"}}
	b.Firing, b.Resolved = 2, 1
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, &model.OperatorDelta{ClearedAlerts: []string{"CPU load"}})
	got := strings.Join(canonicalClearanceLines(tr, b), "\n")
	for _, want := range []string{"🔹 CPU load · just recovered", "🔸 memory · firing", "🔸 inodes in use · firing"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
}

func TestCompactRevisedDiagnosisSurvivesRecoveredRoot(t *testing.T) {
	b := canonicalFixture(t)
	b.Historical = true
	b.Firing, b.Resolved = 0, 3
	for i := range b.Alerts {
		b.Alerts[i].State = "resolved"
	}
	b.Analyses = []model.IncidentAnalysis{{Title: "Checkout errors coincide with payment failures", Summary: "Checkout errors coincide with payment failures, suggesting a downstream dependency problem.", Verification: "revised", Observations: []string{"Log sample: Payment request failed. Invalid token."}}}
	root, err := RenderSituationRoot(bcRoot(t, model.LifecycleRecovered, model.AttentionObserve, rsTerminalContract(), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, root, "*Finding:* During the incident: Checkout errors coincide with payment failures, suggesting a downstream dependency problem.")
	if strings.Contains(root.Text, "*Working diagnosis:*") {
		t.Fatal("obsolete diagnosis label", root.Text)
	}
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), b, nil)
	reply, err := RenderSituationReply(SituationReplyInput{Transition: tr, ReplyKind: model.ReplyAnalysisCompleted})
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, reply, "*Finding:* Checkout errors coincide with payment failures", "Log sample: Payment request failed. Invalid token.")
	b.Analyses[0].VerificationLimit = "budget_deferred"
	root, err = RenderSituationRoot(bcRoot(t, model.LifecycleRecovered, model.AttentionObserve, rsTerminalContract(), b))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(root.Text, "downstream dependency") {
		t.Fatal("unreconciled draft exposed", root.Text)
	}
}

// The executed expression, not a speculative rationale, identifies a check.
func TestCompactCheckUsesExecutedQuerySubject(t *testing.T) {
	var checks []model.SourceCheck
	err := json.Unmarshal([]byte(`[
 {"source":"Prometheus","kind":"promql","query_expr":"histogram_quantile(0.95, rate(checkout_request_duration_seconds_bucket[1m])) > 5","check":"Check if p95 latency spiked, which could indicate downstream timeouts affecting error rates.","outcome":"empty"},
 {"source":"Prometheus","kind":"promql","query_expr":"count by (user_segment) (payment_request_errors_total{error_type=\"invalid_token\"})","check":"Determine whether the token rejection affects one user segment or the entire system.","outcome":"empty"}
 ]`), &checks)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(canonicalSourceLines(checks), "\n")
	for _, want := range []string{"P95 checkout request duration seconds", "payment request errors by user segment"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
	for _, bad := range []string{"Error rate", "Verification check", "no data"} {
		if strings.Contains(got, bad) {
			t.Errorf("misleading subject %q: %s", bad, got)
		}
	}
}

// Different executed selectors and time windows must remain distinguishable;
// retaining both rows alone is insufficient if their subjects look identical.
func TestCompactChecksRetainQueryScope(t *testing.T) {
	checks := []model.SourceCheck{
		{Source: "Prometheus", Kind: "promql", Check: "Token errors", QueryExpr: `rate(payment_request_errors_total{error_type="invalid_token"}[5m])`, Outcome: model.SourceCheckEmpty},
		{Source: "Prometheus", Kind: "promql", Check: "Other errors", QueryExpr: `rate(payment_request_errors_total{error_type!="invalid_token"}[5m])`, Outcome: model.SourceCheckEmpty},
		{Source: "Prometheus", Kind: "promql", Check: "Earlier errors", QueryExpr: `rate(payment_request_errors_total{error_type="invalid_token"}[1m] offset 10m)`, Outcome: model.SourceCheckEmpty},
	}
	got := strings.Join(canonicalSourceLines(checks), "\n")
	for _, want := range []string{`error＿type="invalid＿token"`, `error＿type!="invalid＿token"`, "5m window", "1m window", "offset 10m"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing scope %q: %s", want, got)
		}
	}
	if strings.Count(got, "query succeeded · empty result") != 3 {
		t.Fatal("lost distinct query results", got)
	}
}

func TestCompactChecksDisambiguateRemainingLabelCollisions(t *testing.T) {
	checks := []model.SourceCheck{
		{Source: "Prometheus", Kind: "promql", Check: "Errors", QueryExpr: `sum(payment_request_errors_total) > 5`, Outcome: model.SourceCheckEmpty},
		{Source: "Prometheus", Kind: "promql", Check: "Errors", QueryExpr: `sum(payment_request_errors_total) > 10`, Outcome: model.SourceCheckEmpty},
	}
	got := strings.Join(canonicalSourceLines(checks), "\n")
	for _, want := range []string{"payment request errors · check 1", "payment request errors · check 2"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing distinct check reference %q: %s", want, got)
		}
	}
}

// The channel scan must encounter the conclusion before lifecycle and membership detail.
func TestCanonicalRootUsesCompletedDiagnosisTitle(t *testing.T) {
	for _, lifecycle := range []model.Lifecycle{model.LifecycleActive, model.LifecycleRecovered} {
		b := canonicalFixture(t)
		b.Analyses = []model.IncidentAnalysis{{Title: "Checkout errors likely linked to payment failures", Summary: "Checkout errors likely stemmed from payment failures in the same window.", Verification: "revised"}}
		contract := bcObserveMonitorContract(bcNow(t))
		if lifecycle.Terminal() {
			contract = rsTerminalContract()
		}
		msg, err := RenderSituationRoot(bcRoot(t, lifecycle, model.AttentionUrgent, contract, b))
		if err != nil {
			t.Fatal(err)
		}
		heading := strings.SplitN(msg.Text, "\n", 2)[0]
		if !strings.Contains(heading, "— Checkout errors likely linked to payment failures") {
			t.Fatalf("heading lost the completed diagnosis: %s", heading)
		}
		b.Analyses[0].VerificationLimit = "budget_deferred"
		msg, err = RenderSituationRoot(bcRoot(t, lifecycle, model.AttentionUrgent, contract, b))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.SplitN(msg.Text, "\n", 2)[0], "likely linked") {
			t.Fatal("draft diagnosis promoted to heading")
		}
	}
}

func TestCanonicalRootFindingLeadsDetails(t *testing.T) {
	for _, lifecycle := range []model.Lifecycle{model.LifecycleActive, model.LifecycleRecovered} {
		b := canonicalFixture(t)
		b.Analyses = []model.IncidentAnalysis{{Summary: "Payment token failures affected checkout.", Verification: "revised"}}
		contract := bcObserveMonitorContract(bcNow(t))
		if lifecycle.Terminal() {
			contract = rsTerminalContract()
		}
		msg, err := RenderSituationRoot(bcRoot(t, lifecycle, model.AttentionUrgent, contract, b))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(msg.Blocks)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{msg.Text, string(raw)} {
			finding := strings.Index(text, "*Finding:*")
			chain := strings.Index(text, "Observed ·")
			counts := strings.Index(text, "*Alerts:*")
			if chain < 0 || finding < chain || counts < finding {
				t.Fatalf("expected status line, finding, then alert details: %s", text)
			}
		}
	}
}

// A recovered source is not proof of a completed investigation. Failed initial
// analysis followed by budget backoff must remain visible after terminalization.
func TestCanonicalRecoveredIncompleteInvestigation(t *testing.T) {
	for _, blocked := range []string{"budget_deferred", ""} {
		b := canonicalFixture(t)
		b.Work.Phase = model.WorkPhaseRetryWait
		b.Work.ExecutionStarted = true
		b.BlockedReason = blocked
		in := bcRoot(t, model.LifecycleRecovered, model.AttentionUrgent, rsTerminalContract(), b)
		root, err := RenderSituationRoot(in)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := RenderSituationReply(SituationReplyInput{Transition: in.SourceTransition, ReplyKind: model.ReplyRecovered})
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range []RenderedMessage{root, reply} {
			bcBothSurfaces(t, msg, "*Finding:* Investigation incomplete.")
			if blocked != "" {
				bcBothSurfaces(t, msg, "analysis budget")
			}
			if strings.Contains(msg.Text, "retry scheduled") {
				t.Fatal(msg.Text)
			}
		}
		b.Analyses = []model.IncidentAnalysis{{Summary: "Payment token failures affected checkout.", Verification: "revised"}}
		root, err = RenderSituationRoot(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(root.Text, "Investigation incomplete") {
			t.Fatal("successful initial finding replaced by follow-up failure", root.Text)
		}
	}
}
