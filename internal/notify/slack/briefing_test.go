// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestOperatorBriefingShowsAnalysisAndCurrentStateWithoutControllerJargon(t *testing.T) {
	now := rsMustTime(t, "2026-09-07T10:00:00Z")
	next := now.Add(time.Minute)
	contract := rsMonitoringContract(next)
	sum := rsSummary(1, "Situation opaque-id", model.AttentionObserve, contract, now.Add(-time.Hour), now)
	tr := rsTransition(1, model.LifecycleRecoveryPending, model.AttentionObserve, contract, model.ReasonRecoveryObserved, model.JournalRecoveryPending,
		model.JournalData{Headline: "Recovery observed", OccurredAt: now}, rsProjection(now.Add(-time.Hour), rsAssessment(model.CausalityUnknown, model.ImpactNoneObserved)), now)
	sum.EvidenceConclusion = "Confirmed active critical source severity establishes deterministic floor"
	sum.InvestigationWork = []string{"run_acute_triage (planned)"}
	// Decode the wire projection to exercise backwards-compatible persisted JSON.
	err := json.Unmarshal([]byte(`{"briefing":{"scope":"checkout · production","firing":0,"total":4,"analysis_count":1,"analyses":[{"incident_id":"private-id","title":"Checkout errors after deployment","summary":"The new deployment may have broken checkout.","findings":["Errors and restarts began together"],"verification":"degraded","analyzed_at":"2026-09-07T09:59:00Z"}]}}`), &sum)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := RenderSituationRoot(SituationRootInput{Summary: sum, SourceTransition: tr, ContractDeadlineAt: &next, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	text := rsFallbackBlocksText(msg)
	for _, want := range []string{"checkout", "production", "The new deployment may have broken checkout.", "Errors and restarts began together", "4", "resolved", "verification", "Next"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Errorf("operator cannot find %q in:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"deterministic floor", "run_acute_triage", "No impact observed", "Situation opaque-id", "private-id", "Operator contract"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("misleading or internal detail %q shown in:\n%s", forbidden, text)
		}
	}
	if !strings.Contains(msg.Text, "deployment") || !strings.Contains(msg.Text, "resolved") {
		t.Errorf("mobile fallback loses the operational briefing: %s", msg.Text)
	}
}

type briefingAssessmentClient struct{ calls int }

func (c *briefingAssessmentClient) CompleteOnce(_ context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.calls++
	return llm.OneShotCompletion{Completion: llm.Completion{Raw: json.RawMessage(`{"schema_version":1,"persistence":"sustained","impact":"suspected","novelty":"familiar","causality":"correlated","attention":"observe"}`)}, RequestStarted: llm.RequestStartStatusTrue}, nil
}

// Exercise the real coherent read, controller, fenced commit, persisted view,
// immutable journal and Slack renderer. Only the external L2 boundary is fake.
//
//nolint:gocyclo // Keep the sequential real-store publication/replay/recovery scenario together; most branches check boundary errors.
func TestBriefingStoredAnalysisFlowsThroughControllerAndReplay(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "briefing.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := st.DB().ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	d := store.DeliveryInput{ID: "briefing-delivery", Alert: store.Alert{ID: "briefing-alert", Fingerprint: "briefing-fp", Status: "firing", Labels: map[string]string{"service": "checkout", "environment": "production", "alertname": "CheckoutErrors", "severity": "critical"}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}, Source: "alertmanager", SourceEpisodeKey: "briefing-episode", SourceStartedAt: &now, StartedAtBasis: model.SourceTimeBasisSourcePayload, ResolvedAtBasis: model.SourceTimeBasisMissing, ReceiverGroupingIdentity: "checkout", PayloadDigest: "sha256:briefing", SourceProvenance: store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook}}
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{d}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertIncident(ctx, store.Incident{ID: "briefing-incident", GroupKey: "service=checkout", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute), AlertCount: 1}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE incidents SET status='analyzed' WHERE id='briefing-incident'`)
	exec(`INSERT INTO incident_alert_deliveries (incident_id,delivery_id,created_at) VALUES ('briefing-incident','briefing-delivery',?)`, now.Format(time.RFC3339Nano))
	exec(`INSERT INTO situation_input_outbox (id,idempotency_key,incident_id,delivery_id,kind,group_key,occurred_at,status) VALUES ('briefing-input','briefing-input','briefing-incident','briefing-delivery','membership_changed','service=checkout',?,'pending')`, now.Format(time.RFC3339Nano))
	inputs, err := st.ClaimSituationInputs(ctx, "briefing", now.Add(time.Minute), time.Minute, 1)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("inputs: %v %v", inputs, err)
	}
	if err := st.ApplySituationInput(ctx, inputs[0]); err != nil {
		t.Fatal(err)
	}
	var sid string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM situations`).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	client := &briefingAssessmentClient{}
	controllerNow := now.Add(5 * time.Minute)
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return controllerNow }, nil, nil)
	reconcile := func() {
		t.Helper()
		claims, err := st.ClaimDueSituations(ctx, "briefing", now.Add(time.Hour), time.Minute, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claims: %v %v", claims, err)
		}
		s := claims[0]
		if err := controller.Reconcile(ctx, situation.Claim{Situation: s, ClaimOwner: *s.LeaseOwner, ClaimToken: s.ClaimToken}); err != nil {
			t.Fatal(err)
		}
	}
	countReplies := func() int {
		t.Helper()
		var n int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents WHERE effect_class IN ('thread_append','broadcast_handoff')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	reconcile()
	if n := countReplies(); n != 0 {
		t.Fatalf("initial root echoed: %d replies", n)
	}
	first, err := st.GetSituationEpisodeView(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	// Model the persisted coordinates left by a successful initial root delivery.
	exec(`UPDATE situations SET slack_channel='C-test',slack_root_ts='1.0' WHERE id=?`, sid)
	// The first critical floor changes persisted Attention (part of the existing
	// L2 basis). Let that normal basis transition settle before changing prose.
	reconcile()
	exec(`UPDATE incidents SET summary='Checkout errors after deployment',root_cause='Deployment may explain checkout errors',output_json=?,enrichment_json=?,last_judged_at=? WHERE id='briefing-incident'`,
		`{"analysis_name":"Checkout errors after deployment","overall_issue":"Deployment may explain checkout errors","correlation_findings":["Restarts and errors began together"],"severity":"critical","confidence":0.8}`,
		`{"verification":{"outcome":"supported","rounds":[{"queries":[{"outcome":"invalid"}]}]}}`, now.Add(time.Minute).Format(time.RFC3339Nano))
	calls := client.calls
	reconcile()
	if client.calls != calls {
		t.Fatalf("publication prose triggered L2: %d -> %d", calls, client.calls)
	}
	view, err := st.GetSituationEpisodeView(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if view.Summary.Version <= first.Summary.Version {
		t.Fatal("analysis did not advance persisted projection")
	}
	if n := countReplies(); n != 1 {
		t.Fatalf("new analysis needs exactly one reply, got %d", n)
	}
	root, err := RenderSituationRoot(SituationRootInput{Summary: view.Summary, SourceTransition: view.SourceTransition, ContractDeadlineAt: view.Summary.ActionContract.NextUpdateAt, Now: controllerNow})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := RenderSituationJournal(view.SourceTransition)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("representative active root:\n%s\nrepresentative meaningful reply:\n%s", root.Text, journal.Text)
	for _, txt := range []string{root.Text, journal.Text} {
		for _, want := range []string{"Deployment may explain checkout errors", "Restarts and errors began together", "verification"} {
			if !strings.Contains(txt, want) {
				t.Errorf("persisted Slack flow lost %q: %s", want, txt)
			}
		}
	}
	reconcile()
	if n := countReplies(); n != 1 {
		t.Fatalf("quiet cycle produced replies: %d", n)
	}
	// Mutable incident changes cannot alter a selected historical publication.
	exec(`UPDATE incidents SET root_cause='MUTATED LATER' WHERE id='briefing-incident'`)
	ledger, err := st.ListSituationTransitions(ctx, sid, store.TransitionCursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	var replay *model.EpisodeSummary
	for _, tr := range ledger {
		sum, err := situation.ProjectEpisode(replay, tr)
		if err != nil {
			t.Fatal(err)
		}
		replay = &sum
	}
	before, err := json.Marshal(view.Summary)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("persisted replay diverged:\n%s\n%s", before, after)
	}
	// A source recovery uses the unchanged PR87 lifecycle path and a resolved
	// incident row; completed analysis must survive into the terminal root.
	exec(`UPDATE incidents SET root_cause='Deployment may explain checkout errors',status='resolved' WHERE id='briefing-incident'`)
	resolvedAt := now.Add(10 * time.Minute)
	d.ID = "briefing-resolution"
	d.Alert.Status = "resolved"
	d.Alert.ReceivedAt = resolvedAt
	d.Alert.EndsAt = &resolvedAt
	d.SourceResolvedAt = &resolvedAt
	d.ResolvedAtBasis = model.SourceTimeBasisSourcePayload
	d.PayloadDigest = "sha256:resolved"
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{d}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO incident_alert_deliveries (incident_id,delivery_id,created_at) VALUES ('briefing-incident','briefing-resolution',?)`, resolvedAt.Format(time.RFC3339Nano))
	exec(`INSERT INTO situation_input_outbox (id,idempotency_key,incident_id,delivery_id,kind,group_key,occurred_at,status) VALUES ('resolution-input','resolution-input','briefing-incident','briefing-resolution','membership_changed','service=checkout',?,'pending')`, resolvedAt.Format(time.RFC3339Nano))
	inputs, err = st.ClaimSituationInputs(ctx, "briefing", resolvedAt, time.Minute, 1)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("resolution input: %v %v", inputs, err)
	}
	if err := st.ApplySituationInput(ctx, inputs[0]); err != nil {
		t.Fatal(err)
	}
	controllerNow = resolvedAt
	reconcile()
	controllerNow = resolvedAt.Add(3 * time.Minute)
	reconcile()
	recovered, err := st.GetSituationEpisodeView(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.SourceTransition.Lifecycle != model.LifecycleRecovered {
		t.Fatalf("PR87 recovery path lost: %s", recovered.SourceTransition.Lifecycle)
	}
	root, err = RenderSituationRoot(SituationRootInput{Summary: recovered.Summary, SourceTransition: recovered.SourceTransition, Now: controllerNow})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Likely cause", "Deployment may explain checkout errors", "Finding at", "resolved", "*▸ Recovered*"} {
		if !strings.Contains(root.Text, want) {
			t.Errorf("terminal root lost %q: %s", want, root.Text)
		}
	}
}

func briefingRootFixture(t *testing.T, wire string) SituationRootInput {
	t.Helper()
	now := rsMustTime(t, "2026-09-07T10:00:00Z")
	next := now.Add(time.Minute)
	c := rsRunningTriageContract(next)
	s := rsSummary(1, "Situation opaque", model.AttentionUrgent, c, now.Add(-time.Hour), now)
	s.PublicHandle = "checkout-42"
	tr := rsTransition(1, model.LifecycleActive, model.AttentionUrgent, c, model.ReasonFirstAuthoritativeState, model.JournalEvidenceConclusion, model.JournalData{Headline: "Published", OccurredAt: now}, rsProjection(now.Add(-time.Hour), rsAssessment(model.CausalityUnknown, model.ImpactUnknown)), now)
	if err := json.Unmarshal([]byte(wire), &s); err != nil {
		t.Fatal(err)
	}
	return SituationRootInput{Summary: s, SourceTransition: tr, ContractDeadlineAt: &next, Now: now}
}

func TestBriefingRootHonestAnalysisAndIndependentHumanAction(t *testing.T) {
	for _, tc := range []struct{ name, wire, want string }{
		{"missing", `{"briefing":{"scope":"checkout","firing":2,"total":2,"pending":1}}`, "No completed analysis"},
		{"failed", `{"briefing":{"scope":"checkout","firing":2,"total":2,"failed":1}}`, "Analysis failed"},
		{"stale", `{"briefing":{"scope":"checkout","firing":2,"total":2,"analyses":[{"summary":"Deployment may explain errors","stale":true}]}}`, "Earlier hypothesis"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := briefingRootFixture(t, tc.wire)
			msg, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatal(err)
			}
			for _, txt := range []string{rsFallbackBlocksText(msg), msg.Text} {
				// The Action line stays independent of analysis state, and
				// (R4 repair, lead review 2026-09-09) is now equally
				// independent of source counts and attention: this fixture
				// records NO operator request, so the canonical slide-4 rule
				// "Add a concrete Action: only when the operator contract
				// requires one" forbids the health-check ask this assertion
				// previously demanded.
				for _, want := range []string{tc.want, "AlertINT:", "Action:", "None required from on-call", "Impact unknown"} {
					if !strings.Contains(txt, want) {
						t.Errorf("missing %q: %s", want, txt)
					}
				}
				for _, bad := range []string{"On-call: ", "No action currently required", "No impact observed", "has accepted", "Newer observations limit relevance", "limit relevance"} {
					if strings.Contains(txt, bad) {
						t.Errorf("misleading %q: %s", bad, txt)
					}
				}
			}
		})
	}
}

func TestBriefingRootBoundsEscapingPhaseAndPlainCommand(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout <!channel> & production","firing":1,"total":1,"analyses":[{"summary":"Suspected <@U123> deployment *problem*","findings":["Errors & restarts"]}]}}`)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	txt := rsFallbackBlocksText(msg)
	if strings.Contains(txt, "<!channel>") || strings.Contains(txt, "<@U123>") || strings.Contains(txt, "*problem*") {
		t.Fatalf("untrusted markup escaped containment: %s", txt)
	}
	if !strings.Contains(txt, "Observed · *▸ Investigating* · Monitoring · Confirming recovery · Outcome") {
		t.Fatalf("phase must be marked only: %s", txt)
	}
	command := "get situation checkout-42 using alertint"
	for _, body := range []string{txt, msg.Text} {
		if strings.Count(body, command) != 1 {
			t.Fatalf("command duplicated/missing: %s", body)
		}
		found := false
		for _, line := range strings.Split(body, "\n") {
			if line == command {
				found = true
			}
		}
		if !found {
			t.Fatalf("command not standalone plain text: %s", body)
		}
	}
	// The visible root stays bounded even when a persisted projection is large.
	in.Summary.Briefing.Analyses[0].Summary = strings.Repeat("\u754c", 4000)
	msg, err = RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsFallbackBlocksText(msg)) > 2200 || !strings.Contains(rsFallbackBlocksText(msg), "…") {
		t.Fatal("root did not bound oversized analysis with a visible marker")
	}
	in.Summary.Briefing.Scope = strings.Repeat("&", 4000)
	in.Summary.Briefing.Analyses[0].Title = strings.Repeat("&", 4000)
	in.Summary.Briefing.Analyses[0].Summary = strings.Repeat("&", 4000)
	in.Summary.Briefing.Analyses[0].Findings = []string{strings.Repeat("&", 4000)}
	msg, err = RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Text) > 2200 {
		t.Fatalf("escaping expanded mobile fallback to %d bytes", len(msg.Text))
	}
}

func TestBriefingJournalCarriesUsefulAnalysisAndAttributedContext(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1,"analyses":[{"summary":"Deployment may explain errors","findings":["Restarts began with deployment"],"verification":"degraded"}]}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	tr.Reason = model.ReasonMaterialAssessmentChanged
	tr.JournalKind = model.JournalEvidenceConclusion
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Deployment may explain errors", "Restarts began with deployment", "verification"} {
		if !strings.Contains(rsFallbackBlocksText(msg), want) {
			t.Errorf("reply lost %q: %s", want, rsFallbackBlocksText(msg))
		}
	}
	tr.Reason = model.ReasonOperatorArtifactRecorded
	id := "annotation-input"
	tr.OperatorArtifactInputID = &id
	tr.JournalKind = model.JournalOperatorNote
	tr.Journal.Headline = "Rollback under review"
	tr.Journal.Detail = "Checking the rollout <!channel>"
	tr.Journal.AttributedActor = "operator@example.com"
	msg, err = RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rsFallbackBlocksText(msg), "operator@example.com") || strings.Contains(rsFallbackBlocksText(msg), "<!channel>") {
		t.Fatalf("lost attribution or mention containment: %s", rsFallbackBlocksText(msg))
	}
}

func TestBriefingSupportedVerificationStillReportsInvalidQueries(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":1,"total":1,"analyses":[{"summary":"Deployment explains errors","verification":"supported","verification_gaps":2}]}}`)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Likely cause", "Verification limited", "cause unconfirmed"} {
		if !strings.Contains(rsFallbackBlocksText(msg), want) {
			t.Errorf("lost verification qualification %q: %s", want, rsFallbackBlocksText(msg))
		}
	}
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	reply, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Causality remains unproven", "2 verification checks unavailable or invalid", "*AlertINT:*", "*Action:*"} {
		if !strings.Contains(reply.Text, want) {
			t.Errorf("structured evidence reply lost %q: %s", want, reply.Text)
		}
	}
}

func TestBriefingJournalShowsChangeWithoutRepeatingOldAnalysis(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":2,"total":3,"analyses":[{"summary":"OLD ANALYSIS"}]}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	if err := json.Unmarshal([]byte(`{"operator_delta":{"state_changed":true,"previous_firing":1,"previous_total":2}}`), &tr.Projection); err != nil {
		t.Fatal(err)
	}
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	txt := rsFallbackBlocksText(msg)
	if !strings.Contains(txt, "1/2 → 2/3 alerts firing") || strings.Contains(txt, "OLD ANALYSIS") {
		t.Fatalf("reply must show the new consequence, not repeat old analysis: %s", txt)
	}
}

func TestBriefingReviewMixedWorkAvailability(t *testing.T) {
	for _, pending := range []int{0, 1} {
		in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","firing":3,"total":3,"unavailable":1,"failed":1}}`)
		in.Summary.Briefing.Pending = pending
		msg, err := RenderSituationRoot(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, txt := range []string{msg.Text, rsFallbackBlocksText(msg)} {
			for _, want := range []string{"Analysis unavailable for 1 incident(s)", "Analysis failed for 1 incident(s)"} {
				if !strings.Contains(txt, want) {
					t.Errorf("mixed work counts lost %q: %s", want, txt)
				}
			}
			if pending > 0 && (!strings.Contains(txt, "1 incident(s) still awaiting analysis") || strings.Contains(txt, "no further analysis")) {
				t.Errorf("pending work hidden by global unavailable claim: %s", txt)
			}
		}
	}
}

func TestBriefingReviewSymptomDeltaExplainsOldAndNew(t *testing.T) {
	in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","symptoms":["HighLatency"],"firing":1,"total":1}}`)
	tr := in.SourceTransition
	tr.Projection.Briefing = in.Summary.Briefing
	if err := json.Unmarshal([]byte(`{"operator_delta":{"symptoms_changed":true,"previous_symptoms":["CheckoutErrors"]}}`), &tr.Projection); err != nil {
		t.Fatal(err)
	}
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, txt := range []string{msg.Text, rsFallbackBlocksText(msg)} {
		if !strings.Contains(txt, "CheckoutErrors → HighLatency") || strings.Contains(txt, "scope changed") {
			t.Errorf("symptom-only reply must explain symptoms, not identical scope: %s", txt)
		}
	}
}

func TestBriefingReviewVerificationLimitIsHumanReadable(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{"verification_source_unavailable", "verification source unavailable"},
		{"llm_call_failed", "verification review could not complete"},
		{"llm_response_invalid", "verification review returned an unusable response"},
		{"unknown_private_reason_<!channel>", "verification limitation recorded; details unavailable"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			in := briefingRootFixture(t, `{"briefing":{"scope":"checkout","analyses":[{"summary":"Deployment may explain errors","verification":"degraded"}]}}`)
			in.Summary.Briefing.Analyses[0].VerificationLimit = tc.code
			root, err := RenderSituationRoot(in)
			if err != nil {
				t.Fatal(err)
			}
			tr := in.SourceTransition
			tr.Projection.Briefing = in.Summary.Briefing
			tr.Projection.OperatorDelta = &model.OperatorDelta{Analyses: in.Summary.Briefing.Analyses}
			reply, err := RenderSituationJournal(tr)
			if err != nil {
				t.Fatal(err)
			}
			for _, txt := range []string{root.Text, rsFallbackBlocksText(root)} {
				if !strings.Contains(txt, "Verification limited") || strings.Contains(txt, tc.code) {
					t.Errorf("root lost compact limitation: %s", txt)
				}
			}
			for _, txt := range []string{reply.Text, rsFallbackBlocksText(reply)} {
				if !strings.Contains(txt, tc.want) || strings.Contains(txt, tc.code) {
					t.Errorf("limitation missing or raw reason exposed: %s", txt)
				}
			}
		})
	}
}

func TestBriefingReviewLegacyFallbackRemainsHeadlineOnly(t *testing.T) {
	in := briefingRootFixture(t, `{}`)
	tr := in.SourceTransition
	tr.Journal.Detail = "private journal detail <!channel>"
	msg, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Text != tr.Journal.Headline {
		t.Fatalf("legacy fallback exposed detail: %q", msg.Text)
	}
}
