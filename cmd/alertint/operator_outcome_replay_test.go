// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// Replays the lab ordering the seven-event fixture missed: assessments run
// BEFORE the incident becomes ready. Store/controller/delivery/renderer are
// real; external assessment and Slack are faked. No execution is fabricated.
func TestOperatorOutcomeCollectAssessThenReady(t *testing.T) {
	t.Run("recovery while queued", func(t *testing.T) { runOperatorOutcome(t, false) })
	t.Run("investigate then recover", func(t *testing.T) { runOperatorOutcome(t, true) })
}

func runOperatorOutcome(t *testing.T, execute bool) {
	t.Helper()
	f := newE2EFixture(t)
	f.slack.setScript(alwaysOK)
	r := &s5rFixture{e2eFixture: f, groupKey: "service=payment", incidentID: "lab-payment", episode: f.clock.Now()}
	if err := f.st.InsertIncident(f.ctx, store.Incident{ID: r.incidentID, GroupKey: r.groupKey, FirstAlertAt: r.episode, LastAlertAt: r.episode, ReadyAt: r.episode.Add(90 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	acceptOperatorOutcomeAlert(t, r, "firing")
	r.enqueueInput("incident_created", "created")
	r.sitID = f.situationIDForIncident(r.incidentID)
	f.l2.steer(model.AttentionUrgent, true)
	for i := 0; i < 2; i++ {
		f.drainController()
		r.deliverNow()
		f.clock.advance(time.Minute)
	}
	if f.scalarInt(`SELECT COUNT(*) FROM incident_triage_attempts WHERE incident_id=?`, r.incidentID) != 0 {
		t.Fatal("fixture ran investigation before readiness")
	}
	if err := f.st.MarkIncidentReadyWithSituationInput(f.ctx, r.incidentID, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	r.applyPendingInputs()
	f.drainController()
	r.deliverNow()
	phase, _ := r.triageSchedule()
	if phase != "pending" {
		t.Errorf("assessment during collection suppressed first investigation: %s", phase)
	}
	calls := f.slack.snapshot()
	var root e2eSlackCall
	for _, c := range calls {
		if c.ThreadTS == "" && (c.Method == "chat.postMessage" || c.Method == "chat.update") {
			root = c
		}
	}
	if root.Text == "" {
		t.Fatal("no operator root delivered")
	}
	for surface, text := range map[string]string{"fallback": root.Text, "blocks": r.blockText("root", root.Blocks)} {
		for _, want := range []string{"64.71% over 5m", "Investigation is queued", "Next status check"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s missing %q:\n%s", surface, want, text)
			}
		}
		if strings.Contains(text, "None required") {
			t.Errorf("%s invents reassurance:\n%s", surface, text)
		}
	}
	if execute {
		runOperatorInvestigation(t, r)
	}

	// Source reset is not itself a clearance. A received resolution is what
	// starts grace; then the real controller must produce the terminal outcome.
	r.clock.advance(time.Minute)
	acceptOperatorOutcomeAlert(t, r, "resolved")
	f.l2.steer(model.AttentionObserve, false)
	r.enqueueInput("membership_changed", "clear")
	f.drainController()
	r.deliverNow()
	if r.lifecycle() != "recovery_pending" {
		t.Fatalf("received clearance: %s", r.lifecycle())
	}
	grace := r.mustSituationTime("grace_until")
	r.advanceTo(grace.Add(-time.Second))
	f.drainController()
	if r.lifecycle() != "recovery_pending" {
		t.Fatal("recovered before grace")
	}
	r.advanceTo(grace)
	f.drainController()
	r.deliverNow()
	if r.lifecycle() != "recovered" {
		t.Fatalf("clearance through grace: %s", r.lifecycle())
	}
	calls = f.slack.snapshot()
	last := calls[len(calls)-1]
	for surface, text := range map[string]string{"fallback": last.Text, "blocks": r.blockText("outcome", last.Blocks)} {
		if !strings.Contains(text, "payment") {
			t.Errorf("%s changed affected service: %s", surface, text)
		}
		if !strings.Contains(text, "Recovery confirmed") {
			t.Errorf("%s missing delivered recovery: %s", surface, text)
		}
	}
	t.Logf("QUEUED ROOT:\n%s\nFINAL OUTCOME:\n%s", root.Text, last.Text)
}

// Only the external investigation boundary is scripted; the real worker
// owns claiming, completion, input events and retry suppression.
type operatorOutcomeAnalyzer struct {
	calls int
	run   func(situation.TriageAttemptClaim)
}

func (a *operatorOutcomeAnalyzer) Analyze(_ context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	a.calls++
	a.run(claim)
	return situation.AcuteResult{IncidentID: claim.IncidentID, EvidencePackDigest: "sha256:fake-backend", OutputJSON: json.RawMessage(`{"correlation_findings":["Payment errors recorded in logs"]}`), EnrichmentJSON: `{"logs":{"outcome":"fetched","lines":[{"timestamp":"2026-09-06T10:46:40Z","line":"Payment errors recorded in logs"}]}}`, Summary: "Payment failure", RootCause: "Payment errors", Confidence: 0.7}, nil
}

func runOperatorInvestigation(t *testing.T, r *s5rFixture) {
	t.Helper()
	f := r.e2eFixture
	analyzer := &operatorOutcomeAnalyzer{run: func(claim situation.TriageAttemptClaim) {
		if claim.IncidentID != r.incidentID || len(claim.MemberDeliveryIDs) != 1 {
			t.Fatalf("wrong frozen execution input: %+v", claim)
		}
		r.applyPendingInputs()
		f.drainController()
		r.deliverNow()
		calls := f.slack.snapshot()
		latest := calls[len(calls)-1]
		if !strings.Contains(latest.Text, "Investigating") {
			t.Fatalf("actual worker start hidden: %s", latest.Text)
		}
	}}
	worker := situation.NewTriageWorker(&triageAttemptStoreAdapter{f.st}, &triageScheduleListerAdapter{f.st}, analyzer, nil, nil, situation.TriageWorkerConfig{Owner: "operator-outcome", Now: f.clock.Now}, slog.New(slog.DiscardHandler))
	n, err := worker.RunOnce(f.ctx)
	if err != nil || n != 1 {
		t.Fatalf("real worker: n=%d err=%v", n, err)
	}
	r.applyPendingInputs()
	f.drainController()
	r.deliverNow()
	if n := f.scalarInt(`SELECT COUNT(*) FROM incident_triage_attempts WHERE incident_id=? AND result_code='success'`, r.incidentID); n != 1 {
		t.Fatalf("accepted executions=%d", n)
	}
	n, err = worker.RunOnce(f.ctx)
	if err != nil || n != 0 || analyzer.calls != 1 {
		t.Fatalf("unexpected repeat: n=%d calls=%d err=%v", n, analyzer.calls, err)
	}
	calls := f.slack.snapshot()
	found := false
	for _, c := range calls {
		if c.ThreadTS != "" && strings.Contains(c.Text, "Payment errors recorded in logs") {
			found = true
			if !strings.Contains(r.blockText("finding", c.Blocks), "Payment errors recorded in logs") {
				t.Fatal("finding absent from blocks")
			}
		}
	}
	if !found {
		t.Fatal("accepted worker finding never delivered")
	}
}

// Seed immutable source deliveries through the real acceptance writer, keeping
// the same alert identity and scope on firing and clearance.
func acceptOperatorOutcomeAlert(t *testing.T, r *s5rFixture, status string) {
	t.Helper()
	now := r.clock.Now()
	in := store.DeliveryInput{
		ID:     "lab-delivery-" + status,
		Alert:  store.Alert{ID: "lab-alert", Fingerprint: "lab-fingerprint", Status: status, Labels: map[string]string{"alertname": "ServiceErrorRateHigh", "service": "payment", "severity": "critical"}, Annotations: map[string]string{"summary": "payment error ratio 64.71% over 5m"}, StartsAt: r.episode, ReceivedAt: now},
		Source: "alertmanager", SourceEpisodeKey: "lab-payment-episode", SourceStartedAt: &r.episode, StartedAtBasis: model.SourceTimeBasisSourcePayload, ResolvedAtBasis: model.SourceTimeBasisMissing, ReceiverGroupingIdentity: r.groupKey, PayloadDigest: "sha256:lab-" + status, SourceProvenance: store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
	if status == "resolved" {
		in.SourceResolvedAt = &now
		in.ResolvedAtBasis = model.SourceTimeBasisSourcePayload
		in.Alert.Annotations["summary"] = "payment error-rate alert cleared"
	}
	deliveries, err := r.st.AcceptDeliveries(r.ctx, []store.DeliveryInput{in})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("accept %s: %v", status, err)
	}
	if _, err := r.st.DB().ExecContext(r.ctx, `INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES(?,?,?)`, r.incidentID, deliveries[0].ID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}
