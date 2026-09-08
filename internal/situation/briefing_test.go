// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Losing the briefing-only comparison would discard newly completed analysis
// whenever the assessment codes remain unchanged.
func TestBriefingAnalysisChangePersistsWithoutAssessmentChange(t *testing.T) {
	c := hsNext(t)
	if err := json.Unmarshal([]byte(`{"briefing":{"scope":"checkout","analysis_count":1,"analyses":[{"incident_id":"i","summary":"Deployment may explain errors"}]}}`), &c.Projection); err != nil {
		t.Fatal(err)
	}
	trs, sum := hsCommitOf(t, c)
	if len(trs) != 1 {
		t.Fatalf("new analysis needs one persisted transition, got %d", len(trs))
	}
	raw, err := json.Marshal(sum)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	_ = json.Unmarshal(raw, &wire)
	if len(wire["briefing"]) == 0 {
		t.Fatalf("summary lost analysis: %s", raw)
	}
	intents := hsPlan(t, hsPub(c, trs, sum))
	if len(hsReplyIntents(intents)) != 1 {
		t.Fatalf("new analysis needs one reply: %+v", intents)
	}
	c.PriorTransition, c.PriorSummary = &trs[0], &sum
	quiet, err := BuildTransitions(c)
	if err != nil || len(quiet) != 0 {
		t.Fatalf("unchanged analysis must be quiet: %v %v", quiet, err)
	}
}

func TestBriefingBoundsProjectionWithoutChangingSnapshot(t *testing.T) {
	in := criticalInput(t)
	before := BuildSnapshot(in)
	prompt, err := BuildAssessmentPrompt(before)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		in.Analyses = append(in.Analyses, model.IncidentAnalysis{IncidentID: strings.Repeat("i", 400), Summary: strings.Repeat("\u754c", 4000), Title: strings.Repeat("Title", 1000), Findings: []string{strings.Repeat("evidence", 1000), "second", "third", "fourth"}})
	}
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 8000 || len(b.Analyses) != 3 || b.AnalysisCount != 12 {
		t.Fatalf("unbounded projection: %d bytes, %d/%d analyses", len(raw), len(b.Analyses), b.AnalysisCount)
	}
	if !strings.Contains(string(raw), "…") {
		t.Fatal("truncation must be explicit")
	}
	b.Analyses[0].Findings[0] = "mutated projection"
	if in.Analyses[0].Findings[0] == "mutated projection" {
		t.Fatal("projection aliases snapshot evidence")
	}
	after := BuildSnapshot(in)
	p2, err := BuildAssessmentPrompt(after)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(prompt, p2) {
		t.Fatal("briefing prose changed L2 snapshot/prompt/hashes")
	}
}

// Plan 3 adaptation of the archived TestBriefingCountsUseAuthoritative-
// PreparedAndDeliveryState: this tree has no prepared observations, so the
// authoritative source truth is the latest immutable delivery per Alert —
// the same fold the lifecycle reads. The archived "unobserved" case cannot
// exist here (Unknown is reserved and always 0); the resolved and empty
// cases keep their original expectations.
func TestBriefingCountsUseAuthoritativeDeliveryState(t *testing.T) {
	in := criticalInput(t)
	in.Deliveries = in.Deliveries[:1]
	resolved := in.Deliveries[0]
	resolved.ID, resolved.Status, resolved.ReceivedAt = "later-resolved", model.DeliveryStatusResolved, in.Now
	in.Deliveries = append(in.Deliveries, resolved)
	b := BuildOperatorBriefing(in, model.LifecycleRecoveryPending)
	if b.Firing != 0 || b.Resolved != 1 || b.Total != 1 || b.Unknown != 0 || !b.Historical {
		t.Fatalf("latest resolution lost: %+v", b)
	}
	in.Deliveries = nil
	b = BuildOperatorBriefing(in, model.LifecycleActive)
	if b.Total != 0 || b.Resolved != 0 {
		t.Fatalf("empty members imply recovery: %+v", b)
	}
}

// B0 integration contract §2: the operator briefing and the lifecycle read
// ONE source fold. Whatever mix of member Incidents, re-fires, late
// resolutions and an Alert attached under two Incidents the deliveries
// carry, "Firing > 0" in the briefing must equal AnyFiring over the
// lifecycle's own symptoms, and every counted Alert is firing or resolved.
func TestBriefingCountsAgreeWithLifecycleFold(t *testing.T) {
	base := baseSnapshotInput(t)
	now := base.Now
	d := func(id, incident, alert string, firing bool, at time.Time) Delivery {
		out := deliveryFor(id, incident, "digest-"+id, at)
		out.AlertID = alert
		if !firing {
			out.Status = model.DeliveryStatusResolved
		}
		return out
	}
	cases := []struct {
		name       string
		deliveries []Delivery
	}{
		{"all firing", []Delivery{d("1", "i1", "a", true, now), d("2", "i2", "b", true, now)}},
		{"all resolved", []Delivery{d("1", "i1", "a", false, now), d("2", "i2", "b", false, now)}},
		{"late resolution wins", []Delivery{d("1", "i1", "a", true, now.Add(-time.Minute)), d("2", "i1", "a", false, now)}},
		{"re-fire after resolution", []Delivery{d("1", "i1", "a", false, now.Add(-time.Minute)), d("2", "i1", "a", true, now)}},
		{"sibling still firing", []Delivery{d("1", "i1", "a", false, now), d("2", "i1", "b", true, now.Add(-time.Minute))}},
		{"same alert under two incidents, one still firing", []Delivery{d("1", "i1", "a", true, now.Add(-time.Minute)), d("2", "i2", "a", false, now)}},
		{"no alert ids", []Delivery{d("1", "i1", "", true, now), d("2", "i1", "", false, now)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.Deliveries = tc.deliveries
			b := BuildOperatorBriefing(in, model.LifecycleActive)
			if got, want := b.Firing > 0, AnyFiring(deriveSymptoms(in.Deliveries)); got != want {
				t.Fatalf("briefing firing=%v, lifecycle AnyFiring=%v: %+v", got, want, b)
			}
			if b.Unknown != 0 || b.Firing+b.Resolved != b.Total {
				t.Fatalf("plan 3 alert states must be firing or resolved: %+v", b)
			}
			if b.Total != len(latestDeliveryPerAlert(in.Deliveries)) {
				t.Fatalf("total %d is not the distinct alert count %d", b.Total, len(latestDeliveryPerAlert(in.Deliveries)))
			}
		})
	}
}

// Scheduling and repeated work must remain auditable without earning replies.
func TestBriefingRoutineWorkIsAuditOnly(t *testing.T) {
	c := hsNext(t)
	c.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout"}
	c.Assessment.ActionContract = hsMonitoringContract(c.Now)
	trs, sum := hsCommitOf(t, c)
	if len(trs) == 0 {
		t.Fatal("routine conclusion must remain in audit")
	}
	intents := hsPlan(t, hsPub(c, trs, sum))
	if len(hsReplyIntents(intents)) != 0 {
		t.Fatalf("job completion alone earned replies: %+v", intents)
	}
	if len(hsIntentsOfClass(intents, model.EffectRootSync)) != 1 {
		t.Fatal("root must remain current")
	}
}

func TestBriefingInitialRootDoesNotEchoControllerJournal(t *testing.T) {
	c := hsChange(t)
	c.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout"}
	trs, sum := hsCommitOf(t, c)
	pub := hsPub(c, trs, sum)
	pub.RootPublished = false
	intents := hsPlan(t, pub)
	if len(hsReplyIntents(intents)) != 0 {
		t.Fatalf("initial root echoed as reply: %+v", intents)
	}
	if len(trs) != 1 || len(hsIntentsOfClass(intents, model.EffectRootSync)) != 1 {
		t.Fatal("lost initial audit/root")
	}
}

func TestBriefingMeaningfulDeltaSurvivesDelayedRoot(t *testing.T) {
	c := hsNext(t)
	c.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment may explain errors"}}}
	trs, sum := hsCommitOf(t, c)
	pub := hsPub(c, trs, sum)
	pub.RootPublished = false
	pub.RootPublicationOwed = true
	intents := hsPlan(t, pub)
	if len(hsReplyIntents(intents)) != 1 {
		t.Fatalf("an undelivered root swallowed new analysis: %+v", intents)
	}
}

func TestBriefingReplyGateRejectsNoiseAndPreservesConsequences(t *testing.T) {
	prior := hsFirst(t)
	prior.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 2, Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "supported"}}}
	cases := []struct {
		name   string
		change func(*model.Transition)
		want   bool
	}{
		{"job completed", func(tr *model.Transition) { tr.ActionContract = hsMonitoringContract(tr.CreatedAt) }, false},
		{"renewed loop", func(tr *model.Transition) { tr.ActionContract.NextUpdateAt = timePtr(tr.CreatedAt) }, false},
		{"paraphrase", func(tr *model.Transition) {
			tr.Projection.Briefing.Analyses[0].Summary = "Errors may follow deployment"
		}, false},
		{"new finding", func(tr *model.Transition) {
			tr.Projection.Briefing.Analyses[0].Findings = []string{"All failing pods run the new image"}
		}, true},
		{"new failure", func(tr *model.Transition) { tr.Projection.Briefing.Failed = 1 }, true},
		{"scope expanded", func(tr *model.Transition) { tr.Projection.Briefing.Total = 3 }, true},
		{"worsened", func(tr *model.Transition) { tr.Projection.Briefing.Firing = 2 }, true},
		{"handoff", func(tr *model.Transition) { tr.ActionContract = hsOperatorContract(tr.CreatedAt) }, true},
		{"blocked", func(tr *model.Transition) { s := model.AlertINTStatusBlocked; tr.ActionContract.AlertINTStatus = &s }, true},
		{"recovery", func(tr *model.Transition) { tr.Lifecycle = model.LifecycleRecoveryPending }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(prior)
			if err != nil {
				t.Fatal(err)
			}
			var tr model.Transition
			_ = json.Unmarshal(raw, &tr)
			tc.change(&tr)
			if got := operatorReplyWarranted(&prior, tr); got != tc.want {
				t.Fatalf("reply=%v want %v", got, tc.want)
			}
		})
	}
}

func TestBriefingCapturesUsefulDeltaForImmutableJournal(t *testing.T) {
	c := hsNext(t)
	old := &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 2}
	c.PriorTransition.Projection.Briefing = old
	c.PriorSummary.Briefing = old
	c.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 2, Total: 3}
	trs, _ := hsCommitOf(t, c)
	raw, err := json.Marshal(trs[0].Projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"operator_delta"`, `"previous_firing":1`, `"previous_total":2`, `"state_changed":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("immutable journal lost delta %s: %s", want, raw)
		}
	}
}

func TestBriefingSkippedAnalysisDoesNotPromisePendingWork(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Incidents = []IncidentState{{ID: "i", Status: "ready", Triage: TriageState{Phase: "skipped"}}}
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if b.Pending != 0 || !strings.Contains(string(raw), `"unavailable":1`) {
		t.Fatalf("skipped analysis still promised: %s", raw)
	}
	prior := hsFirst(t)
	prior.Projection.Briefing = &model.OperatorBriefing{Scope: b.Scope, Pending: 1}
	tr := prior
	tr.ActionContract = hsMonitoringContract(tr.CreatedAt)
	tr.Projection.Briefing = b
	if !operatorReplyWarranted(&prior, tr) {
		t.Fatal("loss of promised analysis must be reported once")
	}
}

func TestBriefingReviewPersistsActualReplyDifferences(t *testing.T) {
	for _, symptomChange := range []bool{true, false} {
		c := hsNext(t)
		old := &model.OperatorBriefing{Scope: "checkout", Symptoms: []string{"CheckoutErrors"}, Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "Deployment may explain errors", Verification: "degraded"}}}
		c.PriorTransition.Projection.Briefing = old
		c.PriorSummary.Briefing = old
		b := *old
		b.Analyses = append([]model.IncidentAnalysis(nil), old.Analyses...)
		if symptomChange {
			b.Symptoms = []string{"HighLatency"}
		} else {
			b.Analyses[0].VerificationLimit = "verification_source_unavailable"
		}
		c.Projection.Briefing = &b
		trs, sum := hsCommitOf(t, c)
		if len(trs) != 1 || len(hsReplyIntents(hsPlan(t, hsPub(c, trs, sum)))) != 1 {
			t.Fatal("meaningful difference must persist and earn one reply")
		}
		raw, err := json.Marshal(trs[0].Projection.OperatorDelta)
		if err != nil {
			t.Fatal(err)
		}
		if symptomChange {
			for _, want := range []string{`"symptoms_changed":true`, `"previous_symptoms":["CheckoutErrors"]`} {
				if !strings.Contains(string(raw), want) {
					t.Errorf("persisted delta lost %s: %s", want, raw)
				}
			}
			if strings.Contains(string(raw), `"scope_changed":true`) {
				t.Errorf("symptom-only change misclassified as scope: %s", raw)
			}
		} else if !strings.Contains(string(raw), `"verification_limit":"verification_source_unavailable"`) {
			t.Errorf("persisted delta lost verification limit: %s", raw)
		}
	}
}

// TestBriefingReplyGateDistinguishesRefireFromCountRung pins decision E2 of
// the B0 integration contract against slide 1 (edge `refire`) and slide 4
// (gate node): a refire that moves Recovery pending back to Active earns a
// thread reply, while a recurrence-count rung alone refreshes the root and
// stays quiet.
func TestBriefingReplyGateDistinguishesRefireFromCountRung(t *testing.T) {
	briefing := &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 2}
	clone := func(tr model.Transition) model.Transition {
		raw, err := json.Marshal(tr)
		if err != nil {
			t.Fatal(err)
		}
		var out model.Transition
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("refire during recovery earns a reply", func(t *testing.T) {
		prior := hsFirst(t)
		prior.Lifecycle = model.LifecycleRecoveryPending
		prior.Projection.Briefing = briefing
		tr := clone(prior)
		tr.Lifecycle = model.LifecycleActive
		tr.Reason = model.ReasonMaterialAssessmentChanged
		if !operatorReplyWarranted(&prior, tr) {
			t.Fatal("Recovery pending → Active refire must pass the reply gate")
		}
	})

	t.Run("count rung alone stays quiet", func(t *testing.T) {
		prior := hsFirst(t)
		prior.Lifecycle = model.LifecycleActive
		prior.Projection.Briefing = briefing
		tr := clone(prior)
		tr.Reason = model.ReasonRecurrenceMilestone
		tr.Journal.RecurrenceCount = 10
		if operatorReplyWarranted(&prior, tr) {
			t.Fatal("a recurrence-count rung with unchanged facts must not earn a thread reply")
		}
	})
}
