// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestPresentationRevisionPersistsNamedAlertFacts(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Deliveries[0].Labels = map[string]string{"alertname": "CheckoutErrors", "service": "checkout", "environment": "production", "cluster": "synthetic-drill-cluster"}
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"display_scope":"checkout · production"`, `"alerts":[{"id":"delivery-1","name":"CheckoutErrors","service":"checkout","context":"checkout","state":"firing"}]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("persisted briefing missing %s: %s", want, raw)
		}
	}
}

func TestPresentationSourcesPreferRecordedOutcomeAndRetainSkippedInventory(t *testing.T) {
	configured := []model.SourceCheck{
		{Source: "Prometheus", Check: "collection", Outcome: model.SourceCheckConfigured, CallsKnown: true},
		{Source: "Changes", Check: "collection", Outcome: model.SourceCheckSkipped, CallsKnown: true, RecordsKnown: true},
	}
	recorded := []model.SourceCheck{{Source: "Prometheus", Check: "collection", Outcome: model.SourceCheckEmpty, RecordsKnown: true}}
	got := mergePresentationSourceChecks(configured, recorded)
	if len(got) != 2 || got[0].Source != "Changes" || got[0].Outcome != model.SourceCheckSkipped || got[1].Outcome != model.SourceCheckEmpty {
		t.Fatalf("merged source inventory = %+v", got)
	}
}

func presentationInput(t *testing.T, n int) SnapshotInput {
	t.Helper()
	in := baseSnapshotInput(t)
	in.Deliveries = nil
	for i := 0; i < n; i++ {
		d := deliveryFor(fmt.Sprintf("id-%02d", i), "incident-1", "digest", in.Now)
		d.Labels = map[string]string{"alertname": fmt.Sprintf("Alert %02d", i), "service": "checkout", "environment": "production", "cluster": "synthetic-cluster"}
		in.Deliveries = append(in.Deliveries, d)
	}
	return in
}

func TestPresentationRevisionCompleteStableSelectionAndAssessmentIsolation(t *testing.T) {
	in := presentationInput(t, 10)
	in.Deliveries[0].Labels["alertname"] = strings.Repeat("\u754c", 300)
	before := BuildSnapshot(in)
	prompt, err := BuildAssessmentPrompt(before)
	if err != nil {
		t.Fatal(err)
	}
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	if len(b.Alerts) != 10 || b.AlertsOmitted != 0 || b.Total != 10 || b.Firing != 10 {
		t.Fatalf("selection must retain every recognizable alert identity: %+v", b)
	}
	for i, a := range b.Alerts {
		if a.ID != fmt.Sprintf("id-%02d", i) || len(a.Name) > 240 || a.State != "firing" {
			t.Fatalf("unbounded or unstable alert selection: %+v", a)
		}
	}
	slices.Reverse(in.Deliveries)
	reordered := BuildOperatorBriefing(in, model.LifecycleActive)
	if operatorBriefingChanged(b, reordered) {
		t.Fatal("input reordering must not change persisted briefing")
	}
	slices.Reverse(in.Deliveries)
	inputName := in.Deliveries[0].Labels["alertname"]
	b.Alerts[0].Name = "mutated selected prose"
	if in.Deliveries[0].Labels["alertname"] != inputName {
		t.Fatal("selected alert aliases input")
	}
	after := BuildSnapshot(in)
	afterPrompt, err := BuildAssessmentPrompt(after)
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(prompt, afterPrompt) {
		t.Fatal("presentation changed snapshot, L2 hashes or prompt")
	}
}

func TestPresentationRevisionNamesUseIdentityAndReducer(t *testing.T) {
	in := presentationInput(t, 3)
	for i := 0; i < 2; i++ {
		in.Deliveries[i].Labels["alertname"] = "Latency"
		in.Deliveries[i].Labels["host"] = fmt.Sprintf("host-%d", i)
		in.Deliveries[i].Labels["secret_custom_label"] = "DO NOT PUBLISH"
	}
	// Plan 3 adaptation: the archived test resolved id-00 and marked id-01
	// unobserved through Plan 4 prepared observations. This tree's
	// authoritative truth is the latest delivery per Alert, and it has no
	// unobserved state, so id-00 resolves through a later delivery and
	// id-01 simply stays firing.
	resolved := in.Deliveries[0]
	resolved.ID, resolved.Status, resolved.ReceivedAt = "id-00-resolved", model.DeliveryStatusResolved, in.Now.Add(time.Minute)
	in.Deliveries = append(in.Deliveries, resolved)
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	if len(b.Alerts) != 3 || b.Firing != 2 || b.Resolved != 1 || b.Unknown != 0 {
		t.Fatalf("named state and counts must share the source reducer: %+v", b)
	}
	for i, state := range []string{"resolved", "firing", "firing"} {
		if b.Alerts[i].State != state || b.Alerts[i].ID != fmt.Sprintf("id-%02d", i) {
			t.Fatalf("wrong identity/state: %+v", b.Alerts)
		}
	}
	if b.Alerts[0].Name == b.Alerts[1].Name || !strings.Contains(b.Alerts[0].Name, "host-0") || b.Alerts[2].Name != "Alert 02" {
		t.Fatalf("disambiguate equal names only: %+v", b.Alerts)
	}
	raw, err := json.Marshal(b.Alerts)
	if err != nil || strings.Contains(string(raw), "DO NOT PUBLISH") || strings.Contains(string(raw), "synthetic-cluster") {
		t.Fatalf("arbitrary labels leaked: %s %v", raw, err)
	}
}

func TestPresentationRevisionPartialRecoveryAndEqualCountSwapPersist(t *testing.T) {
	for _, swap := range []bool{false, true} {
		t.Run(fmt.Sprintf("swap=%v", swap), func(t *testing.T) {
			in := presentationInput(t, 4)
			if swap {
				in.Deliveries[1].Status = model.DeliveryStatusResolved
			}
			old := BuildOperatorBriefing(in, model.LifecycleActive)
			in.Deliveries[0].Status = model.DeliveryStatusResolved
			in.Deliveries[1].Status = model.DeliveryStatusFiring
			current := BuildOperatorBriefing(in, model.LifecycleActive)
			c := hsNext(t)
			c.PriorTransition.Projection.Briefing, c.PriorSummary.Briefing = old, old
			c.Projection.Briefing = current
			trs, sum := hsCommitOf(t, c)
			if len(trs) != 1 || len(hsReplyIntents(hsPlan(t, hsPub(c, trs, sum)))) != 1 {
				t.Fatal("named state change must persist and earn exactly one reply, even at equal counts")
			}
			d := trs[0].Projection.OperatorDelta
			if d == nil || !reflect.DeepEqual(d.ClearedAlerts, []string{"Alert 00"}) {
				t.Fatalf("4 -> 3 partial recovery lost named clearance: %+v", d)
			}
			if swap && !reflect.DeepEqual(d.NewFiringAlerts, []string{"Alert 01"}) {
				t.Fatalf("same-count state swap lost new firing member: %+v", d)
			}
			raw, err := json.Marshal(trs[0])
			if err != nil {
				t.Fatal(err)
			}
			current.Alerts[0].Name = "MUTATED AFTER PERSISTENCE"
			var frozen model.Transition
			if err := json.Unmarshal(raw, &frozen); err != nil {
				t.Fatal(err)
			}
			replay, err := ProjectEpisode(c.PriorSummary, frozen)
			if err != nil || replay.Briefing.Alerts[0].Name != "Alert 00" || frozen.Projection.OperatorDelta.ClearedAlerts[0] != "Alert 00" {
				t.Fatalf("immutable wire replay lost selected names: %+v %v", replay, err)
			}
		})
	}
}

func TestPresentationRevisionMissingMetadataNeverInventsClearance(t *testing.T) {
	prior := hsFirst(t)
	for _, wire := range []string{
		`{"scope":"checkout","firing":1,"total":1}`,
		`{"scope":"checkout","firing":1,"total":1,"alerts":[{"id":"old","name":"Same name","state":"firing"}]}`,
	} {
		var old model.OperatorBriefing
		if err := json.Unmarshal([]byte(wire), &old); err != nil {
			t.Fatal(err)
		}
		prior.Projection.Briefing = &old
		tr := prior
		tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Total: 1, Alerts: []model.BriefingAlert{{ID: "different", Name: "Same name", State: "resolved"}}}
		d := buildOperatorDelta(&prior, tr)
		if len(d.ClearedAlerts) != 0 || len(d.NewFiringAlerts) != 0 {
			t.Fatalf("absent identities or name equality cannot prove resolution: %+v", d)
		}
	}
}

func TestPresentationRevisionRetryUsesActualDueNotStatusCheckpoint(t *testing.T) {
	in := baseSnapshotInput(t)
	checkpoint, due, later := in.Now.Add(time.Minute), in.Now.Add(7*time.Minute), in.Now.Add(12*time.Minute)
	in.Incidents[0].Triage = TriageState{Phase: "backoff", NextAt: &due}
	in.Incidents = append(in.Incidents, IncidentState{ID: "another", Status: "ready", Triage: TriageState{Phase: "backoff", NextAt: &later}})
	for _, semantic := range []bool{false, true} {
		t.Run(fmt.Sprintf("semantic=%v", semantic), func(t *testing.T) {
			action, status, reason := model.AlertINTActionRunAcuteTriage, model.AlertINTStatusWaiting, model.WaitReasonAcuteTriageBackoff
			if semantic {
				action, reason = model.AlertINTActionRetrySituationAssessment, model.WaitReasonAssessmentRetry
			}
			commit := ControllerCommit{Lifecycle: model.LifecycleActive, RetryAt: &later, Assessment: model.Assessment{ActionContract: model.ActionContract{AlertINTAction: &action, AlertINTStatus: &status, WaitReason: &reason, NextUpdateAt: &checkpoint}}}
			if !semantic {
				// Refreshing an already-backed-off request preserves its actual due time.
				commit.TriageDecisions = []TriageDecision{{IncidentID: in.Incidents[0].ID, Decision: TriageDecisionRequest}}
			}
			basis := historyBasis{In: in, Snap: BuildSnapshot(in), Now: in.Now}
			change := authoritativeChangeOf(Claim{Situation: in.Situation}, basis, commit)
			want := due
			if semantic {
				want = later
			}
			if b := change.Projection.Briefing; b.RetryAt == nil || !b.RetryAt.Equal(want) || !b.RetryAt.After(checkpoint) {
				t.Fatalf("retry must use persisted work due, not earlier check: %+v", b)
			}
			*change.Projection.Briefing.RetryAt = in.Now
			if !in.Incidents[0].Triage.NextAt.Equal(in.Now.Add(7*time.Minute)) || !commit.RetryAt.Equal(in.Now.Add(12*time.Minute)) {
				t.Fatal("retry projection aliases scheduler state")
			}
			status = model.AlertINTStatusRunning
			change = authoritativeChangeOf(Claim{Situation: in.Situation}, basis, commit)
			if change.Projection.Briefing.RetryAt != nil {
				t.Fatal("running work must not retain a misleading backoff timestamp")
			}
		})
	}
}

func TestPresentationRevisionRetryOnlyUpdatesRootQuietly(t *testing.T) {
	c := hsNext(t)
	first, second := c.Now.Add(7*time.Minute), c.Now.Add(12*time.Minute)
	old := &model.OperatorBriefing{Scope: "checkout", RetryAt: &first}
	c.PriorTransition.Projection.Briefing, c.PriorSummary.Briefing = old, old
	current := *old
	current.RetryAt = &second
	c.Projection.Briefing = &current
	trs, sum := hsCommitOf(t, c)
	if len(trs) != 1 || sum.Briefing.RetryAt == nil || !sum.Briefing.RetryAt.Equal(second) {
		t.Fatal("changed persisted work due must update the frozen projection")
	}
	intents := hsPlan(t, hsPub(c, trs, sum))
	if len(hsReplyIntents(intents)) != 0 || len(hsIntentsOfClass(intents, model.EffectRootSync)) != 1 {
		t.Fatal("retry timing alone must update the root without earning a reply")
	}
}

func TestPresentationRevisionStableIdentityAcrossDeliveriesAndBounds(t *testing.T) {
	in := presentationInput(t, 2)
	in.Deliveries[0].AlertID = strings.Repeat("long-shared-id", 100) + "a"
	in.Deliveries[1].AlertID = strings.Repeat("long-shared-id", 100) + "b"
	latest := in.Deliveries[0]
	latest.ID = "later-delivery"
	latest.ReceivedAt = in.Now.Add(time.Minute)
	latest.Status = model.DeliveryStatusResolved
	in.Deliveries = append(in.Deliveries, latest)
	b := BuildOperatorBriefing(in, model.LifecycleActive)
	if len(b.Alerts) != 2 || b.Total != 2 || b.Firing != 1 || b.Resolved != 1 {
		t.Fatalf("delivery count/name cannot replace stable alert identity: %+v", b)
	}
	if b.Alerts[0].ID == b.Alerts[1].ID || len(b.Alerts[0].ID) > 200 || len(b.Alerts[1].ID) > 200 {
		t.Fatal("bounded identities must remain distinct, not truncate to a shared prefix")
	}
	slices.Reverse(in.Deliveries)
	if operatorBriefingChanged(b, BuildOperatorBriefing(in, model.LifecycleActive)) {
		t.Fatal("delivery reordering changed selected current alert facts")
	}
}

// S3-04 (B0 integration contract §4): a changed Verification enum ALONE —
// with Observations/Unknowns unchanged — is a text-comparison outcome, not
// a material Slack update. Only a changed Findings/Observations set, or a
// changed VerificationLimit/VerificationGaps (an actual new decision-
// relevant limitation), earns a reply.
func TestBriefingVerificationEnumAloneIsNotMaterial(t *testing.T) {
	prior := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "supported"}}}
	current := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "revised"}}}
	if usefulAnalysisChanged(prior, current) {
		t.Fatal("a changed Verification enum alone, with identical Observations, must not be material")
	}
	changedFindings := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"All failing pods run the new image"}, Verification: "supported"}}}
	if !usefulAnalysisChanged(prior, changedFindings) {
		t.Fatal("a changed Observations set must remain material")
	}
	changedLimit := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "supported", VerificationLimit: "verification_source_unavailable"}}}
	if !usefulAnalysisChanged(prior, changedLimit) {
		t.Fatal("a new decision-relevant verification limitation must remain material")
	}
}

// S3-03 (B0 integration contract §4): "Stale flips are not evidence." A
// previously-stale analysis becoming fresh again, with no other structural
// change, must not by itself earn a reply.
func TestBriefingStaleFlipAloneIsNotMaterial(t *testing.T) {
	prior := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "supported", Stale: true}}}
	current := &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{{IncidentID: "i", Summary: "A deployment may explain errors", Findings: []string{"Restarts and errors began together"}, Verification: "supported", Stale: false}}}
	if usefulAnalysisChanged(prior, current) {
		t.Fatal("a Stale flip alone must not be material")
	}
}

func TestPresentationRevisionUnknownAndOmittedAlertsDoNotInventDeltas(t *testing.T) {
	prior := &model.OperatorBriefing{Alerts: []model.BriefingAlert{{ID: "a", Name: "Alert A", State: "firing"}}, AlertsOmitted: 2}
	current := &model.OperatorBriefing{Alerts: []model.BriefingAlert{{ID: "a", Name: "Alert A", State: "unknown"}, {ID: "b", Name: "Alert B", State: "firing"}}}
	changed, cleared, firing := briefingAlertDelta(prior, current)
	if !changed || len(cleared) != 0 || len(firing) != 0 {
		t.Fatalf("unknown is not cleared; omitted prior membership is not newly firing: changed=%v clear=%v new=%v", changed, cleared, firing)
	}
	var old model.OperatorBriefing
	if err := json.Unmarshal([]byte(`{"scope":"checkout","firing":1,"total":1}`), &old); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(old)
	if err != nil || strings.Contains(string(raw), "alerts") || strings.Contains(string(raw), "retry_at") || strings.Contains(string(raw), "display_scope") {
		t.Fatalf("old wire projection gained fabricated metadata: %s %v", raw, err)
	}
}
