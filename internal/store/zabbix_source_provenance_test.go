// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestCommitObservationRunPublishesCurrentZabbixSourceDefinition(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "source-restart.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	situationID := newSituationForGroup(t, st, "host=db-01", now)
	claim := claimSituation(t, st, situationID, "source-provenance", now)
	fence := observationmodel.Fence{SituationID: situationID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	plan := testPlan(now)
	plan.Capability = observationmodel.CapabilityZabbixProblemHist
	plan.Scope.Source = "zabbix"
	plan.Parameters = json.RawMessage(`{"host":"db-01","trigger_id":"18422","source_instance_id":"prod-zbx"}`)
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{
		Anchor: now, ConfigDigest: "cfg-zabbix-source", RefreshInterval: 5 * time.Minute, Plans: []observationmodel.Plan{plan},
	}, 6)
	if err != nil {
		t.Fatal(err)
	}
	planID := cycle.Draft.Plans[0].ID
	value := json.RawMessage(`{"source":"zabbix","instance_id":"prod-zbx","rule_id":"18422","host":"db-01","endpoint_id":"sha256:endpoint","available":true,"version_algorithm":"zabbix-trigger-effective-v1","version":"sha256:v1","component_digests":{"logic":"sha256:logic"},"trigger_ids":["18422"],"item_ids":["22"],"historical_version_proven":false}`)
	run := observationmodel.Run{
		ID: "run:source-v1", CycleID: cycle.ID, PlanID: planID, Status: observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: true},
		Facts: []observationmodel.Fact{{
			ID: "fact:source-v1", RunID: "run:source-v1", Kind: "source_definition", Subject: "alert-zbx",
			Digest: "sha256:v1-fact", SchemaVersion: observationmodel.FactSchemaVersion, Value: value,
			ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh,
			ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute), Material: true,
		}},
		ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := st.CommitObservationRun(ctx, fence, run, now); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	current, err := st.GetCurrentZabbixSourceObservations(ctx, situationID, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 1 || !current[0].Definition.Available || current[0].Definition.Version != "sha256:v1" || current[0].Freshness != "fresh" {
		t.Fatalf("current source definition = %+v", current)
	}
	expired, err := st.GetCurrentZabbixSourceObservations(ctx, situationID, now.Add(6*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Definition.Available || expired[0].Definition.Version != "" || expired[0].Definition.UnavailableReason != "expired" || expired[0].Freshness != "stale" {
		t.Fatalf("expired source definition = %+v", expired)
	}
}

func zabbixJudgmentSituationFixture(t *testing.T, st *Store, now time.Time) string {
	t.Helper()
	d := deliveryFixture("delivery-zabbix-judgment", "fp-zabbix-judgment", now)
	d.Source = "zabbix"
	d.SourceEpisodeKey = "zabbix:prod-zbx:event-1"
	d.Alert.Labels = map[string]string{
		"alertname": "HighCPU", "host": "db-01", "zabbix_trigger_id": "18422", "severity": "warning",
	}
	instanceID := "prod-zbx"
	d.SourceProvenance.InstanceID = &instanceID
	if _, err := st.AcceptDeliveries(context.Background(), []DeliveryInput{d}); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndDeliveryInput(t, st, "incident-zabbix-judgment", "input-zabbix-judgment", "host=db-01", d.ID, now)
	inputClaim := claimOneInput(t, st, "input-zabbix-judgment-worker", now)
	if err := st.ApplySituationInput(context.Background(), inputClaim); err != nil {
		t.Fatal(err)
	}
	situationID := listSituations(t, st)[0].ID
	assessment := validAssessmentFixture()
	assessment.Impact = situationmodel.ImpactSuspected
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_assessment_attempts (
			id,situation_id,sequence,input_version,work_attempt,status,derivation,provider_request_started,
			material_fact_hash,assessment_json,created_at,completed_at
		) VALUES ('zabbix-judgment-assessment',?,1,1,1,'authoritative','deterministic_controller','false',
			'sha256:zabbix-judgment',?,?,?)`, situationID, mustJSON(t, assessment), canonicalTime(now), canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET current_assessment_id='zabbix-judgment-assessment',attention='investigate' WHERE id=?`, situationID); err != nil {
		t.Fatal(err)
	}
	return situationID
}

func sourceDefinitionRun(t *testing.T, plan observationmodel.Plan, runID, factID, version, digest string, now time.Time) observationmodel.Run {
	t.Helper()
	value := json.RawMessage(mustJSON(t, observationmodel.SourceDefinitionObservation{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Host: "db-01", EndpointID: "sha256:endpoint",
		Available: true, VersionAlgorithm: "zabbix-trigger-effective-v1", Version: version,
		ComponentDigests: map[string]string{"logic": digest}, TriggerIDs: []string{"18422"}, ItemIDs: []string{"22"},
	}))
	return observationmodel.Run{
		ID: runID, CycleID: plan.CycleID, PlanID: plan.ID, Status: observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: true},
		Facts: []observationmodel.Fact{{
			ID: factID, RunID: runID, Kind: "source_definition", Subject: "alert-zbx", Digest: digest,
			SchemaVersion: observationmodel.FactSchemaVersion, Value: value, ResultStatus: observationmodel.ResultConfirmedValue,
			Freshness: observationmodel.FreshnessFresh, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute), Material: true,
		}}, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}

func unavailableSourceDefinitionRun(t *testing.T, plan observationmodel.Plan, runID, factID, reason, digest string, now time.Time) observationmodel.Run {
	t.Helper()
	value := json.RawMessage(mustJSON(t, observationmodel.SourceDefinitionObservation{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Host: "db-01",
		Available: false, UnavailableReason: reason,
	}))
	return observationmodel.Run{
		ID: runID, CycleID: plan.CycleID, PlanID: plan.ID, Status: observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: true},
		Facts: []observationmodel.Fact{{
			ID: factID, RunID: runID, Kind: "source_definition", Subject: "alert-zbx", Digest: digest,
			SchemaVersion: observationmodel.FactSchemaVersion, Value: value, ResultStatus: observationmodel.ResultUnavailable,
			Freshness: observationmodel.FreshnessFresh, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute), Material: true,
		}}, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}

func sourceObservationHistoryCount(t *testing.T, st *Store, situationID string) int {
	t.Helper()
	var count int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM zabbix_source_observations WHERE situation_id=?`, situationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestZabbixSourceHeadIgnoresUnchangedRepeatAndAtomicallyInvalidatesChangedRule(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)
	situationID := zabbixJudgmentSituationFixture(t, st, now)

	// First observe v1, then record expectedness against that exact current
	// configuration version.
	claim := claimSituation(t, st, situationID, "source-v1", now)
	fence := observationmodel.Fence{SituationID: situationID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	plan := testPlan(now)
	plan.Capability, plan.Scope.Source = observationmodel.CapabilityZabbixProblemHist, "zabbix"
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now, ConfigDigest: "cfg-v1", RefreshInterval: 5 * time.Minute, Plans: []observationmodel.Plan{plan}}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CommitObservationRun(ctx, fence, sourceDefinitionRun(t, cycle.Draft.Plans[0], "run:v1", "fact:v1", "sha256:v1", "sha256:fact-v1", now), now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseSituationClaim(ctx, claim.Situation, now); err != nil {
		t.Fatal(err)
	}
	sit, _ := st.GetSituation(ctx, situationID)
	write := recordJudgmentRequest(sit, now.Add(time.Second), "request-zabbix-source")
	if _, err := st.WriteSituationJudgment(ctx, audit.New(st.DB()), write); err != nil {
		t.Fatal(err)
	}

	// A fresh cycle repeats v1, then observes v2. The repeat must preserve
	// authority; the changed version must retire it in the same commit.
	claim2 := claimSituation(t, st, situationID, "source-v2", now.Add(2*time.Second))
	fence2 := observationmodel.Fence{SituationID: situationID, InputVersion: claim2.Situation.InputVersion, Owner: claim2.ClaimOwner, Token: claim2.ClaimToken}
	repeatPlan, changedPlan, stalePlan := testPlan(now.Add(2*time.Second)), testPlan(now.Add(3*time.Second)), testPlan(now.Add(2500*time.Millisecond))
	unavailablePlan, restoredPlan := testPlan(now.Add(5*time.Second)), testPlan(now.Add(6*time.Second))
	repeatPlan.Capability, repeatPlan.Scope.Source = observationmodel.CapabilityZabbixProblemHist, "zabbix"
	changedPlan.Capability, changedPlan.Scope.Source, changedPlan.Purpose = observationmodel.CapabilityZabbixProblemHist, "zabbix", "verify_changed_rule"
	stalePlan.Capability, stalePlan.Scope.Source, stalePlan.Purpose = observationmodel.CapabilityZabbixProblemHist, "zabbix", "late_stale_rule"
	unavailablePlan.Capability, unavailablePlan.Scope.Source, unavailablePlan.Purpose = observationmodel.CapabilityZabbixProblemHist, "zabbix", "unavailable_rule"
	restoredPlan.Capability, restoredPlan.Scope.Source, restoredPlan.Purpose = observationmodel.CapabilityZabbixProblemHist, "zabbix", "restored_rule"
	cycle2, err := st.BeginPreparation(ctx, fence2, observationmodel.CycleDraft{Anchor: now.Add(2 * time.Second), ConfigDigest: "cfg-v2", RefreshInterval: 5 * time.Minute, Plans: []observationmodel.Plan{repeatPlan, changedPlan, stalePlan, unavailablePlan, restoredPlan}}, 18)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CommitObservationRun(ctx, fence2, sourceDefinitionRun(t, cycle2.Draft.Plans[0], "run:v1-repeat", "fact:v1-repeat", "sha256:v1", "sha256:fact-v1", now.Add(2*time.Second)), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	view, err := st.GetCurrentSituationJudgment(ctx, situationID, now.Add(2*time.Second))
	if err != nil || view == nil || !view.Applicability.Applicable {
		t.Fatalf("unchanged repeat applicability = %+v, err=%v", view, err)
	}
	if err := st.CommitObservationRun(ctx, fence2, sourceDefinitionRun(t, cycle2.Draft.Plans[1], "run:v2", "fact:v2", "sha256:v2", "sha256:fact-v2", now.Add(3*time.Second)), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	view, err = st.GetCurrentSituationJudgment(ctx, situationID, now.Add(3*time.Second))
	if err != nil || view == nil || view.Applicability.Applicable || view.Applicability.Reason != situationmodel.JudgmentSourceSignatureChanged {
		t.Fatalf("changed rule applicability = %+v, err=%v", view, err)
	}
	current, _ := st.GetSituation(ctx, situationID)
	if !hasDueReason(current.DueReasons, situationmodel.DueSourceProvenanceChanged) {
		t.Fatalf("due reasons = %v, want source_provenance_changed", current.DueReasons)
	}
	if err := st.CommitObservationRun(ctx, fence2, sourceDefinitionRun(t, cycle2.Draft.Plans[2], "run:v1-late", "fact:v1-late", "sha256:v1", "sha256:fact-v1", now.Add(2500*time.Millisecond)), now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	definitions, err := st.GetCurrentZabbixSourceObservations(ctx, situationID, now.Add(4*time.Second))
	if err != nil || len(definitions) != 1 || definitions[0].Definition.Version != "sha256:v2" {
		t.Fatalf("late stale completion replaced current head: %+v, err=%v", definitions, err)
	}
	historyCount := sourceObservationHistoryCount(t, st, situationID)
	if historyCount != 4 {
		t.Fatalf("source observation history count = %d, want 4 including late stale result", historyCount)
	}
	if err := st.CommitObservationRun(ctx, fence2, unavailableSourceDefinitionRun(t, cycle2.Draft.Plans[3], "run:unavailable", "fact:unavailable", "api_unavailable", "sha256:unavailable", now.Add(5*time.Second)), now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	definitions, _ = st.GetCurrentZabbixSourceObservations(ctx, situationID, now.Add(5*time.Second))
	if len(definitions) != 1 || definitions[0].Definition.Available || definitions[0].Definition.Version != "" || definitions[0].Definition.UnavailableReason != "api_unavailable" {
		t.Fatalf("unavailable head fell back to prior success: %+v", definitions)
	}
	if err := st.CommitObservationRun(ctx, fence2, sourceDefinitionRun(t, cycle2.Draft.Plans[4], "run:restored", "fact:restored", "sha256:v2", "sha256:fact-v2", now.Add(6*time.Second)), now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	definitions, _ = st.GetCurrentZabbixSourceObservations(ctx, situationID, now.Add(6*time.Second))
	if len(definitions) != 1 || !definitions[0].Definition.Available || definitions[0].Definition.Version != "sha256:v2" {
		t.Fatalf("restored head = %+v", definitions)
	}
}
