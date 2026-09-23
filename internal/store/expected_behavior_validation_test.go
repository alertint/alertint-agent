// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func validationBinding(role, trigger string) situationmodel.ExpectedBehaviorBinding {
	return situationmodel.ExpectedBehaviorBinding{
		Role: role, Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01",
		TriggerID: trigger, TriggerVersion: "sha256:" + trigger,
	}
}

func TestPrepareExpectedBehaviorValidationCoalescesAndOwnWakeDoesNotStale(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "host=db-01", now)
	sit := getSituationByID(t, st, id)
	req := ExpectedBehaviorValidationPrepare{
		SituationID: id, SituationInputVersion: sit.InputVersion,
		Bindings: []situationmodel.ExpectedBehaviorBinding{validationBinding("database_lag", "200")}, Now: now, FreshFor: 10 * time.Minute,
	}
	first, err := st.PrepareExpectedBehaviorValidation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	after := getSituationByID(t, st, id)
	if first.SituationInputVersion != sit.InputVersion+1 || after.InputVersion != first.SituationInputVersion || !hasDueReason(after.DueReasons, situationmodel.DueEnvelopeChanged) {
		t.Fatalf("validation=%+v situation version=%d due=%v", first, after.InputVersion, after.DueReasons)
	}
	replay, err := st.PrepareExpectedBehaviorValidation(context.Background(), req)
	if err != nil || replay.ID != first.ID {
		t.Fatalf("pre-wake replay=%+v err=%v", replay, err)
	}
	req.SituationInputVersion = after.InputVersion
	replay, err = st.PrepareExpectedBehaviorValidation(context.Background(), req)
	if err != nil || replay.ID != first.ID || getSituationByID(t, st, id).InputVersion != after.InputVersion {
		t.Fatalf("post-wake replay=%+v err=%v", replay, err)
	}
}

func TestExpectedBehaviorValidationChangedInputReadsStale(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "host=db-02", now)
	sit := getSituationByID(t, st, id)
	v, err := st.PrepareExpectedBehaviorValidation(context.Background(), ExpectedBehaviorValidationPrepare{
		SituationID: id, SituationInputVersion: sit.InputVersion, Bindings: []situationmodel.ExpectedBehaviorBinding{validationBinding("lag", "201")}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET input_version=input_version+1 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetExpectedBehaviorValidation(context.Background(), v.ID, now.Add(time.Minute))
	if err != nil || got.Status != situationmodel.ExpectedBehaviorValidationStale {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestCompleteExpectedBehaviorValidationFencesAndPersistsFreshProof(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "host=db-03", now)
	sit := getSituationByID(t, st, id)
	binding := validationBinding("lag", "202")
	v, err := st.PrepareExpectedBehaviorValidation(context.Background(), ExpectedBehaviorValidationPrepare{
		SituationID: id, SituationInputVersion: sit.InputVersion, Bindings: []situationmodel.ExpectedBehaviorBinding{binding}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof := situationmodel.ExpectedBehaviorBindingObservation{
		Binding: binding, Presence: "absent", EvidenceRefs: []string{"fact:problem-state"},
		ObservedAt: now.Add(time.Second), ExpiresAt: now.Add(5 * time.Minute),
	}
	ready, err := st.CompleteExpectedBehaviorValidation(context.Background(), v.ID, id, v.SituationInputVersion, []situationmodel.ExpectedBehaviorBindingObservation{proof}, "", now.Add(2*time.Second))
	if err != nil || ready.Status != situationmodel.ExpectedBehaviorValidationReady || len(ready.Observations) != 1 {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	got, err := st.GetExpectedBehaviorValidation(context.Background(), v.ID, now.Add(3*time.Second))
	if err != nil || got.Status != situationmodel.ExpectedBehaviorValidationReady || got.Observations[0].EvidenceRefs[0] != "fact:problem-state" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	_, err = st.CompleteExpectedBehaviorValidation(context.Background(), v.ID, id, v.SituationInputVersion, []situationmodel.ExpectedBehaviorBindingObservation{proof}, "", now.Add(4*time.Second))
	if !errors.Is(err, ErrExpectedBehaviorValidationStale) {
		t.Fatalf("repeat completion error=%v", err)
	}
}

func TestExpectedBehaviorValidationRejectsDuplicateBindingAndExpires(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "host=db-04", now)
	sit := getSituationByID(t, st, id)
	b := validationBinding("lag", "203")
	if _, err := st.PrepareExpectedBehaviorValidation(context.Background(), ExpectedBehaviorValidationPrepare{
		SituationID: id, SituationInputVersion: sit.InputVersion, Bindings: []situationmodel.ExpectedBehaviorBinding{b, b}, Now: now,
	}); err == nil {
		t.Fatal("duplicate binding accepted")
	}
	v, err := st.PrepareExpectedBehaviorValidation(context.Background(), ExpectedBehaviorValidationPrepare{
		SituationID: id, SituationInputVersion: sit.InputVersion, Bindings: []situationmodel.ExpectedBehaviorBinding{b}, Now: now, FreshFor: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetExpectedBehaviorValidation(context.Background(), v.ID, now.Add(time.Minute))
	if err != nil || got.Status != situationmodel.ExpectedBehaviorValidationUnavailable || got.UnavailableReason != "validation_expired" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestCompleteExpectedBehaviorValidationRejectsAlertmanagerProofFromDifferentScope(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	situationID := newSituationForGroup(t, st, "service=billing", now)
	sit := getSituationByID(t, st, situationID)
	ruleID := "prometheus:prod-prom:jobs:ReconciliationLoad"
	binding := situationmodel.ExpectedBehaviorBinding{
		Role: "billing_load", Source: "alertmanager", SourceInstanceID: "prod-am", ProducerID: "prod-prom",
		RuleID: ruleID, RuleVersion: "sha256:v1", RuleGroup: "jobs", RuleName: "ReconciliationLoad",
		ScopeLabels: map[string]string{"service": "billing"},
	}
	validation, err := st.PrepareExpectedBehaviorValidation(ctx, ExpectedBehaviorValidationPrepare{
		SituationID: situationID, SituationInputVersion: sit.InputVersion, Bindings: []situationmodel.ExpectedBehaviorBinding{binding},
		Now: now, FreshFor: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, situationID, "am-binding-proof", now.Add(time.Second))
	fence := observationmodel.Fence{SituationID: situationID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	plan := testPlan(now)
	plan.Capability, plan.Scope.Source = observationmodel.CapabilityPrometheusQuery, "alertmanager"
	plan.Purpose = "expected_behavior_validation:" + validation.ID + ":" + binding.Role
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{
		Anchor: now, ConfigDigest: "cfg-am-binding", RefreshInterval: 5 * time.Minute, Plans: []observationmodel.Plan{plan},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	definition := observationmodel.SourceDefinitionObservation{
		Source: "alertmanager", InstanceID: "prod-am", ProducerID: "prod-prom", RuleGroup: "jobs", RuleID: ruleID,
		Host: "service=payment", EndpointID: "prod-prom", Available: true,
		VersionAlgorithm: "prometheus-alerting-rule-effective-v1", Version: "sha256:v1", Presence: "present",
		ScopeLabels: map[string]string{"service": "payment"},
	}
	runID := "run:" + cycle.Draft.Plans[0].ID
	run := observationmodel.Run{
		ID: runID, CycleID: cycle.ID, PlanID: cycle.Draft.Plans[0].ID, Status: observationmodel.ResultConfirmedValue,
		Coverage: observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: true, Returned: 1},
		Facts: []observationmodel.Fact{{
			ID: "fact:am-binding-payment", RunID: runID, Kind: "source_definition", Subject: ruleID,
			Digest: "sha256:am-binding-payment", SchemaVersion: observationmodel.FactSchemaVersion, Value: json.RawMessage(mustJSON(t, definition)),
			ResultStatus: observationmodel.ResultConfirmedValue, Freshness: observationmodel.FreshnessFresh,
			ObservedAt: now.Add(time.Second), ExpiresAt: now.Add(5 * time.Minute), Material: true,
		}},
		ObservedAt: now.Add(time.Second), ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := st.CommitObservationRun(ctx, fence, run, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteExpectedBehaviorValidationsFromCycle(ctx, fence, cycle, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetExpectedBehaviorValidation(ctx, validation.ID, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != situationmodel.ExpectedBehaviorValidationUnavailable || got.UnavailableReason != "binding_identity_changed" {
		t.Fatalf("validation = %+v, want unavailable binding_identity_changed", got)
	}
}
