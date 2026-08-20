// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestAppendObservationRunAndFactsRequiresCurrentSituationFence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-observe", "host=db-1", "", situationmodel.LifecycleActive, now)
	claims, err := s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	claim := claims[0]
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityZabbixProblemHistory,
		Scope:      map[string]string{"host": "db-1"}, Parameters: json.RawMessage(`{"severity_min":"3"}`),
		Start: now.Add(-24 * time.Hour), End: now, Limit: 20, Why: "compare history",
	}
	run := ObservationRun{
		ID: "run-1", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		ProposedPlan: plan, ValidatedPlan: plan, Capability: plan.Capability,
		Status: observationmodel.ResultStatusConfirmedValue, ObservedAt: now,
		Freshness: observationmodel.FreshnessFresh, Digest: "run-digest", SourceCallCost: 2, CreatedAt: now,
	}
	if err := s.AppendObservationRun(context.Background(), claim, run); err != nil {
		t.Fatalf("append run: %v", err)
	}
	changedRun := run
	changedRun.SourceCallCost++
	if err := s.AppendObservationRun(context.Background(), claim, changedRun); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("changed run replay err=%v", err)
	}
	fact := observationmodel.Fact{
		ID: "fact-1", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Kind: "problem_history", Subject: "db-1", Value: json.RawMessage(`{"episodes":3}`),
		SourceCapability: plan.Capability, ObservedAt: now, Freshness: observationmodel.FreshnessFresh,
		ResultStatus: observationmodel.ResultStatusConfirmedValue, Digest: "fact-digest",
		EvidenceRefs: []string{"zabbix:event:1"}, Material: true,
	}
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{fact}); err != nil {
		t.Fatalf("append facts: %v", err)
	}
	// Exact replay is idempotent; an identity collision with changed evidence is not.
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{fact}); err != nil {
		t.Fatalf("replay facts: %v", err)
	}
	fact.Digest = "different"
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{fact}); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("collision err=%v", err)
	}
	fact.Digest = "fact-digest"
	fact.EvidenceRefs = []string{"zabbix:event:2"}
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{fact}); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("changed evidence replay err=%v", err)
	}
	fact.ID = "fact-too-large"
	fact.Digest = "large"
	fact.EvidenceRefs = nil
	fact.Value = json.RawMessage(`{"payload":"` + strings.Repeat("x", 600<<10) + `"}`)
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{fact}); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversize fact err=%v", err)
	}

	second, err := s.ClaimDueSituations(context.Background(), "worker-2", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("reclaim=%+v err=%v", second, err)
	}
	stale := run
	stale.ID = "run-stale"
	if err := s.AppendObservationRun(context.Background(), claim, stale); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale run err=%v", err)
	}
	if err := s.AppendSituationFacts(context.Background(), claim, []observationmodel.Fact{{
		ID: "fact-stale", SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Kind: "test", Subject: "db-1", Value: json.RawMessage(`{}`), SourceCapability: plan.Capability,
		ObservedAt: now, Freshness: observationmodel.FreshnessFresh, ResultStatus: observationmodel.ResultStatusConfirmedEmpty,
		Digest: "stale", EvidenceRefs: []string{},
	}}); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale fact err=%v", err)
	}
}

func TestAssessmentAttemptSeparatesProposalAndValidatedAuthority(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-assess", "host=db-2", "", situationmodel.LifecycleActive, now)
	claims, err := s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	claim := claims[0]
	proposal := json.RawMessage(`{"attention":"urgent"}`)
	validated := json.RawMessage(`{"attention":"investigate"}`)
	proposed := AssessmentAttempt{
		ID: "attempt-proposed", SituationID: claim.Situation.ID, Sequence: 1,
		InputVersion: claim.Situation.InputVersion, FactHash: "facts-v1", Actor: AssessmentActorLLM,
		Status: AssessmentStatusProposed, TriggerReasons: []string{"new_symptom"}, SnapshotDigest: "snapshot-1",
		Proposal: proposal, ValidationAdjustments: json.RawMessage(`[]`), CreatedAt: now,
	}
	if err := s.AppendAssessmentAttempt(context.Background(), claim, proposed); err != nil {
		t.Fatalf("append proposed: %v", err)
	}
	changedProposal := proposed
	changedProposal.Proposal = json.RawMessage(`{"attention":"observe"}`)
	if err := s.AppendAssessmentAttempt(context.Background(), claim, changedProposal); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("changed proposal replay err=%v", err)
	}
	var current sql.NullString
	if err := s.DB().QueryRow(`SELECT current_assessment_id FROM situations WHERE id = ?`, claim.Situation.ID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current.Valid {
		t.Fatalf("proposed attempt became current: %q", current.String)
	}
	authoritative := proposed
	authoritative.ID = "attempt-authoritative"
	authoritative.Sequence = 2
	authoritative.Status = AssessmentStatusAuthoritative
	authoritative.Validated = validated
	authoritative.CompletedAt = &now
	if err := s.AppendAssessmentAttempt(context.Background(), claim, authoritative); err != nil {
		t.Fatalf("append authoritative: %v", err)
	}
	var proposalJSON, validatedJSON string
	if err := s.DB().QueryRow(`SELECT proposal_json, validated_json FROM situation_assessment_attempts WHERE id = ?`, authoritative.ID).Scan(&proposalJSON, &validatedJSON); err != nil {
		t.Fatal(err)
	}
	if proposalJSON != string(proposal) || validatedJSON != string(validated) {
		t.Fatalf("proposal=%s validated=%s", proposalJSON, validatedJSON)
	}
	if err := s.DB().QueryRow(`SELECT current_assessment_id FROM situations WHERE id = ?`, claim.Situation.ID).Scan(&current); err != nil || current.String != authoritative.ID {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	if _, err := s.DB().Exec(`UPDATE situations SET current_assessment_id = ? WHERE id = ?`, proposed.ID, claim.Situation.ID); err == nil {
		t.Fatal("schema allowed a non-authoritative current assessment")
	}
}

func TestObservationSchemaHasClosedStatusesAndNoRawResponseColumn(t *testing.T) {
	s := newTestStore(t)
	rows, err := s.DB().Query(`PRAGMA table_info(situation_observation_runs)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(name, "raw") || strings.Contains(name, "response") {
			t.Fatalf("raw connector persistence column exists: %q", name)
		}
	}
	insertSituationFixture(t, s, "s-status", "host=db-3", "", situationmodel.LifecycleActive, time.Now().UTC())
	_, err = s.DB().Exec(`INSERT INTO situation_observation_runs
		(id, situation_id, input_version, proposed_plan_json, validated_plan_json, capability, scope_json,
		 parameters_json, budget, status, observed_at, freshness, truncated, digest, token_cost,
		 source_call_cost, created_at)
		VALUES ('bad', 's-status', 1, '{}', '{}', 'store_read', '{}', '{}', 1, 'absent', ?, 'fresh', 0, 'd', 0, 0, ?)`, canonicalTime(time.Now()), canonicalTime(time.Now()))
	if err == nil {
		t.Fatal("migration accepted open-ended observation status")
	}
}

func TestUpdateDeliverySourceTimesCorrectsFallbackAndSchedulesOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	received := mustSituationTime(t, "2026-08-20T10:00:00Z")
	observed := mustSituationTime(t, "2026-08-20T11:00:00Z")
	apiStart := mustSituationTime(t, "2026-08-20T09:00:00Z")
	apiEnd := mustSituationTime(t, "2026-08-20T10:30:00Z")
	seedSourceTimeFixture(t, s, received)
	insertSituationFixture(t, s, "s-source-time", "host=db-source", "", situationmodel.LifecycleActive, observed.Add(time.Hour))
	if _, err := s.DB().Exec(`UPDATE situations SET effective_started_at = ?, effective_started_at_basis = 'receipt_fallback' WHERE id = 's-source-time'`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO situation_incidents(situation_id, incident_id, attached_at) VALUES ('s-source-time','inc-source-time',?)`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id, delivery_id, created_at) VALUES ('inc-source-time','delivery-source-time',?)`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	claims, err := s.ClaimDueSituations(ctx, "source-worker", observed.Add(time.Hour), time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	claim := claims[0]
	if err := s.UpdateDeliverySourceTimes(ctx, claim, "delivery-source-time", &apiStart, &apiEnd, observed); err != nil {
		t.Fatalf("update source times: %v", err)
	}
	var sourceStart, sourceEnd, startedBasis, resolvedBasis, projectionStart, projectionEnd string
	if err := s.DB().QueryRow(`SELECT d.source_started_at, d.source_resolved_at, d.started_at_basis, d.resolved_at_basis,
		a.starts_at, a.ends_at FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id WHERE d.id='delivery-source-time'`).
		Scan(&sourceStart, &sourceEnd, &startedBasis, &resolvedBasis, &projectionStart, &projectionEnd); err != nil {
		t.Fatal(err)
	}
	if sourceStart != canonicalTime(apiStart) || sourceEnd != canonicalTime(apiEnd) || projectionStart != sourceStart || projectionEnd != sourceEnd || startedBasis != "source_api" || resolvedBasis != "source_api" {
		t.Fatalf("source=(%s,%s,%s,%s) projection=(%s,%s)", sourceStart, sourceEnd, startedBasis, resolvedBasis, projectionStart, projectionEnd)
	}
	got, err := s.SituationForIncident(ctx, "inc-source-time")
	if err != nil {
		t.Fatal(err)
	}
	if !got.EffectiveStartedAt.Equal(apiStart) || got.EffectiveStartedAtBasis != situationmodel.SourceTimeBasisSourceAPI || got.InputVersion != 2 || got.NextAssessmentAt.After(observed) {
		t.Fatalf("situation=%+v", got)
	}
	if err := s.UpdateDeliverySourceTimes(ctx, claim, "delivery-source-time", &received, &apiEnd, observed.Add(time.Minute)); !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("stale correction err=%v", err)
	}
}

func TestUpdateDeliverySourceTimesPreservesMixedBasisWithNullFallbackMember(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	received := mustSituationTime(t, "2026-08-20T10:00:00Z")
	observed := mustSituationTime(t, "2026-08-20T11:00:00Z")
	apiStart := mustSituationTime(t, "2026-08-20T09:00:00Z")
	seedSourceTimeFixture(t, s, received)
	insertSituationFixture(t, s, "s-mixed-time", "host=db-source", "", situationmodel.LifecycleActive, observed.Add(time.Hour))
	if _, err := s.DB().Exec(`UPDATE situations SET effective_started_at=?,effective_started_at_basis='receipt_fallback' WHERE id='s-mixed-time'`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO situation_incidents(situation_id,incident_id,attached_at) VALUES('s-mixed-time','inc-source-time',?)`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES('inc-source-time','delivery-source-time',?)`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	seedNullFallbackSituationMember(t, s, "s-mixed-time", received)
	claims, err := s.ClaimDueSituations(ctx, "mixed-worker", observed.Add(time.Hour), time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	if err := s.UpdateDeliverySourceTimes(ctx, claims[0], "delivery-source-time", &apiStart, nil, observed); err != nil {
		t.Fatal(err)
	}
	got, err := s.SituationForIncident(ctx, "inc-source-time")
	if err != nil {
		t.Fatal(err)
	}
	if !got.EffectiveStartedAt.Equal(apiStart) || got.EffectiveStartedAtBasis != situationmodel.SourceTimeBasisMixed {
		t.Fatalf("situation=%+v", got)
	}
}

func seedSourceTimeFixture(t *testing.T, s *Store, received time.Time) {
	t.Helper()
	if _, err := s.DB().Exec(`INSERT INTO alerts(id,fingerprint,status,labels_json,annotations_json,starts_at,received_at)
		VALUES('alert-source-time','fp-source-time','firing','{}','{}',?,?)`, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO alert_deliveries(
		id,alert_id,source,source_episode_key,status,labels_json,annotations_json,starts_at,
		started_at_basis,resolved_at_basis,receiver_grouping_identity,payload_digest,received_at)
		VALUES('delivery-source-time','alert-source-time','zabbix','zabbix:event:1','firing','{}','{}',?,
		'receipt_fallback','missing','host=db-source','digest-source-time',?)`, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incidents(id,group_key,status,first_alert_at,last_alert_at,ready_at,alert_count,created_at,updated_at,dispatch_managed)
		VALUES('inc-source-time','host=db-source','ready',?,?,?,?,?,?,1)`, canonicalTime(received), canonicalTime(received), canonicalTime(received), 1, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
}

func seedNullFallbackSituationMember(t *testing.T, s *Store, situationID string, received time.Time) {
	t.Helper()
	if _, err := s.DB().Exec(`INSERT INTO alerts(id,fingerprint,status,labels_json,annotations_json,starts_at,received_at)
		VALUES('alert-null-fallback','fp-null-fallback','firing','{}','{}',?,?)`, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO alert_deliveries(
		id,alert_id,source,source_episode_key,status,labels_json,annotations_json,starts_at,
		started_at_basis,resolved_at_basis,receiver_grouping_identity,payload_digest,received_at)
		VALUES('delivery-null-fallback','alert-null-fallback','zabbix','zabbix:event:2','firing','{}','{}',?,
		'receipt_fallback','missing','host=db-source','digest-null-fallback',?)`, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incidents(id,group_key,status,first_alert_at,last_alert_at,ready_at,alert_count,created_at,updated_at,dispatch_managed)
		VALUES('inc-null-fallback','host=db-source','ready',?,?,?,?,?,?,1)`, canonicalTime(received), canonicalTime(received), canonicalTime(received), 1, canonicalTime(received), canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO situation_incidents(situation_id,incident_id,attached_at) VALUES(?,'inc-null-fallback',?)`, situationID, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id,delivery_id,created_at) VALUES('inc-null-fallback','delivery-null-fallback',?)`, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
}
