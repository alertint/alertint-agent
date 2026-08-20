// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClosedLifecycleAndDueReasonValues(t *testing.T) {
	if LifecycleActive != "active" || LifecycleRecoveryPending != "recovery_pending" || LifecycleRecovered != "recovered" || LifecycleClosedUnknown != "closed_unknown" {
		t.Fatalf("lifecycles = %q, %q, %q, %q", LifecycleActive, LifecycleRecoveryPending, LifecycleRecovered, LifecycleClosedUnknown)
	}
	if DueIncidentCreated != "incident_created" || DueRecoveryGraceExpired != "recovery_grace_expired" || DueUpgradeReconstruction != "upgrade_reconstruction" {
		t.Fatalf("due reasons = %q, %q, %q", DueIncidentCreated, DueRecoveryGraceExpired, DueUpgradeReconstruction)
	}
}

func TestAssessmentCarriesControllerLifecycleAndActionContract(t *testing.T) {
	next := time.Date(2026, time.August, 20, 10, 5, 0, 0, time.UTC)
	action := "check bounded workload evidence"
	assessment := Assessment{
		SchemaVersion:   1,
		Persistence:     PersistenceSustained,
		Impact:          ImpactSuspected,
		Novelty:         NoveltyChanged,
		Causality:       CausalityCorrelated,
		Attention:       AttentionInvestigate,
		Lifecycle:       LifecycleActive,
		EvidenceQuality: EvidenceQualityDegraded,
		SufficientReason: &SufficientReason{
			Code:         "duration_outlier",
			CandidateID:  "reason:duration_outlier:v1:abc",
			Summary:      "episode duration exceeds comparable history",
			EvidenceRefs: []string{"fact:duration"},
		},
		ActionContract: ActionContract{
			NextActor:      NextActorAlertint,
			ActionStatus:   ActionStatusRunning,
			AlertintAction: &action,
			NextUpdateAt:   &next,
			NextUpdateOn:   []string{"recovery_observed", "new_symptom"},
		},
		Limitations:     []Limitation{{Code: "metric_samples_unavailable", Detail: "metrics unavailable"}},
		ProposedCadence: CadenceFast,
	}

	raw, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"schema_version", "lifecycle", "sufficient_reason", "action_contract", "limitations"} {
		if _, ok := got[field]; !ok {
			t.Fatalf("assessment JSON missing %q: %s", field, raw)
		}
	}
}

func TestSituationCarriesCanonicalLifecycleObservationTime(t *testing.T) {
	observedAt := time.Date(2026, time.August, 20, 10, 30, 0, 0, time.UTC)
	raw, err := json.Marshal(Situation{LastLifecycleObservedAt: observedAt})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var rendered string
	if err := json.Unmarshal(got["last_lifecycle_observed_at"], &rendered); err != nil {
		t.Fatalf("Unmarshal last_lifecycle_observed_at: %v", err)
	}
	if rendered != "2026-08-20T10:30:00Z" {
		t.Fatalf("last_lifecycle_observed_at = %q", rendered)
	}
}

func TestEnvelopeCompanionSetsRemainSeparate(t *testing.T) {
	envelope := EnvelopeVersion{
		Conditions: EnvelopeConditions{
			RequiredCompanionSignals: []string{"database_lock"},
			AllowedCompanionSignals:  []string{"slow_query"},
		},
	}
	if got := envelope.Conditions.RequiredCompanionSignals; len(got) != 1 || got[0] != "database_lock" {
		t.Fatalf("required companions = %v", got)
	}
	if got := envelope.Conditions.AllowedCompanionSignals; len(got) != 1 || got[0] != "slow_query" {
		t.Fatalf("allowed companions = %v", got)
	}
}
