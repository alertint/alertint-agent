// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestExpectedBehaviorInputKeepsAlertmanagerScopesDistinct(t *testing.T) {
	now := time.Date(2026, 9, 21, 22, 5, 0, 0, time.UTC)
	started := now.Add(-5 * time.Minute)
	instanceID := "prod-am"
	ruleID := "prometheus:prod-prom:jobs:ReconciliationLoad"
	policy := situationmodel.ExpectedBehaviorPolicy{
		Scope: situationmodel.ExpectedBehaviorScope{
			GroupKey: "services", Source: "alertmanager", SourceInstanceID: instanceID, ProducerID: "prod-prom",
			ScopeLabels: map[string]string{"service": "payment"}, PrimaryRuleID: ruleID, PrimaryRuleVersion: "sha256:v1",
		},
		Conditions: situationmodel.ExpectedBehaviorConditions{
			Workload: "nightly_reconciliation", MaxDurationMinutes: 55,
			Schedule: situationmodel.ExpectedBehaviorSchedule{Days: []situationmodel.ExpectedBehaviorWeekday{situationmodel.ExpectedBehaviorMonday}, LocalStart: "22:00", LocalEnd: "23:00", Timezone: "UTC", StartToleranceMinutes: 10},
		},
		ReviewDueAt: now.Add(24 * time.Hour),
	}
	head := situationmodel.ExpectedBehaviorHead{EnvelopeID: "env-payment", Version: 1, State: situationmodel.ExpectedBehaviorStateActive, Scope: policy.Scope, Policy: &policy}
	delivery := func(id, service string, received time.Time) situation.Delivery {
		return situation.Delivery{
			ID: id, AlertID: id, Status: situationmodel.DeliveryStatusFiring, ReceivedAt: received, SourceStartedAt: &started,
			Source: "alertmanager", SourceInstanceID: &instanceID, SourceSignalID: &ruleID,
			Labels: map[string]string{"alertname": "ReconciliationLoad", "service": service, "severity": "warning"},
		}
	}
	definition := func(service, factID string) observationmodel.SourceDefinitionObservation {
		return observationmodel.SourceDefinitionObservation{
			Source: "alertmanager", InstanceID: instanceID, ProducerID: "prod-prom", RuleGroup: "jobs", RuleID: ruleID,
			Available: true, VersionAlgorithm: "prometheus-alerting-rule-effective-v1", Version: "sha256:v1", Presence: "present",
			ScopeLabels: map[string]string{"service": service}, EvidenceRefs: []string{factID}, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		}
	}
	in := situation.SnapshotInput{
		Situation:  situationmodel.Situation{ID: "sit", GroupKey: "services", InputVersion: 3, EffectiveStartedAt: started, Attention: situationmodel.AttentionInvestigate},
		Deliveries: []situation.Delivery{delivery("d-payment", "payment", now.Add(-time.Minute)), delivery("d-billing", "billing", now)},
		Prepared: situation.PreparedState{SourceDefinitions: []observationmodel.SourceDefinitionObservation{
			definition("payment", "fact:payment"), definition("billing", "fact:billing"),
		}},
		Now: now,
	}

	assembled := expectedBehaviorInputFromSnapshot(in, []situationmodel.ExpectedBehaviorHead{head})
	if assembled.ScopeLabels["service"] != "payment" || assembled.PrimaryRuleID != ruleID {
		t.Fatalf("primary = rule %q scope %v, want payment", assembled.PrimaryRuleID, assembled.ScopeLabels)
	}
	if len(assembled.FiringSignals) != 2 || assembled.FiringSignals[0].ScopeLabels["service"] != "payment" || assembled.FiringSignals[1].ScopeLabels["service"] != "billing" {
		t.Fatalf("firing signals = %+v, want independent payment and billing scopes", assembled.FiringSignals)
	}
	if got := situation.EvaluateExpectedBehaviors(assembled); got.Reason != situationmodel.ExpectedBehaviorReasonUnexpectedSymptom {
		t.Fatalf("evaluation = %+v, want billing flagged as unexpected", got)
	}
}
