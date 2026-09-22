// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func expectedJudgmentFixture(t *testing.T) (SnapshotInput, model.SituationJudgment) {
	t.Helper()
	in := baseSnapshotInput(t)
	in.Situation.GroupKey = "instance=db-prod-1"
	in.Situation.Attention = model.AttentionInvestigate
	in.Deliveries[0].AlertID = "alert-db-cpu"
	in.Deliveries[0].Severity = "warning"
	in.Deliveries[0].Source = "alertmanager"
	in.Deliveries[0].EpisodeKey = "am:db-prod-1:cpu"
	in.Deliveries[0].SourceSignalID = stringPtrOf("HighCPU")
	in.Deliveries[0].SourceSignalVersion = stringPtrOf("rule-v3")
	in.Deliveries[0].Labels = map[string]string{
		"alertname": "HighCPU", "instance": "db-prod-1", "service": "postgres", "severity": "warning",
	}
	in.CurrentAssessment = &AuthoritativeAssessment{Assessment: model.Assessment{Impact: model.ImpactSuspected}}
	coverage, err := DeriveExpectedJudgmentCoverage(in)
	if err != nil {
		t.Fatalf("derive coverage: %v", err)
	}
	return in, model.SituationJudgment{
		ID: "judgment-1", SituationID: in.Situation.ID, Revision: 1,
		Operation: model.JudgmentOperationRecord, State: model.JudgmentStateExpected,
		AssertedOperator: "Janis", TrustDomain: model.JudgmentTrustAuthenticatedMCP,
		ValidUntil: in.Now.Add(time.Hour), Coverage: coverage,
	}
}

func TestExpectedJudgmentApplicabilityIgnoresUnchangedTelemetryRepeats(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	repeat := in.Deliveries[0]
	repeat.ID = "delivery-repeat"
	repeat.PayloadDigest = "new-receipt-payload"
	repeat.ReceivedAt = repeat.ReceivedAt.Add(time.Minute)
	in.Deliveries = append(in.Deliveries, repeat)

	got := EvaluateExpectedJudgment(judgment, in, in.Now.Add(2*time.Minute))
	if !got.Applicable || got.Reason != model.JudgmentApplicable {
		t.Fatalf("applicability = %+v, want applicable unchanged repeat", got)
	}
}

func TestExpectedJudgmentApplicabilityTracksCurrentZabbixRuleVersion(t *testing.T) {
	in, _ := expectedJudgmentFixture(t)
	in.Deliveries[0].Source = "zabbix"
	in.Deliveries[0].SourceInstanceID = stringPtrOf("prod-zbx")
	in.Deliveries[0].Labels["zabbix_trigger_id"] = "18422"
	in.Prepared.SourceDefinitions = []observationmodel.SourceDefinitionObservation{{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Available: true,
		VersionAlgorithm: "zabbix-trigger-effective-v1", Version: "sha256:v1",
	}}
	coverage, err := DeriveExpectedJudgmentCoverage(in)
	if err != nil {
		t.Fatal(err)
	}
	judgment := model.SituationJudgment{State: model.JudgmentStateExpected, ValidUntil: in.Now.Add(time.Hour), Coverage: coverage}

	repeat := in
	repeat.Deliveries = append([]Delivery(nil), in.Deliveries...)
	repeat.Deliveries[0].ID = "repeat-delivery"
	if got := EvaluateExpectedJudgment(judgment, repeat, in.Now); !got.Applicable {
		t.Fatalf("unchanged current rule version = %+v, want applicable", got)
	}

	changed := in
	changed.Prepared.SourceDefinitions = []observationmodel.SourceDefinitionObservation{{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Available: true,
		VersionAlgorithm: "zabbix-trigger-effective-v1", Version: "sha256:v2",
	}}
	if got := EvaluateExpectedJudgment(judgment, changed, in.Now); got.Applicable || got.Reason != model.JudgmentSourceSignatureChanged {
		t.Fatalf("changed current rule version = %+v, want source_signature_changed", got)
	}

	unavailable := in
	unavailable.Prepared.SourceDefinitions = []observationmodel.SourceDefinitionObservation{{
		Source: "zabbix", InstanceID: "prod-zbx", RuleID: "18422", Available: false,
		UnavailableReason: "api_unavailable",
	}}
	if got := EvaluateExpectedJudgment(judgment, unavailable, in.Now); got.Applicable || got.Reason != model.JudgmentSourceDefinitionUnavailable {
		t.Fatalf("unavailable current rule version = %+v, want source_definition_unavailable", got)
	}
}

func TestExpectedJudgmentApplicabilityRejectsMaterialChanges(t *testing.T) {
	base, judgment := expectedJudgmentFixture(t)
	cases := []struct {
		name string
		edit func(*SnapshotInput)
		want model.JudgmentApplicabilityReason
	}{
		{"new symptom", func(in *SnapshotInput) {
			d := in.Deliveries[0]
			d.ID, d.AlertID = "delivery-unavailable", "alert-db-unavailable"
			d.Labels = map[string]string{"alertname": "DatabaseUnavailable", "instance": "db-prod-1", "severity": "warning"}
			in.Deliveries = append(in.Deliveries, d)
		}, model.JudgmentSymptomsChanged},
		{"severity", func(in *SnapshotInput) {
			in.Deliveries[0].Severity = "critical"
			in.Deliveries[0].Labels["severity"] = "critical"
		}, model.JudgmentUrgent},
		{"impact", func(in *SnapshotInput) {
			in.CurrentAssessment.Assessment.Impact = model.ImpactConfirmed
		}, model.JudgmentImpactChanged},
		{"source signature", func(in *SnapshotInput) {
			in.Deliveries[0].SourceSignalVersion = stringPtrOf("rule-v4")
		}, model.JudgmentSourceSignatureChanged},
		{"withdrawn", func(*SnapshotInput) {}, model.JudgmentRevoked},
		{"terminal", func(in *SnapshotInput) {
			in.Situation.Lifecycle = model.LifecycleRecovered
		}, model.JudgmentSituationTerminal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			assessment := *base.CurrentAssessment
			in.CurrentAssessment = &assessment
			in.Deliveries = append([]Delivery(nil), base.Deliveries...)
			in.Deliveries[0].Labels = map[string]string{}
			for k, v := range base.Deliveries[0].Labels {
				in.Deliveries[0].Labels[k] = v
			}
			j := judgment
			tc.edit(&in)
			if tc.name == "withdrawn" {
				j.State = model.JudgmentStateRevoked
			}
			got := EvaluateExpectedJudgment(j, in, in.Now)
			if got.Applicable || got.Reason != tc.want {
				t.Fatalf("applicability = %+v, want false/%s", got, tc.want)
			}
		})
	}
}

func TestExpectedJudgmentApplicabilityExpiresAndNeverQuietsUrgency(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	if got := EvaluateExpectedJudgment(judgment, in, judgment.ValidUntil); got.Applicable || got.Reason != model.JudgmentExpired {
		t.Fatalf("at deadline = %+v, want expired", got)
	}
	in.Situation.Attention = model.AttentionUrgent
	if got := EvaluateExpectedJudgment(judgment, in, in.Now); got.Applicable || got.Reason != model.JudgmentUrgent {
		t.Fatalf("urgent = %+v, want urgent rejection", got)
	}
}

func TestApplicableExpectedJudgmentRetiresOnlyCoveredOperatorRequest(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	in.Judgment = &judgment
	in.JudgmentApplicability = EvaluateExpectedJudgment(judgment, in, in.Now)
	action := model.OperatorActionInvestigateSituation
	auto := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusWaiting
	next := in.Now.Add(2 * time.Hour)
	commit := ControllerCommit{
		Lifecycle: model.LifecycleActive,
		Attention: model.AttentionInvestigate,
		Assessment: model.Assessment{
			Impact:    model.ImpactSuspected,
			Attention: model.AttentionInvestigate,
			ActionContract: model.ActionContract{
				NextActor: model.NextActorOperator, AlertINTAction: &auto, AlertINTStatus: &status,
				OperatorActionRequired: &action, NextUpdateAt: &next,
			},
		},
		ConsumedDueReasons: []model.DueReason{model.DueOperatorJudgment, model.DueJudgmentBoundary},
	}

	applyExpectedJudgment(&commit, in, in.Now)
	if commit.Assessment.ActionContract.OperatorActionRequired != nil {
		t.Fatalf("operator request retained: %+v", commit.Assessment.ActionContract)
	}
	if commit.Assessment.ActionContract.AlertINTAction == nil || *commit.Assessment.ActionContract.AlertINTAction != auto || commit.Assessment.ActionContract.NextActor != model.NextActorAlertINT {
		t.Fatalf("monitoring work changed: %+v", commit.Assessment.ActionContract)
	}
	if commit.Attention != model.AttentionInvestigate || commit.Lifecycle != model.LifecycleActive {
		t.Fatalf("attention/lifecycle changed: %+v", commit)
	}
	if commit.Assessment.ActionContract.NextUpdateAt == nil || !commit.Assessment.ActionContract.NextUpdateAt.Equal(judgment.ValidUntil) {
		t.Fatalf("checkpoint = %v, want judgment deadline %s", commit.Assessment.ActionContract.NextUpdateAt, judgment.ValidUntil)
	}
	if len(commit.ConsumedDueReasons) != 1 || commit.ConsumedDueReasons[0] != model.DueOperatorJudgment {
		t.Fatalf("consumed due reasons = %v, want boundary retained", commit.ConsumedDueReasons)
	}
}

func TestExpectedJudgmentNeverOverridesIndependentUrgentAssessment(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	in.Judgment = &judgment
	in.JudgmentApplicability = EvaluateExpectedJudgment(judgment, in, in.Now)
	action := model.OperatorActionInvestigateSituation
	commit := ControllerCommit{
		Lifecycle: model.LifecycleActive, Attention: model.AttentionUrgent,
		Assessment: model.Assessment{Attention: model.AttentionUrgent, ActionContract: model.ActionContract{
			NextActor: model.NextActorOperator, OperatorActionRequired: &action,
		}},
	}
	applyExpectedJudgment(&commit, in, in.Now)
	if commit.Assessment.ActionContract.OperatorActionRequired == nil || commit.JudgmentApplicable {
		t.Fatalf("urgent assessment was quieted: %+v", commit)
	}
}

func TestExpectedJudgmentDoesNotSuppressRequestAfterSameCycleImpactChange(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	in.Judgment = &judgment
	in.JudgmentApplicability = EvaluateExpectedJudgment(judgment, in, in.Now)
	action := model.OperatorActionInvestigateSituation
	commit := ControllerCommit{
		Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
		Assessment: model.Assessment{
			Impact: model.ImpactConfirmed, Attention: model.AttentionInvestigate,
			ActionContract: model.ActionContract{NextActor: model.NextActorOperator, OperatorActionRequired: &action},
		},
	}

	applyExpectedJudgment(&commit, in, in.Now)
	if commit.JudgmentApplicable || commit.JudgmentApplicabilityReason != model.JudgmentImpactChanged {
		t.Fatalf("same-cycle impact change retained authority: %+v", commit)
	}
	if commit.Assessment.ActionContract.OperatorActionRequired == nil {
		t.Fatalf("same-cycle changed-condition request was suppressed: %+v", commit.Assessment.ActionContract)
	}
}

func TestExpectedJudgmentDoesNotDelaySourceDrivenRecovery(t *testing.T) {
	in, judgment := expectedJudgmentFixture(t)
	in.Judgment = &judgment
	in.Situation.Lifecycle = model.LifecycleRecoveryPending
	for i := range in.Deliveries {
		in.Deliveries[i].Status = model.DeliveryStatusResolved
	}
	commit := ControllerCommit{
		Lifecycle: model.LifecycleRecovered,
		Attention: model.AttentionObserve,
		Assessment: model.Assessment{
			Lifecycle:      model.LifecycleRecovered,
			Attention:      model.AttentionObserve,
			ActionContract: model.ActionContract{NextActor: model.NextActorNone},
		},
	}

	applyExpectedJudgment(&commit, in, in.Now)
	if commit.Lifecycle != model.LifecycleRecovered || commit.JudgmentApplicable {
		t.Fatalf("source recovery was altered by judgment: %+v", commit)
	}
}
