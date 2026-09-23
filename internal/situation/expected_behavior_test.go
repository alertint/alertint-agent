// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func evaluatorHead(id string) model.ExpectedBehaviorHead {
	return model.ExpectedBehaviorHead{
		EnvelopeID: id, Version: 1, State: model.ExpectedBehaviorStateActive, AssertedOperator: "default",
		Policy: &model.ExpectedBehaviorPolicy{
			Scope: model.ExpectedBehaviorScope{GroupKey: "host=db-01", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", PrimaryTriggerID: "100", PrimaryTriggerVersion: "v1"},
			Conditions: model.ExpectedBehaviorConditions{
				Workload: "reconciliation", MaxDurationMinutes: 55,
				Schedule: model.ExpectedBehaviorSchedule{Days: []model.ExpectedBehaviorWeekday{model.ExpectedBehaviorMonday}, LocalStart: "22:00", LocalEnd: "23:30", Timezone: "Europe/Riga", StartToleranceMinutes: 10},
			},
		},
	}
}

func TestEvaluateExpectedBehaviors_AlertmanagerRuleVersionAndScope(t *testing.T) {
	now := time.Date(2026, 9, 21, 22, 5, 0, 0, time.UTC)
	policy := model.ExpectedBehaviorPolicy{Scope: model.ExpectedBehaviorScope{GroupKey: "service=payment", Source: "alertmanager", SourceInstanceID: "prod-am", ProducerID: "prod-prom", ScopeLabels: map[string]string{"service": "payment"}, PrimaryRuleID: "prometheus:prod-prom:jobs:ReconciliationLoad", PrimaryRuleVersion: "sha256:v1"}, Conditions: model.ExpectedBehaviorConditions{Workload: "nightly_reconciliation", Schedule: model.ExpectedBehaviorSchedule{Days: []model.ExpectedBehaviorWeekday{model.ExpectedBehaviorMonday}, LocalStart: "22:00", LocalEnd: "23:00", Timezone: "UTC", StartToleranceMinutes: 10}, MaxDurationMinutes: 55}, ReviewDueAt: now.Add(24 * time.Hour)}
	head := model.ExpectedBehaviorHead{EnvelopeID: "env-am", Version: 1, State: model.ExpectedBehaviorStateActive, Scope: policy.Scope, Policy: &policy}
	in := ExpectedBehaviorInput{SituationID: "sit", SituationVersion: 1, GroupKey: "service=payment", Now: now, PrimaryStartedAt: now.Add(-5 * time.Minute), Source: "alertmanager", SourceInstanceID: "prod-am", ProducerID: "prod-prom", ScopeLabels: map[string]string{"service": "payment"}, PrimaryRuleID: policy.Scope.PrimaryRuleID, PrimaryRuleVersion: "sha256:v1", PrimaryPresence: "present", Heads: []model.ExpectedBehaviorHead{head}, FiringSignals: []ExpectedBehaviorSignal{{SourceInstanceID: "prod-am", ProducerID: "prod-prom", RuleID: policy.Scope.PrimaryRuleID, RuleVersion: "sha256:v1", ScopeLabels: map[string]string{"service": "payment"}, Presence: "present", ExpiresAt: now.Add(time.Minute), EvidenceRefs: []string{"fact:rule"}}}}
	if got := EvaluateExpectedBehaviors(in); got.Disposition != model.ExpectedBehaviorDispositionMatched || got.Occurrence == nil || !got.Occurrence.Boundary.Equal(time.Date(2026, 9, 21, 22, 55, 0, 0, time.UTC)) || got.EvidenceExpiresAt == nil || !got.EvidenceExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("evaluation = %+v", got)
	}
	in.PrimaryRuleVersion = "sha256:v2"
	if got := EvaluateExpectedBehaviors(in); got.Reason != model.ExpectedBehaviorReasonPrimaryDefinitionChanged {
		t.Fatalf("changed evaluation = %+v", got)
	}
	in.PrimaryRuleVersion = "sha256:v1"
	in.ScopeLabels = map[string]string{"service": "checkout"}
	if got := EvaluateExpectedBehaviors(in); got.Reason != model.ExpectedBehaviorReasonScopeMismatch {
		t.Fatalf("scope evaluation = %+v", got)
	}
}

func evaluatorInput(heads ...model.ExpectedBehaviorHead) ExpectedBehaviorInput {
	started := time.Date(2026, 9, 21, 19, 5, 0, 0, time.UTC)
	return ExpectedBehaviorInput{
		SituationID: "sit-1", SituationVersion: 3, GroupKey: "host=db-01", Now: started.Add(10 * time.Minute), PrimaryStartedAt: started,
		Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", PrimaryTriggerID: "100", PrimaryVersion: "v1", Heads: heads,
	}
}

func TestEvaluateExpectedBehaviorsMatchWinsAcrossAlternatives(t *testing.T) {
	violated := evaluatorHead("env-a")
	violated.Policy.Conditions.RequiredCompanions = []model.ExpectedBehaviorBinding{{Role: "lag", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "200", TriggerVersion: "v1"}}
	matched := evaluatorHead("env-b")
	in := evaluatorInput(violated, matched)
	in.Observations = []ExpectedBehaviorSignal{{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "200", TriggerVersion: "v1", Presence: "absent", ExpiresAt: in.Now.Add(time.Minute)}}
	got := EvaluateExpectedBehaviors(in)
	if got.Disposition != model.ExpectedBehaviorDispositionMatched || got.ChosenEnvelopeID != "env-b" {
		t.Fatalf("evaluation=%+v", got)
	}
}

func TestEvaluateExpectedBehaviorsCriticalAlwaysWins(t *testing.T) {
	in := evaluatorInput(evaluatorHead("env-a"))
	in.HasCriticalFiring = true
	got := EvaluateExpectedBehaviors(in)
	if got.Disposition != model.ExpectedBehaviorDispositionViolated || got.Reason != model.ExpectedBehaviorReasonUrgent {
		t.Fatalf("evaluation=%+v", got)
	}
}

func TestEvaluateExpectedBehaviorsUnknownBeatsAllViolated(t *testing.T) {
	missing := evaluatorHead("env-a")
	missing.Policy.Conditions.RequiredCompanions = []model.ExpectedBehaviorBinding{{Role: "lag", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "200", TriggerVersion: "v1"}}
	changed := evaluatorHead("env-b")
	changed.Policy.Scope.PrimaryTriggerVersion = "v0"
	got := EvaluateExpectedBehaviors(evaluatorInput(missing, changed))
	if got.Disposition != model.ExpectedBehaviorDispositionAuthorityUnavailable || got.Reason != model.ExpectedBehaviorReasonObservationUnavailable {
		t.Fatalf("evaluation=%+v", got)
	}
}

func TestExpectedBehaviorExplanationUsesLatestNotApplicableSchedule(t *testing.T) {
	old := evaluatorHead("env-a")
	old.UpdatedAt = time.Date(2026, 9, 22, 19, 0, 0, 0, time.UTC)
	old.InvalidatedAt = &old.UpdatedAt
	newer := evaluatorHead("env-b")
	newer.UpdatedAt = old.UpdatedAt.Add(time.Hour)
	newer.State = model.ExpectedBehaviorStateRevoked
	newer.Policy = nil
	for _, tc := range []struct {
		name string
		head model.ExpectedBehaviorHead
		want model.ExpectedBehaviorReason
	}{
		{name: "withdrawn", head: newer, want: model.ExpectedBehaviorReasonRevoked},
		{name: "active but out of scope", head: func() model.ExpectedBehaviorHead {
			head := newer
			head.State = model.ExpectedBehaviorStateActive
			head.Policy = evaluatorHead("env-b").Policy
			head.Policy.Scope.Host = "other-host"
			return head
		}(), want: model.ExpectedBehaviorReasonScopeMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := evaluatorInput(old, tc.head)
			got := EvaluateExpectedBehaviors(in)
			if got.Disposition != model.ExpectedBehaviorDispositionNotApplicable || got.Reason != tc.want {
				t.Fatalf("evaluation = %+v, want %s", got, tc.want)
			}
			if got.Candidates[0].EnvelopeID != "env-a" || got.Candidates[1].EnvelopeID != "env-b" {
				t.Fatalf("candidate order changed: %+v", got.Candidates)
			}
			briefing := CommittedOperatorBriefing(SnapshotInput{ExpectedBehaviorHeads: in.Heads}, ControllerCommit{ExpectedBehaviorEvaluation: &got})
			if briefing.ExpectedBehavior == nil || briefing.ExpectedBehavior.EnvelopeID != "env-b" || briefing.ExpectedBehavior.Reason != tc.want {
				t.Fatalf("operator explanation = %+v, want env-b/%s", briefing.ExpectedBehavior, tc.want)
			}
		})
	}
}

func TestEvaluateExpectedBehaviorsRequiredForbiddenAndUnexpected(t *testing.T) {
	head := evaluatorHead("env-a")
	head.Policy.Conditions.RequiredCompanions = []model.ExpectedBehaviorBinding{{Role: "lag", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "200", TriggerVersion: "v1"}}
	head.Policy.Conditions.ForbiddenSignals = []model.ExpectedBehaviorBinding{{Role: "backup_failed", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "300", TriggerVersion: "v1"}}
	in := evaluatorInput(head)
	in.Observations = []ExpectedBehaviorSignal{
		{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "200", TriggerVersion: "v1", Presence: "present", ExpiresAt: in.Now.Add(time.Minute)},
		{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "300", TriggerVersion: "v1", Presence: "absent", ExpiresAt: in.Now.Add(time.Minute)},
	}
	if got := EvaluateExpectedBehaviors(in); got.Disposition != model.ExpectedBehaviorDispositionMatched {
		t.Fatalf("match=%+v", got)
	}
	in.Observations[1].Presence = "present"
	if got := EvaluateExpectedBehaviors(in); got.Reason != model.ExpectedBehaviorReasonForbiddenPresent {
		t.Fatalf("forbidden=%+v", got)
	}
	in.Observations[1].Presence = "absent"
	in.FiringSignals = []ExpectedBehaviorSignal{{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "999", TriggerVersion: "v1", Presence: "present"}}
	if got := EvaluateExpectedBehaviors(in); got.Reason != model.ExpectedBehaviorReasonUnexpectedSymptom {
		t.Fatalf("unexpected=%+v", got)
	}
}

func TestEvaluateExpectedBehaviorsOptionalCompanionMayBeAbsentButMustBeProvenWhenFiring(t *testing.T) {
	head := evaluatorHead("env-a")
	head.Policy.Conditions.AllowedCompanions = []model.ExpectedBehaviorBinding{{Role: "backup", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "400", TriggerVersion: "v1"}}
	in := evaluatorInput(head)
	if got := EvaluateExpectedBehaviors(in); got.Disposition != model.ExpectedBehaviorDispositionMatched {
		t.Fatalf("absent optional companion = %+v", got)
	}
	in.FiringSignals = []ExpectedBehaviorSignal{{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "400", Presence: "present"}}
	if got := EvaluateExpectedBehaviors(in); got.Disposition != model.ExpectedBehaviorDispositionAuthorityUnavailable {
		t.Fatalf("unproven firing optional companion = %+v", got)
	}
	in.Observations = []ExpectedBehaviorSignal{{SourceInstanceID: "prod-zbx", Host: "db-01", TriggerID: "400", TriggerVersion: "v1", Presence: "present", ExpiresAt: in.Now.Add(time.Minute)}}
	if got := EvaluateExpectedBehaviors(in); got.Disposition != model.ExpectedBehaviorDispositionMatched {
		t.Fatalf("proven firing optional companion = %+v", got)
	}
}

func TestExpectedBehaviorBasisHashStableAndOverlayOnlyClearsOperatorRequest(t *testing.T) {
	in := evaluatorInput(evaluatorHead("env-a"))
	a, b := EvaluateExpectedBehaviors(in), EvaluateExpectedBehaviors(in)
	if a.BasisHash == "" || a.BasisHash != b.BasisHash {
		t.Fatalf("basis hashes %q %q", a.BasisHash, b.BasisHash)
	}
	action := model.OperatorAction("acknowledge")
	alertintAction := model.AlertINTAction("monitor")
	commit := ControllerCommit{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, Assessment: model.Assessment{Attention: model.AttentionObserve, ActionContract: model.ActionContract{OperatorActionRequired: &action, AlertINTAction: &alertintAction, NextActor: model.NextActorOperator}}}
	ApplyExpectedBehaviorAuthority(&commit, &a)
	if commit.Assessment.ActionContract.OperatorActionRequired != nil || commit.Assessment.ActionContract.NextActor != model.NextActorAlertINT || commit.Assessment.ActionContract.NextUpdateAt == nil {
		t.Fatalf("commit=%+v", commit)
	}
}

func TestApplyExpectedBehaviorAuthorityChecksFreshEvidenceBeforeScheduleBoundary(t *testing.T) {
	now := time.Date(2026, 9, 21, 22, 5, 0, 0, time.UTC)
	scheduleBoundary, evidenceBoundary := now.Add(time.Hour), now.Add(time.Minute)
	evaluation := model.ExpectedBehaviorEvaluation{
		Disposition:       model.ExpectedBehaviorDispositionMatched,
		Occurrence:        &model.ExpectedBehaviorOccurrence{Boundary: scheduleBoundary},
		EvidenceExpiresAt: &evidenceBoundary,
	}
	commit := ControllerCommit{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, Assessment: model.Assessment{Attention: model.AttentionObserve}}
	ApplyExpectedBehaviorAuthority(&commit, &evaluation)
	if got := commit.Assessment.ActionContract.NextUpdateAt; got == nil || !got.Equal(evidenceBoundary) {
		t.Fatalf("next update = %v, want %v", got, evidenceBoundary)
	}
	RefreshExpectedBehaviorEvaluationForCommit(&evaluation, false, evidenceBoundary)
	if evaluation.Disposition != model.ExpectedBehaviorDispositionAuthorityUnavailable || evaluation.Reason != model.ExpectedBehaviorReasonObservationUnavailable {
		t.Fatalf("expired evaluation = %+v", evaluation)
	}
}
