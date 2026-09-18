// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"encoding/json"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

func basicInput(anchor time.Time) PlannerInput {
	return PlannerInput{
		Anchor:   anchor,
		GroupKey: "service=checkout",
		Phase:    model.PhaseAssessment,
		Members: []MemberSubject{
			{SubjectID: "signal-a", Source: "alertmanager", Labels: map[string]string{"service": "checkout"}},
		},
		Configured: []CapabilityDescriptor{
			{Capability: model.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: 20, MaxRequestsHint: 1},
		},
		CycleCap: 6,
	}
}

func TestBuildPlansDeterministicForFixedInput(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)

	plans1, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	plans2, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans1) != 1 || len(plans2) != 1 {
		t.Fatalf("expected exactly 1 plan each run, got %d and %d", len(plans1), len(plans2))
	}
	if plans1[0].Capability != model.CapabilityPrometheusQuery {
		t.Fatalf("capability = %q, want prometheus_query", plans1[0].Capability)
	}
	if plans1[0].Scope.SubjectID != "signal-a" {
		t.Fatalf("scope subject = %q, want signal-a", plans1[0].Scope.SubjectID)
	}
	if !plans1[0].End.Equal(anchor) {
		t.Fatalf("plan end = %v, want anchor %v", plans1[0].End, anchor)
	}
}

// TestBuildPlansDerivesZabbixParametersFromMemberLabels proves the planner
// carries adapter-proven host/zabbix_trigger_id/item_key labels (internal/
// ingress/zabbix.go's own webhook receiver sets all three) through into
// each candidate's typed Plan.Parameters — the ONLY way ZabbixMetricExecutor/
// ZabbixProblemExecutor can ever resolve an exact technical host and item/
// trigger (review F17: no Scope.SubjectID fallback for Host any more).
// zabbix_problem_history is lifecycle-phase evidence; zabbix_metric_range
// is assessment-phase corroboration, so each phase yields exactly one plan.
func TestBuildPlansDerivesZabbixParametersFromMemberLabels(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := PlannerInput{
		Anchor: anchor, GroupKey: "service=checkout", Phase: model.PhaseAssessment,
		Members: []MemberSubject{
			{SubjectID: "host-a", Source: "zabbix", Labels: map[string]string{
				"host": "db-01", "zabbix_trigger_id": "trigger-123", "item_key": "vfs.fs.size[/,pfree]",
			}},
		},
		Configured: []CapabilityDescriptor{
			{Capability: model.CapabilityZabbixMetricRange, DefaultWindow: time.Hour, DefaultLimit: 20, MaxRequestsHint: 2},
			{Capability: model.CapabilityZabbixProblemHist, DefaultWindow: time.Hour, DefaultLimit: 20, MaxRequestsHint: 2},
		},
		CycleCap: 6,
	}
	assessmentPlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Phase = model.PhaseLifecycle
	lifecyclePlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	plans := append(append([]model.Plan(nil), assessmentPlans...), lifecyclePlans...)
	if len(plans) != 2 {
		t.Fatalf("plans = %d, want 2 (one per phase)", len(plans))
	}
	byCapability := make(map[model.Capability]model.Plan, len(plans))
	for _, p := range plans {
		byCapability[p.Capability] = p
	}

	metricPlan := byCapability[model.CapabilityZabbixMetricRange]
	if metricPlan.Phase != model.PhaseAssessment {
		t.Fatalf("zabbix_metric_range phase = %q, want assessment", metricPlan.Phase)
	}
	var metricParams struct {
		Host    string `json:"host"`
		ItemKey string `json:"item_key"`
	}
	if err := json.Unmarshal(metricPlan.Parameters, &metricParams); err != nil {
		t.Fatalf("unmarshal zabbix_metric_range parameters: %v (raw=%s)", err, metricPlan.Parameters)
	}
	if metricParams.ItemKey != "vfs.fs.size[/,pfree]" || metricParams.Host != "db-01" {
		t.Fatalf("zabbix_metric_range parameters = %+v, want host db-01 + item key", metricParams)
	}
	if metricPlan.MaxRequests != 2 {
		t.Fatalf("zabbix_metric_range max requests = %d, want 2 (item lookup + history read)", metricPlan.MaxRequests)
	}

	problemPlan := byCapability[model.CapabilityZabbixProblemHist]
	if problemPlan.Phase != model.PhaseLifecycle {
		t.Fatalf("zabbix_problem_history phase = %q, want lifecycle", problemPlan.Phase)
	}
	var problemParams struct {
		Host      string `json:"host"`
		TriggerID string `json:"trigger_id"`
	}
	if err := json.Unmarshal(problemPlan.Parameters, &problemParams); err != nil {
		t.Fatalf("unmarshal zabbix_problem_history parameters: %v (raw=%s)", err, problemPlan.Parameters)
	}
	if problemParams.TriggerID != "trigger-123" || problemParams.Host != "db-01" {
		t.Fatalf("zabbix_problem_history parameters = %+v, want host db-01 + trigger id", problemParams)
	}
}

// TestBuildPlansOmitsZabbixParametersWhenLabelsAbsent proves a member with
// no proven zabbix_trigger_id/item_key label produces a plan with empty
// Parameters — never a fabricated identifier — so the connector's own
// "no fallback" ItemKey/TriggerID check correctly, honestly reports
// vocabulary_unresolved rather than querying an invented target.
func TestBuildPlansOmitsZabbixParametersWhenLabelsAbsent(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := PlannerInput{
		Anchor: anchor, GroupKey: "service=checkout", Phase: model.PhaseAssessment,
		Members: []MemberSubject{
			{SubjectID: "host-b", Source: "zabbix", Labels: map[string]string{}},
		},
		Configured: []CapabilityDescriptor{
			{Capability: model.CapabilityZabbixMetricRange, DefaultWindow: time.Hour, DefaultLimit: 20, MaxRequestsHint: 1},
		},
		CycleCap: 6,
	}
	plans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	if len(plans[0].Parameters) != 0 {
		t.Fatalf("parameters = %s, want empty (no proven item_key label)", plans[0].Parameters)
	}
}

func TestBuildPlansSkipsCapabilityNotDueYet(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.RefreshCursors = []RefreshCursor{
		{Subject: "signal-a", Capability: model.CapabilityPrometheusQuery, NextRefreshAt: anchor.Add(time.Minute)},
	}
	plans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 0 {
		t.Fatalf("expected 0 plans (not yet due), got %d", len(plans))
	}
}

func TestBuildPlansAdmitsWhenRefreshCursorDue(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.RefreshCursors = []RefreshCursor{
		{Subject: "signal-a", Capability: model.CapabilityPrometheusQuery, NextRefreshAt: anchor.Add(-time.Minute)},
	}
	plans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan (due), got %d", len(plans))
	}
}

// TestBuildPlansSeparatesLifecycleAndAssessmentPhases: phase is decided by
// CAPABILITY (review F11) — store_read and zabbix_problem_history decide
// recovery/closure and run in the lifecycle phase; every corroborating
// capability runs in the assessment phase. A member checkpoint falling
// within the next refresh makes its LIFECYCLE reads time-sensitive; it never
// pulls a corroborating capability into the lifecycle phase.
func TestBuildPlansSeparatesLifecycleAndAssessmentPhases(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.Members[0].ObservationDeadlineAt = anchor.Add(-time.Minute) // past deadline
	in.Configured = append(in.Configured, CapabilityDescriptor{Capability: model.CapabilityZabbixProblemHist, DefaultWindow: time.Hour, DefaultLimit: 20, MaxRequestsHint: 2})

	assessmentPlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(assessmentPlans) != 1 || assessmentPlans[0].Capability != model.CapabilityPrometheusQuery {
		t.Fatalf("assessment plans = %+v, want exactly the prometheus_query corroboration", assessmentPlans)
	}
	if assessmentPlans[0].Tier == model.TierTimeSensitive {
		t.Fatalf("a corroborating read is never time-sensitive lifecycle work: tier = %q", assessmentPlans[0].Tier)
	}

	in.Phase = model.PhaseLifecycle
	lifecyclePlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(lifecyclePlans) != 1 {
		t.Fatalf("expected 1 lifecycle-phase plan, got %d", len(lifecyclePlans))
	}
	if lifecyclePlans[0].Phase != model.PhaseLifecycle || lifecyclePlans[0].Capability != model.CapabilityZabbixProblemHist {
		t.Fatalf("lifecycle plan = %+v, want the zabbix_problem_history lifecycle read", lifecyclePlans[0])
	}
	if lifecyclePlans[0].Tier != model.TierTimeSensitive {
		t.Fatalf("lifecycle plan tier = %q, want time_sensitive (deadline already passed)", lifecyclePlans[0].Tier)
	}
}

func TestBuildPlansSkipsUnresolvableMemberWithoutBroadFallback(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.Members[0].SubjectID = "" // unresolvable scope
	plans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 0 {
		t.Fatalf("expected 0 plans for an unresolvable member, got %d", len(plans))
	}
}

func TestBuildPlansProfileSuggestedCapabilityBecomesOptional(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.Configured = append(in.Configured, CapabilityDescriptor{
		Capability: model.CapabilityZabbixMetricRange, DefaultWindow: time.Hour, DefaultLimit: 100, MaxRequestsHint: 2,
	})
	in.ProfileGuidance = []model.ProfileGuidance{{UsefulCapabilities: []model.Capability{model.CapabilityZabbixMetricRange}}}
	in.InvestigationCredit = 100

	plans, alloc, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans (routine prometheus + optional zabbix), got %d", len(plans))
	}
	if alloc.OptionalRequests == 0 {
		t.Fatal("expected the profile-suggested capability to be admitted as optional")
	}
}

func TestBuildPlansRejectsEmptyMembers(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.Members = nil
	if _, _, err := BuildPlans(in); err == nil {
		t.Fatal("expected error for empty members")
	}
}

func TestBuildPlansEnforcesMaxPlansPerCycle(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.CycleCap = 100
	for i := 0; i < 20; i++ {
		in.Members = append(in.Members, MemberSubject{
			SubjectID: "signal-" + string(rune('a'+i)), Source: "alertmanager",
			Labels: map[string]string{"service": "checkout"},
		})
	}
	plans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) > model.MaxPlansPerCycle {
		t.Fatalf("plans = %d, exceeds cap %d", len(plans), model.MaxPlansPerCycle)
	}
}
