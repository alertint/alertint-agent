// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
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

func TestBuildPlansSeparatesLifecycleAndAssessmentPhases(t *testing.T) {
	anchor := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	in := basicInput(anchor)
	in.Members[0].ObservationDeadlineAt = anchor.Add(-time.Minute) // past deadline: time-sensitive -> lifecycle

	assessmentPlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(assessmentPlans) != 0 {
		t.Fatalf("expected 0 assessment-phase plans for a time-sensitive member, got %d", len(assessmentPlans))
	}

	in.Phase = model.PhaseLifecycle
	lifecyclePlans, _, err := BuildPlans(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(lifecyclePlans) != 1 {
		t.Fatalf("expected 1 lifecycle-phase plan, got %d", len(lifecyclePlans))
	}
	if lifecyclePlans[0].Phase != model.PhaseLifecycle {
		t.Fatalf("plan phase = %q, want lifecycle", lifecyclePlans[0].Phase)
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
