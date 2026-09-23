// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func validExpectedBehaviorPolicy() model.ExpectedBehaviorPolicy {
	return model.ExpectedBehaviorPolicy{
		Scope: model.ExpectedBehaviorScope{
			GroupKey:              "host=db-prod-1",
			Source:                "zabbix",
			SourceInstanceID:      "prod-zabbix",
			Host:                  "db-prod-1",
			PrimaryTriggerID:      "18422",
			PrimaryTriggerVersion: "sha256:primary",
		},
		Conditions: model.ExpectedBehaviorConditions{
			Workload: "nightly_reconciliation",
			Schedule: model.ExpectedBehaviorSchedule{
				Days:       []model.ExpectedBehaviorWeekday{model.ExpectedBehaviorMonday},
				LocalStart: "22:00", LocalEnd: "06:00", Timezone: "Europe/Riga",
				StartToleranceMinutes: 10,
			},
			MaxDurationMinutes: 55,
		},
		ReviewDueAt: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
	}
}

func TestResolveExpectedBehaviorOccurrenceOwnsOvernightByStartDay(t *testing.T) {
	policy := validExpectedBehaviorPolicy()
	started := time.Date(2026, 9, 21, 19, 5, 0, 0, time.UTC) // Monday 22:05 in Riga.
	got, err := ResolveExpectedBehaviorOccurrence(policy.Conditions.Schedule, policy.Conditions.MaxDurationMinutes, started)
	if err != nil {
		t.Fatalf("ResolveExpectedBehaviorOccurrence: %v", err)
	}
	if got.OwningLocalDate != "2026-09-21" {
		t.Fatalf("owning date = %q, want 2026-09-21", got.OwningLocalDate)
	}
	if want := "2026-09-21T19:00:00Z"; got.Start.UTC().Format(time.RFC3339) != want {
		t.Fatalf("start = %s, want %s", got.Start.UTC().Format(time.RFC3339), want)
	}
	if want := "2026-09-22T03:00:00Z"; got.End.UTC().Format(time.RFC3339) != want {
		t.Fatalf("end = %s, want %s", got.End.UTC().Format(time.RFC3339), want)
	}
	if want := started.Add(55 * time.Minute); !got.Boundary.Equal(want) {
		t.Fatalf("boundary = %s, want %s", got.Boundary, want)
	}
}

func TestResolveExpectedBehaviorOccurrenceToleranceEdges(t *testing.T) {
	policy := validExpectedBehaviorPolicy()
	tests := []struct {
		name    string
		started time.Time
		wantErr bool
	}{
		{"lower inclusive", time.Date(2026, 9, 21, 18, 50, 0, 0, time.UTC), false},
		{"upper inclusive", time.Date(2026, 9, 21, 19, 10, 0, 0, time.UTC), false},
		{"before lower", time.Date(2026, 9, 21, 18, 49, 59, 0, time.UTC), true},
		{"after upper", time.Date(2026, 9, 21, 19, 10, 1, 0, time.UTC), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveExpectedBehaviorOccurrence(policy.Conditions.Schedule, policy.Conditions.MaxDurationMinutes, tc.started)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestResolveExpectedBehaviorOccurrenceDSTBoundariesAreDeterministic(t *testing.T) {
	tests := []struct {
		name      string
		day       model.ExpectedBehaviorWeekday
		start     string
		end       string
		started   time.Time
		wantStart string
		wantEnd   string
	}{
		{
			name: "spring missing start advances", day: model.ExpectedBehaviorSunday,
			start: "03:30", end: "05:00", started: time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC),
			wantStart: "2026-03-29T01:00:00Z", wantEnd: "2026-03-29T02:00:00Z",
		},
		{
			name: "autumn repeated start chooses earliest and end latest", day: model.ExpectedBehaviorSunday,
			start: "03:30", end: "04:30", started: time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC),
			wantStart: "2026-10-25T00:30:00Z", wantEnd: "2026-10-25T02:30:00Z",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			schedule := model.ExpectedBehaviorSchedule{
				Days: []model.ExpectedBehaviorWeekday{tc.day}, LocalStart: tc.start, LocalEnd: tc.end,
				Timezone: "Europe/Riga", StartToleranceMinutes: 120,
			}
			got, err := ResolveExpectedBehaviorOccurrence(schedule, 7*24*60, tc.started)
			if err != nil {
				t.Fatalf("ResolveExpectedBehaviorOccurrence: %v", err)
			}
			if got.Start.UTC().Format(time.RFC3339) != tc.wantStart || got.End.UTC().Format(time.RFC3339) != tc.wantEnd {
				t.Fatalf("range = %s..%s, want %s..%s", got.Start.UTC().Format(time.RFC3339), got.End.UTC().Format(time.RFC3339), tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestValidateExpectedBehaviorPolicyRejectsInvalidShape(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*model.ExpectedBehaviorPolicy)
	}{
		{"unsupported source", func(p *model.ExpectedBehaviorPolicy) { p.Scope.Source = "alertmanager" }},
		{"missing installation", func(p *model.ExpectedBehaviorPolicy) { p.Scope.SourceInstanceID = "" }},
		{"bad timezone", func(p *model.ExpectedBehaviorPolicy) { p.Conditions.Schedule.Timezone = "Mars/Olympus" }},
		{"equal times", func(p *model.ExpectedBehaviorPolicy) {
			p.Conditions.Schedule.LocalEnd = p.Conditions.Schedule.LocalStart
		}},
		{"duplicate day", func(p *model.ExpectedBehaviorPolicy) {
			p.Conditions.Schedule.Days = append(p.Conditions.Schedule.Days, model.ExpectedBehaviorMonday)
		}},
		{"tolerance too large", func(p *model.ExpectedBehaviorPolicy) { p.Conditions.Schedule.StartToleranceMinutes = 121 }},
		{"duration missing", func(p *model.ExpectedBehaviorPolicy) { p.Conditions.MaxDurationMinutes = 0 }},
		{"duration too large", func(p *model.ExpectedBehaviorPolicy) { p.Conditions.MaxDurationMinutes = 7*24*60 + 1 }},
		{"review not future", func(p *model.ExpectedBehaviorPolicy) { p.ReviewDueAt = now }},
		{"primary reused", func(p *model.ExpectedBehaviorPolicy) {
			p.Conditions.RequiredCompanions = []model.ExpectedBehaviorBinding{{
				Role: "duplicate", Source: "zabbix", SourceInstanceID: p.Scope.SourceInstanceID,
				Host: p.Scope.Host, TriggerID: p.Scope.PrimaryTriggerID, TriggerVersion: p.Scope.PrimaryTriggerVersion,
			}}
		}},
		{"role reused", func(p *model.ExpectedBehaviorPolicy) {
			p.Conditions.RequiredCompanions = []model.ExpectedBehaviorBinding{{Role: "database_lock", Source: "zabbix", SourceInstanceID: "prod-zabbix", Host: "db-prod-1", TriggerID: "1", TriggerVersion: "v1"}}
			p.Conditions.ForbiddenSignals = []model.ExpectedBehaviorBinding{{Role: "database_lock", Source: "zabbix", SourceInstanceID: "prod-zabbix", Host: "db-prod-1", TriggerID: "2", TriggerVersion: "v2"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := validExpectedBehaviorPolicy()
			tc.mutate(&policy)
			if err := ValidateExpectedBehaviorPolicy(policy, now); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := ValidateExpectedBehaviorPolicy(validExpectedBehaviorPolicy(), now); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}
