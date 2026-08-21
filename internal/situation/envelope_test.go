// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func envelopeWithCompanions(required, allowed []string) model.EnvelopeVersion {
	return model.EnvelopeVersion{
		EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{RequiredCompanionSignals: required, AllowedCompanionSignals: allowed},
	}
}

func observed(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

func envelopeFacts(active []string, observable map[string]bool) EnvelopeFacts {
	observedNames := make([]string, 0, len(observable))
	for name := range observable {
		observedNames = append(observedNames, name)
	}
	return EnvelopeFacts{ActiveSignals: active, ObservedSignals: observedNames}
}

func TestRequiredAndAllowedCompanions(t *testing.T) {
	env := envelopeWithCompanions([]string{"database_lock"}, []string{"slow_query"})
	cases := []struct {
		name       string
		active     []string
		observable map[string]bool
		want       model.EnvelopeEvaluationResult
	}{
		{"required present optional absent", []string{"database_lock"}, observed("database_lock", "slow_query"), model.EnvelopeEvaluationMatch},
		{"required absent", nil, observed("database_lock"), model.EnvelopeEvaluationViolation},
		{"required unavailable", nil, observed(), model.EnvelopeEvaluationAuthorityRemoved},
		{"unlisted active", []string{"database_lock", "replication_lag"}, observed("database_lock", "replication_lag"), model.EnvelopeEvaluationAuthorityRemoved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateEnvelope(env, envelopeFacts(tc.active, tc.observable))
			if got.Result != tc.want {
				t.Fatalf("result=%s want=%s (matched=%v violations=%v observability=%v)", got.Result, tc.want, got.MatchedFields, got.Violations, got.Observability)
			}
		})
	}
}

func TestEvaluateEnvelopeInactiveStatusIsNotApplicable(t *testing.T) {
	v := envelopeWithCompanions(nil, nil)
	v.Status = model.EnvelopeStatusRevoked
	got := EvaluateEnvelope(v, EnvelopeFacts{})
	if got.Result != model.EnvelopeEvaluationNotApplicable {
		t.Fatalf("result=%s", got.Result)
	}
}

func TestEvaluateEnvelopeForbiddenImpactSignal(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{ForbiddenImpactSignals: []string{"data_loss"}}}

	present := EvaluateEnvelope(v, EnvelopeFacts{ActiveImpactSignals: []string{"data_loss"}, ObservedImpactSignals: []string{"data_loss"}})
	if present.Result != model.EnvelopeEvaluationViolation {
		t.Fatalf("present result=%s", present.Result)
	}

	confirmedAbsent := EvaluateEnvelope(v, EnvelopeFacts{ObservedImpactSignals: []string{"data_loss"}})
	if confirmedAbsent.Result != model.EnvelopeEvaluationMatch {
		t.Fatalf("confirmed-absent result=%s", confirmedAbsent.Result)
	}

	unobserved := EvaluateEnvelope(v, EnvelopeFacts{})
	if unobserved.Result != model.EnvelopeEvaluationAuthorityRemoved {
		t.Fatalf("unobserved result=%s", unobserved.Result)
	}
}

func TestEvaluateEnvelopeScheduleOutsideWindowViolates(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{Schedule: &model.Schedule{Days: []string{"sun"}, LocalStart: "01:30", LocalEnd: "03:30", Timezone: "Europe/Riga"}}}
	outside := mustScheduleTime(t, "2026-10-25T12:00:00Z")
	got := EvaluateEnvelope(v, EnvelopeFacts{Occurred: outside})
	if got.Result != model.EnvelopeEvaluationViolation {
		t.Fatalf("result=%s", got.Result)
	}

	inside := mustScheduleTime(t, "2026-10-25T01:00:00Z")
	matched := EvaluateEnvelope(v, EnvelopeFacts{Occurred: inside})
	if matched.Result != model.EnvelopeEvaluationMatch {
		t.Fatalf("inside result=%s", matched.Result)
	}
}

// TestEvaluateEnvelopePersistsResolvedScheduleWindow covers review finding
// #1: the resolved UTC schedule interval must be carried onto EnvelopeResult
// (never re-derived), for both a match and a violation, and DST-sensitive
// determinations stay independently auditable.
func TestEvaluateEnvelopePersistsResolvedScheduleWindow(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{Schedule: &model.Schedule{Days: []string{"sun"}, LocalStart: "01:30", LocalEnd: "03:30", Timezone: "Europe/Riga"}}}
	wantStart := mustScheduleTime(t, "2026-10-24T22:30:00Z")
	wantEnd := mustScheduleTime(t, "2026-10-25T01:30:00Z")

	inside := EvaluateEnvelope(v, EnvelopeFacts{Occurred: mustScheduleTime(t, "2026-10-25T01:00:00Z")})
	if inside.ScheduleWindowStart == nil || inside.ScheduleWindowEnd == nil {
		t.Fatalf("expected a persisted schedule window on match, got %+v", inside)
	}
	if !inside.ScheduleWindowStart.Equal(wantStart) || !inside.ScheduleWindowEnd.Equal(wantEnd) {
		t.Fatalf("window=%s..%s want=%s..%s", inside.ScheduleWindowStart, inside.ScheduleWindowEnd, wantStart, wantEnd)
	}

	outside := EvaluateEnvelope(v, EnvelopeFacts{Occurred: mustScheduleTime(t, "2026-10-25T12:00:00Z")})
	if outside.Result != model.EnvelopeEvaluationViolation {
		t.Fatalf("result=%s", outside.Result)
	}
	if outside.ScheduleWindowStart == nil || outside.ScheduleWindowEnd == nil {
		t.Fatalf("expected a persisted schedule window on violation too, got %+v", outside)
	}

	noSchedule := EvaluateEnvelope(envelopeWithCompanions(nil, nil), EnvelopeFacts{})
	if noSchedule.ScheduleWindowStart != nil || noSchedule.ScheduleWindowEnd != nil {
		t.Fatalf("expected no persisted window without a configured schedule, got %+v", noSchedule)
	}
}

// TestEvaluateEnvelopeScopeGates covers matching-order steps 1-3 (exact
// group scope, source/trigger identity, current trigger version): any
// mismatch is a hard gate to not_applicable, evaluated before any condition.
func TestEvaluateEnvelopeScopeGates(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Scope:      model.EnvelopeScope{GroupKey: "host=db-prod-1", Source: "zabbix", TriggerID: "18422", TriggerVersion: "sha256:923b"},
		Conditions: model.EnvelopeConditions{RequiredCompanionSignals: []string{"database_lock"}}}
	matchingFacts := func() EnvelopeFacts {
		return EnvelopeFacts{GroupKey: "host=db-prod-1", Source: "zabbix", TriggerID: "18422", TriggerVersion: "sha256:923b",
			ActiveSignals: []string{"database_lock"}, ObservedSignals: []string{"database_lock"}}
	}

	if got := EvaluateEnvelope(v, matchingFacts()); got.Result != model.EnvelopeEvaluationMatch {
		t.Fatalf("exact scope match result=%s", got.Result)
	}

	cases := map[string]func(*EnvelopeFacts){
		"group_key mismatch":       func(f *EnvelopeFacts) { f.GroupKey = "host=other" },
		"source mismatch":          func(f *EnvelopeFacts) { f.Source = "prometheus" },
		"trigger_id mismatch":      func(f *EnvelopeFacts) { f.TriggerID = "99999" },
		"trigger_version mismatch": func(f *EnvelopeFacts) { f.TriggerVersion = "sha256:changed" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			facts := matchingFacts()
			mutate(&facts)
			got := EvaluateEnvelope(v, facts)
			if got.Result != model.EnvelopeEvaluationNotApplicable {
				t.Fatalf("%s: result=%s, want not_applicable", name, got.Result)
			}
			if len(got.MatchedFields) != 0 || len(got.Violations) != 0 || len(got.Observability) != 0 {
				t.Fatalf("%s: expected no condition checks to run once scope is gated, got matched=%v violations=%v observability=%v",
					name, got.MatchedFields, got.Violations, got.Observability)
			}
		})
	}
}

func TestEvaluateEnvelopeOmittedDurationMaxDoesNotAuthorizeArbitraryDuration(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{DurationMinutes: &model.DurationRange{Min: 5, Max: 0}}}
	start := mustScheduleTime(t, "2026-01-01T00:00:00Z")
	got := EvaluateEnvelope(v, EnvelopeFacts{Occurred: start.Add(time.Minute), ScopeStartedAt: start})
	if got.Result != model.EnvelopeEvaluationViolation {
		t.Fatalf("result=%s, want violation for a zero-valued max duration", got.Result)
	}
}

func TestEvaluateEnvelopeDurationScopeUnobservedRemovesAuthority(t *testing.T) {
	v := model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive,
		Conditions: model.EnvelopeConditions{DurationMinutes: &model.DurationRange{Min: 0, Max: 30}}}
	got := EvaluateEnvelope(v, EnvelopeFacts{Occurred: mustScheduleTime(t, "2026-01-01T00:00:00Z")})
	if got.Result != model.EnvelopeEvaluationAuthorityRemoved {
		t.Fatalf("result=%s", got.Result)
	}
}

func TestEvaluateEnvelopeQuietingAuthorityDefaultOff(t *testing.T) {
	v := envelopeWithCompanions(nil, nil)
	matchNoFlag := EvaluateEnvelope(v, EnvelopeFacts{})
	if matchNoFlag.Result != model.EnvelopeEvaluationMatch || matchNoFlag.QuietingAuthority {
		t.Fatalf("expected match without quieting authority by default: %+v", matchNoFlag)
	}

	v.Conditions.AllowExpectedCritical = true
	matchWithFlag := EvaluateEnvelope(v, EnvelopeFacts{})
	if !matchWithFlag.QuietingAuthority {
		t.Fatalf("expected quieting authority when allow_expected_critical is set and result matches")
	}

	violating := envelopeWithCompanions([]string{"database_lock"}, nil)
	violating.Conditions.AllowExpectedCritical = true
	notMatch := EvaluateEnvelope(violating, EnvelopeFacts{ObservedSignals: []string{"database_lock"}})
	if notMatch.Result != model.EnvelopeEvaluationViolation || notMatch.QuietingAuthority {
		t.Fatalf("expected a violation never carries quieting authority: %+v", notMatch)
	}
}

func TestValidateEnvelopeConditionsRejectsOverlappingCompanions(t *testing.T) {
	err := ValidateEnvelopeConditions(model.EnvelopeConditions{
		RequiredCompanionSignals: []string{"database_lock"},
		AllowedCompanionSignals:  []string{"database_lock"},
	})
	if err == nil {
		t.Fatal("expected disjoint required/allowed rejection")
	}
}

func TestValidateEnvelopeConditionsRejectsZeroDurationMax(t *testing.T) {
	err := ValidateEnvelopeConditions(model.EnvelopeConditions{DurationMinutes: &model.DurationRange{Min: 0, Max: 0}})
	if err == nil {
		t.Fatal("expected an omitted/zero duration max to be rejected at confirm time")
	}
}

func TestValidateEnvelopeConditionsRejectsFreeTextUncertainty(t *testing.T) {
	free := "kinda uncertain"
	err := ValidateEnvelopeConditions(model.EnvelopeConditions{MaximumUncertainty: &free})
	if err == nil {
		t.Fatal("expected free-text maximum_uncertainty to be rejected")
	}
}

func TestValidateEnvelopeConditionsAcceptsClosedUncertainty(t *testing.T) {
	closed := uncertaintyPolicyMandatorySignalsObservable
	if err := ValidateEnvelopeConditions(model.EnvelopeConditions{MaximumUncertainty: &closed}); err != nil {
		t.Fatalf("expected the one closed maximum_uncertainty value to validate: %v", err)
	}
}

func TestValidateEnvelopeConditionsAcceptsDisjointSchedule(t *testing.T) {
	cond := model.EnvelopeConditions{
		RequiredCompanionSignals: []string{"database_lock"},
		AllowedCompanionSignals:  []string{"slow_query"},
		DurationMinutes:          &model.DurationRange{Min: 0, Max: 60},
		Schedule:                 &model.Schedule{Days: []string{"sun"}, LocalStart: "01:30", LocalEnd: "03:30", Timezone: "Europe/Riga"},
	}
	if err := ValidateEnvelopeConditions(cond); err != nil {
		t.Fatalf("expected valid conditions to accept: %v", err)
	}
}
