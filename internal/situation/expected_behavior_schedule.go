// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // scratch deployments still need IANA schedule resolution

	"github.com/alertint/alertint-agent/internal/situation/model"
)

const expectedBehaviorResolverVersion = 1

var expectedBehaviorIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidateExpectedBehaviorPolicy validates ADR-0054's complete, source-bound
// writable policy body.
func ValidateExpectedBehaviorPolicy(policy model.ExpectedBehaviorPolicy, confirmedAt time.Time) error {
	scope := policy.Scope
	if strings.TrimSpace(scope.GroupKey) == "" || strings.TrimSpace(scope.SourceInstanceID) == "" {
		return errors.New("expected behavior: scope requires group and installation")
	}
	switch scope.Source {
	case "zabbix":
		if strings.TrimSpace(scope.Host) == "" || strings.TrimSpace(scope.PrimaryTriggerID) == "" || strings.TrimSpace(scope.PrimaryTriggerVersion) == "" {
			return errors.New("expected behavior: zabbix scope requires host, trigger, and version")
		}
	case "alertmanager":
		if strings.TrimSpace(scope.ProducerID) == "" || strings.TrimSpace(scope.PrimaryRuleID) == "" || strings.TrimSpace(scope.PrimaryRuleVersion) == "" || strings.TrimSpace(scope.RuleGroup) == "" || strings.TrimSpace(scope.RuleName) == "" || len(scope.ScopeLabels) == 0 {
			return errors.New("expected behavior: alertmanager scope requires producer, rule, version, and labels")
		}
	default:
		return errors.New("expected behavior: source must be zabbix or alertmanager")
	}
	if !expectedBehaviorIdentifier.MatchString(policy.Conditions.Workload) {
		return errors.New("expected behavior: workload must be a lowercase identifier of at most 64 characters")
	}
	if err := validateExpectedBehaviorSchedule(policy.Conditions.Schedule); err != nil {
		return err
	}
	if policy.Conditions.MaxDurationMinutes < 1 || policy.Conditions.MaxDurationMinutes > 7*24*60 {
		return errors.New("expected behavior: maximum duration must be between 1 minute and 7 days")
	}
	if policy.ReviewDueAt.IsZero() || !policy.ReviewDueAt.After(confirmedAt) {
		return errors.New("expected behavior: review_due_at must be later than confirmation")
	}
	primaryKey := expectedBehaviorScopeBindingKey(scope)
	roles := make(map[string]struct{})
	bindings := make(map[string]struct{})
	sets := [][]model.ExpectedBehaviorBinding{
		policy.Conditions.RequiredCompanions,
		policy.Conditions.AllowedCompanions,
		policy.Conditions.ForbiddenSignals,
	}
	for _, set := range sets {
		for _, binding := range set {
			if err := validateExpectedBehaviorBinding(binding); err != nil {
				return err
			}
			if _, ok := roles[binding.Role]; ok {
				return fmt.Errorf("expected behavior: role %q is reused", binding.Role)
			}
			roles[binding.Role] = struct{}{}
			key := expectedBehaviorBindingSignalKey(binding)
			if key == primaryKey {
				return errors.New("expected behavior: primary trigger cannot be a companion or forbidden signal")
			}
			if _, ok := bindings[key]; ok {
				return errors.New("expected behavior: a binding cannot have multiple roles")
			}
			bindings[key] = struct{}{}
		}
	}
	return nil
}

func validateExpectedBehaviorBinding(binding model.ExpectedBehaviorBinding) error {
	if !expectedBehaviorIdentifier.MatchString(binding.Role) {
		return errors.New("expected behavior: binding role must be a lowercase identifier of at most 64 characters")
	}
	if strings.TrimSpace(binding.SourceInstanceID) == "" {
		return errors.New("expected behavior: binding requires installation")
	}
	switch binding.Source {
	case "zabbix":
		if strings.TrimSpace(binding.Host) == "" || strings.TrimSpace(binding.TriggerID) == "" || strings.TrimSpace(binding.TriggerVersion) == "" {
			return errors.New("expected behavior: zabbix binding requires host, trigger, and version")
		}
	case "alertmanager":
		if strings.TrimSpace(binding.ProducerID) == "" || strings.TrimSpace(binding.RuleID) == "" || strings.TrimSpace(binding.RuleVersion) == "" || strings.TrimSpace(binding.RuleGroup) == "" || strings.TrimSpace(binding.RuleName) == "" || len(binding.ScopeLabels) == 0 {
			return errors.New("expected behavior: alertmanager binding requires producer, rule, version, and labels")
		}
	default:
		return errors.New("expected behavior: binding source must be zabbix or alertmanager")
	}
	return nil
}

func expectedBehaviorScopeBindingKey(scope model.ExpectedBehaviorScope) string {
	if scope.Source == "alertmanager" {
		return scope.SourceInstanceID + "\x00" + scope.ProducerID + "\x00" + scope.PrimaryRuleID + "\x00" + canonicalExpectedBehaviorLabels(scope.ScopeLabels)
	}
	return expectedBehaviorBindingKey(scope.SourceInstanceID, scope.Host, scope.PrimaryTriggerID)
}

func expectedBehaviorBindingKey(instanceID, host, triggerID string) string {
	return instanceID + "\x00" + host + "\x00" + triggerID
}

func validateExpectedBehaviorSchedule(schedule model.ExpectedBehaviorSchedule) error {
	if len(schedule.Days) == 0 {
		return errors.New("expected behavior: schedule requires at least one weekday")
	}
	seen := make(map[model.ExpectedBehaviorWeekday]struct{}, len(schedule.Days))
	for _, day := range schedule.Days {
		if _, ok := expectedBehaviorTimeWeekday(day); !ok {
			return fmt.Errorf("expected behavior: invalid weekday %q", day)
		}
		if _, ok := seen[day]; ok {
			return fmt.Errorf("expected behavior: duplicate weekday %q", day)
		}
		seen[day] = struct{}{}
	}
	startHour, startMinute, err := parseExpectedBehaviorClock(schedule.LocalStart)
	if err != nil {
		return fmt.Errorf("expected behavior: local_start: %w", err)
	}
	endHour, endMinute, err := parseExpectedBehaviorClock(schedule.LocalEnd)
	if err != nil {
		return fmt.Errorf("expected behavior: local_end: %w", err)
	}
	if startHour == endHour && startMinute == endMinute {
		return errors.New("expected behavior: schedule start and end cannot be equal")
	}
	if _, err := time.LoadLocation(schedule.Timezone); err != nil {
		return errors.New("expected behavior: timezone must be a valid IANA name")
	}
	if schedule.StartToleranceMinutes < 0 || schedule.StartToleranceMinutes > 120 {
		return errors.New("expected behavior: start tolerance must be between 0 and 120 minutes")
	}
	return nil
}

// ResolveExpectedBehaviorOccurrence resolves the one schedule occurrence
// owned by primaryStartedAt. The returned UTC instants are persisted so a
// restart does not reinterpret DST boundaries.
func ResolveExpectedBehaviorOccurrence(schedule model.ExpectedBehaviorSchedule, maxDurationMinutes int, primaryStartedAt time.Time) (model.ExpectedBehaviorOccurrence, error) {
	if err := validateExpectedBehaviorSchedule(schedule); err != nil {
		return model.ExpectedBehaviorOccurrence{}, err
	}
	if maxDurationMinutes < 1 || maxDurationMinutes > 7*24*60 {
		return model.ExpectedBehaviorOccurrence{}, errors.New("expected behavior: maximum duration must be between 1 minute and 7 days")
	}
	loc, _ := time.LoadLocation(schedule.Timezone)
	localStart := primaryStartedAt.In(loc)
	dates := []time.Time{
		time.Date(localStart.Year(), localStart.Month(), localStart.Day(), 12, 0, 0, 0, loc),
		time.Date(localStart.Year(), localStart.Month(), localStart.Day()-1, 12, 0, 0, 0, loc),
	}
	tolerance := time.Duration(schedule.StartToleranceMinutes) * time.Minute
	type candidate struct {
		date       time.Time
		start, end time.Time
	}
	var candidates []candidate
	for _, date := range dates {
		day, ok := expectedBehaviorModelWeekday(date.Weekday())
		if !ok || !containsExpectedBehaviorDay(schedule.Days, day) {
			continue
		}
		start, end, err := resolveExpectedBehaviorRange(date, schedule, loc)
		if err != nil {
			return model.ExpectedBehaviorOccurrence{}, err
		}
		if primaryStartedAt.Before(start.Add(-tolerance)) || primaryStartedAt.After(start.Add(tolerance)) {
			continue
		}
		candidates = append(candidates, candidate{date: date, start: start, end: end})
	}
	if len(candidates) == 0 {
		return model.ExpectedBehaviorOccurrence{}, errors.New("expected behavior: primary start is outside the schedule tolerance")
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].start.Before(candidates[j].start) })
	chosen := candidates[len(candidates)-1]
	boundary := primaryStartedAt.Add(time.Duration(maxDurationMinutes) * time.Minute)
	if chosen.end.Before(boundary) {
		boundary = chosen.end
	}
	return model.ExpectedBehaviorOccurrence{
		OwningLocalDate: chosen.date.Format("2006-01-02"), Timezone: schedule.Timezone,
		Start: chosen.start.UTC(), End: chosen.end.UTC(), PrimaryStartedAt: primaryStartedAt.UTC(),
		Boundary: boundary.UTC(), ResolverVersion: expectedBehaviorResolverVersion,
	}, nil
}

func resolveExpectedBehaviorRange(date time.Time, schedule model.ExpectedBehaviorSchedule, loc *time.Location) (time.Time, time.Time, error) {
	startHour, startMinute, _ := parseExpectedBehaviorClock(schedule.LocalStart)
	endHour, endMinute, _ := parseExpectedBehaviorClock(schedule.LocalEnd)
	endDate := date
	if endHour*60+endMinute < startHour*60+startMinute {
		endDate = date.AddDate(0, 0, 1)
	}
	startCandidates := resolveExpectedBehaviorLocal(date.Year(), date.Month(), date.Day(), startHour, startMinute, loc)
	endCandidates := resolveExpectedBehaviorLocal(endDate.Year(), endDate.Month(), endDate.Day(), endHour, endMinute, loc)
	if len(startCandidates) == 0 || len(endCandidates) == 0 {
		return time.Time{}, time.Time{}, errors.New("expected behavior: schedule boundary could not be resolved")
	}
	start := startCandidates[0]
	end := endCandidates[len(endCandidates)-1]
	if !end.After(start) {
		return time.Time{}, time.Time{}, errors.New("expected behavior: resolved schedule end must follow start")
	}
	return start, end, nil
}

// resolveExpectedBehaviorLocal finds all UTC instants for one local minute.
// If the minute does not exist during a spring transition, it advances to
// the first valid local minute. Scanning UTC also exposes both autumn copies.
func resolveExpectedBehaviorLocal(year int, month time.Month, day, hour, minute int, loc *time.Location) []time.Time {
	wanted := time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
	for advance := 0; advance <= 180; advance++ {
		localMinute := wanted.Add(time.Duration(advance) * time.Minute)
		nominal := time.Date(localMinute.Year(), localMinute.Month(), localMinute.Day(), localMinute.Hour(), localMinute.Minute(), 0, 0, loc)
		var matches []time.Time
		for instant := nominal.UTC().Add(-4 * time.Hour); !instant.After(nominal.UTC().Add(4 * time.Hour)); instant = instant.Add(time.Minute) {
			got := instant.In(loc)
			if got.Year() == localMinute.Year() && got.Month() == localMinute.Month() && got.Day() == localMinute.Day() &&
				got.Hour() == localMinute.Hour() && got.Minute() == localMinute.Minute() {
				matches = append(matches, instant.UTC())
			}
		}
		if len(matches) > 0 {
			sort.Slice(matches, func(i, j int) bool { return matches[i].Before(matches[j]) })
			return matches
		}
	}
	return nil
}

func parseExpectedBehaviorClock(value string) (int, int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, 0, errors.New("must use HH:MM minute precision")
	}
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, 0, errors.New("must be a valid 24-hour time")
	}
	return parsed.Hour(), parsed.Minute(), nil
}

func containsExpectedBehaviorDay(days []model.ExpectedBehaviorWeekday, wanted model.ExpectedBehaviorWeekday) bool {
	for _, day := range days {
		if day == wanted {
			return true
		}
	}
	return false
}

func expectedBehaviorTimeWeekday(day model.ExpectedBehaviorWeekday) (time.Weekday, bool) {
	switch day {
	case model.ExpectedBehaviorMonday:
		return time.Monday, true
	case model.ExpectedBehaviorTuesday:
		return time.Tuesday, true
	case model.ExpectedBehaviorWednesday:
		return time.Wednesday, true
	case model.ExpectedBehaviorThursday:
		return time.Thursday, true
	case model.ExpectedBehaviorFriday:
		return time.Friday, true
	case model.ExpectedBehaviorSaturday:
		return time.Saturday, true
	case model.ExpectedBehaviorSunday:
		return time.Sunday, true
	default:
		return 0, false
	}
}

func expectedBehaviorModelWeekday(day time.Weekday) (model.ExpectedBehaviorWeekday, bool) {
	switch day {
	case time.Monday:
		return model.ExpectedBehaviorMonday, true
	case time.Tuesday:
		return model.ExpectedBehaviorTuesday, true
	case time.Wednesday:
		return model.ExpectedBehaviorWednesday, true
	case time.Thursday:
		return model.ExpectedBehaviorThursday, true
	case time.Friday:
		return model.ExpectedBehaviorFriday, true
	case time.Saturday:
		return model.ExpectedBehaviorSaturday, true
	case time.Sunday:
		return model.ExpectedBehaviorSunday, true
	default:
		return "", false
	}
}
