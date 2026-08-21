// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ScheduleOccurrence is one resolved UTC instant window for a Schedule rule.
// Deterministic DST evaluation happens exactly once, here, using Go's
// IANA-backed time.Date against rule.Timezone; every other caller compares
// against Start/End rather than re-deriving offsets itself.
type ScheduleOccurrence struct {
	Weekday time.Weekday
	Start   time.Time
	End     time.Time
}

// Contains reports whether at falls within the occurrence. toleranceMinutes
// widens the open boundary only — a late-arriving evaluation still counts,
// but the window never opens earlier than declared minus the tolerance, and
// it never stays open past its declared end.
func (o ScheduleOccurrence) Contains(at time.Time, toleranceMinutes int) bool {
	start := o.Start.Add(-time.Duration(toleranceMinutes) * time.Minute)
	return !at.Before(start) && at.Before(o.End)
}

var scheduleWeekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// ResolveScheduleOccurrence resolves the exact UTC window that owns at: the
// enrolled calendar day whose local wall-clock LocalStart..LocalEnd contains
// at. An overnight window (LocalEnd at or before LocalStart) is owned by the
// day it starts on even when at itself falls on the following calendar date
// — the classic "Saturday 23:00 to Sunday 02:00" maintenance window belongs
// to Saturday. Ambiguous (fall-back) or nonexistent (spring-forward) local
// instants are resolved exactly as Go's time.Date resolves them against the
// IANA rule for rule.Timezone; this function adds no separate DST logic, so
// the result is deterministic for a given (rule, at) pair and nothing else.
func ResolveScheduleOccurrence(rule model.Schedule, at time.Time) (ScheduleOccurrence, error) {
	loc, days, startH, startM, endH, endM, err := parseSchedule(rule)
	if err != nil {
		return ScheduleOccurrence{}, err
	}
	if at.IsZero() {
		return ScheduleOccurrence{}, errors.New("situation: schedule occurrence requires a reference instant")
	}
	local := at.In(loc)
	overnight := endH < startH || (endH == startH && endM <= startM)
	anchor := local
	if overnight && (local.Hour() < startH || (local.Hour() == startH && local.Minute() < startM)) {
		// at's wall-clock falls in the tail portion (past local midnight) of
		// an overnight window that started the previous calendar day.
		anchor = local.AddDate(0, 0, -1)
	}
	anchorNoon := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), 12, 0, 0, 0, loc)
	if _, ok := days[anchorNoon.Weekday()]; !ok {
		return ScheduleOccurrence{}, fmt.Errorf("situation: schedule occurrence day %s is not enrolled", anchorNoon.Weekday())
	}
	start := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), startH, startM, 0, 0, loc)
	endDay := anchor
	if overnight {
		endDay = anchor.AddDate(0, 0, 1)
	}
	end := time.Date(endDay.Year(), endDay.Month(), endDay.Day(), endH, endM, 0, 0, loc)
	if !start.Before(end) {
		return ScheduleOccurrence{}, errors.New("situation: schedule occurrence resolved a non-positive window")
	}
	return ScheduleOccurrence{Weekday: anchorNoon.Weekday(), Start: start.UTC(), End: end.UTC()}, nil
}

func parseSchedule(rule model.Schedule) (*time.Location, map[time.Weekday]struct{}, int, int, int, int, error) {
	if strings.TrimSpace(rule.Timezone) == "" || len(rule.Days) == 0 {
		return nil, nil, 0, 0, 0, 0, errors.New("situation: schedule requires timezone and at least one day")
	}
	if rule.StartToleranceMinutes < 0 {
		return nil, nil, 0, 0, 0, 0, errors.New("situation: schedule start tolerance must be nonnegative")
	}
	loc, err := time.LoadLocation(rule.Timezone)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("situation: schedule timezone %q: %w", rule.Timezone, err)
	}
	days := make(map[time.Weekday]struct{}, len(rule.Days))
	for _, d := range rule.Days {
		wd, ok := scheduleWeekdays[strings.ToLower(strings.TrimSpace(d))]
		if !ok {
			return nil, nil, 0, 0, 0, 0, fmt.Errorf("situation: schedule day %q is invalid", d)
		}
		days[wd] = struct{}{}
	}
	startH, startM, err := parseClock(rule.LocalStart)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("situation: schedule local_start: %w", err)
	}
	endH, endM, err := parseClock(rule.LocalEnd)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("situation: schedule local_end: %w", err)
	}
	if startH == endH && startM == endM {
		return nil, nil, 0, 0, 0, 0, errors.New("situation: schedule local_start and local_end must differ")
	}
	return loc, days, startH, startM, endH, endM, nil
}

func parseClock(value string) (int, int, error) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("clock %q must be HH:MM", value)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, 0, fmt.Errorf("clock %q hour is invalid", value)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("clock %q minute is invalid", value)
	}
	return h, m, nil
}
