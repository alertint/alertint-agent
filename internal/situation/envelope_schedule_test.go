// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func mustScheduleTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

// TestOvernightDSTOccurrence covers the Riga autumn fall-back: the resolved
// window still spans strictly more than its nominal two hours because the
// repeated local hour (03:00-03:59) falls inside it.
func TestOvernightDSTOccurrence(t *testing.T) {
	rule := model.Schedule{Days: []string{"sun"}, LocalStart: "01:30", LocalEnd: "03:30", Timezone: "Europe/Riga"}
	got, err := ResolveScheduleOccurrence(rule, mustScheduleTime(t, "2026-10-25T01:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Start.Before(got.End) || got.End.Sub(got.Start) < 3*time.Hour {
		t.Fatalf("interval=%s..%s duration=%s", got.Start, got.End, got.End.Sub(got.Start))
	}
	if got.Weekday != time.Sunday {
		t.Fatalf("weekday=%s", got.Weekday)
	}
}

// TestSpringForwardOccurrenceCrossesNonexistentBoundary covers the Riga
// spring-forward gap (local 03:00-03:59 does not exist): the window still
// resolves to a positive, deterministic UTC interval using Go's own IANA
// zone resolution, with no separate gap-avoidance logic.
func TestSpringForwardOccurrenceCrossesNonexistentBoundary(t *testing.T) {
	rule := model.Schedule{Days: []string{"sun"}, LocalStart: "02:30", LocalEnd: "03:15", Timezone: "Europe/Riga"}
	got, err := ResolveScheduleOccurrence(rule, mustScheduleTime(t, "2026-03-29T01:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Start.Before(got.End) {
		t.Fatalf("interval=%s..%s", got.Start, got.End)
	}
	wantStart := mustScheduleTime(t, "2026-03-29T00:30:00Z")
	wantEnd := mustScheduleTime(t, "2026-03-29T01:15:00Z")
	if !got.Start.Equal(wantStart) || !got.End.Equal(wantEnd) {
		t.Fatalf("interval=%s..%s want=%s..%s", got.Start, got.End, wantStart, wantEnd)
	}
}

// TestOvernightWeekdayOwnership covers a window crossing midnight: the
// occurrence belongs to the day it starts on even when the reference instant
// falls in the small hours of the following calendar day.
func TestOvernightWeekdayOwnership(t *testing.T) {
	rule := model.Schedule{Days: []string{"sat"}, LocalStart: "23:00", LocalEnd: "02:00", Timezone: "Europe/Riga"}
	// 2026-08-16 is a Sunday; 01:00 local (UTC+3 in August, no DST edge) is
	// the tail of Saturday night's window.
	at := mustScheduleTime(t, "2026-08-15T22:00:00Z") // 2026-08-16T01:00:00+03:00
	got, err := ResolveScheduleOccurrence(rule, at)
	if err != nil {
		t.Fatal(err)
	}
	if got.Weekday != time.Saturday {
		t.Fatalf("weekday=%s, want saturday (window owned by the day it starts on)", got.Weekday)
	}
	if !got.Start.Before(at) || !at.Before(got.End) {
		t.Fatalf("at=%s not inside resolved window %s..%s", at, got.Start, got.End)
	}
	wantStart := mustScheduleTime(t, "2026-08-15T20:00:00Z") // Saturday 23:00 +03:00
	wantEnd := mustScheduleTime(t, "2026-08-15T23:00:00Z")   // Sunday 02:00 +03:00
	if !got.Start.Equal(wantStart) || !got.End.Equal(wantEnd) {
		t.Fatalf("interval=%s..%s want=%s..%s", got.Start, got.End, wantStart, wantEnd)
	}
}

func TestResolveScheduleOccurrenceDayNotEnrolled(t *testing.T) {
	rule := model.Schedule{Days: []string{"mon"}, LocalStart: "01:00", LocalEnd: "02:00", Timezone: "Europe/Riga"}
	if _, err := ResolveScheduleOccurrence(rule, mustScheduleTime(t, "2026-08-16T10:00:00Z")); err == nil {
		t.Fatal("expected error for an unenrolled weekday")
	}
}

func TestResolveScheduleOccurrenceInvalidTimezone(t *testing.T) {
	rule := model.Schedule{Days: []string{"sun"}, LocalStart: "01:00", LocalEnd: "02:00", Timezone: "Not/AZone"}
	if _, err := ResolveScheduleOccurrence(rule, time.Now()); err == nil {
		t.Fatal("expected error for an invalid timezone")
	}
}

func TestScheduleOccurrenceContainsToleranceWidensStartOnly(t *testing.T) {
	rule := model.Schedule{Days: []string{"sat"}, LocalStart: "23:00", LocalEnd: "02:00", Timezone: "Europe/Riga", StartToleranceMinutes: 15}
	got, err := ResolveScheduleOccurrence(rule, mustScheduleTime(t, "2026-08-15T22:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	before := got.Start.Add(-10 * time.Minute)
	if !got.Contains(before, rule.StartToleranceMinutes) {
		t.Fatalf("expected tolerance to admit an instant 10m before start")
	}
	tooEarly := got.Start.Add(-20 * time.Minute)
	if got.Contains(tooEarly, rule.StartToleranceMinutes) {
		t.Fatalf("expected tolerance to reject an instant 20m before start")
	}
	if got.Contains(got.End, rule.StartToleranceMinutes) {
		t.Fatalf("expected the window to be exclusive of its own end")
	}
}
