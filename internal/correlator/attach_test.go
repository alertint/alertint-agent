// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"testing"
	"time"
)

// baseInputs is a plain in-horizon attach with no trigger: analyzed incident,
// new episode, recent activity, severity/alertname matching the baseline.
func baseInputs(now time.Time) attachInputs {
	return attachInputs{
		now:                    now,
		lastJudgedAt:           now.Add(-10 * time.Minute),
		lastActivity:           now.Add(-5 * time.Minute),
		occurrencesSinceJudged: 3,
		isNewEpisode:           true,
		incomingSeverityRank:   2, // warning
		incomingAlertname:      "DiskFull",
		baselineSeverityRank:   2, // warning
		knownAlertnames:        map[string]bool{"DiskFull": true},
		episodeTimes:           nil,
		attachWindow:           30 * time.Minute,
		judgmentCeiling:        4 * time.Hour,
		occurrenceCap:          100,
	}
}

func TestDecideAttach_PlainAttach(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	got := decideAttach(baseInputs(now))
	if got.action != actionAttach || got.trigger != "none" {
		t.Fatalf("got %v/%q, want actionAttach/none", got.action, got.trigger)
	}
}

func TestDecideAttach_RepeatTouchBeatsEverything(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.isNewEpisode = false
	// Even with a severity rise and an expired ceiling, an unchanged repeat only touches.
	in.incomingSeverityRank = 4
	in.lastJudgedAt = now.Add(-10 * time.Hour)
	in.lastActivity = now.Add(-100 * time.Minute) // outside Clock A too
	if got := decideAttach(in); got.action != actionRepeatTouch {
		t.Fatalf("got %v, want actionRepeatTouch (a repeat never escalates or mints)", got.action)
	}
}

func TestDecideAttach_OutsideClockANewIncident(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.lastActivity = now.Add(-31 * time.Minute) // just outside the 30m window
	if got := decideAttach(in); got.action != actionNewIncident {
		t.Fatalf("got %v, want actionNewIncident (outside Clock A)", got.action)
	}
}

func TestDecideAttach_SeverityRise(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.incomingSeverityRank = 4 // critical
	in.baselineSeverityRank = 2 // warning
	got := decideAttach(in)
	if got.action != actionRejudge || got.trigger != "severity" {
		t.Fatalf("got %v/%q, want actionRejudge/severity", got.action, got.trigger)
	}
}

func TestDecideAttach_NewAlertname(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.incomingAlertname = "OOMKilled"
	got := decideAttach(in)
	if got.action != actionRejudge || got.trigger != "new_alertname" {
		t.Fatalf("got %v/%q, want actionRejudge/new_alertname", got.action, got.trigger)
	}
}

func TestDecideAttach_CadenceTrigger(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	// 4 episodes ~24h apart -> 3 intervals, median ~24h. A 20-min new interval
	// (20 << 1440/8=180) fires the cadence trigger.
	last := now.Add(-20 * time.Minute)
	in.episodeTimes = []time.Time{
		last.Add(-72 * time.Hour), last.Add(-48 * time.Hour), last.Add(-24 * time.Hour), last,
	}
	in.lastActivity = last // inside Clock A
	got := decideAttach(in)
	if got.action != actionRejudge || got.trigger != "cadence" {
		t.Fatalf("got %v/%q, want actionRejudge/cadence", got.action, got.trigger)
	}
}

func TestDecideAttach_CadenceInactiveUnderThreeIntervals(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	last := now.Add(-20 * time.Minute)
	// Only 3 episodes -> 2 intervals -> cold start, no cadence trigger.
	in.episodeTimes = []time.Time{last.Add(-48 * time.Hour), last.Add(-24 * time.Hour), last}
	in.lastActivity = last
	if got := decideAttach(in); got.action != actionAttach {
		t.Fatalf("got %v/%q, want actionAttach (cadence inactive under 3 intervals)", got.action, got.trigger)
	}
}

func TestDecideAttach_OccurrenceCap(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.occurrencesSinceJudged = 99 // this attach would be the 100th
	got := decideAttach(in)
	if got.action != actionRejudge || got.trigger != "cap" {
		t.Fatalf("got %v/%q, want actionRejudge/cap", got.action, got.trigger)
	}
}

func TestDecideAttach_ClockBCeiling(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.lastJudgedAt = now.Add(-5 * time.Hour) // > 4h ceiling
	got := decideAttach(in)
	if got.action != actionRejudge || got.trigger != "ceiling" {
		t.Fatalf("got %v/%q, want actionRejudge/ceiling", got.action, got.trigger)
	}
}

func TestDecideAttach_SeverityBeatsCeiling(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	in := baseInputs(now)
	in.incomingSeverityRank = 4
	in.lastJudgedAt = now.Add(-5 * time.Hour) // ceiling also exceeded
	got := decideAttach(in)
	if got.trigger != "severity" {
		t.Fatalf("trigger = %q, want severity (severity ranks before ceiling)", got.trigger)
	}
}
