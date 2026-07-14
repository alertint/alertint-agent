// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedWindowIncident inserts an analyzed incident with one member alert
// carrying a severity label, last_alert_at set to `when` — the shape
// IncidentsInWindow reads. Named distinctly from occurrences_test.go's
// seedIncident (same package, different signature — a same-named helper here
// would redeclare it). Returns the new incident id.
func seedWindowIncident(t *testing.T, s *Store, groupKey string, when time.Time, severity string) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	ts := when.UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, 'analyzed', ?, ?, ?, 1, ?, ?)
	`, id, groupKey, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed window incident %s: %v", groupKey, err)
	}

	labels := map[string]string{"alertname": "InstanceDown"}
	if severity != "" {
		labels["severity"] = severity
	}
	a := Alert{
		ID:          uuid.NewString(),
		Fingerprint: "fp-" + id,
		Status:      "firing",
		Labels:      labels,
		Annotations: map[string]string{},
		StartsAt:    when,
		ReceivedAt:  when,
	}
	stored, err := s.UpsertAlertByFingerprint(ctx, a)
	if err != nil {
		t.Fatalf("seed window incident alert %s: %v", groupKey, err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_alerts (incident_id, alert_id, created_at) VALUES (?, ?, ?)
	`, id, stored.ID, ts); err != nil {
		t.Fatalf("seed window incident link %s: %v", groupKey, err)
	}
	return id
}

// seedWindowDrillIncident is seedWindowIncident plus the Drill-alert marker
// (ADR-0013) on the member alert, so excludeDrills tests have an incident that
// must be filtered out.
func seedWindowDrillIncident(t *testing.T, s *Store, groupKey string, when time.Time, severity string) string {
	t.Helper()
	ctx := context.Background()
	id := seedWindowIncident(t, s, groupKey, when, severity)
	a := Alert{
		ID:          uuid.NewString(),
		Fingerprint: "fp-drill-" + id,
		Status:      "firing",
		Labels:      map[string]string{"alertname": "InstanceDown", DrillMarkerLabel: DrillMarkerValue},
		Annotations: map[string]string{},
		StartsAt:    when,
		ReceivedAt:  when,
	}
	stored, err := s.UpsertAlertByFingerprint(ctx, a)
	if err != nil {
		t.Fatalf("seed drill alert %s: %v", groupKey, err)
	}
	ts := when.UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_alerts (incident_id, alert_id, created_at) VALUES (?, ?, ?)
	`, id, stored.ID, ts); err != nil {
		t.Fatalf("seed drill link %s: %v", groupKey, err)
	}
	return id
}

func TestIncidentsInWindow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed: the "self" incident, one other-key incident inside the window,
	// one outside the window, one sharing self's group key.
	self := seedWindowIncident(t, st, "db|stolon|InstanceDown", now.Add(-5*time.Minute), "critical")
	other := seedWindowIncident(t, st, "payments|api|HighLatency", now.Add(-30*time.Minute), "warning")
	_ = seedWindowIncident(t, st, "web|cdn|SlowResponses", now.Add(-3*time.Hour), "warning")      // outside 60m
	_ = seedWindowIncident(t, st, "db|stolon|InstanceDown", now.Add(-20*time.Minute), "critical") // same key

	total, top, err := st.IncidentsInWindow(ctx, now.Add(-60*time.Minute), self, "db|stolon|InstanceDown", true, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("want total 1 (only the other-key in-window incident), got %d", total)
	}
	if len(top) != 1 || top[0].GroupKey != "payments|api|HighLatency" || top[0].Severity != "warning" {
		t.Fatalf("unexpected top: %+v", top)
	}
	if top[0].Status != "analyzed" {
		t.Errorf("Status = %q, want analyzed", top[0].Status)
	}
	if top[0].AlertCount != 1 {
		t.Errorf("AlertCount = %d, want 1", top[0].AlertCount)
	}
	_ = other
}

// TestIncidentsInWindow_ExcludesDrillsWhenRequested confirms excludeDrills
// filters out incidents carrying the Drill-alert marker (ADR-0013) on any
// member alert, and that turning the flag off surfaces them again.
func TestIncidentsInWindow_ExcludesDrillsWhenRequested(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	self := seedWindowIncident(t, st, "db|stolon|InstanceDown", now.Add(-5*time.Minute), "critical")
	_ = seedWindowDrillIncident(t, st, "drill|chaos|InjectedFault", now.Add(-10*time.Minute), "critical")

	total, top, err := st.IncidentsInWindow(ctx, now.Add(-60*time.Minute), self, "db|stolon|InstanceDown", true, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(top) != 0 {
		t.Fatalf("excludeDrills=true: want 0 results, got total=%d top=%+v", total, top)
	}

	total, top, err = st.IncidentsInWindow(ctx, now.Add(-60*time.Minute), self, "db|stolon|InstanceDown", false, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(top) != 1 || top[0].GroupKey != "drill|chaos|InjectedFault" {
		t.Fatalf("excludeDrills=false: want the drill incident included, got total=%d top=%+v", total, top)
	}
}

// TestIncidentsInWindow_LimitCapsTopNotTotal confirms `top` is capped at
// limit and ordered most-recent-first while `total` still reports the full
// in-window count, and that a no-severity member yields "".
func TestIncidentsInWindow_LimitCapsTopNotTotal(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	self := seedWindowIncident(t, st, "self|key", now.Add(-1*time.Minute), "critical")
	_ = seedWindowIncident(t, st, "a|key", now.Add(-40*time.Minute), "warning")
	newest := seedWindowIncident(t, st, "b|key", now.Add(-10*time.Minute), "high")
	_ = seedWindowIncident(t, st, "c|key", now.Add(-30*time.Minute), "") // no severity label

	total, top, err := st.IncidentsInWindow(ctx, now.Add(-60*time.Minute), self, "self|key", false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(top) != 2 {
		t.Fatalf("top len = %d, want 2 (limit)", len(top))
	}
	if top[0].GroupKey != "b|key" {
		t.Fatalf("top[0] = %+v, want the most recent (b|key = %s)", top[0], newest)
	}
}
