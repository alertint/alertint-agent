// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// ExhaustOverdueUnclaimedIncidentTriage — Task 9's one-hour startup horizon
// (ADR-0045), continued over the controller-gated schedule.
// ----------------------------------------------------------------------

// seedIncidentTriageSchedule inserts a fresh incident_triage row for
// incidentID directly at phase, mirroring situation_views_test.go's own
// TestSituationControllerViewIncludesCurrentTriageState pattern —
// newSituationForGroup's own fixture path (insertIncidentAndInput ->
// st.MarkIncidentReady, the PLAIN legacy method, never
// MarkIncidentReadyWithSituationInput) does not itself create an
// incident_triage row, so there is nothing to UPDATE here.
func seedIncidentTriageSchedule(t *testing.T, st *Store, incidentID, phase string, nextAt time.Time, now time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, next_at, updated_at)
		VALUES (?, ?, 1, ?, ?)`,
		incidentID, phase, nextAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed incident_triage schedule for %s: %v", incidentID, err)
	}
}

func TestExhaustOverdueUnclaimedIncidentTriageClosesOutOverdueUnjudgedWork(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-horizon-overdue", now)
	incID := "inc-group-horizon-overdue"

	// A "pending" row more than one hour overdue.
	seedIncidentTriageSchedule(t, st, incID, "pending", now.Add(-2*time.Hour), now)

	n, err := st.ExhaustOverdueUnclaimedIncidentTriage(context.Background(), now, time.Hour)
	if err != nil {
		t.Fatalf("ExhaustOverdueUnclaimedIncidentTriage: %v", err)
	}
	if n != 1 {
		t.Fatalf("exhausted = %d, want 1", n)
	}

	var phase string
	var lastErrorCode string
	if err := st.db.QueryRowContext(context.Background(), `SELECT phase, last_error_code FROM incident_triage WHERE incident_id = ?`, incID).
		Scan(&phase, &lastErrorCode); err != nil {
		t.Fatal(err)
	}
	if phase != "exhausted" {
		t.Fatalf("phase = %q, want exhausted", phase)
	}
	if lastErrorCode != "startup_retry_window_expired" {
		t.Fatalf("last_error_code = %q, want startup_retry_window_expired", lastErrorCode)
	}

	var incidentStatus string
	if err := st.db.QueryRowContext(context.Background(), `SELECT status FROM incidents WHERE id = ?`, incID).Scan(&incidentStatus); err != nil {
		t.Fatal(err)
	}
	if incidentStatus != "failed" {
		t.Fatalf("incident status = %q, want failed", incidentStatus)
	}

	var inputCount int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id = ? AND kind = 'triage_exhausted'`, incID).
		Scan(&inputCount); err != nil {
		t.Fatal(err)
	}
	if inputCount != 1 {
		t.Fatalf("triage_exhausted inputs = %d, want exactly 1", inputCount)
	}
	_ = sitID
}

func TestExhaustOverdueUnclaimedIncidentTriageLeavesRecentWorkUntouched(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	newSituationForGroup(t, st, "group-horizon-recent", now)
	incID := "inc-group-horizon-recent"

	// A "backoff" row due only 10 minutes ago — well inside the one-hour
	// horizon — must survive untouched.
	seedIncidentTriageSchedule(t, st, incID, "backoff", now.Add(-10*time.Minute), now)

	n, err := st.ExhaustOverdueUnclaimedIncidentTriage(context.Background(), now, time.Hour)
	if err != nil {
		t.Fatalf("ExhaustOverdueUnclaimedIncidentTriage: %v", err)
	}
	if n != 0 {
		t.Fatalf("exhausted = %d, want 0 (still inside the horizon)", n)
	}

	var phase string
	if err := st.db.QueryRowContext(context.Background(), `SELECT phase FROM incident_triage WHERE incident_id = ?`, incID).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if phase != "backoff" {
		t.Fatalf("phase = %q, want backoff (untouched)", phase)
	}
}

func TestExhaustOverdueUnclaimedIncidentTriageNeverTouchesInFlightOrTerminalRows(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	newSituationForGroup(t, st, "group-horizon-inflight", now)
	incID := "inc-group-horizon-inflight"

	// A claimed row (in_flight) that happens to be old is a live claim, not
	// unjudged unclaimed work — RecoverExpiredIncidentTriageAttempts owns
	// recovering it, never this primitive. decision_origin is left NULL, the
	// migration's own "migrated legacy in_flight row" CHECK branch, so no
	// lease/current_attempt_id fields are required for this fixture.
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, updated_at)
		VALUES (?, 'in_flight', 1, ?)`,
		incID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	n, err := st.ExhaustOverdueUnclaimedIncidentTriage(context.Background(), now, time.Hour)
	if err != nil {
		t.Fatalf("ExhaustOverdueUnclaimedIncidentTriage: %v", err)
	}
	if n != 0 {
		t.Fatalf("exhausted = %d, want 0 (in_flight is never this primitive's concern)", n)
	}
}

func TestExhaustOverdueUnclaimedIncidentTriageZeroHorizonIsNoOp(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	newSituationForGroup(t, st, "group-horizon-zero", now)
	incID := "inc-group-horizon-zero"
	seedIncidentTriageSchedule(t, st, incID, "pending", now.Add(-3*time.Hour), now)

	n, err := st.ExhaustOverdueUnclaimedIncidentTriage(context.Background(), now, 0)
	if err != nil {
		t.Fatalf("ExhaustOverdueUnclaimedIncidentTriage: %v", err)
	}
	if n != 0 {
		t.Fatalf("exhausted = %d, want 0 (horizon<=0 is a no-op)", n)
	}
}
