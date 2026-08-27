// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestIncidentTriageLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const groupKey = "service=api"
	incID := readyIncident(t, st, groupKey)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	if err := st.SeedIncidentTriage(ctx, incID, now); err != nil {
		t.Fatal(err)
	}
	active, err := st.BeginIncidentTriage(ctx, incID, now)
	if err != nil {
		t.Fatal(err)
	}
	if active.Phase != TriageInFlight || active.Attempts != 1 {
		t.Fatalf("active = %+v", active)
	}
	if got, _ := st.GetIncidentByID(ctx, incID); got.Status != "processing" {
		t.Fatalf("status after Begin = %q, want processing", got.Status)
	}
	if _, err := st.BeginIncidentTriage(ctx, incID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Begin must fail the guarded transition, got %v", err)
	}
	if err := st.BackoffIncidentTriage(ctx, incID, now.Add(30*time.Second), "timeout", "deadline exceeded"); err != nil {
		t.Fatal(err)
	}
	gotInc, gotTriage, err := st.GetBackoffIncidentByGroupKey(ctx, groupKey)
	if err != nil {
		t.Fatal(err)
	}
	if gotInc.ID != incID || gotInc.Status != "ready" || gotTriage.Phase != TriageBackoff || gotTriage.Attempts != 1 {
		t.Fatalf("lookup = %+v %+v", gotInc, gotTriage)
	}
	if !gotTriage.NextAt.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("next_at = %v", gotTriage.NextAt)
	}
}

func TestIncidentTriageSkippedIsNotBackoff(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	incID := readyIncident(t, st, "service=skip")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	_ = st.SeedIncidentTriage(ctx, incID, now)
	_, _ = st.BeginIncidentTriage(ctx, incID, now)
	if err := st.SkipIncidentTriage(ctx, incID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetBackoffIncidentByGroupKey(ctx, "service=skip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("skipped row must be absent from the backoff lookup, got %v", err)
	}
}

func TestIncidentTriageDetailIsCapped(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	incID := readyIncident(t, st, "service=cap")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	_ = st.SeedIncidentTriage(ctx, incID, now)
	_, _ = st.BeginIncidentTriage(ctx, incID, now)
	long := "x\r\n" + string(make([]byte, 600))
	if err := st.BackoffIncidentTriage(ctx, incID, now.Add(time.Minute), "timeout", long); err != nil {
		t.Fatal(err)
	}
	_, tri, _ := st.GetBackoffIncidentByGroupKey(ctx, "service=cap")
	if len(tri.LastErrorDetail) > 256 || tri.LastErrorDetail[:1] != "x" || tri.LastErrorDetail[1:2] != " " {
		t.Fatalf("detail not sanitized/capped: %q", tri.LastErrorDetail)
	}
}

// TestSanitizeTriageDetail_InvalidUTF8 covers a provider response body
// containing arbitrary, non-UTF-8 bytes: the result must always be valid
// UTF-8 and within the byte cap, both when the raw input is short (never
// reaches the truncation path at all) and when it is long enough that
// truncation must walk past invalid bytes without miscounting their width.
func TestSanitizeTriageDetail_InvalidUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"short lone continuation byte", "error: \x80\x81 bad gateway"},
		{"short truncated multi-byte sequence", "prefix \xe2\x82 suffix"},
		{"long input entirely invalid bytes", "x" + strings.Repeat("\xff", 400)},
		{"invalid bytes just before the byte cap", strings.Repeat("a", 250) + "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"},
		{"valid multibyte runes straddling the byte cap", strings.Repeat("a", 254) + strings.Repeat("€", 4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTriageDetail(tc.in)
			if !utf8.ValidString(got) {
				t.Fatalf("sanitizeTriageDetail(%q) = %q, not valid UTF-8", tc.in, got)
			}
			if len(got) > maxTriageDetailBytes {
				t.Fatalf("sanitizeTriageDetail(%q) = %q, len %d exceeds cap %d", tc.in, got, len(got), maxTriageDetailBytes)
			}
		})
	}
}

func TestRecoverInterruptedIncidentTriage(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	incID := readyIncident(t, st, "service=recover")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	if err := st.SeedIncidentTriage(ctx, incID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BeginIncidentTriage(ctx, incID, now); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: nothing resolves the in-flight attempt.

	next := now.Add(2 * time.Minute)
	if err := st.RecoverInterruptedIncidentTriage(ctx, incID, next, "process_interrupted", "attempt interrupted before completion"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetIncidentByID(ctx, incID)
	if err != nil || got == nil || got.Status != "ready" {
		t.Fatalf("status after recover = %+v, %v, want ready", got, err)
	}
	_, tri, err := st.GetBackoffIncidentByGroupKey(ctx, "service=recover")
	if err != nil {
		t.Fatal(err)
	}
	if tri.Attempts != 1 || !tri.NextAt.Equal(next) {
		t.Fatalf("recovered triage = %+v, want attempts=1 next_at=%v", tri, next)
	}

	// A row not currently in_flight (e.g. already recovered, or never begun)
	// must not be touched a second time.
	if err := st.RecoverInterruptedIncidentTriage(ctx, incID, next.Add(time.Minute), "process_interrupted", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second recover on a non-in_flight row = %v, want ErrNotFound", err)
	}
}

func TestListLegacyReadyIncidents(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	legacyID := readyIncident(t, st, "service=legacy")

	durableID := readyIncident(t, st, "service=durable")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if err := st.SeedIncidentTriage(ctx, durableID, now); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListLegacyReadyIncidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != legacyID {
		t.Fatalf("legacy ready incidents = %+v, want exactly [%s] (durable row has its own triage row)", got, legacyID)
	}
}

// TestIncidentTriageSurvivesRestart proves attempts and next_at persist across
// Close + Open on a temp-file database — :memory: cannot prove durability.
func TestIncidentTriageSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "triage.db")

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	incID := readyIncident(t, st, "service=restart")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if err := st.SeedIncidentTriage(ctx, incID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BeginIncidentTriage(ctx, incID, now); err != nil {
		t.Fatal(err)
	}
	if err := st.BackoffIncidentTriage(ctx, incID, now.Add(2*time.Minute), "timeout", "deadline exceeded"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	_, tri, err := reopened.GetBackoffIncidentByGroupKey(ctx, "service=restart")
	if err != nil {
		t.Fatal(err)
	}
	if tri.Attempts != 1 || !tri.NextAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("after restart: attempts=%d next_at=%v, want attempts=1 next_at=%v",
			tri.Attempts, tri.NextAt, now.Add(2*time.Minute))
	}
}
