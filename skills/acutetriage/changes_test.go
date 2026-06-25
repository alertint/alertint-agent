// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func alertsWithLabels(labels map[string]string) []store.Alert {
	now := time.Now().UTC()
	return []store.Alert{
		{ID: "a1", Fingerprint: "f1", Status: "firing", Labels: labels, StartsAt: now, ReceivedAt: now},
		{ID: "a2", Fingerprint: "f2", Status: "firing", Labels: labels, StartsAt: now, ReceivedAt: now},
	}
}

func TestFetchChanges_RanksByMatchCountThenRecency(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	first := time.Date(2026, 6, 18, 10, 50, 0, 0, time.UTC)
	last := first.Add(5 * time.Minute)
	ins := func(id string, mins int, labels map[string]string) {
		ts := first.Add(time.Duration(mins) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: id, Source: "ci", Kind: "deploy", Title: id, Labels: labels, OccurredAt: ts, ReceivedAt: ts})
	}
	// shared = {service:checkout, namespace:prod, region:us-east}
	ins("two-a", -8, map[string]string{"service": "checkout", "namespace": "prod"})                       // 2 matches
	ins("two-b", -10, map[string]string{"service": "payments", "namespace": "prod", "region": "us-east"}) // 2 matches (namespace,region)
	ins("one", -5, map[string]string{"region": "us-east"})                                                // 1 match, most recent
	ins("zero", -3, map[string]string{"team": "infra"})                                                   // 0 matches → ADR-0005: now INCLUDED, ranked last

	shared := map[string]string{"service": "checkout", "namespace": "prod", "region": "us-east"}
	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10},
		alertsWithLabels(shared), first, last, "inc1", slog.Default())

	if got == nil {
		t.Fatal("want non-nil enrichment")
	}
	// ADR-0005: the 0-match "zero" change is no longer excluded — all 4 surface.
	if len(got.Changes) != 4 {
		t.Fatalf("want 4 (incl. the 0-match change), got %d: %#v", len(got.Changes), got.Changes)
	}
	// match-count primary: the two 2-match changes outrank "one" (1) which
	// outranks "zero" (0), even though "zero" is the most recent.
	if got.Changes[0].MatchCount != 2 || got.Changes[1].MatchCount != 2 {
		t.Fatalf("top two should be 2-match: %#v", got.Changes)
	}
	if got.Changes[2].Title != "one" || got.Changes[3].Title != "zero" {
		t.Fatalf("ranking wrong, want one then zero last: %#v", got.Changes)
	}
	// recency tiebreak among the two 2-match changes: two-a (-8) newer than two-b (-10).
	if got.Changes[0].Title != "two-a" {
		t.Fatalf("recency tiebreak wrong: %#v", got.Changes)
	}
}

// TestFetchChanges_AE6_UnmatchedIncludedAfterMatched pins the ADR-0005 shift: an
// in-window change sharing NO label with the incident is surfaced (not dropped),
// ranked after the matched one.
func TestFetchChanges_AE6_UnmatchedIncludedAfterMatched(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	first := time.Date(2026, 6, 18, 10, 50, 0, 0, time.UTC)
	ins := func(id string, mins int, labels map[string]string) {
		ts := first.Add(time.Duration(mins) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: id, Source: "sentry", Kind: "deploy", Title: id, Labels: labels, OccurredAt: ts, ReceivedAt: ts})
	}
	ins("matched", -10, map[string]string{"service": "checkout"}) // shares service
	ins("unmatched", -2, map[string]string{"project": "billing"}) // shares nothing, more recent

	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10},
		alertsWithLabels(map[string]string{"service": "checkout"}), first, first, "inc1", slog.Default())
	if got == nil || len(got.Changes) != 2 {
		t.Fatalf("want both changes surfaced, got %#v", got)
	}
	// Match-first preserved: matched ranks before the more-recent unmatched.
	if got.Changes[0].Title != "matched" || got.Changes[1].Title != "unmatched" {
		t.Fatalf("ordering wrong, want matched then unmatched: %#v", got.Changes)
	}
	if got.Changes[0].MatchCount != 1 || len(got.Changes[0].MatchedOn) != 1 {
		t.Errorf("matched change lost its MatchedOn: %#v", got.Changes[0])
	}
	if got.Changes[1].MatchCount != 0 || len(got.Changes[1].MatchedOn) != 0 {
		t.Errorf("unmatched change should have empty MatchedOn: %#v", got.Changes[1])
	}
}

// TestFetchChanges_AE7_NoSharedLabelsStillSurfaces pins that an incident whose
// alerts share no labels still receives recent in-window changes by recency
// (the old len(shared)==0 early-return is gone).
func TestFetchChanges_AE7_NoSharedLabelsStillSurfaces(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	first := time.Date(2026, 6, 18, 10, 50, 0, 0, time.UTC)
	ins := func(id string, mins int) {
		ts := first.Add(time.Duration(mins) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: id, Source: "sentry", Kind: "deploy", Title: id, Labels: map[string]string{"project": "checkout"}, OccurredAt: ts, ReceivedAt: ts})
	}
	ins("older", -20)
	ins("newer", -3)

	// Alerts share NO label (different service values).
	noShared := []store.Alert{
		{ID: "a1", Fingerprint: "f1", Status: "firing", Labels: map[string]string{"service": "a"}, StartsAt: first, ReceivedAt: first},
		{ID: "a2", Fingerprint: "f2", Status: "firing", Labels: map[string]string{"service": "b"}, StartsAt: first, ReceivedAt: first},
	}
	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10}, noShared, first, first, "inc1", slog.Default())
	if got == nil {
		t.Fatal("want non-nil enrichment")
	}
	if len(got.Changes) != 2 {
		t.Fatalf("want both changes by recency, got %#v", got.Changes)
	}
	if got.Changes[0].Title != "newer" { // recency order, no match to rank on
		t.Errorf("want newest first, got %#v", got.Changes)
	}
	if got.Note != "no shared labels; showing recent changes by recency" {
		t.Errorf("want no-shared-labels note, got %q", got.Note)
	}
}

func TestFetchChanges_MaxEventsCapOnMixedSet(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()
	first := time.Date(2026, 6, 18, 10, 50, 0, 0, time.UTC)
	ins := func(id string, mins int, labels map[string]string) {
		ts := first.Add(time.Duration(mins) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: id, Source: "ci", Kind: "deploy", Title: id, Labels: labels, OccurredAt: ts, ReceivedAt: ts})
	}
	// One matched + several unmatched; cap=2 keeps the matched + one unmatched.
	ins("matched", -15, map[string]string{"service": "checkout"})
	ins("u1", -1, map[string]string{"x": "1"})
	ins("u2", -2, map[string]string{"x": "2"})
	ins("u3", -3, map[string]string{"x": "3"})

	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 2},
		alertsWithLabels(map[string]string{"service": "checkout"}), first, first, "inc1", slog.Default())
	if len(got.Changes) != 2 {
		t.Fatalf("cap not applied: %d", len(got.Changes))
	}
	// Matched retained first; the single unmatched kept is the most recent (u1).
	if got.Changes[0].Title != "matched" || got.Changes[1].Title != "u1" {
		t.Fatalf("cap dropped the wrong items: %#v", got.Changes)
	}
}

func TestFetchChanges_VisibilityNotes(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()
	first := time.Now().UTC()

	// Contract unchanged: disabled → nil ("we never looked").
	if FetchChanges(ctx, st, ChangeParams{Enabled: false}, alertsWithLabels(map[string]string{"a": "b"}), first, first, "i", slog.Default()) != nil {
		t.Fatal("disabled must return nil")
	}
	// Genuinely empty window (no changes at all) → "no changes in window",
	// regardless of whether the incident had shared labels.
	e := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10}, alertsWithLabels(map[string]string{"service": "a"}), first, first, "i", slog.Default())
	if e == nil || e.Note != "no changes in window" {
		t.Fatalf("want no-changes note, got %#v", e)
	}
}
