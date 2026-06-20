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
	ins("zero", -3, map[string]string{"team": "infra"})                                                   // 0 matches → excluded

	shared := map[string]string{"service": "checkout", "namespace": "prod", "region": "us-east"}
	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10},
		alertsWithLabels(shared), first, last, "inc1", slog.Default())

	if got == nil {
		t.Fatal("want non-nil enrichment")
	}
	if len(got.Changes) != 3 {
		t.Fatalf("want 3 matched (zero excluded), got %d: %#v", len(got.Changes), got.Changes)
	}
	// match-count primary: the two 2-match changes outrank the 1-match "one",
	// even though "one" is more recent.
	if got.Changes[0].MatchCount != 2 || got.Changes[1].MatchCount != 2 || got.Changes[2].Title != "one" {
		t.Fatalf("ranking wrong: %#v", got.Changes)
	}
	// recency tiebreak among the two 2-match changes: two-a (-8) newer than two-b (-10).
	if got.Changes[0].Title != "two-a" {
		t.Fatalf("recency tiebreak wrong: %#v", got.Changes)
	}
}

func TestFetchChanges_MaxEventsCap(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()
	first := time.Date(2026, 6, 18, 10, 50, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ts := first.Add(time.Duration(-i-1) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: string(rune('a' + i)), Source: "ci", Kind: "deploy", Title: "t", Labels: map[string]string{"service": "checkout"}, OccurredAt: ts, ReceivedAt: ts})
	}
	got := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 2},
		alertsWithLabels(map[string]string{"service": "checkout"}), first, first, "inc1", slog.Default())
	if len(got.Changes) != 2 {
		t.Fatalf("cap not applied: %d", len(got.Changes))
	}
}

func TestFetchChanges_VisibilityNotes(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()
	first := time.Now().UTC()

	// disabled → nil
	if FetchChanges(ctx, st, ChangeParams{Enabled: false}, alertsWithLabels(map[string]string{"a": "b"}), first, first, "i", slog.Default()) != nil {
		t.Fatal("disabled must return nil")
	}
	// enabled, no shared labels → note
	noShared := []store.Alert{
		{ID: "a1", Fingerprint: "f1", Status: "firing", Labels: map[string]string{"service": "a"}, StartsAt: first, ReceivedAt: first},
		{ID: "a2", Fingerprint: "f2", Status: "firing", Labels: map[string]string{"service": "b"}, StartsAt: first, ReceivedAt: first},
	}
	e := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10}, noShared, first, first, "i", slog.Default())
	if e == nil || e.Note != "no shared labels to match changes for this incident" {
		t.Fatalf("want no-shared-labels note, got %#v", e)
	}
	// enabled, shared labels, empty window → "no changes in window"
	e2 := FetchChanges(ctx, st, ChangeParams{Enabled: true, WindowMinutes: 120, MaxEvents: 10}, alertsWithLabels(map[string]string{"service": "a"}), first, first, "i", slog.Default())
	if e2 == nil || e2.Note != "no changes in window" {
		t.Fatalf("want no-changes note, got %#v", e2)
	}
}
