// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"
)

func TestChanges_InsertQueryPrune(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	base := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	mk := func(id string, mins int) Change {
		return Change{
			ID:         id,
			Source:     "github-actions",
			Kind:       "deploy",
			Title:      "checkout deploy",
			Labels:     map[string]string{"service": "checkout", "namespace": "prod"},
			Version:    "v1.42.0",
			Link:       "https://example/run/1",
			OccurredAt: base.Add(time.Duration(mins) * time.Minute),
			ReceivedAt: base.Add(time.Duration(mins) * time.Minute),
		}
	}
	for _, c := range []Change{mk("c1", 0), mk("c2", 30), mk("c3", 90)} {
		if err := st.InsertChange(ctx, c); err != nil {
			t.Fatalf("insert %s: %v", c.ID, err)
		}
	}

	// Window [10:10, 10:40] selects only c2; newest-first ordering.
	got, err := st.ChangesInWindow(ctx, base.Add(10*time.Minute), base.Add(40*time.Minute))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(got) != 1 || got[0].ID != "c2" {
		t.Fatalf("window got %#v, want [c2]", got)
	}
	if got[0].Labels["service"] != "checkout" || got[0].Version != "v1.42.0" {
		t.Fatalf("round-trip lost fields: %#v", got[0])
	}

	// Prune everything strictly before 10:30 → removes c1 only.
	n, err := st.PruneChanges(ctx, base.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("prune removed %d, want 1", n)
	}
	all, _ := st.ChangesInWindow(ctx, base.Add(-time.Hour), base.Add(2*time.Hour))
	if len(all) != 2 {
		t.Fatalf("after prune have %d, want 2", len(all))
	}
}

func TestChangesInScopeWindow_ScopedAndBounded(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	base := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	mk := func(id, service, env string, mins int) Change {
		return Change{
			ID: id, Source: "github-actions", Kind: "deploy", Title: "deploy",
			Labels:     map[string]string{"service": service, "environment": env},
			OccurredAt: base.Add(time.Duration(mins) * time.Minute),
			ReceivedAt: base.Add(time.Duration(mins) * time.Minute),
		}
	}
	changes := []Change{
		mk("checkout-1", "checkout", "prod", 0),
		mk("checkout-2", "checkout", "prod", 10),
		mk("checkout-3", "checkout", "prod", 20),
		mk("other-service", "worker", "prod", 5),  // wrong service: never returned
		mk("wrong-env", "checkout", "staging", 5), // wrong environment: never returned
	}
	for _, c := range changes {
		if err := st.InsertChange(ctx, c); err != nil {
			t.Fatalf("insert %s: %v", c.ID, err)
		}
	}

	got, truncated, err := st.ChangesInScopeWindow(ctx,
		map[string]string{"service": "checkout", "environment": "prod"},
		base.Add(-time.Hour), base.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("scope window: %v", err)
	}
	if truncated {
		t.Fatal("expected no truncation under the cap")
	}
	if len(got) != 3 {
		t.Fatalf("got %d changes, want 3 (exact service+environment match only)", len(got))
	}
	for _, c := range got {
		if c.Labels["service"] != "checkout" || c.Labels["environment"] != "prod" {
			t.Fatalf("scope leaked a non-matching change: %#v", c)
		}
	}

	// Bounded: limit=2 truncates the 3 matching changes.
	limited, truncated, err := st.ChangesInScopeWindow(ctx,
		map[string]string{"service": "checkout", "environment": "prod"},
		base.Add(-time.Hour), base.Add(time.Hour), 2)
	if err != nil {
		t.Fatalf("scope window limited: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncation when limit < matching row count")
	}
	if len(limited) != 2 {
		t.Fatalf("got %d changes, want 2 (bounded)", len(limited))
	}
}

func TestChangesInScopeWindow_RejectsEmptySelector(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	if _, _, err := st.ChangesInScopeWindow(ctx, nil, time.Now().Add(-time.Hour), time.Now(), 10); err == nil {
		t.Fatal("expected error for empty selector")
	}
}

func TestInsertChange_Validation(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	now := time.Now().UTC()
	bad := Change{Source: "x", Title: "t", Labels: map[string]string{"a": "b"}, OccurredAt: now, ReceivedAt: now}
	// missing ID and Kind
	if err := st.InsertChange(ctx, bad); err == nil {
		t.Fatal("want validation error for missing id/kind")
	}
}
