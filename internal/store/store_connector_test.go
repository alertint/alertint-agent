// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestConnectorState_TableIsStrict(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	var ddl string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='connector_state'`,
	).Scan(&ddl); err != nil {
		t.Fatalf("connector_state not created by migration 0007: %v", err)
	}
	if !strings.Contains(strings.ToUpper(ddl), "STRICT") {
		t.Errorf("connector_state is not STRICT: %s", ddl)
	}
}

func TestConnectorState_SaveLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	// Missing name → ("", false, nil).
	if v, found, err := st.LoadConnectorState(ctx, "sentry-releases"); err != nil || found || v != "" {
		t.Fatalf("Load missing = (%q, %v, %v), want (\"\", false, nil)", v, found, err)
	}

	const payload = `{"last_emitted_at":"2026-06-25T10:00:00Z","boundary_event_ids":["deploy:d-1"]}`
	if err := st.SaveConnectorState(ctx, "sentry-releases", payload); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v, found, err := st.LoadConnectorState(ctx, "sentry-releases")
	if err != nil || !found || v != payload {
		t.Fatalf("Load after save = (%q, %v, %v), want (%q, true, nil)", v, found, err, payload)
	}

	// Upsert overwrites.
	const payload2 = `{"last_emitted_at":"2026-06-25T11:00:00Z","boundary_event_ids":[]}`
	if err := st.SaveConnectorState(ctx, "sentry-releases", payload2); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	if v, _, _ := st.LoadConnectorState(ctx, "sentry-releases"); v != payload2 {
		t.Errorf("after upsert = %q, want %q", v, payload2)
	}
}

func sentryChange(id string, occurred time.Time) Change {
	return Change{
		ID:         id,
		Source:     "sentry",
		Kind:       "deploy",
		Title:      "checkout deployed v1 to production",
		Labels:     map[string]string{"project": "checkout", "environment": "production"},
		Version:    "v1",
		Link:       "https://sentry.io/organizations/acme/releases/v1/",
		OccurredAt: occurred,
		ReceivedAt: occurred,
	}
}

func TestInsertChangesAndAdvanceWatermark_AtomicCommit(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	base := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	batch := []Change{
		sentryChange("deploy:d-1", base.Add(1*time.Minute)),
		sentryChange("deploy:d-2", base.Add(2*time.Minute)),
	}
	const wm = `{"last_emitted_at":"2026-06-25T10:02:00Z","boundary_event_ids":["deploy:d-2"]}`
	if err := st.InsertChangesAndAdvanceWatermark(ctx, batch, "sentry-releases", wm); err != nil {
		t.Fatalf("batch insert: %v", err)
	}

	got, err := st.ChangesInWindow(ctx, base, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2", len(got))
	}
	if v, found, _ := st.LoadConnectorState(ctx, "sentry-releases"); !found || v != wm {
		t.Errorf("watermark = (%q, %v), want (%q, true)", v, found, wm)
	}
}

// TestInsertChangesAndAdvanceWatermark_DuplicateIDIsNoOpNotError proves the batch
// path is idempotent on id: a change already on disk (from a prior cycle) must be
// silently skipped, not roll the whole tx back on a PK collision — otherwise the
// watermark never advances and the poller wedges permanently. The append-only
// InsertChange path stays strict (covered separately).
func TestInsertChangesAndAdvanceWatermark_DuplicateIDIsNoOpNotError(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	base := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	// A change already persisted by an earlier cycle.
	if err := st.InsertChange(ctx, sentryChange("release:checkout:v1", base)); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// A later cycle re-emits that same id (its dateReleased advanced) alongside a
	// genuinely new change. The batch must commit and advance the watermark.
	batch := []Change{
		sentryChange("release:checkout:v1", base.Add(5*time.Minute)), // duplicate id, newer occurred_at
		sentryChange("deploy:d-9", base.Add(6*time.Minute)),          // brand new
	}
	const wm = `{"last_emitted_at":"2026-06-25T10:06:00Z","boundary_event_ids":["deploy:d-9"]}`
	if err := st.InsertChangesAndAdvanceWatermark(ctx, batch, "sentry-releases", wm); err != nil {
		t.Fatalf("batch with a duplicate id must not error: %v", err)
	}

	got, _ := st.ChangesInWindow(ctx, base.Add(-time.Hour), base.Add(time.Hour))
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2 (duplicate skipped, new inserted)", len(got))
	}
	// DO NOTHING leaves the pre-existing row untouched (original occurred_at).
	for _, c := range got {
		if c.ID == "release:checkout:v1" && !c.OccurredAt.Equal(base) {
			t.Errorf("duplicate-id row occurred_at = %v, want unchanged %v", c.OccurredAt, base)
		}
	}
	if v, found, _ := st.LoadConnectorState(ctx, "sentry-releases"); !found || v != wm {
		t.Errorf("watermark = (%q, %v), want advanced (%q, true)", v, found, wm)
	}
}

func TestInsertChangesAndAdvanceWatermark_RollsBackOnBadChange(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	// Seed an existing watermark so we can prove it does NOT advance on failure.
	const seed = `{"last_emitted_at":"2026-06-25T09:00:00Z","boundary_event_ids":[]}`
	if err := st.SaveConnectorState(ctx, "sentry-releases", seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	base := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	good := sentryChange("deploy:d-1", base.Add(time.Minute))
	bad := sentryChange("deploy:d-2", base.Add(2*time.Minute))
	bad.Kind = "" // fails validateChange → whole tx must roll back

	err := st.InsertChangesAndAdvanceWatermark(ctx, []Change{good, bad}, "sentry-releases", `{"advanced":true}`)
	if err == nil {
		t.Fatal("expected error from bad change, got nil")
	}

	// Neither change persisted...
	all, _ := st.ChangesInWindow(ctx, base, base.Add(time.Hour))
	if len(all) != 0 {
		t.Errorf("after rollback have %d changes, want 0 (good one must roll back too)", len(all))
	}
	// ...and the watermark did not advance.
	if v, _, _ := st.LoadConnectorState(ctx, "sentry-releases"); v != seed {
		t.Errorf("watermark advanced on failure: %q, want unchanged %q", v, seed)
	}
}

// TestSharedInsertPath_ByteIdenticalRows guards against SQL drift between the
// append-only InsertChange (via s.db) and the batch method (via a tx): the same
// logical change written through each path must produce identical column values.
func TestSharedInsertPath_ByteIdenticalRows(t *testing.T) {
	ctx := context.Background()
	st, _ := Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()

	at := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	viaDB := sentryChange("via-db", at)
	viaTx := sentryChange("via-tx", at)

	if err := st.InsertChange(ctx, viaDB); err != nil {
		t.Fatalf("InsertChange: %v", err)
	}
	if err := st.InsertChangesAndAdvanceWatermark(ctx, []Change{viaTx}, "sentry-releases", "{}"); err != nil {
		t.Fatalf("batch: %v", err)
	}

	read := func(id string) []any {
		var source, kind, title, labels, occurred, received string
		var version, link any
		err := st.DB().QueryRowContext(ctx, `
			SELECT source, kind, title, labels_json, version, link, occurred_at, received_at
			FROM changes WHERE id = ?`, id,
		).Scan(&source, &kind, &title, &labels, &version, &link, &occurred, &received)
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return []any{source, kind, title, labels, version, link, occurred, received}
	}
	db, tx := read("via-db"), read("via-tx")
	for i := range db {
		if db[i] != tx[i] {
			t.Errorf("column %d differs between db-path (%v) and tx-path (%v)", i, db[i], tx[i])
		}
	}
}
