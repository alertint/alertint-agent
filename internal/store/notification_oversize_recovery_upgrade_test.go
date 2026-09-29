// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Upgrading to the bounded renderer retries only the current root that the
// old renderer lost to msg_too_long. Unrelated invalid deliveries stay failed.
func TestUpgradeRetriesCurrentOversizedRootOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oversized-root.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	_, first := snSeedOneCycle(t, st, "oversized-root", now)
	root := shIntentOfClass(t, first.History.Intents, model.EffectRootSync)
	claim := snClaimOne(t, st, now)
	if err := st.FailNotificationIntent(ctx, claim, "msg_too_long", now); err != nil {
		t.Fatal(err)
	}
	_, second := snSeedOneCycle(t, st, "other-invalid-root", now.Add(time.Second))
	other := shIntentOfClass(t, second.History.Intents, model.EffectRootSync)
	claim = snClaimOne(t, st, now.Add(time.Second))
	if err := st.FailNotificationIntent(ctx, claim, "invalid_blocks", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 40`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgraded.Close() }()
	got := snIntent(t, upgraded, root.ID)
	if got.Status != model.IntentPending || got.AttemptCount != 1 || got.RetryAt == nil {
		t.Fatalf("oversized root after upgrade: status=%s attempts=%d retry=%v", got.Status, got.AttemptCount, got.RetryAt)
	}
	if gotOther := snIntent(t, upgraded, other.ID); gotOther.Status != model.IntentFailed {
		t.Fatalf("unrelated invalid root = %s, want failed", gotOther.Status)
	}
	claimed := snClaimOne(t, upgraded, time.Now().UTC().Add(time.Minute))
	if claimed.Intent.ID != root.ID {
		t.Fatalf("claimed %s, want recovered root %s", claimed.Intent.ID, root.ID)
	}
	if err := upgraded.FailNotificationIntent(ctx, claimed, "msg_too_long", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	if again := snIntent(t, restarted, root.ID); again.Status != model.IntentFailed {
		t.Fatalf("root after another restart = %s, want failed (no retry loop)", again.Status)
	}
}
