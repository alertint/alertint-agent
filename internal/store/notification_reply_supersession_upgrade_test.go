// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Migration 0023 upgrade test (B0 integration contract §5.3/§6, E1): a
// populated migration-22 database must relax notification_intents'
// supersession CHECK to admit a live thread_append assurance alongside
// root_sync, gain the thread supersession guard trigger, keep 0021's
// live-only rule, preserve slack_delivery_gaps.recovery_notice_intent_id
// across the rebuild, keep MaxSchemaVersion honest at the newest embedded
// migration, pass PRAGMA foreign_key_check, and fabricate no rows.
//
// Open() applies the whole embedded chain, so the guard this exercises is
// migration 0024's replacement (D1, lead review 2026-09-10), not 0023's
// original. Both refuse this fixture's rows for the same reason and the
// upgrade path is what is under test here; 0024's own before/after upgrade
// is notification_assurance_candidate_guard_upgrade_test.go, and the two
// guards' differing verdicts are
// situation_assurance_candidate_parity_test.go.
// ----------------------------------------------------------------------

// seedMigration22ReplySupersessionFixture builds a database shaped like the
// schema immediately before 0023 (every embedded migration through 22) and
// seeds one Situation with two Transitions — one investigation_started
// (the assurance), one an ordinary evidence_conclusion — three
// notification_intents rows (a pending assurance thread_append, a pending
// non-assurance thread_append, and a delivered assurance thread_append) and
// one slack_delivery_gaps row whose recovery_notice_intent_id points at the
// delivered row, so the upgrade is exercised over real ledger rows and a
// real cross-table FK, not an empty table.
func seedMigration22ReplySupersessionFixture(t *testing.T, path string) (pendingAssuranceID, pendingOtherID, deliveredAssuranceID, gapID string) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range migrations {
		if m.version > 22 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	situationID := "sit-reply-supersession"
	insertOperationalIncident(ctx, t, fixture, "inc-reply-supersession", "group-reply-supersession")
	if err := insertSituation(ctx, fixture, situationRow{
		id: situationID, groupKey: "group-reply-supersession", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	assuranceTransitionID := "tr-assurance"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 1, 1, 'sha256:assurance', 'active', 'observe',
		          '{}', 'investigation_started', 'investigation_started', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		assuranceTransitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("insert assurance transition: %v", err)
	}
	otherTransitionID := "tr-other"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 2, 1, 'sha256:other', 'active', 'observe',
		          '{}', 'material_assessment_changed', 'evidence_conclusion', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		otherTransitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("insert other transition: %v", err)
	}
	// A second, distinct investigation_started-journalled transition for the
	// already-delivered assurance: the thread_broadcast_uniq_idx forbids two
	// thread_append rows on the same (situation, sequence), and this fixture
	// only cares that its journal_kind qualifies for the new guard, not that
	// a Situation realistically earns two assurances.
	deliveredAssuranceTransitionID := "tr-assurance-delivered"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 3, 1, 'sha256:assurance-delivered', 'active', 'observe',
		          '{}', 'investigation_started', 'investigation_started', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		deliveredAssuranceTransitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("insert delivered-assurance transition: %v", err)
	}

	pendingAssuranceID = "intent-pending-assurance"
	pendingOtherID = "intent-pending-other"
	deliveredAssuranceID = "intent-delivered-assurance"
	rows := []struct {
		id, transitionID string
		sequence         int
		status           string
		delivered        bool
	}{
		{pendingAssuranceID, assuranceTransitionID, 1, "pending", false},
		{pendingOtherID, otherTransitionID, 2, "pending", false},
		{deliveredAssuranceID, deliveredAssuranceTransitionID, 3, "delivered", true},
	}
	for _, r := range rows {
		if r.delivered {
			if _, err := db.ExecContext(ctx, `
				INSERT INTO notification_intents (
					id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
					requires_root, main_channel_poke, client_message_id, status,
					delivered_as, channel, message_ts, delivered_at, created_at
				) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, 'delivered', 'thread', 'C', '1.1', ?, ?)`,
				r.id, "key:"+r.id, situationID, r.transitionID, r.sequence, "client:"+r.id,
				canonicalTime(now), canonicalTime(now)); err != nil {
				t.Fatalf("insert delivered intent %s: %v", r.id, err)
			}
			continue
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
				requires_root, main_channel_poke, client_message_id, status, created_at
			) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, ?, ?)`,
			r.id, "key:"+r.id, situationID, r.transitionID, r.sequence, "client:"+r.id, r.status, canonicalTime(now)); err != nil {
			t.Fatalf("insert %s intent %s: %v", r.status, r.id, err)
		}
	}

	gapID = "gap-reply-supersession"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO slack_delivery_gaps (id, status, opened_at, recovered_at, completed_at, recovery_notice_intent_id)
		VALUES (?, 'complete', ?, ?, ?, ?)`,
		gapID, canonicalTime(now), canonicalTime(now), canonicalTime(now), deliveredAssuranceID); err != nil {
		t.Fatalf("insert slack delivery gap: %v", err)
	}
	return pendingAssuranceID, pendingOtherID, deliveredAssuranceID, gapID
}

func TestNotificationReplySupersessionUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration22-reply-supersession.db")
	pendingAssuranceID, pendingOtherID, deliveredAssuranceID, gapID := seedMigration22ReplySupersessionFixture(t, path)

	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 23`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 23 applied count = %d, want 1", applied)
	}
	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 36 {
		t.Fatalf("MaxSchemaVersion = %d, want 36", got)
	}

	assertNoForeignKeyViolations(ctx, t, st)

	var intents int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 3 {
		t.Fatalf("notification_intents count = %d, want the 3 seeded rows", intents)
	}

	// The cross-table FK survived the drop/rebuild round trip unchanged.
	var recoveryNoticeID string
	if err := st.DB().QueryRowContext(ctx, `SELECT recovery_notice_intent_id FROM slack_delivery_gaps WHERE id = ?`, gapID).Scan(&recoveryNoticeID); err != nil {
		t.Fatalf("read recovery_notice_intent_id after upgrade: %v", err)
	}
	if recoveryNoticeID != deliveredAssuranceID {
		t.Fatalf("recovery_notice_intent_id = %q after upgrade, want unchanged %q", recoveryNoticeID, deliveredAssuranceID)
	}

	// A pending assurance thread_append may now become superseded.
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'superseded_by_finding',
		       replacement_intent_id = ?
		WHERE id = ?`, pendingOtherID, pendingAssuranceID); err != nil {
		t.Fatalf("supersede a pending assurance thread_append after 0023: %v", err)
	}

	// A pending thread_append that is not an assurance may not — the guard
	// trigger. This fixture's row records no candidates at all, so both
	// 0023's label rule and 0024's legacy fallback reach the same verdict
	// through it: its journal_kind is evidence_conclusion.
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'superseded_by_finding',
		       replacement_intent_id = ?
		WHERE id = ?`, deliveredAssuranceID, pendingOtherID); err == nil || !strings.Contains(err.Error(), "purely transient first_execution_assurance") {
		t.Fatalf("superseding a non-assurance thread_append = %v, want the supersession guard's rejection", err)
	}

	// A DELIVERED assurance thread_append still may not — 0021's live-only
	// rule, unchanged and now also covering thread_append.
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'superseded_by_finding',
		       replacement_intent_id = ?, delivered_as = NULL, channel = NULL, message_ts = NULL, delivered_at = NULL
		WHERE id = ?`, pendingOtherID, deliveredAssuranceID); err == nil || !strings.Contains(err.Error(), "live root_sync or thread_append") {
		t.Fatalf("superseding a delivered assurance = %v, want the live-only trigger's rejection", err)
	}

	assertNoForeignKeyViolations(ctx, t, st)
}
