// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Step 5: migration 0018 upgrade tests — a populated migration-17 fixture
// (Task 2's history schema already applied) must gain the new STRICT
// tables and MaxSchemaVersion 18, pass PRAGMA foreign_key_check, gain
// NULL slack_channel/slack_root_ts on every existing situations row, and
// acquire zero fabricated notification_intents/slack_delivery_gaps rows.
// ----------------------------------------------------------------------

// seedMigration17NotificationsFixture builds a database file shaped like
// the schema immediately before this task's 0018 (every embedded
// migration through version 17 only, so notification_intents/
// slack_delivery_state/slack_delivery_gaps and situations.slack_channel/
// slack_root_ts do not exist yet) and seeds three Situations covering the
// states the brief's Step 5 names: one nonterminal with pending controller
// work (a due, unclaimed reconciliation), one carrying blocked/retry state
// (a claimed-and-failed lease with a scheduled retry), and one terminal —
// entirely by direct SQL, since this fixture predates 0018's columns.
func seedMigration17NotificationsFixture(t *testing.T, path string) (pendingID, retryID, terminalID string) {
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
		if m.version > 17 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	pendingID = "sit-notif-pending"
	retryID = "sit-notif-retry"
	terminalID = "sit-notif-terminal"

	insertOperationalIncident(ctx, t, fixture, "inc-notif-pending", "group-notif-pending")
	if err := insertSituation(ctx, fixture, situationRow{id: pendingID, groupKey: "group-notif-pending", lifecycle: "active"}); err != nil {
		t.Fatalf("insert pending situation: %v", err)
	}

	insertOperationalIncident(ctx, t, fixture, "inc-notif-retry", "group-notif-retry")
	if err := insertSituation(ctx, fixture, situationRow{id: retryID, groupKey: "group-notif-retry", lifecycle: "active"}); err != nil {
		t.Fatalf("insert retry situation: %v", err)
	}
	// Blocked/retry state: a claimed lease that failed and is now scheduled
	// for retry, the same shape ClaimDueSituations/its failure path leaves
	// behind — proves the upgrade preserves this in-flight controller state
	// verbatim.
	if _, err := db.ExecContext(ctx, `
		UPDATE situations SET last_error_class = 'llm_timeout', retry_at = ?, attempt_count = 2 WHERE id = ?
	`, canonicalTime(now.Add(5*time.Minute)), retryID); err != nil {
		t.Fatalf("seed retry state: %v", err)
	}

	insertOperationalIncident(ctx, t, fixture, "inc-notif-terminal", "group-notif-terminal")
	term := canonicalTime(now.Add(time.Hour))
	if err := insertSituation(ctx, fixture, situationRow{
		id: terminalID, groupKey: "group-notif-terminal", lifecycle: "closed_unknown",
		terminalAt: term, terminalReason: "resolution_missing",
	}); err != nil {
		t.Fatalf("insert terminal situation: %v", err)
	}

	return pendingID, retryID, terminalID
}

// TestSituationNotificationsUpgrade_CreatesStrictTablesAndBumpsSchemaVersion
// is the brief's literal Step 5 test: opening a migration-17 database with
// the current Open must apply 0018, create its new STRICT tables, bump
// MaxSchemaVersion to 18, pass PRAGMA foreign_key_check, seed exactly one
// slack_delivery_state row, and fabricate zero notification_intents or
// slack_delivery_gaps rows.
func TestSituationNotificationsUpgrade_CreatesStrictTablesAndBumpsSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration17-notifications.db")
	seedMigration17NotificationsFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 18`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 18 applied count = %d, want 1", applied)
	}

	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 18 {
		t.Fatalf("MaxSchemaVersion = %d, want 18", got)
	}

	for _, table := range []string{"notification_intents", "slack_delivery_gaps", "slack_delivery_state"} {
		var name string
		if err := st.DB().QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("table %s missing after upgrade: %v", table, err)
		}
	}

	assertNoForeignKeyViolations(ctx, t, st)

	var intents, gaps, states int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("notification_intents count = %d, want 0 (migration alone fabricates nothing)", intents)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM slack_delivery_gaps`).Scan(&gaps); err != nil {
		t.Fatal(err)
	}
	if gaps != 0 {
		t.Fatalf("slack_delivery_gaps count = %d, want 0 (migration alone fabricates nothing)", gaps)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM slack_delivery_state`).Scan(&states); err != nil {
		t.Fatal(err)
	}
	if states != 1 {
		t.Fatalf("slack_delivery_state count = %d, want exactly 1 seeded singleton", states)
	}

	var configGen int
	var openGap sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT configuration_generation, open_gap_generation FROM slack_delivery_state WHERE id = 1`).
		Scan(&configGen, &openGap); err != nil {
		t.Fatalf("read seeded slack_delivery_state: %v", err)
	}
	if configGen != 0 || openGap.Valid {
		t.Fatalf("seeded slack_delivery_state = (configuration_generation=%d, open_gap_generation=%v), want (0, NULL)", configGen, openGap)
	}
}

// TestSituationNotificationsUpgrade_ExistingSituationsGainNoSlackRoot
// proves every pre-0018 Situation — pending controller work, blocked/retry
// state, and terminal — remains fully readable after the upgrade, with
// NULL slack_channel/slack_root_ts: this migration never invents a
// published root, and it preserves in-flight retry/attempt state exactly.
func TestSituationNotificationsUpgrade_ExistingSituationsGainNoSlackRoot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration17-notifications-readable.db")
	pendingID, retryID, terminalID := seedMigration17NotificationsFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	for _, id := range []string{pendingID, retryID, terminalID} {
		var channel, rootTS sql.NullString
		if err := st.DB().QueryRowContext(ctx, `SELECT slack_channel, slack_root_ts FROM situations WHERE id = ?`, id).
			Scan(&channel, &rootTS); err != nil {
			t.Fatalf("read slack root coordinates for %s: %v", id, err)
		}
		if channel.Valid || rootTS.Valid {
			t.Fatalf("situation %s slack root = (%v,%v), want (NULL,NULL)", id, channel, rootTS)
		}
	}

	var lastErrorClass sql.NullString
	var attemptCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT last_error_class, attempt_count FROM situations WHERE id = ?`, retryID).
		Scan(&lastErrorClass, &attemptCount); err != nil {
		t.Fatalf("read retry situation: %v", err)
	}
	if !lastErrorClass.Valid || lastErrorClass.String != "llm_timeout" || attemptCount != 2 {
		t.Fatalf("retry situation state = (%v,%d), want (llm_timeout,2) preserved across upgrade", lastErrorClass, attemptCount)
	}

	nonterm, err := st.GetSituation(ctx, pendingID)
	if err != nil {
		t.Fatalf("get pending situation: %v", err)
	}
	if nonterm.Lifecycle != "active" {
		t.Fatalf("pending situation lifecycle = %s, want active", nonterm.Lifecycle)
	}

	term, err := st.GetSituation(ctx, terminalID)
	if err != nil {
		t.Fatalf("get terminal situation: %v", err)
	}
	if term.Lifecycle != "closed_unknown" {
		t.Fatalf("terminal situation lifecycle = %s, want closed_unknown", term.Lifecycle)
	}
}

// ----------------------------------------------------------------------
// Step 1/2: direct constraint tests for notification_intents.
// ----------------------------------------------------------------------

// notificationIntentRow is a minimal, overridable set of columns for
// inserting a row into notification_intents directly — schema/constraint
// tests only; the planning/commit logic that builds real intents is a
// later task. Every field defaults to a legal root_sync shape unless
// overridden, since that is the most field-heavy effect class.
type notificationIntentRow struct {
	id                   string
	idempotencyKey       string
	effectClass          string
	situationID          any
	transitionID         any
	transitionSequence   any
	summaryVersion       any
	gapGeneration        any
	requiresRoot         int
	mainChannelPoke      int
	interruptionPriority any
	contractDeadlineAt   any
	clientMessageID      string
	status               string
	claimOwner           any
	leaseExpiresAt       any
	supersessionReason   any
	replacementIntentID  any
	deliveredAs          any
	channel              any
	messageTS            any
	deliveredAt          any
}

func insertNotificationIntent(ctx context.Context, s *Store, r notificationIntentRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := r.status
	if status == "" {
		status = "pending"
	}
	clientMessageID := r.clientMessageID
	if clientMessageID == "" {
		clientMessageID = "cmid-" + r.id
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			summary_version, gap_generation, requires_root, main_channel_poke, interruption_priority,
			contract_deadline_at, client_message_id, status, claim_owner, lease_expires_at,
			supersession_reason, replacement_intent_id, delivered_as, channel, message_ts,
			created_at, delivered_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.id, r.idempotencyKey, r.effectClass, r.situationID, r.transitionID, r.transitionSequence,
		r.summaryVersion, r.gapGeneration, r.requiresRoot, r.mainChannelPoke, r.interruptionPriority,
		r.contractDeadlineAt, clientMessageID, status, r.claimOwner, r.leaseExpiresAt,
		r.supersessionReason, r.replacementIntentID, r.deliveredAs, r.channel, r.messageTS,
		now, r.deliveredAt)
	return err
}

// legalRootSyncIntent returns a notificationIntentRow shaped as a legal
// pending root_sync referencing the given situation/transition, for tests
// that only need one valid anchor row to mutate or conflict against.
func legalRootSyncIntent(id, situationID, transitionID string, sequence, summaryVersion int) notificationIntentRow {
	return notificationIntentRow{
		id: id, idempotencyKey: "idem-" + id, effectClass: "root_sync",
		situationID: situationID, transitionID: transitionID, transitionSequence: sequence,
		summaryVersion: summaryVersion, requiresRoot: 0, mainChannelPoke: 1, interruptionPriority: "high",
	}
}

func seedNotificationIntentFixture(ctx context.Context, t *testing.T, s *Store, situationID, groupKey, transitionID string) {
	t.Helper()
	insertOperationalIncident(ctx, t, s, "inc-"+situationID, groupKey)
	if err := insertSituation(ctx, s, situationRow{id: situationID, groupKey: groupKey, lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation %s: %v", situationID, err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: transitionID, situationID: situationID, sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition %s: %v", transitionID, err)
	}
}

// TestSituationNotificationSchema_ClosedEffectClassAndStatus proves the
// closed effect_class and status enums.
func TestSituationNotificationSchema_ClosedEffectClassAndStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-enum", "group-ni-enum", "tr-ni-enum")

	bad := legalRootSyncIntent("ni-enum-bad-class", "sit-ni-enum", "tr-ni-enum", 1, 1)
	bad.effectClass = "bogus_class"
	if err := insertNotificationIntent(ctx, s, bad); err == nil {
		t.Fatal("expected an unknown effect_class to be rejected")
	}

	badStatus := legalRootSyncIntent("ni-enum-bad-status", "sit-ni-enum", "tr-ni-enum", 1, 1)
	badStatus.status = "bogus_status"
	if err := insertNotificationIntent(ctx, s, badStatus); err == nil {
		t.Fatal("expected an unknown status to be rejected")
	}

	good := legalRootSyncIntent("ni-enum-good", "sit-ni-enum", "tr-ni-enum", 1, 1)
	if err := insertNotificationIntent(ctx, s, good); err != nil {
		t.Fatalf("expected a legal root_sync intent to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_ClosedDeliveryMode proves delivered_as is
// a closed enum: root | thread | broadcast | delayed_thread | system.
func TestSituationNotificationSchema_ClosedDeliveryMode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-mode", "group-ni-mode", "tr-ni-mode")

	bad := legalRootSyncIntent("ni-mode-bad", "sit-ni-mode", "tr-ni-mode", 1, 1)
	bad.status = "delivered"
	bad.deliveredAs = "bogus_mode"
	bad.channel, bad.messageTS = "C1", "111.222"
	bad.deliveredAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := insertNotificationIntent(ctx, s, bad); err == nil {
		t.Fatal("expected an unknown delivered_as value to be rejected")
	}

	for _, mode := range []string{"root", "thread", "broadcast", "delayed_thread", "system"} {
		row := legalRootSyncIntent("ni-mode-"+mode, "sit-ni-mode", "tr-ni-mode", 1, 1)
		row.status = "delivered"
		row.deliveredAs = mode
		row.channel, row.messageTS = "C1", "111.222"
		row.deliveredAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := insertNotificationIntent(ctx, s, row); err != nil {
			t.Fatalf("expected delivered_as=%s to be accepted: %v", mode, err)
		}
	}
}

// TestSituationNotificationSchema_UTCInstants proves created_at is required
// and non-empty (the store convention of UTC RFC3339Nano text timestamps —
// a blank value is the one shape a CHECK can reject directly).
func TestSituationNotificationSchema_UTCInstants(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-utc", "group-ni-utc", "tr-ni-utc")

	row := legalRootSyncIntent("ni-utc-bad", "sit-ni-utc", "tr-ni-utc", 1, 1)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			summary_version, requires_root, main_channel_poke, interruption_priority,
			client_message_id, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
	`, row.id, row.idempotencyKey, row.effectClass, row.situationID, row.transitionID, row.transitionSequence,
		row.summaryVersion, row.requiresRoot, row.mainChannelPoke, row.interruptionPriority,
		"cmid-ni-utc-bad", "pending"); err == nil {
		t.Fatal("expected an empty created_at to be rejected")
	}
}

// TestSituationNotificationSchema_StableIdempotencyAndClientIDs proves
// idempotency_key is unique and client_message_id is required.
func TestSituationNotificationSchema_StableIdempotencyAndClientIDs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-idem", "group-ni-idem", "tr-ni-idem")

	first := legalRootSyncIntent("ni-idem-1", "sit-ni-idem", "tr-ni-idem", 1, 1)
	if err := insertNotificationIntent(ctx, s, first); err != nil {
		t.Fatalf("insert first intent: %v", err)
	}
	dup := legalRootSyncIntent("ni-idem-2", "sit-ni-idem", "tr-ni-idem", 1, 1)
	dup.idempotencyKey = first.idempotencyKey
	if err := insertNotificationIntent(ctx, s, dup); err == nil {
		t.Fatal("expected a duplicate idempotency_key to be rejected")
	}

	// A blank client_message_id is rejected. Uses thread_append (not
	// root_sync) so the only thing under test is the client_message_id
	// CHECK, not the separate one-pending-root_sync-per-situation index —
	// insertNotificationIntent's own helper can't exercise this: it
	// substitutes a synthesized id whenever clientMessageID is left blank,
	// so this needs a direct INSERT with a literal empty string.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			requires_root, main_channel_poke, client_message_id, status, created_at
		) VALUES (?, ?, 'thread_append', ?, ?, ?, ?, ?, '', 'pending', ?)
	`, "ni-idem-blank", "idem-ni-idem-blank", "sit-ni-idem", "tr-ni-idem", 1, 1, 0,
		time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("expected an empty client_message_id to be rejected")
	}
}

// TestSituationNotificationSchema_ReferenceShapeBySituationAndGapClass
// proves the effect-class reference shape: the three Situation effects
// require Situation/Transition/sequence and forbid gap_generation;
// installation_gap_recovery requires gap_generation and forbids the rest.
func TestSituationNotificationSchema_ReferenceShapeBySituationAndGapClass(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-ref", "group-ni-ref", "tr-ni-ref")
	if err := insertGapGeneration(ctx, s, "gap-ni-ref", "open"); err != nil {
		t.Fatalf("seed gap generation: %v", err)
	}

	// A Situation effect missing situation_id/transition_id is rejected.
	missing := legalRootSyncIntent("ni-ref-missing", "sit-ni-ref", "tr-ni-ref", 1, 1)
	missing.situationID = nil
	if err := insertNotificationIntent(ctx, s, missing); err == nil {
		t.Fatal("expected root_sync with no situation_id to be rejected")
	}

	// A Situation effect also carrying gap_generation is rejected.
	both := legalRootSyncIntent("ni-ref-both", "sit-ni-ref", "tr-ni-ref", 1, 1)
	both.gapGeneration = "gap-ni-ref"
	if err := insertNotificationIntent(ctx, s, both); err == nil {
		t.Fatal("expected root_sync also carrying gap_generation to be rejected")
	}

	// installation_gap_recovery with a situation_id is rejected.
	gapWithSituation := notificationIntentRow{
		id: "ni-ref-gap-bad", idempotencyKey: "idem-ni-ref-gap-bad", effectClass: "installation_gap_recovery",
		situationID: "sit-ni-ref", gapGeneration: "gap-ni-ref", requiresRoot: 0, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, gapWithSituation); err == nil {
		t.Fatal("expected installation_gap_recovery with a situation_id to be rejected")
	}

	// installation_gap_recovery with no gap_generation is rejected.
	gapMissing := notificationIntentRow{
		id: "ni-ref-gap-missing", idempotencyKey: "idem-ni-ref-gap-missing", effectClass: "installation_gap_recovery",
		requiresRoot: 0, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, gapMissing); err == nil {
		t.Fatal("expected installation_gap_recovery with no gap_generation to be rejected")
	}

	// A legal installation_gap_recovery intent is accepted.
	gapGood := notificationIntentRow{
		id: "ni-ref-gap-good", idempotencyKey: "idem-ni-ref-gap-good", effectClass: "installation_gap_recovery",
		gapGeneration: "gap-ni-ref", requiresRoot: 0, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, gapGood); err != nil {
		t.Fatalf("expected a legal installation_gap_recovery intent to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_SummaryVersionOnlyOnRootSync proves
// summary_version is set if and only if effect_class = 'root_sync'.
func TestSituationNotificationSchema_SummaryVersionOnlyOnRootSync(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-sv", "group-ni-sv", "tr-ni-sv")

	rootNoVersion := legalRootSyncIntent("ni-sv-root-missing", "sit-ni-sv", "tr-ni-sv", 1, 1)
	rootNoVersion.summaryVersion = nil
	if err := insertNotificationIntent(ctx, s, rootNoVersion); err == nil {
		t.Fatal("expected root_sync with no summary_version to be rejected")
	}

	threadWithVersion := notificationIntentRow{
		id: "ni-sv-thread-bad", idempotencyKey: "idem-ni-sv-thread-bad", effectClass: "thread_append",
		situationID: "sit-ni-sv", transitionID: "tr-ni-sv", transitionSequence: 1, summaryVersion: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, threadWithVersion); err == nil {
		t.Fatal("expected thread_append carrying summary_version to be rejected")
	}

	threadGood := notificationIntentRow{
		id: "ni-sv-thread-good", idempotencyKey: "idem-ni-sv-thread-good", effectClass: "thread_append",
		situationID: "sit-ni-sv", transitionID: "tr-ni-sv", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, threadGood); err != nil {
		t.Fatalf("expected thread_append with no summary_version to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_ContractDeadlineOnlyOnRootSync (R4)
// proves contract_deadline_at is nullable but non-NULL only on root_sync.
func TestSituationNotificationSchema_ContractDeadlineOnlyOnRootSync(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-deadline", "group-ni-deadline", "tr-ni-deadline")

	now := time.Now().UTC().Format(time.RFC3339Nano)

	threadWithDeadline := notificationIntentRow{
		id: "ni-deadline-thread-bad", idempotencyKey: "idem-ni-deadline-thread-bad", effectClass: "thread_append",
		situationID: "sit-ni-deadline", transitionID: "tr-ni-deadline", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0, contractDeadlineAt: now,
	}
	if err := insertNotificationIntent(ctx, s, threadWithDeadline); err == nil {
		t.Fatal("expected thread_append carrying contract_deadline_at to be rejected")
	}

	rootNoDeadline := legalRootSyncIntent("ni-deadline-root-nil", "sit-ni-deadline", "tr-ni-deadline", 1, 1)
	if err := insertNotificationIntent(ctx, s, rootNoDeadline); err != nil {
		t.Fatalf("expected root_sync with no contract_deadline_at (terminal root) to be accepted: %v", err)
	}
	// Free the situation's one-pending-root_sync slot before inserting a
	// second root_sync below.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', channel = 'C1', message_ts = '111.222',
			delivered_as = 'root', delivered_at = ? WHERE id = ?
	`, now, rootNoDeadline.id); err != nil {
		t.Fatalf("mark rootNoDeadline delivered: %v", err)
	}

	rootWithDeadline := legalRootSyncIntent("ni-deadline-root-set", "sit-ni-deadline", "tr-ni-deadline", 1, 2)
	rootWithDeadline.contractDeadlineAt = now
	if err := insertNotificationIntent(ctx, s, rootWithDeadline); err != nil {
		t.Fatalf("expected root_sync carrying contract_deadline_at to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_MainPokePriorityEquivalence proves a
// candidate main-channel poke always carries an Interruption priority, and
// nothing else does.
func TestSituationNotificationSchema_MainPokePriorityEquivalence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-poke", "group-ni-poke", "tr-ni-poke")

	pokeNoPriority := legalRootSyncIntent("ni-poke-missing", "sit-ni-poke", "tr-ni-poke", 1, 1)
	pokeNoPriority.mainChannelPoke = 1
	pokeNoPriority.interruptionPriority = nil
	if err := insertNotificationIntent(ctx, s, pokeNoPriority); err == nil {
		t.Fatal("expected main_channel_poke=true with no interruption_priority to be rejected")
	}

	priorityNoPoke := legalRootSyncIntent("ni-poke-extra", "sit-ni-poke", "tr-ni-poke", 1, 1)
	priorityNoPoke.mainChannelPoke = 0
	priorityNoPoke.interruptionPriority = "high"
	if err := insertNotificationIntent(ctx, s, priorityNoPoke); err == nil {
		t.Fatal("expected main_channel_poke=false carrying interruption_priority to be rejected")
	}

	good := legalRootSyncIntent("ni-poke-good", "sit-ni-poke", "tr-ni-poke", 1, 1)
	good.mainChannelPoke = 0
	good.interruptionPriority = nil
	if err := insertNotificationIntent(ctx, s, good); err != nil {
		t.Fatalf("expected a non-poke with no priority to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_RootRequirementMatchesEffectClass proves
// requires_root is exactly true for thread_append/broadcast_handoff and
// false otherwise.
func TestSituationNotificationSchema_RootRequirementMatchesEffectClass(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-root", "group-ni-root", "tr-ni-root")
	if err := insertGapGeneration(ctx, s, "gap-ni-root", "open"); err != nil {
		t.Fatalf("seed gap generation: %v", err)
	}

	rootSyncWrong := legalRootSyncIntent("ni-root-rs-bad", "sit-ni-root", "tr-ni-root", 1, 1)
	rootSyncWrong.requiresRoot = 1
	if err := insertNotificationIntent(ctx, s, rootSyncWrong); err == nil {
		t.Fatal("expected root_sync with requires_root=true to be rejected")
	}

	threadWrong := notificationIntentRow{
		id: "ni-root-thread-bad", idempotencyKey: "idem-ni-root-thread-bad", effectClass: "thread_append",
		situationID: "sit-ni-root", transitionID: "tr-ni-root", transitionSequence: 1,
		requiresRoot: 0, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, threadWrong); err == nil {
		t.Fatal("expected thread_append with requires_root=false to be rejected")
	}

	threadGood := notificationIntentRow{
		id: "ni-root-thread-good", idempotencyKey: "idem-ni-root-thread-good", effectClass: "thread_append",
		situationID: "sit-ni-root", transitionID: "tr-ni-root", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, threadGood); err != nil {
		t.Fatalf("expected thread_append with requires_root=true to be accepted: %v", err)
	}

	gapWrong := notificationIntentRow{
		id: "ni-root-gap-bad", idempotencyKey: "idem-ni-root-gap-bad", effectClass: "installation_gap_recovery",
		gapGeneration: "gap-ni-root", requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, gapWrong); err == nil {
		t.Fatal("expected installation_gap_recovery with requires_root=true to be rejected")
	}
}

// TestSituationNotificationSchema_ClaimOwnerTokenLeaseConsistency proves
// claim_owner/lease_expires_at are paired and claiming is only legal while
// status='pending'.
func TestSituationNotificationSchema_ClaimOwnerTokenLeaseConsistency(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-claim", "group-ni-claim", "tr-ni-claim")

	unpaired := legalRootSyncIntent("ni-claim-unpaired", "sit-ni-claim", "tr-ni-claim", 1, 1)
	unpaired.claimOwner = "worker-1"
	unpaired.leaseExpiresAt = nil
	if err := insertNotificationIntent(ctx, s, unpaired); err == nil {
		t.Fatal("expected claim_owner with no lease_expires_at to be rejected")
	}

	claimedButDelivered := legalRootSyncIntent("ni-claim-delivered", "sit-ni-claim", "tr-ni-claim", 1, 1)
	claimedButDelivered.claimOwner = "worker-1"
	claimedButDelivered.leaseExpiresAt = time.Now().UTC().Format(time.RFC3339Nano)
	claimedButDelivered.status = "delivered"
	claimedButDelivered.deliveredAs = "root"
	claimedButDelivered.channel = "C1"
	claimedButDelivered.messageTS = "111.222"
	claimedButDelivered.deliveredAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := insertNotificationIntent(ctx, s, claimedButDelivered); err == nil {
		t.Fatal("expected a claim_owner set while status != pending to be rejected")
	}

	good := legalRootSyncIntent("ni-claim-good", "sit-ni-claim", "tr-ni-claim", 1, 1)
	good.claimOwner = "worker-1"
	good.leaseExpiresAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := insertNotificationIntent(ctx, s, good); err != nil {
		t.Fatalf("expected a pending claimed intent to be accepted: %v", err)
	}

	var claimToken int
	if err := s.db.QueryRowContext(ctx, `SELECT claim_token FROM notification_intents WHERE id = ?`, good.id).Scan(&claimToken); err != nil {
		t.Fatalf("read default claim_token: %v", err)
	}
	if claimToken != 0 {
		t.Fatalf("default claim_token = %d, want 0", claimToken)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET claim_token = -1 WHERE id = ?`, good.id); err == nil {
		t.Fatal("expected a negative claim_token to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET claim_token = 3 WHERE id = ?`, good.id); err != nil {
		t.Fatalf("expected bumping claim_token to succeed: %v", err)
	}
}

// TestSituationNotificationSchema_AttemptCountPreservedAcrossConfigurationBlock
// proves attempt_count survives a pending -> blocked_configuration ->
// pending round trip untouched: no schema field resets or caps it, and
// blocked_configuration is a durable, indefinitely-held state rather than
// an attempt-exhaustion outcome.
func TestSituationNotificationSchema_AttemptCountPreservedAcrossConfigurationBlock(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-attempts", "group-ni-attempts", "tr-ni-attempts")

	row := legalRootSyncIntent("ni-attempts", "sit-ni-attempts", "tr-ni-attempts", 1, 1)
	if err := insertNotificationIntent(ctx, s, row); err != nil {
		t.Fatalf("insert intent: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET attempt_count = 5 WHERE id = ?`, row.id); err != nil {
		t.Fatalf("bump attempt_count: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET status = 'blocked_configuration' WHERE id = ?`, row.id); err != nil {
		t.Fatalf("block on configuration: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET status = 'pending' WHERE id = ?`, row.id); err != nil {
		t.Fatalf("redrive back to pending: %v", err)
	}

	var attemptCount int
	if err := s.db.QueryRowContext(ctx, `SELECT attempt_count FROM notification_intents WHERE id = ?`, row.id).Scan(&attemptCount); err != nil {
		t.Fatalf("read attempt_count: %v", err)
	}
	if attemptCount != 5 {
		t.Fatalf("attempt_count after blocked_configuration round trip = %d, want 5 (preserved, not reset)", attemptCount)
	}
}

// TestSituationNotificationSchema_DeliveredCoordinatesAndTimeConsistency
// proves delivered_at/channel/message_ts/delivered_as are set together iff
// status='delivered'.
func TestSituationNotificationSchema_DeliveredCoordinatesAndTimeConsistency(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-delivered", "group-ni-delivered", "tr-ni-delivered")

	now := time.Now().UTC().Format(time.RFC3339Nano)

	partial := legalRootSyncIntent("ni-delivered-partial", "sit-ni-delivered", "tr-ni-delivered", 1, 1)
	partial.status = "delivered"
	partial.channel = "C1"
	partial.messageTS = "111.222"
	// deliveredAt and deliveredAs left unset — must be rejected.
	if err := insertNotificationIntent(ctx, s, partial); err == nil {
		t.Fatal("expected status=delivered with incomplete delivery coordinates to be rejected")
	}

	claimedNotDelivered := legalRootSyncIntent("ni-delivered-early", "sit-ni-delivered", "tr-ni-delivered", 1, 1)
	claimedNotDelivered.channel = "C1"
	claimedNotDelivered.messageTS = "111.222"
	claimedNotDelivered.deliveredAt = now
	claimedNotDelivered.deliveredAs = "root"
	// status stays 'pending' while delivery coordinates are already set —
	// must be rejected.
	if err := insertNotificationIntent(ctx, s, claimedNotDelivered); err == nil {
		t.Fatal("expected delivery coordinates set while status != delivered to be rejected")
	}

	good := legalRootSyncIntent("ni-delivered-good", "sit-ni-delivered", "tr-ni-delivered", 1, 1)
	good.status = "delivered"
	good.channel = "C1"
	good.messageTS = "111.222"
	good.deliveredAt = now
	good.deliveredAs = "root"
	if err := insertNotificationIntent(ctx, s, good); err != nil {
		t.Fatalf("expected a fully delivered intent to be accepted: %v", err)
	}
}

// ----------------------------------------------------------------------
// Step 2: indexes and history safety.
// ----------------------------------------------------------------------

// TestSituationNotificationSchema_OnlyOnePendingUnsupersededRootSync proves
// the partial unique index: at most one pending root_sync per Situation.
func TestSituationNotificationSchema_OnlyOnePendingUnsupersededRootSync(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-onepending", "group-ni-onepending", "tr-ni-onepending")

	first := legalRootSyncIntent("ni-onepending-1", "sit-ni-onepending", "tr-ni-onepending", 1, 1)
	if err := insertNotificationIntent(ctx, s, first); err != nil {
		t.Fatalf("insert first pending root_sync: %v", err)
	}

	second := legalRootSyncIntent("ni-onepending-2", "sit-ni-onepending", "tr-ni-onepending", 1, 2)
	if err := insertNotificationIntent(ctx, s, second); err == nil {
		t.Fatal("expected a second pending root_sync for the same situation to be rejected")
	}

	// placeholder stands in for the real replacement intent that a live
	// controller commit would create in the same transaction (Task 5); this
	// schema-only test just needs any legal, already-existing row to satisfy
	// replacement_intent_id's FK and NOT-NULL-on-superseded requirements.
	placeholder := notificationIntentRow{
		id: "ni-onepending-placeholder", idempotencyKey: "idem-ni-onepending-placeholder", effectClass: "thread_append",
		situationID: "sit-ni-onepending", transitionID: "tr-ni-onepending", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, placeholder); err != nil {
		t.Fatalf("insert placeholder: %v", err)
	}

	// Superseding the first frees the slot for a new pending root_sync.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'newer_root', replacement_intent_id = ?
		WHERE id = 'ni-onepending-1'
	`, placeholder.id); err != nil {
		t.Fatalf("supersede first root_sync: %v", err)
	}
	if err := insertNotificationIntent(ctx, s, second); err != nil {
		t.Fatalf("expected a new pending root_sync to be accepted once the prior one is superseded: %v", err)
	}
}

// TestSituationNotificationSchema_ThreadAndBroadcastUniquePerTransition
// proves the partial unique index on (situation_id, transition_sequence,
// effect_class) for thread_append/broadcast_handoff, and that root_sync is
// exempt (a root_sync refresh may legally reuse the same sequence).
func TestSituationNotificationSchema_ThreadAndBroadcastUniquePerTransition(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-tb-uniq", "group-ni-tb-uniq", "tr-ni-tb-uniq")

	thread1 := notificationIntentRow{
		id: "ni-tb-uniq-thread-1", idempotencyKey: "idem-ni-tb-uniq-thread-1", effectClass: "thread_append",
		situationID: "sit-ni-tb-uniq", transitionID: "tr-ni-tb-uniq", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, thread1); err != nil {
		t.Fatalf("insert first thread_append: %v", err)
	}
	thread2 := thread1
	thread2.id, thread2.idempotencyKey = "ni-tb-uniq-thread-2", "idem-ni-tb-uniq-thread-2"
	if err := insertNotificationIntent(ctx, s, thread2); err == nil {
		t.Fatal("expected a second thread_append for the same (situation,sequence) to be rejected")
	}

	broadcast1 := notificationIntentRow{
		id: "ni-tb-uniq-broadcast-1", idempotencyKey: "idem-ni-tb-uniq-broadcast-1", effectClass: "broadcast_handoff",
		situationID: "sit-ni-tb-uniq", transitionID: "tr-ni-tb-uniq", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 1, interruptionPriority: "high",
	}
	if err := insertNotificationIntent(ctx, s, broadcast1); err != nil {
		t.Fatalf("expected broadcast_handoff to coexist with thread_append at the same sequence: %v", err)
	}

	// root_sync is exempt: two root_sync rows at the same sequence (an
	// initial post plus an R4 deadline refresh) are legal at the schema
	// level as long as only one stays pending (proven separately above), so
	// mark the first delivered before inserting the second at the same
	// sequence.
	root1 := legalRootSyncIntent("ni-tb-uniq-root-1", "sit-ni-tb-uniq", "tr-ni-tb-uniq", 1, 1)
	if err := insertNotificationIntent(ctx, s, root1); err != nil {
		t.Fatalf("insert first root_sync: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', channel = 'C1', message_ts = '111.222',
			delivered_as = 'root', delivered_at = ? WHERE id = 'ni-tb-uniq-root-1'
	`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("mark first root_sync delivered: %v", err)
	}
	root2 := legalRootSyncIntent("ni-tb-uniq-root-2", "sit-ni-tb-uniq", "tr-ni-tb-uniq", 1, 2)
	if err := insertNotificationIntent(ctx, s, root2); err != nil {
		t.Fatalf("expected a second root_sync at the same sequence to be accepted: %v", err)
	}
}

// TestSituationNotificationSchema_OnlyRootSyncMayBeSuperseded proves
// thread_append/broadcast_handoff rows can never become superseded.
func TestSituationNotificationSchema_OnlyRootSyncMayBeSuperseded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-supersede", "group-ni-supersede", "tr-ni-supersede")

	thread := notificationIntentRow{
		id: "ni-supersede-thread", idempotencyKey: "idem-ni-supersede-thread", effectClass: "thread_append",
		situationID: "sit-ni-supersede", transitionID: "tr-ni-supersede", transitionSequence: 1,
		requiresRoot: 1, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, thread); err != nil {
		t.Fatalf("insert thread_append: %v", err)
	}
	// bystander is a second, unrelated row used only as a legal (non-self)
	// replacement_intent_id target, so the rejection below is attributable
	// to the "only root_sync may be superseded" CHECK and not the separate
	// no-self-reference CHECK.
	bystander := legalRootSyncIntent("ni-supersede-bystander", "sit-ni-supersede", "tr-ni-supersede", 1, 1)
	if err := insertNotificationIntent(ctx, s, bystander); err != nil {
		t.Fatalf("insert bystander root_sync: %v", err)
	}
	// Mark it delivered so it no longer occupies the situation's
	// one-pending-root_sync slot (needed below for `root`).
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', channel = 'C1', message_ts = '111.222',
			delivered_as = 'root', delivered_at = ? WHERE id = ?
	`, time.Now().UTC().Format(time.RFC3339Nano), bystander.id); err != nil {
		t.Fatalf("mark bystander delivered: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'x', replacement_intent_id = ? WHERE id = ?
	`, bystander.id, thread.id); err == nil {
		t.Fatal("expected a thread_append row to reject becoming superseded")
	}

	// A root_sync that already delivered cannot retroactively become
	// superseded either — only a still-pending one may.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'x', replacement_intent_id = ? WHERE id = ?
	`, thread.id, bystander.id); err == nil {
		t.Fatal("expected an already-delivered root_sync to reject becoming superseded")
	}

	root := legalRootSyncIntent("ni-supersede-root", "sit-ni-supersede", "tr-ni-supersede", 1, 1)
	if err := insertNotificationIntent(ctx, s, root); err != nil {
		t.Fatalf("insert root_sync: %v", err)
	}
	// A root_sync, unlike thread_append, accepts becoming superseded.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'superseded', supersession_reason = 'newer_root', replacement_intent_id = ? WHERE id = ?
	`, bystander.id, root.id); err != nil {
		t.Fatalf("expected a root_sync row to accept becoming superseded: %v", err)
	}
}

// TestSituationNotificationSchema_NoDelete proves notification_intents
// rows can never be deleted, even a terminal one.
func TestSituationNotificationSchema_NoDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-delete", "group-ni-delete", "tr-ni-delete")

	row := legalRootSyncIntent("ni-delete", "sit-ni-delete", "tr-ni-delete", 1, 1)
	if err := insertNotificationIntent(ctx, s, row); err != nil {
		t.Fatalf("insert intent: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM notification_intents WHERE id = ?`, row.id); err == nil {
		t.Fatal("expected deleting a notification intent to be rejected")
	}

	// A status mutation (the intent's ordinary lifecycle), by contrast, must
	// succeed — "no DELETE" is not "no UPDATE".
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET status = 'delivered', channel = 'C1', message_ts = '111.222',
			delivered_as = 'root', delivered_at = ? WHERE id = ?
	`, time.Now().UTC().Format(time.RFC3339Nano), row.id); err != nil {
		t.Fatalf("expected a lifecycle status update to succeed: %v", err)
	}
}

// TestSituationNotificationSchema_IdentityImmutable proves an intent's
// identity columns (effect class, subject references, poke/priority,
// deadline, client message id, created_at) can never change post-insert,
// while status/claim/retry/delivery columns can.
func TestSituationNotificationSchema_IdentityImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-immut", "group-ni-immut", "tr-ni-immut")

	row := legalRootSyncIntent("ni-immut", "sit-ni-immut", "tr-ni-immut", 1, 1)
	if err := insertNotificationIntent(ctx, s, row); err != nil {
		t.Fatalf("insert intent: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET effect_class = 'thread_append' WHERE id = ?`, row.id); err == nil {
		t.Fatal("expected changing effect_class to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_intents SET idempotency_key = 'changed' WHERE id = ?`, row.id); err == nil {
		t.Fatal("expected changing idempotency_key to be rejected")
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET claim_owner = 'worker-1', lease_expires_at = ?, status = 'pending' WHERE id = ?
	`, time.Now().UTC().Format(time.RFC3339Nano), row.id); err != nil {
		t.Fatalf("expected claiming (a lifecycle field) to succeed: %v", err)
	}
}

// TestSituationNotificationSchema_ForeignKeyShape proves a notification
// intent must reference a real Situation, Transition, and (for
// installation_gap_recovery) gap generation.
func TestSituationNotificationSchema_ForeignKeyShape(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNotificationIntentFixture(ctx, t, s, "sit-ni-fk", "group-ni-fk", "tr-ni-fk")

	badSituation := legalRootSyncIntent("ni-fk-bad-situation", "does-not-exist", "tr-ni-fk", 1, 1)
	if err := insertNotificationIntent(ctx, s, badSituation); err == nil {
		t.Fatal("expected a nonexistent situation_id to be rejected")
	}

	badTransition := legalRootSyncIntent("ni-fk-bad-transition", "sit-ni-fk", "does-not-exist", 1, 1)
	if err := insertNotificationIntent(ctx, s, badTransition); err == nil {
		t.Fatal("expected a nonexistent transition_id to be rejected")
	}

	mismatchedSequence := legalRootSyncIntent("ni-fk-mismatch-seq", "sit-ni-fk", "tr-ni-fk", 99, 1)
	if err := insertNotificationIntent(ctx, s, mismatchedSequence); err == nil {
		t.Fatal("expected a transition_sequence not matching the referenced transition's actual sequence to be rejected")
	}

	badGap := notificationIntentRow{
		id: "ni-fk-bad-gap", idempotencyKey: "idem-ni-fk-bad-gap", effectClass: "installation_gap_recovery",
		gapGeneration: "does-not-exist", requiresRoot: 0, mainChannelPoke: 0,
	}
	if err := insertNotificationIntent(ctx, s, badGap); err == nil {
		t.Fatal("expected a nonexistent gap_generation to be rejected")
	}
}

// ----------------------------------------------------------------------
// Step 3: slack_delivery_state and slack_delivery_gaps.
// ----------------------------------------------------------------------

// insertGapGeneration seeds a minimal slack_delivery_gaps row in the given
// status and returns nothing (id is caller-supplied so FK tests can target
// it deterministically).
func insertGapGeneration(ctx context.Context, s *Store, id, status string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var recoveredAt, completedAt any
	if status == "replaying" || status == "complete" {
		recoveredAt = now
	}
	if status == "complete" {
		completedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO slack_delivery_gaps (id, status, opened_at, recovered_at, completed_at)
		VALUES (?, ?, ?, ?, ?)
	`, id, status, now, recoveredAt, completedAt)
	return err
}

// TestSlackDeliveryGapSchema_SingletonState proves slack_delivery_state
// seeds exactly one row at id=1 and rejects a second.
func TestSlackDeliveryGapSchema_SingletonState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM slack_delivery_state`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("slack_delivery_state count = %d, want 1 (seeded singleton)", count)
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO slack_delivery_state (id, configuration_generation, updated_at) VALUES (2, 0, ?)
	`, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("expected a second slack_delivery_state row (id != 1) to be rejected")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state SET first_failure_at = ?, last_warning_at = ?, updated_at = ? WHERE id = 1
	`, now, now, now); err != nil {
		t.Fatalf("expected updating the singleton to succeed: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM slack_delivery_state WHERE id = 1`); err == nil {
		t.Fatal("expected deleting the singleton to be rejected")
	}
}

// TestSlackDeliveryGapSchema_StatusesAndFields proves the closed
// open|replaying|complete status set and the fields each carries.
func TestSlackDeliveryGapSchema_StatusesAndFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := insertGapGeneration(ctx, s, "gap-fields-bad", "bogus"); err == nil {
		t.Fatal("expected an unknown gap status to be rejected")
	}

	if err := insertGapGeneration(ctx, s, "gap-fields-open", "open"); err != nil {
		t.Fatalf("expected an open gap to be accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_gaps SET affected_situation_count = 3, delayed_effect_count = 5 WHERE id = 'gap-fields-open'
	`); err != nil {
		t.Fatalf("expected setting affected/delayed counts to succeed: %v", err)
	}

	if err := insertGapGeneration(ctx, s, "gap-fields-replaying", "replaying"); err != nil {
		t.Fatalf("expected a replaying gap (recovered_at set) to be accepted: %v", err)
	}

	if err := insertGapGeneration(ctx, s, "gap-fields-complete", "complete"); err != nil {
		t.Fatalf("expected a complete gap (recovered_at and completed_at set) to be accepted: %v", err)
	}
}

// TestSlackDeliveryGapSchema_OpenGapCannotClaimCompleteGeneration proves
// slack_delivery_state.open_gap_generation can never point at an
// already-complete generation.
func TestSlackDeliveryGapSchema_OpenGapCannotClaimCompleteGeneration(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := insertGapGeneration(ctx, s, "gap-claim-complete", "complete"); err != nil {
		t.Fatalf("seed complete gap: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = 'gap-claim-complete', updated_at = ? WHERE id = 1
	`, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("expected claiming a complete generation as open to be rejected")
	}

	if err := insertGapGeneration(ctx, s, "gap-claim-open", "open"); err != nil {
		t.Fatalf("seed open gap: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = 'gap-claim-open', updated_at = ? WHERE id = 1
	`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("expected claiming an open generation to succeed: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = ?, updated_at = ? WHERE id = 1
	`, nil, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("expected clearing open_gap_generation to succeed: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = ?, updated_at = ? WHERE id = 1
	`, "does-not-exist", time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("expected claiming a nonexistent generation to be rejected")
	}
}

// TestSlackDeliveryGapSchema_NoDelete proves slack_delivery_gaps rows are
// never deleted, and identity (id, opened_at) never changes post-insert.
func TestSlackDeliveryGapSchema_NoDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := insertGapGeneration(ctx, s, "gap-nodelete", "open"); err != nil {
		t.Fatalf("seed gap: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM slack_delivery_gaps WHERE id = 'gap-nodelete'`); err == nil {
		t.Fatal("expected deleting a gap generation to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE slack_delivery_gaps SET id = 'renamed' WHERE id = 'gap-nodelete'`); err == nil {
		t.Fatal("expected changing a gap generation's id to be rejected")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_gaps SET status = 'replaying', recovered_at = ? WHERE id = 'gap-nodelete'
	`, now); err != nil {
		t.Fatalf("expected the ordinary open->replaying lifecycle update to succeed: %v", err)
	}
}
