// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// migration12Fixture builds a file-backed database with only migrations
// 1-12 applied (the schema as it existed before this slice's 0013/0014),
// seeds one Alert and one operational Incident, and returns the file path
// so a caller can reopen it with the current Open and observe the
// upgrade to 13/14 land cleanly on top of pre-existing data.
func migration12Fixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "migration12.db")

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range all {
		if m.version > 12 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	if _, err := fixture.UpsertAlertByFingerprint(ctx, Alert{
		ID:          uuid.NewString(),
		Fingerprint: "pre-upgrade-fp",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "PreUpgrade"},
		Annotations: map[string]string{},
		StartsAt:    now,
		ReceivedAt:  now,
	}); err != nil {
		t.Fatalf("seed pre-upgrade alert: %v", err)
	}
	if err := fixture.InsertIncident(ctx, Incident{
		ID:           "pre-upgrade-incident",
		GroupKey:     "pre-upgrade-group",
		FirstAlertAt: now,
		LastAlertAt:  now,
		ReadyAt:      now,
	}); err != nil {
		t.Fatalf("seed pre-upgrade incident: %v", err)
	}

	return path
}

// TestSituationFoundationUpgradesMigration12Database is the brief's upgrade
// test: opening a migration-12 database with the current Open must apply
// 0013 and 0014 without disturbing rows that predate them.
func TestSituationFoundationUpgradesMigration12Database(t *testing.T) {
	ctx := context.Background()
	path := migration12Fixture(t)
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	var versions int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version IN (13,14)`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("new migration count = %d, want 2", versions)
	}

	var incidents int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM incidents WHERE id='pre-upgrade-incident'`).Scan(&incidents); err != nil {
		t.Fatal(err)
	}
	if incidents != 1 {
		t.Fatalf("pre-upgrade incident count = %d", incidents)
	}
}

// ----------------------------------------------------------------------
// Direct constraint tests for migrations 0013/0014.
// ----------------------------------------------------------------------

// insertOperationalIncident inserts an incident row (status='collecting')
// purely as an FK anchor for the tests below; each caller must use a
// distinct groupKey since 0013 enforces one collecting incident per group.
func insertOperationalIncident(ctx context.Context, t *testing.T, s *Store, id, groupKey string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.InsertIncident(ctx, Incident{
		ID: id, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}); err != nil {
		t.Fatalf("insert operational incident %s: %v", id, err)
	}
}

// seedAlert inserts a minimal alert and returns its canonical id, for use
// as the alert_id FK anchor on alert_deliveries rows.
func seedAlert(ctx context.Context, t *testing.T, s *Store, fingerprint string) string {
	t.Helper()
	now := time.Now().UTC()
	a, err := s.UpsertAlertByFingerprint(ctx, Alert{
		ID: uuid.NewString(), Fingerprint: fingerprint, Status: "firing",
		Labels: map[string]string{"alertname": "seed"}, Annotations: map[string]string{},
		StartsAt: now, ReceivedAt: now,
	})
	if err != nil {
		t.Fatalf("seed alert %s: %v", fingerprint, err)
	}
	return a.ID
}

// situationRow is a minimal, overridable set of columns for inserting a
// row into situations directly (bypassing any Go-level helper, since none
// exists yet — this migration only adds schema). Fields left as nil use
// SQL NULL; every situationRow satisfies the table's baseline NOT NULL /
// CHECK constraints for whichever lifecycle is supplied, as long as the
// lifecycle-specific terminal/recovery fields are set by the caller.
type situationRow struct {
	id                 string
	groupKey           string
	publicHandle       any
	lifecycle          string
	recoveryObservedAt any
	graceUntil         any
	terminalAt         any
	terminalReason     any
}

func insertSituation(ctx context.Context, s *Store, r situationRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situations (
			id, group_key, public_handle, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis,
			first_received_at, last_lifecycle_observed_at,
			recovery_observed_at, grace_until, terminal_at, terminal_reason,
			next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'observe', 1, ?, ?, 'source_payload', ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)
	`,
		r.id, r.groupKey, r.publicHandle, r.lifecycle,
		now, now, now, now,
		r.recoveryObservedAt, r.graceUntil, r.terminalAt, r.terminalReason,
		now, now, now,
	)
	return err
}

// deliveryRow is a minimal, overridable set of columns for inserting a row
// into alert_deliveries directly.
type deliveryRow struct {
	id                  string
	alertID             string
	sourceSignalID      any
	sourceSignalVersion any
}

func insertAlertDelivery(ctx context.Context, s *Store, r deliveryRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			id, alert_id, source, source_episode_key, status,
			labels_json, annotations_json, starts_at,
			started_at_basis, resolved_at_basis,
			receiver_grouping_identity, payload_digest,
			source_signal_id, source_signal_version,
			acquisition_mode, poll_interval_seconds, received_at
		) VALUES (?, ?, 'alertmanager', ?, 'firing', '{}', '{}', ?, 'source_payload', 'missing', ?, ?, ?, ?, 'webhook', 0, ?)
	`,
		r.id, r.alertID, r.id+"-episode", now,
		r.id+"-identity", r.id+"-digest",
		r.sourceSignalID, r.sourceSignalVersion,
		now,
	)
	return err
}

// TestSituationFoundation_SecondNonterminalSituationSharesGroupKeyFails proves
// situations_one_nonterminal_group_idx: at most one active/recovery_pending
// Situation may exist per group_key, but a terminal one does not collide.
func TestSituationFoundation_SecondNonterminalSituationSharesGroupKeyFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := insertSituation(ctx, s, situationRow{id: "sit-1", groupKey: "group-a", lifecycle: "active"}); err != nil {
		t.Fatalf("insert first nonterminal situation: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-2", groupKey: "group-a", lifecycle: "active"}); err == nil {
		t.Fatal("expected unique-index violation for a second nonterminal situation sharing group_key")
	}

	term := time.Now().UTC().Format(time.RFC3339Nano)
	if err := insertSituation(ctx, s, situationRow{
		id: "sit-3", groupKey: "group-a", lifecycle: "closed_unknown",
		terminalAt: term, terminalReason: "resolution_missing",
	}); err != nil {
		t.Fatalf("expected terminal situation for the same group_key to succeed: %v", err)
	}
}

// TestSituationFoundation_TwoSituationsCannotOwnSameIncident proves the
// UNIQUE constraint on situation_incidents.incident_id.
func TestSituationFoundation_TwoSituationsCannotOwnSameIncident(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertOperationalIncident(ctx, t, s, "inc-shared", "group-shared")
	if err := insertSituation(ctx, s, situationRow{id: "sit-a", groupKey: "group-shared", lifecycle: "active"}); err != nil {
		t.Fatalf("insert sit-a: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-b", groupKey: "group-b", lifecycle: "active"}); err != nil {
		t.Fatalf("insert sit-b: %v", err)
	}

	attach := func(situationID string) error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)
		`, situationID, "inc-shared", now.Format(time.RFC3339Nano))
		return err
	}
	if err := attach("sit-a"); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if err := attach("sit-b"); err == nil {
		t.Fatal("expected unique violation: incident already owned by sit-a")
	}
}

// TestSituationFoundation_TerminalFieldsAreImmutable proves the
// situations_terminal_immutable and situations_legal_lifecycle_update
// triggers reject any attempt to change a terminal Situation's lifecycle
// or terminal fields once set.
func TestSituationFoundation_TerminalFieldsAreImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	term := time.Now().UTC().Format(time.RFC3339Nano)

	if err := insertSituation(ctx, s, situationRow{
		id: "sit-term", groupKey: "group-term", lifecycle: "closed_unknown",
		terminalAt: term, terminalReason: "resolution_missing",
	}); err != nil {
		t.Fatalf("insert terminal situation: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE situations SET terminal_reason = 'budget_exhausted' WHERE id = 'sit-term'
	`); err == nil {
		t.Fatal("expected terminal_reason change on a terminal situation to be rejected")
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE situations
		SET lifecycle = 'active', terminal_at = NULL, terminal_reason = NULL
		WHERE id = 'sit-term'
	`); err == nil {
		t.Fatal("expected reopening a terminal situation's lifecycle to be rejected")
	}

	var reason string
	if err := s.db.QueryRowContext(ctx, `SELECT terminal_reason FROM situations WHERE id = 'sit-term'`).Scan(&reason); err != nil {
		t.Fatalf("read back terminal_reason: %v", err)
	}
	if reason != "resolution_missing" {
		t.Fatalf("terminal_reason = %q after rejected updates, want unchanged %q", reason, "resolution_missing")
	}
}

// TestSituationFoundation_AppliedInputOutboxRequiresSituationAndAppliedAt
// proves the CHECK pairing status='applied' with both
// applied_situation_id and applied_at being set.
func TestSituationFoundation_AppliedInputOutboxRequiresSituationAndAppliedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertOperationalIncident(ctx, t, s, "inc-outbox", "group-outbox")
	if err := insertSituation(ctx, s, situationRow{id: "sit-outbox", groupKey: "group-outbox-owner", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	insert := func(id string, appliedSituationID, appliedAt any) error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO situation_input_outbox (
				id, idempotency_key, incident_id, kind, group_key, occurred_at,
				status, applied_situation_id, applied_at
			) VALUES (?, ?, 'inc-outbox', 'incident_created', 'group-outbox', ?, 'applied', ?, ?)
		`, id, id+"-idem", now.Format(time.RFC3339Nano), appliedSituationID, appliedAt)
		return err
	}

	nowStr := now.Format(time.RFC3339Nano)
	if err := insert("in-1", nil, nowStr); err == nil {
		t.Fatal("expected failure: applied without applied_situation_id")
	}
	if err := insert("in-2", "sit-outbox", nil); err == nil {
		t.Fatal("expected failure: applied without applied_at")
	}
	if err := insert("in-3", "sit-outbox", nowStr); err != nil {
		t.Fatalf("expected success with both applied fields set: %v", err)
	}
}

// TestSituationFoundation_ClaimedDispatchRequiresOwnerAndExpiry proves the
// CHECK pairing status='claimed' with both lease_owner and
// lease_expires_at being set on alert_delivery_dispatches.
func TestSituationFoundation_ClaimedDispatchRequiresOwnerAndExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	alertID := seedAlert(ctx, t, s, "fp-claimed-dispatch")
	for _, id := range []string{"delivery-owner-only", "delivery-expiry-only", "delivery-both"} {
		if err := insertAlertDelivery(ctx, s, deliveryRow{id: id, alertID: alertID}); err != nil {
			t.Fatalf("seed delivery %s: %v", id, err)
		}
	}

	claim := func(deliveryID string, owner, expiresAt any) error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO alert_delivery_dispatches (delivery_id, status, lease_owner, lease_expires_at)
			VALUES (?, 'claimed', ?, ?)
		`, deliveryID, owner, expiresAt)
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := claim("delivery-owner-only", "worker-1", nil); err == nil {
		t.Fatal("expected failure: claimed with owner but no expiry")
	}
	if err := claim("delivery-expiry-only", nil, now); err == nil {
		t.Fatal("expected failure: claimed with expiry but no owner")
	}
	if err := claim("delivery-both", "worker-1", now); err != nil {
		t.Fatalf("expected success with both owner and expiry set: %v", err)
	}
}

// TestSituationFoundation_ClaimedInputOutboxRequiresOwnerAndExpiry proves
// the same claimed-lease CHECK on situation_input_outbox.
func TestSituationFoundation_ClaimedInputOutboxRequiresOwnerAndExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertOperationalIncident(ctx, t, s, "inc-claim", "group-claim")

	claim := func(id string, owner, expiresAt any) error {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO situation_input_outbox (
				id, idempotency_key, incident_id, kind, group_key, occurred_at,
				status, lease_owner, lease_expires_at
			) VALUES (?, ?, 'inc-claim', 'incident_created', 'group-claim', ?, 'claimed', ?, ?)
		`, id, id+"-idem", now.Format(time.RFC3339Nano), owner, expiresAt)
		return err
	}

	expiresAt := now.Add(time.Minute).Format(time.RFC3339Nano)
	if err := claim("in-owner-only", "worker-1", nil); err == nil {
		t.Fatal("expected failure: claimed with owner but no expiry")
	}
	if err := claim("in-expiry-only", nil, expiresAt); err == nil {
		t.Fatal("expected failure: claimed with expiry but no owner")
	}
	if err := claim("in-both", "worker-1", expiresAt); err != nil {
		t.Fatalf("expected success with both owner and expiry set: %v", err)
	}
}

// TestSituationFoundation_SignalIdentityAndVersionConstraint proves
// alert_deliveries' identity/version pairing: both may be null, identity
// may stand alone, but version without identity is rejected.
func TestSituationFoundation_SignalIdentityAndVersionConstraint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	alertID := seedAlert(ctx, t, s, "fp-signal")

	if err := insertAlertDelivery(ctx, s, deliveryRow{id: "delivery-both-null", alertID: alertID}); err != nil {
		t.Fatalf("expected both signal id and version null to be valid: %v", err)
	}
	if err := insertAlertDelivery(ctx, s, deliveryRow{id: "delivery-id-only", alertID: alertID, sourceSignalID: "sig-1"}); err != nil {
		t.Fatalf("expected identity without version to be valid: %v", err)
	}
	if err := insertAlertDelivery(ctx, s, deliveryRow{id: "delivery-version-only", alertID: alertID, sourceSignalVersion: "v1"}); err == nil {
		t.Fatal("expected failure: version without identity")
	}
}

// TestSituationFoundation_SituationIncidentsAreImmutable proves the
// situation_incidents_no_update / situation_incidents_no_delete triggers
// reject any mutation of an attached membership row.
func TestSituationFoundation_SituationIncidentsAreImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertOperationalIncident(ctx, t, s, "inc-immutable", "group-immutable")
	if err := insertSituation(ctx, s, situationRow{id: "sit-immutable", groupKey: "group-immutable-owner", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)
	`, "sit-immutable", "inc-immutable", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE situation_incidents SET attached_at = ? WHERE situation_id = 'sit-immutable'
	`, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("expected update of situation_incidents to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM situation_incidents WHERE situation_id = 'sit-immutable'
	`); err == nil {
		t.Fatal("expected delete of situation_incidents to be rejected")
	}
}
