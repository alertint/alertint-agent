// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
)

// ----------------------------------------------------------------------
// Migration 0023 upgrade test: a populated migration-21 database (the
// schema as it existed before Plan 4) must upgrade through 0022/0023
// without disturbing existing deliveries, source identity, the
// notification queue, foreign keys, or the audit hash chain — plan.md
// Task 7: "Populate the full migration-21 fixture, migrate through 23,
// verify old rows, source identity, notification queue state, foreign
// keys and audit chain."
// ----------------------------------------------------------------------

func seedMigration21SemanticProfilesFixture(t *testing.T, path string) (deliveryID, situationID string) {
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
		if m.version > 21 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	sigID, sigVersion := "item:pre-upgrade", "v1"
	delivered, err := fixture.AcceptDeliveries(ctx, []DeliveryInput{{
		ID: "pre-upgrade-delivery",
		Alert: Alert{
			ID: uuid.NewString(), Fingerprint: "pre-upgrade-fp", Status: "firing",
			Labels: map[string]string{"alertname": "PreUpgrade"}, Annotations: map[string]string{},
			StartsAt: now, ReceivedAt: now,
		},
		Source:                   "zabbix",
		SourceEpisodeKey:         "zabbix:pre-upgrade:" + now.Format(time.RFC3339Nano),
		StartedAtBasis:           "source_payload",
		ResolvedAtBasis:          "missing",
		ReceiverGroupingIdentity: "group:pre-upgrade",
		PayloadDigest:            "sha256:pre-upgrade",
		SourceProvenance: SourceProvenance{
			SignalID: &sigID, SignalVersion: &sigVersion, AcquisitionMode: SourceAcquisitionWebhook,
		},
	}})
	if err != nil {
		t.Fatalf("seed pre-upgrade delivery: %v", err)
	}
	deliveryID = delivered[0].ID

	if err := fixture.InsertIncident(ctx, Incident{
		ID: "pre-upgrade-incident", GroupKey: "pre-upgrade-group",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}); err != nil {
		t.Fatalf("seed pre-upgrade incident: %v", err)
	}
	situationID = "pre-upgrade-situation"
	if err := insertSituation(ctx, fixture, situationRow{
		id: situationID, groupKey: "pre-upgrade-group", lifecycle: "active",
	}); err != nil {
		t.Fatalf("seed pre-upgrade situation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)`,
		situationID, "pre-upgrade-incident", canonicalTime(now)); err != nil {
		t.Fatalf("attach pre-upgrade incident to situation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		"pre-upgrade-incident", deliveryID, canonicalTime(now)); err != nil {
		t.Fatalf("attach pre-upgrade delivery to incident: %v", err)
	}

	transitionID := "pre-upgrade-transition"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, 1, 1, 'sha256:pre-upgrade', 'active', 'observe',
		          '{}', 'first_authoritative_state', 'publication', '{}', '{}', '[]',
		          'deterministic_controller', ?)`,
		transitionID, situationID, canonicalTime(now)); err != nil {
		t.Fatalf("seed pre-upgrade transition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence, summary_version,
			requires_root, main_channel_poke, client_message_id, status, created_at
		) VALUES ('pre-upgrade-intent', 'idem:pre-upgrade-intent', 'root_sync', ?, ?, 1, 1, 0, 0,
		          'client:pre-upgrade-intent', 'pending', ?)`,
		situationID, transitionID, canonicalTime(now)); err != nil {
		t.Fatalf("seed pre-upgrade notification intent: %v", err)
	}

	if err := audit.New(db).Append(ctx, "test:fixture", "pre_upgrade_event", map[string]string{"situation_id": situationID}); err != nil {
		t.Fatalf("seed pre-upgrade audit row: %v", err)
	}

	return deliveryID, situationID
}

func TestSemanticProfilesUpgradeMigration21Database(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upgrade-23.db")
	deliveryID, situationID := seedMigration21SemanticProfilesFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open (apply migrations 0022/0023): %v", err)
	}
	defer func() { _ = st.Close() }()

	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 23 {
		t.Fatalf("MaxSchemaVersion = %d, want 23", got)
	}
	var version int
	if err := st.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 23 {
		t.Fatalf("applied schema version = %d (err=%v), want 23", version, err)
	}
	var fkViolations int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&fkViolations); err != nil || fkViolations != 0 {
		t.Fatalf("foreign_key_check violations = %d (err=%v), want 0", fkViolations, err)
	}

	// Source identity survives untouched.
	var source string
	var signalID, signalVersion sql.NullString
	if err := st.db.QueryRowContext(ctx, `
		SELECT source, source_signal_id, source_signal_version FROM alert_deliveries WHERE id = ?`, deliveryID).
		Scan(&source, &signalID, &signalVersion); err != nil {
		t.Fatalf("read pre-upgrade delivery: %v", err)
	}
	if source != "zabbix" || !signalID.Valid || signalID.String != "item:pre-upgrade" || !signalVersion.Valid || signalVersion.String != "v1" {
		t.Fatalf("source identity after upgrade = %q/%v/%v, want zabbix/item:pre-upgrade/v1", source, signalID, signalVersion)
	}

	// Notification queue state survives.
	var intentStatus string
	if err := st.db.QueryRowContext(ctx, `SELECT status FROM notification_intents WHERE id = 'pre-upgrade-intent'`).Scan(&intentStatus); err != nil {
		t.Fatalf("read pre-upgrade notification intent: %v", err)
	}
	if intentStatus != "pending" {
		t.Fatalf("notification intent status after upgrade = %q, want pending", intentStatus)
	}

	// The audit hash chain still verifies.
	report, err := audit.New(st.db).Verify(ctx)
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !report.OK || report.RowsChecked != 1 {
		t.Fatalf("audit verify = %+v, want OK with 1 row", report)
	}

	// Task 7's new tables exist and start genuinely empty — nothing
	// fabricated for a pre-existing delivery/situation the upgrade never
	// touches (ApplySituationInput's own signature attach only runs for a
	// FRESH input, never retroactively for rows that predate it).
	for _, table := range []string{
		"delivery_semantic_signatures", "semantic_profile_versions", "semantic_profile_heads",
		"semantic_profile_inference_jobs", "semantic_profile_calls", "semantic_profile_call_outcomes",
		"semantic_profile_changes", "semantic_profile_change_deliveries",
	} {
		var n int
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Fatalf("%s after upgrade = %d, want 0 (nothing fabricated)", table, n)
		}
	}

	// A fresh backfill against the upgraded database still works end to
	// end for the pre-existing active Situation's member delivery.
	n, err := st.BackfillActiveSemanticMappings(ctx, time.Now().UTC(), 100)
	if err != nil {
		t.Fatalf("BackfillActiveSemanticMappings after upgrade: %v", err)
	}
	if n != 1 {
		t.Fatalf("backfilled = %d, want 1", n)
	}
	var mode string
	if err := st.db.QueryRowContext(ctx, `SELECT mode FROM delivery_semantic_signatures WHERE delivery_id = ?`, deliveryID).Scan(&mode); err != nil {
		t.Fatalf("read backfilled signature: %v", err)
	}
	if mode != "signal_version" {
		t.Fatalf("backfilled signature mode = %q, want signal_version", mode)
	}

	var lifecycle string
	if err := st.db.QueryRowContext(ctx, `SELECT lifecycle FROM situations WHERE id = ?`, situationID).Scan(&lifecycle); err != nil {
		t.Fatalf("read pre-upgrade situation: %v", err)
	}
	if lifecycle != "active" {
		t.Fatalf("pre-upgrade situation lifecycle = %q, want active", lifecycle)
	}
}
