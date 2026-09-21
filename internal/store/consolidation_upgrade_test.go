// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

// The operator and evidence branches both allocated migrations after 21.
// An existing operator database must keep its notification history while
// acquiring the evidence schema, including after reopening the migrated file.
func TestConsolidationPreservesPopulatedOperatorDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "operator-upgrade.db")
	deliveryID, situationID := seedMigration22SemanticProfilesFixture(t, path)
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &Store{db: db}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fixture.appliedVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version > 22 && m.version <= 26 && !applied[m.version] {
			if err := fixture.applyMigration(ctx, m); err != nil {
				t.Fatalf("operator migration %d: %v", m.version, err)
			}
		}
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE situations SET slack_channel='C-existing', slack_root_ts='123.456' WHERE id=?`, situationID)
	for _, status := range []string{"blocked_configuration", "withheld_by_operator_slack_floor"} {
		exec(`INSERT INTO notification_intents (
			id,idempotency_key,effect_class,situation_id,transition_id,transition_sequence,
			summary_version,requires_root,main_channel_poke,interruption_priority,
			client_message_id,status,created_at)
			VALUES (?,?,'root_sync',?,'pre-upgrade-transition',1,1,0,1,'high',?,?,?)`,
			status, "idem:"+status, situationID, "client:"+status, status, canonicalTime(time.Now().UTC()))
	}
	exec(`INSERT INTO notification_intents (
		id,idempotency_key,effect_class,situation_id,transition_id,transition_sequence,
		requires_root,main_channel_poke,client_message_id,status,reply_kind,created_at)
		VALUES ('analysis-reply','idem:analysis','thread_append',?,'pre-upgrade-transition',1,
		1,0,'client:analysis','pending','analysis_completed',?)`, situationID, canonicalTime(time.Now().UTC()))
	exec(`UPDATE llm_health SET state='unavailable',reason_code='transport',outage_generation=3,
		slack_channel='C-health',slack_ts='123.789',slack_delivery='delivered',slack_generation=3`)
	exec(`INSERT INTO llm_health_capabilities(capability,healthy,reason_code,content_subjects,updated_at)
		VALUES ('triage_draft',0,'content','["incident-one","incident-two"]',?)`, canonicalTime(time.Now().UTC()))
	queries := []string{
		`SELECT id,alert_id,source,source_event_id,source_episode_key,status,labels_json,annotations_json,
			starts_at,ends_at,source_started_at,source_resolved_at,started_at_basis,resolved_at_basis,
			receiver_grouping_identity,payload_digest,source_signal_id,source_signal_version,generator_url,
			acquisition_mode,poll_interval_seconds,received_at FROM alert_deliveries ORDER BY id`,
		`SELECT * FROM situation_transitions ORDER BY id`,
		`SELECT * FROM notification_intents ORDER BY id`,
		`SELECT id,lifecycle,slack_channel,slack_root_ts FROM situations ORDER BY id`,
		`SELECT * FROM llm_health ORDER BY id`,
		`SELECT * FROM llm_health_capabilities ORDER BY capability`,
		`SELECT * FROM audit_log ORDER BY seq`,
	}
	before := make([]string, len(queries))
	for i, query := range queries {
		before[i] = consolidationRows(t, db, query)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		st, err := openTestStoreWithMigrations(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		for i, query := range queries {
			if after := consolidationRows(t, st.db, query); after != before[i] {
				t.Errorf("reopen %d changed %s\nbefore: %s\nafter: %s", attempt, query, before[i], after)
			}
		}
		var violations int
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil || violations != 0 {
			t.Fatalf("foreign keys: %d, %v", violations, err)
		}
		report, err := audit.New(st.db).Verify(ctx)
		if err != nil || !report.OK || report.RowsChecked != 1 {
			t.Fatalf("audit: %+v, %v", report, err)
		}
		if _, err := st.db.ExecContext(ctx, `SELECT id FROM situation_observation_runs LIMIT 1`); err != nil {
			t.Fatalf("missing evidence schema: %v", err)
		}
		if attempt == 1 {
			n, err := st.BackfillActiveSemanticMappings(ctx, time.Now().UTC(), 100)
			if err != nil || n != 1 {
				t.Fatalf("resumed backfill: %d, %v", n, err)
			}
			var mode string
			if err := st.db.QueryRowContext(ctx, `SELECT mode FROM delivery_semantic_signatures WHERE delivery_id=?`, deliveryID).Scan(&mode); err != nil || mode != "signal_version" {
				t.Fatalf("source identity backfill: %q, %v", mode, err)
			}
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func consolidationRows(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		result = append(result, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
