// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// readyIncident inserts an incident and transitions it to "ready" so
// SaveIncidentOutput (which requires ready/processing) accepts it.
func readyIncident(t *testing.T, s *Store, groupKey string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	id := uuid.NewString()
	if err := s.InsertIncident(ctx, Incident{
		ID:           id,
		GroupKey:     groupKey,
		FirstAlertAt: now,
		LastAlertAt:  now,
		ReadyAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	return id
}

func TestSaveIncidentOutput_EnrichmentRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "test=enrich")

	enrichment := `{"source":"loki","query":"{namespace=\"prod\",app=\"api\"}","lines":[{"timestamp":"2026-06-17T14:03:11Z","line":"ERROR boom"}]}`
	if err := s.SaveIncidentOutput(ctx, id, `{"ok":true}`, "name", "issue", 0.7, enrichment); err != nil {
		t.Fatalf("SaveIncidentOutput: %v", err)
	}

	inc, err := s.GetIncidentByID(ctx, id)
	if err != nil {
		t.Fatalf("GetIncidentByID: %v", err)
	}
	if inc == nil {
		t.Fatal("incident not found")
	}
	if inc.EnrichmentJSON != enrichment {
		t.Fatalf("enrichment_json round-trip mismatch:\n got: %s\nwant: %s", inc.EnrichmentJSON, enrichment)
	}
}

func TestSaveIncidentOutput_NoteOnlyEnrichmentRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "test=note")

	// A queried-but-empty enrichment: no lines, just a note + provenance.
	noteOnly := `{"source":"loki","query":"{namespace=\"prod\",app=\"api\"}","note":"log backend returned no lines for this query"}`
	if err := s.SaveIncidentOutput(ctx, id, `{"ok":true}`, "n", "i", 0.5, noteOnly); err != nil {
		t.Fatalf("SaveIncidentOutput: %v", err)
	}

	inc, err := s.GetIncidentByID(ctx, id)
	if err != nil {
		t.Fatalf("GetIncidentByID: %v", err)
	}
	if inc.EnrichmentJSON != noteOnly {
		t.Fatalf("note-only enrichment did not round-trip:\n got: %s\nwant: %s", inc.EnrichmentJSON, noteOnly)
	}
}

func TestSaveIncidentOutput_EmptyEnrichmentPersistsNull(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "test=null")

	// Logs disabled / short-circuit path: empty string => SQL NULL.
	if err := s.SaveIncidentOutput(ctx, id, `{"ok":true}`, "n", "i", 0.5, ""); err != nil {
		t.Fatalf("SaveIncidentOutput: %v", err)
	}

	var raw any
	if err := s.db.QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if raw != nil {
		t.Fatalf("enrichment_json = %v, want NULL", raw)
	}

	// And it surfaces as "" via the COALESCE'd accessor.
	inc, err := s.GetIncidentByID(ctx, id)
	if err != nil {
		t.Fatalf("GetIncidentByID: %v", err)
	}
	if inc.EnrichmentJSON != "" {
		t.Fatalf("EnrichmentJSON = %q, want empty", inc.EnrichmentJSON)
	}
}

func TestMigration0006_WrapsLegacyBareRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Seed an incident, then force a legacy bare-LogEnrichment enrichment_json.
	id := readyIncident(t, s, "test=mig6")
	if _, err := s.db.ExecContext(ctx, `UPDATE incidents SET enrichment_json=? WHERE id=?`,
		`{"source":"loki","query":"{app=\"x\"}","lines":[]}`, id); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	// Apply the guarded wrap (MUST be kept identical to 0006_enrichment_envelope.sql).
	if _, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET enrichment_json = '{"logs":' || enrichment_json || '}'
		WHERE enrichment_json IS NOT NULL AND json_valid(enrichment_json)
		  AND json_extract(enrichment_json,'$.source') IS NOT NULL
		  AND json_extract(enrichment_json,'$.logs') IS NULL
		  AND json_extract(enrichment_json,'$.changes') IS NULL
	`); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got string
	_ = s.db.QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id=?`, id).Scan(&got)
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := env["logs"]; !ok {
		t.Fatalf("want logs envelope, got %s", got)
	}
	// Idempotent: re-running must NOT double-wrap.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET enrichment_json = '{"logs":' || enrichment_json || '}'
		WHERE json_valid(enrichment_json)
		  AND json_extract(enrichment_json,'$.source') IS NOT NULL
		  AND json_extract(enrichment_json,'$.logs') IS NULL
		  AND json_extract(enrichment_json,'$.changes') IS NULL`); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	_ = s.db.QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id=?`, id).Scan(&got)
	if strings.Count(got, `"logs"`) != 1 {
		t.Fatalf("double-wrapped: %s", got)
	}
}

func TestMigration0004_AppliesOverPriorSchema(t *testing.T) {
	// Open runs all embedded migrations, including 0004 over 0003. Assert the
	// migration version is recorded and the column is writable.
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	var found bool
	for _, m := range ms {
		if m.version == 4 && m.name == "incidents_enrichment" {
			found = true
		}
	}
	if !found {
		t.Fatal("migration 0004_incidents_enrichment not discovered")
	}

	s := newTestStore(t)
	ctx := context.Background()
	var applied bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=4)`,
	).Scan(&applied); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if !applied {
		t.Fatal("migration 0004 not recorded in schema_migrations")
	}
	// Column exists and accepts a write.
	id := readyIncident(t, s, "test=col")
	if err := s.SaveIncidentOutput(ctx, id, `{}`, "n", "i", 0.1, `{"source":"loki"}`); err != nil {
		t.Fatalf("write enrichment column: %v", err)
	}
}
