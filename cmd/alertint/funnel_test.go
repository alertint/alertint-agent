// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestRunFunnel_RequiresSinceAndUntil(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)

	var stdout, stderr bytes.Buffer
	err := run([]string{"funnel", "--db", dbPath}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--since and --until are required") {
		t.Fatalf("err = %v, want a since/until requirement error", err)
	}
}

func TestRunFunnel_RequiresDBOrConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"funnel", "--since", "2026-08-01T00:00:00Z", "--until", "2026-09-01T00:00:00Z"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "either --config or --db is required") {
		t.Fatalf("err = %v, want flag-requirement error", err)
	}
}

func TestRunFunnel_RejectsInvalidTime(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)

	var stdout, stderr bytes.Buffer
	err := run([]string{"funnel", "--db", dbPath, "--since", "not-a-time", "--until", "2026-09-01T00:00:00Z"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "invalid --since") {
		t.Fatalf("err = %v, want an invalid --since error", err)
	}
}

func TestRunFunnel_ReportsAcceptedDeliveries(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "alertint-agent.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := st.DB().Exec(`INSERT INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, received_at)
		VALUES ('a1', 'a1', 'firing', '{}', '{}', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO alert_deliveries (
		id, alert_id, source, source_episode_key, status, labels_json, annotations_json,
		starts_at, started_at_basis, resolved_at_basis, receiver_grouping_identity, payload_digest, received_at
	) VALUES ('d1', 'a1', 'zabbix', 'ep1', 'firing', '{}', '{}', ?, 'source_payload', 'missing', 'zabbix:webhook', 'digest1', ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := run([]string{"funnel", "--db", dbPath, "--since", "2026-08-01T00:00:00Z", "--until", "2026-09-01T00:00:00Z"}, &stdout, &stderr); err != nil {
		t.Fatalf("funnel: %v (stderr=%s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "accepted deliveries:      1") {
		t.Fatalf("stdout = %q, want accepted deliveries: 1", out)
	}
	if !strings.Contains(out, "distinct source episodes: 1") {
		t.Fatalf("stdout = %q, want distinct source episodes: 1", out)
	}
}
