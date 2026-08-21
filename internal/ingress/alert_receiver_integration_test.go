// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestAlertmanagerReceiverQueuesEnvelopeGroupedDeliveries(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)
	now := time.Now().UTC()
	payload := AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"tenant": "acme", "workload": "checkout"},
		Alerts: []AlertmanagerAlert{
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "HighLatency", "tenant": "acme", "workload": "checkout"},
				StartsAt:    now,
				Fingerprint: "fp-tracer-latency",
			},
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "ErrorRate", "tenant": "acme", "workload": "checkout"},
				StartsAt:    now,
				Fingerprint: "fp-tracer-errors",
			},
		},
	}
	if _, err := r.Ingest(ctx, mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	var pending int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 2 {
		t.Fatalf("pending dispatches = %d, want 2", pending)
	}
	var identities int
	if err := st.DB().QueryRow(`SELECT COUNT(DISTINCT receiver_grouping_identity) FROM alert_deliveries`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 1 {
		t.Fatalf("distinct grouping identities = %d, want 1", identities)
	}
}

// TestAlertmanagerReceiverAcceptedDeliveryIsDurableAcrossRestart proves the
// receiver-commit boundary the Situation crash-boundary suite
// (internal/situation/controller_integration_test.go) drives end to end:
// once Ingest returns success, the accepted delivery and its pending
// correlation dispatch are durable against a real SQLite file, survive a
// full process restart (closing and reopening the same file — never
// :memory:), and are claimable exactly once — never lost, never duplicated.
func TestAlertmanagerReceiverAcceptedDeliveryIsDurableAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "alertint.db")

	first, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	now := time.Now().UTC()
	r := NewAlertReceiver(first, "token", nil, nil)
	payload := AlertmanagerPayload{
		Version: "4", Status: "firing", GroupLabels: map[string]string{"service": "restart-probe"},
		Alerts: []AlertmanagerAlert{{
			Status: "firing", Fingerprint: "fp-restart-probe",
			Labels: map[string]string{"alertname": "RestartProbe", "service": "restart-probe"}, StartsAt: now,
		}},
	}
	if _, err := r.Ingest(ctx, mustMarshal(t, payload)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// The process crashes right here — no clean shutdown, no drain.
	if err := first.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	second, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	var deliveries int
	if err := second.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_deliveries ad JOIN alerts a ON a.id = ad.alert_id
		WHERE a.fingerprint = 'fp-restart-probe'`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("accepted deliveries after restart = %d, want exactly 1 (no lost accepted delivery)", deliveries)
	}
	var pending int
	if err := second.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending correlation dispatches after restart = %d, want exactly 1 (durable, never lost, never duplicated)", pending)
	}

	// Claimable exactly once against the reopened file: a claim now, and a
	// second claim attempt while the first is still leased, must not both
	// succeed.
	claims, err := second.ClaimAlertDispatches(ctx, "worker-a", now.Add(time.Second), time.Minute, 10)
	if err != nil {
		t.Fatalf("claim dispatches: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed dispatches = %d, want exactly 1", len(claims))
	}
	again, err := second.ClaimAlertDispatches(ctx, "worker-b", now.Add(2*time.Second), time.Minute, 10)
	if err != nil {
		t.Fatalf("second claim attempt: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("a second worker claimed %d already-leased dispatches, want 0", len(again))
	}
}
