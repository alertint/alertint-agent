// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"testing"
	"time"
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
