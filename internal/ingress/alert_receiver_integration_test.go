// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"testing"
	"time"
)

// TestAlertmanagerReceiverEnvelopeGroupingReachesDispatchQueue proves the
// receiver-to-Situation-controller handoff surface this task actually owns:
// envelope grouping identity flows from the parsed payload all the way
// through one durable AcceptDeliveries commit into the pending dispatch
// queue, with exactly one wake for the whole envelope. The receiver no
// longer hands alerts to the correlator directly (that direct
// Receiver-to-Correlator.Accept wiring is removed by this task); a later
// task's durable dispatch worker claims these pending dispatches and drives
// actual Incident/Situation correlation, so this test stops at the boundary
// this task is responsible for.
func TestAlertmanagerReceiverEnvelopeGroupingReachesDispatchQueue(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	var wakes int
	r := NewAlertReceiver(st, "token", func() { wakes++ }, nil)

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
	if wakes != 1 {
		t.Fatalf("wake calls = %d, want 1 for the whole envelope", wakes)
	}

	claims := claimAll(t, st)
	if len(claims) != 2 {
		t.Fatalf("claimed dispatches = %d, want 2", len(claims))
	}
	const wantIdentity = "tenant=acme,workload=checkout"
	for _, c := range claims {
		if got := c.Delivery.ReceiverGroupingIdentity; got != wantIdentity {
			t.Fatalf("dispatch grouping identity = %q, want %q", got, wantIdentity)
		}
	}
}
