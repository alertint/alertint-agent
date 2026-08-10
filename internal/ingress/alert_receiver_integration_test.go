// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
)

func TestAlertmanagerReceiverToIncidentUsesEnvelopeGrouping(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	c := correlator.New(correlator.Config{
		WindowSeconds: 60,
		TickInterval:  20 * time.Millisecond,
	}, st, correlator.NopIncidentSink{}, nil)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	r := NewAlertReceiver(st, "token", c.Accept, nil)
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

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		incs, err := st.ListCollectingIncidents(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(incs) == 1 && incs[0].AlertCount == 2 {
			if got, want := incs[0].GroupKey, "tenant=acme,workload=checkout"; got != want {
				t.Fatalf("Incident group key = %q, want %q", got, want)
			}
			if incs[0].GroupKey == "" {
				t.Fatal("Incident group key must not be empty")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	incs, _ := st.ListCollectingIncidents(ctx)
	t.Fatalf("Receiver-to-Incident grouping did not converge: %+v", incs)
}
