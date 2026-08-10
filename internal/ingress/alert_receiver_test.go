// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestAlertmanagerReceiverHandsOffSortedGroupLabelsIdentity(t *testing.T) {
	st := newTestStore(t)
	var sunk []store.Alert
	r := NewAlertReceiver(st, "token", func(_ context.Context, a store.Alert) error {
		sunk = append(sunk, a)
		return nil
	}, nil)

	payload := AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"zone": "west", "team": "payments"},
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "HighLatency"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "fp-sorted",
		}},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	if len(sunk) != 1 {
		t.Fatalf("sink calls = %d, want 1", len(sunk))
	}
	if got, want := sunk[0].ReceiverGroupingIdentity, "team=payments,zone=west"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFallsBackToAlertnameIdentity(t *testing.T) {
	st := newTestStore(t)
	var sunk store.Alert
	r := NewAlertReceiver(st, "token", func(_ context.Context, a store.Alert) error {
		sunk = a
		return nil
	}, nil)

	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "HighLatency", "service": "api"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "fp-alertname",
		}},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	if got, want := sunk.ReceiverGroupingIdentity, "alertname=HighLatency"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFallsBackToFingerprintIdentity(t *testing.T) {
	st := newTestStore(t)
	var sunk store.Alert
	r := NewAlertReceiver(st, "token", func(_ context.Context, a store.Alert) error {
		sunk = a
		return nil
	}, nil)

	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"service": "api"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "fp-only",
		}},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	if got, want := sunk.ReceiverGroupingIdentity, "fingerprint=fp-only"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFiringAndResolvedShareIdentity(t *testing.T) {
	st := newTestStore(t)
	var sunk []store.Alert
	r := NewAlertReceiver(st, "token", func(_ context.Context, a store.Alert) error {
		sunk = append(sunk, a)
		return nil
	}, nil)

	payload := AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"team": "payments"},
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "HighLatency"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "fp-resolution",
		}},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}
	payload.Status = "resolved"
	payload.Alerts[0].Status = "resolved"
	payload.Alerts[0].EndsAt = time.Now().UTC()
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	if len(sunk) != 2 {
		t.Fatalf("sink calls = %d, want 2", len(sunk))
	}
	if sunk[0].ReceiverGroupingIdentity != sunk[1].ReceiverGroupingIdentity {
		t.Fatalf("firing identity %q differs from resolved identity %q", sunk[0].ReceiverGroupingIdentity, sunk[1].ReceiverGroupingIdentity)
	}
}
