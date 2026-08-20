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
	r := NewAlertReceiver(st, "token", nil, nil)

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

	if got, want := deliveryGroupingIdentity(t, st, "fp-sorted"), "team=payments,zone=west"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFallsBackToAlertnameIdentity(t *testing.T) {
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)

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

	if got, want := deliveryGroupingIdentity(t, st, "fp-alertname"), "alertname=HighLatency"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFallsBackToFingerprintIdentity(t *testing.T) {
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)

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

	if got, want := deliveryGroupingIdentity(t, st, "fp-only"), "fingerprint=fp-only"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func TestAlertmanagerReceiverFiringAndResolvedShareIdentity(t *testing.T) {
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)

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

	if got, want := deliveryGroupingIdentity(t, st, "fp-resolution"), "team=payments"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

func deliveryGroupingIdentity(t *testing.T, st *store.Store, fingerprint string) string {
	t.Helper()
	var got string
	if err := st.DB().QueryRow(`
		SELECT d.receiver_grouping_identity
		FROM alert_deliveries d JOIN alerts a ON a.id = d.alert_id
		WHERE a.fingerprint = ? ORDER BY d.received_at DESC LIMIT 1
	`, fingerprint).Scan(&got); err != nil {
		t.Fatalf("delivery grouping identity: %v", err)
	}
	return got
}
