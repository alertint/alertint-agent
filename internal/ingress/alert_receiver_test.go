// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// alertReceiverFixture builds an Alertmanager receiver over a fresh
// in-memory Store, for tests that assert directly against the durable
// ledger instead of a sink.
func alertReceiverFixture(t *testing.T) (Receiver, *store.Store) {
	t.Helper()
	st := newTestStore(t)
	return NewAlertReceiver(st, "token", nil, nil), st
}

// validAlert builds a minimal, structurally valid AlertmanagerAlert member.
func validAlert(fingerprint, status string) AlertmanagerAlert {
	return AlertmanagerAlert{
		Status:      status,
		Labels:      map[string]string{"alertname": "Test"},
		StartsAt:    time.Now().UTC(),
		Fingerprint: fingerprint,
	}
}

// alertmanagerBody marshals a v4 envelope carrying exactly these members.
func alertmanagerBody(alerts ...AlertmanagerAlert) []byte {
	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts:  alerts,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err) // payload is always marshal-safe; a failure here is a test bug
	}
	return b
}

// claimAll drains every pending/due dispatch from st, for tests that need to
// inspect the immutable AlertDelivery rows a receiver produced.
func claimAll(t *testing.T, st *store.Store) []store.AlertDispatch {
	t.Helper()
	claims, err := st.ClaimAlertDispatches(context.Background(), "test-claimer", time.Now().UTC().Add(time.Hour), time.Minute, 1000)
	if err != nil {
		t.Fatalf("ClaimAlertDispatches: %v", err)
	}
	return claims
}

// findDelivery locates the one claimed dispatch whose Alert fingerprint and
// status match, regardless of claim order — deliveries sharing a
// fingerprint (e.g. a firing member and its later resolution) are only
// distinguishable by status.
func findDelivery(t *testing.T, claims []store.AlertDispatch, fingerprint, status string) store.AlertDispatch {
	t.Helper()
	for _, c := range claims {
		if c.Delivery.Alert.Fingerprint == fingerprint && c.Delivery.Alert.Status == status {
			return c
		}
	}
	t.Fatalf("no delivery found for fingerprint=%s status=%s among %d claims", fingerprint, status, len(claims))
	return store.AlertDispatch{}
}

func TestAlertmanagerReceiverHandsOffSortedGroupLabelsIdentity(t *testing.T) {
	st := newTestStore(t)
	var wakes int
	r := NewAlertReceiver(st, "token", func() { wakes++ }, nil)

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
	if wakes != 1 {
		t.Fatalf("wake calls = %d, want 1", wakes)
	}

	claims := claimAll(t, st)
	d := findDelivery(t, claims, "fp-sorted", "firing")
	if got, want := d.Delivery.ReceiverGroupingIdentity, "team=payments,zone=west"; got != want {
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

	d := findDelivery(t, claimAll(t, st), "fp-alertname", "firing")
	if got, want := d.Delivery.ReceiverGroupingIdentity, "alertname=HighLatency"; got != want {
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

	d := findDelivery(t, claimAll(t, st), "fp-only", "firing")
	if got, want := d.Delivery.ReceiverGroupingIdentity, "fingerprint=fp-only"; got != want {
		t.Fatalf("ReceiverGroupingIdentity = %q, want %q", got, want)
	}
}

// TestAlertmanagerReceiverFiringAndResolvedHaveDistinctIDsStableEpisodeKey
// proves the durable ledger records a firing member and its later
// resolution as two immutable deliveries sharing one source episode.
func TestAlertmanagerReceiverFiringAndResolvedHaveDistinctIDsStableEpisodeKey(t *testing.T) {
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)
	now := time.Now().UTC()

	payload := AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"team": "payments"},
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "HighLatency"},
			StartsAt:    now,
			Fingerprint: "fp-resolution",
		}},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}
	payload.Status = "resolved"
	payload.Alerts[0].Status = "resolved"
	payload.Alerts[0].EndsAt = now.Add(time.Minute)
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}

	assertTableCount(t, st.DB(), "alert_deliveries", 2)

	claims := claimAll(t, st)
	firing := findDelivery(t, claims, "fp-resolution", "firing")
	resolved := findDelivery(t, claims, "fp-resolution", "resolved")
	if firing.Delivery.ID == resolved.Delivery.ID {
		t.Fatal("firing and resolved deliveries must have distinct IDs")
	}
	if firing.Delivery.SourceEpisodeKey != resolved.Delivery.SourceEpisodeKey {
		t.Fatalf("episode key must stay stable: firing=%q resolved=%q",
			firing.Delivery.SourceEpisodeKey, resolved.Delivery.SourceEpisodeKey)
	}
	if firing.Delivery.ReceiverGroupingIdentity != resolved.Delivery.ReceiverGroupingIdentity {
		t.Fatalf("firing identity %q differs from resolved identity %q",
			firing.Delivery.ReceiverGroupingIdentity, resolved.Delivery.ReceiverGroupingIdentity)
	}
}

// TestAlertmanagerReceiverTwoMemberEnvelopeInvokesOneWake proves a
// multi-member POST creates one immutable delivery per member but invokes
// its post-commit wake exactly once, not once per member.
func TestAlertmanagerReceiverTwoMemberEnvelopeInvokesOneWake(t *testing.T) {
	st := newTestStore(t)
	var wakes int
	r := NewAlertReceiver(st, "token", func() { wakes++ }, nil)
	now := time.Now().UTC()

	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []AlertmanagerAlert{
			{Status: "firing", Labels: map[string]string{"alertname": "A"}, StartsAt: now, Fingerprint: "fp-a"},
			{Status: "firing", Labels: map[string]string{"alertname": "B"}, StartsAt: now, Fingerprint: "fp-b"},
		},
	}
	if _, err := r.Ingest(context.Background(), mustMarshal(t, payload)); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, st.DB(), "alert_deliveries", 2)
	if wakes != 1 {
		t.Fatalf("wake calls = %d, want 1", wakes)
	}
}

// TestAlertmanagerReceiverRedeliveryIsIdempotent proves transport redelivery
// of the exact same POST body is a successful no-op: the same two members
// posted twice leave two total delivery rows, not four.
func TestAlertmanagerReceiverRedeliveryIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	r := NewAlertReceiver(st, "token", nil, nil)
	now := time.Now().UTC()

	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []AlertmanagerAlert{
			{Status: "firing", Labels: map[string]string{"alertname": "A"}, StartsAt: now, Fingerprint: "fp-a"},
			{Status: "firing", Labels: map[string]string{"alertname": "B"}, StartsAt: now, Fingerprint: "fp-b"},
		},
	}
	body := mustMarshal(t, payload)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	assertTableCount(t, st.DB(), "alerts", 2)
	assertTableCount(t, st.DB(), "alert_deliveries", 2)
	assertTableCount(t, st.DB(), "alert_delivery_dispatches", 2)
}

// TestAlertmanagerReceiverRejectsWholeInvalidEnvelope is the literal
// all-or-nothing case from the task brief: one invalid member rejects the
// whole POST and commits no member, not even the otherwise-valid one.
func TestAlertmanagerReceiverRejectsWholeInvalidEnvelope(t *testing.T) {
	receiver, st := alertReceiverFixture(t)
	body := alertmanagerBody(
		validAlert("fp-good", "firing"),
		AlertmanagerAlert{Fingerprint: "fp-bad", Status: "firing"},
	)
	if _, err := receiver.Ingest(context.Background(), body); err == nil {
		t.Fatal("invalid envelope accepted")
	}
	assertTableCount(t, st.DB(), "alerts", 0)
	assertTableCount(t, st.DB(), "alert_deliveries", 0)
}

// assertTableCount asserts the row count of table equals want. Duplicated
// (rather than shared) with internal/store's own test helper of the same
// name, since Go test helpers don't cross package boundaries.
func assertTableCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}
