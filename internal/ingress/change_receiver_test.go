// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestParseChange_HappyPath(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	body := []byte(`{
		"source":"github-actions","kind":"deploy",
		"title":"checkout v1.42.0 deployed to prod",
		"labels":{"service":"checkout","namespace":"prod"},
		"version":"v1.42.0","link":"https://x/run/1",
		"occurred_at":"2026-06-18T10:42:00Z"
	}`)
	out, err := ParseChange(body, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 change, got %d", len(out))
	}
	c := out[0]
	if c.Kind != "deploy" || c.Source != "github-actions" || c.Title == "" {
		t.Fatalf("fields: %#v", c)
	}
	if !c.OccurredAt.Equal(time.Date(2026, 6, 18, 10, 42, 0, 0, time.UTC)) {
		t.Fatalf("occurred_at: %v", c.OccurredAt)
	}
	if !c.ReceivedAt.Equal(now) {
		t.Fatalf("received_at: %v", c.ReceivedAt)
	}
	if c.ID != "" {
		t.Fatal("ID must be stamped by the receiver, not ParseChange")
	}
}

func TestParseChange_FutureOccurredClampsToReceived(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	body := []byte(`{"kind":"deploy","labels":{"service":"x"},"occurred_at":"2026-06-18T16:00:00Z"}`)
	out, err := ParseChange(body, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !out[0].OccurredAt.Equal(now) {
		t.Fatalf("future occurred_at must clamp to received_at, got %v", out[0].OccurredAt)
	}
}

func TestParseChange_MissingOccurredFallsBack(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	out, err := ParseChange([]byte(`{"kind":"config","labels":{"a":"b"}}`), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !out[0].OccurredAt.Equal(now) {
		t.Fatalf("missing occurred_at must fall back to received_at, got %v", out[0].OccurredAt)
	}
}

func TestParseChange_DefaultsSourceAndSynthesizesTitle(t *testing.T) {
	now := time.Now().UTC()
	out, err := ParseChange([]byte(`{"kind":"deploy","labels":{"service":"checkout"},"version":"v9"}`), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out[0].Source != "unknown" {
		t.Fatalf("source default: %q", out[0].Source)
	}
	if out[0].Title != "deploy checkout v9" {
		t.Fatalf("synth title: %q", out[0].Title)
	}
}

func TestParseChange_Rejects(t *testing.T) {
	now := time.Now().UTC()
	cases := map[string]string{
		"missing kind":   `{"labels":{"a":"b"}}`,
		"empty labels":   `{"kind":"deploy","labels":{}}`,
		"missing labels": `{"kind":"deploy"}`,
		"bad json":       `{`,
	}
	for name, body := range cases {
		if _, err := ParseChange([]byte(body), now); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestChangeReceiver_PersistsAndAudits(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer func() { _ = st.Close() }()
	auditor := audit.New(st.DB())

	// A sink that must NEVER be called by the change route.
	alertSinkCalled := false
	sink := func(context.Context, store.Alert) error { alertSinkCalled = true; return nil }

	host, err := New(Options{
		Store:   st,
		Auditor: auditor,
		Receivers: []Receiver{
			NewAlertReceiver(st, "alert-tok", sink, slog.Default()),
			NewChangeReceiver(st, "change-tok", 30, slog.Default()),
		},
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	defer srv.Close()

	body := `{"source":"github-actions","kind":"deploy","labels":{"service":"checkout"},"occurred_at":"2026-06-18T10:42:00Z"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhook/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer change-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()

	got, _ := st.ChangesInWindow(ctx, time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC), time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC))
	if len(got) != 1 || got[0].ID == "" {
		t.Fatalf("want 1 stored change with stamped ID, got %#v", got)
	}
	if alertSinkCalled {
		t.Fatal("change route must not invoke the alert sink / correlator")
	}

	// Audit row recorded under kind=change.received.
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE kind='change.received'`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("change.received audit rows = %d, want 1", n)
	}

	// Per-route token isolation: alert token must not authorize the change route.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhook/change", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer alert-tok")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-token status = %d, want 401", resp2.StatusCode)
	}
	_ = resp2.Body.Close()
}
