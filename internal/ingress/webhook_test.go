// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/store"
)

const testToken = "secret-test-token"

type harness struct {
	hook    *Webhook
	store   *store.Store
	server  *httptest.Server
	sinkMu  sync.Mutex
	sinkIn  []store.Alert
	sinkErr error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	a := audit.New(s.DB())

	h := &harness{store: s}
	w, err := New(Options{
		Store:   s,
		Auditor: a,
		Token:   testToken,
		Sink: func(ctx context.Context, alert store.Alert) error {
			h.sinkMu.Lock()
			defer h.sinkMu.Unlock()
			h.sinkIn = append(h.sinkIn, alert)
			return h.sinkErr
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.hook = w
	h.server = httptest.NewServer(w.Handler())
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) sinkCalls() []store.Alert {
	h.sinkMu.Lock()
	defer h.sinkMu.Unlock()
	out := make([]store.Alert, len(h.sinkIn))
	copy(out, h.sinkIn)
	return out
}

func samplePayload() AlertmanagerPayload {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return AlertmanagerPayload{
		Version:  "4",
		GroupKey: "{}:{alertname=\"HighCPU\"}",
		Status:   "firing",
		Receiver: "alertint",
		Alerts: []AlertmanagerAlert{
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "HighCPU", "service": "api"},
				Annotations: map[string]string{"summary": "CPU is high"},
				StartsAt:    now,
				Fingerprint: "fp-1",
			},
		},
	}
}

// mustMarshal marshals v to JSON or fails the test.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func postPayload(t *testing.T, srv *httptest.Server, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhook/alertmanager", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestPost_HappyPath_204_PersistsAndAudits(t *testing.T) {
	h := newHarness(t)
	body := mustMarshal(t, samplePayload())

	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", resp.StatusCode, mustReadBody(t, resp))
	}

	got, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1")
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.Status != "firing" || got.Labels["alertname"] != "HighCPU" {
		t.Errorf("alert not persisted as expected: %+v", got)
	}

	// One audit row was appended.
	var n int
	if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE kind='alert.received'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("audit row count = %d, want 1", n)
	}

	// Sink received the alert.
	calls := h.sinkCalls()
	if len(calls) != 1 || calls[0].Fingerprint != "fp-1" {
		t.Errorf("sink calls = %+v", calls)
	}
}

func TestPost_MultipleAlerts_OneAuditRow_AllPersisted(t *testing.T) {
	h := newHarness(t)
	p := samplePayload()
	p.Alerts = append(p.Alerts, AlertmanagerAlert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "HighMem"},
		Annotations: map[string]string{},
		StartsAt:    time.Now().UTC(),
		Fingerprint: "fp-2",
	})
	body := mustMarshal(t, p)

	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	for _, fp := range []string{"fp-1", "fp-2"} {
		if _, err := h.store.GetAlertByFingerprint(context.Background(), fp); err != nil {
			t.Errorf("missing alert %s: %v", fp, err)
		}
	}

	var n int
	_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE kind='alert.received'`).Scan(&n)
	if n != 1 {
		t.Errorf("audit rows = %d, want 1 per call", n)
	}

	if got := h.sinkCalls(); len(got) != 2 {
		t.Errorf("sink call count = %d, want 2", len(got))
	}
}

func TestPost_MissingAuth_401(t *testing.T) {
	h := newHarness(t)
	body := mustMarshal(t, samplePayload())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.server.URL+"/webhook/alertmanager", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPost_WrongToken_401(t *testing.T) {
	h := newHarness(t)
	body := mustMarshal(t, samplePayload())
	resp := postPayload(t, h.server, body, map[string]string{"Authorization": "Bearer not-the-token"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPost_WrongContentType_415(t *testing.T) {
	h := newHarness(t)
	resp := postPayload(t, h.server, []byte("not json"), map[string]string{"Content-Type": "text/plain"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

func TestPost_MalformedJSON_400(t *testing.T) {
	h := newHarness(t)
	resp := postPayload(t, h.server, []byte("{not-json"), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPost_UnsupportedVersion_400(t *testing.T) {
	h := newHarness(t)
	p := samplePayload()
	p.Version = "3"
	body := mustMarshal(t, p)
	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPost_BodyTooLarge_413(t *testing.T) {
	h := newHarness(t)
	// Build a valid envelope but with an alert annotation that pushes
	// the body past the 1 MiB cap.
	p := samplePayload()
	p.Alerts[0].Annotations = map[string]string{
		"description": strings.Repeat("x", MaxBodyBytes+1024),
	}
	body := mustMarshal(t, p)
	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

func TestPost_GET_405(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.server.URL+"/webhook/alertmanager", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestPost_FingerprintDedupe_LatestWins(t *testing.T) {
	h := newHarness(t)

	// First post: firing.
	p1 := samplePayload()
	body1 := mustMarshal(t, p1)
	resp1 := postPayload(t, h.server, body1, nil)
	_ = resp1.Body.Close()

	// Second post: same fingerprint, resolved.
	p2 := samplePayload()
	end := time.Now().UTC().Add(2 * time.Minute)
	p2.Alerts[0].Status = "resolved"
	p2.Alerts[0].EndsAt = end
	body2 := mustMarshal(t, p2)
	resp2 := postPayload(t, h.server, body2, nil)
	_ = resp2.Body.Close()

	got, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "resolved" || got.EndsAt == nil {
		t.Errorf("dedupe latest-wins failed: %+v", got)
	}

	var rowCount int
	_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&rowCount)
	if rowCount != 1 {
		t.Errorf("alerts row count = %d, want 1 after dedupe", rowCount)
	}
}

func TestPost_ZeroEndsAt_StoredAsNil(t *testing.T) {
	h := newHarness(t)
	p := samplePayload()
	// AM sends "0001-01-01T00:00:00Z" for unresolved alerts. Our JSON
	// will use the time.Time zero value which marshals to that.
	p.Alerts[0].EndsAt = time.Time{}
	body := mustMarshal(t, p)
	resp := postPayload(t, h.server, body, nil)
	_ = resp.Body.Close()

	got, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.EndsAt != nil {
		t.Errorf("ends_at should be nil for unresolved alert, got %v", got.EndsAt)
	}
}

func TestPost_InvalidAlertStatus_PartialPersistStill204(t *testing.T) {
	h := newHarness(t)
	p := samplePayload()
	p.Alerts = append(p.Alerts, AlertmanagerAlert{
		Status:      "weird",
		Labels:      map[string]string{},
		Annotations: map[string]string{},
		StartsAt:    time.Now().UTC(),
		Fingerprint: "fp-bad",
	})
	body := mustMarshal(t, p)
	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (partial-persist tolerated)", resp.StatusCode)
	}

	if _, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1"); err != nil {
		t.Errorf("valid alert should be persisted: %v", err)
	}
	if _, err := h.store.GetAlertByFingerprint(context.Background(), "fp-bad"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("invalid alert should not be persisted: %v", err)
	}
}

func TestPost_SinkFailure_StillReturns204(t *testing.T) {
	h := newHarness(t)
	h.sinkMu.Lock()
	h.sinkErr = errors.New("downstream blew up")
	h.sinkMu.Unlock()

	body := mustMarshal(t, samplePayload())
	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if _, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1"); err != nil {
		t.Errorf("alert should be persisted even when sink fails: %v", err)
	}
}

func TestPost_EmptyAlertList_204AndAuditRow(t *testing.T) {
	h := newHarness(t)
	p := samplePayload()
	p.Alerts = nil
	body := mustMarshal(t, p)
	resp := postPayload(t, h.server, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	var n int
	_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE kind='alert.received'`).Scan(&n)
	if n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}
}

// TestPost_WebhookReceivedLine verifies one INFO "webhook received" line per
// POST (alerts + group) and that per-alert detail is at DEBUG.
func TestPost_WebhookReceivedLine(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := New(Options{Store: s, Auditor: audit.New(s.DB()), Token: testToken, Logger: logger})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(w.Handler())
	t.Cleanup(srv.Close)

	resp := postPayload(t, srv, mustMarshal(t, samplePayload()), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	out := buf.String()
	if !strings.Contains(out, "webhook received") || !strings.Contains(out, "alerts=1") {
		t.Errorf("missing webhook received INFO line with alert count: %s", out)
	}
	if !strings.Contains(out, "group=") {
		t.Errorf("webhook received line must carry group: %s", out)
	}
	// Per-alert detail lives at DEBUG, not INFO.
	if !strings.Contains(out, "alert upserted") || !strings.Contains(out, "fingerprint=fp-1") {
		t.Errorf("missing per-alert DEBUG detail line: %s", out)
	}
}

func TestNew_ValidatesRequiredFields(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(ctx, ":memory:")
	defer func() { _ = s.Close() }()
	a := audit.New(s.DB())

	cases := []struct {
		name string
		opts Options
	}{
		{"missing store", Options{Auditor: a, Token: "x"}},
		{"missing auditor", Options{Store: s, Token: "x"}},
		{"missing token", Options{Store: s, Auditor: a}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"APPLICATION/JSON", true},
		{"text/plain", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isJSONContentType(tc.in); got != tc.want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.server.URL+"/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	if !strings.Contains(body, `"ok"`) {
		t.Errorf("body = %q, want json with status ok", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHealth_IncludesIntegrationStatuses(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	reg := health.NewRegistry(time.Minute,
		health.Check{Name: "prometheus", Detail: "http://prom:9090", Probe: func(context.Context) error { return nil }},
		health.Check{Name: "slack", Detail: "#alerts", Probe: func(context.Context) error { return errors.New("invalid_auth") }},
	)
	w, err := New(Options{Store: s, Auditor: audit.New(s.DB()), Token: testToken, Health: reg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(w.Handler())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (integration failures are informational)", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	for _, want := range []string{`"prometheus"`, `"ok":true`, `"slack"`, `"invalid_auth"`, `"ok":false`} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q should contain %s", body, want)
		}
	}
}

func mustReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
