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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
)

const testToken = "secret-test-token"

type harness struct {
	host   *Server
	store  *store.Store
	server *httptest.Server
	wakeMu sync.Mutex
	wakeN  int
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
	wake := func() {
		h.wakeMu.Lock()
		defer h.wakeMu.Unlock()
		h.wakeN++
	}
	host, err := New(Options{
		Store:     s,
		Auditor:   a,
		Receivers: []Receiver{NewAlertReceiver(s, testToken, wake, nil)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.host = host
	h.server = httptest.NewServer(host.Handler())
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) wakeCalls() int {
	h.wakeMu.Lock()
	defer h.wakeMu.Unlock()
	return h.wakeN
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

	// wake fired exactly once for the durably-accepted delivery.
	if got := h.wakeCalls(); got != 1 {
		t.Errorf("wake calls = %d, want 1", got)
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

	// One wake per POST, not one per member alert.
	if got := h.wakeCalls(); got != 1 {
		t.Errorf("wake call count = %d, want 1", got)
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

// TestPost_InvalidAlertStatus_WholeEnvelopeRejected400 proves the all-or-
// nothing durability boundary: one structurally invalid member rejects the
// whole POST as 400 and commits no member, not even the otherwise-valid one.
func TestPost_InvalidAlertStatus_WholeEnvelopeRejected400(t *testing.T) {
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
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (all-or-nothing envelope rejection)", resp.StatusCode)
	}

	if _, err := h.store.GetAlertByFingerprint(context.Background(), "fp-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the otherwise-valid alert must not be persisted when a sibling member is invalid: %v", err)
	}
	if _, err := h.store.GetAlertByFingerprint(context.Background(), "fp-bad"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("invalid alert should not be persisted: %v", err)
	}
	if got := h.wakeCalls(); got != 0 {
		t.Errorf("wake calls = %d, want 0 for a rejected envelope", got)
	}
}

// stubDurabilityReceiver is a minimal Receiver whose Ingest always fails with
// a *DurabilityError, used to prove the host maps that failure class to 503
// with the fixed public message, independent of any real receiver's
// internals.
type stubDurabilityReceiver struct {
	route, name string
	token       []byte
}

func (s *stubDurabilityReceiver) Route() string { return s.route }
func (s *stubDurabilityReceiver) Name() string  { return s.name }
func (s *stubDurabilityReceiver) Token() []byte { return s.token }
func (s *stubDurabilityReceiver) Ingest(_ context.Context, _ []byte) (Summary, error) {
	return Summary{}, &DurabilityError{Err: errors.New("database is locked")}
}

func TestPost_DurabilityFailure_503WithFixedMessage(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	host, err := New(Options{
		Store:   s,
		Auditor: audit.New(s.DB()),
		Receivers: []Receiver{
			&stubDurabilityReceiver{route: "POST /webhook/stub-durability", name: "stub", token: []byte("tok")},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhook/stub-durability", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	if !strings.Contains(body, "delivery could not be persisted; retry later") {
		t.Errorf("body = %q, want the fixed public durability message", body)
	}
	if strings.Contains(body, "database is locked") {
		t.Errorf("body = %q, must not leak the wrapped internal error text", body)
	}

	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("audit rows = %d, want 0 for a durability failure", n)
	}
}

// TestPost_HappyPath_204_QueryableFromSecondConnection proves 204 means
// durably committed, not merely accepted into this process's memory: a
// second, independent connection into the same on-disk database must
// already see the delivery and its pending dispatch by the time the
// response returns.
func TestPost_HappyPath_204_QueryableFromSecondConnection(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "durability.db")
	s, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	host, err := New(Options{
		Store:     s,
		Auditor:   audit.New(s.DB()),
		Receivers: []Receiver{NewAlertReceiver(s, testToken, nil, nil)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	resp := postPayload(t, srv, mustMarshal(t, samplePayload()), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	second, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second store.Open: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if _, err := second.GetAlertByFingerprint(ctx, "fp-1"); err != nil {
		t.Errorf("delivered alert not visible from a second connection: %v", err)
	}
	var deliveries, pending int
	if err := second.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_deliveries`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := second.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || pending != 1 {
		t.Fatalf("second connection sees deliveries=%d pending_dispatches=%d, want 1 and 1", deliveries, pending)
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
	host, err := New(Options{Store: s, Auditor: audit.New(s.DB()), Logger: logger, Receivers: []Receiver{NewAlertReceiver(s, testToken, nil, logger)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
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
	rcv := NewAlertReceiver(s, "x", nil, nil)

	cases := []struct {
		name string
		opts Options
	}{
		{"missing store", Options{Auditor: a, Receivers: []Receiver{rcv}}},
		{"missing auditor", Options{Store: s, Receivers: []Receiver{rcv}}},
		{"missing receivers", Options{Store: s, Auditor: a}},
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
	host, err := New(Options{Store: s, Auditor: audit.New(s.DB()), Health: reg, Receivers: []Receiver{NewAlertReceiver(s, testToken, nil, nil)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
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

type stubLLMHealth struct{ s llmhealth.Snapshot }

func (x stubLLMHealth) Snapshot() llmhealth.Snapshot { return x.s }

func TestHealth_IncludesLLMStateButStays200(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	since := time.Now().UTC().Add(-7 * time.Minute)
	snap := llmhealth.Snapshot{State: llmhealth.StateUnavailable, Reason: llmhealth.ReasonProviderUnavailable, Detail: "HTTP 503", UnhealthySince: &since, OutageGeneration: 2,
		Capabilities: []llmhealth.CapabilitySnapshot{{Capability: llmhealth.CapabilityTriageDraft, Healthy: false, Reason: llmhealth.ReasonProviderUnavailable, Detail: "HTTP 503"}}}
	host, err := New(Options{Store: s, Auditor: audit.New(s.DB()), LLMHealth: stubLLMHealth{snap}, Receivers: []Receiver{NewAlertReceiver(s, testToken, nil, nil)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (LLM dependency state never fails liveness)", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	for _, want := range []string{`"status":"ok"`, `"llm":{"state":"unavailable"`, `"reason":"provider_unavailable"`, `"outage_generation":2`, `"capability":"triage_draft"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q should contain %s", body, want)
		}
	}
}

func TestHealth_OmitsLLMWhenNotWired(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	host, err := New(Options{Store: s, Auditor: audit.New(s.DB()), Receivers: []Receiver{NewAlertReceiver(s, testToken, nil, nil)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := mustReadBody(t, resp)
	if strings.Contains(body, `"llm"`) {
		t.Errorf("body %q should omit llm when not wired", body)
	}
}

// stubReceiver is a minimal second receiver used to assert per-route token
// isolation: one receiver's token must not authorize another's route.
type stubReceiver struct {
	route string
	name  string
	token []byte
}

func (s *stubReceiver) Route() string { return s.route }
func (s *stubReceiver) Name() string  { return s.name }
func (s *stubReceiver) Token() []byte { return s.token }
func (s *stubReceiver) Ingest(_ context.Context, _ []byte) (Summary, error) {
	return Summary{Kind: "stub.received", Audit: map[string]any{}}, nil
}

func TestServer_PerRouteTokenIsolation(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	host, err := New(Options{
		Store:   s,
		Auditor: audit.New(s.DB()),
		Receivers: []Receiver{
			NewAlertReceiver(s, "alert-tok", nil, nil),
			&stubReceiver{route: "POST /webhook/stub", name: "stub", token: []byte("stub-tok")},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	// The alert token must NOT authorize the stub route.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhook/stub", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer alert-tok")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-token status = %d, want 401", resp.StatusCode)
	}

	// The stub's own token authorizes its own route → 204.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhook/stub", strings.NewReader("{}"))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer stub-tok")
	resp2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("own-token status = %d, want 204", resp2.StatusCode)
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
