// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestLivenessDoesNotWaitForStorageOrIntegrations(t *testing.T) {
	h := newHarness(t)
	h.host.health = health.NewRegistry(time.Minute, health.Check{
		Name: "unavailable source",
		Probe: func(context.Context) error {
			t.Error("liveness must not probe integrations")
			return nil
		},
	})
	tx, err := h.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	h.host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/live", nil))
	if response.Code != http.StatusOK || ctx.Err() != nil {
		t.Fatalf("busy storage: liveness status=%d, context=%v", response.Code, ctx.Err())
	}
}

func TestReadinessKeepsStorageFailureVisible(t *testing.T) {
	h := newHarness(t)
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ready", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed storage: readiness status=%d", response.Code)
	}
}

func TestReadinessDoesNotProbeExternalSources(t *testing.T) {
	h := newHarness(t)
	h.host.health = health.NewRegistry(time.Minute, health.Check{
		Name: "unavailable source",
		Probe: func(context.Context) error {
			t.Error("readiness must not probe integrations")
			return nil
		},
	})
	response := httptest.NewRecorder()
	h.host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ready", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("healthy storage: readiness status=%d", response.Code)
	}
}

// TestReadinessDoesNotWaitForBusyStoreConnection is issue #99: a long store
// call holds the store's only connection, and readiness must not queue
// behind it. /health reports the contention instead of failing.
func TestReadinessDoesNotWaitForBusyStoreConnection(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "busy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	host, err := New(Options{Store: st, Auditor: audit.New(st.DB()), Receivers: []Receiver{NewAlertReceiver(st, testToken, nil, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE schema_migrations SET applied_at = applied_at`); err != nil {
		t.Fatal(err)
	}

	for _, route := range []string{"/ready", "/health"} {
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		response := httptest.NewRecorder()
		host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(reqCtx, http.MethodGet, route, nil))
		expired := reqCtx.Err()
		cancel()
		if response.Code != http.StatusOK || expired != nil {
			t.Fatalf("busy store connection: %s status=%d context=%v body=%s", route, response.Code, expired, response.Body)
		}
		if route == "/health" && !strings.Contains(response.Body.String(), `"storage":{"connection_in_use":true,`) {
			t.Fatalf("/health should report the held store connection: %s", response.Body)
		}
	}
}

// TestHealthReportsStorageSize: once a storage maintenance pass ran, /health
// carries what the database uses, its limit and how far back it reaches.
func TestHealthReportsStorageSize(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "size.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	host, err := New(Options{Store: st, Auditor: audit.New(st.DB()), Receivers: []Receiver{NewAlertReceiver(st, testToken, nil, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	get := func() string {
		response := httptest.NewRecorder()
		host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/health", nil))
		return response.Body.String()
	}
	if body := get(); strings.Contains(body, "used_bytes") {
		t.Fatalf("/health reported a size before any maintenance pass: %s", body)
	}
	if _, err := st.RunStorageMaintenance(ctx, time.Now().UTC(), store.StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365, SizePercent: 80}, audit.New(st.DB())); err != nil {
		t.Fatal(err)
	}
	body := get()
	for _, want := range []string{`"used_bytes":`, `"limit_bytes":`, `"volume_bytes":`, `"retention_days":90`, `"audit_retention_days":365`, `"checked_at":`} {
		if !strings.Contains(body, want) {
			t.Fatalf("/health lacks %s: %s", want, body)
		}
	}
}
