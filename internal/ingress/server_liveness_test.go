// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/health"
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

func TestReadinessBoundsStorageWait(t *testing.T) {
	h := newHarness(t)
	tx, err := h.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response := httptest.NewRecorder()
	h.host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/ready", nil))
	if response.Code != http.StatusServiceUnavailable || ctx.Err() != nil {
		t.Fatalf("storage wait wasn't bounded independently: status=%d context=%v", response.Code, ctx.Err())
	}
}
