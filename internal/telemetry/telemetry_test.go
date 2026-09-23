// SPDX-License-Identifier: FSL-1.1-ALv2

package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/alertint/alertint-agent/internal/telemetry"
)

// TestStartExportsSpansOverOTLPHTTPAndRestoresGlobalOnShutdown proves the
// operator-configured exporter really delivers a span to an OTLP/HTTP
// collector endpoint, and that shutdown flushes and hands the global
// provider back — the no-op state the process is in when telemetry is
// disabled.
func TestStartExportsSpansOverOTLPHTTPAndRestoresGlobalOnShutdown(t *testing.T) {
	var traceRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			traceRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := otel.GetTracerProvider()
	ctx := context.Background()
	shutdown, err := telemetry.Start(ctx, telemetry.Options{
		Endpoint:       srv.URL,
		Protocol:       telemetry.ProtocolHTTP,
		ServiceName:    "alertint-agent-test",
		ServiceVersion: "test",
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if otel.GetTracerProvider() == before {
		t.Fatal("Start did not install a tracer provider")
	}

	_, span := otel.Tracer("test").Start(ctx, "situation.controller.reconcile")
	if !span.SpanContext().IsValid() {
		t.Fatal("span context invalid: the installed provider is not recording")
	}
	span.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if got := traceRequests.Load(); got < 1 {
		t.Fatalf("OTLP /v1/traces requests = %d, want >= 1 (shutdown must flush the batch)", got)
	}
	if otel.GetTracerProvider() != before {
		t.Fatal("shutdown did not restore the previous global tracer provider")
	}
}

func TestStartRejectsMissingEndpointAndUnknownProtocol(t *testing.T) {
	if _, err := telemetry.Start(context.Background(), telemetry.Options{Protocol: telemetry.ProtocolGRPC}); err == nil {
		t.Fatal("expected an error for an empty endpoint")
	}
	if _, err := telemetry.Start(context.Background(), telemetry.Options{Endpoint: "collector:4317", Protocol: "thrift"}); err == nil {
		t.Fatal("expected an error for an unsupported protocol")
	}
}

// TestStartGRPCDoesNotDialEagerly proves a gRPC exporter pointed at a
// collector that is not there is still a successful Start: reachability is
// an export-time concern (logged), never a startup failure.
func TestStartGRPCDoesNotDialEagerly(t *testing.T) {
	shutdown, err := telemetry.Start(context.Background(), telemetry.Options{
		Endpoint: "127.0.0.1:1", Protocol: telemetry.ProtocolGRPC, Insecure: true, Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = shutdown(ctx) // an export failure here is expected and must not hang past the bound
}
