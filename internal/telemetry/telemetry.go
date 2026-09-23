// SPDX-License-Identifier: FSL-1.1-ALv2

// Package telemetry installs the process-wide OpenTelemetry trace exporter
// the operator opted into through the `telemetry.otlp` config section.
//
// Nothing in this package runs unless that section is enabled: with the
// default (disabled) configuration no provider is installed, every span
// internal/situation emits is a no-op, and no telemetry leaves the process.
// Enabling it points an OTLP trace exporter (gRPC or HTTP/protobuf) at the
// configured collector — the operator-configured observability boundary
// Plan 2's Global Constraint names — with a batching span processor, so a
// span's End() only enqueues and no exporter I/O ever happens on the caller's
// goroutine (in particular never inside a database transaction).
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Protocols the OTLP trace exporter speaks.
const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http"
)

// Options configures Start.
type Options struct {
	// Endpoint is the collector address: "host:port" or a URL with scheme
	// ("http://host:4318"). A URL's scheme decides TLS on its own; a bare
	// host:port uses TLS unless Insecure is set.
	Endpoint string
	// Protocol is ProtocolGRPC or ProtocolHTTP.
	Protocol string
	// Insecure selects a plaintext transport for a bare host:port Endpoint.
	Insecure bool
	// ServiceName and ServiceVersion become the resource's service.name /
	// service.version. OTEL_RESOURCE_ATTRIBUTES from the environment is
	// merged in as well (resource.WithFromEnv), so a deployment can add
	// service.namespace / deployment.environment.name without a config key.
	ServiceName    string
	ServiceVersion string
	// Timeout bounds one export batch.
	Timeout time.Duration
	// Logger receives exporter errors (the OpenTelemetry global error
	// handler); nil means slog.Default().
	Logger *slog.Logger
}

// Start builds the exporter and tracer provider for o, installs the
// provider as the OpenTelemetry global, and returns a shutdown func that
// flushes pending spans, stops the exporter, and restores the previous
// global provider. It never dials eagerly: a collector that is down at
// startup surfaces as logged export errors, never as a startup failure.
func Start(ctx context.Context, o Options) (func(context.Context) error, error) {
	if strings.TrimSpace(o.Endpoint) == "" {
		return nil, errors.New("telemetry: otlp endpoint is required")
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}

	exporter, err := newExporter(ctx, o)
	if err != nil {
		return nil, err
	}

	attrs := []attribute.KeyValue{}
	if o.ServiceName != "" {
		attrs = append(attrs, attribute.String("service.name", o.ServiceName))
	}
	if o.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", o.ServiceVersion))
	}
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		// resource.New reports partial-detection errors alongside a usable
		// resource; a missing env attribute must not block export.
		logger.Warn("telemetry: resource detection incomplete", "err", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithExportTimeout(o.Timeout)),
		sdktrace.WithResource(res),
	)
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.Warn("telemetry: OTLP trace export error", "err", err)
	}))

	return func(ctx context.Context) error {
		otel.SetTracerProvider(previous)
		return tp.Shutdown(ctx)
	}, nil
}

func newExporter(ctx context.Context, o Options) (*otlptrace.Exporter, error) {
	hasScheme := strings.Contains(o.Endpoint, "://")
	switch o.Protocol {
	case ProtocolGRPC, "":
		opts := []otlptracegrpc.Option{otlptracegrpc.WithTimeout(o.Timeout)}
		if hasScheme {
			opts = append(opts, otlptracegrpc.WithEndpointURL(o.Endpoint))
		} else {
			opts = append(opts, otlptracegrpc.WithEndpoint(o.Endpoint))
			if o.Insecure {
				opts = append(opts, otlptracegrpc.WithInsecure())
			}
		}
		return otlptracegrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlptracehttp.Option{otlptracehttp.WithTimeout(o.Timeout)}
		if hasScheme {
			opts = append(opts, otlptracehttp.WithEndpointURL(o.Endpoint))
		} else {
			opts = append(opts, otlptracehttp.WithEndpoint(o.Endpoint))
			if o.Insecure {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
		}
		return otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("telemetry: unsupported otlp protocol %q (want %s or %s)", o.Protocol, ProtocolGRPC, ProtocolHTTP)
	}
}
