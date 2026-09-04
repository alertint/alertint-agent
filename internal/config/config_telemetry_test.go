// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

// TestTelemetryDefaultsAreDisabledEgress locks the operator-configured
// observability boundary: with nothing configured, no exporter is enabled.
func TestTelemetryDefaultsAreDisabledEgress(t *testing.T) {
	o := Defaults().Telemetry.OTLP
	if o.Enabled {
		t.Fatal("telemetry.otlp.enabled defaults to true — telemetry egress must be opt-in")
	}
	if o.Protocol != "grpc" || o.ServiceName != "alertint-agent" || o.TimeoutSeconds != 10 || o.Endpoint != "" || o.Insecure {
		t.Fatalf("telemetry.otlp defaults = %+v, want protocol=grpc service_name=alertint-agent timeout_seconds=10 endpoint='' insecure=false", o)
	}
}

func TestTelemetryValidation(t *testing.T) {
	base := situationsBaseYAML(t)
	cases := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"enabled grpc host:port", "telemetry:\n  otlp:\n    enabled: true\n    endpoint: otel-collector:4317\n    insecure: true\n", ""},
		{"enabled http url", "telemetry:\n  otlp:\n    enabled: true\n    endpoint: http://otel-collector:4318\n    protocol: http\n", ""},
		{"disabled block validates shape", "telemetry:\n  otlp:\n    enabled: false\n", ""},
		{"enabled without endpoint", "telemetry:\n  otlp:\n    enabled: true\n", "telemetry.otlp.endpoint is required"},
		{"unknown protocol", "telemetry:\n  otlp:\n    enabled: true\n    endpoint: c:4317\n    protocol: thrift\n", "telemetry.otlp.protocol"},
		{"non-positive timeout", "telemetry:\n  otlp:\n    timeout_seconds: 0\n", "telemetry.otlp.timeout_seconds must be > 0"},
		{"empty service name", "telemetry:\n  otlp:\n    enabled: true\n    endpoint: c:4317\n    service_name: \"\"\n", "telemetry.otlp.service_name"},
		{"unknown key", "telemetry:\n  otlp:\n    exporter: jaeger\n", "field exporter not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFrom(strings.NewReader(base+"\n"+tc.block), "test.yaml")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
