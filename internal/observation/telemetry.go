// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ----------------------------------------------------------------------
// OpenTelemetry span for one plan's executor dispatch — Plan 4 Task 9's
// "situation.observation" span (spec.md's "MCP, audit, logs, and OTel").
// Mirrors internal/situation/telemetry.go's own SpanAssessmentDispatch: it
// wraps only the out-of-transaction connector I/O (Executor.Execute), never
// a durable write, and carries identity/closed-class attributes only —
// never a raw connector request or provider response body. Emitted through
// the OpenTelemetry global TracerProvider; with no provider configured
// every span is a no-op and nothing leaves the process.
// ----------------------------------------------------------------------

const tracerName = "github.com/alertint/alertint-agent/internal/observation"

// SpanObservationRun covers one plan's executor dispatch within a
// preparation phase: the frozen plan is already durable when it starts; it
// measures the connector I/O and produces the Run RunPhase commits next.
const SpanObservationRun = "situation.observation"

// Attribute keys (stable). Identity, counts, and closed result classes only.
const (
	AttrCycleID     = attribute.Key("alertint.preparation.cycle_id")
	AttrPlanID      = attribute.Key("alertint.observation.plan_id")
	AttrCapability  = attribute.Key("alertint.observation.capability")
	AttrPhase       = attribute.Key("alertint.observation.phase")
	AttrResultClass = attribute.Key("alertint.result.class")
)

func tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(tracerName)
}
