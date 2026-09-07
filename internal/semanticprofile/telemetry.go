// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ----------------------------------------------------------------------
// OpenTelemetry span for the semantic-profile inference worker — Plan 4
// Task 9's "semantic_profile.inference" span (spec.md's "MCP, audit, logs,
// and OTel"). Mirrors internal/situation/telemetry.go's own
// SpanAssessmentDispatch exactly: identity, digests, counts, and closed
// result classes only — never a raw prompt, provider response, or profile
// content. Emitted through the OpenTelemetry global TracerProvider; with no
// provider configured every span is a no-op and nothing leaves the process.
// ----------------------------------------------------------------------

const tracerName = "github.com/alertint/alertint-agent/internal/semanticprofile"

// SpanSemanticInference covers one consumed inference dispatch slot: the
// durable call row is already committed when it starts; it measures the
// physical provider request plus classification.
const SpanSemanticInference = "semantic_profile.inference"

// Attribute keys (stable). Identity, counts, and closed result classes only.
const (
	AttrJobID       = attribute.Key("alertint.semantic_profile.job_id")
	AttrCallID      = attribute.Key("alertint.semantic_profile.call_id")
	AttrAttempt     = attribute.Key("alertint.semantic_profile.attempt")
	AttrResultClass = attribute.Key("alertint.result.class")
)

func tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(tracerName)
}
