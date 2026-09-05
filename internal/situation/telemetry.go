// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ----------------------------------------------------------------------
// OpenTelemetry spans for the controller and Triage worker.
//
// spec.md ("MCP, audit, logs, and OTel"): "Structured logs and OTel use
// stable Situation, Incident, attempt, input-version, and digest
// attributes. They expose consumed dispatch/attempt counts and timings
// without recording payloads, prompts, or model output bodies." The three
// spans below are that surface. Every attribute is a stable identity, a
// digest, a closed result class, a count, or a duration — never a
// proposal, prompt, provider response, error body, SQL text, or secret
// (TestTelemetrySpansCarryIdentityDigestsAndCountsNeverPayloads pins the
// absence). Spans are started AFTER the durable write they describe has
// committed, or wrap only the out-of-transaction I/O they measure, so no
// exporter call ever happens inside a database transaction (Global
// Constraint).
//
// Spans are emitted through the OpenTelemetry global TracerProvider
// (otel.GetTracerProvider). This package installs no provider of its own:
// with nothing configured every span is a no-op and no telemetry leaves
// the process. The operator opts in through the `telemetry.otlp` config
// section (internal/telemetry installs the OTLP exporter and provider at
// startup) — never unconsented telemetry egress.
//
// Every span site also writes one structured log line carrying the same
// stable identities plus the span's trace/span IDs (spanLogAttrs), so
// logs, spans, audit rows, and the store reconcile against each other by
// identity rather than by timestamp proximity.
// ----------------------------------------------------------------------

// tracerName is the instrumentation scope every span in this package uses.
const tracerName = "github.com/alertint/alertint-agent/internal/situation"

// Span names (stable; documented in docs/concepts/architecture.md).
const (
	// SpanControllerReconcile covers one fenced Situation controller cycle
	// (Controller.Reconcile): claim to commit.
	SpanControllerReconcile = "situation.controller.reconcile"
	// SpanAssessmentDispatch covers one consumed L2 dispatch slot: the
	// durable call row is already committed when it starts; it measures the
	// physical provider request plus validation/classification.
	SpanAssessmentDispatch = "situation.assessment.dispatch"
	// SpanTriageAttempt covers one consumed Acute Triage attempt
	// (TriageWorker.processOne): the claim is already durable when it
	// starts; it measures analysis plus completion.
	SpanTriageAttempt = "incident.triage.attempt"
)

// Attribute keys (stable). Identity, digests, counts, closed result
// classes, and durations only.
const (
	AttrSituationID            = attribute.Key("alertint.situation.id")
	AttrIncidentID             = attribute.Key("alertint.incident.id")
	AttrInputVersion           = attribute.Key("alertint.situation.input_version")
	AttrAttemptID              = attribute.Key("alertint.attempt.id")
	AttrAssessmentCallID       = attribute.Key("alertint.assessment.call_id")
	AttrRetryEpoch             = attribute.Key("alertint.assessment.retry_epoch")
	AttrWorkAttempt            = attribute.Key("alertint.assessment.work_attempt")
	AttrDispatchSlot           = attribute.Key("alertint.assessment.dispatch_slot")
	AttrMaterialFactHash       = attribute.Key("alertint.assessment.material_fact_hash")
	AttrAssessmentBasisHash    = attribute.Key("alertint.assessment.basis_hash")
	AttrAssessmentDerivation   = attribute.Key("alertint.assessment.derivation")
	AttrProviderRequestStarted = attribute.Key("alertint.assessment.provider_request_started")
	AttrTriageAttemptNumber    = attribute.Key("alertint.triage.attempt_number")
	AttrMembershipDigest       = attribute.Key("alertint.triage.membership_digest")
	AttrIncidentInputDigest    = attribute.Key("alertint.triage.incident_input_digest")
	AttrEvidencePackDigest     = attribute.Key("alertint.triage.evidence_pack_digest")
	AttrResultClass            = attribute.Key("alertint.result.class")
	AttrDurationMS             = attribute.Key("alertint.duration_ms")
)

// Closed result classes for SpanControllerReconcile's AttrResultClass.
// SpanAssessmentDispatch uses L2Outcome values; SpanTriageAttempt uses the
// Triage completion outcomes plus clean_skip/backoff/exhausted/lease_lost
// and the *_failed store-write classes.
const (
	ReconcileResultCommitted    = "committed"
	ReconcileResultCommitFailed = "commit_failed"
	ReconcileResultError        = "error"
)

func tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(tracerName)
}

// spanLogAttrs returns the trace_id/span_id slog attribute pair for span,
// or nil when span carries no valid span context (no provider installed),
// so a log line's identity attributes stay the same whether or not export
// is configured and the trace/span pair simply appears once it is.
func spanLogAttrs(span trace.Span) []any {
	sc := span.SpanContext()
	if !sc.IsValid() {
		return nil
	}
	return []any{"trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String()}
}
