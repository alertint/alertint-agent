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

	// Plan 3 Task 9 (R8): three additional spans on this SAME scope. Plan 3
	// adds no metric instruments, no exporter, and no configuration surface
	// — the operational signals spec.md lists (retries by class, open gap
	// age, replay backlog, uncertain outcomes) are bounded MCP fields and
	// log fields instead. See plan.md R8 for why: telemetry.otlp exports
	// traces only, so a counter would be unobservable dead code and a
	// metrics exporter is a config surface this plan does not own.

	// SpanHistoryCommit covers one fenced controller commit's durable
	// history: the immutable Transitions, the Episode-summary version folded
	// across them, the stdout stream rows, and the notification intents they
	// warranted. It starts AFTER CommitController has returned, so no
	// exporter call ever happens inside a database transaction.
	SpanHistoryCommit = "situation.history.commit"
	// SpanNotificationDeliver covers one claimed notification intent's
	// single Slack call: the claim is already durable when it starts, and
	// it wraps only the out-of-transaction provider I/O plus the fenced
	// acknowledgement's outcome class.
	SpanNotificationDeliver = "situation.notification.deliver"
	// SpanTransitionStreamEmit covers one stdout Transition-stream row's
	// write and acknowledgement. Emitted from internal/notify/stdout through
	// Tracer(), so it lands on this same scope.
	SpanTransitionStreamEmit = "situation.transition_stream.emit"

	// Plan 4 Task 9: one additional span on this SAME scope, wrapping each
	// EvidencePreparer.Prepare call reconcile's own prepareLifecyclePhase/
	// prepareAssessmentPhaseIfActive make (Task 6). Started only after
	// c.preparer is known non-nil (a build with no preparer configured
	// emits nothing for this span, exactly like every other nil-guarded
	// optional dependency in this package).

	// SpanEvidencePreparation covers one bounded preparation phase call:
	// planning, executing connector reads, and durably committing this
	// cycle's evidence, entirely inside the EvidencePreparer adapter
	// (cmd/alertint). Each individual plan's own connector dispatch gets
	// its own NESTED internal/observation.SpanObservationRun; each
	// profile-inference dispatch its own semanticprofile.SpanSemanticInference —
	// neither of which this package can import, so those two spans are
	// defined and started in their own packages instead.
	SpanEvidencePreparation = "situation.preparation"
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

	// AttrTransitionID and the six keys below are Plan 3 Task 9's (R8)
	// additions: identities, sequences, versions, counts, and closed classes
	// only — never journal prose, an Episode narrative, a Slack response
	// body, a channel token, or a claim owner.
	AttrTransitionID       = attribute.Key("alertint.transition.id")
	AttrTransitionSequence = attribute.Key("alertint.transition.sequence")
	AttrSummaryVersion     = attribute.Key("alertint.summary.version")
	AttrIntentID           = attribute.Key("alertint.intent.id")
	AttrIntentEffectClass  = attribute.Key("alertint.intent.effect_class")
	AttrIntentAttempt      = attribute.Key("alertint.intent.attempt")
	AttrGapGeneration      = attribute.Key("alertint.gap.generation")

	// AttrPreparationPhase is Plan 4 Task 9's own addition, for
	// SpanEvidencePreparation: the closed two-value observationmodel.Phase
	// ("lifecycle"|"assessment") this Prepare call ran.
	AttrPreparationPhase = attribute.Key("alertint.preparation.phase")
)

// Closed result classes for SpanHistoryCommit's AttrResultClass.
const (
	// HistoryResultCommitted means this cycle committed durable history.
	HistoryResultCommitted = "committed"
	// HistoryResultNoHistory means the cycle was non-material and warranted
	// no Transition, Episode version, stream row, or intent at all (R4).
	HistoryResultNoHistory = "no_history"
)

// Closed result classes for SpanNotificationDeliver's AttrResultClass.
const (
	DeliverResultDelivered  = "delivered"
	DeliverResultRetried    = "retried"
	DeliverResultBlocked    = "configuration_blocked"
	DeliverResultFailed     = "failed"
	DeliverResultSuperseded = "superseded"
	DeliverResultClaimLost  = "claim_lost"
)

// Closed result classes for SpanTransitionStreamEmit's AttrResultClass.
const (
	StreamResultEmitted = "emitted"
	StreamResultRetried = "retried"
	StreamResultFailed  = "failed"
)

// Closed result classes for SpanEvidencePreparation's AttrResultClass.
const (
	PreparationResultCommitted = "committed"
	PreparationResultError     = "error"
)

// ----------------------------------------------------------------------
// Plan 3 Task 9 audit event kinds emitted from THIS package.
//
// The catalog of record is internal/audit (audit.SituationHistoryKinds),
// where it can be checked for completeness against spec.md and for
// non-collision with Plan 2's names. This package cannot import it: the
// audit package's own in-package tests import internal/store, and
// internal/store imports this package, so internal/situation ->
// internal/audit closes an import cycle in that test binary. The values are
// therefore restated here, and telemetry_test.go's
// TestTelemetryAuditKindsMatchTheAuditCatalog — an EXTERNAL test package,
// which can import both — fails if the two ever drift apart. Emitters
// outside this package (internal/notify/stdout, cmd/alertint) use the audit
// package's constants directly.
const (
	auditKindTransitionCommitted    = "situation.history.transition_committed"
	auditKindSummaryProjected       = "situation.history.summary_projected"
	auditKindArtifactJournaled      = "situation.history.artifact_journaled"
	auditKindIntentCreated          = "situation.notification.intent_created"
	auditKindNotificationClaimed    = "situation.notification.claimed"
	auditKindNotificationDelivered  = "situation.notification.delivered"
	auditKindNotificationRetried    = "situation.notification.retried"
	auditKindConfigurationBlocked   = "situation.notification.configuration_blocked"
	auditKindNotificationFailed     = "situation.notification.failed"
	auditKindNotificationWithheld   = "situation.notification.withheld"
	auditKindNotificationSuperseded = "situation.notification.superseded"
	auditKindGapOpened              = "situation.notification.gap_opened"
	auditKindGapRecovered           = "situation.notification.gap_recovered"
	auditKindGapCompleted           = "situation.notification.gap_completed"
)

// AuditKindsEmittedHere lists every audit kind this package emits, for the
// external drift test described above.
func AuditKindsEmittedHere() []string {
	return []string{
		auditKindTransitionCommitted, auditKindSummaryProjected, auditKindArtifactJournaled,
		auditKindIntentCreated, auditKindNotificationClaimed, auditKindNotificationDelivered,
		auditKindNotificationRetried, auditKindConfigurationBlocked, auditKindNotificationFailed,
		auditKindNotificationWithheld, auditKindNotificationSuperseded,
		auditKindGapOpened, auditKindGapRecovered, auditKindGapCompleted,
	}
}

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

// Tracer exposes this package's instrumentation scope so the one Plan 3 span
// site that lives outside it — the stdout Transition-stream worker in
// internal/notify/stdout, which cannot import this package's unexported
// tracer — emits on the SAME scope rather than opening a second one (R8:
// "on Plan 2's tracer scope"). It installs no provider: with nothing
// configured every span it returns is a no-op.
func Tracer() trace.Tracer { return tracer() }

// SpanLogAttrs is spanLogAttrs, exported for the same single out-of-package
// span site, so its paired structured log line carries the identical
// trace_id/span_id pair every span site in this package writes.
func SpanLogAttrs(span trace.Span) []any { return spanLogAttrs(span) }

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
