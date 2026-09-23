// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
)

// jsonLogLines parses every JSON line a slog.JSONHandler wrote into buf.
func jsonLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func linesWithMsg(lines []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, m := range lines {
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func spanByID(t *testing.T, spans tracetest.SpanStubs, spanID string) tracetest.SpanStub {
	t.Helper()
	for _, s := range spans {
		if s.SpanContext.SpanID().String() == spanID {
			return s
		}
	}
	t.Fatalf("no recorded span has span_id %q", spanID)
	return tracetest.SpanStub{}
}

// stringAttr returns line[key] as a string, failing the test when it is
// absent or not a string.
func stringAttr(t *testing.T, line map[string]any, key string) string {
	t.Helper()
	v, ok := line[key].(string)
	if !ok {
		t.Fatalf("log line %q attribute %q = %v (%T), want a string", line["msg"], key, line[key], line[key])
	}
	return v
}

func requireKeys(t *testing.T, line map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := line[k]; !ok {
			t.Fatalf("log line %q lacks attribute %q: %v", line["msg"], k, line)
		}
	}
}

// TestTelemetryReconcileAndDispatchLogLinesCarrySpanIdentity proves the
// structured log lines the controller writes per cycle and per consumed
// dispatch slot carry the same stable identities the spans do (spec.md:
// "Structured logs and OTel use stable Situation, Incident, attempt,
// input-version, and digest attributes") plus the trace/span IDs of the
// exact span they describe — so a lab operator can reconcile a log line
// against its span, its audit rows, and the store by identity.
func TestTelemetryReconcileAndDispatchLogLinesCarrySpanIdentity(t *testing.T) {
	exporter := installSpanRecorder(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 2, beginRetryEpoch: 1}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		malformedResponse(), acceptedResponse(t),
	}}
	clock := func() time.Time { return ctBaseTime.Add(10 * time.Minute) }
	c := situation.NewController(store, client, situation.ControllerConfig{}, clock, nil, logger)
	claim := ctBaseClaim()
	if err := c.Reconcile(context.Background(), claim); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	spans := exporter.GetSpans()
	lines := jsonLogLines(t, &buf)

	reconciles := linesWithMsg(lines, "situation: controller reconcile")
	if len(reconciles) != 1 {
		t.Fatalf("reconcile log lines = %d, want 1", len(reconciles))
	}
	r := reconciles[0]
	requireKeys(t, r, "situation_id", "input_version", "result_class", "duration_ms", "trace_id", "span_id")
	if r["situation_id"] != claim.Situation.ID || r["result_class"] != situation.ReconcileResultCommitted {
		t.Fatalf("reconcile line = %v, want situation %q committed", r, claim.Situation.ID)
	}
	rs := spanByID(t, spans, stringAttr(t, r, "span_id"))
	if rs.Name != situation.SpanControllerReconcile {
		t.Fatalf("reconcile line span_id resolves to span %q, want %q", rs.Name, situation.SpanControllerReconcile)
	}
	if rs.SpanContext.TraceID().String() != r["trace_id"] {
		t.Fatalf("reconcile line trace_id = %v, want the span's %s", r["trace_id"], rs.SpanContext.TraceID())
	}

	dispatches := linesWithMsg(lines, "situation: assessment dispatch")
	if len(dispatches) != 2 {
		t.Fatalf("dispatch log lines = %d, want 2 (one per consumed dispatch slot)", len(dispatches))
	}
	wantClasses := []string{string(situation.L2OutcomeMalformed), string(situation.L2OutcomeAccepted)}
	for i, d := range dispatches {
		requireKeys(t, d, "situation_id", "call_id", "dispatch_slot", "input_version", "retry_epoch", "work_attempt",
			"material_fact_hash", "result_class", "provider_request_started", "duration_ms", "trace_id", "span_id")
		if d["call_id"] != store.recordCalls[i].ID {
			t.Fatalf("dispatch line %d call_id = %v, want the durable call row %q", i, d["call_id"], store.recordCalls[i].ID)
		}
		if d["result_class"] != wantClasses[i] {
			t.Fatalf("dispatch line %d result_class = %v, want %q", i, d["result_class"], wantClasses[i])
		}
		ds := spanByID(t, spans, stringAttr(t, d, "span_id"))
		if ds.Name != situation.SpanAssessmentDispatch {
			t.Fatalf("dispatch line %d span_id resolves to span %q, want %q", i, ds.Name, situation.SpanAssessmentDispatch)
		}
		if ds.SpanContext.TraceID().String() != r["trace_id"] {
			t.Fatalf("dispatch line %d trace_id = %v, want the reconcile's trace %v", i, ds.SpanContext.TraceID(), r["trace_id"])
		}
	}

	// Never a payload: the malformed body, the accepted proposal, and the
	// prompt must not appear in any log line.
	for _, bad := range []string{"{not valid json", string(acceptedProposalJSON(t))} {
		if strings.Contains(buf.String(), bad) {
			t.Fatalf("log output carries payload text %q", bad)
		}
	}
}

// TestTelemetryTriageAttemptLogLineCarriesSpanIdentity is the Triage-worker
// counterpart: one line per consumed attempt with the attempt's identity,
// both coverage digests, the evidence-pack digest, its closed result class,
// and the attempt span's own trace/span IDs.
func TestTelemetryTriageAttemptLogLineCarriesSpanIdentity(t *testing.T) {
	exporter := installSpanRecorder(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	claim := testClaim("inc-log", 2)
	claim.MembershipDigest = "sha256:membership-log"
	claim.IncidentInputDigest = "sha256:input-log"
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-log"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{IncidentID: c.IncidentID, EvidencePackDigest: "sha256:evidence-log"}, nil
	}}
	w := situation.NewTriageWorker(store, lister, analyzer, &fakeAfterCommit{}, nil, situation.TriageWorkerConfig{Owner: "test-owner"}, logger)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	attempts := linesWithMsg(jsonLogLines(t, &buf), "situation: triage worker: attempt finished")
	if len(attempts) != 1 {
		t.Fatalf("attempt log lines = %d, want 1", len(attempts))
	}
	a := attempts[0]
	requireKeys(t, a, "situation_id", "incident_id", "attempt_id", "attempt_number", "input_version",
		"membership_digest", "incident_input_digest", "evidence_pack_digest", "result_class", "duration_ms", "trace_id", "span_id")
	want := map[string]any{
		"incident_id": "inc-log", "attempt_id": claim.AttemptID, "attempt_number": float64(2),
		"membership_digest": "sha256:membership-log", "incident_input_digest": "sha256:input-log",
		"evidence_pack_digest": "sha256:evidence-log", "result_class": string(situation.TriageCompletionSuccess),
	}
	for k, v := range want {
		if a[k] != v {
			t.Fatalf("attempt line %s = %v, want %v", k, a[k], v)
		}
	}
	as := spanByID(t, exporter.GetSpans(), stringAttr(t, a, "span_id"))
	if as.Name != situation.SpanTriageAttempt || as.SpanContext.TraceID().String() != a["trace_id"] {
		t.Fatalf("attempt line resolves to span %q trace %s, want %q trace %v", as.Name, as.SpanContext.TraceID(), situation.SpanTriageAttempt, a["trace_id"])
	}
}
