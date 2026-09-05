// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// installSpanRecorder swaps the global TracerProvider for an in-memory
// recorder for the duration of one test. The production binary installs no
// provider at all (every span is a no-op there); this is the only place one
// exists.
func installSpanRecorder(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = tp.Shutdown(context.Background())
	})
	return exporter
}

func spansNamed(spans tracetest.SpanStubs, name string) []tracetest.SpanStub {
	var out []tracetest.SpanStub
	for _, s := range spans {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func attrValue(t *testing.T, span tracetest.SpanStub, key attribute.Key) attribute.Value {
	t.Helper()
	for _, kv := range span.Attributes {
		if kv.Key == key {
			return kv.Value
		}
	}
	t.Fatalf("span %q has no attribute %q: %v", span.Name, key, span.Attributes)
	return attribute.Value{}
}

// TestTelemetrySpansCarryIdentityDigestsAndCountsNeverPayloads drives one
// work-bearing controller cycle (malformed draft, accepted correction) and
// proves the reconcile span and both dispatch-slot spans carry exactly the
// stable identity/digest/count attributes spec.md names — and nothing that
// could be a prompt, proposal, provider body, or SQL text.
func TestTelemetrySpansCarryIdentityDigestsAndCountsNeverPayloads(t *testing.T) {
	exporter := installSpanRecorder(t)

	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 2, beginRetryEpoch: 1}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		malformedResponse(), acceptedResponse(t),
	}}
	c := ctController(t, store, client)
	claim := ctBaseClaim()
	if err := c.Reconcile(context.Background(), claim); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	spans := exporter.GetSpans()

	reconciles := spansNamed(spans, situation.SpanControllerReconcile)
	if len(reconciles) != 1 {
		t.Fatalf("reconcile spans = %d, want 1", len(reconciles))
	}
	r := reconciles[0]
	if got := attrValue(t, r, situation.AttrSituationID).AsString(); got != claim.Situation.ID {
		t.Fatalf("reconcile situation id = %q, want %q", got, claim.Situation.ID)
	}
	if got := attrValue(t, r, situation.AttrInputVersion).AsInt64(); got != int64(claim.Situation.InputVersion) {
		t.Fatalf("reconcile input version = %d, want %d", got, claim.Situation.InputVersion)
	}
	if got := attrValue(t, r, situation.AttrResultClass).AsString(); got != situation.ReconcileResultCommitted {
		t.Fatalf("reconcile result class = %q, want committed", got)
	}
	commit := store.commits[0]
	if got := attrValue(t, r, situation.AttrAttemptID).AsString(); got != commit.Attempt.ID {
		t.Fatalf("reconcile attempt id = %q, want the committed attempt %q", got, commit.Attempt.ID)
	}
	if got := attrValue(t, r, situation.AttrAssessmentDerivation).AsString(); got != string(model.DerivationModelValidated) {
		t.Fatalf("reconcile derivation = %q, want model_validated", got)
	}
	if got := attrValue(t, r, situation.AttrMaterialFactHash).AsString(); got != commit.MaterialFactHash {
		t.Fatalf("reconcile material hash = %q, want %q", got, commit.MaterialFactHash)
	}
	if got := attrValue(t, r, situation.AttrAssessmentBasisHash).AsString(); got != commit.AssessmentBasisHash {
		t.Fatalf("reconcile basis hash = %q, want %q", got, commit.AssessmentBasisHash)
	}

	dispatches := spansNamed(spans, situation.SpanAssessmentDispatch)
	if len(dispatches) != 2 {
		t.Fatalf("dispatch spans = %d, want 2 (one per consumed dispatch slot)", len(dispatches))
	}
	wantClasses := []string{string(situation.L2OutcomeMalformed), string(situation.L2OutcomeAccepted)}
	for i, d := range dispatches {
		if got := attrValue(t, d, situation.AttrDispatchSlot).AsInt64(); got != int64(i+1) {
			t.Fatalf("dispatch %d slot = %d, want %d", i, got, i+1)
		}
		if got := attrValue(t, d, situation.AttrAssessmentCallID).AsString(); got != store.recordCalls[i].ID {
			t.Fatalf("dispatch %d call id = %q, want the durable call row %q", i, got, store.recordCalls[i].ID)
		}
		if got := attrValue(t, d, situation.AttrRetryEpoch).AsInt64(); got != 1 {
			t.Fatalf("dispatch %d retry epoch = %d, want 1", i, got)
		}
		if got := attrValue(t, d, situation.AttrWorkAttempt).AsInt64(); got != 2 {
			t.Fatalf("dispatch %d work attempt = %d, want 2", i, got)
		}
		if got := attrValue(t, d, situation.AttrResultClass).AsString(); got != wantClasses[i] {
			t.Fatalf("dispatch %d result class = %q, want %q", i, got, wantClasses[i])
		}
		if got := attrValue(t, d, situation.AttrProviderRequestStarted).AsString(); got != string(model.ProviderRequestStartedTrue) {
			t.Fatalf("dispatch %d provider_request_started = %q, want true", i, got)
		}
		attrValue(t, d, situation.AttrDurationMS)
		if d.Parent.SpanID() != r.SpanContext.SpanID() {
			t.Fatalf("dispatch %d is not a child of the reconcile span", i)
		}
	}

	// Payload absence: no attribute key or value may carry a prompt,
	// proposal, provider response, error text, or SQL. The fake client's
	// two responses are the exact bodies that must not leak.
	forbiddenKeyFragments := []string{"prompt", "proposal", "response", "body", "raw", "sql", "error", "secret", "token"}
	forbiddenValues := []string{string(acceptedProposalJSON(t)), "{not valid json", "persistence", "SELECT", "INSERT", "UPDATE"}
	for _, s := range spans {
		for _, kv := range s.Attributes {
			key := strings.ToLower(string(kv.Key))
			for _, frag := range forbiddenKeyFragments {
				if strings.Contains(key, frag) {
					t.Fatalf("span %q attribute key %q looks like payload (%q)", s.Name, kv.Key, frag)
				}
			}
			if kv.Value.Type() == attribute.STRING {
				v := kv.Value.AsString()
				for _, bad := range forbiddenValues {
					if strings.Contains(v, bad) {
						t.Fatalf("span %q attribute %q carries payload text %q", s.Name, kv.Key, bad)
					}
				}
			}
		}
		if len(s.Events) != 0 {
			t.Fatalf("span %q has events %v, want none (no recorded errors/bodies)", s.Name, s.Events)
		}
	}
}

// TestTelemetryReconcileSpanClassifiesCommitFailureAsStaleNotError proves a
// fenced-commit rejection (a stale claim) is reported as commit_failed —
// spec.md's "the controller fails closed and the newer input remains due"
// is an expected race, not an error class — and that the error text is
// never attached to the span.
func TestTelemetryReconcileSpanClassifiesCommitFailureAsStaleNotError(t *testing.T) {
	exporter := installSpanRecorder(t)

	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, commitErr: model.ErrSituationLeaseLost}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	c := ctController(t, store, client)
	if err := c.Reconcile(context.Background(), ctBaseClaim()); err == nil {
		t.Fatal("expected Reconcile to surface the commit failure")
	}

	reconciles := spansNamed(exporter.GetSpans(), situation.SpanControllerReconcile)
	if len(reconciles) != 1 {
		t.Fatalf("reconcile spans = %d, want 1", len(reconciles))
	}
	if got := attrValue(t, reconciles[0], situation.AttrResultClass).AsString(); got != situation.ReconcileResultCommitFailed {
		t.Fatalf("result class = %q, want commit_failed", got)
	}
	if len(reconciles[0].Events) != 0 {
		t.Fatalf("span events = %v, want none — error text is never recorded", reconciles[0].Events)
	}
}

// TestTelemetryTriageAttemptSpanCarriesAttemptIdentityAndDigests proves one
// consumed Acute Triage attempt is one span carrying the attempt's own
// identity, both coverage digests, the evidence-pack digest the analysis
// produced, and its closed completion class.
func TestTelemetryTriageAttemptSpanCarriesAttemptIdentityAndDigests(t *testing.T) {
	exporter := installSpanRecorder(t)

	claim := testClaim("inc-span", 3)
	claim.MembershipDigest = "sha256:membership-span"
	claim.IncidentInputDigest = "sha256:input-span"
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-span"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{IncidentID: c.IncidentID, EvidencePackDigest: "sha256:evidence-span"}, nil
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	attempts := spansNamed(exporter.GetSpans(), situation.SpanTriageAttempt)
	if len(attempts) != 1 {
		t.Fatalf("triage attempt spans = %d, want 1", len(attempts))
	}
	a := attempts[0]
	checks := map[attribute.Key]string{
		situation.AttrSituationID:         claim.SituationID,
		situation.AttrIncidentID:          "inc-span",
		situation.AttrAttemptID:           claim.AttemptID,
		situation.AttrMembershipDigest:    "sha256:membership-span",
		situation.AttrIncidentInputDigest: "sha256:input-span",
		situation.AttrEvidencePackDigest:  "sha256:evidence-span",
		situation.AttrResultClass:         string(situation.TriageCompletionSuccess),
	}
	for key, want := range checks {
		if got := attrValue(t, a, key).AsString(); got != want {
			t.Fatalf("attempt span %q = %q, want %q", key, got, want)
		}
	}
	if got := attrValue(t, a, situation.AttrTriageAttemptNumber).AsInt64(); got != 3 {
		t.Fatalf("attempt number = %d, want 3", got)
	}
	if got := attrValue(t, a, situation.AttrInputVersion).AsInt64(); got != int64(claim.DecisionInputVersion) {
		t.Fatalf("input version = %d, want %d", got, claim.DecisionInputVersion)
	}
	attrValue(t, a, situation.AttrDurationMS)
}
