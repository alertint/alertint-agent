// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 9: end-to-end proof (real Reconcile, real dispatchWorkBearing/commit
// paths) that spec.md's named audit events actually fire for their real
// scenario, reusing this file's own established fakeControllerStore/
// fakeAssessmentClient fixtures and controller_test.go's own scenario
// construction exactly — never a hand-rolled shortcut. assessmentAuditKind's
// own exhaustive derivation mapping, and the per-Triage-decision requested/
// skipped split, are proven directly (package-internal) in
// controller_audit_internal_test.go; this file proves the real dispatch/
// commit call sites actually reach those code paths with the right kind.
// ----------------------------------------------------------------------

type fakeAuditSink struct {
	kinds    []string
	payloads []any
}

func (s *fakeAuditSink) Append(_ context.Context, _actor, kind string, payload any) error {
	s.kinds = append(s.kinds, kind)
	s.payloads = append(s.payloads, payload)
	return nil
}

func (s *fakeAuditSink) has(kind string) bool {
	for _, k := range s.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func ctControllerWithAudit(t *testing.T, store situation.ControllerStore, client situation.AssessmentClient, audit situation.AuditSink) *situation.Controller {
	t.Helper()
	clock := func() time.Time { return ctBaseTime.Add(10 * time.Minute) }
	return situation.NewController(store, client, situation.ControllerConfig{}, clock, audit, nil)
}

// TestControllerReconcileAuditsAssessmentCallDispatchedAndAuthoritative
// mirrors TestControllerReconcileWorkBearingRecordsDispatchBeforeIOAndAcceptsOnce's
// exact scenario (a fresh work-bearing dispatch that L2 accepts) and proves
// it audits exactly situation.assessment_call_dispatched (the dispatch slot)
// then situation.assessment_authoritative (the fresh model_validated
// commit) — never assessment_reused or assessment_fallback.
func TestControllerReconcileAuditsAssessmentCallDispatchedAndAuthoritative(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !audit.has("situation.assessment_call_dispatched") {
		t.Fatalf("audit kinds = %v, want situation.assessment_call_dispatched", audit.kinds)
	}
	if !audit.has("situation.assessment_authoritative") {
		t.Fatalf("audit kinds = %v, want situation.assessment_authoritative", audit.kinds)
	}
	if audit.has("situation.assessment_reused") || audit.has("situation.assessment_fallback") {
		t.Fatalf("audit kinds = %v, want no reused/fallback event for a fresh accepted dispatch", audit.kinds)
	}
}

// TestControllerReconcileAuditsAssessmentRejectedOnPolicyRejection mirrors
// TestControllerReconcilePolicyRejectionParksWithoutRetry's scenario (an
// urgent proposal with no deterministic floor grounding it — deterministic
// policy rejection) and proves it audits situation.assessment_rejected, not
// situation.assessment_failed.
func TestControllerReconcileAuditsAssessmentRejectedOnPolicyRejection(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){policyRejectedResponse(t)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !audit.has("situation.assessment_rejected") {
		t.Fatalf("audit kinds = %v, want situation.assessment_rejected", audit.kinds)
	}
	if audit.has("situation.assessment_failed") {
		t.Fatalf("audit kinds = %v, want no assessment_failed for a policy rejection", audit.kinds)
	}
}

// TestControllerReconcileAuditsAssessmentFailedAndFallback mirrors
// TestControllerReconcileTransportFailureSchedulesTypedRetryAndFallsBackWhenNoTrustworthyPrior's
// exact scenario and proves it audits situation.assessment_failed (the
// transport-layer outcome) and situation.assessment_fallback (the
// resulting deterministic_fallback commit, no trustworthy prior exists) —
// never assessment_rejected or assessment_authoritative.
func TestControllerReconcileAuditsAssessmentFailedAndFallback(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, errors.New("dial tcp: connection refused")
		},
	}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !audit.has("situation.assessment_failed") {
		t.Fatalf("audit kinds = %v, want situation.assessment_failed", audit.kinds)
	}
	if !audit.has("situation.assessment_fallback") {
		t.Fatalf("audit kinds = %v, want situation.assessment_fallback", audit.kinds)
	}
	if audit.has("situation.assessment_rejected") || audit.has("situation.assessment_authoritative") {
		t.Fatalf("audit kinds = %v, want no rejected/authoritative event for a transport failure", audit.kinds)
	}
}

// TestControllerReconcileAuditsAssessmentStaleOnStaleClaimAfterAcceptedCall
// mirrors TestControllerReconcileStaleCommitAfterAcceptedCallRetainsSanitizedStaleOutcome's
// exact scenario (a real L2 call succeeds, but the fenced commit fails
// closed on a stale claim) and proves it audits situation.assessment_stale —
// the late/stale completion race — never assessment_failed: the model work
// itself did not fail.
func TestControllerReconcileAuditsAssessmentStaleOnStaleClaimAfterAcceptedCall(t *testing.T) {
	in := ctBaseSnapshotInput()
	sentinel := errors.New("stale claim")
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0, commitErr: sentinel}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); !errors.Is(err, sentinel) {
		t.Fatalf("Reconcile err = %v, want to wrap %v", err, sentinel)
	}

	if !audit.has("situation.assessment_stale") {
		t.Fatalf("audit kinds = %v, want situation.assessment_stale", audit.kinds)
	}
	if audit.has("situation.assessment_failed") {
		t.Fatalf("audit kinds = %v, want no assessment_failed: the model call itself succeeded", audit.kinds)
	}
}

// TestControllerReconcileAuditsAssessmentReusedOnUnchangedTrustworthyBasis
// mirrors TestControllerReconcileUnchangedTrustworthyBasisReusesWithZeroL2Calls's
// exact scenario and proves it audits situation.assessment_reused with zero
// L2 dispatch — never assessment_call_dispatched, assessment_authoritative,
// or assessment_fallback.
func TestControllerReconcileAuditsAssessmentReusedOnUnchangedTrustworthyBasis(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Now = ctBaseTime.Add(10 * time.Minute)
	snap := situation.BuildSnapshot(in)
	prior := &situation.AuthoritativeAssessment{
		ID: "assessment-prior", SituationID: "situation-1",
		AssessmentBasisHash: snap.AssessmentBasisHash, MaterialFactHash: snap.MaterialFactHash,
		InputVersion: 2, Derivation: model.DerivationModelValidated,
		Assessment: model.Assessment{
			SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
			Impact: model.ImpactSuspected, Novelty: model.NoveltyFamiliar, Causality: model.CausalityCorrelated,
			Attention: model.AttentionObserve, Lifecycle: model.LifecycleActive,
			EvidenceQuality: model.EvidenceQualityComplete, Cadence: model.CadenceSlow,
			ActionContract: model.ActionContract{NextActor: model.NextActorNone, NextUpdateAt: &ctBaseTime},
		},
	}
	in.CurrentAssessment = prior
	store := &fakeControllerStore{loadInput: in}
	client := &fakeAssessmentClient{}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0", client.calls)
	}
	if !audit.has("situation.assessment_reused") {
		t.Fatalf("audit kinds = %v, want situation.assessment_reused", audit.kinds)
	}
	if audit.has("situation.assessment_call_dispatched") || audit.has("situation.assessment_authoritative") || audit.has("situation.assessment_fallback") {
		t.Fatalf("audit kinds = %v, want no dispatch/authoritative/fallback event for a zero-L2-call reuse", audit.kinds)
	}
}

// ----------------------------------------------------------------------
// Task 9 fix round, Finding #4: duration_ms and provider_request_started
// must carry REAL values measured from an actual call, not a
// hand-constructed fixture that only proves the audit payload KEY is
// present. These tests mirror the reviewer's own diagnostic method: a fake
// client with a controlled, non-trivial (non-zero, easy to distinguish from
// a bug that always reports 0) Latency, verifying the resulting audit
// payload reflects it exactly — across every call-backed outcome
// (authoritative/rejected/failed/stale).
// ----------------------------------------------------------------------

// acceptedResponseWithLatency mirrors acceptedResponse but stamps a
// caller-controlled llm.Completion.Latency — the field a real provider
// client (internal/llm/anthropic, internal/llm/openaicompat) always
// populates from its own measured c.now().Sub(start), on every CompleteOnce
// outcome, success or failure alike.
func acceptedResponseWithLatency(t *testing.T, latency time.Duration) func() (llm.OneShotCompletion, error) {
	t.Helper()
	raw := acceptedProposalJSON(t)
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "test-model", Latency: latency},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

// policyRejectedResponseWithLatency mirrors policyRejectedResponse but
// stamps a caller-controlled Latency, for the same reason as
// acceptedResponseWithLatency above.
func policyRejectedResponseWithLatency(t *testing.T, latency time.Duration) func() (llm.OneShotCompletion, error) {
	t.Helper()
	p := model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained,
		Impact:        model.ImpactSuspected,
		Novelty:       model.NoveltyFamiliar,
		Causality:     model.CausalityCorrelated,
		Attention:     model.AttentionUrgent,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy-rejected proposal: %v", err)
	}
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "test-model", Latency: latency},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

// payloadOfKind returns the map[string]any payload of the first record in
// audit matching kind, failing the test if none matches or the payload is
// not a map.
func payloadOfKind(t *testing.T, audit *fakeAuditSink, kind string) map[string]any {
	t.Helper()
	for i, k := range audit.kinds {
		if k != kind {
			continue
		}
		payload, ok := audit.payloads[i].(map[string]any)
		if !ok {
			t.Fatalf("payload for %q type = %T, want map[string]any", kind, audit.payloads[i])
		}
		return payload
	}
	t.Fatalf("audit kinds = %v, want to find %q", audit.kinds, kind)
	return nil
}

// TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnAuthoritative
// mirrors TestControllerReconcileAuditsAssessmentCallDispatchedAndAuthoritative's
// exact scenario but with a controlled, non-trivial fake-client Latency,
// proving situation.assessment_authoritative's own duration_ms/
// provider_request_started reflect that REAL measured call — not the
// structurally-always-zero duration a same-clock-read CreatedAt/CompletedAt
// pair produced before this fix.
func TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnAuthoritative(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	const latency = 250 * time.Millisecond
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponseWithLatency(t, latency)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	payload := payloadOfKind(t, audit, "situation.assessment_authoritative")
	if got := payload["duration_ms"]; got != latency.Milliseconds() {
		t.Fatalf("duration_ms = %v, want %d (the fake client's own scripted Latency)", got, latency.Milliseconds())
	}
	if got := payload["provider_request_started"]; got != "true" {
		t.Fatalf("provider_request_started = %v, want true (a real call was made)", got)
	}
}

// TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnRejected
// mirrors TestControllerReconcileAuditsAssessmentRejectedOnPolicyRejection's
// exact scenario but with a controlled fake-client Latency, proving
// situation.assessment_rejected's own duration_ms/provider_request_started
// reflect the REAL measured call that produced the rejected outcome.
func TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnRejected(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	const latency = 175 * time.Millisecond
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){policyRejectedResponseWithLatency(t, latency)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	payload := payloadOfKind(t, audit, "situation.assessment_rejected")
	if got := payload["duration_ms"]; got != latency.Milliseconds() {
		t.Fatalf("duration_ms = %v, want %d (the fake client's own scripted Latency)", got, latency.Milliseconds())
	}
	if got := payload["provider_request_started"]; got != "true" {
		t.Fatalf("provider_request_started = %v, want true (a real call was made)", got)
	}
}

// TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnFailed
// mirrors TestControllerReconcileAuditsAssessmentFailedAndFallback's exact
// scenario but with a controlled fake-client Latency stamped on the
// transport-failure outcome, proving situation.assessment_failed's own
// duration_ms/provider_request_started reflect the real measured call
// attempt even though it ultimately failed transport-side.
func TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnFailed(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	const latency = 90 * time.Millisecond
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{
				Completion:     llm.Completion{Latency: latency},
				RequestStarted: llm.RequestStartStatusUnknown,
			}, errors.New("dial tcp: connection refused")
		},
	}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	payload := payloadOfKind(t, audit, "situation.assessment_failed")
	if got := payload["duration_ms"]; got != latency.Milliseconds() {
		t.Fatalf("duration_ms = %v, want %d (the fake client's own scripted Latency)", got, latency.Milliseconds())
	}
	if got := payload["provider_request_started"]; got != string(llm.RequestStartStatusUnknown) {
		t.Fatalf("provider_request_started = %v, want %q (ambiguous transport failure)", got, llm.RequestStartStatusUnknown)
	}
}

// TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnStale
// mirrors TestControllerReconcileAuditsAssessmentStaleOnStaleClaimAfterAcceptedCall's
// exact scenario but with a controlled fake-client Latency, proving
// situation.assessment_stale's own duration_ms/provider_request_started
// reflect the real measured call that succeeded before the fenced commit
// itself lost the race.
func TestControllerReconcileAuditsRealDurationAndProviderRequestStartedOnStale(t *testing.T) {
	in := ctBaseSnapshotInput()
	sentinel := errors.New("stale claim")
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0, commitErr: sentinel}
	const latency = 300 * time.Millisecond
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponseWithLatency(t, latency)}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); !errors.Is(err, sentinel) {
		t.Fatalf("Reconcile err = %v, want to wrap %v", err, sentinel)
	}

	payload := payloadOfKind(t, audit, "situation.assessment_stale")
	if got := payload["duration_ms"]; got != latency.Milliseconds() {
		t.Fatalf("duration_ms = %v, want %d (the fake client's own scripted Latency)", got, latency.Milliseconds())
	}
	if got := payload["provider_request_started"]; got != "true" {
		t.Fatalf("provider_request_started = %v, want true (a real call succeeded before the stale race)", got)
	}
}

// TestControllerReconcileAuditsTriageRequested mirrors
// TestControllerReconcileTriageRequestAndAssessmentShareOneCommit's exact
// scenario and proves the shared commit audits situation.triage_requested
// alongside its Assessment event.
func TestControllerReconcileAuditsTriageRequested(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Incidents[0].Triage.Phase = "awaiting_decision"
	store := &fakeControllerStore{loadInput: in}
	client := &fakeAssessmentClient{}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !audit.has("situation.triage_requested") {
		t.Fatalf("audit kinds = %v, want situation.triage_requested", audit.kinds)
	}
	if audit.has("situation.triage_skipped") {
		t.Fatalf("audit kinds = %v, want no triage_skipped for a fresh request decision", audit.kinds)
	}
}

// TestControllerReconcileAppendOutcomeFailureAbortsBeforeAuditAndCorrection
// proves a failed AppendAssessmentOutcome aborts the cycle at that exact
// point: the reconcile returns the store error, no assessment_rejected/
// _failed audit event is emitted for an outcome SQLite does not hold (audit
// follows the durable write, never precedes it), the one immediate
// correction call the malformed draft would otherwise have earned is never
// dispatched, and nothing is committed.
func TestControllerReconcileAppendOutcomeFailureAbortsBeforeAuditAndCorrection(t *testing.T) {
	in := ctBaseSnapshotInput()
	sentinel := errors.New("disk I/O error")
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0, outcomeErr: sentinel}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		malformedResponse(), acceptedResponse(t),
	}}
	audit := &fakeAuditSink{}
	c := ctControllerWithAudit(t, store, client, audit)

	err := c.Reconcile(context.Background(), ctBaseClaim())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Reconcile error = %v, want it to wrap the append failure %v", err, sentinel)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 — no correction call after the outcome append failed", client.calls)
	}
	if len(store.outcomeCalls) != 1 {
		t.Fatalf("AppendAssessmentOutcome calls = %d, want 1", len(store.outcomeCalls))
	}
	if len(store.commits) != 0 {
		t.Fatalf("commits = %d, want 0 — nothing may be committed after the durable outcome record failed", len(store.commits))
	}
	if !audit.has("situation.assessment_call_dispatched") {
		t.Fatalf("audit kinds = %v, want the dispatch itself (its call row DID commit) to be audited", audit.kinds)
	}
	for _, kind := range []string{"situation.assessment_rejected", "situation.assessment_failed", "situation.assessment_fallback", "situation.assessment_authoritative"} {
		if audit.has(kind) {
			t.Fatalf("audit kinds = %v, want no %s — the audit log must never claim an outcome SQLite lacks", audit.kinds, kind)
		}
	}
}
