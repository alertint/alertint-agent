// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
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
