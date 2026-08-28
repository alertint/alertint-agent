// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

func healthFixture(t *testing.T) (context.Context, *store.Store, *llmhealth.Tracker, store.Incident) {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	tr, err := llmhealth.New(ctx, st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-1", map[string]string{"alertname": "DiskFull", "host": "web1"})
	inc.AlertCount = 1
	return ctx, st, tr, inc
}

func TestCall1TransportFailureObservedAsTriageDraft(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	failing := &fakeLLM{err: &llm.RetryableError{StatusCode: 503}}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr}, st, failing, nil, nil, nil)

	if err := sk.Run(ctx, inc); err == nil {
		t.Fatal("want error")
	}
	s := tr.Snapshot()
	if s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonProviderUnavailable || len(s.Capabilities) != 1 || s.Capabilities[0].Capability != llmhealth.CapabilityTriageDraft {
		t.Fatalf("%+v", s)
	}
	if s.InFlight != 0 {
		t.Fatal("in-flight leaked")
	}
}

func TestCall1MalformedTypedResponseObservedAfterDecode(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	// Passes RequiredKeys validation (all six keys present) but breaks the typed
	// decode: confidence is a string, llmResponse.Confidence is float64.
	bad := &fakeLLM{response: json.RawMessage(`{"analysis_name":"x","overall_issue":"y","correlation_findings":[],"severity":"low","confidence":"high","alerts":[]}`)}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr}, st, bad, nil, nil, nil)
	if err := sk.Run(ctx, inc); err == nil {
		t.Fatal("malformed typed response must fail the triage")
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("one malformed incident is not an outage: %+v", s)
	}
	inc2 := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc2.ID, "fp-2", map[string]string{"alertname": "DiskFull", "host": "web2"})
	inc2.AlertCount = 1
	_ = sk.Run(ctx, inc2)
	s := tr.Snapshot()
	if s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonResponseMalformed {
		t.Fatalf("two distinct incidents must corroborate: %+v", s)
	}
}

// TestCall1MalformedTypedResponseErrorCarriesReason pins that the error Run
// returns for a typed-decode failure is the SAME reason-bearing error the
// health tracker observed: both wrap llmhealth.ErrResponseMalformed, so the
// Correlator's durable triage row records response_malformed exactly as
// /health does, never a generic code that disagrees with it.
func TestCall1MalformedTypedResponseErrorCarriesReason(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	bad := &fakeLLM{response: json.RawMessage(`{"analysis_name":"x","overall_issue":"y","correlation_findings":[],"severity":"low","confidence":"high","alerts":[]}`)}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr}, st, bad, nil, nil, nil)

	err := sk.Run(ctx, inc)
	if err == nil {
		t.Fatal("malformed typed response must fail the triage")
	}
	if !errors.Is(err, llmhealth.ErrResponseMalformed) {
		t.Fatalf("Run error %v does not wrap ErrResponseMalformed", err)
	}
	if got := llmhealth.Classify(err); got != llmhealth.ReasonResponseMalformed {
		t.Fatalf("Classify(Run error) = %q, want response_malformed (what the tracker recorded)", got)
	}
}

func verificationEnvelope(t *testing.T, st *store.Store, id string) (outcome, reason string) {
	t.Helper()
	got, err := st.GetIncidentByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Verification struct {
			Outcome           string `json:"outcome"`
			DegradationReason string `json:"degradation_reason"`
		} `json:"verification"`
	}
	if err := json.Unmarshal([]byte(got.EnrichmentJSON), &env); err != nil {
		t.Fatalf("enrichment %q: %v", got.EnrichmentJSON, err)
	}
	return env.Verification.Outcome, env.Verification.DegradationReason
}

var verifyOn = acutetriage.VerificationParams{Enabled: true, MaxQueries: 1, QueryTimeoutSeconds: 1}

func TestCall2FailureDegradesAndPersistsReason(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	seq := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk", "disk full", 0.8, nil)},
		{err: &llm.RetryableError{StatusCode: 503}},
	}}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr, Verification: verifyOn}, st, seq, nil, nil, nil)
	if err := sk.Run(ctx, inc); err != nil {
		t.Fatalf("draft must ship: %v", err)
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateDegraded || s.Reason != llmhealth.ReasonProviderUnavailable {
		t.Fatalf("%+v", s)
	}
	if outcome, reason := verificationEnvelope(t, st, inc.ID); outcome != "degraded" || reason != acutetriage.DegradationLLMCallFailed {
		t.Fatalf("outcome=%q reason=%q", outcome, reason)
	}
}

func TestCall2MalformedIsLLMResponseInvalid(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	seq := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk", "disk full", 0.8, nil)},
		{raw: json.RawMessage(`{"analysis_name":1,"overall_issue":"y","correlation_findings":[],"severity":"low","confidence":0.5,"alerts":[]}`)},
	}}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr, Verification: verifyOn}, st, seq, nil, nil, nil)
	if err := sk.Run(ctx, inc); err != nil {
		t.Fatalf("draft must ship: %v", err)
	}
	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy || len(s.Capabilities) != 2 {
		t.Fatalf("one malformed re-judge is a content failure on one incident, not an outage: %+v", s)
	}
	for _, c := range s.Capabilities {
		if c.Capability == llmhealth.CapabilityVerificationRejudge && c.Reason != llmhealth.ReasonResponseMalformed {
			t.Fatalf("verification capability = %+v", c)
		}
	}
	if outcome, reason := verificationEnvelope(t, st, inc.ID); outcome != "degraded" || reason != acutetriage.DegradationLLMResponseInvalid {
		t.Fatalf("outcome=%q reason=%q", outcome, reason)
	}
}

func TestFloorUnfetchedIsVerificationSourceUnavailable(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	// No Prometheus/Zabbix querier wired → the floor cannot fetch; both LLM
	// calls succeed, so the LLM itself stays healthy.
	seq := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk", "disk full", 0.8, nil)},
		{raw: callTwoResp(t, "disk", "disk full", 0.8, "")},
	}}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr, Verification: verifyOn}, st, seq, nil, nil, nil)
	if err := sk.Run(ctx, inc); err != nil {
		t.Fatal(err)
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("%+v", s)
	}
	if outcome, reason := verificationEnvelope(t, st, inc.ID); outcome != "degraded" || reason != acutetriage.DegradationVerificationSourceUnavailable {
		t.Fatalf("outcome=%q reason=%q", outcome, reason)
	}
}

// TestClassifierFailureIsComponentOnly reuses classifierScenario in "shadow"
// mode with a classifier client whose Complete returns &llm.APIError{StatusCode:
// 401}: exactly one unhealthy capability (memory_classifier, auth_failed) and
// the aggregate stays healthy — the triage itself succeeded.
func TestClassifierFailureIsComponentOnly(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	tr, err := llmhealth.New(ctx, st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	classifierScenario(t, "shadow", nil, classifierOpts{err: &llm.APIError{StatusCode: 401}, health: tr})

	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy {
		t.Fatalf("classifier failure changed the aggregate: %+v", s)
	}
	var unhealthy []llmhealth.CapabilitySnapshot
	for _, c := range s.Capabilities {
		if !c.Healthy {
			unhealthy = append(unhealthy, c)
		}
	}
	if len(unhealthy) != 1 || unhealthy[0].Capability != llmhealth.CapabilityMemoryClassifier || unhealthy[0].Reason != llmhealth.ReasonAuthFailed {
		t.Fatalf("classifier must be reported independently, and the triage itself must have succeeded: %+v", s.Capabilities)
	}
}

func TestShutdownCancelDuringCall1LeavesHealthy(t *testing.T) {
	ctx, st, tr, inc := healthFixture(t)
	canceled := &fakeLLM{err: context.Canceled}
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Health: tr}, st, canceled, nil, nil, nil)
	if err := sk.Run(ctx, inc); err == nil {
		t.Fatal("want error")
	}
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || len(s.Capabilities) != 0 || s.InFlight != 0 {
		t.Fatalf("shutdown cancel must leave no trace: %+v", s)
	}
}
