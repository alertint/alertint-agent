// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
)

// clock is read from the Runner's own goroutine (TestRunWakesOnKick) and
// written from the test goroutine, so it needs its own lock distinct from
// the Tracker's.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type recAudit struct {
	kinds    []string
	payloads []map[string]any
}

func (a *recAudit) Append(_ context.Context, _ string, kind string, payload any) error {
	a.kinds = append(a.kinds, kind)
	if m, ok := payload.(map[string]any); ok {
		a.payloads = append(a.payloads, m)
	}
	return nil
}

func newTracker(t *testing.T) (*llmhealth.Tracker, *store.Store, *clock, *recAudit) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := &clock{t: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
	a := &recAudit{}
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, Auditor: a, BroadcastAfter: 5 * time.Minute, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return tr, st, c, a
}

// newTrackerOnly is newTracker for the common case: a test that needs only
// the Tracker itself, with no clock or audit assertions.
func newTrackerOnly(t *testing.T) *llmhealth.Tracker {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{
		Now:            time.Now,
		BroadcastAfter: 5 * time.Minute,
		IdleProbeAfter: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

var err503 = &llm.RetryableError{StatusCode: 503}

func TestCall1FailureMakesUnavailableAndOnlyCall1SuccessClears(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(err503)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonProviderUnavailable || s.Detail != "HTTP 503" || s.OutageGeneration != 1 {
		t.Fatalf("after call-1 failure: %+v", s)
	}
	// A probe success must NOT clear a real inference failure.
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/v1/models/x"})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("probe success cleared an inference failure: %+v", s)
	}
	// A classifier success must not clear it either.
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-2").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("classifier success cleared call-1 failure: %+v", s)
	}
	c.add(12 * time.Minute)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-3").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || s.OutageGeneration != 1 {
		t.Fatalf("after call-1 success: %+v", s)
	}
}

// capSnap returns capability's entry in s, failing the test if absent.
func capSnap(t *testing.T, s llmhealth.Snapshot, capability llmhealth.Capability) llmhealth.CapabilitySnapshot {
	t.Helper()
	for _, c := range s.Capabilities {
		if c.Capability == capability {
			return c
		}
	}
	t.Fatalf("capability %q absent from snapshot: %+v", capability, s.Capabilities)
	return llmhealth.CapabilitySnapshot{}
}

// TestCapabilityAssessmentDrivesUnavailableLikeTriageDraft proves Task 9's
// own wiring: the Situation controller's own L2 dispatch capability
// (CapabilityAssessment) is treated as a peer of CapabilityTriageDraft in
// the rolled-up installation state (spec.md: "LLM health remains one
// installation-level capability state fed by real Acute Triage and
// Assessment outcomes") — a failure there alone makes the installation
// unavailable, and neither a probe success nor a classifier success clears
// it; its own success does.
func TestCapabilityAssessmentDrivesUnavailableLikeTriageDraft(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	tr.Begin(llmhealth.CapabilityAssessment, "").Finish(err503)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.OutageGeneration != 1 {
		t.Fatalf("after assessment failure: %+v", s)
	}
	// A probe success must not clear a real assessment failure.
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/v1/models/x"})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("probe success cleared an assessment failure: %+v", s)
	}
	// A classifier success must not clear it either — the classifier may
	// run on a separate model/client and proves nothing about the primary.
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-1").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("classifier success cleared an assessment failure: %+v", s)
	}
	c.add(12 * time.Minute)
	tr.Begin(llmhealth.CapabilityAssessment, "").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || s.OutageGeneration != 1 {
		t.Fatalf("after assessment success: %+v", s)
	}
}

func TestCall2FailureDegradesOnly(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "inc-1").Finish(context.DeadlineExceeded)
	if s := tr.Snapshot(); s.State != llmhealth.StateDegraded || s.Reason != llmhealth.ReasonTimeout {
		t.Fatalf("%+v", s)
	}
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-2").Finish(nil) // a classifier success never clears a primary failure
	if s := tr.Snapshot(); s.State != llmhealth.StateDegraded {
		t.Fatalf("classifier success cleared call-2 failure: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "inc-2").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("%+v", s)
	}
}

// TestSharedPrimarySuccessClearsDependencyFailuresAcrossCapabilities pins
// the lab-F10 rule: the capabilities served by the shared primary client
// (triage_draft, assessment, verification_rejudge, query_repair) recover
// together from a dependency-class failure on a real success on any one of
// them, because that success proves the shared transport/provider is back.
// The capability that was not actually called keeps its own last_success_at
// (never fabricated) and its last_failure_at.
func TestSharedPrimarySuccessClearsDependencyFailuresAcrossCapabilities(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	failAt := c.now()
	tr.Begin(llmhealth.CapabilityAssessment, "").Finish(context.DeadlineExceeded)
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "inc-0").Finish(err503)
	tr.ProbeDue(c.now()) // reserve the activity generation, as the Runner does before a probe
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/health", Err: err503})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.OutageGeneration != 1 {
		t.Fatalf("after assessment timeout: %+v", s)
	}

	c.add(10 * time.Second)
	successAt := c.now()
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(nil)
	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy || s.OutageGeneration != 1 {
		t.Fatalf("a Triage-draft success must clear the shared primary's dependency failures: %+v", s)
	}
	for _, capability := range []llmhealth.Capability{llmhealth.CapabilityAssessment, llmhealth.CapabilityVerificationRejudge, llmhealth.CapabilityProbe} {
		cs := capSnap(t, s, capability)
		if !cs.Healthy || cs.Reason != "" || cs.Detail != "" || cs.UnhealthySince != nil {
			t.Fatalf("%s must be healthy again with no residual reason: %+v", capability, cs)
		}
		if cs.LastSuccessAt != nil {
			t.Fatalf("%s was never called successfully; last_success_at must stay unset, got %v", capability, *cs.LastSuccessAt)
		}
		if cs.LastFailureAt == nil || !cs.LastFailureAt.Equal(failAt) {
			t.Fatalf("%s must keep its own last_failure_at %v: %+v", capability, failAt, cs)
		}
	}
	if cs := capSnap(t, s, llmhealth.CapabilityTriageDraft); cs.LastSuccessAt == nil || !cs.LastSuccessAt.Equal(successAt) {
		t.Fatalf("the capability that actually succeeded records its own last_success_at: %+v", cs)
	}

	// The rule is symmetric: an assessment success clears a Triage-draft
	// dependency failure the same way (the lab's real recovery order).
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-2").Finish(err503)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.OutageGeneration != 2 {
		t.Fatalf("second outage: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityAssessment, "").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || s.OutageGeneration != 2 {
		t.Fatalf("an assessment success must clear a Triage-draft dependency failure: %+v", s)
	}
}

// TestSharedPrimarySuccessKeepsContentFailuresCapabilityLocal: a
// corroborated content-class failure says the model's OUTPUT for that
// capability is unusable, not that the provider is unreachable — another
// capability's success proves nothing about it, so only its own success
// clears it. A dependency failure recorded on the same record after the
// content verdict is likewise not cleared, because the record's reason is
// still the content one.
func TestSharedPrimarySuccessKeepsContentFailuresCapabilityLocal(t *testing.T) {
	tr := newTrackerOnly(t)
	malformed := errors.Join(llmhealth.ErrResponseMalformed, errors.New("unexpected end of JSON"))
	tr.Begin(llmhealth.CapabilityAssessment, "sit-1").Finish(malformed)
	tr.Begin(llmhealth.CapabilityAssessment, "sit-2").Finish(malformed)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonResponseMalformed {
		t.Fatalf("two subjects must corroborate an assessment content failure: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(nil)
	s := tr.Snapshot()
	if s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonResponseMalformed {
		t.Fatalf("a Triage-draft success must not clear an assessment content failure: %+v", s)
	}
	if cs := capSnap(t, s, llmhealth.CapabilityAssessment); cs.Healthy {
		t.Fatalf("assessment must stay unhealthy on its content verdict: %+v", cs)
	}
	tr.Begin(llmhealth.CapabilityAssessment, "sit-3").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("only its own success clears a content failure: %+v", s)
	}
}

// TestClassifierAndProbeNeverCrossTheSharedPrimaryBoundary: memory_classifier
// is outside the shared-primary rule in both directions (it may run on a
// separate model/client), and probe is a receiver only — a probe success
// never clears a real inference failure.
func TestClassifierAndProbeNeverCrossTheSharedPrimaryBoundary(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-0").Finish(err503)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(context.DeadlineExceeded)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("after Triage-draft timeout: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-2").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("a classifier success must not clear a primary inference failure: %+v", s)
	}
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("a probe success must not clear a primary inference failure: %+v", s)
	}
	// Re-fail the classifier, then recover the primary: the classifier's own
	// dependency failure is untouched by the primary's success.
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-3").Finish(err503)
	tr.Begin(llmhealth.CapabilityAssessment, "").Finish(nil)
	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy {
		t.Fatalf("an assessment success clears the Triage-draft timeout: %+v", s)
	}
	if cs := capSnap(t, s, llmhealth.CapabilityMemoryClassifier); cs.Healthy {
		t.Fatalf("a primary success must not clear the classifier's own failure: %+v", cs)
	}
}

func TestClassifierNeverChangesAggregate(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.Begin(llmhealth.CapabilityMemoryClassifier, "inc-1").Finish(&llm.APIError{StatusCode: 401})
	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy {
		t.Fatalf("classifier failure changed aggregate: %+v", s)
	}
	if len(s.Capabilities) != 1 || s.Capabilities[0].Capability != llmhealth.CapabilityMemoryClassifier || s.Capabilities[0].Healthy {
		t.Fatalf("classifier must be reported independently: %+v", s.Capabilities)
	}
}

func TestShutdownCancelIsIgnored(t *testing.T) {
	tr, _, _, a := newTracker(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(context.Canceled)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || len(s.Capabilities) != 0 || len(a.kinds) != 0 {
		t.Fatalf("cancel produced state: %+v audits=%v", s, a.kinds)
	}
}

func TestContentFailureNeedsTwoSubjects(t *testing.T) {
	tr := newTrackerOnly(t)
	malformed := errors.Join(llmhealth.ErrResponseMalformed, errors.New("unexpected end of JSON"))
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(malformed)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(malformed) // retry of the same Incident
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("one bad incident is not an outage: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-2").Finish(malformed)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonResponseMalformed {
		t.Fatalf("two distinct subjects must corroborate: %+v", s)
	}
}

// TestContentFailureNeverMasksDependencyOutageReason: a capability already
// unhealthy from a real dependency failure keeps that reason/detail through
// an uncorroborated (single-subject) content failure — aggregate() reads
// the capability's own ReasonCode/Detail for any unhealthy capability, so
// overwriting it here would report the wrong outage cause mid-incident.
func TestContentFailureNeverMasksDependencyOutageReason(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(err503)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonProviderUnavailable {
		t.Fatalf("after dependency failure: %+v", s)
	}
	malformed := errors.Join(llmhealth.ErrResponseMalformed, errors.New("unexpected end of JSON"))
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-2").Finish(malformed)
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonProviderUnavailable {
		t.Fatalf("one uncorroborated content failure must not mask the ongoing dependency outage reason: %+v", s)
	}
}

// TestContentFailureCorroborationSurvivesRestart covers H1/H5's durability
// requirement for the two-distinct-Incident corroboration evidence itself:
// a content failure recorded just before a restart, plus one on a different
// Incident just after, must still corroborate — an outage episode spans
// restarts, so the evidence backing it must too.
func TestContentFailureCorroborationSurvivesRestart(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	malformed := errors.Join(llmhealth.ErrResponseMalformed, errors.New("unexpected end of JSON"))
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(malformed)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("one bad incident is not an outage: %+v", s)
	}

	// Restart: a fresh Tracker loads off the same durable store.
	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tr2.Begin(llmhealth.CapabilityTriageDraft, "inc-2").Finish(malformed)
	if s := tr2.Snapshot(); s.State != llmhealth.StateUnavailable || s.Reason != llmhealth.ReasonResponseMalformed {
		t.Fatalf("corroboration evidence from before the restart must still count: %+v", s)
	}
}

func TestProbeFailureMakesUnavailableUntilRealSuccess(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/health", Err: err503})
	if s := tr.Snapshot(); s.State != llmhealth.StateUnavailable {
		t.Fatalf("%+v", s)
	}
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeOK, Method: "GET", Path: "/health"})
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("probe success must clear a probe failure: %+v", s)
	}
	probeOKAt := capSnap(t, tr.Snapshot(), llmhealth.CapabilityProbe).LastSuccessAt
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/health", Err: err503})
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(nil)
	s := tr.Snapshot()
	if s.State != llmhealth.StateHealthy {
		t.Fatalf("real call-1 success must clear a probe failure: %+v", s)
	}
	// The probe itself did not succeed: its last_success_at is still the
	// earlier real probe OK, never the inference call's time.
	if cs := capSnap(t, s, llmhealth.CapabilityProbe); probeOKAt == nil || cs.LastSuccessAt == nil || !cs.LastSuccessAt.Equal(*probeOKAt) {
		t.Fatalf("probe last_success_at must be its own earlier OK %v, got %+v", probeOKAt, cs)
	}
}

func TestProbeUnsupportedIsNotFailure(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeUnsupported, Method: "GET", Path: "/v1/models"})
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy || s.LastProbeOutcome != "unsupported" {
		t.Fatalf("%+v", s)
	}
	c.add(30 * time.Minute)
	if tr.ProbeDue(c.now()) {
		t.Fatal("unsupported probe route must stop probing")
	}
}

// TestProbeUnsupportedIsProcessLocalAndRechecked pins that "unsupported" is
// a suppression, not a permanent verdict: the route is re-validated once an
// hour in-process (a backend can be upgraded to expose a probe route), and
// never restored from the durable outcome across a restart (the endpoint or
// provider may have changed in config), so the first idle window after a
// restart probes again.
func TestProbeUnsupportedIsProcessLocalAndRechecked(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeUnsupported, Method: "GET", Path: "/v1/models"})
	c.add(time.Hour)
	if !tr.ProbeDue(c.now()) {
		t.Fatal("an unsupported route must be re-validated after an hour")
	}

	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now, IdleProbeAfter: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if tr2.ProbeDue(c.now()) {
		t.Fatal("not idle yet after restart")
	}
	c.add(5 * time.Minute)
	if !tr2.ProbeDue(c.now()) {
		t.Fatal("a restart must not inherit the previous process's unsupported verdict")
	}
}

func TestStatePersistsAndRestores(t *testing.T) {
	tr, st, c, _ := newTracker(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(err503)
	c.add(time.Minute)
	tr2, err := llmhealth.New(context.Background(), st, llmhealth.Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	s := tr2.Snapshot()
	if s.State != llmhealth.StateUnavailable || s.OutageGeneration != 1 || s.UnhealthySince == nil || s.InFlight != 0 {
		t.Fatalf("restored = %+v", s)
	}
	if s.Capabilities[0].Capability != llmhealth.CapabilityTriageDraft || s.Capabilities[0].Healthy {
		t.Fatalf("restored caps = %+v", s.Capabilities)
	}
}

func TestOutageGenerationAndAudit(t *testing.T) {
	tr, _, _, a := newTracker(t)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(nil)
	tr.Begin(llmhealth.CapabilityTriageDraft, "i").Finish(err503)
	if s := tr.Snapshot(); s.OutageGeneration != 2 {
		t.Fatalf("generation = %d, want 2", s.OutageGeneration)
	}
	want := []string{"llm.health.changed", "llm.health.changed", "llm.health.slack_suppressed", "llm.health.changed"}
	if len(a.kinds) != len(want) {
		t.Fatalf("audit kinds = %v", a.kinds)
	}
	for i := range want {
		if a.kinds[i] != want[i] {
			t.Fatalf("audit kinds = %v, want %v", a.kinds, want)
		}
	}
	for _, p := range a.payloads {
		for k := range p {
			if k == "prompt" || k == "body" || k == "error" {
				t.Fatalf("audit payload carries raw field %q", k)
			}
		}
	}
}

func TestInFlightAndIdle(t *testing.T) {
	tr, _, c, _ := newTracker(t)
	if tr.ProbeDue(c.now()) {
		t.Fatal("probe must not be due at boot")
	}
	c.add(5 * time.Minute)
	if !tr.ProbeDue(c.now()) {
		t.Fatal("probe due after idle interval")
	}
	obs := tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1")
	if tr.ProbeDue(c.now()) || tr.Snapshot().InFlight != 1 {
		t.Fatal("in-flight call must suppress the probe")
	}
	obs.Finish(nil)
	obs.Finish(nil) // idempotent
	if tr.Snapshot().InFlight != 0 || tr.ProbeDue(c.now()) {
		t.Fatal("completed call resets the idle clock")
	}
	c.add(5 * time.Minute)
	if !tr.ProbeDue(c.now()) {
		t.Fatal("probe due again after idle")
	}
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeOK})
	c.add(30 * time.Second)
	if tr.ProbeDue(c.now()) {
		t.Fatal("at most one probe per minute")
	}
	c.add(31 * time.Second)
	if !tr.ProbeDue(c.now()) {
		t.Fatal("probe due after a minute")
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *llmhealth.Tracker
	tr.Begin(llmhealth.CapabilityTriageDraft, "x").Finish(errors.New("boom"))
	var obs *llmhealth.Observation
	obs.Finish(nil)
}

// TestSealDropsObservationsAfterTheFinalAcknowledgment: Seal is the
// runner's guarantee that the state it acknowledged in its final pass is the
// state that survives. Owners join every producer before that pass, but a
// join can time out (a handler wedged past the shutdown window); a producer
// that then finishes must not move the durable state behind the
// acknowledgment, kick a runner that is gone, or write to a store that is
// closing. It is dropped and logged, whether it began before or after Seal.
func TestSealDropsObservationsAfterTheFinalAcknowledgment(t *testing.T) {
	tr, st, _, a := newTracker(t)
	before := tr.Begin(llmhealth.CapabilityTriageDraft, "i")
	tr.Seal()
	before.Finish(err503)
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "j").Finish(nil)
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Err: err503})

	snap := tr.Snapshot()
	if snap.State != llmhealth.StateHealthy || len(snap.Capabilities) != 0 || snap.LastRealSuccessAt != nil || snap.InFlight != 0 {
		t.Fatalf("sealed tracker moved: %+v", snap)
	}
	select {
	case <-tr.Kick():
		t.Fatal("sealed tracker kicked a runner that is gone")
	default:
	}
	rec, caps, err := st.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.LastRealCallAt != nil || len(caps) != 0 {
		t.Fatalf("sealed tracker persisted: rec=%+v caps=%d", rec, len(caps))
	}
	if len(a.kinds) != 0 {
		t.Fatalf("sealed tracker audited: %v", a.kinds)
	}
}
