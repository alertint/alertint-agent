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

func TestCall2FailureDegradesOnly(t *testing.T) {
	tr := newTrackerOnly(t)
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "inc-1").Finish(context.DeadlineExceeded)
	if s := tr.Snapshot(); s.State != llmhealth.StateDegraded || s.Reason != llmhealth.ReasonTimeout {
		t.Fatalf("%+v", s)
	}
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-2").Finish(nil) // call 1 success does not clear call 2
	if s := tr.Snapshot(); s.State != llmhealth.StateDegraded {
		t.Fatalf("call-1 success cleared call-2 failure: %+v", s)
	}
	tr.Begin(llmhealth.CapabilityVerificationRejudge, "inc-2").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("%+v", s)
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
	tr.ObserveProbe(llm.ProbeResult{Outcome: llm.ProbeFailed, Method: "GET", Path: "/health", Err: err503})
	tr.Begin(llmhealth.CapabilityTriageDraft, "inc-1").Finish(nil)
	if s := tr.Snapshot(); s.State != llmhealth.StateHealthy {
		t.Fatalf("real call-1 success must clear a probe failure: %+v", s)
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
