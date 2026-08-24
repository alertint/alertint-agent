// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// failingSink errors on the first `failures` OnIncidentReady calls and
// succeeds afterwards, recording every call.
type failingSink struct {
	mu       sync.Mutex
	failures int
	calls    []string
	onCall   func() // optional hook run inside each call (e.g. advance the clock)
}

func (s *failingSink) OnIncidentReady(_ context.Context, inc store.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onCall != nil {
		s.onCall()
	}
	s.calls = append(s.calls, inc.ID)
	if len(s.calls) <= s.failures {
		return errors.New("acutetriage: llm: connection refused")
	}
	return nil
}

func (s *failingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// exhaustCapture records every triage-exhausted event the correlator emits.
type exhaustCapture struct {
	events []notify.TriageExhaustedEvent
}

func (e *exhaustCapture) OnTriageExhausted(_ context.Context, ev notify.TriageExhaustedEvent) error {
	e.events = append(e.events, ev)
	return nil
}

// retryHarness drives flushExpired by hand with a fake clock.
type retryHarness struct {
	t       *testing.T
	st      *store.Store
	cor     *correlator.Correlator
	sink    *failingSink
	exhaust *exhaustCapture
	inc     store.Incident
	now     time.Time
}

// newRetryHarness inserts one overdue collecting incident (with a member
// alert) and a correlator whose sink fails the first `failures` calls.
func newRetryHarness(t *testing.T, failures int) *retryHarness {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	past := time.Now().UTC().Add(-10 * time.Second)
	inc := store.Incident{
		ID:           uuid.NewString(),
		GroupKey:     "alertname=Retry",
		FirstAlertAt: past,
		LastAlertAt:  past,
		ReadyAt:      past,
		AlertCount:   0, // AddAlertToIncident below brings it to 1
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	a := newAlert("fp-retry", map[string]string{"alertname": "Retry"}, past)
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, inc.ID, a.ID, a.ReceivedAt); err != nil {
		t.Fatalf("add alert to incident: %v", err)
	}

	h := &retryHarness{
		t: t, st: st, sink: &failingSink{failures: failures}, exhaust: &exhaustCapture{},
		inc: inc, now: time.Now().UTC(),
	}
	h.cor = correlator.New(correlator.Config{WindowSeconds: 60}, st, h.sink, nil)
	h.cor.SetNow(func() time.Time { return h.now })
	h.cor.SetTriageFailureNotifier(h.exhaust)
	return h
}

func (h *retryHarness) flush() {
	h.t.Helper()
	if err := h.cor.FlushExpired(context.Background()); err != nil {
		h.t.Fatalf("flush: %v", err)
	}
}

func (h *retryHarness) status() string {
	h.t.Helper()
	got, err := h.st.GetIncidentByID(context.Background(), h.inc.ID)
	if err != nil {
		h.t.Fatalf("get incident: %v", err)
	}
	if got == nil {
		h.t.Fatalf("incident %s vanished", h.inc.ID)
	}
	return got.Status
}

func (h *retryHarness) wantCalls(n int, when string) {
	h.t.Helper()
	if got := h.sink.count(); got != n {
		h.t.Fatalf("%s: sink calls = %d, want %d", when, got, n)
	}
}

func (h *retryHarness) wantExhaustEvents(n int, when string) {
	h.t.Helper()
	if got := len(h.exhaust.events); got != n {
		h.t.Fatalf("%s: triage-exhausted events = %d, want %d", when, got, n)
	}
}

// TestTriageRetryAfterSinkError: one failed dispatch is retried after the
// first backoff delay, and a successful retry ends the schedule.
func TestTriageRetryAfterSinkError(t *testing.T) {
	h := newRetryHarness(t, 1)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if s := h.status(); s != "ready" {
		t.Fatalf("status after failed dispatch = %q, want ready", s)
	}

	// Same instant, and just short of the delay: not due yet.
	h.flush()
	h.now = h.now.Add(correlator.TriageRetryDelays[0] - time.Second)
	h.flush()
	h.wantCalls(1, "before first delay elapsed")

	h.now = h.now.Add(time.Second)
	h.flush()
	h.wantCalls(2, "first retry")
	if s := h.status(); s != "ready" {
		t.Fatalf("status after successful retry = %q, want ready (sink is a fake; skill persists)", s)
	}

	// Success cleared the retry state: nothing more is dispatched, ever.
	h.now = h.now.Add(2 * time.Hour)
	h.flush()
	h.wantCalls(2, "after success")
}

// TestTriageExhaustsToFailed: a sink that never recovers is retried through
// the whole schedule, then the incident is closed out as "failed".
func TestTriageExhaustsToFailed(t *testing.T) {
	h := newRetryHarness(t, 1000)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	for i, d := range correlator.TriageRetryDelays {
		if s := h.status(); s != "ready" {
			t.Fatalf("status before retry %d = %q, want ready", i+1, s)
		}
		h.now = h.now.Add(d)
		h.flush()
		h.wantCalls(i+2, "retry")
	}
	if s := h.status(); s != "failed" {
		t.Fatalf("status after exhausting retries = %q, want failed", s)
	}
	h.wantExhaustEvents(1, "after exhaustion")
	ev := h.exhaust.events[0]
	if ev.IncidentID != h.inc.ID || ev.GroupKey != h.inc.GroupKey || ev.AlertCount != 1 ||
		ev.Attempts != len(correlator.TriageRetryDelays)+1 || ev.Error == "" {
		t.Fatalf("triage-exhausted event = %+v", ev)
	}

	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	h.wantCalls(len(correlator.TriageRetryDelays)+1, "after exhaustion")
	h.wantExhaustEvents(1, "much later")
}

// TestTriageRetrySkipsIncidentThatLeftReady: an incident resolved while a
// retry is pending is dropped without another sink call and keeps its status.
func TestTriageRetrySkipsIncidentThatLeftReady(t *testing.T) {
	h := newRetryHarness(t, 1000)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if err := h.st.MarkIncidentResolved(context.Background(), h.inc.ID); err != nil {
		t.Fatalf("mark resolved: %v", err)
	}

	h.now = h.now.Add(correlator.TriageRetryDelays[0])
	h.flush()
	h.wantCalls(1, "after resolution")
	if s := h.status(); s != "resolved" {
		t.Fatalf("status = %q, want resolved", s)
	}

	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	h.wantCalls(1, "much later")
	h.wantExhaustEvents(0, "incident resolved, never exhausted")
}

// TestTriageNoRetryOnCleanSkip: a sink that returns nil (the skill skipping
// below min_alerts, say) is never re-dispatched.
func TestTriageNoRetryOnCleanSkip(t *testing.T) {
	h := newRetryHarness(t, 0)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	h.wantCalls(1, "much later")
	if s := h.status(); s != "ready" {
		t.Fatalf("status = %q, want ready", s)
	}
}

// TestTriageBackoffCountsFromAfterTheCall: a sink call that itself outlasts
// the backoff delay must not be followed by an immediate second call in the
// same flush — the deadline is taken after the call returns.
func TestTriageBackoffCountsFromAfterTheCall(t *testing.T) {
	h := newRetryHarness(t, 1000)
	slow := correlator.TriageRetryDelays[0] + time.Second
	h.sink.onCall = func() { h.now = h.now.Add(slow) }

	h.flush()
	h.wantCalls(1, "initial dispatch (slow)")

	// Just short of one full delay after the call returned: not due.
	h.now = h.now.Add(correlator.TriageRetryDelays[0] - time.Second)
	h.flush()
	h.wantCalls(1, "before delay elapsed since call end")

	h.now = h.now.Add(time.Second)
	h.flush()
	h.wantCalls(2, "first retry")
}

// TestTriageExhaustedWriteIsRetriedUntilItSucceeds: when the terminal
// "failed" write fails, the incident keeps its retry entry and the write —
// not the sink call — is re-attempted on a later tick.
func TestTriageExhaustedWriteIsRetriedUntilItSucceeds(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()
	delays := correlator.TriageRetryDelays
	attempts := len(delays) + 1

	h.flush()
	for _, d := range delays[:len(delays)-1] {
		h.now = h.now.Add(d)
		h.flush()
	}
	h.wantCalls(attempts-1, "before last attempt")

	// Make every write fail; the store runs on a single connection so the
	// pragma sticks for the calls below.
	if _, err := h.st.DB().ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
		t.Fatalf("query_only on: %v", err)
	}
	h.now = h.now.Add(delays[len(delays)-1])
	h.flush()
	h.wantCalls(attempts, "last attempt")
	if s := h.status(); s != "ready" {
		t.Fatalf("status with failing write = %q, want ready", s)
	}

	// Write still failing: no sink call, no status change, entry retained.
	h.now = h.now.Add(delays[0])
	h.flush()
	h.wantCalls(attempts, "write retry while store read-only")
	if s := h.status(); s != "ready" {
		t.Fatalf("status = %q, want ready", s)
	}
	h.wantExhaustEvents(0, "while the terminal write keeps failing")

	if _, err := h.st.DB().ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatalf("query_only off: %v", err)
	}
	h.now = h.now.Add(delays[0])
	h.flush()
	h.wantCalls(attempts, "write retry after store recovered")
	if s := h.status(); s != "failed" {
		t.Fatalf("status after write recovered = %q, want failed", s)
	}
	h.wantExhaustEvents(1, "once the terminal write succeeded")

	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	h.wantCalls(attempts, "after terminal write")
	h.wantExhaustEvents(1, "after terminal write")
}

// TestStartupRecoveryRedispatchesReadyIncidents: an incident left in "ready"
// by a previous process is dispatched once on the first tick after Start and,
// if that fails, enters the normal schedule.
func TestStartupRecoveryRedispatchesReadyIncidents(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()
	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	h.flush()
	h.wantCalls(1, "first tick after start")
	if s := h.status(); s != "ready" {
		t.Fatalf("status = %q, want ready", s)
	}

	h.now = h.now.Add(correlator.TriageRetryDelays[0] - time.Second)
	h.flush()
	h.wantCalls(1, "before first delay")
	h.now = h.now.Add(time.Second)
	h.flush()
	h.wantCalls(2, "first retry after recovered dispatch")
}

// TestStartupRecoveryCleanSkipIsDispatchedOnce: a legitimately-ready incident
// (the skill returns nil) costs one sink call per restart and nothing more.
func TestStartupRecoveryCleanSkipIsDispatchedOnce(t *testing.T) {
	h := newRetryHarness(t, 0)
	ctx := context.Background()
	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	h.flush()
	h.wantCalls(1, "first tick after start")
	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	h.wantCalls(1, "much later")
	if s := h.status(); s != "ready" {
		t.Fatalf("status = %q, want ready", s)
	}
}
