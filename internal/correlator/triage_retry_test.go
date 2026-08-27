// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// failingSink errors on the first `failures` OnIncidentReady calls. After
// that it either performs a clean skip (returns nil without persisting,
// leaving the Incident "processing") or persists a Finding via
// SaveIncidentOutput, depending on cleanSkip.
type failingSink struct {
	mu        sync.Mutex
	failures  int
	cleanSkip bool
	calls     []string
	onCall    func() // optional hook run inside each call (e.g. advance the clock)
	st        *store.Store
}

func (s *failingSink) OnIncidentReady(ctx context.Context, inc store.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onCall != nil {
		s.onCall()
	}
	s.calls = append(s.calls, inc.ID)
	if len(s.calls) <= s.failures {
		return errors.New("acutetriage: llm: connection refused")
	}
	if s.cleanSkip {
		return nil
	}
	return s.st.SaveIncidentOutput(ctx, inc.ID, `{"ok":true}`, "n", "i", 0.5, "")
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

// insertCollectingIncident inserts a collecting incident for group `name`
// with one member alert, ready at readyAt.
func insertCollectingIncident(t *testing.T, st *store.Store, name string, readyAt time.Time) store.Incident {
	t.Helper()
	ctx := context.Background()
	inc := store.Incident{
		ID:           uuid.NewString(),
		GroupKey:     "alertname=" + name,
		FirstAlertAt: readyAt,
		LastAlertAt:  readyAt,
		ReadyAt:      readyAt,
		AlertCount:   0, // AddAlertToIncident below brings it to 1
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	a := newAlert("fp-"+name, map[string]string{"alertname": name}, readyAt)
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, inc.ID, a.ID, a.ReceivedAt); err != nil {
		t.Fatalf("add alert to incident: %v", err)
	}
	return inc
}

// newRetryHarness inserts one overdue collecting incident (with a member
// alert) and a correlator whose sink fails the first `failures` calls, then
// persists a Finding.
func newRetryHarness(t *testing.T, failures int) *retryHarness {
	t.Helper()
	return newRetryHarnessMode(t, failures, false)
}

// newRetryHarnessCleanSkip is like newRetryHarness but the sink never fails
// and never persists — every call is a clean skip (the skill's deterministic
// "nothing to say").
func newRetryHarnessCleanSkip(t *testing.T) *retryHarness {
	t.Helper()
	return newRetryHarnessMode(t, 0, true)
}

func newRetryHarnessMode(t *testing.T, failures int, cleanSkip bool) *retryHarness {
	t.Helper()
	st := newTestStore(t)
	now := time.Now().UTC()
	inc := insertCollectingIncident(t, st, "Retry", now.Add(-10*time.Second))

	h := &retryHarness{
		t: t, st: st,
		sink:    &failingSink{failures: failures, cleanSkip: cleanSkip, st: st},
		exhaust: &exhaustCapture{},
		inc:     inc, now: now,
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

// triagePhase reads the durable triage phase for incidentID, or "" if no row
// exists (e.g. never seeded, or deleted on completion).
func triagePhase(t *testing.T, st *store.Store, incidentID string) string {
	t.Helper()
	var phase string
	err := st.DB().QueryRowContext(context.Background(),
		`SELECT phase FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&phase)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ""
		}
		t.Fatalf("triage phase: %v", err)
	}
	return phase
}

// triageAttempts reads the durable attempt count for incidentID, or -1 if no
// row exists.
func triageAttempts(t *testing.T, st *store.Store, incidentID string) int {
	t.Helper()
	var n int
	err := st.DB().QueryRowContext(context.Background(),
		`SELECT attempts FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&n)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return -1
		}
		t.Fatalf("triage attempts: %v", err)
	}
	return n
}

// TestTriageRetry_PendingThroughBackoffThenSuccess pins the durable phase
// sequence across a failed dispatch followed by a successful retry:
// pending/0 -> in_flight/1 -> backoff/1, then backoff/1 -> in_flight/2 ->
// analyzed/no triage row. in_flight is transient (Begin and the sink call
// both happen inside one synchronous dispatch), so only the states at rest
// between ticks are directly observable.
func TestTriageRetry_PendingThroughBackoffThenSuccess(t *testing.T) {
	h := newRetryHarness(t, 1)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if s := h.status(); s != "ready" {
		t.Fatalf("status after failed dispatch = %q, want ready", s)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase after failed dispatch = %q, want backoff", got)
	}
	if got := triageAttempts(t, h.st, h.inc.ID); got != 1 {
		t.Fatalf("attempts after failed dispatch = %d, want 1", got)
	}

	h.now = h.now.Add(correlator.TriageRetryDelays[0])
	h.flush()
	h.wantCalls(2, "first retry")
	if s := h.status(); s != "analyzed" {
		t.Fatalf("status after successful retry = %q, want analyzed", s)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "" {
		t.Fatalf("triage row after completion = %q, want absent (deleted)", got)
	}

	// Completion deleted the triage row: nothing more is dispatched, ever.
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
	if got := triagePhase(t, h.st, h.inc.ID); got != "exhausted" {
		t.Fatalf("phase after exhausting retries = %q, want exhausted", got)
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

// TestTriageNoRetryOnCleanSkip: a sink that performs a clean skip (the skill
// deterministically has nothing to say, e.g. below min_alerts) is never
// re-dispatched.
func TestTriageNoRetryOnCleanSkip(t *testing.T) {
	h := newRetryHarnessCleanSkip(t)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if got := triagePhase(t, h.st, h.inc.ID); got != "skipped" {
		t.Fatalf("phase after clean skip = %q, want skipped", got)
	}
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

// TestTriageExhaustedWriteIsRetriedUntilItSucceeds: when the terminal write
// (the exhaustion transition) fails after the fifth sink call has already
// run, the incident stays durably "processing"/in_flight — not re-dispatched
// — and the write itself, not the sink call, is retried on a later tick.
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

	// Once the fifth sink call has run (Begin already durably succeeded),
	// make the database read-only so only the terminal exhaustion write fails.
	h.sink.onCall = func() {
		if len(h.sink.calls) == attempts-1 {
			if _, err := h.st.DB().ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
				t.Fatalf("query_only on: %v", err)
			}
		}
	}
	h.now = h.now.Add(delays[len(delays)-1])
	h.flush()
	h.wantCalls(attempts, "last attempt")
	if got := triagePhase(t, h.st, h.inc.ID); got != "in_flight" {
		t.Fatalf("phase with failing terminal write = %q, want in_flight", got)
	}
	if s := h.status(); s != "processing" {
		t.Fatalf("status with failing write = %q, want processing", s)
	}
	h.wantExhaustEvents(0, "while the terminal write keeps failing")

	// Write still failing: no sink call, no status change, row retained.
	h.now = h.now.Add(delays[0])
	h.flush()
	h.wantCalls(attempts, "write retry while store read-only")
	if got := triagePhase(t, h.st, h.inc.ID); got != "in_flight" {
		t.Fatalf("phase = %q, want in_flight", got)
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
