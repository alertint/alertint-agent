// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
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
	// failErr, when set, is returned on every failing call instead of the
	// generic connection-refused error — lets a test drive a specific
	// llmhealth-classifiable error shape through the retry path.
	failErr error
	calls   []string
	onCall  func() // optional hook run inside each call (e.g. advance the clock)
	st      *store.Store
}

func (s *failingSink) OnIncidentReady(ctx context.Context, inc store.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onCall != nil {
		s.onCall()
	}
	s.calls = append(s.calls, inc.ID)
	if len(s.calls) <= s.failures {
		if s.failErr != nil {
			return s.failErr
		}
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

// triageNextAt reads the durable next-due time for incidentID.
func triageNextAt(t *testing.T, st *store.Store, incidentID string) time.Time {
	t.Helper()
	var s sql.NullString
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT next_at FROM incident_triage WHERE incident_id = ?`, incidentID).Scan(&s); err != nil {
		t.Fatalf("triage next_at: %v", err)
	}
	if !s.Valid {
		return time.Time{}
	}
	got, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		t.Fatalf("parse next_at: %v", err)
	}
	return got
}

// mustBackoffRow reads back incidentID's Incident and its durable triage row,
// failing the test if the Incident is not currently "ready" in phase
// "backoff" (the only state GetBackoffIncidentByGroupKey resolves).
func mustBackoffRow(t *testing.T, st *store.Store, incidentID string) store.IncidentTriage {
	t.Helper()
	inc, err := st.GetIncidentByID(context.Background(), incidentID)
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	_, tri, err := st.GetBackoffIncidentByGroupKey(context.Background(), inc.GroupKey)
	if err != nil {
		t.Fatalf("get backoff incident by group key: %v", err)
	}
	return *tri
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

// TestTriageBackoffRecordsCapabilityAwareCode pins classifyTriageError's
// classified branch: a dependency-class llmhealth error persists its
// llmhealth reason code and safe detail on the durable triage row, not the
// generic "triage_dispatch_failed" fallback.
func TestTriageBackoffRecordsCapabilityAwareCode(t *testing.T) {
	h := newRetryHarness(t, 1)
	h.sink.failErr = &llm.RetryableError{StatusCode: 503}

	h.flush()

	tri := mustBackoffRow(t, h.st, h.inc.ID)
	if tri.LastErrorCode != "provider_unavailable" || tri.LastErrorDetail != "HTTP 503" {
		t.Fatalf("triage row = %+v", tri)
	}
}

// TestTriageBackoffDoesNotMisattributeAmbiguousShapedErrors pins
// classifyTriageError's other side: llmhealth.Classify's timeout/network/
// canceled reasons match on generic stdlib shapes (context.DeadlineExceeded,
// net.Error, url.Error) that any non-LLM failure in the sink call — a SQLite
// write timing out, a Prometheus/Zabbix/log-source fetch failing — could
// produce too. Trusting them here would misattribute a non-LLM failure as an
// LLM dependency code, so classifyTriageError falls back to the generic code
// for exactly these three ambiguous reasons and trusts only the reasons that
// require an internal/llm- or internal/llmhealth-specific typed error no
// other subsystem constructs.
func TestTriageBackoffDoesNotMisattributeAmbiguousShapedErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"context deadline (e.g. a SQLite write timing out)", fmt.Errorf("store: save output: %w", context.DeadlineExceeded)},
		{"context canceled (e.g. shutdown mid non-LLM call)", fmt.Errorf("store: save output: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRetryHarness(t, 1)
			h.sink.failErr = tc.err

			h.flush()

			tri := mustBackoffRow(t, h.st, h.inc.ID)
			if tri.LastErrorCode != "triage_dispatch_failed" {
				t.Fatalf("code = %q, want the generic fallback (a %v is not LLM-specific)", tri.LastErrorCode, tc.err)
			}
		})
	}
}

// TestTriageBackoffRecordsLLMOriginTimeout pins the resolution of the
// ambiguity above: a timeout/network/canceled error that Acute Triage marked
// as LLM-origin (llmhealth.MarkLLMOrigin at its Complete boundary) IS
// trustworthy, so the motivating production failure — a real Call-1 context
// deadline — persists its capability-aware "timeout" code instead of the
// generic fallback.
func TestTriageBackoffRecordsLLMOriginTimeout(t *testing.T) {
	h := newRetryHarness(t, 1)
	h.sink.failErr = fmt.Errorf("acutetriage: llm: %w", llmhealth.MarkLLMOrigin(context.DeadlineExceeded))

	h.flush()

	tri := mustBackoffRow(t, h.st, h.inc.ID)
	if tri.LastErrorCode != "timeout" {
		t.Fatalf("code = %q, want timeout (the error is marked LLM-origin)", tri.LastErrorCode)
	}
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
// retry is pending is dropped without another sink call and keeps its
// status. R7: resolution also clears the triage row outright, so it is
// absent from every later scan, not merely skipped by the Begin guard.
func TestTriageRetrySkipsIncidentThatLeftReady(t *testing.T) {
	h := newRetryHarness(t, 1000)

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if err := h.st.MarkIncidentResolved(context.Background(), h.inc.ID); err != nil {
		t.Fatalf("mark resolved: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "" {
		t.Fatalf("triage row after resolution = %q, want absent (deleted)", got)
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

// --------------------------------------------------------------------------
// Startup recovery (Task 3): interrupted and legacy triage state, and the
// one-hour startup horizon (ADR-0045).
// --------------------------------------------------------------------------

// TestStartupRecovery_PreservesDurableBackoff: a durable backoff row that
// was never interrupted (the process shut down cleanly between attempts)
// survives Recover with its attempts and next_at exactly unchanged.
func TestStartupRecovery_PreservesDurableBackoff(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	h.flush()
	h.now = h.now.Add(correlator.TriageRetryDelays[0])
	h.flush()
	h.wantCalls(2, "two failed attempts")
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase = %q, want backoff", got)
	}
	if got := triageAttempts(t, h.st, h.inc.ID); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	wantNext := triageNextAt(t, h.st, h.inc.ID)

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase after recover = %q, want backoff (unchanged)", got)
	}
	if got := triageAttempts(t, h.st, h.inc.ID); got != 2 {
		t.Fatalf("attempts after recover = %d, want 2 (unchanged)", got)
	}
	if got := triageNextAt(t, h.st, h.inc.ID); !got.Equal(wantNext) {
		t.Fatalf("next_at after recover = %v, want %v (unchanged)", got, wantNext)
	}
	h.wantCalls(2, "recover itself dispatches nothing")
}

// TestStartupRecovery_InterruptedAttemptBecomesBackoff covers ADR-0045: an
// attempt interrupted mid-flight counts. The row is built directly through
// the store's guarded transitions (Seed/Begin/Backoff/Begin again) to land
// exactly on "processing"/in_flight/attempts=2 without ever resolving the
// second attempt — the state a process crash mid-call would leave behind.
func TestStartupRecovery_InterruptedAttemptBecomesBackoff(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.st.SeedIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("begin 1: %v", err)
	}
	if err := h.st.BackoffIncidentTriage(ctx, h.inc.ID, h.now.Add(correlator.TriageRetryDelays[0]), "timeout", "deadline exceeded"); err != nil {
		t.Fatalf("backoff 1: %v", err)
	}
	startedAt := h.now.Add(correlator.TriageRetryDelays[0])
	active, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, startedAt)
	if err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	if active.Attempts != 2 {
		t.Fatalf("attempts before crash = %d, want 2", active.Attempts)
	}
	// Nothing resolves this attempt: simulates a crash mid-call.

	h.now = startedAt
	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase after recover = %q, want backoff", got)
	}
	if s := h.status(); s != "ready" {
		t.Fatalf("status after recover = %q, want ready", s)
	}
	wantNext := startedAt.Add(correlator.TriageRetryDelays[1]) // delay[attempts-1] = delay[1]
	if got := triageNextAt(t, h.st, h.inc.ID); !got.Equal(wantNext) {
		t.Fatalf("next_at after recover = %v, want %v (started_at + delay[attempts-1])", got, wantNext)
	}
	h.wantCalls(0, "recover itself dispatches nothing")
}

// TestStartupRecovery_InterruptedAtMaxAttemptsExhausts covers ADR-0045: an
// Incident can reach "failed" with fewer than five completed LLM calls when
// the fifth attempt itself is interrupted — the schedule is spent regardless.
func TestStartupRecovery_InterruptedAtMaxAttemptsExhausts(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.st.SeedIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	at := h.now
	for i := 0; i < len(correlator.TriageRetryDelays); i++ {
		if _, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, at); err != nil {
			t.Fatalf("begin %d: %v", i+1, err)
		}
		at = at.Add(correlator.TriageRetryDelays[i])
		if err := h.st.BackoffIncidentTriage(ctx, h.inc.ID, at, "timeout", "deadline exceeded"); err != nil {
			t.Fatalf("backoff %d: %v", i+1, err)
		}
	}
	active, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, at) // 5th attempt, in_flight
	if err != nil {
		t.Fatalf("begin final: %v", err)
	}
	if active.Attempts != 5 {
		t.Fatalf("attempts before crash = %d, want 5", active.Attempts)
	}

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "exhausted" {
		t.Fatalf("phase after recover = %q, want exhausted", got)
	}
	if s := h.status(); s != "failed" {
		t.Fatalf("status after recover = %q, want failed", s)
	}
	h.wantCalls(0, "recover never calls the sink")
	h.wantExhaustEvents(1, "interrupted at max attempts")
	if ev := h.exhaust.events[0]; ev.Attempts != 5 {
		t.Fatalf("exhaust event attempts = %d, want 5", ev.Attempts)
	}
}

// TestStartupRecovery_LegacyReadySeedsAndDispatchesOnce: a "ready" incident
// with no triage row (left by a pre-upgrade binary) is seeded as pending and
// dispatched once on the first tick after Start; if that fails, it enters the
// normal schedule.
func TestStartupRecovery_LegacyReadySeedsAndDispatchesOnce(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()
	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "pending" {
		t.Fatalf("phase after recover = %q, want pending", got)
	}
	h.wantCalls(0, "recover itself dispatches nothing")

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

// TestStartupRecovery_LegacyReadyCleanSkipDispatchedOnce: a legitimately-ready
// legacy incident (the skill returns nil) costs one sink call per restart and
// nothing more.
func TestStartupRecovery_LegacyReadyCleanSkipDispatchedOnce(t *testing.T) {
	h := newRetryHarnessCleanSkip(t)
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
	if got := triagePhase(t, h.st, h.inc.ID); got != "skipped" {
		t.Fatalf("phase = %q, want skipped", got)
	}
}

// TestStartupRecovery_ExpiresStaleLegacyReadyIncidents: a legacy incident
// that has been "ready" for longer than the startup window is closed out as
// "failed" at Start without a sink call, so an upgrade over a backlog of
// stuck incidents does not become an LLM burst. A fresh one is still
// re-dispatched normally.
func TestStartupRecovery_ExpiresStaleLegacyReadyIncidents(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()
	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	stale := insertCollectingIncident(t, h.st, "Stale", h.now.Add(-correlator.StartupRetryWindow-time.Minute))
	if err := h.st.MarkIncidentReady(ctx, stale.ID); err != nil {
		t.Fatalf("mark stale ready: %v", err)
	}

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	got, err := h.st.GetIncidentByID(ctx, stale.ID)
	if err != nil || got == nil {
		t.Fatalf("get stale: %v", err)
	}
	if got.Status != "failed" {
		t.Fatalf("stale incident status after start = %q, want failed", got.Status)
	}
	if phase := triagePhase(t, h.st, stale.ID); phase != "exhausted" {
		t.Fatalf("stale phase = %q, want exhausted", phase)
	}
	h.wantCalls(0, "recover itself dispatches nothing")
	h.wantExhaustEvents(1, "stale closure (reason startup_retry_window_expired)")

	h.flush()
	h.wantCalls(1, "first tick: only the fresh incident")
	if h.sink.calls[0] != h.inc.ID {
		t.Fatalf("dispatched %s, want the fresh incident %s", h.sink.calls[0], h.inc.ID)
	}
	h.now = h.now.Add(24 * time.Hour)
	h.flush()
	for _, id := range h.sink.calls {
		if id == stale.ID {
			t.Fatalf("stale incident %s was dispatched", stale.ID)
		}
	}
	h.wantExhaustEvents(1, "still only the one exhaust event")
}

// TestStartupRecovery_DurableBackoffOverdueExpires covers R3/ADR-0045: a
// durable backoff row (not merely legacy) whose next_at is more than the
// startup window in the past also expires at recovery — the horizon applies
// to every unjudged row, not only legacy ones. A backoff row overdue by less
// than the window is left untouched and runs on the first tick.
func TestStartupRecovery_DurableBackoffOverdueExpires(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.st.SeedIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	overdueNext := h.now.Add(-correlator.StartupRetryWindow - time.Minute)
	if err := h.st.BackoffIncidentTriage(ctx, h.inc.ID, overdueNext, "timeout", "deadline exceeded"); err != nil {
		t.Fatalf("backoff: %v", err)
	}

	fresh := insertCollectingIncident(t, h.st, "Fresh", h.now.Add(-5*time.Second))
	if err := h.st.MarkIncidentReady(ctx, fresh.ID); err != nil {
		t.Fatalf("mark fresh ready: %v", err)
	}
	if err := h.st.SeedIncidentTriage(ctx, fresh.ID, h.now); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}
	if _, err := h.st.BeginIncidentTriage(ctx, fresh.ID, h.now); err != nil {
		t.Fatalf("begin fresh: %v", err)
	}
	// Overdue by less than the window: must survive recovery untouched.
	recentNext := h.now.Add(-time.Minute)
	if err := h.st.BackoffIncidentTriage(ctx, fresh.ID, recentNext, "timeout", "deadline exceeded"); err != nil {
		t.Fatalf("backoff fresh: %v", err)
	}

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if phase := triagePhase(t, h.st, h.inc.ID); phase != "exhausted" {
		t.Fatalf("overdue backoff phase after recover = %q, want exhausted", phase)
	}
	stale, err := h.st.GetIncidentByID(ctx, h.inc.ID)
	if err != nil || stale == nil || stale.Status != "failed" {
		t.Fatalf("overdue backoff incident = %+v, %v, want status failed", stale, err)
	}

	if phase := triagePhase(t, h.st, fresh.ID); phase != "backoff" {
		t.Fatalf("recent backoff phase after recover = %q, want backoff (untouched)", phase)
	}
	if got := triageNextAt(t, h.st, fresh.ID); !got.Equal(recentNext) {
		t.Fatalf("recent backoff next_at after recover = %v, want %v (unchanged)", got, recentNext)
	}
	h.wantCalls(0, "recover itself dispatches nothing")
	h.wantExhaustEvents(1, "only the overdue backoff row expires")
}

// --------------------------------------------------------------------------
// Code-review follow-ups: in-flight reconciliation runs every tick (not only
// at startup, and not only once a row reaches the attempt ceiling), and a
// stale in_flight row left by a successful-but-uncleaned dispatch is deleted
// rather than orphaned forever.
// --------------------------------------------------------------------------

// TestTriageBackoffWriteIsRetriedUntilItSucceeds: a terminal write that
// fails below the attempt ceiling (not just at it) is retried on the very
// next tick without another sink call. Before this fix, mid-run
// reconciliation only handled a row already at max attempts.
func TestTriageBackoffWriteIsRetriedUntilItSucceeds(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	h.flush()
	h.wantCalls(1, "initial dispatch")
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase = %q, want backoff", got)
	}

	// Once the second sink call has run (Begin already durably succeeded,
	// attempts=2), make the database read-only so only that attempt's
	// terminal backoff write fails.
	h.sink.onCall = func() {
		if len(h.sink.calls) == 1 { // about to make the 2nd call
			if _, err := h.st.DB().ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
				t.Fatalf("query_only on: %v", err)
			}
		}
	}
	h.now = h.now.Add(correlator.TriageRetryDelays[0])
	h.flush()
	h.wantCalls(2, "second attempt")
	if got := triagePhase(t, h.st, h.inc.ID); got != "in_flight" {
		t.Fatalf("phase with failing backoff write = %q, want in_flight", got)
	}
	if got := triageAttempts(t, h.st, h.inc.ID); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}

	if _, err := h.st.DB().ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatalf("query_only off: %v", err)
	}
	// The store recovered; the very next tick reconciles the stuck write
	// without dispatching another sink call.
	h.now = h.now.Add(time.Second)
	h.flush()
	h.wantCalls(2, "reconciled without another sink call")
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase after reconciliation = %q, want backoff", got)
	}
	if got := triageAttempts(t, h.st, h.inc.ID); got != 2 {
		t.Fatalf("attempts after reconciliation = %d, want 2 (unchanged)", got)
	}
}

// TestStartupRecovery_StaleInFlightRowAfterSuccessIsCleared: if the triage
// skill's own persist (SaveIncidentOutput, a separate transaction) succeeds
// but the dispatch's own cleanup (CompleteIncidentTriage) never runs — a
// crash, or a transient store error right after — the leftover in_flight row
// is deleted rather than orphaned: it belongs to an Incident that is no
// longer unjudged, so reconciling it into a schedule would never be reached
// again.
func TestStartupRecovery_StaleInFlightRowAfterSuccessIsCleared(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := h.st.SeedIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := h.st.BeginIncidentTriage(ctx, h.inc.ID, h.now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := h.st.SaveIncidentOutput(ctx, h.inc.ID, `{"ok":true}`, "n", "i", 0.5, ""); err != nil {
		t.Fatalf("save output: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "in_flight" {
		t.Fatalf("phase before reconciliation = %q, want in_flight (unreconciled)", got)
	}

	if err := h.cor.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if got := triagePhase(t, h.st, h.inc.ID); got != "" {
		t.Fatalf("phase after reconciliation = %q, want absent (deleted, not orphaned)", got)
	}
	inc, err := h.st.GetIncidentByID(ctx, h.inc.ID)
	if err != nil || inc == nil || inc.Status != "analyzed" {
		t.Fatalf("incident = %+v, %v, want status analyzed (untouched)", inc, err)
	}
	h.wantCalls(0, "recover never calls the sink")
}

// TestFlushExpired_ReconcilesUnscheduledReadyIncident proves a code-review
// fix (R1/R3): an Incident left "ready" with no triage row — because
// MarkIncidentReady and SeedIncidentTriage are two separate store calls, and
// the second can fail after the first already committed — is picked up and
// dispatched on a later flush tick, not stuck until a process restart.
func TestFlushExpired_ReconcilesUnscheduledReadyIncident(t *testing.T) {
	h := newRetryHarness(t, 1000)
	ctx := context.Background()

	// Simulate MarkIncidentReady succeeding while SeedIncidentTriage failed:
	// "ready" with no triage row, without ever going through Start/Recover.
	if err := h.st.MarkIncidentReady(ctx, h.inc.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if got := triagePhase(t, h.st, h.inc.ID); got != "" {
		t.Fatalf("phase = %q, want absent (unscheduled)", got)
	}

	// An ordinary flush tick, not startup recovery, must reconcile it.
	h.flush()
	h.wantCalls(1, "unscheduled incident reconciled and dispatched")
	if got := triagePhase(t, h.st, h.inc.ID); got != "backoff" {
		t.Fatalf("phase after reconciliation = %q, want backoff", got)
	}
}
