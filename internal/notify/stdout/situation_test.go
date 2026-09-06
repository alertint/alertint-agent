// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Fixtures: an in-memory transition-stream ledger with the same fencing
// contract internal/store implements, so this worker's crash/replay
// behaviour is provable without a database.
// ----------------------------------------------------------------------

const tsSituationID = "1f0f5a0c-0000-4000-8000-0000000000e1"

func tsTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return parsed.UTC()
}

func tsTransition(t *testing.T, seq int, lifecycle model.Lifecycle, reason model.TransitionReason) model.Transition { //nolint:unparam // lifecycle is a real axis of this fixture; the terminal branch below exists for the cases that need it
	t.Helper()
	started := tsTime(t, "2026-09-05T10:00:00Z")
	contract := model.ActionContract{NextActor: model.NextActorNone}
	if !lifecycle.Terminal() {
		action := model.AlertINTActionRunAcuteTriage
		status := model.AlertINTStatusRunning
		next := started.Add(15 * time.Minute)
		contract = model.ActionContract{
			NextActor:      model.NextActorAlertINT,
			AlertINTAction: &action,
			AlertINTStatus: &status,
			NextUpdateAt:   &next,
			NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnTriageOutcome},
		}
	}
	projection := model.ProjectionFacts{
		EffectiveStartedAt:      started,
		EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
	}
	if lifecycle.Terminal() {
		terminalAt := started.Add(time.Hour)
		terminalReason := model.TerminalReasonResolutionMissing
		projection.TerminalAt = &terminalAt
		projection.TerminalReason = &terminalReason
	}
	tr := model.Transition{
		ID:               "transition-" + string(rune('a'+seq)),
		SituationID:      tsSituationID,
		Sequence:         seq,
		InputVersion:     seq,
		MaterialFactHash: "sha256:deadbeef",
		Lifecycle:        lifecycle,
		Attention:        model.AttentionInvestigate,
		ActionContract:   contract,
		Reason:           reason,
		JournalKind:      model.JournalPublication,
		Journal: model.JournalData{
			Headline:   "Checkout latency is being investigated",
			Detail:     "Two related alerts have been correlated into one Situation.",
			OccurredAt: started,
		},
		Projection:   projection,
		EvidenceRefs: []string{"evidence-1"},
		Actor:        model.ActorDeterministicController,
		CreatedAt:    started.Add(time.Duration(seq) * time.Minute),
	}
	if err := tr.Validate(); err != nil {
		t.Fatalf("fixture transition %d is invalid: %v", seq, err)
	}
	return tr
}

type tsRow struct {
	claim     store.TransitionStreamClaim
	status    string
	retryAt   *time.Time
	errClass  string
	delivered bool
	leased    bool
}

type tsFakeStore struct {
	mu       sync.Mutex
	rows     []*tsRow
	claimErr error
}

func newTSFakeStore(transitions ...model.Transition) *tsFakeStore {
	f := &tsFakeStore{}
	for i, tr := range transitions {
		f.rows = append(f.rows, &tsRow{
			claim:  store.TransitionStreamClaim{StreamID: "stream-" + string(rune('a'+i)), Transition: tr},
			status: "pending",
		})
	}
	return f
}

func (f *tsFakeStore) RecoverExpiredTransitionStreamClaims(context.Context, time.Time) (int, error) {
	return 0, nil
}

func (f *tsFakeStore) ClaimTransitionStream(_ context.Context, owner string, now time.Time,
	_ time.Duration, limit int) ([]store.TransitionStreamClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	out := []store.TransitionStreamClaim{}
	for _, r := range f.rows {
		if len(out) >= limit {
			break
		}
		if r.status != "pending" || r.leased {
			continue
		}
		if r.retryAt != nil && now.Before(*r.retryAt) {
			continue
		}
		r.leased = true
		r.claim.ClaimOwner = owner
		r.claim.ClaimToken++
		out = append(out, r.claim)
	}
	return out, nil
}

func (f *tsFakeStore) find(claim store.TransitionStreamClaim) (*tsRow, error) {
	for _, r := range f.rows {
		if r.claim.StreamID != claim.StreamID {
			continue
		}
		if r.status != "pending" || r.claim.ClaimOwner != claim.ClaimOwner || r.claim.ClaimToken != claim.ClaimToken {
			return nil, store.ErrTransitionStreamClaimLost
		}
		return r, nil
	}
	return nil, store.ErrNotFound
}

func (f *tsFakeStore) MarkTransitionStreamDelivered(_ context.Context, claim store.TransitionStreamClaim, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.find(claim)
	if err != nil {
		return err
	}
	r.status = "delivered"
	r.delivered = true
	r.leased = false
	return nil
}

func (f *tsFakeStore) RetryTransitionStreamEntry(_ context.Context, claim store.TransitionStreamClaim,
	errorClass string, retryAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.find(claim)
	if err != nil {
		return err
	}
	r.errClass = errorClass
	at := retryAt
	r.retryAt = &at
	r.leased = false
	return nil
}

func (f *tsFakeStore) FailTransitionStreamEntry(_ context.Context, claim store.TransitionStreamClaim,
	errorClass string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.find(claim)
	if err != nil {
		return err
	}
	r.status = "failed"
	r.errClass = errorClass
	r.leased = false
	return nil
}

func (f *tsFakeStore) ReleaseTransitionStreamClaim(_ context.Context, claim store.TransitionStreamClaim) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.find(claim)
	if err != nil {
		return err
	}
	r.leased = false
	return nil
}

func (f *tsFakeStore) snapshot() []tsRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]tsRow, 0, len(f.rows))
	for _, r := range f.rows {
		out = append(out, *r)
	}
	return out
}

// failingWriter fails every write until enabled is set.
type tsFailingWriter struct {
	mu      sync.Mutex
	fail    bool
	partial bool
	buf     bytes.Buffer
}

func (w *tsFailingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.fail:
		return 0, errors.New("stdout is unavailable")
	case w.partial:
		// A crash DURING the write: half the line reaches the consumer and
		// the acknowledgement never happens.
		n, _ := w.buf.Write(p[:len(p)/2])
		return n, errors.New("short write")
	default:
		return w.buf.Write(p)
	}
}

func (w *tsFailingWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type tsAuditRow struct {
	actor   string
	kind    string
	payload any
}

type tsFakeAuditor struct {
	mu   sync.Mutex
	rows []tsAuditRow
}

func (a *tsFakeAuditor) Append(_ context.Context, actor, kind string, payload any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, tsAuditRow{actor: actor, kind: kind, payload: payload})
	return nil
}

func (a *tsFakeAuditor) kinds() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.rows))
	for _, r := range a.rows {
		out = append(out, r.kind)
	}
	return out
}

func tsWorker(w *tsFailingWriter, st TransitionStreamStore, auditor TransitionStreamAuditSink) *TransitionStreamWorker {
	clock := func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }
	return NewTransitionStreamWorker(w, st, TransitionStreamConfig{Owner: "test-owner"}, auditor, clock, nil)
}

func tsLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	lines := []map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("stdout line %q is not canonical JSON: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

// TestSituationTransitionStreamEmitsOneVersionedLinePerTransition pins the
// contract: one canonical JSON object per committed Transition, carrying the
// stream envelope version, the Transition's ID and sequence, and the
// Episode-summary version that Transition produced.
func TestSituationTransitionStreamEmitsOneVersionedLinePerTransition(t *testing.T) {
	st := newTSFakeStore(
		tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState),
		tsTransition(t, 2, model.LifecycleActive, model.ReasonAttentionChanged),
	)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	handled, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if handled != 2 {
		t.Fatalf("handled = %d, want 2", handled)
	}

	lines := tsLines(t, w.String())
	if len(lines) != 2 {
		t.Fatalf("emitted %d lines, want 2: %q", len(lines), w.String())
	}
	for i, line := range lines {
		if line["kind"] != TransitionStreamKind {
			t.Errorf("line %d kind = %v, want %q", i, line["kind"], TransitionStreamKind)
		}
		if line["version"] != float64(TransitionStreamVersion) {
			t.Errorf("line %d version = %v, want %d", i, line["version"], TransitionStreamVersion)
		}
		if line["situation_id"] != tsSituationID {
			t.Errorf("line %d situation_id = %v", i, line["situation_id"])
		}
		wantSeq := float64(i + 1)
		if line["sequence"] != wantSeq {
			t.Errorf("line %d sequence = %v, want %v", i, line["sequence"], wantSeq)
		}
		// The Episode fold advances the summary by exactly one version per
		// Transition and Transition sequences are contiguous from one, so
		// the summary version a Transition produced IS its sequence.
		if line["summary_version"] != wantSeq {
			t.Errorf("line %d summary_version = %v, want %v", i, line["summary_version"], wantSeq)
		}
		if line["transition_id"] == "" || line["transition_id"] == nil {
			t.Errorf("line %d carries no transition_id", i)
		}
	}
	for _, r := range st.snapshot() {
		if !r.delivered {
			t.Errorf("stream row %s was never acknowledged", r.claim.StreamID)
		}
	}
}

// TestSituationTransitionStreamAcknowledgesWithFencing proves the
// acknowledgement is fenced: a row whose claim moved on (a sweep reclaimed
// it mid-write) is never marked delivered by the stale holder, and the
// worker keeps going rather than failing the round.
func TestSituationTransitionStreamAcknowledgesWithFencing(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	claims, err := st.ClaimTransitionStream(context.Background(), "someone-else", time.Now().UTC(), time.Minute, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("seed claim: %v, %d claims", err, len(claims))
	}
	stale := claims[0]
	stale.ClaimOwner = "test-owner"
	stale.ClaimToken = 1

	if err := worker.acknowledge(context.Background(), stale, nil); !errors.Is(err, store.ErrTransitionStreamClaimLost) {
		t.Fatalf("acknowledge with a stale claim = %v, want ErrTransitionStreamClaimLost", err)
	}
	if st.snapshot()[0].delivered {
		t.Fatal("a stale claim marked the row delivered")
	}
}

// TestSituationTransitionStreamCrashBeforeAcknowledgementNeverLoses proves
// the at-least-once contract from the consumer's side: the line is written
// BEFORE the acknowledgement commits, so a crash between the two replays
// the same Transition — a duplicate line, never a lost one. Consumers
// deduplicate by transition_id.
func TestSituationTransitionStreamCrashBeforeAcknowledgementNeverLoses(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	// Round one: write the line, then "crash" before acknowledging — the
	// lease simply expires and the row returns to the pool.
	claims, err := st.ClaimTransitionStream(context.Background(), "test-owner", time.Now().UTC(), time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v", err)
	}
	if err := worker.emit(w, claims[0]); err != nil {
		t.Fatalf("emit: %v", err)
	}
	st.rows[0].leased = false // the crashed process's lease is swept at startup

	// Round two: a fresh process replays the still-pending row.
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	lines := tsLines(t, w.String())
	if len(lines) != 2 {
		t.Fatalf("emitted %d lines, want 2 (the duplicate a crash before acknowledgement permits)", len(lines))
	}
	if lines[0]["transition_id"] != lines[1]["transition_id"] {
		t.Fatal("the replayed line names a different transition; consumers cannot deduplicate")
	}
	if !st.snapshot()[0].delivered {
		t.Fatal("the replayed row was never acknowledged")
	}
}

// TestSituationTransitionStreamCrashDuringWriteReplaysTheWholeLine proves a
// half-written line is never acknowledged: the row stays pending, retries,
// and the complete line is written again.
func TestSituationTransitionStreamCrashDuringWriteReplaysTheWholeLine(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{partial: true}
	worker := tsWorker(w, st, nil)

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	row := st.snapshot()[0]
	if row.delivered {
		t.Fatal("a short write was acknowledged as delivered")
	}
	if row.status != "pending" || row.retryAt == nil {
		t.Fatalf("row after a short write = %+v, want pending with a retry time", row)
	}

	w.mu.Lock()
	w.partial = false
	w.buf.Reset()
	w.mu.Unlock()
	st.rows[0].retryAt = nil

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (retry): %v", err)
	}
	if lines := tsLines(t, w.String()); len(lines) != 1 {
		t.Fatalf("retry emitted %d lines, want 1 complete line", len(lines))
	}
	if !st.snapshot()[0].delivered {
		t.Fatal("the retried row was never acknowledged")
	}
}

// TestSituationTransitionStreamWriterFailureRetriesIndefinitely proves an
// unavailable stdout retries — never dead-letters — and touches no Slack
// intent state at all (this worker has no notification-intent surface).
func TestSituationTransitionStreamWriterFailureRetriesIndefinitely(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{fail: true}
	worker := tsWorker(w, st, nil)

	for range 3 {
		if _, err := worker.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		st.rows[0].retryAt = nil
	}
	row := st.snapshot()[0]
	if row.status != "pending" {
		t.Fatalf("status after three stdout failures = %q, want pending (retry is indefinite)", row.status)
	}
	if row.errClass != streamErrorUnavailable {
		t.Fatalf("last_error_class = %q, want %q", row.errClass, streamErrorUnavailable)
	}
}

// TestSituationTransitionStreamInvalidPayloadFailsOnlyThatRow proves a
// durable row this build cannot serialize moves to failed — with an audit
// record — while every other row in the same batch still emits.
func TestSituationTransitionStreamInvalidPayloadFailsOnlyThatRow(t *testing.T) {
	bad := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	bad.SituationID = "" // a hand-corrupted durable row
	good := tsTransition(t, 2, model.LifecycleActive, model.ReasonAttentionChanged)
	st := newTSFakeStore(bad, good)
	w := &tsFailingWriter{}
	auditor := &tsFakeAuditor{}
	worker := tsWorker(w, st, auditor)

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	rows := st.snapshot()
	if rows[0].status != "failed" || rows[0].errClass != streamErrorInvalid {
		t.Fatalf("invalid row = %+v, want failed/%s", rows[0], streamErrorInvalid)
	}
	if !rows[1].delivered {
		t.Fatal("a valid row in the same batch was not emitted")
	}
	kinds := auditor.kinds()
	found := false
	for _, k := range kinds {
		if k == AuditTransitionStreamFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit kinds = %v, want one %s row", kinds, AuditTransitionStreamFailed)
	}
}

// TestSituationTransitionStreamEmitsForSilentAndWithheldSituations proves
// the stream is state, not Slack: a Situation that creates no Slack effect
// at all still emits its Transitions, and the line says nothing about Slack
// delivery.
func TestSituationTransitionStreamEmitsForSilentAndWithheldSituations(t *testing.T) {
	quiet := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	quiet.JournalKind = model.JournalNone
	quiet.Journal = model.JournalData{OccurredAt: quiet.CreatedAt}
	st := newTSFakeStore(quiet)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	lines := tsLines(t, w.String())
	if len(lines) != 1 {
		t.Fatalf("a silent Situation emitted %d lines, want 1", len(lines))
	}
	for _, key := range []string{"slack_channel", "slack_message_ts", "delivered_to_slack", "channel", "message_ts"} {
		if _, ok := lines[0][key]; ok {
			t.Errorf("stdout line carries %q; stdout success must never imply Slack delivery", key)
		}
	}
}

// TestSituationTransitionStreamLineCarriesNoProse proves the payload-absence
// contract: identities, closed codes, hashes, counters, and instants only —
// never journal headline/detail prose, an Assessment body, or a Slack
// response.
func TestSituationTransitionStreamLineCarriesNoProse(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	out := w.String()
	for _, prose := range []string{tr.Journal.Headline, tr.Journal.Detail} {
		if strings.Contains(out, prose) {
			t.Fatalf("stdout line carries prose %q", prose)
		}
	}
}

// TestSituationTransitionStreamStopRunsOneFinalPassAndReleasesClaims proves
// R6 for this worker: Stop runs exactly one bounded final pass and releases
// whatever it still holds, so a shutdown leaves no committed Transition
// waiting out a lease.
func TestSituationTransitionStreamStopRunsOneFinalPassAndReleasesClaims(t *testing.T) {
	tr := tsTransition(t, 1, model.LifecycleActive, model.ReasonFirstAuthoritativeState)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)

	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	row := st.snapshot()[0]
	if !row.delivered {
		t.Fatal("Stop's final pass did not emit the pending Transition")
	}
	if row.leased {
		t.Fatal("Stop left a claim held")
	}
}

// TestSituationTransitionStreamEmitSpanUsesTheSituationScope proves R8's
// third new span lands on internal/situation's EXISTING instrumentation
// scope (via situation.Tracer(), never a second scope of this package's
// own), carries the Transition identity attributes, and carries no prose.
func TestSituationTransitionStreamEmitSpanUsesTheSituationScope(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = tp.Shutdown(context.Background())
	})

	tr := tsTransition(t, 3, model.LifecycleActive, model.ReasonAttentionChanged)
	st := newTSFakeStore(tr)
	w := &tsFailingWriter{}
	worker := tsWorker(w, st, nil)
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want exactly 1", len(spans))
	}
	span := spans[0]
	if span.Name != situation.SpanTransitionStreamEmit {
		t.Fatalf("span name = %q, want %q", span.Name, situation.SpanTransitionStreamEmit)
	}
	if got := span.InstrumentationScope.Name; got != "github.com/alertint/alertint-agent/internal/situation" {
		t.Fatalf("instrumentation scope = %q, want internal/situation's existing scope", got)
	}
	attrs := map[string]string{}
	for _, kv := range span.Attributes {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	for key, want := range map[string]string{
		string(situation.AttrSituationID):        tsSituationID,
		string(situation.AttrTransitionID):       tr.ID,
		string(situation.AttrTransitionSequence): "3",
		string(situation.AttrSummaryVersion):     "3",
		string(situation.AttrResultClass):        situation.StreamResultEmitted,
	} {
		if attrs[key] != want {
			t.Errorf("span %s = %q, want %q", key, attrs[key], want)
		}
	}
	for key, value := range attrs {
		if !strings.HasPrefix(key, "alertint.") {
			t.Errorf("span carries a non-alertint attribute %q", key)
		}
		if strings.Contains(value, tr.Journal.Headline) || strings.Contains(value, tr.Journal.Detail) {
			t.Errorf("span attribute %q leaks journal prose", key)
		}
	}
}
