// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// fakeAnnotationSink is a notify.Notifier that also implements
// notify.AnnotationSink, so capture-engine tests can assert what the fan-out
// saw without a real Slack/stdout notifier.
type fakeAnnotationSink struct {
	events []notify.AnnotationEvent
}

func (f *fakeAnnotationSink) Name() string                                 { return "fake" }
func (f *fakeAnnotationSink) Notify(context.Context, notify.Finding) error { return nil }
func (f *fakeAnnotationSink) OnAnnotation(_ context.Context, ev notify.AnnotationEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// skillForCapture builds a Skill wired for capture-engine tests: the given
// store, a fake LLM (Annotate never calls it; CaptureVerdict tests script it
// separately), a real auditor over the same store, and a Multi notifier
// fanning to sink so annotation events can be asserted.
func skillForCapture(t *testing.T, st *store.Store, sink *fakeAnnotationSink) *acutetriage.Skill {
	t.Helper()
	return acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, &fakeLLM{}, audit.New(st.DB()), notify.NewMulti(nil, sink), slog.Default())
}

// skillForCaptureWithProm is skillForCapture plus a live-ish Prometheus client
// for the widen() live-once fetch (Task 12's persist phase).
func skillForCaptureWithProm(t *testing.T, st *store.Store, sink *fakeAnnotationSink, prom *promclient.Client) *acutetriage.Skill {
	t.Helper()
	cfg := acutetriage.Config{
		MinAlerts:    1,
		Prometheus:   prom,
		Verification: acutetriage.VerificationParams{QueryTimeoutSeconds: 5, MaxSeries: 100},
	}
	return acutetriage.New(cfg, st, &fakeLLM{}, audit.New(st.DB()), notify.NewMulti(nil, sink), slog.Default())
}

// countingPromServer wraps promServer, counting every request it serves —
// used to assert repeat-call/merge widening fetches exactly the new exprs.
func countingCaptureProm(t *testing.T) (*promclient.Client, *int) {
	t.Helper()
	n := 0
	return promServer(t, func(string) (int, string) { n++; return 200, vectorValue3 }), &n
}

// seedAnalyzedIncidentOnKey inserts an incident on "service=api" with one
// member alert and a persisted (trivial) finding — status "analyzed" — the
// input shape the capture engine's write tools operate on.
func seedAnalyzedIncidentOnKey(t *testing.T, st *store.Store) store.Incident {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	inc := store.Incident{
		ID: uuid.NewString(), GroupKey: "service=api",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, inc.ID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	insertTestAlert(t, st, ctx, inc.ID, "fp-"+inc.ID, map[string]string{"alertname": "TargetDown"})
	if err := st.SaveIncidentOutput(ctx, inc.ID, `{"analysis_name":"x","overall_issue":"y"}`, "x", "y", 0.7, "{}"); err != nil {
		t.Fatalf("save incident output: %v", err)
	}
	got, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("reload incident: %v", err)
	}
	return *got
}

// TestAnnotate_CorrectionAuditsNoDemote proves Annotate's persist-only
// contract post-Task-8: the annotation lands, is audited, pulls no D7 lever,
// and — since Task 8 removed capture.go's own notifyAnnotation fan-out —
// never calls a notifier directly any more. Presentation is the Situation
// controller/notification worker's job (Task 6/7); this engine's own job is
// now limited to persisting the annotation and (situationOwnedIncident
// cases below) durably enqueuing the Situation input that makes it visible
// there.
func TestAnnotate_CorrectionAuditsNoDemote(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))
	ctx := context.Background()

	res, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{
		IncidentID: inc.ID, Kind: "correction", Note: "not an AZ outage",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Demoted {
		t.Fatal("a note-only correction pulls no lever (D7): demoted must be false")
	}

	// and the marks floor must be untouched
	if marks := readRefuteMarks(t, st, ctx, inc.ID); marks != 0 {
		t.Fatalf("annotate must not set the marks floor, got %d", marks)
	}

	if n := auditCount(t, st, "incident.annotated"); n != 1 {
		t.Fatalf("want exactly one incident.annotated audit row, got %d", n)
	}
	auditor := audit.New(st.DB())
	rep, err := auditor.Verify(ctx)
	if err != nil || !rep.OK {
		t.Fatalf("audit chain must verify: report=%+v err=%v", rep, err)
	}

	if len(sink.events) != 0 {
		t.Fatalf("Annotate must never call a notifier directly (Task 8: the Situation controller/worker owns presentation); sink saw %+v", sink.events)
	}
}

// situationOwnedIncident builds one real Incident and durably attaches it to
// a brand-new active Situation the same way the durable pipeline does —
// InsertIncident, a queued incident_created situation_input_outbox row,
// ClaimSituationInputs, ApplySituationInput (mirrors internal/mcp's
// seedSituationForMCP and internal/store's own situationOwnedIncident) —
// never an INSERT INTO situations by hand. Task 8's write-back enqueue
// (InsertIncidentAnnotation/PersistVerdictCapture, called through
// CaptureEngine here) only reaches situation_input_outbox when the target
// Incident currently belongs to a nonterminal Situation, so the tests below
// that assert on that enqueue call this first.
func situationOwnedIncident(t *testing.T, st *store.Store, groupKey string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	incidentID := uuid.NewString()
	if err := st.InsertIncident(ctx, store.Incident{
		ID: incidentID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	inputID := "input-" + incidentID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, 'incident_created', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, groupKey, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed situation input: %v", err)
	}
	claims, err := st.ClaimSituationInputs(ctx, "test-worker", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim seed situation input: claims=%d err=%v", len(claims), err)
	}
	if err := st.ApplySituationInput(ctx, claims[0]); err != nil {
		t.Fatalf("apply seed situation input: %v", err)
	}
	return incidentID
}

// countSituationInputKind counts situation_input_outbox rows of kind for
// incidentID — the write-back enqueue's own visible effect.
func countSituationInputKind(t *testing.T, st *store.Store, incidentID, kind string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id = ? AND kind = ?`, incidentID, kind).Scan(&n); err != nil {
		t.Fatalf("count situation inputs: %v", err)
	}
	return n
}

// TestAnnotate_NoDirectNotifyEnqueuesOperatorAnnotationRecordedInput proves
// Task 8's Step 5 cutover end to end from the CaptureEngine's own entry
// point: Annotate never calls a notifier directly (no direct Slack call),
// and — because the target Incident belongs to an active Situation — the
// durable write-back enqueues exactly one operator_annotation_recorded
// situation_input_outbox row (the "one attributable Situation journal"
// input a later controller reconciliation cycle folds into a Transition).
func TestAnnotate_NoDirectNotifyEnqueuesOperatorAnnotationRecordedInput(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	incidentID := situationOwnedIncident(t, st, "service=annotate-situation")
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))

	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{
		IncidentID: incidentID, Kind: "observation", Note: "fyi",
	}); err != nil {
		t.Fatal(err)
	}

	if len(sink.events) != 0 {
		t.Fatalf("Annotate must never call a notifier directly; sink saw %+v", sink.events)
	}
	if n := countSituationInputKind(t, st, incidentID, "operator_annotation_recorded"); n != 1 {
		t.Fatalf("operator_annotation_recorded situation inputs = %d, want 1", n)
	}
}

// readRefuteMarks reads memory_refute_marks for an incident — used to assert
// annotate (D7) never touches the marks floor.
func readRefuteMarks(t *testing.T, st *store.Store, ctx context.Context, incidentID string) int {
	t.Helper()
	var marks int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, incidentID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	return marks
}

func TestAnnotate_Validation(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))
	ctx := context.Background()

	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: inc.ID, Kind: "confirmation", Note: "x"}); err == nil {
		t.Fatal("kind=confirmation must be rejected — only capture writes it")
	}
	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: "nope", Kind: "observation", Note: "x"}); err == nil {
		t.Fatal("unknown incident must error")
	}

	res, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: inc.ID, Kind: "observation", Note: "fyi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Demoted {
		t.Fatal("an observation must not demote")
	}
	if marks := readRefuteMarks(t, st, ctx, inc.ID); marks != 0 {
		t.Fatalf("an observation must not touch marks, got %d", marks)
	}
}

// --------------------------------------------------------------------------
// CaptureVerdict — persist phase (Task 12): grading is stubbed
// (ReplayFailed: true) until Task 13 wires the grade phase.
// --------------------------------------------------------------------------

func TestCaptureVerdict_PersistPhase(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promHealthy(t)))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:   json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries:  []string{"node_network_up"},
		CauseCategory: "network-flap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != 1 {
		t.Fatalf("version: %d", res.Version)
	}

	v, err := st.LatestIncidentVerdict(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v == nil || v.Version != 1 || v.Verdict != "correction" {
		t.Fatalf("verdict row: %+v", v)
	}
	var widened []acutetriage.VerificationQuery
	if err := json.Unmarshal([]byte(v.WidenedJSON), &widened); err != nil {
		t.Fatalf("widened_json: %v (%q)", err, v.WidenedJSON)
	}
	if len(widened) != 1 || widened[0].Kind != "promql" || widened[0].Source != "capture" || widened[0].Result == "" {
		t.Fatalf("widened entry wrong: %+v", widened)
	}

	anns, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	// No free-text note and no cause_alert on the expectation: the note
	// synthesizes to the bare verb — must_not_conclude ("AZ outage") is
	// grading vocabulary (R6) and must never surface in the synthesized note.
	if len(anns) != 1 || anns[0].Kind != "correction" || anns[0].Note != "corrected" {
		t.Fatalf("annotation row: %+v", anns)
	}

	var marks int
	if err := st.DB().QueryRowContext(ctx, `SELECT memory_refute_marks FROM incidents WHERE id = ?`, inc.ID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 2 {
		t.Fatalf("marks floored at 2, got %d", marks)
	}

	if n := auditCount(t, st, "incident.verdict_captured"); n != 1 {
		t.Fatalf("want exactly one incident.verdict_captured audit row, got %d", n)
	}
	rep, err := audit.New(st.DB()).Verify(ctx)
	if err != nil || !rep.OK {
		t.Fatalf("audit chain must verify: report=%+v err=%v", rep, err)
	}
}

// TestCaptureVerdict_NoDirectNotifyEnqueuesCapturedVerdictRecordedInput
// mirrors TestAnnotate_NoDirectNotifyEnqueuesOperatorAnnotationRecordedInput
// for the CaptureVerdict persist phase: no direct notifier call, and exactly
// one captured_verdict_recorded situation input when the Incident belongs to
// an active Situation.
func TestCaptureVerdict_NoDirectNotifyEnqueuesCapturedVerdictRecordedInput(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	incidentID := situationOwnedIncident(t, st, "service=verdict-situation")
	insertTestAlert(t, st, ctx, incidentID, "fp-"+incidentID, map[string]string{"alertname": "TargetDown"})
	if err := st.SaveIncidentOutput(ctx, incidentID, `{"analysis_name":"x","overall_issue":"y"}`, "x", "y", 0.7, "{}"); err != nil {
		t.Fatalf("save incident output: %v", err)
	}
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promHealthy(t)))

	if _, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: incidentID, Verdict: "correction",
		Expectation: json.RawMessage(`{"must_not_conclude":["AZ outage"]}`),
	}); err != nil {
		t.Fatal(err)
	}

	if len(sink.events) != 0 {
		t.Fatalf("CaptureVerdict must never call a notifier directly; sink saw %+v", sink.events)
	}
	if n := countSituationInputKind(t, st, incidentID, "captured_verdict_recorded"); n != 1 {
		t.Fatalf("captured_verdict_recorded situation inputs = %d, want 1", n)
	}
}

func TestCaptureVerdict_RepeatCallSkipsPersist(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	prom, reqs := countingCaptureProm(t)
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, prom))

	req := acutetriage.CaptureRequest{
		IncidentID:   inc.ID,
		Verdict:      "correction",
		Expectation:  json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	}
	res1, err := eng.CaptureVerdict(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	afterFirst := *reqs
	annsAfterFirst, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}

	res2, err := eng.CaptureVerdict(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != res1.Version {
		t.Fatalf("repeat call versioned: %d != %d", res2.Version, res1.Version)
	}
	if *reqs != afterFirst {
		t.Fatalf("repeat call issued a new widening HTTP request: %d != %d", *reqs, afterFirst)
	}
	annsAfterSecond, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(annsAfterSecond) != len(annsAfterFirst) {
		t.Fatalf("repeat call wrote a new annotation row: %d != %d", len(annsAfterSecond), len(annsAfterFirst))
	}
}

func TestCaptureVerdict_ChangedExpectationVersions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promHealthy(t)))

	if _, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation: json.RawMessage(`{"must_not_conclude":["AZ outage"]}`),
	}); err != nil {
		t.Fatal(err)
	}
	res2, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation: json.RawMessage(`{"must_not_conclude":["different cause"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != 2 {
		t.Fatalf("changed expectation should version: got %d", res2.Version)
	}
	anns, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(anns) != 2 {
		t.Fatalf("want 2 annotation rows (one per capture), got %d", len(anns))
	}
}

func TestCaptureVerdict_NewWidenQueriesVersionAndMerge(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	prom, reqs := countingCaptureProm(t)
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, prom))

	req := acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	}
	if _, err := eng.CaptureVerdict(ctx, req); err != nil {
		t.Fatal(err)
	}
	afterFirst := *reqs

	req.WidenQueries = []string{"node_network_up", "rate(errors[5m])"}
	res2, err := eng.CaptureVerdict(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != 2 {
		t.Fatalf("new widen expr should version: got %d", res2.Version)
	}
	if got := *reqs - afterFirst; got != 1 {
		t.Fatalf("should fetch only the NEW expr (1 request), got %d", got)
	}
	v, err := st.LatestIncidentVerdict(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var widened []acutetriage.VerificationQuery
	if err := json.Unmarshal([]byte(v.WidenedJSON), &widened); err != nil {
		t.Fatal(err)
	}
	if len(widened) != 2 {
		t.Fatalf("widened_json should merge old+new: got %d entries", len(widened))
	}
}

func TestCaptureVerdict_FailedWideningDegradesNotAborts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promAllFail(t)))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != 1 {
		t.Fatalf("a failed widening fetch must still persist the capture: version=%d", res.Version)
	}
	v, err := st.LatestIncidentVerdict(ctx, inc.ID)
	if err != nil || v == nil {
		t.Fatalf("verdict row must exist: v=%+v err=%v", v, err)
	}
	var widened []acutetriage.VerificationQuery
	if err := json.Unmarshal([]byte(v.WidenedJSON), &widened); err != nil {
		t.Fatal(err)
	}
	if len(widened) != 1 || widened[0].Outcome != acutetriage.OutcomeFailed {
		t.Fatalf("widened entry should record the failed outcome: %+v", widened)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "widening fetch failed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings should mention the failed fetch: %v", res.Warnings)
	}
}

// TestCaptureVerdict_InvalidWideningDegradesNotAborts covers a widen expr
// that fails LOCAL PromQL validation (issue #62: a function call followed by
// a bare "by (...)" clause, e.g. `func(...) by (...)` instead of `agg by
// (...) (func(...))`) — it must never reach Prometheus at all, land as
// OutcomeInvalid, and still only degrade the capture with a warning, never
// abort the persist phase (mirrors TestCaptureVerdict_FailedWideningDegradesNotAborts
// for the backend-rejected case).
func TestCaptureVerdict_InvalidWideningDegradesNotAborts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promHealthy(t)))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{`increase(metric_name[1h]) by (type)`},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := st.LatestIncidentVerdict(ctx, inc.ID)
	if err != nil || v == nil {
		t.Fatalf("verdict row must exist: v=%+v err=%v", v, err)
	}
	var widened []acutetriage.VerificationQuery
	if err := json.Unmarshal([]byte(v.WidenedJSON), &widened); err != nil {
		t.Fatal(err)
	}
	if len(widened) != 1 || widened[0].Outcome != acutetriage.OutcomeInvalid {
		t.Fatalf("invalid widening outcome = %+v", widened)
	}
	if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.Contains(s, "widening fetch failed") }) {
		t.Fatalf("missing invalid-widen warning: %v", res.Warnings)
	}
}

func TestCaptureVerdict_Validation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st)
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCaptureWithProm(t, st, sink, promHealthy(t)))

	if _, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "observation",
		Expectation: json.RawMessage(`{"must_not_conclude":["x"]}`),
	}); err == nil {
		t.Fatal("bad verdict accepted")
	}

	noFindingInc := store.Incident{}
	{
		now := time.Now()
		id := uuid.NewString()
		if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "service=nofinding", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkIncidentReady(ctx, id); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetIncidentByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		noFindingInc = *got
	}
	if _, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: noFindingInc.ID, Verdict: "correction",
		Expectation: json.RawMessage(`{"must_not_conclude":["x"]}`),
	}); err == nil || !strings.Contains(err.Error(), "no finding to grade") {
		t.Fatalf("want a 'no finding to grade' error, got %v", err)
	}

	widen11 := make([]string, 11)
	for i := range widen11 {
		widen11[i] = "expr" + string(rune('a'+i))
	}
	if _, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"must_not_conclude":["x"]}`),
		WidenQueries: widen11,
	}); err == nil || !strings.Contains(err.Error(), "10") {
		t.Fatalf("want an error naming the cap of 10, got %v", err)
	}

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation: json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["x"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	lintFound := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "expectation unverifiable") {
			lintFound = true
		}
	}
	if !lintFound {
		t.Fatalf("want an unverifiable-cause-series lint warning, got %v", res.Warnings)
	}
}

// --------------------------------------------------------------------------
// CaptureVerdict — grade phase (Task 13): two-stage advisory grading.
// --------------------------------------------------------------------------

// captureEngineWithHint mirrors expectation_test.go's engineWithHint (that
// one lives in the internal `acutetriage` package and is unreachable from
// here): a one-rule *rules.Engine matching alertname=TargetDown whose
// then.root_cause_hint carries hint — the "steering rule" fixture.
func captureEngineWithHint(t *testing.T, hint string) *rules.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte("name: test\nversion: \"0.0.1\"\nupdated: \"2026-07-24\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ruleYAML := `rules:
  - id: test.steering-hint
    kind: correlation
    description: Steering hint for TargetDown
    when:
      all:
        - label: alertname
          op: equals
          value: TargetDown
    then:
      root_cause_hint: ` + hint + `
    updated: "2026-07-24"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "01-hint.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := rules.NewEngine(context.Background(), nil, rules.NewLocalDirSource(dir, 0))
	if err != nil {
		t.Fatalf("build rule engine: %v", err)
	}
	return e
}

// explodingLLM fails the test if ever called — proves a code path never
// reaches the LLM (stage-1 red must short-circuit before any grading call).
type explodingLLM struct{ t *testing.T }

func (e *explodingLLM) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	e.t.Helper()
	e.t.Fatal("LLM must not be called")
	return llm.Completion{}, nil
}

// seedGradableIncident seeds an analyzed incident (via a real Run, no
// steering rule, no model-proposed verification query — a floor-only round)
// carrying a "TargetDown" member alert on worker-14 — the fixture Task 13's
// grading tests capture a verdict against and replay under current rules.
func seedGradableIncident(t *testing.T, st *store.Store, prom *promclient.Client) store.Incident {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	id := uuid.NewString()
	if err := st.InsertIncident(ctx, store.Incident{
		ID: id, GroupKey: "namespace=prod", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	a := store.Alert{
		ID: uuid.NewString(), Fingerprint: "fp-" + id, Status: "firing",
		Labels:      map[string]string{"alertname": "TargetDown", "namespace": "prod", "instance": "worker-14"},
		Annotations: map[string]string{"summary": "target down"},
		StartsAt:    now, ReceivedAt: now,
	}
	stored, err := st.UpsertAlertByFingerprint(ctx, a)
	if err != nil {
		t.Fatalf("upsert alert: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, id, stored.ID, now); err != nil {
		t.Fatalf("add alert: %v", err)
	}

	seedLLM := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "TargetDown", "target down", 0.6, nil)},
		{raw: callTwoResp(t, "TargetDown", "target down", 0.6, "")},
	}}
	seedSkill := acutetriage.New(verifyConfig(prom), st, seedLLM, audit.New(st.DB()), nil, nil)
	inc, err := st.GetIncidentByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedSkill.Run(ctx, *inc); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	got, err := st.GetIncidentByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return *got
}

// gradeSkill builds the Skill CaptureEngine grades against — the "current
// triage" wiring (rules/LLM the operator's install runs NOW, which may
// differ from what produced the incident's original finding).
func gradeSkill(t *testing.T, st *store.Store, llmClient acutetriage.LLMClient, rulesEngine *rules.Engine, prom *promclient.Client, sink *fakeAnnotationSink) *acutetriage.Skill {
	t.Helper()
	cfg := verifyConfig(prom)
	cfg.Rules = rulesEngine
	return acutetriage.New(cfg, st, llmClient, audit.New(st.DB()), notify.NewMulti(nil, sink), nil)
}

func TestGrade_Stage1RedEvidenceSelection(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	eng := acutetriage.NewCaptureEngine(gradeSkill(t, st, &explodingLLM{t: t}, nil, prom, &fakeAnnotationSink{}))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != "red" || res.Layer != "evidence_selection" {
		t.Fatalf("grade=%q layer=%q warnings=%v", res.Grade, res.Layer, res.Warnings)
	}
	if res.ReplayFidelity != "" {
		t.Fatalf("stage-1 red must not run stage 2, got fidelity %q", res.ReplayFidelity)
	}
	if res.ReplayFailed {
		t.Fatal("a graded (non-erroring) capture must not report replay_failed")
	}
}

func TestGrade_Stage2GreenWithSteeringRule(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	gradeLLM := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "TargetDown", "flapping NIC", 0.70, []map[string]any{
			{"kind": "promql", "expr": "node_network_up", "why": "discriminates NIC flap"},
		})},
		{raw: callTwoResp(t, "NIC flap", "flapping NIC on worker-14", 0.75, "")},
	}}
	hintEngine := captureEngineWithHint(t, "check node_network_up on the flapping NIC")
	eng := acutetriage.NewCaptureEngine(gradeSkill(t, st, gradeLLM, hintEngine, prom, &fakeAnnotationSink{}))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"cause_series":["node_network_up"],"must_mention":["worker-14"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != "green" {
		t.Fatalf("grade=%q layer=%q warnings=%v", res.Grade, res.Layer, res.Warnings)
	}
	if res.ReplayFidelity != "full" {
		t.Fatalf("fidelity=%q, want full", res.ReplayFidelity)
	}
}

func TestGrade_SynthesisRed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	gradeLLM := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "TargetDown", "flapping NIC", 0.70, []map[string]any{
			{"kind": "promql", "expr": "node_network_up", "why": "discriminates NIC flap"},
		})},
		{raw: callTwoResp(t, "AZ event", "regional AZ outage in eu-west-1", 0.75, "")},
	}}
	hintEngine := captureEngineWithHint(t, "check node_network_up on the flapping NIC")
	eng := acutetriage.NewCaptureEngine(gradeSkill(t, st, gradeLLM, hintEngine, prom, &fakeAnnotationSink{}))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != "red" || res.Layer != "synthesis" {
		t.Fatalf("grade=%q layer=%q warnings=%v", res.Grade, res.Layer, res.Warnings)
	}
}

func TestGrade_ConfirmationRegression(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	gradeLLM := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "TargetDown", "still fine", 0.6, nil)},
		{raw: callTwoResp(t, "unrelated", "something else entirely", 0.6, "")},
	}}
	eng := acutetriage.NewCaptureEngine(gradeSkill(t, st, gradeLLM, nil, prom, &fakeAnnotationSink{}))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "confirmation",
		Expectation: json.RawMessage(`{"must_mention":["worker-14"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != "red" {
		t.Fatalf("a regressed confirmation must grade red, got %q layer=%q warnings=%v", res.Grade, res.Layer, res.Warnings)
	}
}

func TestGrade_ReplayFailureLeavesCaptureIntact(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	gradeLLM := &scriptedLLM{responses: []scriptResp{{err: errors.New("boom")}}}
	eng := acutetriage.NewCaptureEngine(gradeSkill(t, st, gradeLLM, nil, prom, &fakeAnnotationSink{}))

	res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation: json.RawMessage(`{"must_mention":["worker-14"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayFailed {
		t.Fatal("want replay_failed true")
	}
	if res.Grade != "" {
		t.Fatalf("grade must be empty on a replay failure, got %q", res.Grade)
	}
	v, err := st.LatestIncidentVerdict(ctx, inc.ID)
	if err != nil || v == nil {
		t.Fatalf("verdict row must exist despite grading failure: v=%+v err=%v", v, err)
	}
	anns, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil || len(anns) != 1 {
		t.Fatalf("annotation row must exist: anns=%+v err=%v", anns, err)
	}
	if n := auditCount(t, st, "incident.verdict_captured"); n != 1 {
		t.Fatalf("audit row must exist, got %d", n)
	}
}

func TestGrade_RepeatCallRegrades(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom, reqs := countingCaptureProm(t)
	inc := seedGradableIncident(t, st, prom)

	req := acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "correction",
		Expectation:  json.RawMessage(`{"cause_series":["node_network_up"],"must_not_conclude":["AZ outage"]}`),
		WidenQueries: []string{"node_network_up"},
	}
	eng1 := acutetriage.NewCaptureEngine(gradeSkill(t, st, &explodingLLM{t: t}, nil, prom, &fakeAnnotationSink{}))
	res1, err := eng1.CaptureVerdict(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res1.Grade != "red" || res1.Layer != "evidence_selection" {
		t.Fatalf("first call: grade=%q layer=%q", res1.Grade, res1.Layer)
	}
	reqsAfterFirst := *reqs
	annsAfterFirst, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}

	gradeLLM := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "TargetDown", "flapping NIC", 0.70, []map[string]any{
			{"kind": "promql", "expr": "node_network_up", "why": "discriminates NIC flap"},
		})},
		{raw: callTwoResp(t, "NIC flap", "flapping NIC on worker-14", 0.75, "")},
	}}
	hintEngine := captureEngineWithHint(t, "check node_network_up on the flapping NIC")
	eng2 := acutetriage.NewCaptureEngine(gradeSkill(t, st, gradeLLM, hintEngine, prom, &fakeAnnotationSink{}))
	res2, err := eng2.CaptureVerdict(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != res1.Version {
		t.Fatalf("repeat call versioned: %d != %d", res2.Version, res1.Version)
	}
	if res2.Grade != "green" {
		t.Fatalf("repeat call should re-grade fresh (green with the new rule), got %q layer=%q", res2.Grade, res2.Layer)
	}
	if *reqs != reqsAfterFirst {
		t.Fatalf("repeat call issued a new widening HTTP request: %d != %d", *reqs, reqsAfterFirst)
	}
	annsAfterSecond, err := st.ListIncidentAnnotations(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(annsAfterSecond) != len(annsAfterFirst) {
		t.Fatalf("repeat call wrote a new annotation row: %d != %d", len(annsAfterSecond), len(annsAfterFirst))
	}
}

// blockingLLM holds every completion until its ctx is canceled.
type blockingLLM struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockingLLM) Complete(ctx context.Context, _ string, _ llm.Prompt, _ []string) (llm.Completion, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return llm.Completion{}, ctx.Err()
}

// TestCaptureEngineCloseJoinsGrading: grading's live LLM calls are LLM
// capability observations (in flight while they run — fencing the idle
// probe — and reported when they finish). http.Server.Shutdown does not
// interrupt an MCP handler mid-grade, so the engine must be closable: Close
// cancels the grade (shutdown-driven cancellation is ignored, H1) and
// returns only once no grade is running, so the owner can stop the health
// runner knowing no producer is left.
func TestCaptureEngineCloseJoinsGrading(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	prom := promHealthy(t)
	inc := seedGradableIncident(t, st, prom)
	tr, err := llmhealth.New(ctx, st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := verifyConfig(prom)
	cfg.Health = tr
	gradeLLM := &blockingLLM{started: make(chan struct{})}
	eng := acutetriage.NewCaptureEngine(acutetriage.New(cfg, st, gradeLLM, audit.New(st.DB()), notify.NewMulti(nil, &fakeAnnotationSink{}), nil))

	type outcome struct {
		res *acutetriage.CaptureResult
		err error
	}
	got := make(chan outcome, 1)
	go func() {
		res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
			IncidentID: inc.ID, Verdict: "correction",
			Expectation: json.RawMessage(`{"must_mention":["worker-14"]}`),
		})
		got <- outcome{res, err}
	}()
	<-gradeLLM.started
	if n := tr.Snapshot().InFlight; n != 1 {
		t.Fatalf("in_flight during grading = %d, want 1: a grading call must fence the idle probe", n)
	}

	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := eng.Close(cctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case o := <-got:
		if o.err != nil || !o.res.ReplayFailed {
			t.Fatalf("after Close: err=%v res=%+v, want a captured verdict with replay_failed", o.err, o.res)
		}
	default:
		t.Fatal("Close returned while the grade was still running")
	}
	snap := tr.Snapshot()
	if snap.InFlight != 0 || snap.LastRealSuccessAt != nil || len(snap.Capabilities) != 0 {
		t.Fatalf("a shutdown-canceled grade must leave no observation: %+v", snap)
	}
	// A call that begins after Close is refused before it touches the store:
	// the store is about to close behind the engine, so nothing may start a
	// persist phase the owner can no longer wait for. The operator's verdict
	// is not lost — it was never accepted; the MCP caller gets a clear error.
	late, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
		IncidentID: inc.ID, Verdict: "confirmation",
		Expectation: json.RawMessage(`{"must_mention":["worker-14"]}`),
	})
	if !errors.Is(err, acutetriage.ErrCaptureClosed) || late != nil {
		t.Fatalf("capture after Close: err=%v res=%+v, want ErrCaptureClosed and no result", err, late)
	}
	if v, err := st.LatestIncidentVerdict(ctx, inc.ID); err != nil || v == nil || v.Version != 1 {
		t.Fatalf("a refused capture must persist nothing: latest verdict = %+v (err %v), want v1 only", v, err)
	}
	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: inc.ID, Kind: "observation", Note: "late"}); !errors.Is(err, acutetriage.ErrCaptureClosed) {
		t.Fatalf("annotate after Close: err=%v, want ErrCaptureClosed", err)
	}
	if n := tr.Snapshot().InFlight; n != 0 {
		t.Fatalf("a refused call must not touch the tracker: in_flight=%d", n)
	}
}

// blockingWidenProm builds a Prometheus test server whose query handler
// blocks until release is closed, signaling started exactly once first. It
// is TestCaptureEngineCloseWaitsForThePersistPhase's mid-persist observation
// point: since Task 8 removed capture.go's own notifyAnnotation fan-out (the
// former last step of the persist phase, strictly before grading), the live
// widen() fetch is the only externally-blockable step left inside
// persistCapture, so this replaces the former blockingSink.
func blockingWidenProm(t *testing.T, started, release chan struct{}) *promclient.Client {
	t.Helper()
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(vectorValue3))
	}))
	t.Cleanup(srv.Close)
	return promclient.NewClient(promclient.Config{BaseURL: srv.URL, TimeoutSeconds: 30})
}

// TestCaptureEngineCloseWaitsForThePersistPhase: the engine's join must cover
// the WHOLE Captured-verdict operation, not just its grade. A handler still
// persisting (store writes, audit, widening) is invisible to an
// http.Server.Shutdown that has given up, so if Close could return while one
// is in the persist phase, the owner would close the store underneath it —
// and the runner's final pass would run with a producer about to enter
// grading. Close returns only once the operation has left; the operation
// itself completes its persist (the verdict lands) and only its grade is
// refused.
func TestCaptureEngineCloseWaitsForThePersistPhase(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedProm := promHealthy(t)
	inc := seedGradableIncident(t, st, seedProm)
	tr, err := llmhealth.New(ctx, st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	cfg := verifyConfig(blockingWidenProm(t, started, release))
	cfg.Verification.QueryTimeoutSeconds = 30
	cfg.Health = tr
	sink := &fakeAnnotationSink{}
	gradeLLM := &blockingLLM{started: make(chan struct{})}
	eng := acutetriage.NewCaptureEngine(acutetriage.New(cfg, st, gradeLLM, audit.New(st.DB()), notify.NewMulti(nil, sink), nil))

	type outcome struct {
		res *acutetriage.CaptureResult
		err error
	}
	got := make(chan outcome, 1)
	go func() {
		res, err := eng.CaptureVerdict(ctx, acutetriage.CaptureRequest{
			IncidentID: inc.ID, Verdict: "correction",
			Expectation:  json.RawMessage(`{"must_mention":["worker-14"]}`),
			WidenQueries: []string{"node_network_up"},
		})
		got <- outcome{res, err}
	}()
	<-started // the operation is mid-persist (a live widen fetch), before enterGrade

	closed := make(chan error, 1)
	go func() {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		closed <- eng.Close(cctx)
	}()
	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while a capture was still in its persist phase; the owner would close the store underneath it", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return once the operation left")
	}
	select {
	case o := <-got:
		if o.err != nil || !o.res.ReplayFailed || o.res.Version != 1 {
			t.Fatalf("operation overlapping Close: err=%v res=%+v, want the verdict persisted (v1) and only the grade refused", o.err, o.res)
		}
	default:
		t.Fatal("Close returned before the operation did")
	}
	select {
	case <-gradeLLM.started:
		t.Fatal("a grade must not start once Close has begun")
	default:
	}
	if v, err := st.LatestIncidentVerdict(ctx, inc.ID); err != nil || v == nil || v.Version != 1 {
		t.Fatalf("persist phase must complete before Close returns: latest verdict = %+v (err %v)", v, err)
	}
}
