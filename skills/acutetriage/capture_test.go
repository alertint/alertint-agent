// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// fakeAnnotationSink is a notify.Notifier that also implements
// notify.AnnotationSink, so capture-engine tests can assert what the fan-out
// saw without a real Slack/stdout notifier.
type fakeAnnotationSink struct {
	events []notify.AnnotationEvent
}

func (f *fakeAnnotationSink) Name() string { return "fake" }
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

// seedAnalyzedIncidentOnKey inserts an incident on groupKey with one member
// alert and a persisted (trivial) finding — status "analyzed" — the input
// shape the capture engine's write tools operate on.
func seedAnalyzedIncidentOnKey(t *testing.T, st *store.Store, groupKey string) store.Incident {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	inc := store.Incident{
		ID: uuid.NewString(), GroupKey: groupKey,
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

func TestAnnotate_CorrectionDemotesAuditsNotifies(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))

	res, err := eng.Annotate(context.Background(), acutetriage.AnnotateRequest{
		IncidentID: inc.ID, Kind: "correction", Note: "not an AZ outage",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Demoted {
		t.Fatal("correction must demote")
	}

	var marks int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, inc.ID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 2 { // demotionThreshold
		t.Fatalf("marks floored at 2, got %d", marks)
	}

	if n := auditCount(t, st, "incident.annotated"); n != 1 {
		t.Fatalf("want exactly one incident.annotated audit row, got %d", n)
	}
	auditor := audit.New(st.DB())
	rep, err := auditor.Verify(context.Background())
	if err != nil || !rep.OK {
		t.Fatalf("audit chain must verify: report=%+v err=%v", rep, err)
	}

	if len(sink.events) != 1 || sink.events[0].Kind != "correction" || sink.events[0].Note != "not an AZ outage" {
		t.Fatalf("annotation sink saw %+v", sink.events)
	}
}

func TestAnnotate_Validation(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
	var marks int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, inc.ID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 0 {
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
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
	if len(anns) != 1 || anns[0].Kind != "correction" || !strings.Contains(anns[0].Note, "not AZ outage") {
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

func TestCaptureVerdict_RepeatCallSkipsPersist(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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

func TestCaptureVerdict_Validation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
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
