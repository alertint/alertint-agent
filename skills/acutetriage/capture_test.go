// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
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
