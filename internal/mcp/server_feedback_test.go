// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// failingLLM always errors — used so a capture-verdict handler test can
// exercise the replay_failed path without a real model.
type failingLLM struct{}

func (failingLLM) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return llm.Completion{}, errors.New("boom")
}

// captureTestServer builds a Server wired with a real CaptureEngine (over st,
// a failing LLM — the write handlers' happy paths never need a green grade)
// so the two write-back tools can be exercised end-to-end.
func captureTestServer(t *testing.T, st *store.Store) *Server {
	t.Helper()
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, failingLLM{}, audit.New(st.DB()), nil, nil)
	eng := acutetriage.NewCaptureEngine(sk)
	return &Server{cfg: Config{Capture: eng}, st: st, auditor: audit.New(st.DB())}
}

func TestIncidentAnnotate_HappyPath(t *testing.T) {
	st := newMCPStore(t)
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	s := captureTestServer(t, st)

	res, err := s.handleIncidentAnnotate(context.Background(), reqWith(map[string]any{
		"incident_id": "inc1", "kind": "correction", "note": "not an AZ outage",
	}))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if payload["demoted"] != true {
		t.Fatalf("payload: %v", payload)
	}
	if _, ok := payload["annotation_id"]; !ok {
		t.Fatalf("missing annotation_id: %v", payload)
	}
	anns, err := st.ListIncidentAnnotations(context.Background(), "inc1")
	if err != nil || len(anns) != 1 {
		t.Fatalf("store row missing: anns=%+v err=%v", anns, err)
	}
}

func TestIncidentAnnotate_Validation(t *testing.T) {
	st := newMCPStore(t)
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	s := captureTestServer(t, st)
	ctx := context.Background()

	res, err := s.handleIncidentAnnotate(ctx, reqWith(map[string]any{"kind": "correction", "note": "x"}))
	if err != nil || !res.IsError {
		t.Fatalf("missing incident_id must error: %v %+v", err, res)
	}
	res, err = s.handleIncidentAnnotate(ctx, reqWith(map[string]any{"incident_id": "inc1", "kind": "confirmation", "note": "x"}))
	if err != nil || !res.IsError {
		t.Fatalf("kind=confirmation must error (capture-only): %v %+v", err, res)
	}
	if !strings.Contains(resultText(t, res), "capture") {
		t.Fatalf("error should mention capture: %s", resultText(t, res))
	}

	nilCaptureServer := &Server{cfg: Config{}, st: st, auditor: audit.New(st.DB())}
	res, err = nilCaptureServer.handleIncidentAnnotate(ctx, reqWith(map[string]any{"incident_id": "inc1", "kind": "correction", "note": "x"}))
	if err != nil || !res.IsError {
		t.Fatalf("nil capture engine must error: %v %+v", err, res)
	}
}

func TestIncidentCaptureVerdict_HappyAndFailedReplay(t *testing.T) {
	st := newMCPStore(t)
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	s := captureTestServer(t, st)

	res, err := s.handleIncidentCaptureVerdict(context.Background(), reqWith(map[string]any{
		"incident_id":   "inc1",
		"verdict":       "correction",
		"expectation":   map[string]any{"must_not_conclude": []any{"AZ outage"}},
		"widen_queries": []any{"node_network_up"},
	}))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if _, ok := payload["verdict_id"]; !ok {
		t.Fatalf("missing verdict_id: %v", payload)
	}
	if payload["version"] != float64(1) {
		t.Fatalf("version: %v", payload)
	}
	if payload["replay_failed"] != true {
		t.Fatalf("want replay_failed true (failingLLM), got: %v", payload)
	}
	if _, hasGrade := payload["grade"]; hasGrade {
		t.Fatalf("grade must be absent when replay_failed: %v", payload)
	}
	v, err := st.LatestIncidentVerdict(context.Background(), "inc1")
	if err != nil || v == nil {
		t.Fatalf("verdict row missing: v=%+v err=%v", v, err)
	}
}

// TestIncidentCaptureVerdict_MalformedWidenQueriesErrors covers a
// widen_queries argument that doesn't match the documented shape (an array
// of strings): the handler must error, not silently drop the discriminating
// evidence the caller asked to be fetched and frozen.
func TestIncidentCaptureVerdict_MalformedWidenQueriesErrors(t *testing.T) {
	st := newMCPStore(t)
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	s := captureTestServer(t, st)
	ctx := context.Background()

	res, err := s.handleIncidentCaptureVerdict(ctx, reqWith(map[string]any{
		"incident_id":   "inc1",
		"verdict":       "correction",
		"expectation":   map[string]any{"must_not_conclude": []any{"AZ outage"}},
		"widen_queries": "node_network_up", // not an array
	}))
	if err != nil || !res.IsError {
		t.Fatalf("a non-array widen_queries must error: %v %+v", err, res)
	}

	res, err = s.handleIncidentCaptureVerdict(ctx, reqWith(map[string]any{
		"incident_id":   "inc1",
		"verdict":       "correction",
		"expectation":   map[string]any{"must_not_conclude": []any{"AZ outage"}},
		"widen_queries": []any{"node_network_up", float64(1)}, // non-string element
	}))
	if err != nil || !res.IsError {
		t.Fatalf("a widen_queries element that isn't a string must error: %v %+v", err, res)
	}
	// No verdict must have been persisted by either malformed call.
	if v, err := st.LatestIncidentVerdict(ctx, "inc1"); err != nil || v != nil {
		t.Fatalf("malformed widen_queries must not persist a verdict: v=%+v err=%v", v, err)
	}
}

func TestGetIncident_ExposesAnnotationsAndVerdict(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	seedAnalyzedPrior(t, st, "inc2", "service=other", "root cause", 0.7, time.Now(), false)

	if _, err := st.InsertIncidentAnnotation(ctx, "inc1", "observation", "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertIncidentAnnotation(ctx, "inc1", "correction", "second"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.PersistVerdictCapture(ctx, store.VerdictCapture{
		IncidentID: "inc1", Verdict: "correction",
		ExpectationJSON: `{"must_not_conclude":["x"]}`, AnnotationNote: "n",
		CauseCategory: "network-flap",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: Config{}, st: st, auditor: audit.New(st.DB())}
	res, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": "inc1"}))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatal(err)
	}
	anns, ok := payload["annotations"].([]any)
	if !ok || len(anns) != 3 { // 2 explicit + 1 from PersistVerdictCapture's own annotation row
		t.Fatalf("annotations: %v", payload["annotations"])
	}
	first, ok := anns[0].(map[string]any)
	if !ok || first["note"] != "n" { // newest-first: PersistVerdictCapture's row ("n") is newest
		t.Fatalf("annotations[0] not newest-first: %v", anns[0])
	}
	verdict, ok := payload["verdict"].(map[string]any)
	if !ok || verdict["kind"] != "correction" || verdict["version"] != float64(1) || verdict["cause_category"] != "network-flap" {
		t.Fatalf("verdict: %v", payload["verdict"])
	}

	res2, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": "inc2"}))
	if err != nil || res2.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res2))
	}
	var payload2 map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res2)), &payload2); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload2["annotations"]; ok {
		t.Fatalf("incident without annotations must omit the key: %v", payload2["annotations"])
	}
	if _, ok := payload2["verdict"]; ok {
		t.Fatalf("incident without a verdict must omit the key: %v", payload2["verdict"])
	}
}

func TestListIncidents_VerdictKind(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	seedAnalyzedPrior(t, st, "inc1", "service=api", "root cause", 0.7, time.Now(), false)
	seedAnalyzedPrior(t, st, "inc2", "service=other", "root cause", 0.7, time.Now(), false)
	if _, _, err := st.PersistVerdictCapture(ctx, store.VerdictCapture{
		IncidentID: "inc1", Verdict: "correction",
		ExpectationJSON: `{"must_not_conclude":["x"]}`, AnnotationNote: "n",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: Config{}, st: st, auditor: audit.New(st.DB())}
	res, err := s.handleListIncidents(ctx, reqWith(map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Incidents []map[string]any `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, r := range payload.Incidents {
		id, ok := r["id"].(string)
		if !ok {
			t.Fatalf("row missing string id: %v", r)
		}
		byID[id] = r
	}
	if byID["inc1"]["verdict_kind"] != "correction" {
		t.Fatalf("inc1 verdict_kind: %v", byID["inc1"]["verdict_kind"])
	}
	if _, ok := byID["inc2"]["verdict_kind"]; ok {
		t.Fatalf("inc2 has no verdict, key must be omitted: %v", byID["inc2"]["verdict_kind"])
	}
}
