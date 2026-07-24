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
