// SPDX-License-Identifier: FSL-1.1-ALv2

package triage_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/triage"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
)

type fakeJudgeLLM struct {
	response string
}

func (f *fakeJudgeLLM) Complete(_ context.Context, _ string, _ llm.Prompt, _ []string) (llm.Completion, error) {
	return llm.Completion{Raw: json.RawMessage(f.response), Model: "fake", Latency: time.Millisecond}, nil
}

func TestJudge_PassVerdict(t *testing.T) {
	g := &triage.Golden{
		RenderedFinding: json.RawMessage(`{"analysis_name":"x","overall_issue":"y","correlation_findings":["z"],"severity":"high","confidence":0.9,"alerts":[{"alert_id":"a1","role_in_incident":"correlated"}]}`),
		Incident: triage.IncidentSnapshot{
			AlertCount: 1,
			Alerts: []triage.AlertSnapshot{{
				ID:     "a1",
				Labels: map[string]string{"alertname": "DiskFull", "severity": "critical"},
			}},
		},
	}
	client := &fakeJudgeLLM{response: `{"verdict":"pass","reasons":[],"missing":[]}`}
	v, _, err := triage.Judge(context.Background(), client, g)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if v.Decision != "pass" {
		t.Fatalf("verdict = %q, want pass", v.Decision)
	}
}

func TestJudge_FailVerdict(t *testing.T) {
	g := &triage.Golden{
		RenderedFinding: json.RawMessage(`{"analysis_name":"x","overall_issue":"y","correlation_findings":["z"],"severity":"low","confidence":0.9,"alerts":[{"alert_id":"a1","role_in_incident":"correlated"}]}`),
		Incident: triage.IncidentSnapshot{
			AlertCount: 1,
			Alerts: []triage.AlertSnapshot{{
				ID:     "a1",
				Labels: map[string]string{"alertname": "DiskFull", "severity": "critical"},
			}},
		},
	}
	client := &fakeJudgeLLM{response: `{"verdict":"fail","reasons":["severity mismatch"],"missing":[]}`}
	v, _, err := triage.Judge(context.Background(), client, g)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if v.Decision != "fail" {
		t.Fatalf("verdict = %q, want fail", v.Decision)
	}
	if len(v.Reasons) == 0 {
		t.Fatal("expected reasons")
	}
}

func TestJudge_NilClient(t *testing.T) {
	g := &triage.Golden{}
	_, _, err := triage.Judge(context.Background(), nil, g)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}
