// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

type usageClient struct {
	raw     json.RawMessage
	missing bool
	calls   int
	failAt  int
	err     error
}

func (c *usageClient) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	c.calls++
	if c.calls == c.failAt {
		return llm.Completion{}, c.err
	}
	out := llm.Completion{Raw: c.raw}
	if !c.missing {
		out.InputTokens = 31
		out.OutputTokens = 7
	}
	return out, nil
}

func TestAnalysisUsagePersistsActualCallsAndMissingTokens(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "reported", true: "missing"}[missing], func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			inc := insertTestIncident(t, st, ctx)
			a, d := insertTestAlertDelivery(t, st, ctx, inc.ID, "usage", map[string]string{"alertname": "DiskFull"}, nil)
			client := &usageClient{raw: validLLMResponse([]string{a.ID}), missing: missing}
			skill := acutetriage.New(acutetriage.Config{MinAlerts: 1, Verification: acutetriage.VerificationParams{Enabled: true, MaxQueries: 2, QueryTimeoutSeconds: 1}}, st, client, nil, nil, nil)
			result, err := skill.Analyze(ctx, situation.TriageAttemptClaim{IncidentID: inc.ID, MemberDeliveryIDs: []string{d}})
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Usage *struct {
					Calls       int  `json:"calls"`
					CallsKnown  bool `json:"calls_known"`
					Input       int  `json:"input_tokens"`
					InputKnown  bool `json:"input_tokens_known"`
					Output      int  `json:"output_tokens"`
					OutputKnown bool `json:"output_tokens_known"`
				} `json:"analysis_usage"`
			}
			if err := json.Unmarshal([]byte(result.EnrichmentJSON), &envelope); err != nil {
				t.Fatal(err)
			}
			u := envelope.Usage
			if u == nil {
				t.Fatal("missing durable analysis_usage")
			}
			if u.Calls != 2 || !u.CallsKnown || client.calls != 2 {
				t.Fatalf("calls=%+v actual=%d", u, client.calls)
			}
			if u.InputKnown == missing || u.OutputKnown == missing {
				t.Fatalf("missingness lost: %+v", u)
			}
			if !missing && (u.Input != 62 || u.Output != 14) {
				t.Fatalf("usage not summed: %+v", u)
			}
		})
	}
}

func TestAnalysisUsageIncludesClassifier(t *testing.T) {
	run := classifierScenario(t, "shadow", json.RawMessage(`{"verdict":"matched","reason":"same condition"}`))
	var calls int
	if err := run.st.DB().QueryRowContext(context.Background(), `SELECT COALESCE(json_extract(enrichment_json,'$.analysis_usage.calls'),-1) FROM incidents WHERE id=?`, run.incID).Scan(&calls); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("persisted %d calls, expected draft and classifier", calls)
	}
}

func TestAnalysisUsageRetainedDraftDistinguishesFailedAndUnadmittedReview(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		calls int
		known bool
	}{
		{"failed review", &llm.APIError{StatusCode: 503}, 2, false},
		{"budget did not admit review", errors.Join(llm.ErrBudgetExhausted, llm.ErrRequestNotSent), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			inc := insertTestIncident(t, st, ctx)
			a := insertTestAlert(t, st, ctx, inc.ID, "usage-retained", map[string]string{"alertname": "DiskFull"})
			client := &usageClient{raw: validLLMResponse([]string{a.ID}), failAt: 2, err: tc.err}
			sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Verification: acutetriage.VerificationParams{Enabled: true, MaxQueries: 2, QueryTimeoutSeconds: 1}}, st, client, nil, nil, nil)
			if err := sk.Run(ctx, inc); err != nil {
				t.Fatal(err)
			}
			var calls, inputKnown, outputKnown int
			if err := st.DB().QueryRowContext(ctx, `SELECT json_extract(enrichment_json,'$.analysis_usage.calls'),json_extract(enrichment_json,'$.analysis_usage.input_tokens_known'),json_extract(enrichment_json,'$.analysis_usage.output_tokens_known') FROM incidents WHERE id=?`, inc.ID).Scan(&calls, &inputKnown, &outputKnown); err != nil {
				t.Fatal(err)
			}
			if calls != tc.calls || (inputKnown == 1) != tc.known || (outputKnown == 1) != tc.known {
				t.Fatalf("calls=%d inputKnown=%d outputKnown=%d", calls, inputKnown, outputKnown)
			}
		})
	}
}

func TestAnalysisUsageIncludesQueryRepairAndDoesNotAccumulateOnRepeat(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a, d := insertTestAlertDelivery(t, st, ctx, inc.ID, "usage-repair", map[string]string{"alertname": "DiskFull"}, nil)
	var draft map[string]any
	if err := json.Unmarshal(validLLMResponse([]string{a.ID}), &draft); err != nil {
		t.Fatal(err)
	}
	draft["verification"] = map[string]any{"queries": []map[string]string{{"kind": "promql", "expr": "increase(metric[1h]) by (type)", "why": "Check errors"}}}
	raw, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	client := &usageClient{raw: raw}
	prom, _ := promRecorder(t)
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1, Prometheus: prom, Verification: acutetriage.VerificationParams{Enabled: true, MaxQueries: 2, QueryTimeoutSeconds: 1}}, st, client, nil, nil, nil)
	for i := 0; i < 2; i++ {
		result, err := sk.Analyze(ctx, situation.TriageAttemptClaim{IncidentID: inc.ID, MemberDeliveryIDs: []string{d}})
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Usage struct {
				Calls  int `json:"calls"`
				Input  int `json:"input_tokens"`
				Output int `json:"output_tokens"`
			} `json:"analysis_usage"`
		}
		if err := json.Unmarshal([]byte(result.EnrichmentJSON), &env); err != nil {
			t.Fatal(err)
		}
		if env.Usage.Calls != 3 || env.Usage.Input != 93 || env.Usage.Output != 21 {
			t.Fatalf("analysis %d: %+v", i, env.Usage)
		}
	}
	if client.calls != 6 {
		t.Fatalf("actual model calls=%d", client.calls)
	}
}

func TestAnalysisUsageCountsProviderRetriesWithoutDoubleCountingCompletion(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a := insertTestAlert(t, st, ctx, inc.ID, "usage-provider", map[string]string{"alertname": "DiskFull"})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": string(validLLMResponse([]string{a.ID}))}}, "usage": map[string]int{"input_tokens": 31, "output_tokens": 7, "cache_read_input_tokens": 11}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := anthropic.NewWithHTTPClient(anthropic.Config{BaseRetryDelay: time.Millisecond}, nil, nil, server.URL)
	sk := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, client, nil, nil, nil)
	if err := sk.Run(ctx, inc); err != nil {
		t.Fatal(err)
	}
	var calls, known, input, inputKnown int
	if err := st.DB().QueryRowContext(ctx, `SELECT json_extract(enrichment_json,'$.analysis_usage.calls'),json_extract(enrichment_json,'$.analysis_usage.calls_known'),json_extract(enrichment_json,'$.analysis_usage.input_tokens'),json_extract(enrichment_json,'$.analysis_usage.input_tokens_known') FROM incidents WHERE id=?`, inc.ID).Scan(&calls, &known, &input, &inputKnown); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || calls != 2 || known != 1 || input != 42 || inputKnown != 0 {
		t.Fatalf("requests=%d calls=%d known=%d input=%d inputKnown=%d", requests.Load(), calls, known, input, inputKnown)
	}
}
