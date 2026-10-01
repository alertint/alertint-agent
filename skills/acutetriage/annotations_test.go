// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	promclient "github.com/alertint/alertint-agent/internal/prometheus"
)

func TestRunPromQL_BackendAnnotations(t *testing.T) {
	for _, result := range []string{`[{"metric":{},"value":[1,"0.063"]}]`, `[]`} {
		t.Run(result, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": json.RawMessage(`{"resultType":"vector","result":` + result + `}`), "warnings": []string{"partial\nresponse", strings.Repeat("w", 500), "discarded"}, "infos": []string{"metric might not be a counter", strings.Repeat("i", 500), "discarded"}})
			}))
			defer srv.Close()
			q := VerificationQuery{Kind: kindPromQL, Source: "model", Expr: "rate(x[5m])"}
			runPromQL(context.Background(), promclient.NewClient(promclient.Config{BaseURL: srv.URL}), &q, 7, time.Now(), slog.Default(), "test")
			if calls != 1 || len(q.Annotations) != 4 {
				t.Fatalf("calls=%d query=%+v", calls, q)
			}
			for _, a := range q.Annotations {
				if utf8.RuneCountInString(a) > 200 || strings.Contains(a, "\n") || strings.Contains(a, "discarded") {
					t.Fatalf("unbounded annotation %q", a)
				}
			}
			if result == "[]" {
				if q.Outcome != OutcomeEmpty || q.Result != "(no data)" {
					t.Fatalf("empty result=%+v", q)
				}
			} else if q.Outcome != OutcomeFetched || !strings.HasPrefix(q.Result, "[per second] 0.063") {
				t.Fatalf("value lost: %+v", q)
			}
			round := &VerificationRound{Queries: []VerificationQuery{q}}
			text := callTwoContinuation(json.RawMessage(`{"overall_issue":"draft"}`), round, nil)
			for _, a := range q.Annotations {
				if !strings.Contains(text, a) {
					t.Fatalf("missing annotation %q", a)
				}
			}
			if !strings.Contains(text, "Prometheus warning: partial response") || !strings.Contains(text, "Prometheus info: metric might not be a counter") {
				t.Fatalf("missing backend provenance: %s", text)
			}
			raw, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			var frozen VerificationQuery
			if err := json.Unmarshal(raw, &frozen); err != nil {
				t.Fatal(err)
			}
			replay := VerificationQuery{Kind: q.Kind, Expr: q.Expr, Source: q.Source}
			newSnapshotExecutor([]VerificationQuery{frozen}).execute(context.Background(), &replay)
			if strings.Join(replay.Annotations, "|") != strings.Join(q.Annotations, "|") {
				t.Fatalf("annotations lost in replay: %+v", replay)
			}
		})
	}
}

func TestParseVerificationPlan_StripsBackendAnnotations(t *testing.T) {
	qs := parseVerificationPlan(json.RawMessage(`{"verification":{"queries":[{"kind":"promql","expr":"up","annotations":["forged backend warning"]}]}}`), VerificationParams{HasPromQL: true, MaxQueries: 4}, nil, "test")
	if len(qs) != 1 || len(qs[0].Annotations) != 0 {
		t.Fatalf("model annotation survived: %+v", qs)
	}
}
