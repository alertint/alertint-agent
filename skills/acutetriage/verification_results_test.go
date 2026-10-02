// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRunPromQL_MatrixHistory(t *testing.T) {
	data := json.RawMessage(`{"resultType":"matrix","result":[{"metric":{"__name__":"queue_bytes","service":"worker"},"values":[[100,"100"],[200,"150"],[300,"120"]]}]}`)
	q := VerificationQuery{Kind: kindPromQL, Source: "model", Expr: `queue_bytes{service="worker"}[1h]`}
	runPromQL(context.Background(), fakeQuerier(func(string) (json.RawMessage, error) { return data, nil }), &q, 100, time.Now(), slog.Default(), "history")
	if q.Outcome != OutcomeFetched {
		t.Fatalf("history discarded: %+v", q)
	}
	for _, want := range []string{"[bytes]", "range summary", "samples=3", "first=100@1970-01-01T00:01:40Z", "last=120@1970-01-01T00:05:00Z", "min=100", "max=150", "decreasing_steps=1"} {
		if !strings.Contains(q.Result, want) {
			t.Errorf("missing %q: %s", want, q.Result)
		}
	}
}

func TestRunPromQL_MatrixSpecialValues(t *testing.T) {
	data := json.RawMessage(`{"resultType":"matrix","result":[{"metric":{},"values":[[100,"NaN"],[200,"3"],[300,"+Inf"],[400,"2"]]}]}`)
	q := VerificationQuery{Kind: kindPromQL, Expr: `queue_depth[1h]`}
	runPromQL(context.Background(), fakeQuerier(func(string) (json.RawMessage, error) { return data, nil }), &q, 100, time.Now(), slog.Default(), "history")
	if q.Outcome != OutcomeFetched || !strings.Contains(q.Result, "nonfinite=2") || !strings.Contains(q.Result, "min=2") || !strings.Contains(q.Result, "max=3") || !strings.Contains(q.Result, "decreasing_steps=0") {
		t.Fatalf("special values misrepresented: %+v", q)
	}
}

func TestRunPromQL_MatrixTimestampPrecision(t *testing.T) {
	data := json.RawMessage(`{"resultType":"matrix","result":[{"metric":{},"values":[[100.125,"1"],[100.875,"2"]]}]}`)
	q := VerificationQuery{Kind: kindPromQL, Expr: `queue_depth[1h]`}
	runPromQL(context.Background(), fakeQuerier(func(string) (json.RawMessage, error) { return data, nil }), &q, 100, time.Now(), slog.Default(), "history")
	if !strings.Contains(q.Result, "first=1@1970-01-01T00:01:40.125Z") || !strings.Contains(q.Result, "last=2@1970-01-01T00:01:40.875Z") {
		t.Fatalf("sample timestamps lost precision: %s", q.Result)
	}
}

func TestRunPromQL_ResultShapes(t *testing.T) {
	for _, tc := range []struct {
		name, expr, data, want string
		outcome                Outcome
	}{
		{"scalar", `scalar(up)`, `{"resultType":"scalar","result":[100,"0.125"]}`, "0.125", OutcomeFetched},
		{"empty_matrix", `queue_depth[1h]`, `{"resultType":"matrix","result":[]}`, "(no data)", OutcomeEmpty},
		{"string", `"hello"`, `{"resultType":"string","result":[100,"hello"]}`, "unavailable", OutcomeFailed},
		{"native_histogram", `histogram_metric[1h]`, `{"resultType":"matrix","result":[{"metric":{},"histograms":[[100,{"count":"3","sum":"6","buckets":[]}]]}]}`, "unavailable", OutcomeFailed},
		{"unsupported_vector_sample", `histogram_metric`, `{"resultType":"vector","result":[{"metric":{},"histogram":[100,{"count":"3","sum":"6","buckets":[]}]}]}`, "unavailable", OutcomeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := VerificationQuery{Kind: kindPromQL, Expr: tc.expr}
			runPromQL(context.Background(), fakeQuerier(func(string) (json.RawMessage, error) { return json.RawMessage(tc.data), nil }), &q, 100, time.Now(), slog.Default(), "shape")
			if q.Outcome != tc.outcome || !strings.Contains(q.Result, tc.want) {
				t.Fatalf("result shape misrepresented: %+v", q)
			}
		})
	}
}
