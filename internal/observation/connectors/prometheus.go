// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// PrometheusClient is the narrow bounded-query boundary
// PrometheusExecutor depends on; *prometheus.Client structurally satisfies
// it via QueryRangeBounded.
type PrometheusClient interface {
	QueryRangeBounded(ctx context.Context, expr string, start, end time.Time, step time.Duration, limit int) (json.RawMessage, error)
}

// PrometheusExecutor implements observation.Executor for prometheus_query:
// a deterministic selector built from the frozen plan's scope (never a
// generator-URL target, never a model-authored query), summarized with
// bounded, deterministic statistics — never a raw matrix persisted verbatim.
type PrometheusExecutor struct {
	Client PrometheusClient
	Clock  func() time.Time
}

func (e *PrometheusExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

func (e *PrometheusExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	expr, err := buildPromQLSelector(plan.Scope)
	if err != nil {
		return unresolvedRun(plan, now), nil
	}

	reservation, err := recorder.BeforeRequest(ctx)
	if err != nil {
		if errors.Is(err, model.ErrBudgetExhausted) {
			return withheldRun(plan, now), nil
		}
		return model.Run{}, fmt.Errorf("connectors: reserve prometheus request: %w", err)
	}

	limit := plan.Limit
	if limit <= 0 {
		limit = 100
	}
	raw, execErr := e.Client.QueryRangeBounded(ctx, expr, plan.Start, plan.End, 0, limit+1)

	started := model.RequestStartedTrue
	code := "ok"
	if execErr != nil {
		code = "transport_failure"
	}
	if outcomeErr := recorder.AfterRequest(ctx, model.RequestOutcome{
		ReservationID: reservation.ID, RequestStarted: started, Code: code, CompletedAt: e.clock(),
	}); outcomeErr != nil {
		return model.Run{}, fmt.Errorf("connectors: record prometheus outcome: %w", outcomeErr)
	}
	if execErr != nil {
		return model.Run{}, fmt.Errorf("connectors: prometheus query: %w", execErr)
	}

	summary, truncated, err := summarizePrometheusMatrix(raw, limit)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: parse prometheus response: %w", err)
	}

	status := model.ResultConfirmedEmpty
	if len(summary.Series) > 0 {
		status = model.ResultConfirmedValue
	}
	if truncated {
		status = model.ResultTruncated
	}

	value, err := json.Marshal(summary)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal metric summary: %w", err)
	}
	expiresAt := now.Add(model.MaxWindowHoursMetricsLogs * time.Hour)
	fact := model.Fact{
		ID: factID(plan.ID, "metric_summary", value), RunID: "run:" + plan.ID,
		Kind: "metric_summary", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: status, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}

	var limitationCodes []string
	if truncated {
		limitationCodes = []string{"truncated"}
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: !truncated, Returned: len(summary.Series), Omitted: 0},
		Facts:           []model.Fact{fact},
		LimitationCodes: limitationCodes,
		ObservedAt:      now, ExpiresAt: expiresAt,
	}, nil
}

func withheldRun(plan model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: model.ResultWithheldByBudget,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: false},
		LimitationCodes: []string{"withheld_by_budget"},
		ObservedAt:      now, ExpiresAt: now.Add(24 * time.Hour),
	}
}

// buildPromQLSelector deterministically builds an exact-match PromQL
// selector from scope's labels — sorted for a stable, reproducible
// expression string, using only configured label keys/values already
// resolved onto the plan; never a generator URL or free-form annotation
// text. An empty label set is unresolvable (spec.md: "An unresolved or
// ambiguous scope produces vocabulary_unresolved, without a broad
// fallback").
func buildPromQLSelector(scope model.Scope) (string, error) {
	if len(scope.Labels) == 0 {
		return "", fmt.Errorf("connectors: prometheus scope has no labels to select on")
	}
	keys := make([]string, 0, len(scope.Labels))
	for k := range scope.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	matchers := make([]string, 0, len(keys))
	for _, k := range keys {
		matchers = append(matchers, fmt.Sprintf("%s=%q", k, scope.Labels[k]))
	}
	expr := "{"
	for i, m := range matchers {
		if i > 0 {
			expr += ","
		}
		expr += m
	}
	expr += "}"
	return expr, nil
}

// metricSummary is the bounded, deterministic statistics shape persisted
// for prometheus_query — never a raw matrix (spec.md: "Persist series
// summaries, sample coverage and finite-value checks, not raw matrices").
type metricSummary struct {
	Series []seriesSummary `json:"series"`
}

type seriesSummary struct {
	Labels      map[string]string `json:"labels"`
	SampleCount int               `json:"sample_count"`
	FiniteCount int               `json:"finite_count"`
	Min         float64           `json:"min,omitempty"`
	Max         float64           `json:"max,omitempty"`
	Last        float64           `json:"last,omitempty"`
	AllFinite   bool              `json:"all_finite"`
}

func summarizePrometheusMatrix(raw json.RawMessage, limit int) (metricSummary, bool, error) {
	var payload struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return metricSummary{}, false, fmt.Errorf("decode matrix: %w", err)
	}

	truncated := limit > 0 && len(payload.Result) > limit
	series := payload.Result
	if truncated {
		series = series[:limit]
	}

	out := metricSummary{Series: make([]seriesSummary, 0, len(series))}
	for _, s := range series {
		summary := seriesSummary{Labels: s.Metric, AllFinite: true}
		var lo, hi, last float64
		first := true
		for _, sample := range s.Values {
			summary.SampleCount++
			valStr, ok := sample[1].(string)
			if !ok {
				summary.AllFinite = false
				continue
			}
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				summary.AllFinite = false
				continue
			}
			summary.FiniteCount++
			if first {
				lo, hi = v, v
				first = false
			} else {
				if v < lo {
					lo = v
				}
				if v > hi {
					hi = v
				}
			}
			last = v
		}
		summary.Min, summary.Max, summary.Last = lo, hi, last
		out.Series = append(out.Series, summary)
	}
	return out, truncated, nil
}
