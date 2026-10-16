// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

type alertRuleMetricClient interface {
	AlertRuleMetrics(ctx context.Context, alertName string, scope map[string]string) ([]string, string, error)
}

// Background reads are a small diagnostic sample, not another full primary
// query. A 32-series sample leaves room for primary evidence in a typical
// 16 KiB summary. Large labels/windows remain subject to the independent byte
// caps; this series budget cannot guarantee that a response fits in memory.
const prometheusBackgroundSeries = 32

// metricReadSession accounts the bounded rule/primary/diagnostic reads of one
// frozen plan. A settlement failure is never mistaken for source unavailability.
type metricReadSession struct {
	executor              *PrometheusExecutor
	plan                  model.Plan
	recorder              observation.RequestRecorder
	requests, maxRequests int
	settlementErr         error
}

func (s *metricReadSession) reserve(ctx context.Context) (model.RequestReservation, error) {
	if s.requests >= s.maxRequests {
		return model.RequestReservation{}, model.ErrBudgetExhausted
	}
	r, err := s.recorder.BeforeRequest(ctx)
	if err == nil {
		s.requests++
	}
	return r, err
}

func (s *metricReadSession) settle(ctx context.Context, r model.RequestReservation, callErr error) {
	s.settlementErr = s.recorder.AfterRequest(ctx, model.RequestOutcome{ReservationID: r.ID, RequestStarted: model.RequestStartedTrue, Code: outcomeCode(callErr), CompletedAt: s.executor.clock()})
}

func (s *metricReadSession) ruleMetricNames(ctx context.Context, alertName string) ([]string, string, error) {
	if alertName == "" {
		return nil, "", nil
	}
	client, ok := s.executor.Client.(alertRuleMetricClient)
	if !ok {
		return nil, "rule_metrics_api_unavailable", nil
	}
	if s.maxRequests < 2 {
		return nil, "rule_metrics_withheld_by_budget", nil
	}
	reservation, err := s.reserve(ctx)
	if err != nil {
		return nil, "", err
	}
	names, reason, err := client.AlertRuleMetrics(ctx, alertName, s.plan.Scope.Labels)
	s.settle(ctx, reservation, err)
	if s.settlementErr != nil {
		return nil, "", s.settlementErr
	}
	if isResponseTooLarge(err) {
		return nil, "rule_metrics_response_too_large", nil
	}
	if err != nil {
		return nil, "rule_metrics_api_unavailable", nil
	}
	if len(names) > 0 {
		if reason != "" {
			return names, "rule_metrics_" + reason, nil
		}
		return names, "", nil
	}
	if reason == "" {
		reason = "unsupported_expression"
	}
	return nil, "rule_metrics_" + reason, nil
}

func (s *metricReadSession) query(ctx context.Context, expr string, limit int) (metricSummary, bool, error) {
	reservation, err := s.reserve(ctx)
	if err != nil {
		return metricSummary{}, false, err
	}
	raw, err := s.executor.Client.QueryRangeBounded(ctx, expr, s.plan.Start, s.plan.End, 0, limit+1)
	s.settle(ctx, reservation, err)
	if s.settlementErr != nil {
		return metricSummary{}, false, s.settlementErr
	}
	if err != nil {
		return metricSummary{}, false, err
	}
	return summarizePrometheusMatrix(raw, limit)
}

type metricCollection struct {
	summary               metricSummary
	truncated, incomplete bool
	omitted               int
	extra                 []string
}

func (s *metricReadSession) appendDiagnostics(ctx context.Context, c *metricCollection, scope string, names []string, limit int) error {
	if len(c.summary.Series) == 0 {
		c.extra = append(c.extra, "rule_metrics_empty")
	}
	primaryBytes, err := json.Marshal(c.summary)
	if err != nil {
		return err
	}
	remaining := limit - len(c.summary.Series)
	if remaining <= 0 || len(primaryBytes) >= model.MaxFactBytes {
		c.incomplete = true
		code := "diagnostics_withheld_by_summary_limit"
		if remaining <= 0 {
			code = "diagnostics_withheld_by_series_limit"
		}
		c.extra = append(c.extra, code)
		return nil
	}
	diagnostics, more, err := s.query(ctx, metricNameSelector(scope, names, true), min(remaining, prometheusBackgroundSeries))
	if s.settlementErr != nil {
		return s.settlementErr
	}
	if err != nil {
		c.incomplete = true
		c.extra = append(c.extra, diagnosticLimitation(err))
		return nil
	}
	c.summary.Series = append(c.summary.Series, diagnostics.Series...)
	if more {
		c.truncated = true
		c.omitted++
	}
	return nil
}

func diagnosticLimitation(err error) string {
	switch {
	case errors.Is(err, model.ErrBudgetExhausted):
		return "diagnostics_withheld_by_budget"
	case isResponseTooLarge(err):
		return limitationResponseTooLarge
	default:
		return "diagnostics_failed"
	}
}

// executeMetrics keeps primary evidence before diagnostics, including
// when the later read fails. Every query retains the entire frozen scope; only
// the metric-name matcher differs. No rule expression is executed directly.
func (e *PrometheusExecutor) executeMetrics(ctx context.Context, plan model.Plan, rec observation.RequestRecorder, scope, alertName string, now time.Time) (model.Run, error) {
	limit := plan.Limit
	if limit <= 0 {
		limit = 100
	}
	s := metricReadSession{executor: e, plan: plan, recorder: rec, maxRequests: max(1, plan.MaxRequests)}
	names, code, err := s.ruleMetricNames(ctx, alertName)
	if err != nil {
		if errors.Is(err, model.ErrBudgetExhausted) {
			return withheldRun(plan, now), nil
		}
		return model.Run{}, err
	}
	c := metricCollection{}
	if code != "" {
		c.extra = append(c.extra, code)
	}
	expr := scope
	if len(names) > 0 {
		expr = metricNameSelector(scope, names, false)
	}
	readLimit := limit
	if len(names) == 0 && plan.Scope.Source == "alertmanager" {
		readLimit = min(limit, prometheusBackgroundSeries)
	}
	c.summary, c.truncated, err = s.query(ctx, expr, readLimit)
	if s.settlementErr != nil {
		return model.Run{}, s.settlementErr
	}
	if err != nil {
		if errors.Is(err, model.ErrBudgetExhausted) {
			return withheldRun(plan, now), nil
		}
		if isResponseTooLarge(err) {
			run := responseTooLargeRun(plan, now, now.Add(model.MaxWindowHoursMetricsLogs*time.Hour))
			run.LimitationCodes = append(run.LimitationCodes, c.extra...)
			return run, nil
		}
		return model.Run{}, fmt.Errorf("connectors: primary prometheus query: %w", err)
	}
	if c.truncated {
		c.omitted++
	}
	if len(names) > 0 {
		if err := s.appendDiagnostics(ctx, &c, scope, names, limit); err != nil {
			return model.Run{}, err
		}
	}
	value, kept, err := fitFactValue(len(c.summary.Series), func(n int) ([]byte, error) { return json.Marshal(metricSummary{Series: c.summary.Series[:n]}) })
	if err != nil {
		return model.Run{}, err
	}
	c.omitted += len(c.summary.Series) - kept
	run := boundedRun(plan, now, boundedResult{Kind: "metric_summary", Value: value, Returned: kept, Omitted: c.omitted, Truncated: c.truncated, Capped: kept < len(c.summary.Series), ExtraLimitations: c.extra, ExpiresAt: now.Add(model.MaxWindowHoursMetricsLogs * time.Hour)})
	if c.incomplete {
		run.Status = model.ResultTruncated
		run.Coverage.Complete = false
		for i := range run.Facts {
			run.Facts[i].ResultStatus = model.ResultTruncated
		}
	}
	return run, nil
}

func metricNameSelector(scope string, names []string, exclude bool) string {
	escaped := make([]string, 0, len(names))
	for _, name := range names {
		escaped = append(escaped, regexp.QuoteMeta(name))
	}
	op := "=~"
	if exclude {
		op = "!~"
	}
	return fmt.Sprintf("{__name__%s%q,%s", op, strings.Join(escaped, "|"), strings.TrimPrefix(scope, "{"))
}
