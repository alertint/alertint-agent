// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// ZabbixMetricClient is the narrow bounded boundary ZabbixMetricExecutor
// depends on; *zabbix.Client structurally satisfies it via
// MetricHistoryBounded.
type ZabbixMetricClient interface {
	MetricHistoryBounded(ctx context.Context, host, itemKey string, from, to time.Time, limit int,
		before func() error, after func(started bool, err error)) (zabbix.Series, error)
}

// ZabbixProblemClient is the narrow bounded boundary ZabbixProblemExecutor
// depends on; *zabbix.Client structurally satisfies it via ProblemHistory.
type ZabbixProblemClient interface {
	ProblemHistory(ctx context.Context, host, triggerID string, start, end time.Time, severityMin string, limit int,
		before func() error, after func(started bool, err error)) (zabbix.ProblemHistoryResult, error)
}

// zabbixMetricParameters is zabbix_metric_range's own typed
// Plan.Parameters shape: the exact adapter-resolved technical host and
// item key from the source trigger's items — never a model-invented
// metric key. Host falls back to Scope.SubjectID when omitted (still
// code-derived, never model-authored); ItemKey has no fallback.
type zabbixMetricParameters struct {
	Host    string `json:"host,omitempty"`
	ItemKey string `json:"item_key"`
}

// ZabbixMetricExecutor implements observation.Executor for
// zabbix_metric_range.
type ZabbixMetricExecutor struct {
	Client ZabbixMetricClient
	Clock  func() time.Time
}

func (e *ZabbixMetricExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

func (e *ZabbixMetricExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	var params zabbixMetricParameters
	if len(plan.Parameters) > 0 {
		if err := json.Unmarshal(plan.Parameters, &params); err != nil {
			return unresolvedRun(plan, now), nil
		}
	}
	host := params.Host
	if host == "" {
		host = plan.Scope.SubjectID
	}
	if host == "" || params.ItemKey == "" {
		return unresolvedRun(plan, now), nil
	}

	before, after, budgetExhausted := zabbixHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = 100
	}
	series, err := e.Client.MetricHistoryBounded(ctx, host, params.ItemKey, plan.Start, plan.End, limit, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		if errors.Is(err, zabbix.ErrNotFound) {
			return unresolvedRun(plan, now), nil
		}
		return model.Run{}, fmt.Errorf("connectors: zabbix metric history: %w", err)
	}

	status := model.ResultConfirmedEmpty
	if len(series.Points) > 0 {
		status = model.ResultConfirmedValue
	}
	value, err := json.Marshal(series)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal zabbix series: %w", err)
	}
	expiresAt := now.Add(model.MaxWindowHoursMetricsLogs * time.Hour)
	fact := model.Fact{
		ID: factID(plan.ID, "metric_summary", value), RunID: "run:" + plan.ID,
		Kind: "metric_summary", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: status, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage:   model.Coverage{Start: plan.Start, End: plan.End, Complete: true, Returned: len(series.Points)},
		Facts:      []model.Fact{fact},
		ObservedAt: now, ExpiresAt: expiresAt,
	}, nil
}

// zabbixProblemParameters is zabbix_problem_history's own typed
// Plan.Parameters shape: exact member host/trigger identifiers.
type zabbixProblemParameters struct {
	Host        string `json:"host,omitempty"`
	TriggerID   string `json:"trigger_id"`
	SeverityMin string `json:"severity_min,omitempty"`
}

// ZabbixProblemExecutor implements observation.Executor for
// zabbix_problem_history.
type ZabbixProblemExecutor struct {
	Client ZabbixProblemClient
	Clock  func() time.Time
}

func (e *ZabbixProblemExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

func (e *ZabbixProblemExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	var params zabbixProblemParameters
	if len(plan.Parameters) > 0 {
		if err := json.Unmarshal(plan.Parameters, &params); err != nil {
			return unresolvedRun(plan, now), nil
		}
	}
	host := params.Host
	if host == "" {
		host = plan.Scope.SubjectID
	}
	if host == "" || params.TriggerID == "" {
		return unresolvedRun(plan, now), nil
	}

	before, after, budgetExhausted := zabbixHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = 20
	}
	result, err := e.Client.ProblemHistory(ctx, host, params.TriggerID, plan.Start, plan.End, params.SeverityMin, limit, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		return model.Run{}, fmt.Errorf("connectors: zabbix problem history: %w", err)
	}

	status := model.ResultConfirmedEmpty
	if len(result.Episodes) > 0 {
		status = model.ResultConfirmedValue
	}
	if result.Truncated {
		status = model.ResultTruncated
	}

	value, err := json.Marshal(result.Episodes)
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal zabbix episodes: %w", err)
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	fact := model.Fact{
		ID: factID(plan.ID, "problem_episode", value), RunID: "run:" + plan.ID,
		Kind: "problem_episode", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value,
		ResultStatus: status, Freshness: model.FreshnessFresh,
		ObservedAt: now, ExpiresAt: expiresAt, Material: true,
	}

	var limitationCodes []string
	if result.Truncated {
		limitationCodes = append(limitationCodes, "truncated")
	}
	if result.UnresolvedRecoveryCount > 0 {
		limitationCodes = append(limitationCodes, "recovery_unknown")
	}
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: status,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: result.Complete, Returned: len(result.Episodes)},
		Facts:           []model.Fact{fact},
		LimitationCodes: limitationCodes,
		ObservedAt:      now, ExpiresAt: expiresAt,
	}, nil
}

// zabbixHooks builds a before/after pair bridging observation.RequestRecorder
// into the zabbix client's own before()/after(started, err) instrumentation
// shape, shared by both Zabbix executors. The returned bool pointer is set
// true if any BeforeRequest call fails with model.ErrBudgetExhausted, so
// the caller can distinguish "withheld by budget" from a real transport
// failure after the client call returns.
func zabbixHooks(ctx context.Context, recorder observation.RequestRecorder, clock func() time.Time) (func() error, func(started bool, err error), *bool) {
	var lastReservationID string
	budgetExhausted := new(bool)
	before := func() error {
		r, err := recorder.BeforeRequest(ctx)
		if err != nil {
			if errors.Is(err, model.ErrBudgetExhausted) {
				*budgetExhausted = true
			}
			return err
		}
		lastReservationID = r.ID
		return nil
	}
	after := func(started bool, callErr error) {
		code := "ok"
		s := model.RequestStartedTrue
		if callErr != nil {
			code = "transport_failure"
		}
		if !started {
			s = model.RequestStartedFalse
		}
		_ = recorder.AfterRequest(ctx, model.RequestOutcome{
			ReservationID: lastReservationID, RequestStarted: s, Code: code, CompletedAt: clock(),
		})
	}
	return before, after, budgetExhausted
}
