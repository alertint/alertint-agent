// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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

	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = 100
	}
	expiresAt := now.Add(model.MaxWindowHoursMetricsLogs * time.Hour)
	// limit+1: one overflow sentinel row proves "more than limit" without
	// ever treating the hard cap itself as completeness (F20).
	series, err := e.Client.MetricHistoryBounded(ctx, host, params.ItemKey, plan.Start, plan.End, limit+1, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		if errors.Is(err, zabbix.ErrNotFound) {
			return unresolvedRun(plan, now), nil
		}
		if isResponseTooLarge(err) {
			return responseTooLargeRun(plan, now, expiresAt), nil
		}
		return model.Run{}, fmt.Errorf("connectors: zabbix metric history: %w", err)
	}

	// Canonical order (newest clock first, then value) before truncation and
	// hashing (F28): trend.get has no sort parameter at all.
	points := slices.Clone(series.Points)
	slices.SortFunc(points, func(a, b zabbix.SeriesPoint) int {
		if c := b.Clock.Compare(a.Clock); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	points, omitted, truncated := truncateToLimit(points, limit)

	value, kept, err := fitFactValue(len(points), func(n int) ([]byte, error) {
		bounded := series
		bounded.Points = points[:n]
		return json.Marshal(bounded)
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal zabbix series: %w", err)
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "metric_summary", Value: value, Returned: kept, Omitted: omitted + len(points) - kept,
		Truncated: truncated, Capped: kept < len(points), ExpiresAt: expiresAt,
	}), nil
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

	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = 20
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	result, err := e.Client.ProblemHistory(ctx, host, params.TriggerID, plan.Start, plan.End, params.SeverityMin, limit, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		if isResponseTooLarge(err) {
			return responseTooLargeRun(plan, now, expiresAt), nil
		}
		return model.Run{}, fmt.Errorf("connectors: zabbix problem history: %w", err)
	}

	// Canonical order (newest event id first) before hashing (F28). The
	// client already applied its own limit+1 truncation under the source's
	// clock/eventid sort.
	episodes := slices.Clone(result.Episodes)
	slices.SortFunc(episodes, func(a, b zabbix.ProblemEpisode) int { return compareIDs(b.EventID, a.EventID) })
	value, kept, err := fitFactValue(len(episodes), func(n int) ([]byte, error) {
		return json.Marshal(episodes[:n])
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal zabbix episodes: %w", err)
	}
	omitted := len(episodes) - kept
	if result.Truncated {
		omitted++ // the overflow sentinel row: at least one more episode exists
	}
	var extra []string
	if result.UnresolvedRecoveryCount > 0 {
		extra = append(extra, limitationRecoveryUnknown)
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "problem_episode", Value: value, Returned: kept, Omitted: omitted,
		Truncated: result.Truncated || !result.Complete, Capped: kept < len(episodes),
		ExtraLimitations: extra, ExpiresAt: expiresAt,
	}), nil
}

// limitationRecoveryUnknown marks a problem-history run in which at least
// one resolved episode's recovery clock could not be confirmed.
const limitationRecoveryUnknown = "recovery_unknown"

// zabbixHooks is requestHooks under its original Zabbix-specific name,
// kept for the existing hook tests.
func zabbixHooks(ctx context.Context, recorder observation.RequestRecorder, clock func() time.Time) (func() error, func(started bool, err error), *bool) {
	return requestHooks(ctx, recorder, clock)
}
