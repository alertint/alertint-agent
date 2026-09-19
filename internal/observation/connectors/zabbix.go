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

// ZabbixSourceDefinitionClient is the bounded boundary used to observe the
// current effective rule configuration alongside problem history.
type ZabbixSourceDefinitionClient interface {
	SourceRuleVersionBounded(ctx context.Context, sourceInstanceID, host, triggerID string,
		before func() error, after func(started bool, err error)) (zabbix.SourceRuleDefinition, error)
}

// zabbixMetricParameters is zabbix_metric_range's own typed
// Plan.Parameters shape: the exact adapter-resolved technical host and
// item key from the source trigger's items — never a model-invented
// metric key. BOTH are required: a plan without a proven host is
// unresolvable, never a Scope.SubjectID guess that could read another
// host's item (F17).
type zabbixMetricParameters struct {
	Host    string `json:"host"`
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
	if host == "" || params.ItemKey == "" {
		return unresolvedRun(plan, now), nil
	}

	// Two reservations: the exact item.get, then history.get/trend.get. A
	// second reservation denied by budget surfaces as withheld_by_budget
	// below, with the first request still honestly accounted for.
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
// Plan.Parameters shape: exact member host/trigger identifiers. Host and
// TriggerID are both required — there is no Scope.SubjectID fallback (F17).
type zabbixProblemParameters struct {
	Host             string `json:"host"`
	TriggerID        string `json:"trigger_id"`
	SeverityMin      string `json:"severity_min,omitempty"`
	SourceInstanceID string `json:"source_instance_id,omitempty"`
	FreshForSeconds  int    `json:"fresh_for_seconds,omitempty"`
}

// ZabbixProblemExecutor implements observation.Executor for
// zabbix_problem_history.
type ZabbixProblemExecutor struct {
	Client           ZabbixProblemClient
	SourceDefinition ZabbixSourceDefinitionClient
	Clock            func() time.Time
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
	if host == "" || params.TriggerID == "" {
		return unresolvedRun(plan, now), nil
	}

	// Up to six reservations: four (or five with direct dependencies) for a
	// consistent source-definition snapshot, then the primary event.get and
	// optional recovery-clock lookup. Every request shares this plan's one
	// durable budget.
	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	sourceFact, sourceLimitation := e.sourceDefinitionFact(ctx, plan, params, before, after, budgetExhausted)
	limit := plan.Limit
	if limit <= 0 {
		limit = 20
	}
	expiresAt := now.Add(model.MaxWindowDaysHistory * 24 * time.Hour)
	result, err := e.Client.ProblemHistory(ctx, host, params.TriggerID, plan.Start, plan.End, params.SeverityMin, limit, before, after)
	if err != nil {
		if *budgetExhausted {
			return appendSourceDefinition(withheldRun(plan, now), sourceFact, sourceLimitation), nil
		}
		if isResponseTooLarge(err) {
			return appendSourceDefinition(responseTooLargeRun(plan, now, expiresAt), sourceFact, sourceLimitation), nil
		}
		failed := appendSourceDefinition(zabbixProblemHistoryFailedRun(plan, now), sourceFact, sourceLimitation)
		return failed, &observation.FailedRunWithEvidenceError{Err: fmt.Errorf("connectors: zabbix problem history: %w", err)}
	}

	if result.ForeignRowsDropped > 0 && len(result.Episodes) == 0 {
		return appendSourceDefinition(unresolvedRun(plan, now), sourceFact, sourceLimitation), nil
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
	omittedSourceRows := result.ForeignRowsDropped
	if result.Truncated {
		// The overflow sentinel can itself be an unlinked row. Count it
		// once: these counts are a lower bound on omitted source rows.
		omittedSourceRows = max(omittedSourceRows, 1)
	}
	var extra []string
	if result.ForeignRowsDropped > 0 {
		extra = append(extra, "source_scope_unverified")
	}
	if result.UnresolvedRecoveryCount > 0 {
		extra = append(extra, limitationRecoveryUnknown)
	}
	return appendSourceDefinition(boundedRun(plan, now, boundedResult{
		Kind: "problem_episode", Value: value, Returned: kept, Omitted: len(episodes) - kept + omittedSourceRows,
		Truncated: result.Truncated || !result.Complete || result.ForeignRowsDropped > 0, Capped: kept < len(episodes),
		ExtraLimitations: extra, ExpiresAt: expiresAt,
	}), sourceFact, sourceLimitation), nil
}

func zabbixProblemHistoryFailedRun(plan model.Plan, now time.Time) model.Run {
	return model.Run{
		ID: "run:" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID, Status: model.ResultFailed,
		Coverage:        model.Coverage{Start: plan.Start, End: plan.End, Complete: false},
		LimitationCodes: []string{"execution_failed"},
		ObservedAt:      now, ExpiresAt: now.Add(model.MaxWindowHoursMetricsLogs * time.Hour),
	}
}

func (e *ZabbixProblemExecutor) sourceDefinitionFact(ctx context.Context, plan model.Plan, params zabbixProblemParameters,
	before func() error, after func(bool, error), budgetExhausted *bool) (*model.Fact, string) {
	if e.SourceDefinition == nil {
		return nil, ""
	}
	freshFor := time.Duration(params.FreshForSeconds) * time.Second
	if freshFor <= 0 {
		freshFor = 5 * time.Minute
	}
	observation := model.SourceDefinitionObservation{
		Source: "zabbix", InstanceID: params.SourceInstanceID, RuleID: params.TriggerID,
		Host: params.Host, HistoricalProven: false,
	}
	if params.SourceInstanceID == "" {
		observation.UnavailableReason = "delivery_instance_unknown"
	} else {
		definition, err := e.SourceDefinition.SourceRuleVersionBounded(ctx, params.SourceInstanceID, params.Host, params.TriggerID, before, after)
		if err == nil {
			observation.Available = true
			observation.EndpointID = definition.EndpointID
			observation.VersionAlgorithm = definition.Algorithm
			observation.Version = definition.Version
			observation.ComponentDigests = definition.ComponentDigests
			observation.TriggerIDs = definition.TriggerIDs
			observation.ItemIDs = definition.ItemIDs
		} else if reason, ok := zabbix.DefinitionUnavailableReason(err); ok {
			observation.UnavailableReason = reason
		} else {
			switch {
			case *budgetExhausted:
				observation.UnavailableReason = "withheld_by_budget"
			case isResponseTooLarge(err):
				observation.UnavailableReason = "response_too_large"
			case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
				observation.UnavailableReason = "timeout"
			default:
				observation.UnavailableReason = "api_unavailable"
			}
		}
	}
	value, err := json.Marshal(observation)
	if err != nil {
		return nil, "source_definition_encoding_failed"
	}
	status := model.ResultUnavailable
	if observation.Available {
		status = model.ResultConfirmedValue
	}
	observedAt := e.clock()
	fact := &model.Fact{
		ID: factID(plan.ID, "source_definition", value), RunID: "run:" + plan.ID,
		Kind: "source_definition", Subject: plan.Scope.SubjectID, Digest: digestOf(value),
		SchemaVersion: model.FactSchemaVersion, Value: value, ResultStatus: status,
		Freshness: model.FreshnessFresh, ObservedAt: observedAt, ExpiresAt: observedAt.Add(freshFor), Material: true,
	}
	if observation.Available {
		return fact, ""
	}
	return fact, "source_definition_" + observation.UnavailableReason
}

func appendSourceDefinition(run model.Run, fact *model.Fact, limitation string) model.Run {
	if fact != nil {
		run.Facts = append(run.Facts, *fact)
		if fact.ExpiresAt.After(run.ExpiresAt) {
			run.ExpiresAt = fact.ExpiresAt
		}
	}
	if limitation != "" {
		run.LimitationCodes = append(run.LimitationCodes, limitation)
	}
	return run
}

// limitationRecoveryUnknown marks a problem-history run in which at least
// one resolved episode's recovery clock could not be confirmed.
const limitationRecoveryUnknown = "recovery_unknown"

// zabbixHooks is requestHooks under its original Zabbix-specific name,
// kept for the existing hook tests.
func zabbixHooks(ctx context.Context, recorder observation.RequestRecorder, clock func() time.Time) (func() error, func(started bool, err error), *bool) {
	return requestHooks(ctx, recorder, clock)
}
