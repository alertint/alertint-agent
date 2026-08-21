// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// PrometheusQuerier is the read-only PromQL surface. Both methods are GETs
// against the query API; neither can mutate an operated system.
type PrometheusQuerier interface {
	QueryInstant(ctx context.Context, expr string, at time.Time, limit int) (json.RawMessage, error)
	QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) (json.RawMessage, error)
}

// ZabbixReader is the read-only Zabbix surface (ADR-0032: *.get only).
type ZabbixReader interface {
	MetricHistory(ctx context.Context, host, itemKey string, from, to time.Time, limit int) (zabbix.Series, error)
	ProblemHistory(ctx context.Context, host string, start, end time.Time, severityMin string, limit int) ([]zabbix.ProblemHistoryRow, error)
}

// metricSeriesFact is the normalized shape both metric reducers emit: the
// bounded shape of a series, never its raw samples.
type metricSeriesFact struct {
	Query   string     `json:"query,omitempty"`
	Name    string     `json:"name,omitempty"`
	Units   string     `json:"units,omitempty"`
	Source  string     `json:"source,omitempty"`
	Series  int        `json:"series"`
	Samples int        `json:"samples"`
	First   *time.Time `json:"first_at,omitempty"`
	Last    *time.Time `json:"last_at,omitempty"`
	Min     *float64   `json:"min,omitempty"`
	Max     *float64   `json:"max,omitempty"`
	Latest  *float64   `json:"latest,omitempty"`
}

// prometheusExecutor reduces one PromQL read to a bounded series shape.
type prometheusExecutor struct {
	client PrometheusQuerier
}

func (e prometheusExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	query := in.Params.Query
	if query == "" {
		return nil, observation.Cost{}, fmt.Errorf("%w: prometheus_query requires a promql query", ErrPlanParameters)
	}

	var raw json.RawMessage
	if in.End.After(in.Start) {
		raw, err = e.client.QueryRange(ctx, query, in.Start, in.End, 0)
	} else {
		raw, err = e.client.QueryInstant(ctx, query, in.End, in.Limit)
	}
	cost := observation.Cost{SourceCalls: 1}
	if err != nil {
		return nil, cost, err
	}
	reduced, ok := reducePrometheus(raw)
	if !ok {
		return nil, cost, fmt.Errorf("connectors: prometheus response was not a recognized result type")
	}
	if reduced.Series == 0 {
		return nil, cost, nil // confirmed empty: the source answered, with nothing
	}
	reduced.Query = query
	fact, err := in.fact(observationmodel.CapabilityPrometheusQuery, "metric_series", query, reduced, timeOrNow(reduced.Last), []string{"promql:" + query})
	if err != nil {
		return nil, cost, err
	}
	return []observationmodel.Fact{fact}, cost, nil
}

// promResponse is the Prometheus "data" payload for both vector and matrix
// result types. Values are [unixSeconds, "sample"] pairs.
type promResponse struct {
	ResultType string `json:"resultType"`
	Result     []struct {
		Metric map[string]string   `json:"metric"`
		Value  []json.RawMessage   `json:"value"`
		Values [][]json.RawMessage `json:"values"`
	} `json:"result"`
}

// reducePrometheus folds a vector or matrix response into the bounded shape.
// The raw response is discarded: only the shape survives into evidence.
func reducePrometheus(raw json.RawMessage) (metricSeriesFact, bool) {
	var parsed promResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return metricSeriesFact{}, false
	}
	if parsed.ResultType != "vector" && parsed.ResultType != "matrix" && parsed.ResultType != "scalar" {
		return metricSeriesFact{}, false
	}
	out := metricSeriesFact{Series: len(parsed.Result), Source: parsed.ResultType}
	for _, series := range parsed.Result {
		samples := series.Values
		if len(series.Value) > 0 {
			samples = append(samples, series.Value)
		}
		for _, sample := range samples {
			at, value, ok := decodePromSample(sample)
			if !ok {
				continue
			}
			out.Samples++
			if out.First == nil || at.Before(*out.First) {
				first := at
				out.First = &first
			}
			if out.Last == nil || at.After(*out.Last) {
				last := at
				out.Last = &last
				latest := value
				out.Latest = &latest
			}
			if out.Min == nil || value < *out.Min {
				min := value
				out.Min = &min
			}
			if out.Max == nil || value > *out.Max {
				max := value
				out.Max = &max
			}
		}
	}
	return out, true
}

func decodePromSample(sample []json.RawMessage) (time.Time, float64, bool) {
	if len(sample) != 2 {
		return time.Time{}, 0, false
	}
	var seconds float64
	if err := json.Unmarshal(sample[0], &seconds); err != nil {
		return time.Time{}, 0, false
	}
	var text string
	if err := json.Unmarshal(sample[1], &text); err != nil {
		return time.Time{}, 0, false
	}
	value, ok := boundedNumeric(text)
	if !ok {
		return time.Time{}, 0, false
	}
	return time.Unix(int64(seconds), 0).UTC(), value, true
}

// zabbixMetricExecutor reduces one Zabbix item history read.
type zabbixMetricExecutor struct {
	client ZabbixReader
}

func (e zabbixMetricExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	host := plan.Scope["host"]
	if host == "" || in.Params.ItemKey == "" {
		return nil, observation.Cost{}, fmt.Errorf("%w: zabbix_metric_range requires host scope and an item key", ErrPlanParameters)
	}
	// Two source calls: resolving the item, then reading its history.
	cost := observation.Cost{SourceCalls: 2}
	series, err := e.client.MetricHistory(ctx, host, in.Params.ItemKey, in.Start, in.End, in.Limit)
	if err != nil {
		return nil, cost, err
	}
	if len(series.Points) == 0 {
		return nil, cost, nil
	}
	reduced := metricSeriesFact{Name: series.Name, Units: series.Units, Source: series.Source, Series: 1}
	for _, point := range series.Points {
		reduced.Samples++
		at := point.Clock.UTC()
		if reduced.First == nil || at.Before(*reduced.First) {
			first := at
			reduced.First = &first
		}
		if reduced.Last == nil || at.After(*reduced.Last) {
			last := at
			reduced.Last = &last
		}
		if value, ok := boundedNumeric(point.Value); ok {
			if reduced.Last != nil && at.Equal(*reduced.Last) {
				latest := value
				reduced.Latest = &latest
			}
			if reduced.Min == nil || value < *reduced.Min {
				min := value
				reduced.Min = &min
			}
			if reduced.Max == nil || value > *reduced.Max {
				max := value
				reduced.Max = &max
			}
		}
	}
	subject := host + ":" + in.Params.ItemKey
	fact, err := in.fact(observationmodel.CapabilityZabbixMetricRange, "metric_series", subject, reduced,
		timeOrNow(reduced.Last), []string{"zabbix:item:" + subject})
	if err != nil {
		return nil, cost, err
	}
	return []observationmodel.Fact{fact}, cost, nil
}

func timeOrNow(at *time.Time) time.Time {
	if at != nil && !at.IsZero() {
		return at.UTC()
	}
	return time.Now().UTC()
}

// sortFactsBySubject keeps a multi-fact batch in a deterministic order so a
// replayed observation produces byte-identical evidence.
func sortFactsBySubject(facts []observationmodel.Fact) {
	sort.Slice(facts, func(i, j int) bool { return facts[i].Subject < facts[j].Subject })
}
