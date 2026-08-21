// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// LogQuerier is the read-only native log-query surface (LogQL for Loki).
type LogQuerier interface {
	QueryRange(ctx context.Context, query string, start, end time.Time, limit int, dir string) (json.RawMessage, error)
}

// logVolumeFact is the bounded shape of a log read: how much matched and
// when, never the matched lines themselves. Log bodies routinely carry
// operator or user data, so evidence keeps the shape and drops the content.
type logVolumeFact struct {
	Query   string     `json:"query"`
	Streams int        `json:"streams"`
	Lines   int        `json:"lines"`
	First   *time.Time `json:"first_at,omitempty"`
	Last    *time.Time `json:"last_at,omitempty"`
}

// logExecutor reduces one native log range query.
type logExecutor struct {
	client LogQuerier
}

func (e logExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	if in.Params.Query == "" {
		return nil, observation.Cost{}, fmt.Errorf("%w: loki_query requires a logql query", ErrPlanParameters)
	}
	cost := observation.Cost{SourceCalls: 1}
	raw, err := e.client.QueryRange(ctx, in.Params.Query, in.Start, in.End, in.Limit, "backward")
	if err != nil {
		return nil, cost, err
	}
	reduced, ok := reduceLogStreams(raw)
	if !ok {
		return nil, cost, fmt.Errorf("connectors: log response was not a recognized result type")
	}
	if reduced.Lines == 0 {
		return nil, cost, nil
	}
	reduced.Query = in.Params.Query
	fact, err := in.fact(observationmodel.CapabilityLokiQuery, "log_volume", in.Params.Query, reduced,
		timeOrNow(reduced.Last), []string{"logql:" + in.Params.Query})
	if err != nil {
		return nil, cost, err
	}
	return []observationmodel.Fact{fact}, cost, nil
}

// logResponse is the Loki "data" payload. Entries are [nanosecondString, line].
type logResponse struct {
	ResultType string `json:"resultType"`
	Result     []struct {
		Values [][]string `json:"values"`
	} `json:"result"`
}

// reduceLogStreams counts matched lines and their span, discarding every line
// body before anything is retained.
func reduceLogStreams(raw json.RawMessage) (logVolumeFact, bool) {
	var parsed logResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return logVolumeFact{}, false
	}
	if parsed.ResultType != "streams" && parsed.ResultType != "matrix" && parsed.ResultType != "vector" {
		return logVolumeFact{}, false
	}
	out := logVolumeFact{Streams: len(parsed.Result)}
	for _, stream := range parsed.Result {
		for _, entry := range stream.Values {
			if len(entry) == 0 {
				continue
			}
			nanos, ok := boundedNumeric(entry[0])
			if !ok {
				continue
			}
			out.Lines++
			at := time.Unix(0, int64(nanos)).UTC()
			if out.First == nil || at.Before(*out.First) {
				first := at
				out.First = &first
			}
			if out.Last == nil || at.After(*out.Last) {
				last := at
				out.Last = &last
			}
		}
	}
	return out, true
}
