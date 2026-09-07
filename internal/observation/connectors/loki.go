// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// maxLokiSampleLines bounds how many normalized log samples one fact keeps
// — distilled counts, not a full dump (spec.md capability table:
// "distilled counts and bounded normalized samples").
const maxLokiSampleLines = 20

// maxLokiSampleLineChars bounds each retained sample line's length.
const maxLokiSampleLineChars = 512

// LokiClient is the narrow bounded-query boundary LokiExecutor depends on;
// *loki.Client structurally satisfies it via FetchRecentBounded.
type LokiClient interface {
	FetchRecentBounded(ctx context.Context, sel logs.Selector, start, end time.Time, limit int,
		before func() error, after func(started bool, err error)) (logs.Fetched, error)
}

// LokiExecutor implements observation.Executor for loki_query: the
// existing label-map/selector translation and filtered+fallback behavior,
// with each physical request individually reserved/recorded — never
// hidden inside one apparent call (spec.md capability table).
type LokiExecutor struct {
	Client LokiClient
	Clock  func() time.Time
}

func (e *LokiExecutor) clock() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

func (e *LokiExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	now := e.clock()
	sel := selectorFromScope(plan.Scope)
	if len(sel.Labels) == 0 {
		return unresolvedRun(plan, now), nil
	}

	before, after, budgetExhausted := requestHooks(ctx, recorder, e.clock)
	limit := plan.Limit
	if limit <= 0 {
		limit = 100
	}
	expiresAt := now.Add(model.MaxWindowHoursMetricsLogs * time.Hour)
	fetched, err := e.Client.FetchRecentBounded(ctx, sel, plan.Start, plan.End, limit, before, after)
	if err != nil {
		if *budgetExhausted {
			return withheldRun(plan, now), nil
		}
		if isResponseTooLarge(err) {
			return responseTooLargeRun(plan, now, expiresAt), nil
		}
		return model.Run{}, fmt.Errorf("connectors: loki fetch: %w", err)
	}
	if fetched.Query == "" {
		// No label survived translation — an untranslated selector is
		// unconfirmed/unresolved, never a confirmed-empty result.
		return unresolvedRun(plan, now), nil
	}

	samples := make([]lokiSample, 0, min(len(fetched.Lines), maxLokiSampleLines))
	for i := 0; i < len(fetched.Lines) && i < maxLokiSampleLines; i++ {
		line := fetched.Lines[i]
		text := line.Line
		if len(text) > maxLokiSampleLineChars {
			text = text[:maxLokiSampleLineChars]
		}
		samples = append(samples, lokiSample{Timestamp: line.Timestamp, Line: text})
	}

	value, kept, err := fitFactValue(len(samples), func(n int) ([]byte, error) {
		return json.Marshal(lokiSummary{Query: fetched.Query, LineCount: len(fetched.Lines), Samples: samples[:n]})
	})
	if err != nil {
		return model.Run{}, fmt.Errorf("connectors: marshal loki summary: %w", err)
	}
	return boundedRun(plan, now, boundedResult{
		Kind: "log_summary", Value: value, Returned: len(fetched.Lines), Omitted: len(samples) - kept,
		Capped: kept < len(samples), ExpiresAt: expiresAt,
	}), nil
}

func selectorFromScope(scope model.Scope) logs.Selector {
	labels := make(map[string][]string, len(scope.Labels))
	for k, v := range scope.Labels {
		if v == "" {
			continue
		}
		labels[k] = []string{v}
	}
	return logs.Selector{Labels: labels}
}

type lokiSample struct {
	Timestamp time.Time `json:"timestamp"`
	Line      string    `json:"line"`
}

type lokiSummary struct {
	Query     string       `json:"query"`
	LineCount int          `json:"line_count"`
	Samples   []lokiSample `json:"samples,omitempty"`
}
