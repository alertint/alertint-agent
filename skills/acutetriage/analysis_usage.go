// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/alertint/alertint-agent/internal/llm"
)

// analysisUsage records only the model work of one analysis invocation. It is
// persisted with that invocation's evidence; legacy findings have no such key.
// Built-in providers report each request below their retry loops. Custom clients
// without request observations fall back to one completion outcome.
// Zero-valued provider token fields do not establish reported zero usage.
type analysisUsage struct {
	Calls             int  `json:"calls"`
	CallsKnown        bool `json:"calls_known"`
	InputTokens       int  `json:"input_tokens"`
	InputTokensKnown  bool `json:"input_tokens_known"`
	OutputTokens      int  `json:"output_tokens"`
	OutputTokensKnown bool `json:"output_tokens_known"`
}

type analysisUsageKey struct{}
type analysisUsageCollector struct {
	mu    sync.Mutex
	usage analysisUsage
}

func withAnalysisUsage(ctx context.Context) (context.Context, *analysisUsageCollector) {
	c := &analysisUsageCollector{usage: analysisUsage{CallsKnown: true, InputTokensKnown: true, OutputTokensKnown: true}}
	return context.WithValue(ctx, analysisUsageKey{}, c), c
}

func (c *analysisUsageCollector) snapshot() analysisUsage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usage
}

// Context scoping covers the optional classifier and repair branches without
// mutating a shared Skill or accumulating work from concurrent incidents.
func completeWithAnalysisUsage(ctx context.Context, client LLMClient, system string, prompt llm.Prompt, keys []string) (llm.Completion, error) {
	c, _ := ctx.Value(analysisUsageKey{}).(*analysisUsageCollector)
	if c == nil {
		return client.Complete(ctx, system, prompt, keys)
	}
	var observed atomic.Bool
	ctx = llm.WithRequestObserver(ctx, func(comp llm.Completion, err error) {
		observed.Store(true)
		c.record(comp, err)
	})
	comp, err := client.Complete(ctx, system, prompt, keys)
	if !observed.Load() {
		c.record(comp, err)
	}
	return comp, err
}

func (c *analysisUsageCollector) record(comp llm.Completion, err error) {
	started := llm.ClassifyRequestStart(err)
	if started == llm.RequestStartStatusFalse {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if started == llm.RequestStartStatusTrue {
		c.usage.Calls++
	} else {
		c.usage.CallsKnown = false
	}
	input := comp.InputTokens + comp.CacheCreationInputTokens + comp.CacheReadInputTokens
	if input > 0 {
		c.usage.InputTokens += input
	} else {
		c.usage.InputTokensKnown = false
	}
	if comp.OutputTokens > 0 {
		c.usage.OutputTokens += comp.OutputTokens
	} else {
		c.usage.OutputTokensKnown = false
	}
}
