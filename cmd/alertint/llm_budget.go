// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
)

// Serve supplies one shared durable budget. Keep existing unlimited builder
// callers compatible, but fail closed if finite configuration lacks a store.
func configuredLLMBudget(cfg *config.Config, supplied []*llm.Budget) *llm.Budget {
	if len(supplied) > 0 && supplied[0] != nil {
		return supplied[0]
	}
	return llm.NewBudget(nil, cfg.LLM.Budget)
}
