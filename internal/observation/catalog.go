// SPDX-License-Identifier: FSL-1.1-ALv2

// Package observation validates and executes typed, read-only, bounded
// evidence plans. Connector responses cross this boundary only after an
// adapter has reduced them to observationmodel.Fact values.
package observation

import (
	"sort"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// Cost records bounded resources consumed by one observation.
type Cost struct {
	SourceCalls int `json:"source_calls"`
	Tokens      int `json:"tokens"`
}

// Scope is the resolved vocabulary permitted for one Situation input. A plan
// value must match one of the exact allowed values for its key.
type Scope map[string][]string

// Capability describes one closed, read-only observation operation.
type Capability struct {
	Name           observationmodel.Capability
	ReadOnly       bool
	ScopeKeys      []string
	RequiredScope  []string
	MaxWindow      time.Duration
	MaxLimit       int
	Freshness      time.Duration
	Timeout        time.Duration
	MaxResultBytes int
	MaxCost        Cost
	Executor       Executor
}

// Catalog is the closed set of observation capabilities.
type Catalog struct {
	capabilities map[string]Capability
}

// NewCatalog constructs a catalog from explicit capabilities. Duplicate or
// empty names are ignored; Validate still rejects plans for them.
func NewCatalog(capabilities ...Capability) *Catalog {
	catalog := &Catalog{capabilities: make(map[string]Capability, len(capabilities))}
	for _, capability := range capabilities {
		if capability.Name == "" {
			continue
		}
		capability.Executor = configuredExecutor(capability.Executor)
		catalog.capabilities[string(capability.Name)] = capability
	}
	return catalog
}

// DefaultCatalog registers every initial read-only capability with explicit
// scope, time, count, freshness, timeout, result-size, and source-call bounds.
func DefaultCatalog(adapters Adapters) *Catalog {
	const resultBytes = 512 << 10
	return NewCatalog(
		Capability{Name: observationmodel.CapabilityStoreRead, ReadOnly: true,
			ScopeKeys:     []string{"situation_id", "incident_id", "host", "service", "environment", "group_key"},
			RequiredScope: []string{"situation_id"}, MaxWindow: 30 * 24 * time.Hour, MaxLimit: 500,
			Freshness: time.Second, Timeout: 3 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 1}, Executor: configuredExecutor(adapters.StoreRead)},
		Capability{Name: observationmodel.CapabilityPrometheusQuery, ReadOnly: true,
			ScopeKeys: []string{"host", "service", "environment"}, MaxWindow: 7 * 24 * time.Hour, MaxLimit: 1000,
			Freshness: 30 * time.Second, Timeout: 10 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 1}, Executor: configuredExecutor(adapters.PrometheusQuery)},
		Capability{Name: observationmodel.CapabilityZabbixMetricRange, ReadOnly: true,
			ScopeKeys: []string{"host"}, RequiredScope: []string{"host"}, MaxWindow: 30 * 24 * time.Hour, MaxLimit: 2000,
			Freshness: 30 * time.Second, Timeout: 10 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 2}, Executor: configuredExecutor(adapters.ZabbixMetricRange)},
		Capability{Name: observationmodel.CapabilityZabbixProblemHistory, ReadOnly: true,
			ScopeKeys: []string{"host"}, RequiredScope: []string{"host"}, MaxWindow: 90 * 24 * time.Hour, MaxLimit: 500,
			Freshness: time.Minute, Timeout: 10 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 3}, Executor: configuredExecutor(adapters.ZabbixProblemHistory)},
		Capability{Name: observationmodel.CapabilityLokiQuery, ReadOnly: true,
			ScopeKeys: []string{"host", "service", "environment"}, MaxWindow: 24 * time.Hour, MaxLimit: 1000,
			Freshness: 10 * time.Second, Timeout: 10 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 1}, Executor: configuredExecutor(adapters.LokiQuery)},
		Capability{Name: observationmodel.CapabilitySentryIssues, ReadOnly: true,
			ScopeKeys: []string{"project", "environment", "service"}, RequiredScope: []string{"project"},
			MaxWindow: 30 * 24 * time.Hour, MaxLimit: 100, Freshness: time.Minute, Timeout: 10 * time.Second,
			MaxResultBytes: resultBytes, MaxCost: Cost{SourceCalls: 1}, Executor: configuredExecutor(adapters.SentryIssues)},
		Capability{Name: observationmodel.CapabilityChangeEvents, ReadOnly: true,
			ScopeKeys: []string{"host", "service", "environment", "project"}, MaxWindow: 30 * 24 * time.Hour, MaxLimit: 500,
			Freshness: time.Second, Timeout: 3 * time.Second, MaxResultBytes: resultBytes,
			MaxCost: Cost{SourceCalls: 1}, Executor: configuredExecutor(adapters.ChangeEvents)},
	)
}

// Capabilities returns the registered names in stable order.
func (c *Catalog) Capabilities() []observationmodel.Capability {
	if c == nil {
		return nil
	}
	out := make([]observationmodel.Capability, 0, len(c.capabilities))
	for _, capability := range c.capabilities {
		out = append(out, capability.Name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (c *Catalog) capability(name observationmodel.Capability) (Capability, bool) {
	if c == nil {
		return Capability{}, false
	}
	value, ok := c.capabilities[string(name)]
	return value, ok
}
