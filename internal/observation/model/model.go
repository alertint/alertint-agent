// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines read-only, bounded observation contracts. All
// timestamps and windows are canonical UTC values.
package model

import (
	"encoding/json"
	"time"
)

// Capability names a read-only bounded evidence source.
type Capability string

const (
	CapabilityStoreRead            Capability = "store_read"
	CapabilityPrometheusQuery      Capability = "prometheus_query"
	CapabilityZabbixMetricRange    Capability = "zabbix_metric_range"
	CapabilityZabbixProblemHistory Capability = "zabbix_problem_history"
	CapabilityLokiQuery            Capability = "loki_query"
	CapabilitySentryIssues         Capability = "sentry_issues"
	CapabilityChangeEvents         Capability = "change_events"
)

// Plan declares one fully resolved, bounded, read-only observation.
type Plan struct {
	Capability   Capability        `json:"capability"`
	Scope        map[string]string `json:"scope"`
	Parameters   json.RawMessage   `json:"parameters,omitempty"`
	Start        time.Time         `json:"start"`
	End          time.Time         `json:"end"`
	Limit        int               `json:"limit"`
	Why          string            `json:"why"`
	ReconsiderOn []string          `json:"reconsider_on,omitempty"`
	StopOn       []string          `json:"stop_on,omitempty"`
	Budget       int               `json:"budget,omitempty"`
}

type ResultStatus string

const (
	ResultStatusConfirmedValue       ResultStatus = "confirmed_value"
	ResultStatusConfirmedEmpty       ResultStatus = "confirmed_empty"
	ResultStatusUnconfirmedEmpty     ResultStatus = "unconfirmed_empty"
	ResultStatusUnavailable          ResultStatus = "unavailable"
	ResultStatusFailed               ResultStatus = "failed"
	ResultStatusStale                ResultStatus = "stale"
	ResultStatusTruncated            ResultStatus = "truncated"
	ResultStatusWithheldByBudget     ResultStatus = "withheld_by_budget"
	ResultStatusVocabularyUnresolved ResultStatus = "vocabulary_unresolved"
)

type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

// Fact is normalized immutable evidence; raw connector responses are not
// retained in this shared contract.
type Fact struct {
	ID               string          `json:"id"`
	SituationID      string          `json:"situation_id"`
	InputVersion     int             `json:"input_version"`
	Kind             string          `json:"kind"`
	Subject          string          `json:"subject"`
	Value            json.RawMessage `json:"value"`
	SourceCapability Capability      `json:"source_capability"`
	ObservedAt       time.Time       `json:"observed_at"`
	Freshness        Freshness       `json:"freshness"`
	ResultStatus     ResultStatus    `json:"result_status"`
	Digest           string          `json:"digest"`
	EvidenceRefs     []string        `json:"evidence_refs"`
	Material         bool            `json:"material"`
}
