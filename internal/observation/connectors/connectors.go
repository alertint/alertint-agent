// SPDX-License-Identifier: FSL-1.1-ALv2

// Package connectors implements the read-only reducers behind the bounded
// observation capabilities. Each executor issues exactly one kind of read
// against a connector AlertINT already talks to, and returns normalized
// facts — never a raw connector response, and never a write of any kind
// toward an operated system.
//
// It lives outside internal/observation so the runner stays free of every
// connector import, and outside cmd/alertint so the reducers are testable
// without standing up serve.
package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// PlanParameters is the shared parameter envelope every AlertINT observation
// plan carries, decoded from the closed per-capability vocabulary the runner
// validates. InputVersion is required by every reducer: a fact belongs to the
// exact Situation input version it was gathered for, and evidence from another
// version must never justify a decision about this one.
type PlanParameters struct {
	// SituationID names the Situation this observation is evidence for.
	// `situation_id` is a scope key only for store_read, so for every other
	// capability the parameter envelope is the sole carrier of it.
	SituationID  string `json:"situation_id,omitempty"`
	InputVersion int    `json:"input_version"`
	// Query is the connector-native query for the query-shaped capabilities
	// (PromQL, LogQL) and the optional Sentry issue narrowing.
	Query string `json:"query,omitempty"`
	// ItemKey names the Zabbix item a metric range reads.
	ItemKey string `json:"item_key,omitempty"`
	// SeverityMin is the numeric Zabbix severity floor ("0".."5").
	SeverityMin string `json:"severity_min,omitempty"`
	// Resource names which local projection a store_read plan reduces.
	Resource string `json:"resource,omitempty"`
}

// ErrPlanParameters means a plan reached an executor without the parameters
// that capability requires. It is an input fault, reported as a failed run
// rather than silently producing no evidence.
var ErrPlanParameters = errors.New("connectors: observation plan parameters are incomplete")

// planContext is the validated per-plan input every reducer shares.
type planContext struct {
	SituationID  string
	InputVersion int
	Params       PlanParameters
	Start        time.Time
	End          time.Time
	Limit        int
}

func newPlanContext(plan observationmodel.Plan) (planContext, error) {
	out := planContext{Start: plan.Start.UTC(), End: plan.End.UTC(), Limit: plan.Limit}
	if len(plan.Parameters) > 0 {
		if err := json.Unmarshal(plan.Parameters, &out.Params); err != nil {
			return planContext{}, fmt.Errorf("%w: %v", ErrPlanParameters, err)
		}
	}
	// store_read carries the Situation in scope; every other capability can
	// only carry it as a parameter. Either is authoritative, and the two must
	// not disagree.
	out.SituationID = strings.TrimSpace(out.Params.SituationID)
	if scoped := strings.TrimSpace(plan.Scope["situation_id"]); scoped != "" {
		if out.SituationID != "" && out.SituationID != scoped {
			return planContext{}, fmt.Errorf("%w: situation_id scope and parameter disagree", ErrPlanParameters)
		}
		out.SituationID = scoped
	}
	if out.SituationID == "" {
		return planContext{}, fmt.Errorf("%w: situation_id is required", ErrPlanParameters)
	}
	out.InputVersion = out.Params.InputVersion
	if out.InputVersion < 1 {
		return planContext{}, fmt.Errorf("%w: input_version is required", ErrPlanParameters)
	}
	return out, nil
}

// fact builds one normalized fact with a deterministic identity, so the same
// observation replayed after a crash lands on the same durable row instead of
// duplicating evidence.
func (p planContext) fact(capability observationmodel.Capability, kind, subject string, value any, observedAt time.Time, refs []string) (observationmodel.Fact, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return observationmodel.Fact{}, fmt.Errorf("connectors: encode %s fact: %w", kind, err)
	}
	digest := sha256.Sum256([]byte(string(capability) + "|" + kind + "|" + subject + "|" + string(encoded)))
	id := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s", capability, p.SituationID, p.InputVersion, kind, subject)))
	return observationmodel.Fact{
		ID:               "fact:" + string(capability) + ":" + hex.EncodeToString(id[:16]),
		SituationID:      p.SituationID,
		InputVersion:     p.InputVersion,
		Kind:             kind,
		Subject:          subject,
		Value:            encoded,
		SourceCapability: capability,
		ObservedAt:       observedAt.UTC(),
		Freshness:        observationmodel.FreshnessFresh,
		ResultStatus:     observationmodel.ResultStatusConfirmedValue,
		Digest:           hex.EncodeToString(digest[:]),
		EvidenceRefs:     refs,
		Material:         true,
	}, nil
}

// Sources carries the read-only clients serve already builds. Every field is
// optional: a nil source leaves its capability registered but honestly
// unavailable rather than pretending an empty result was confirmed.
type Sources struct {
	Prometheus PrometheusQuerier
	Zabbix     ZabbixReader
	Logs       LogQuerier
	Sentry     IssueLister
	Changes    ChangeReader
	Situations SituationReader
}

// Adapters maps the configured sources onto the runner's per-capability
// executor slots. An absent source leaves its slot nil, which the catalog
// classifies as unavailable.
func (s Sources) Adapters() observation.Adapters {
	var out observation.Adapters
	if s.Prometheus != nil {
		out.PrometheusQuery = prometheusExecutor{client: s.Prometheus}
	}
	if s.Zabbix != nil {
		out.ZabbixMetricRange = zabbixMetricExecutor{client: s.Zabbix}
		out.ZabbixProblemHistory = zabbixProblemExecutor{client: s.Zabbix}
	}
	if s.Logs != nil {
		out.LokiQuery = logExecutor{client: s.Logs}
	}
	if s.Sentry != nil {
		out.SentryIssues = issueExecutor{client: s.Sentry}
	}
	if s.Changes != nil {
		out.ChangeEvents = changeExecutor{store: s.Changes}
	}
	if s.Situations != nil {
		out.StoreRead = situationExecutor{store: s.Situations}
	}
	return out
}

// Unavailable names the capabilities left without a reducer, so an operator
// can be told which evidence this installation genuinely cannot gather rather
// than discovering silence.
func (s Sources) Unavailable() []string {
	var out []string
	if s.Situations == nil {
		out = append(out, string(observationmodel.CapabilityStoreRead))
	}
	if s.Prometheus == nil {
		out = append(out, string(observationmodel.CapabilityPrometheusQuery))
	}
	if s.Zabbix == nil {
		out = append(out, string(observationmodel.CapabilityZabbixMetricRange), string(observationmodel.CapabilityZabbixProblemHistory))
	}
	if s.Logs == nil {
		out = append(out, string(observationmodel.CapabilityLokiQuery))
	}
	if s.Sentry == nil {
		out = append(out, string(observationmodel.CapabilitySentryIssues))
	}
	if s.Changes == nil {
		out = append(out, string(observationmodel.CapabilityChangeEvents))
	}
	return out
}

// boundedNumeric parses a connector's string-encoded sample, returning ok
// false rather than inventing a zero for an unparseable value.
func boundedNumeric(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
