// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

var (
	// ErrUnavailable means a configured capability cannot currently be read.
	ErrUnavailable = errors.New("observation: capability unavailable")
	// ErrUnconfirmedEmpty means absence could not be confirmed at the source.
	ErrUnconfirmedEmpty = errors.New("observation: empty result unconfirmed")
	// ErrStale means the source returned evidence outside its freshness bound.
	ErrStale = errors.New("observation: stale result")
	// ErrTruncated means the source reported that its bounded result was cut.
	ErrTruncated = errors.New("observation: truncated result")
	// ErrVocabularyUnresolved means a requested scope value is not resolved for
	// the owning Situation input.
	ErrVocabularyUnresolved = errors.New("observation: vocabulary unresolved")
)

const maxParametersBytes = 32 << 10

// Validate rejects any plan that is not fully resolved, read-only, and bounded
// by the selected capability.
func (c *Catalog) Validate(plan observationmodel.Plan, allowed Scope) error {
	capability, ok := c.capability(plan.Capability)
	if !ok {
		return fmt.Errorf("observation: unknown or non-read capability %q", plan.Capability)
	}
	if !capability.ReadOnly {
		return fmt.Errorf("observation: capability %q is not read-only", plan.Capability)
	}
	if capability.MaxWindow <= 0 || capability.MaxLimit <= 0 || capability.Freshness <= 0 || capability.Timeout <= 0 ||
		capability.MaxResultBytes <= 0 || capability.MaxCost.SourceCalls <= 0 || capability.MaxCost.Tokens < 0 {
		return fmt.Errorf("observation: capability %q has incomplete bounds", plan.Capability)
	}
	if err := validateScope(plan.Scope, capability, allowed); err != nil {
		return err
	}
	if plan.Start.IsZero() || plan.End.IsZero() || plan.Start.Location() != time.UTC || plan.End.Location() != time.UTC {
		return errors.New("observation: window requires canonical utc timestamps")
	}
	window := plan.End.Sub(plan.Start)
	if window <= 0 || capability.MaxWindow <= 0 || window > capability.MaxWindow {
		return fmt.Errorf("observation: window must be positive and at most %s", capability.MaxWindow)
	}
	if plan.Limit <= 0 || capability.MaxLimit <= 0 || plan.Limit > capability.MaxLimit {
		return fmt.Errorf("observation: limit must be between 1 and %d", capability.MaxLimit)
	}
	if plan.Budget < 0 || (plan.Budget > 0 && capability.MaxCost.SourceCalls > 0 && plan.Budget > capability.MaxCost.SourceCalls) {
		return fmt.Errorf("observation: budget exceeds capability source-call bound %d", capability.MaxCost.SourceCalls)
	}
	if strings.TrimSpace(plan.Why) == "" || len(plan.Why) > 1024 {
		return errors.New("observation: bounded reason is required")
	}
	if len(plan.ReconsiderOn) > 16 || len(plan.StopOn) > 16 {
		return errors.New("observation: reconsider and stop conditions are bounded to 16 each")
	}
	parameters, err := decodeParameters(plan.Parameters)
	if err != nil {
		return err
	}
	if containsRecursiveModel(parameters) {
		return errors.New("observation: recursive model calls are forbidden")
	}
	return validateCapabilityParameters(capability, parameters)
}

func validateScope(plan map[string]string, capability Capability, allowed Scope) error {
	permitted := make(map[string]struct{}, len(capability.ScopeKeys))
	for _, key := range capability.ScopeKeys {
		permitted[key] = struct{}{}
	}
	for _, key := range capability.RequiredScope {
		if strings.TrimSpace(plan[key]) == "" {
			return fmt.Errorf("%w: required scope %q is unresolved", ErrVocabularyUnresolved, key)
		}
	}
	if len(plan) == 0 {
		return fmt.Errorf("%w: scope is empty", ErrVocabularyUnresolved)
	}
	for key, value := range plan {
		if _, ok := permitted[key]; !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: scope %q is not valid for %q", ErrVocabularyUnresolved, key, capability.Name)
		}
		values := allowed[key]
		matched := false
		for _, candidate := range values {
			if value == candidate {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: %s=%q is outside the owning group", ErrVocabularyUnresolved, key, value)
		}
	}
	return nil
}

func decodeParameters(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	if len(raw) > maxParametersBytes {
		return nil, errors.New("observation: parameters exceed 32768 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil || out == nil {
		return nil, errors.New("observation: parameters must be one json object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("observation: parameters contain trailing json")
	}
	return out, nil
}

func containsRecursiveModel(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			lower := strings.ToLower(key)
			if lower == "model" || lower == "llm" || lower == "model_call" || lower == "recursive_model_call" {
				return true
			}
			if containsRecursiveModel(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsRecursiveModel(nested) {
				return true
			}
		}
	}
	return false
}

func validateCapabilityParameters(capability Capability, parameters map[string]any) error {
	var required, permitted []string
	switch capability.Name {
	case observationmodel.CapabilityStoreRead:
		required, permitted = []string{"resource"}, []string{"resource"}
	case observationmodel.CapabilityPrometheusQuery:
		required, permitted = []string{"query"}, []string{"query", "sample_interval_seconds"}
	case observationmodel.CapabilityZabbixMetricRange:
		required, permitted = []string{"item_key"}, []string{"item_key", "sample_interval_seconds"}
	case observationmodel.CapabilityZabbixProblemHistory:
		permitted = []string{"severity_min"}
	case observationmodel.CapabilityLokiQuery:
		required, permitted = []string{"query"}, []string{"query", "direction"}
	case observationmodel.CapabilitySentryIssues:
		permitted = []string{"query"}
	case observationmodel.CapabilityChangeEvents:
		permitted = []string{"kind"}
	default:
		return fmt.Errorf("observation: capability %q has no parameter vocabulary", capability.Name)
	}
	allowed := make(map[string]struct{}, len(permitted))
	for _, key := range permitted {
		allowed[key] = struct{}{}
	}
	for key := range parameters {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("observation: parameter %q is not in the %q vocabulary", key, capability.Name)
		}
	}
	for _, key := range required {
		value, ok := parameters[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("observation: parameter %q is required for %q", key, capability.Name)
		}
	}
	for _, key := range []string{"resource", "query", "item_key", "severity_min", "direction", "kind"} {
		if value, present := parameters[key]; present {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("observation: parameter %q must be a string", key)
			}
		}
	}
	if resource, ok := parameters["resource"].(string); ok {
		switch resource {
		case "situation", "incident", "deliveries", "assessments", "judgments", "envelopes", "history":
		default:
			return fmt.Errorf("observation: store resource %q is not in the closed vocabulary", resource)
		}
	}
	if severity, ok := parameters["severity_min"].(string); ok {
		value, err := strconv.Atoi(severity)
		if err != nil || value < 0 || value > 5 {
			return errors.New("observation: severity_min must be a string from 0 through 5")
		}
	}
	if direction, ok := parameters["direction"].(string); ok && direction != "forward" && direction != "backward" {
		return errors.New("observation: direction must be forward or backward")
	}
	if sample, ok := parameters["sample_interval_seconds"]; ok {
		number, ok := sample.(json.Number)
		if !ok {
			return errors.New("observation: sample_interval_seconds must be an integer")
		}
		seconds, err := strconv.ParseInt(number.String(), 10, 64)
		if err != nil || seconds <= 0 || time.Duration(seconds)*time.Second < capability.Freshness {
			return fmt.Errorf("observation: sampling is faster than capability freshness %s", capability.Freshness)
		}
	}
	return nil
}

func validResultStatus(value observationmodel.ResultStatus) bool {
	switch value {
	case observationmodel.ResultStatusConfirmedValue, observationmodel.ResultStatusConfirmedEmpty,
		observationmodel.ResultStatusUnconfirmedEmpty, observationmodel.ResultStatusUnavailable,
		observationmodel.ResultStatusFailed, observationmodel.ResultStatusStale,
		observationmodel.ResultStatusTruncated, observationmodel.ResultStatusWithheldByBudget,
		observationmodel.ResultStatusVocabularyUnresolved:
		return true
	default:
		return false
	}
}

func validFreshness(value observationmodel.Freshness) bool {
	return value == observationmodel.FreshnessFresh || value == observationmodel.FreshnessStale || value == observationmodel.FreshnessUnknown
}
