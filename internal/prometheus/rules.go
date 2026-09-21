// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"

	"gopkg.in/yaml.v3"
)

const RuleDefinitionVersionAlgorithm = "prometheus-alerting-rule-effective-v1"

// RuleDefinition is current Prometheus configuration truth. It never claims
// the version that produced an older Alertmanager delivery.
type RuleDefinition struct {
	ProducerID        string            `json:"producer_id"`
	Group             string            `json:"group"`
	Rule              string            `json:"rule"`
	RuleID            string            `json:"rule_id"`
	Available         bool              `json:"available"`
	VersionAlgorithm  string            `json:"version_algorithm,omitempty"`
	Version           string            `json:"version,omitempty"`
	UnavailableReason string            `json:"unavailable_reason,omitempty"`
	Presence          string            `json:"presence"`
	ScopeLabels       map[string]string `json:"scope_labels,omitempty"`
}

// RuleDefinitionBounded reads the configured group/rule from the bounded
// rules API and hashes only definition fields. Runtime health, values and
// evaluation clocks do not affect the version.
func (c *Client) RuleDefinitionBounded(ctx context.Context, producerID, groupName, ruleName string, scope map[string]string) (RuleDefinition, error) {
	return c.RuleDefinitionObservedBounded(ctx, producerID, groupName, ruleName, scope, func() error { return nil }, func(bool, error) {})
}

// RuleDefinitionObservedBounded accounts each physical source request through
// before/after. Both the rules read and loaded-config check must succeed.
func (c *Client) RuleDefinitionObservedBounded(ctx context.Context, producerID, groupName, ruleName string, scope map[string]string, before func() error, after func(bool, error)) (RuleDefinition, error) {
	result := RuleDefinition{ProducerID: producerID, Group: groupName, Rule: ruleName,
		RuleID: "prometheus:" + producerID + ":" + groupName + ":" + ruleName, Presence: "unknown", ScopeLabels: scope}
	if err := before(); err != nil {
		after(false, err)
		return result, err
	}
	raw, err := c.apiGetBounded(ctx, "/api/v1/rules", url.Values{})
	after(true, err)
	if err != nil {
		return result, err
	}
	if err := before(); err != nil {
		after(false, err)
		return result, err
	}
	configRaw, configErr := c.apiGetBounded(ctx, "/api/v1/status/config", nil)
	after(true, configErr)
	if configErr != nil {
		return result, configErr
	}
	var configEnvelope struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(configRaw, &configEnvelope); err != nil {
		return result, err
	}
	var loaded struct {
		Alerting struct {
			AlertRelabelConfigs []any `yaml:"alert_relabel_configs"`
		} `yaml:"alerting"`
	}
	if err := yaml.Unmarshal([]byte(configEnvelope.YAML), &loaded); err != nil {
		return result, err
	}
	if len(loaded.Alerting.AlertRelabelConfigs) > 0 {
		result.UnavailableReason = "unsupported_alert_relabeling"
		return result, nil
	}
	var payload struct {
		Groups []struct {
			Name     string  `json:"name"`
			File     string  `json:"file"`
			Interval float64 `json:"interval"`
			Limit    int     `json:"limit"`
			Rules    []struct {
				Type          string            `json:"type"`
				Name          string            `json:"name"`
				Query         string            `json:"query"`
				Duration      float64           `json:"duration"`
				KeepFiringFor float64           `json:"keepFiringFor"`
				Labels        map[string]string `json:"labels"`
				Annotations   map[string]string `json:"annotations"`
				Alerts        []struct {
					Labels map[string]string `json:"labels"`
					State  string            `json:"state"`
				} `json:"alerts"`
			} `json:"rules"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return result, err
	}
	type match struct {
		interval float64
		limit    int
		rule     struct {
			Type          string            `json:"type"`
			Name          string            `json:"name"`
			Query         string            `json:"query"`
			Duration      float64           `json:"duration"`
			KeepFiringFor float64           `json:"keepFiringFor"`
			Labels        map[string]string `json:"labels"`
			Annotations   map[string]string `json:"annotations"`
			Alerts        []struct {
				Labels map[string]string `json:"labels"`
				State  string            `json:"state"`
			} `json:"alerts"`
		}
	}
	recordingNames := []string{}
	for _, group := range payload.Groups {
		for _, rule := range group.Rules {
			if rule.Type == "recording" {
				recordingNames = append(recordingNames, rule.Name)
			}
		}
	}
	var matches []match
	for _, group := range payload.Groups {
		if group.Name != groupName {
			continue
		}
		for _, rule := range group.Rules {
			if rule.Type == "alerting" && rule.Name == ruleName {
				matches = append(matches, match{interval: group.Interval, limit: group.Limit, rule: rule})
			}
		}
	}
	if len(matches) != 1 {
		result.UnavailableReason = "rule_not_found"
		if len(matches) > 1 {
			result.UnavailableReason = "ambiguous_rule"
		}
		return result, nil
	}
	m := matches[0]
	for _, name := range recordingNames {
		pattern := `(^|[^A-Za-z0-9_:])` + regexp.QuoteMeta(name) + `([^A-Za-z0-9_:]|$)`
		if matched, _ := regexp.MatchString(pattern, m.rule.Query); matched {
			result.UnavailableReason = "unsupported_recording_dependency"
			return result, nil
		}
	}
	canonical := struct {
		Group         string            `json:"group"`
		Interval      float64           `json:"interval_seconds"`
		Limit         int               `json:"limit"`
		Name          string            `json:"name"`
		Query         string            `json:"query"`
		Duration      float64           `json:"duration_seconds"`
		KeepFiringFor float64           `json:"keep_firing_for_seconds"`
		Labels        map[string]string `json:"labels"`
		Annotations   map[string]string `json:"annotations"`
	}{groupName, m.interval, m.limit, m.rule.Name, m.rule.Query, m.rule.Duration, m.rule.KeepFiringFor, m.rule.Labels, m.rule.Annotations}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(encoded)
	result.Available, result.VersionAlgorithm, result.Version = true, RuleDefinitionVersionAlgorithm, "sha256:"+hex.EncodeToString(sum[:])
	result.Presence = "absent"
	for _, alert := range m.rule.Alerts {
		if alert.State != "firing" && alert.State != "pending" {
			continue
		}
		matched := true
		for key, value := range scope {
			if alert.Labels[key] != value {
				matched = false
				break
			}
		}
		if matched {
			result.Presence = "present"
			break
		}
	}
	return result, nil
}
