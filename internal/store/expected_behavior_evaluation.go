// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"encoding/json"
	"maps"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func expectedBehaviorInputFromSnapshot(in situation.SnapshotInput, heads []model.ExpectedBehaviorHead) situation.ExpectedBehaviorInput { //nolint:gocyclo // source-specific assembly is kept in one pass over coherent snapshot facts.
	out := situation.ExpectedBehaviorInput{
		SituationID: in.Situation.ID, SituationVersion: in.Situation.InputVersion, GroupKey: in.Situation.GroupKey,
		Now: in.Now, PrimaryStartedAt: in.Situation.EffectiveStartedAt, Heads: heads,
		IndependentlyUrgent: in.Situation.Attention == model.AttentionUrgent || (in.CurrentAssessment != nil && in.CurrentAssessment.Assessment.Attention == model.AttentionUrgent),
	}
	definitions := make(map[string]observationmodel.SourceDefinitionObservation)
	for _, definition := range in.Prepared.SourceDefinitions {
		definitions[definition.InstanceID+"\x00"+definition.RuleID] = definition
	}
	latest := latestExpectedBehaviorDeliveries(in.Deliveries)
	var primary *situation.Delivery
	for i := range latest {
		delivery := latest[i]
		if delivery.Status != model.DeliveryStatusFiring || delivery.SourceInstanceID == nil {
			continue
		}
		ruleID := delivery.Labels["zabbix_trigger_id"]
		if delivery.Source == "alertmanager" && delivery.SourceSignalID != nil {
			ruleID = *delivery.SourceSignalID
		}
		definition := definitions[*delivery.SourceInstanceID+"\x00"+ruleID]
		version := ""
		if definition.Available {
			version = definition.Version
		}
		signal := situation.ExpectedBehaviorSignal{SourceInstanceID: *delivery.SourceInstanceID, Host: delivery.Labels["host"], TriggerID: delivery.Labels["zabbix_trigger_id"], TriggerVersion: version, Presence: "present", EvidenceRefs: definition.EvidenceRefs, ObservedAt: definition.ObservedAt, ExpiresAt: definition.ExpiresAt}
		if delivery.Source == "alertmanager" {
			signal.ProducerID, signal.RuleID, signal.RuleVersion, signal.ScopeLabels = definition.ProducerID, ruleID, version, definition.ScopeLabels
		}
		out.FiringSignals = append(out.FiringSignals, signal)
		if severity.Rank(delivery.Severity) >= 4 {
			out.HasCriticalFiring = true
		}
		matchesHead := false
		for _, head := range heads {
			scope := head.Scope
			matchesHead = matchesHead || (scope.Source == "zabbix" && delivery.Source == "zabbix" && scope.SourceInstanceID == signal.SourceInstanceID && scope.Host == signal.Host && scope.PrimaryTriggerID == signal.TriggerID) ||
				(scope.Source == "alertmanager" && delivery.Source == "alertmanager" && scope.SourceInstanceID == signal.SourceInstanceID && scope.ProducerID == signal.ProducerID && scope.PrimaryRuleID == signal.RuleID && maps.Equal(scope.ScopeLabels, signal.ScopeLabels))
		}
		if matchesHead && (primary == nil || delivery.ReceivedAt.After(primary.ReceivedAt)) {
			selected := delivery
			primary = &selected
			out.SourceInstanceID, out.Host, out.PrimaryTriggerID, out.PrimaryVersion = signal.SourceInstanceID, signal.Host, signal.TriggerID, signal.TriggerVersion
			out.Source = delivery.Source
			if delivery.Source == "alertmanager" {
				out.ProducerID, out.ScopeLabels, out.PrimaryRuleID, out.PrimaryRuleVersion, out.PrimaryPresence = signal.ProducerID, signal.ScopeLabels, signal.RuleID, signal.RuleVersion, definition.Presence
			}
		}
	}
	if primary != nil && primary.SourceStartedAt != nil {
		out.PrimaryStartedAt = primary.SourceStartedAt.UTC()
	}
	for _, run := range in.Prepared.Runs {
		for _, fact := range run.Facts {
			if fact.Kind == "source_definition" {
				var observed observationmodel.SourceDefinitionObservation
				if json.Unmarshal(fact.Value, &observed) == nil && observed.Source == "alertmanager" {
					presence := observed.Presence
					if fact.Freshness != observationmodel.FreshnessFresh || !fact.ExpiresAt.After(in.Now) || !observed.Available {
						presence = "unknown"
					}
					out.Observations = append(out.Observations, situation.ExpectedBehaviorSignal{SourceInstanceID: observed.InstanceID, ProducerID: observed.ProducerID, RuleID: observed.RuleID, RuleVersion: observed.Version, ScopeLabels: observed.ScopeLabels, Presence: presence, EvidenceRefs: []string{fact.ID}, ObservedAt: fact.ObservedAt, ExpiresAt: fact.ExpiresAt})
				}
			}
			if fact.Kind != "zabbix_problem_state" {
				continue
			}
			var observed observationmodel.ZabbixProblemStateObservation
			if json.Unmarshal(fact.Value, &observed) != nil {
				continue
			}
			presence := string(observed.Presence)
			if fact.Freshness != observationmodel.FreshnessFresh || !fact.ExpiresAt.After(in.Now) {
				presence = "unknown"
			}
			out.Observations = append(out.Observations, situation.ExpectedBehaviorSignal{
				SourceInstanceID: observed.SourceInstanceID, Host: observed.Host, TriggerID: observed.TriggerID,
				TriggerVersion: observed.TriggerVersion, Presence: presence, EvidenceRefs: []string{fact.ID},
				ObservedAt: fact.ObservedAt, ExpiresAt: fact.ExpiresAt,
			})
		}
	}
	return out
}

func latestExpectedBehaviorDeliveries(deliveries []situation.Delivery) []situation.Delivery {
	latest := make(map[string]situation.Delivery)
	for _, delivery := range deliveries {
		key := delivery.AlertID
		if key == "" {
			key = delivery.ID
		}
		if prior, ok := latest[key]; !ok || delivery.ReceivedAt.After(prior.ReceivedAt) {
			latest[key] = delivery
		}
	}
	out := make([]situation.Delivery, 0, len(latest))
	for _, delivery := range latest {
		out = append(out, delivery)
	}
	return out
}
