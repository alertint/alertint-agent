// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"encoding/json"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func expectedBehaviorInputFromSnapshot(in situation.SnapshotInput, heads []model.ExpectedBehaviorHead) situation.ExpectedBehaviorInput {
	out := situation.ExpectedBehaviorInput{
		SituationID: in.Situation.ID, SituationVersion: in.Situation.InputVersion, GroupKey: in.Situation.GroupKey,
		Now: in.Now, PrimaryStartedAt: in.Situation.EffectiveStartedAt, Source: "zabbix", Heads: heads,
		IndependentlyUrgent: in.Situation.Attention == model.AttentionUrgent || (in.CurrentAssessment != nil && in.CurrentAssessment.Assessment.Attention == model.AttentionUrgent),
	}
	definitions := make(map[string]observationmodel.SourceDefinitionObservation)
	for _, definition := range in.Prepared.SourceDefinitions {
		definitions[definition.InstanceID+"\x00"+definition.RuleID] = definition
	}
	headKeys := make(map[string]bool)
	for _, head := range heads {
		headKeys[head.Scope.SourceInstanceID+"\x00"+head.Scope.Host+"\x00"+head.Scope.PrimaryTriggerID] = true
	}
	latest := latestExpectedBehaviorDeliveries(in.Deliveries)
	var primary *situation.Delivery
	for i := range latest {
		delivery := latest[i]
		if delivery.Status != model.DeliveryStatusFiring || delivery.Source != "zabbix" || delivery.SourceInstanceID == nil {
			continue
		}
		triggerID, host := delivery.Labels["zabbix_trigger_id"], delivery.Labels["host"]
		definition := definitions[*delivery.SourceInstanceID+"\x00"+triggerID]
		version := ""
		if definition.Available {
			version = definition.Version
		}
		signal := situation.ExpectedBehaviorSignal{SourceInstanceID: *delivery.SourceInstanceID, Host: host, TriggerID: triggerID, TriggerVersion: version, Presence: "present"}
		out.FiringSignals = append(out.FiringSignals, signal)
		if severity.Rank(delivery.Severity) >= 4 {
			out.HasCriticalFiring = true
		}
		if headKeys[signal.SourceInstanceID+"\x00"+signal.Host+"\x00"+signal.TriggerID] && (primary == nil || delivery.ReceivedAt.After(primary.ReceivedAt)) {
			selected := delivery
			primary = &selected
			out.SourceInstanceID, out.Host, out.PrimaryTriggerID, out.PrimaryVersion = signal.SourceInstanceID, signal.Host, signal.TriggerID, signal.TriggerVersion
		}
	}
	if primary != nil && primary.SourceStartedAt != nil {
		out.PrimaryStartedAt = primary.SourceStartedAt.UTC()
	}
	for _, run := range in.Prepared.Runs {
		for _, fact := range run.Facts {
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
