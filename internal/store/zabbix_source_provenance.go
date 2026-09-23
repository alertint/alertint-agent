// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// ZabbixSourceObservationView is ADR-0053's durable current source-definition
// head exposed to reconciliation and MCP. A stale view deliberately clears
// the version and reports expired so it cannot be mistaken for current authority.
type ZabbixSourceObservationView struct {
	Definition observationmodel.SourceDefinitionObservation `json:"definition"`
	ObservedAt time.Time                                    `json:"observed_at"`
	ExpiresAt  time.Time                                    `json:"expires_at"`
	Freshness  string                                       `json:"freshness"`
}

func sourceObservationKey(source, instanceID, ruleID, scopeLabelsJSON string) string {
	if instanceID == "" {
		instanceID = "unknown"
	}
	key := instanceID + ":" + ruleID
	if source == "alertmanager" {
		key += ":" + scopeLabelsJSON
	}
	return key
}

//nolint:gocyclo // atomic validation, immutable insert, and head advance are one fail-closed transaction boundary
func insertZabbixSourceObservationTx(ctx context.Context, tx *sql.Tx, situationID, runID string, fact observationmodel.Fact, now time.Time) (bool, error) {
	if fact.Kind != "source_definition" {
		return false, nil
	}
	var definition observationmodel.SourceDefinitionObservation
	if err := json.Unmarshal(fact.Value, &definition); err != nil {
		return false, fmt.Errorf("store: decode zabbix source definition fact: %w", err)
	}
	if (definition.Source != "zabbix" && definition.Source != "alertmanager") || strings.TrimSpace(definition.RuleID) == "" || (definition.Source == "zabbix" && strings.TrimSpace(definition.Host) == "") {
		return false, errors.New("store: source definition requires a supported source and rule identity")
	}
	if definition.HistoricalProven {
		return false, errors.New("store: current zabbix source observation cannot claim historical proof")
	}
	if definition.Available {
		if definition.InstanceID == "" || definition.EndpointID == "" || definition.VersionAlgorithm == "" || definition.Version == "" || definition.UnavailableReason != "" {
			return false, errors.New("store: available zabbix source definition is incomplete")
		}
	} else if definition.UnavailableReason == "" || definition.VersionAlgorithm != "" || definition.Version != "" {
		return false, errors.New("store: unavailable zabbix source definition requires one reason and no version")
	}
	components, err := json.Marshal(definition.ComponentDigests)
	if err != nil {
		return false, fmt.Errorf("store: encode zabbix source component digests: %w", err)
	}
	if string(components) == "null" {
		components = []byte("{}")
	}
	triggerIDs, err := json.Marshal(nonNilStrings(definition.TriggerIDs))
	if err != nil {
		return false, fmt.Errorf("store: encode zabbix source trigger ids: %w", err)
	}
	itemIDs, err := json.Marshal(nonNilStrings(definition.ItemIDs))
	if err != nil {
		return false, fmt.Errorf("store: encode zabbix source item ids: %w", err)
	}
	scopeLabels, err := json.Marshal(definition.ScopeLabels)
	if err != nil {
		return false, fmt.Errorf("store: encode source scope labels: %w", err)
	}
	if string(scopeLabels) == "null" {
		scopeLabels = []byte("{}")
	}
	key := sourceObservationKey(definition.Source, definition.InstanceID, definition.RuleID, string(scopeLabels))
	observationID := definition.Source + "-source:" + fact.ID

	var priorDigest, priorObservedAt string
	err = tx.QueryRowContext(ctx, `
		SELECT o.content_digest,o.observed_at
		FROM zabbix_source_observation_heads h
		JOIN zabbix_source_observations o ON o.id=h.observation_id
		WHERE h.situation_id=? AND h.source_key=?`, situationID, key).Scan(&priorDigest, &priorObservedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("store: read current zabbix source observation: %w", err)
	}
	missingHead := errors.Is(err, sql.ErrNoRows)
	advanceHead := true
	if !missingHead {
		priorObserved, parseErr := time.Parse(time.RFC3339Nano, priorObservedAt)
		if parseErr != nil {
			return false, fmt.Errorf("store: parse current zabbix source observation time: %w", parseErr)
		}
		switch {
		case fact.ObservedAt.Before(priorObserved):
			advanceHead = false
		case fact.ObservedAt.Equal(priorObserved) && priorDigest != fact.Digest:
			return false, errors.New("store: conflicting zabbix source observations have the same observation time")
		}
	}
	changed := advanceHead && (missingHead || priorDigest != fact.Digest)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO zabbix_source_observations (
			id,fact_id,run_id,situation_id,source_key,source_instance_id,rule_id,host,endpoint_id,
			available,version_algorithm,version_value,unavailable_reason,content_digest,
			component_digests_json,trigger_ids_json,item_ids_json,observed_at,expires_at,
			source,producer_id,rule_group,presence,scope_labels_json
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		observationID, fact.ID, runID, situationID, key, nullableText(definition.InstanceID), definition.RuleID,
		definition.Host, nullableText(definition.EndpointID), boolToInt(definition.Available), nullableText(definition.VersionAlgorithm),
		nullableText(definition.Version), nullableText(definition.UnavailableReason), fact.Digest, string(components),
		string(triggerIDs), string(itemIDs), canonicalTime(fact.ObservedAt), canonicalTime(fact.ExpiresAt),
		definition.Source, nullableText(definition.ProducerID), nullableText(definition.RuleGroup), nullableText(definition.Presence), string(scopeLabels)); err != nil {
		return false, fmt.Errorf("store: insert zabbix source observation: %w", err)
	}
	if !advanceHead {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO zabbix_source_observation_heads (situation_id,source_key,observation_id,updated_at)
		VALUES (?,?,?,?)
		ON CONFLICT(situation_id,source_key) DO UPDATE SET observation_id=excluded.observation_id,updated_at=excluded.updated_at`,
		situationID, key, observationID, canonicalTime(now)); err != nil {
		return false, fmt.Errorf("store: advance zabbix source observation head: %w", err)
	}
	return changed, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func loadCurrentZabbixSourceObservationsTx(ctx context.Context, tx *sql.Tx, situationID string, now time.Time) ([]ZabbixSourceObservationView, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT o.fact_id,o.source_instance_id,o.rule_id,o.host,o.endpoint_id,o.available,o.version_algorithm,o.version_value,
		       o.unavailable_reason,o.component_digests_json,o.trigger_ids_json,o.item_ids_json,o.observed_at,o.expires_at,
		       o.source,o.producer_id,o.rule_group,o.presence,o.scope_labels_json
		FROM zabbix_source_observation_heads h
		JOIN zabbix_source_observations o ON o.id=h.observation_id
		WHERE h.situation_id=? ORDER BY o.source_key`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query current zabbix source observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ZabbixSourceObservationView
	for rows.Next() {
		var instanceID, endpointID, algorithm, version, reason, producerID, ruleGroup, presence sql.NullString
		var factID, ruleID, host, componentsJSON, triggerIDsJSON, itemIDsJSON, observedAt, expiresAt, source, scopeLabelsJSON string
		var available int
		if err := rows.Scan(&factID, &instanceID, &ruleID, &host, &endpointID, &available, &algorithm, &version, &reason,
			&componentsJSON, &triggerIDsJSON, &itemIDsJSON, &observedAt, &expiresAt, &source, &producerID, &ruleGroup, &presence, &scopeLabelsJSON); err != nil {
			return nil, fmt.Errorf("store: scan current zabbix source observation: %w", err)
		}
		observed, err := time.Parse(time.RFC3339Nano, observedAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse zabbix source observed_at: %w", err)
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse zabbix source expires_at: %w", err)
		}
		definition := observationmodel.SourceDefinitionObservation{
			Source: source, InstanceID: instanceID.String, RuleID: ruleID, Host: host, EndpointID: endpointID.String,
			Available: available == 1, VersionAlgorithm: algorithm.String, Version: version.String,
			UnavailableReason: reason.String, HistoricalProven: false, ProducerID: producerID.String, RuleGroup: ruleGroup.String, Presence: presence.String,
			EvidenceRefs: []string{factID}, ObservedAt: observed, ExpiresAt: expires,
		}
		if err := json.Unmarshal([]byte(scopeLabelsJSON), &definition.ScopeLabels); err != nil {
			return nil, fmt.Errorf("store: decode source scope labels: %w", err)
		}
		if err := json.Unmarshal([]byte(componentsJSON), &definition.ComponentDigests); err != nil {
			return nil, fmt.Errorf("store: decode zabbix source component digests: %w", err)
		}
		if err := json.Unmarshal([]byte(triggerIDsJSON), &definition.TriggerIDs); err != nil {
			return nil, fmt.Errorf("store: decode zabbix source trigger ids: %w", err)
		}
		if err := json.Unmarshal([]byte(itemIDsJSON), &definition.ItemIDs); err != nil {
			return nil, fmt.Errorf("store: decode zabbix source item ids: %w", err)
		}
		freshness := "fresh"
		if !now.UTC().Before(expires) {
			freshness = "stale"
			definition.Available = false
			definition.EndpointID = ""
			definition.VersionAlgorithm = ""
			definition.Version = ""
			definition.ComponentDigests = nil
			definition.TriggerIDs = nil
			definition.ItemIDs = nil
			definition.UnavailableReason = "expired"
		}
		out = append(out, ZabbixSourceObservationView{Definition: definition, ObservedAt: observed, ExpiresAt: expires, Freshness: freshness})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate current zabbix source observations: %w", err)
	}
	return out, nil
}

// GetCurrentZabbixSourceObservations returns one current head per exact
// Situation/source-rule identity. It never substitutes prior success when
// the current head failed or expired.
func (s *Store) GetCurrentZabbixSourceObservations(ctx context.Context, situationID string, now time.Time) ([]ZabbixSourceObservationView, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	views, err := loadCurrentZabbixSourceObservationsTx(ctx, tx, situationID, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return views, nil
}
