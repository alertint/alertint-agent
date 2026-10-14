// SPDX-License-Identifier: FSL-1.1-ALv2
// Released full-history loader retained as the test equivalence oracle.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// loadSituationDeliveriesTx reads every immutable delivery belonging to any
// current member Incident of situationID, across the whole Situation (not
// grouped) — callers group by Delivery.IncidentID themselves. It also reads
// the delivery's immutable alert_id FK straight into Delivery.AlertID, and
// parses its immutable labels_json to extract two narrow, durable-per-
// delivery values: the raw severity label (Delivery.Severity — ranking it
// is internal/situation's job via internal/severity.Rank, not this store
// layer's) and whether the Drill marker
// (store.DrillMarkerLabel=store.DrillMarkerValue) is set (Delivery.Drill).
// A shared Alert delivery joins an Incident's view only when its immutable
// ownership link was created at or after that Incident membership. This keeps
// terminal predecessor history out of a linked recurrence while preserving a
// delivery accepted early and correlated after the membership was created.
func loadSituationDeliveriesTx(ctx context.Context, tx *sql.Tx, situationID string) ([]situation.Delivery, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH mapped_deliveries(incident_id, delivery_id) AS (
			SELECT si.incident_id, iad.delivery_id
			FROM situation_incidents si
			JOIN situations s ON s.id = si.situation_id
			JOIN incident_alert_deliveries iad ON iad.incident_id = si.incident_id
			JOIN alert_deliveries owned ON owned.id = iad.delivery_id
			WHERE si.situation_id = ?
			  AND (s.terminal_at IS NULL OR
			       (substr(owned.received_at, 1, 19) || '.' ||
			        substr(ltrim(rtrim(substr(owned.received_at, 20), 'Z'), '.') || '000000000', 1, 9)) <=
			       (substr(s.terminal_at, 1, 19) || '.' ||
			        substr(ltrim(rtrim(substr(s.terminal_at, 20), 'Z'), '.') || '000000000', 1, 9)))
			UNION
			SELECT si.incident_id, owner.delivery_id
			FROM situation_incidents si
			JOIN situations s ON s.id = si.situation_id
			JOIN incident_alerts ia ON ia.incident_id = si.incident_id
			JOIN alert_deliveries shared ON shared.alert_id = ia.alert_id
			JOIN incident_alert_deliveries owner ON owner.delivery_id = shared.id
			WHERE si.situation_id = ?
			  AND (substr(owner.created_at, 1, 19) || '.' ||
			       substr(ltrim(rtrim(substr(owner.created_at, 20), 'Z'), '.') || '000000000', 1, 9)) >=
			      (substr(ia.created_at, 1, 19) || '.' ||
			       substr(ltrim(rtrim(substr(ia.created_at, 20), 'Z'), '.') || '000000000', 1, 9))
			  AND (s.terminal_at IS NULL OR
			       (substr(shared.received_at, 1, 19) || '.' ||
			        substr(ltrim(rtrim(substr(shared.received_at, 20), 'Z'), '.') || '000000000', 1, 9)) <=
			       (substr(s.terminal_at, 1, 19) || '.' ||
			        substr(ltrim(rtrim(substr(s.terminal_at, 20), 'Z'), '.') || '000000000', 1, 9)))
		)
		SELECT ad.id, mapped.incident_id, ad.alert_id, ad.status, ad.payload_digest,
		       ad.source_started_at, ad.started_at_basis, ad.source_resolved_at, ad.resolved_at_basis, ad.received_at,
		       ad.labels_json, ad.source, ad.source_episode_key, ad.source_instance_id, ad.source_signal_id, ad.source_signal_version,
		       ad.acquisition_mode, ad.poll_interval_seconds,
               CASE WHEN json_type(ad.annotations_json, '$.summary') = 'text' AND trim(json_extract(ad.annotations_json, '$.summary')) <> ''
                    THEN substr(json_extract(ad.annotations_json, '$.summary'), 1, 501)
                    WHEN json_type(ad.annotations_json, '$.description') = 'text'
                    THEN substr(json_extract(ad.annotations_json, '$.description'), 1, 501) ELSE '' END
		FROM mapped_deliveries mapped
		JOIN alert_deliveries ad ON ad.id = mapped.delivery_id
		ORDER BY ad.received_at ASC, ad.id ASC, mapped.incident_id ASC`, situationID, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: load situation deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situation.Delivery{}
	for rows.Next() {
		var d situation.Delivery
		var status, startedBasis, resolvedBasis, receivedAtStr, labelsJSON string
		var sourceStarted, sourceResolved, sourceInstanceID, signalID, signalVersion sql.NullString
		if err := rows.Scan(&d.ID, &d.IncidentID, &d.AlertID, &status, &d.PayloadDigest,
			&sourceStarted, &startedBasis, &sourceResolved, &resolvedBasis, &receivedAtStr,
			&labelsJSON, &d.Source, &d.EpisodeKey, &sourceInstanceID, &signalID, &signalVersion,
			&d.AcquisitionMode, &d.PollIntervalSeconds, &d.SourceSummary); err != nil {
			return nil, fmt.Errorf("store: scan situation delivery: %w", err)
		}
		if signalID.Valid {
			d.SourceSignalID = &signalID.String
		}
		if sourceInstanceID.Valid {
			d.SourceInstanceID = &sourceInstanceID.String
		}
		if signalVersion.Valid {
			d.SourceSignalVersion = &signalVersion.String
		}
		d.Status = situationmodel.DeliveryStatus(status)
		d.StartedAtBasis = situationmodel.SourceTimeBasis(startedBasis)
		d.ResolvedAtBasis = situationmodel.SourceTimeBasis(resolvedBasis)
		started, err := timePtr(sourceStarted)
		if err != nil {
			return nil, err
		}
		d.SourceStartedAt = started
		resolved, err := timePtr(sourceResolved)
		if err != nil {
			return nil, err
		}
		d.SourceResolvedAt = resolved
		if d.ReceivedAt, err = time.Parse(time.RFC3339Nano, receivedAtStr); err != nil {
			return nil, fmt.Errorf("store: parse situation delivery received_at: %w", err)
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			// Defensive only: labels_json carries a CHECK (json_valid(...))
			// constraint, so a real row should never fail to unmarshal as an
			// object. Fail closed rather than panic on a scan/decode edge
			// case, matching this function's existing error-handling style.
			return nil, fmt.Errorf("store: unmarshal situation delivery %s labels: %w", d.ID, err)
		}
		d.Severity = labels["severity"]
		d.Drill = labels[DrillMarkerLabel] == DrillMarkerValue
		d.Labels = labels
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation deliveries: %w", err)
	}
	return out, nil
}
