// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

const deliveryHistoryPageSize = 256

const situationDeliverySelect = `SELECT ad.id, ?, ad.alert_id, ad.status, ad.payload_digest,
 ad.source_started_at,ad.started_at_basis,ad.source_resolved_at,ad.resolved_at_basis,ad.received_at,
 ad.labels_json,ad.source,ad.source_episode_key,ad.source_instance_id,ad.source_signal_id,ad.source_signal_version,
 ad.acquisition_mode,ad.poll_interval_seconds,
 CASE WHEN json_type(ad.annotations_json,'$.summary')='text' AND trim(json_extract(ad.annotations_json,'$.summary'))<>'' THEN substr(json_extract(ad.annotations_json,'$.summary'),1,501) WHEN json_type(ad.annotations_json,'$.description')='text' THEN substr(json_extract(ad.annotations_json,'$.description'),1,501) ELSE '' END
 FROM alert_deliveries ad`

// These tables append immutable delivery/ownership identities. Capture the
// ledger high-water marks and membership times in the SAME transaction as the
// mutable controller state. Later pages cannot include newly accepted deliveries,
// backdated receipts, or ownership links created after that snapshot. There are
// no runtime deletes/updates of delivery payloads or ownership identities; role
// changes on incident_alerts do not change the captured membership time.
// The full history remains available to coverage digests and investigation inputs.
// Only connection occupancy is bounded, not the semantic contents of the snapshot.
type deliveryHistorySnapshot struct {
	deliveryMax, ownershipMax int64
	terminalAt                *time.Time
	incidents                 []string
	shared                    []deliveryHistoryMember
}
type deliveryHistoryMember struct {
	incidentID, alertID string
	joinedAt            time.Time
}

func captureDeliveryHistoryTx(ctx context.Context, tx *sql.Tx, situationID string, terminalAt *time.Time) (deliveryHistorySnapshot, error) {
	snapshot := deliveryHistorySnapshot{terminalAt: terminalAt}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT MAX(rowid) FROM alert_deliveries),0), COALESCE((SELECT MAX(rowid) FROM incident_alert_deliveries),0)`).Scan(&snapshot.deliveryMax, &snapshot.ownershipMax); err != nil {
		return snapshot, fmt.Errorf("store: capture delivery boundaries: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT si.incident_id,ia.alert_id,ia.created_at FROM situation_incidents si LEFT JOIN incident_alerts ia ON ia.incident_id=si.incident_id WHERE si.situation_id=? ORDER BY si.incident_id,ia.alert_id`, situationID)
	if err != nil {
		return snapshot, err
	}
	defer func() { _ = rows.Close() }()
	last := ""
	for rows.Next() {
		var incidentID string
		var alertID, created sql.NullString
		if err := rows.Scan(&incidentID, &alertID, &created); err != nil {
			return snapshot, err
		}
		if incidentID != last {
			snapshot.incidents = append(snapshot.incidents, incidentID)
			last = incidentID
		}
		if alertID.Valid {
			joined, err := time.Parse(time.RFC3339Nano, created.String)
			if err != nil {
				return snapshot, err
			}
			snapshot.shared = append(snapshot.shared, deliveryHistoryMember{incidentID, alertID.String, joined})
		}
	}
	return snapshot, rows.Err()
}

type deliveryHistoryPointer struct {
	id, receivedText    string
	receivedAt, ownedAt time.Time
}

func (s *Store) loadDeliveryHistory(ctx context.Context, snapshot deliveryHistorySnapshot) ([]situation.Delivery, error) {
	// One load reads hundreds of pages for a long-lived Situation; preparing
	// each page query once spares SQLite parsing it again per page (#99).
	byIncident, err := s.db.PrepareContext(ctx, `SELECT ad.id,ad.received_at,owner.created_at FROM incident_alert_deliveries owner JOIN alert_deliveries ad ON ad.id=owner.delivery_id WHERE owner.incident_id=? AND owner.delivery_id>? AND owner.rowid<=? AND ad.rowid<=? ORDER BY owner.delivery_id LIMIT ?`)
	if err != nil {
		return nil, fmt.Errorf("store: prepare delivery page: %w", err)
	}
	defer func() { _ = byIncident.Close() }()
	byAlert, err := s.db.PrepareContext(ctx, `SELECT ad.id,ad.received_at,owner.created_at FROM alert_deliveries ad INDEXED BY alert_deliveries_alert_id_page_idx JOIN incident_alert_deliveries owner ON owner.delivery_id=ad.id WHERE ad.alert_id=? AND ad.id>? AND ad.rowid<=? AND owner.rowid<=? ORDER BY ad.id LIMIT ?`)
	if err != nil {
		return nil, fmt.Errorf("store: prepare delivery page: %w", err)
	}
	defer func() { _ = byAlert.Close() }()
	out := []situation.Delivery{}
	type key struct{ incidentID, deliveryID string }
	seen := make(map[key]bool)
	receivedOrder := make(map[string]string)
	read := func(incidentID, alertID string, joinedAt time.Time) error {
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			var rows *sql.Rows
			var err error
			if alertID == "" {
				rows, err = byIncident.QueryContext(ctx, incidentID, cursor, snapshot.ownershipMax, snapshot.deliveryMax, deliveryHistoryPageSize)
			} else {
				rows, err = byAlert.QueryContext(ctx, alertID, cursor, snapshot.deliveryMax, snapshot.ownershipMax, deliveryHistoryPageSize)
			}
			if err != nil {
				return fmt.Errorf("store: read delivery page: %w", err)
			}
			page, err := readDeliveryPointers(rows)
			if err != nil {
				return err
			}
			if len(page) == 0 {
				return nil
			}
			cursor = page[len(page)-1].id
			ids := make([]string, 0, len(page))
			for _, p := range page {
				k := key{incidentID, p.id}
				if seen[k] || (snapshot.terminalAt != nil && p.receivedAt.After(*snapshot.terminalAt)) || (alertID != "" && p.ownedAt.Before(joinedAt)) {
					continue
				}
				seen[k] = true
				receivedOrder[p.id] = p.receivedText
				ids = append(ids, p.id)
			}
			if len(ids) > 0 {
				batch, err := s.readDeliveryBodies(ctx, incidentID, ids)
				if err != nil {
					return err
				}
				out = append(out, batch...)
			}
			if len(page) < deliveryHistoryPageSize {
				return nil
			}
		}
	}
	for _, incidentID := range snapshot.incidents {
		if err := read(incidentID, "", time.Time{}); err != nil {
			return nil, err
		}
	}
	for _, member := range snapshot.shared {
		if err := read(member.incidentID, member.alertID, member.joinedAt); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		// Preserve the released SQL TEXT order, including mixed fractional precision.
		if receivedOrder[a.ID] != receivedOrder[b.ID] {
			return receivedOrder[a.ID] < receivedOrder[b.ID]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.IncidentID < b.IncidentID
	})
	return out, nil
}

func readDeliveryPointers(rows *sql.Rows) (out []deliveryHistoryPointer, err error) {
	defer func() {
		if e := rows.Close(); err == nil {
			err = e
		}
	}()
	for rows.Next() {
		var p deliveryHistoryPointer
		var received, owned string
		if err := rows.Scan(&p.id, &received, &owned); err != nil {
			return nil, err
		}
		p.receivedText = received
		p.receivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return nil, err
		}
		p.ownedAt, err = time.Parse(time.RFC3339Nano, owned)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) readDeliveryBodies(ctx context.Context, incidentID string, ids []string) ([]situation.Delivery, error) {
	placeholders, args := inPlaceholders(ids)
	args = append([]any{incidentID}, args...)
	rows, err := s.db.QueryContext(ctx, situationDeliverySelect+` WHERE ad.id IN (`+placeholders+`)`, args...) // #nosec G202 -- fixed placeholders, all values bound
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]situation.Delivery, 0, len(ids))
	for rows.Next() {
		d, err := decodeSituationDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(ids) {
		return nil, fmt.Errorf("store: immutable delivery history changed during read")
	}
	return out, nil
}

func decodeSituationDelivery(rows scanner) (situation.Delivery, error) {
	var d situation.Delivery
	var status, startedBasis, resolvedBasis, receivedAtStr, labelsJSON string
	var sourceStarted, sourceResolved, sourceInstanceID, signalID, signalVersion sql.NullString
	if err := rows.Scan(&d.ID, &d.IncidentID, &d.AlertID, &status, &d.PayloadDigest,
		&sourceStarted, &startedBasis, &sourceResolved, &resolvedBasis, &receivedAtStr,
		&labelsJSON, &d.Source, &d.EpisodeKey, &sourceInstanceID, &signalID, &signalVersion,
		&d.AcquisitionMode, &d.PollIntervalSeconds, &d.SourceSummary); err != nil {
		return situation.Delivery{}, fmt.Errorf("store: scan situation delivery: %w", err)
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
		return situation.Delivery{}, err
	}
	d.SourceStartedAt = started
	resolved, err := timePtr(sourceResolved)
	if err != nil {
		return situation.Delivery{}, err
	}
	d.SourceResolvedAt = resolved
	if d.ReceivedAt, err = time.Parse(time.RFC3339Nano, receivedAtStr); err != nil {
		return situation.Delivery{}, fmt.Errorf("store: parse situation delivery received_at: %w", err)
	}
	var labels map[string]string
	if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
		// Defensive only: labels_json carries a CHECK (json_valid(...))
		// constraint, so a real row should never fail to unmarshal as an
		// object. Fail closed rather than panic on a scan/decode edge
		// case, matching this function's existing error-handling style.
		return situation.Delivery{}, fmt.Errorf("store: unmarshal situation delivery %s labels: %w", d.ID, err)
	}
	d.Severity = labels["severity"]
	d.Drill = labels[DrillMarkerLabel] == DrillMarkerValue
	d.Labels = labels
	return d, nil
}
