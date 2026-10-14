// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
)

// Judgment coverage intentionally excludes delivery history and consumes only
// the authoritative delivery per Alert. Keep its atomic mutation checks narrow;
// reconciliation and triage continue to consume the complete immutable ledger.
func loadSituationJudgmentDeliveriesTx(ctx context.Context, tx *sql.Tx, situationID string, terminalAt *time.Time) ([]situation.Delivery, error) {
	rows, err := tx.QueryContext(ctx, `WITH member_alerts AS (
		SELECT si.incident_id, ia.alert_id FROM situation_incidents si
		JOIN incident_alerts ia ON ia.incident_id=si.incident_id WHERE si.situation_id=?
		UNION
		SELECT si.incident_id, owned.alert_id FROM situation_incidents si
		JOIN incident_delivery_alerts owned ON owned.incident_id=si.incident_id WHERE si.situation_id=?
	)
	SELECT m.incident_id,m.alert_id,ia.created_at FROM member_alerts m
	LEFT JOIN incident_alerts ia ON ia.incident_id=m.incident_id AND ia.alert_id=m.alert_id
	ORDER BY m.incident_id,m.alert_id`, situationID, situationID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	type member struct {
		incidentID, alertID string
		joined              sql.NullString
	}
	var members []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.incidentID, &m.alertID, &m.joined); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	var terminal any
	if terminalAt != nil {
		terminal = canonicalTime(*terminalAt)
	}
	out := make([]situation.Delivery, 0, len(members))
	for _, m := range members {
		var id string
		err := tx.QueryRowContext(ctx, `SELECT ad.id
		FROM alert_deliveries ad INDEXED BY alert_deliveries_judgment_authority_idx
		JOIN incident_alert_deliveries owner ON owner.delivery_id=ad.id
		WHERE ad.alert_id=? AND (owner.incident_id=? OR (? IS NOT NULL AND
		 (substr(owner.created_at,1,19)||'.'||substr(ltrim(rtrim(substr(owner.created_at,20),'Z'),'.')||'000000000',1,9)) >=
		 (substr(?,1,19)||'.'||substr(ltrim(rtrim(substr(?,20),'Z'),'.')||'000000000',1,9))))
		 AND (? IS NULL OR
		 (substr(ad.received_at,1,19)||'.'||substr(ltrim(rtrim(substr(ad.received_at,20),'Z'),'.')||'000000000',1,9)) <=
		 (substr(?,1,19)||'.'||substr(ltrim(rtrim(substr(?,20),'Z'),'.')||'000000000',1,9)))
		ORDER BY
		 (substr(COALESCE(ad.source_started_at,'0001-01-01T00:00:00Z'),1,19)||'.'||substr(ltrim(rtrim(substr(COALESCE(ad.source_started_at,'0001-01-01T00:00:00Z'),20),'Z'),'.')||'000000000',1,9)) DESC,
		 (substr(ad.received_at,1,19)||'.'||substr(ltrim(rtrim(substr(ad.received_at,20),'Z'),'.')||'000000000',1,9)) DESC,
		 ad.id DESC LIMIT 1`, m.alertID, m.incidentID, m.joined, m.joined, m.joined, terminal, terminal, terminal).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		d, err := decodeSituationDelivery(tx.QueryRowContext(ctx, situationDeliverySelect+` WHERE ad.id=?`, m.incidentID, id))
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
