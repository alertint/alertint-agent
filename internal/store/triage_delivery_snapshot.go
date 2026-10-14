// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/alertint/alertint-agent/internal/situation"
)

type incidentHistoryFence struct {
	groupKey            string
	count, maxOwnership int64
}

func readIncidentHistoryFenceTx(ctx context.Context, tx *sql.Tx, incidentID string) (incidentHistoryFence, error) {
	var f incidentHistoryFence
	err := tx.QueryRowContext(ctx, `SELECT i.group_key, COUNT(owner.delivery_id), COALESCE(MAX(owner.rowid),0)
		FROM incidents i LEFT JOIN incident_alert_deliveries owner ON owner.incident_id=i.id
		WHERE i.id=? GROUP BY i.id`, incidentID).Scan(&f.groupKey, &f.count, &f.maxOwnership)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

type incidentHistoryDigests struct {
	membership, input string
	deliveryIDs       []string
}

// Read immutable bodies and compute exact coverage outside the mutation
// transaction. Validate the append-only ownership ledger inside the returned
// transaction before its caller reads or changes mutable triage state. A new
// ownership link (even with backdated created_at) forces a fresh snapshot.
func (s *Store) beginIncidentHistoryTx(ctx context.Context, incidentID string) (*sql.Tx, incidentHistoryDigests, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, incidentHistoryDigests{}, err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, incidentHistoryDigests{}, err
		}
		before, err := readIncidentHistoryFenceTx(ctx, tx, incidentID)
		var deliveryMax int64
		if err == nil {
			err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(rowid),0) FROM alert_deliveries`).Scan(&deliveryMax)
		}
		if err != nil {
			_ = tx.Rollback()
			return nil, incidentHistoryDigests{}, err
		}
		if err := tx.Commit(); err != nil {
			return nil, incidentHistoryDigests{}, err
		}
		deliveries, err := s.loadDeliveryHistory(ctx, deliveryHistorySnapshot{
			deliveryMax: deliveryMax, ownershipMax: before.maxOwnership, incidents: []string{incidentID},
		})
		if err != nil {
			return nil, incidentHistoryDigests{}, err
		}
		history := incidentHistoryDigests{
			membership:  situation.MembershipDigest(incidentID, deliveries),
			input:       situation.IncidentInputDigest(incidentID, before.groupKey, deliveries),
			deliveryIDs: make([]string, 0, len(deliveries)),
		}
		for _, d := range deliveries {
			history.deliveryIDs = append(history.deliveryIDs, d.ID)
		}
		sort.Strings(history.deliveryIDs)
		tx, err = s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, incidentHistoryDigests{}, err
		}
		after, err := readIncidentHistoryFenceTx(ctx, tx, incidentID)
		if err != nil {
			_ = tx.Rollback()
			return nil, incidentHistoryDigests{}, err
		}
		if before == after {
			return tx, history, nil
		}
		_ = tx.Rollback()
	}
	return nil, incidentHistoryDigests{}, errors.New("store: incident delivery history kept changing during snapshot")
}
