// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Startup reconstruction primitives (Task 8)
//
// These three methods back situation.Reconstructor's zero-outward-effect
// startup pass: recover expired leases across every fenced foundation
// table, then represent every operational Incident that predates (or
// otherwise missed) Situation attachment under its exact group's
// Situation. None of them ever call a notifier, LLM, connector, or Slack
// dependency, and none of them run inside the same transaction as one —
// they are pure database projections and lease releases.
//
// LeaseRecovery and UpgradeIncident are defined here, in internal/store,
// rather than in internal/situation, and re-exported there as type
// aliases (see internal/situation/reconstruct.go). internal/situation
// already imports internal/store — its InputStore interface names
// store.SituationClaim directly — so the reverse import store ->
// situation would cycle. Defining the shared types on the store side and
// aliasing them from situation is what lets *Store satisfy
// situation.ReconstructStore without a cycle.
// ----------------------------------------------------------------------

// LeaseRecovery reports how many rows RecoverExpiredFoundationLeases moved
// from an expired claim back to unclaimed, per fenced table.
type LeaseRecovery struct {
	AlertDispatches int64
	SituationInputs int64
	Situations      int64
}

// UpgradeIncident is one operational Incident with no Situation membership
// yet, carrying the persisted Incident/delivery-derived times
// ReconstructSituation needs to represent it — never a live read of
// anything outward.
type UpgradeIncident struct {
	IncidentID              string
	GroupKey                string
	EffectiveStartedAt      time.Time
	EffectiveStartedAtBasis situationmodel.SourceTimeBasis
	FirstReceivedAt         time.Time
	LastLifecycleObservedAt time.Time
}

// RecoverExpiredFoundationLeases releases every expired lease across the
// three fenced foundation tables — claimed alert dispatches, claimed
// Situation inputs, and claimed Situations — back to unclaimed, in one
// atomic transaction. A release never touches claim_token or
// attempt_count: those are fencing/backoff history, not part of the lease
// itself, so a recovered row keeps exactly the attempt history it already
// had ("no loss of attempt count/token"). retry_at is left exactly as it
// was too — recovery is not itself a retry decision, it only returns
// contended state to a claimable rest state; ClaimAlertDispatches /
// ClaimSituationInputs / ClaimDueSituations pick a freed row back up as
// soon as their own due-time predicate says so.
func (s *Store) RecoverExpiredFoundationLeases(ctx context.Context, now time.Time) (LeaseRecovery, error) {
	nowStr := canonicalTime(now.UTC())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LeaseRecovery{}, fmt.Errorf("store: begin recover expired foundation leases: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var rec LeaseRecovery
	rec.AlertDispatches, err = execRowsAffected(ctx, tx, `
		UPDATE alert_delivery_dispatches
		SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'claimed' AND lease_expires_at <= ?`, nowStr)
	if err != nil {
		return LeaseRecovery{}, fmt.Errorf("store: recover alert dispatch leases: %w", err)
	}

	rec.SituationInputs, err = execRowsAffected(ctx, tx, `
		UPDATE situation_input_outbox
		SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'claimed' AND lease_expires_at <= ?`, nowStr)
	if err != nil {
		return LeaseRecovery{}, fmt.Errorf("store: recover situation input leases: %w", err)
	}

	rec.Situations, err = execRowsAffected(ctx, tx, `
		UPDATE situations
		SET lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE lease_owner IS NOT NULL AND lease_expires_at <= ?`, nowStr, nowStr)
	if err != nil {
		return LeaseRecovery{}, fmt.Errorf("store: recover situation leases: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return LeaseRecovery{}, fmt.Errorf("store: commit recover expired foundation leases: %w", err)
	}
	return rec, nil
}

// execRowsAffected runs one UPDATE and returns RowsAffected.
func execRowsAffected(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// unrepresentedOperationalIncidentsQuery selects every Incident with no
// situation_incidents row yet, in exact-group, stable order: an
// operational status (collecting/ready/processing/analyzed/failed)
// represents unconditionally — failed is included deliberately, since
// migration 0001 already supports it and excluding it would hide
// triage-exhausted operational state from the Situation foundation. A
// resolved Incident represents only if it still carries an immutable
// firing delivery member: its own alerts resolved, but the durable
// delivery ledger never recorded that resolution, so from the Situation's
// perspective this Incident is not actually settled.
const unrepresentedOperationalIncidentsQuery = `
SELECT i.id, i.group_key, i.first_alert_at, i.last_alert_at
FROM incidents i
WHERE NOT EXISTS (SELECT 1 FROM situation_incidents si WHERE si.incident_id = i.id)
  AND (
    i.status IN ('collecting','ready','processing','analyzed','failed')
    OR (i.status = 'resolved' AND EXISTS (
        SELECT 1 FROM incident_alert_deliveries iad
        JOIN alert_deliveries ad ON ad.id = iad.delivery_id
        WHERE iad.incident_id = i.id AND ad.status = 'firing'
    ))
  )
ORDER BY i.group_key ASC, i.id ASC`

// UnrepresentedOperationalIncidents lists every Incident reconstruction
// still needs to attach to a Situation, along with the persisted
// Incident/delivery times ReconstructSituation needs to represent each
// one. It never synthesizes an Alert delivery for an old row: an Incident
// with no attached delivery under the durable ledger (every Incident
// predating migration 0013) falls back to its own first_alert_at/
// last_alert_at with basis receipt_fallback — the closest honest
// substitute available for pre-upgrade rows.
func (s *Store) UnrepresentedOperationalIncidents(ctx context.Context) ([]UpgradeIncident, error) {
	raw, err := queryUnrepresentedOperationalIncidentRows(ctx, s.db)
	if err != nil {
		return nil, err
	}

	out := make([]UpgradeIncident, 0, len(raw))
	for _, r := range raw {
		firstAlertAt, err := time.Parse(time.RFC3339Nano, r.firstAlert)
		if err != nil {
			return nil, fmt.Errorf("store: parse incident %s first_alert_at: %w", r.id, err)
		}
		lastAlertAt, err := time.Parse(time.RFC3339Nano, r.lastAlert)
		if err != nil {
			return nil, fmt.Errorf("store: parse incident %s last_alert_at: %w", r.id, err)
		}

		startAt, basis, firstReceived, err := incidentSourceTimes(ctx, s.db, r.id, firstAlertAt)
		if err != nil {
			return nil, fmt.Errorf("store: resolve incident %s source times: %w", r.id, err)
		}

		out = append(out, UpgradeIncident{
			IncidentID:              r.id,
			GroupKey:                r.groupKey,
			EffectiveStartedAt:      startAt,
			EffectiveStartedAtBasis: basis,
			FirstReceivedAt:         firstReceived,
			LastLifecycleObservedAt: lastAlertAt,
		})
	}
	return out, nil
}

// unrepresentedOperationalIncidentRow is one raw scanned row from
// unrepresentedOperationalIncidentsQuery, before its timestamp strings are
// parsed and its source times resolved.
type unrepresentedOperationalIncidentRow struct {
	id, groupKey          string
	firstAlert, lastAlert string
}

// queryUnrepresentedOperationalIncidentRows runs
// unrepresentedOperationalIncidentsQuery and drains it into a slice, always
// closing rows via a single deferred call — even on a scan or iteration
// error — so the connection is never left with an open result set.
func queryUnrepresentedOperationalIncidentRows(ctx context.Context, db *sql.DB) ([]unrepresentedOperationalIncidentRow, error) {
	rows, err := db.QueryContext(ctx, unrepresentedOperationalIncidentsQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list unrepresented operational incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var raw []unrepresentedOperationalIncidentRow
	for rows.Next() {
		var r unrepresentedOperationalIncidentRow
		if err := rows.Scan(&r.id, &r.groupKey, &r.firstAlert, &r.lastAlert); err != nil {
			return nil, fmt.Errorf("store: scan unrepresented operational incident: %w", err)
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate unrepresented operational incidents: %w", err)
	}
	return raw, nil
}

// incidentSourceTimes derives one Incident's aggregate (effective start,
// basis, first received) purely from its own persisted rows: every
// alert_delivery attached to it under the durable ledger, folded exactly
// as sourceTimesForInputTx resolves one input's contribution (earliest
// source-provable start wins; any basis disagreement settles on "mixed"),
// or — for an Incident with zero attached deliveries, i.e. one that
// predates the delivery ledger entirely — the Incident's own
// first_alert_at as a receipt_fallback basis start/receipt time.
func incidentSourceTimes(ctx context.Context, db *sql.DB, incidentID string, fallbackFirstAlertAt time.Time) (time.Time, situationmodel.SourceTimeBasis, time.Time, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ad.source_started_at, ad.started_at_basis, ad.received_at
		FROM incident_alert_deliveries iad
		JOIN alert_deliveries ad ON ad.id = iad.delivery_id
		WHERE iad.incident_id = ?
		ORDER BY ad.received_at ASC, ad.id ASC`, incidentID)
	if err != nil {
		return time.Time{}, "", time.Time{}, err
	}
	defer func() { _ = rows.Close() }()

	var (
		haveAny       bool
		startAt       time.Time
		basis         situationmodel.SourceTimeBasis
		firstReceived time.Time
	)
	for rows.Next() {
		var sourceStarted sql.NullString
		var startedBasis, receivedAtStr string
		if err := rows.Scan(&sourceStarted, &startedBasis, &receivedAtStr); err != nil {
			return time.Time{}, "", time.Time{}, err
		}
		receivedAt, err := time.Parse(time.RFC3339Nano, receivedAtStr)
		if err != nil {
			return time.Time{}, "", time.Time{}, err
		}

		deliveryBasis := situationmodel.SourceTimeBasis(startedBasis)
		deliveryStart := receivedAt
		if sourceStarted.Valid && (deliveryBasis == situationmodel.SourceTimeBasisSourcePayload || deliveryBasis == situationmodel.SourceTimeBasisSourceAPI) {
			deliveryStart, err = time.Parse(time.RFC3339Nano, sourceStarted.String)
			if err != nil {
				return time.Time{}, "", time.Time{}, err
			}
		} else {
			deliveryBasis = situationmodel.SourceTimeBasisReceiptFallback
		}

		if !haveAny {
			startAt, basis, firstReceived = deliveryStart, deliveryBasis, receivedAt
			haveAny = true
			continue
		}
		startAt = earlierTime(startAt, deliveryStart)
		basis = mergeBasis(basis, deliveryBasis)
		firstReceived = earlierTime(firstReceived, receivedAt)
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, "", time.Time{}, err
	}

	if !haveAny {
		return fallbackFirstAlertAt, situationmodel.SourceTimeBasisReceiptFallback, fallbackFirstAlertAt, nil
	}
	return startAt, basis, firstReceived, nil
}

// ReconstructSituation represents one exact group's batch of
// UpgradeIncidents under that group's Situation: joins the group's one
// existing nonterminal Situation if it has one, or creates a new active
// "observe" Situation seeded from the batch, linked via
// previous_situation_id to the newest terminal same-group Situation if
// one exists — resolveAndApplySituationTx's owner-selection precedence,
// generalized from one input to a batch of Incidents sharing one exact
// group. Every Incident in incidents is attached as an immutable member,
// in stable IncidentID order. Due reason upgrade_reconstruction is merged
// in and next_assessment_at is pulled to now, so the represented
// Situation is due for assessment on the controller's very next pass —
// this call itself runs no assessment, notifier, LLM, connector, or Slack
// call, and commits nothing outside its own transaction.
func (s *Store) ReconstructSituation(ctx context.Context, groupKey string, incidents []UpgradeIncident, now time.Time) (string, error) {
	if strings.TrimSpace(groupKey) == "" {
		return "", errors.New("store: reconstruct situation requires a group key")
	}
	if len(incidents) == 0 {
		return "", errors.New("store: reconstruct situation requires at least one incident")
	}

	sorted := make([]UpgradeIncident, len(incidents))
	copy(sorted, incidents)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IncidentID < sorted[j].IncidentID })

	startAt := sorted[0].EffectiveStartedAt
	basis := sorted[0].EffectiveStartedAtBasis
	firstReceived := sorted[0].FirstReceivedAt
	lastLifecycle := sorted[0].LastLifecycleObservedAt
	for _, inc := range sorted {
		if inc.GroupKey != groupKey {
			return "", fmt.Errorf("store: reconstruct situation %s: incident %s has group key %q", groupKey, inc.IncidentID, inc.GroupKey)
		}
	}
	for _, inc := range sorted[1:] {
		startAt = earlierTime(startAt, inc.EffectiveStartedAt)
		basis = mergeBasis(basis, inc.EffectiveStartedAtBasis)
		firstReceived = earlierTime(firstReceived, inc.FirstReceivedAt)
		if inc.LastLifecycleObservedAt.After(lastLifecycle) {
			lastLifecycle = inc.LastLifecycleObservedAt
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin reconstruct situation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	situationID, err := nonterminalSituationIDByGroupTx(ctx, tx, groupKey)
	if err != nil {
		return "", err
	}

	if situationID != "" {
		if err := joinSituationForReconstructionTx(ctx, tx, situationID, startAt, basis, firstReceived, lastLifecycle, now); err != nil {
			return "", err
		}
	} else {
		situationID, err = createSituationForReconstructionTx(ctx, tx, groupKey, startAt, basis, firstReceived, lastLifecycle, now)
		if err != nil {
			return "", err
		}
	}

	for _, inc := range sorted {
		if err := attachSituationMembershipTx(ctx, tx, situationID, inc.IncidentID, now); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit reconstruct situation: %w", err)
	}
	return situationID, nil
}

// joinSituationForReconstructionTx advances an existing Situation with a
// reconstruction batch: input_version increments exactly once,
// effective_started_at/first_received_at take the earlier of their
// current value and the batch's aggregate, effective_started_at_basis
// merges per mergeBasis, last_lifecycle_observed_at takes the LATER of
// its current value and the batch's aggregate (unlike the start/received
// times, this field tracks the most recent lifecycle activity observed,
// not the earliest), next_assessment_at is pulled to now so the Situation
// is due immediately, and due_reasons_json merges upgrade_reconstruction.
// It also clears any aggregate lease owner/expiry while leaving
// claim_token untouched, mirroring joinSituationTx.
func joinSituationForReconstructionTx(ctx context.Context, tx *sql.Tx, situationID string, startAt time.Time, basis situationmodel.SourceTimeBasis, firstReceived, lastLifecycle, now time.Time) error {
	current, err := getSituationTx(ctx, tx, situationID)
	if err != nil {
		return err
	}

	newStart := earlierTime(current.EffectiveStartedAt, startAt)
	newBasis := mergeBasis(current.EffectiveStartedAtBasis, basis)
	newFirstReceived := earlierTime(current.FirstReceivedAt, firstReceived)
	newLastLifecycle := current.LastLifecycleObservedAt
	if lastLifecycle.After(newLastLifecycle) {
		newLastLifecycle = lastLifecycle
	}
	newNextAssessment := earlierTime(current.NextAssessmentAt, now)
	newDueReasons := mergeDueReason(current.DueReasons, situationmodel.DueUpgradeReconstruction)

	dueReasonsJSON, err := json.Marshal(newDueReasons)
	if err != nil {
		return fmt.Errorf("store: marshal situation due reasons: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situations
		SET input_version = input_version + 1,
		    effective_started_at = ?, effective_started_at_basis = ?,
		    first_received_at = ?, last_lifecycle_observed_at = ?,
		    next_assessment_at = ?, due_reasons_json = ?,
		    lease_owner = NULL, lease_expires_at = NULL,
		    updated_at = ?
		WHERE id = ? AND input_version = ?`,
		canonicalTime(newStart), string(newBasis), canonicalTime(newFirstReceived), canonicalTime(newLastLifecycle),
		canonicalTime(newNextAssessment), string(dueReasonsJSON),
		canonicalTime(now), situationID, current.InputVersion)
	if err != nil {
		return fmt.Errorf("store: update situation for reconstruction: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count updated situation for reconstruction: %w", err)
	}
	if n != 1 {
		return ErrSituationVersionConflict
	}
	return nil
}

// createSituationForReconstructionTx inserts a brand-new active "observe"
// Situation at input_version 1, seeded entirely from one reconstruction
// batch, linked via previous_situation_id to the newest terminal
// same-group Situation if one exists. next_assessment_at is set to now,
// so a freshly represented Situation is due for assessment immediately.
func createSituationForReconstructionTx(ctx context.Context, tx *sql.Tx, groupKey string, startAt time.Time, basis situationmodel.SourceTimeBasis, firstReceived, lastLifecycle, now time.Time) (string, error) {
	previousID, err := newestTerminalSituationIDTx(ctx, tx, groupKey)
	if err != nil {
		return "", err
	}
	var previousArg any
	if previousID != nil {
		previousArg = *previousID
	}

	id := uuid.NewString()
	dueReasonsJSON, err := json.Marshal([]situationmodel.DueReason{situationmodel.DueUpgradeReconstruction})
	if err != nil {
		return "", fmt.Errorf("store: marshal new situation due reasons: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO situations (
			id, previous_situation_id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json,
			created_at, updated_at
		) VALUES (?, ?, ?, 'active', 'observe', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, previousArg, groupKey,
		canonicalTime(now), canonicalTime(startAt), string(basis), canonicalTime(firstReceived),
		canonicalTime(lastLifecycle), canonicalTime(now), string(dueReasonsJSON),
		canonicalTime(now), canonicalTime(now))
	if err != nil {
		return "", fmt.Errorf("store: insert situation for reconstruction: %w", err)
	}
	return id, nil
}
