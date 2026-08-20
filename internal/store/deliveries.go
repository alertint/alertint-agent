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

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// DeliveryInput is one validated source lifecycle delivery to commit with its
// latest Alert projection and durable correlation dispatch.
type DeliveryInput struct {
	ID                       string
	Alert                    Alert
	Source                   string
	SourceEventID            *string
	SourceEpisodeKey         string
	SourceStartedAt          *time.Time
	SourceResolvedAt         *time.Time
	StartedAtBasis           situationmodel.SourceTimeBasis
	ResolvedAtBasis          situationmodel.SourceTimeBasis
	ReceiverGroupingIdentity string
	PayloadDigest            string
}

// AlertDelivery is the immutable accepted source lifecycle record.
type AlertDelivery struct {
	ID                       string
	Alert                    Alert
	Source                   string
	SourceEventID            *string
	SourceEpisodeKey         string
	SourceStartedAt          *time.Time
	SourceResolvedAt         *time.Time
	StartedAtBasis           situationmodel.SourceTimeBasis
	ResolvedAtBasis          situationmodel.SourceTimeBasis
	ReceiverGroupingIdentity string
	PayloadDigest            string
	ReceivedAt               time.Time
}

// AlertDispatch is the durable correlation outbox state for one delivery.
type AlertDispatch struct {
	Delivery       AlertDelivery
	Status         string
	LeaseOwner     *string
	LeaseExpiresAt *time.Time
	AttemptCount   int
	LastErrorClass *string
	RetryAt        *time.Time
	AppliedAt      *time.Time
}

type preparedDelivery struct {
	in         DeliveryInput
	labelsJSON string
	annosJSON  string
	receivedAt string
	startsAt   string
	endsAt     any
	startedAt  any
	resolvedAt any
}

// AcceptDeliveries atomically updates latest alert projections, appends their
// immutable delivery records, and queues durable correlation dispatches. A
// duplicate delivery ID is a successful no-op, so transport redelivery cannot
// mutate an already accepted projection.
func (s *Store) AcceptDeliveries(ctx context.Context, in []DeliveryInput) ([]AlertDelivery, error) {
	prepared := make([]preparedDelivery, len(in))
	for i, d := range in {
		p, err := prepareDelivery(d)
		if err != nil {
			return nil, err
		}
		prepared[i] = p
	}
	if len(prepared) == 0 {
		return []AlertDelivery{}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin accept deliveries: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	out := make([]AlertDelivery, 0, len(prepared))
	for _, p := range prepared {
		existing, err := getDelivery(ctx, tx, p.in.ID)
		switch {
		case err == nil:
			out = append(out, existing)
			continue
		case !errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("store: read existing delivery: %w", err)
		}

		alert, err := upsertAlertTx(ctx, tx, p)
		if err != nil {
			return nil, err
		}
		delivery, err := insertDelivery(ctx, tx, p, alert)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_delivery_dispatches (delivery_id, status) VALUES (?, 'pending')`, delivery.ID); err != nil {
			return nil, fmt.Errorf("store: insert alert delivery dispatch: %w", err)
		}
		out = append(out, delivery)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit accept deliveries: %w", err)
	}
	return out, nil
}

func prepareDelivery(d DeliveryInput) (preparedDelivery, error) {
	if err := validateAlert(d.Alert); err != nil {
		return preparedDelivery{}, err
	}
	if strings.TrimSpace(d.ID) == "" {
		return preparedDelivery{}, errors.New("store: delivery id is required")
	}
	if strings.TrimSpace(d.Source) == "" {
		return preparedDelivery{}, errors.New("store: delivery source is required")
	}
	if strings.TrimSpace(d.SourceEpisodeKey) == "" {
		return preparedDelivery{}, errors.New("store: delivery source episode key is required")
	}
	if strings.TrimSpace(d.ReceiverGroupingIdentity) == "" {
		return preparedDelivery{}, errors.New("store: delivery receiver grouping identity is required")
	}
	if strings.TrimSpace(d.PayloadDigest) == "" {
		return preparedDelivery{}, errors.New("store: delivery payload digest is required")
	}
	if !validSourceTimeBasis(d.StartedAtBasis) || !validSourceTimeBasis(d.ResolvedAtBasis) {
		return preparedDelivery{}, fmt.Errorf("store: invalid delivery source time basis started=%q resolved=%q", d.StartedAtBasis, d.ResolvedAtBasis)
	}
	labelsJSON, err := json.Marshal(d.Alert.Labels)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery labels: %w", err)
	}
	annosJSON, err := json.Marshal(d.Alert.Annotations)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery annotations: %w", err)
	}
	p := preparedDelivery{
		in: d, labelsJSON: string(labelsJSON), annosJSON: string(annosJSON),
		receivedAt: canonicalTime(d.Alert.ReceivedAt), startsAt: canonicalTime(d.Alert.StartsAt),
	}
	if d.Alert.EndsAt != nil {
		p.endsAt = canonicalTime(*d.Alert.EndsAt)
	}
	if d.SourceStartedAt != nil {
		p.startedAt = canonicalTime(*d.SourceStartedAt)
	}
	if d.SourceResolvedAt != nil {
		p.resolvedAt = canonicalTime(*d.SourceResolvedAt)
	}
	return p, nil
}

func validSourceTimeBasis(v situationmodel.SourceTimeBasis) bool {
	switch v {
	case situationmodel.SourceTimeBasisSourcePayload, situationmodel.SourceTimeBasisSourceAPI,
		situationmodel.SourceTimeBasisReceiptFallback, situationmodel.SourceTimeBasisMissing,
		situationmodel.SourceTimeBasisMixed:
		return true
	default:
		return false
	}
}

func canonicalTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func upsertAlertTx(ctx context.Context, tx *sql.Tx, p preparedDelivery) (Alert, error) {
	a := p.in.Alert
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, ends_at, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			status = excluded.status, labels_json = excluded.labels_json,
			annotations_json = excluded.annotations_json, starts_at = excluded.starts_at,
			ends_at = excluded.ends_at, received_at = excluded.received_at
	`, a.ID, a.Fingerprint, a.Status, p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt, p.receivedAt)
	if err != nil {
		return Alert{}, fmt.Errorf("store: upsert delivery alert: %w", err)
	}
	row := tx.QueryRowContext(ctx, `SELECT id FROM alerts WHERE fingerprint = ?`, a.Fingerprint)
	if err := row.Scan(&a.ID); err != nil {
		return Alert{}, fmt.Errorf("store: read back delivery alert: %w", err)
	}
	a.ReceiverGroupingIdentity = p.in.ReceiverGroupingIdentity
	return a, nil
}

func insertDelivery(ctx context.Context, tx *sql.Tx, p preparedDelivery, a Alert) (AlertDelivery, error) {
	d := p.in
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			id, alert_id, source, source_event_id, source_episode_key, status, labels_json, annotations_json,
			starts_at, ends_at, source_started_at, source_resolved_at, started_at_basis, resolved_at_basis,
			receiver_grouping_identity, payload_digest, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, d.ID, a.ID, d.Source, nullableString(d.SourceEventID), d.SourceEpisodeKey, d.Alert.Status,
		p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt, p.startedAt, p.resolvedAt, d.StartedAtBasis, d.ResolvedAtBasis,
		d.ReceiverGroupingIdentity, d.PayloadDigest, p.receivedAt)
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: insert alert delivery: %w", err)
	}
	return AlertDelivery{ID: d.ID, Alert: a, Source: d.Source, SourceEventID: copyStringPtr(d.SourceEventID),
		SourceEpisodeKey: d.SourceEpisodeKey, SourceStartedAt: copyTimePtr(d.SourceStartedAt), SourceResolvedAt: copyTimePtr(d.SourceResolvedAt),
		StartedAtBasis: d.StartedAtBasis, ResolvedAtBasis: d.ResolvedAtBasis, ReceiverGroupingIdentity: d.ReceiverGroupingIdentity,
		PayloadDigest: d.PayloadDigest, ReceivedAt: d.Alert.ReceivedAt.UTC()}, nil
}

// ClaimAlertDispatches leases due dispatches. Claiming is durable and never
// calls outbound code; callers apply the claimed work after this transaction.
func (s *Store) ClaimAlertDispatches(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]AlertDispatch, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: dispatch claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim alert dispatches: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	leaseExpires := canonicalTime(now.Add(lease))
	claimedRows, err := tx.QueryContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
		WHERE delivery_id IN (
			SELECT delivery_id FROM alert_delivery_dispatches
			WHERE (status = 'pending' AND (retry_at IS NULL OR retry_at <= ?))
				OR (status = 'claimed' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
			ORDER BY COALESCE(retry_at, '') ASC, delivery_id ASC LIMIT ?
		)
		RETURNING delivery_id
	`, owner, leaseExpires, canonicalTime(now), canonicalTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim alert dispatches: %w", err)
	}
	claimedIDs := make([]string, 0, limit)
	for claimedRows.Next() {
		var id string
		if err := claimedRows.Scan(&id); err != nil {
			_ = claimedRows.Close()
			return nil, fmt.Errorf("store: scan claimed alert dispatch id: %w", err)
		}
		claimedIDs = append(claimedIDs, id)
	}
	if err := claimedRows.Err(); err != nil {
		_ = claimedRows.Close()
		return nil, fmt.Errorf("store: iterate claimed alert dispatch ids: %w", err)
	}
	if err := claimedRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close claimed alert dispatch ids: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty alert dispatch claim: %w", err)
		}
		return []AlertDispatch{}, nil
	}
	args := make([]any, len(claimedIDs))
	placeholders := make([]string, len(claimedIDs))
	for i, id := range claimedIDs {
		args[i], placeholders[i] = id, "?"
	}
	rows, err := tx.QueryContext(ctx, dispatchSelect+` WHERE d.delivery_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY d.delivery_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AlertDispatch{}
	for rows.Next() {
		d, err := scanDispatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed alert dispatches: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim alert dispatches: %w", err)
	}
	return out, nil
}

// MarkAlertDispatchApplied records successful correlation after its own
// transaction has committed.
func (s *Store) MarkAlertDispatchApplied(ctx context.Context, deliveryID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alert_delivery_dispatches SET status='applied', lease_owner=NULL, lease_expires_at=NULL, retry_at=NULL, applied_at=? WHERE delivery_id=?`, canonicalTime(at), deliveryID)
	if err != nil {
		return fmt.Errorf("store: mark alert dispatch applied: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count applied alert dispatch: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RetryAlertDispatch releases a dispatch for retry or marks it terminal.
func (s *Store) RetryAlertDispatch(ctx context.Context, deliveryID, class string, retryAt time.Time, terminal bool) error {
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status, retry = "failed", nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE alert_delivery_dispatches SET status=?, lease_owner=NULL, lease_expires_at=NULL, last_error_class=?, retry_at=? WHERE delivery_id=?`, status, class, retry, deliveryID)
	if err != nil {
		return fmt.Errorf("store: retry alert dispatch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried alert dispatch: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const dispatchSelect = `
SELECT d.delivery_id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest, ad.received_at,
       a.fingerprint, d.status, d.lease_owner, d.lease_expires_at,
       d.attempt_count, d.last_error_class, d.retry_at, d.applied_at
FROM alert_delivery_dispatches d
JOIN alert_deliveries ad ON ad.id = d.delivery_id
JOIN alerts a ON a.id = ad.alert_id`

func getDelivery(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (AlertDelivery, error) {
	row := q.QueryRowContext(ctx, deliverySelect+` WHERE ad.id = ?`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertDelivery{}, ErrNotFound
	}
	return d, err
}

const deliverySelect = `
SELECT ad.id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest, ad.received_at,
       a.fingerprint
FROM alert_deliveries ad JOIN alerts a ON a.id = ad.alert_id`

func scanDispatch(s scanner) (AlertDispatch, error) {
	var d AlertDispatch
	var sourceEvent, alertEnds, sourceStarted, sourceResolved, leaseOwner, leaseExpires, lastClass, retryAt, appliedAt sql.NullString
	var status, labels, annotations, startedBasis, resolvedBasis, received, alertStarts string
	err := s.Scan(&d.Delivery.ID, &d.Delivery.Alert.ID, &d.Delivery.Source, &sourceEvent, &d.Delivery.SourceEpisodeKey, &status,
		&labels, &annotations, &alertStarts, &alertEnds, &sourceStarted, &sourceResolved, &startedBasis, &resolvedBasis, &d.Delivery.ReceiverGroupingIdentity,
		&d.Delivery.PayloadDigest, &received, &d.Delivery.Alert.Fingerprint, &d.Status, &leaseOwner, &leaseExpires,
		&d.AttemptCount, &lastClass, &retryAt, &appliedAt)
	if err != nil {
		return AlertDispatch{}, err
	}
	d.Delivery.Alert.Status = status
	if err := hydrateDelivery(&d.Delivery, labels, annotations, sourceEvent, sourceStarted, sourceResolved, startedBasis, resolvedBasis, received, alertStarts, alertEnds); err != nil {
		return AlertDispatch{}, err
	}
	d.LeaseOwner, d.LastErrorClass = stringPtr(leaseOwner), stringPtr(lastClass)
	if d.LeaseExpiresAt, err = timePtr(leaseExpires); err != nil {
		return AlertDispatch{}, err
	}
	if d.RetryAt, err = timePtr(retryAt); err != nil {
		return AlertDispatch{}, err
	}
	if d.AppliedAt, err = timePtr(appliedAt); err != nil {
		return AlertDispatch{}, err
	}
	return d, nil
}

func scanDelivery(s scanner) (AlertDelivery, error) {
	var d AlertDelivery
	var sourceEvent, alertEnds, sourceStarted, sourceResolved sql.NullString
	var status, labels, annotations, startedBasis, resolvedBasis, received, alertStarts string
	err := s.Scan(&d.ID, &d.Alert.ID, &d.Source, &sourceEvent, &d.SourceEpisodeKey, &status,
		&labels, &annotations, &alertStarts, &alertEnds, &sourceStarted, &sourceResolved, &startedBasis, &resolvedBasis, &d.ReceiverGroupingIdentity,
		&d.PayloadDigest, &received, &d.Alert.Fingerprint)
	if err != nil {
		return AlertDelivery{}, err
	}
	d.Alert.Status = status
	if err := hydrateDelivery(&d, labels, annotations, sourceEvent, sourceStarted, sourceResolved, startedBasis, resolvedBasis, received, alertStarts, alertEnds); err != nil {
		return AlertDelivery{}, err
	}
	return d, nil
}

func hydrateDelivery(d *AlertDelivery, labels, annotations string, sourceEvent, sourceStarted, sourceResolved sql.NullString, startedBasis, resolvedBasis, received, alertStarts string, alertEnds sql.NullString) error {
	if err := json.Unmarshal([]byte(labels), &d.Alert.Labels); err != nil {
		return fmt.Errorf("store: unmarshal delivery labels: %w", err)
	}
	if err := json.Unmarshal([]byte(annotations), &d.Alert.Annotations); err != nil {
		return fmt.Errorf("store: unmarshal delivery annotations: %w", err)
	}
	var err error
	if d.Alert.StartsAt, err = time.Parse(time.RFC3339Nano, alertStarts); err != nil {
		return fmt.Errorf("store: parse delivery alert starts at: %w", err)
	}
	if d.Alert.EndsAt, err = timePtr(alertEnds); err != nil {
		return err
	}
	if d.Alert.ReceivedAt, err = time.Parse(time.RFC3339Nano, received); err != nil {
		return fmt.Errorf("store: parse delivery received at: %w", err)
	}
	d.ReceivedAt = d.Alert.ReceivedAt
	d.Alert.ReceiverGroupingIdentity = d.ReceiverGroupingIdentity
	d.SourceEventID = stringPtr(sourceEvent)
	if d.SourceStartedAt, err = timePtr(sourceStarted); err != nil {
		return err
	}
	if d.SourceResolvedAt, err = timePtr(sourceResolved); err != nil {
		return err
	}
	d.StartedAtBasis, d.ResolvedAtBasis = situationmodel.SourceTimeBasis(startedBasis), situationmodel.SourceTimeBasis(resolvedBasis)
	return nil
}

func nullableString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}
func copyStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
func copyTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	out := v.UTC()
	return &out
}
func stringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	out := v.String
	return &out
}
func timePtr(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	out, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil, fmt.Errorf("store: parse delivery time: %w", err)
	}
	return &out, nil
}
