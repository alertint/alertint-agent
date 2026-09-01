// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// SourceAcquisitionMode records how the immutable lifecycle delivery entered
// AlertINT. A later on-demand API read may refresh evidence, but it must
// never rewrite this provenance from webhook to poll or back.
type SourceAcquisitionMode string

const (
	SourceAcquisitionWebhook SourceAcquisitionMode = "webhook"
	SourceAcquisitionPoll    SourceAcquisitionMode = "poll"
)

// SourceProvenance binds one immutable delivery to the reusable source
// signal whose lifecycle owns envelope authority. SignalID and SignalVersion
// are nil unless the Receiver can prove them from the source payload itself
// — never synthesized from an event ID, Alert fingerprint, wall clock, UUID,
// or a generic source/schema fallback. Unavailable provenance is honest
// durable state; it grants no envelope authority.
type SourceProvenance struct {
	SignalID            *string
	SignalVersion       *string
	GeneratorURL        string
	AcquisitionMode     SourceAcquisitionMode
	PollIntervalSeconds int
}

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
	SourceProvenance         SourceProvenance
}

// AlertDelivery is the immutable accepted source lifecycle record. Once
// committed, none of its fields are ever rewritten — a duplicate delivery ID
// returns the original row unchanged.
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
	SourceProvenance         SourceProvenance
}

// AlertDispatch is the durable correlation outbox state for one delivery.
// It is fenced by (lease_owner, claim_token): every state transition after
// a claim must present both, and any mismatch means the lease moved on.
type AlertDispatch struct {
	Delivery       AlertDelivery
	Status         string
	LeaseOwner     *string
	LeaseExpiresAt *time.Time
	ClaimToken     int64
	AttemptCount   int
	LastErrorClass *string
	RetryAt        *time.Time
	AppliedAt      *time.Time
}

// ErrAlertDispatchLeaseLost means a worker no longer owns the claimed
// delivery dispatch — its lease token was superseded, most often because the
// original lease expired and a different worker reclaimed the row. Callers
// must discard the stale claim, not retry with it, on receiving this error.
var ErrAlertDispatchLeaseLost = errors.New("store: alert dispatch lease lost")

// validateDeliveryInput checks the fields AcceptDeliveries must have before
// it can safely open a transaction. It never touches the database.
func validateDeliveryInput(d DeliveryInput) error {
	if err := validateAlert(d.Alert); err != nil {
		return err
	}
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("store: delivery id is required")
	}
	if strings.TrimSpace(d.Source) == "" {
		return errors.New("store: delivery source is required")
	}
	if strings.TrimSpace(d.SourceEpisodeKey) == "" {
		return errors.New("store: delivery source episode key is required")
	}
	if strings.TrimSpace(d.ReceiverGroupingIdentity) == "" {
		return errors.New("store: delivery receiver grouping identity is required")
	}
	if strings.TrimSpace(d.PayloadDigest) == "" {
		return errors.New("store: delivery payload digest is required")
	}
	return validateSourceProvenance(d)
}

// validateSourceProvenance enforces the two provenance rules the store must
// never relax: SignalVersion requires SignalID (identity may be provable
// while version is not), and the acquisition mode's poll interval contract
// (zero for webhook, positive for poll).
func validateSourceProvenance(d DeliveryInput) error {
	p := d.SourceProvenance
	switch p.AcquisitionMode {
	case SourceAcquisitionWebhook:
		if p.PollIntervalSeconds != 0 {
			return errors.New("store: delivery poll interval must be zero for webhook acquisition")
		}
	case SourceAcquisitionPoll:
		if p.PollIntervalSeconds <= 0 {
			return errors.New("store: delivery poll interval must be positive for poll acquisition")
		}
	default:
		return fmt.Errorf("store: delivery acquisition mode %q must be webhook or poll", p.AcquisitionMode)
	}
	if p.SignalID != nil && strings.TrimSpace(*p.SignalID) == "" {
		return errors.New("store: delivery source signal id must not be blank when present")
	}
	if p.SignalVersion != nil {
		if strings.TrimSpace(*p.SignalVersion) == "" {
			return errors.New("store: delivery source signal version must not be blank when present")
		}
		if p.SignalID == nil {
			return errors.New("store: delivery source signal version requires a source signal id")
		}
	}
	return nil
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

// preparedDelivery holds one validated, normalized delivery plus the exact
// SQL argument encodings it will need, so AcceptDeliveries never does string
// or JSON work after opening its transaction.
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

// prepareDelivery validates d and normalizes it into the exact form
// AcceptDeliveries writes. It performs no I/O.
func prepareDelivery(d DeliveryInput) (preparedDelivery, error) {
	if err := validateDeliveryInput(d); err != nil {
		return preparedDelivery{}, err
	}
	if !validSourceTimeBasis(d.StartedAtBasis) || !validSourceTimeBasis(d.ResolvedAtBasis) {
		return preparedDelivery{}, fmt.Errorf("store: invalid delivery source time basis started=%q resolved=%q", d.StartedAtBasis, d.ResolvedAtBasis)
	}
	d.SourceProvenance = normalizeSourceProvenance(d.SourceProvenance)

	labelsJSON, err := json.Marshal(d.Alert.Labels)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery labels: %w", err)
	}
	annosJSON, err := json.Marshal(d.Alert.Annotations)
	if err != nil {
		return preparedDelivery{}, fmt.Errorf("store: marshal delivery annotations: %w", err)
	}

	p := preparedDelivery{
		in:         d,
		labelsJSON: string(labelsJSON),
		annosJSON:  string(annosJSON),
		receivedAt: canonicalTime(d.Alert.ReceivedAt),
		startsAt:   canonicalTime(d.Alert.StartsAt),
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

// normalizeSourceProvenance trims whitespace only. It must never invent a
// SignalID, SignalVersion, or GeneratorURL — those are Receiver-proven or
// absent; the caller (an ingress receiver) is responsible for supplying them.
func normalizeSourceProvenance(p SourceProvenance) SourceProvenance {
	if p.SignalID != nil {
		v := strings.TrimSpace(*p.SignalID)
		p.SignalID = &v
	}
	if p.SignalVersion != nil {
		v := strings.TrimSpace(*p.SignalVersion)
		p.SignalVersion = &v
	}
	p.GeneratorURL = strings.TrimSpace(p.GeneratorURL)
	return p
}

func canonicalTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// AcceptDeliveries validates every input before opening a transaction, then
// atomically commits the latest Alert projection, the immutable delivery
// row, and a pending correlation dispatch row for each new delivery. A
// duplicate delivery ID is a successful no-op: it returns the existing
// immutable delivery and touches no other row, so transport redelivery of
// the same normalized payload can never mutate an already accepted
// projection. One invalid member fails the whole batch before any row is
// written.
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
		existing, err := getDeliveryTx(ctx, tx, p.in.ID)
		switch {
		case err == nil:
			out = append(out, existing)
			continue
		case !errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("store: read existing delivery: %w", err)
		}

		alert, err := upsertDeliveryAlertTx(ctx, tx, p)
		if err != nil {
			return nil, err
		}
		delivery, err := insertDeliveryTx(ctx, tx, p, alert)
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

// upsertDeliveryAlertTx applies the "latest wins" Alert projection update
// inside the caller's transaction, mirroring UpsertAlertByFingerprint.
func upsertDeliveryAlertTx(ctx context.Context, tx *sql.Tx, p preparedDelivery) (Alert, error) {
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

func insertDeliveryTx(ctx context.Context, tx *sql.Tx, p preparedDelivery, a Alert) (AlertDelivery, error) {
	d := p.in
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			id, alert_id, source, source_event_id, source_episode_key, status,
			labels_json, annotations_json, starts_at, ends_at,
			source_started_at, source_resolved_at, started_at_basis, resolved_at_basis,
			receiver_grouping_identity, payload_digest,
			source_signal_id, source_signal_version, generator_url, acquisition_mode, poll_interval_seconds,
			received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		d.ID, a.ID, d.Source, nullableString(d.SourceEventID), d.SourceEpisodeKey, d.Alert.Status,
		p.labelsJSON, p.annosJSON, p.startsAt, p.endsAt,
		p.startedAt, p.resolvedAt, string(d.StartedAtBasis), string(d.ResolvedAtBasis),
		d.ReceiverGroupingIdentity, d.PayloadDigest,
		nullableString(d.SourceProvenance.SignalID), nullableString(d.SourceProvenance.SignalVersion),
		d.SourceProvenance.GeneratorURL, string(d.SourceProvenance.AcquisitionMode), d.SourceProvenance.PollIntervalSeconds,
		p.receivedAt,
	)
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: insert alert delivery: %w", err)
	}
	return AlertDelivery{
		ID: d.ID, Alert: a, Source: d.Source, SourceEventID: copyStringPtr(d.SourceEventID),
		SourceEpisodeKey: d.SourceEpisodeKey, SourceStartedAt: copyTimePtr(d.SourceStartedAt), SourceResolvedAt: copyTimePtr(d.SourceResolvedAt),
		StartedAtBasis: d.StartedAtBasis, ResolvedAtBasis: d.ResolvedAtBasis, ReceiverGroupingIdentity: d.ReceiverGroupingIdentity,
		PayloadDigest: d.PayloadDigest, ReceivedAt: d.Alert.ReceivedAt.UTC(), SourceProvenance: d.SourceProvenance,
	}, nil
}

// ClaimAlertDispatches leases due dispatches — pending rows never claimed,
// or claimed rows whose lease has expired — in one atomic transaction.
// Claiming increments both claim_token (fencing every prior lease holder
// out) and attempt_count. Rows are claimed and returned in a deterministic
// order: retry_at (nulls last, i.e. behind pending's receipt time), then
// delivery receipt time, then delivery ID. Claiming never calls outbound
// code; callers apply the claimed work only after this transaction commits.
func (s *Store) ClaimAlertDispatches(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]AlertDispatch, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: dispatch claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim alert dispatches: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?,
		    claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE delivery_id IN (
			SELECT d.delivery_id
			FROM alert_delivery_dispatches AS d
			JOIN alert_deliveries AS ad ON ad.id = d.delivery_id
			WHERE (d.status = 'pending' AND (d.retry_at IS NULL OR d.retry_at <= ?))
			   OR (d.status = 'claimed' AND d.lease_expires_at IS NOT NULL AND d.lease_expires_at <= ?)
			ORDER BY COALESCE(d.retry_at, ad.received_at) ASC, ad.received_at ASC, d.delivery_id ASC
			LIMIT ?
		)
		RETURNING delivery_id
	`, owner, leaseExpires, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim alert dispatches: %w", err)
	}
	claimedIDs, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatch ids: %w", err)
	}
	if len(claimedIDs) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty alert dispatch claim: %w", err)
		}
		return []AlertDispatch{}, nil
	}

	out, err := loadClaimedDispatchesTx(ctx, tx, claimedIDs, owner)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim alert dispatches: %w", err)
	}
	return out, nil
}

// scanStringRows drains rows into a []string and always closes rows, even on
// a scan error, so the caller's connection is never left with an open
// result set blocking the next statement on the same transaction.
func scanStringRows(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// loadClaimedDispatchesTx re-reads the just-claimed rows in the same
// deterministic order ClaimAlertDispatches claimed them in. A bare
// UPDATE ... RETURNING does not guarantee it preserves the subquery's
// ORDER BY, so this issues one more SELECT with an explicit ORDER BY of its
// own — using retry_at/received_at/delivery_id, which the claiming UPDATE
// never touches, so they still reflect the pre-claim ordering.
func loadClaimedDispatchesTx(ctx context.Context, tx *sql.Tx, ids []string, owner string) ([]AlertDispatch, error) {
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, owner)
	query := dispatchSelect + ` WHERE d.delivery_id IN (` + strings.Join(placeholders, ",") +
		`) AND d.status = 'claimed' AND d.lease_owner = ?
		ORDER BY COALESCE(d.retry_at, ad.received_at) ASC, ad.received_at ASC, d.delivery_id ASC`

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed alert dispatches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]AlertDispatch, 0, len(ids))
	for rows.Next() {
		d, err := scanDispatch(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan claimed alert dispatch: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed alert dispatches: %w", err)
	}
	return out, nil
}

// errorClassPattern is the stable-lowercase-identifier contract for
// last_error_class: lowercase letters, digits, and underscores, starting
// with a letter. It exists to keep this column a closed-vocabulary-shaped
// classification, never a place a raw error message (which could embed a
// URL, header value, or other sensitive/verbose text) can land.
var errorClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// maxErrorClassLength bounds last_error_class well below anything a raw
// error message would need, so an oversized value is rejected rather than
// silently truncated.
const maxErrorClassLength = 64

// validateErrorClass enforces that class is a stable lowercase identifier
// (e.g. "transient", "rate_limited"), never raw error text. It never
// sanitizes or truncates — a non-conforming class is a validation error,
// not something this function repairs.
func validateErrorClass(class string) error {
	if class == "" {
		return errors.New("store: alert dispatch error class is required")
	}
	if len(class) > maxErrorClassLength {
		return fmt.Errorf("store: alert dispatch error class exceeds %d characters", maxErrorClassLength)
	}
	if !errorClassPattern.MatchString(class) {
		return errors.New("store: alert dispatch error class must be a lowercase identifier (e.g. \"transient\"), not raw error text")
	}
	return nil
}

// RetryAlertDispatch releases a claimed dispatch back to "pending" for a
// future retry, or marks it terminally "failed" when terminal is true. The
// update is fenced on (delivery_id, status='claimed', lease_owner,
// claim_token) all at once: if any of those has moved on since claim was
// issued, exactly zero rows change and this returns
// ErrAlertDispatchLeaseLost instead of silently doing nothing.
func (s *Store) RetryAlertDispatch(ctx context.Context, claim AlertDispatch, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(claim.Delivery.ID) == "" || claim.LeaseOwner == nil || strings.TrimSpace(*claim.LeaseOwner) == "" ||
		claim.ClaimToken <= 0 {
		return errors.New("store: alert dispatch retry requires a complete claim")
	}
	if err := validateErrorClass(class); err != nil {
		return err
	}
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status, retry = "failed", nil
	} else if retryAt.IsZero() {
		return errors.New("store: alert dispatch retry time is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status=?, lease_owner=NULL, lease_expires_at=NULL,
		    last_error_class=?, retry_at=?
		WHERE delivery_id=? AND status='claimed' AND lease_owner=? AND claim_token=?`,
		status, class, retry, claim.Delivery.ID, *claim.LeaseOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: retry alert dispatch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried alert dispatch: %w", err)
	}
	if n != 1 {
		return ErrAlertDispatchLeaseLost
	}
	return nil
}

const deliverySelect = `
SELECT ad.id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest,
       ad.source_signal_id, ad.source_signal_version, ad.generator_url, ad.acquisition_mode, ad.poll_interval_seconds,
       ad.received_at, a.fingerprint
FROM alert_deliveries ad JOIN alerts a ON a.id = ad.alert_id`

const dispatchSelect = `
SELECT d.delivery_id, ad.alert_id, ad.source, ad.source_event_id, ad.source_episode_key, ad.status,
       ad.labels_json, ad.annotations_json, ad.starts_at, ad.ends_at, ad.source_started_at, ad.source_resolved_at,
       ad.started_at_basis, ad.resolved_at_basis, ad.receiver_grouping_identity, ad.payload_digest,
       ad.source_signal_id, ad.source_signal_version, ad.generator_url, ad.acquisition_mode, ad.poll_interval_seconds,
       ad.received_at, a.fingerprint,
       d.status, d.lease_owner, d.lease_expires_at, d.claim_token, d.attempt_count, d.last_error_class, d.retry_at, d.applied_at
FROM alert_delivery_dispatches d
JOIN alert_deliveries ad ON ad.id = d.delivery_id
JOIN alerts a ON a.id = ad.alert_id`

func getDeliveryTx(ctx context.Context, tx *sql.Tx, id string) (AlertDelivery, error) {
	row := tx.QueryRowContext(ctx, deliverySelect+` WHERE ad.id = ?`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertDelivery{}, ErrNotFound
	}
	if err != nil {
		return AlertDelivery{}, fmt.Errorf("store: read delivery: %w", err)
	}
	return d, nil
}

// rawDeliveryFields holds the string-typed columns shared by deliverySelect
// and dispatchSelect, scanned before being parsed/typed by hydrateDelivery.
type rawDeliveryFields struct {
	sourceEvent, alertEnds, sourceStarted, sourceResolved, signalID, signalVersion sql.NullString
	status, labels, annotations, startsAt, startedBasis, resolvedBasis             string
	generatorURL, acquisitionMode, receivedAt                                      string
	pollInterval                                                                   int
}

// deliveryScanDest returns the Scan destinations for the deliverySelect
// column list (and the shared prefix of dispatchSelect), writing directly
// into dest and r.
func deliveryScanDest(dest *AlertDelivery, r *rawDeliveryFields) []any {
	return []any{
		&dest.ID, &dest.Alert.ID, &dest.Source, &r.sourceEvent, &dest.SourceEpisodeKey, &r.status,
		&r.labels, &r.annotations, &r.startsAt, &r.alertEnds, &r.sourceStarted, &r.sourceResolved,
		&r.startedBasis, &r.resolvedBasis, &dest.ReceiverGroupingIdentity, &dest.PayloadDigest,
		&r.signalID, &r.signalVersion, &r.generatorURL, &r.acquisitionMode, &r.pollInterval,
		&r.receivedAt, &dest.Alert.Fingerprint,
	}
}

func hydrateDelivery(d *AlertDelivery, r rawDeliveryFields) error {
	if err := json.Unmarshal([]byte(r.labels), &d.Alert.Labels); err != nil {
		return fmt.Errorf("store: unmarshal delivery labels: %w", err)
	}
	if err := json.Unmarshal([]byte(r.annotations), &d.Alert.Annotations); err != nil {
		return fmt.Errorf("store: unmarshal delivery annotations: %w", err)
	}
	startsAt, err := time.Parse(time.RFC3339Nano, r.startsAt)
	if err != nil {
		return fmt.Errorf("store: parse delivery alert starts at: %w", err)
	}
	d.Alert.StartsAt = startsAt
	if d.Alert.EndsAt, err = timePtr(r.alertEnds); err != nil {
		return err
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, r.receivedAt)
	if err != nil {
		return fmt.Errorf("store: parse delivery received at: %w", err)
	}
	d.Alert.ReceivedAt = receivedAt
	d.ReceivedAt = receivedAt
	d.Alert.Status = r.status
	d.Alert.ReceiverGroupingIdentity = d.ReceiverGroupingIdentity
	d.SourceEventID = stringPtr(r.sourceEvent)
	if d.SourceStartedAt, err = timePtr(r.sourceStarted); err != nil {
		return err
	}
	if d.SourceResolvedAt, err = timePtr(r.sourceResolved); err != nil {
		return err
	}
	d.StartedAtBasis = situationmodel.SourceTimeBasis(r.startedBasis)
	d.ResolvedAtBasis = situationmodel.SourceTimeBasis(r.resolvedBasis)
	d.SourceProvenance = SourceProvenance{
		SignalID:            stringPtr(r.signalID),
		SignalVersion:       stringPtr(r.signalVersion),
		GeneratorURL:        r.generatorURL,
		AcquisitionMode:     SourceAcquisitionMode(r.acquisitionMode),
		PollIntervalSeconds: r.pollInterval,
	}
	return nil
}

func scanDelivery(s scanner) (AlertDelivery, error) {
	var d AlertDelivery
	var r rawDeliveryFields
	if err := s.Scan(deliveryScanDest(&d, &r)...); err != nil {
		return AlertDelivery{}, err
	}
	if err := hydrateDelivery(&d, r); err != nil {
		return AlertDelivery{}, err
	}
	return d, nil
}

func scanDispatch(s scanner) (AlertDispatch, error) {
	var disp AlertDispatch
	var r rawDeliveryFields
	var dispatchStatus string
	var leaseOwner, leaseExpires, lastClass, retryAt, appliedAt sql.NullString

	dest := deliveryScanDest(&disp.Delivery, &r)
	dest = append(dest, &dispatchStatus, &leaseOwner, &leaseExpires, &disp.ClaimToken, &disp.AttemptCount, &lastClass, &retryAt, &appliedAt)
	if err := s.Scan(dest...); err != nil {
		return AlertDispatch{}, err
	}
	if err := hydrateDelivery(&disp.Delivery, r); err != nil {
		return AlertDispatch{}, err
	}
	disp.Status = dispatchStatus
	disp.LeaseOwner = stringPtr(leaseOwner)
	disp.LastErrorClass = stringPtr(lastClass)
	var err error
	if disp.LeaseExpiresAt, err = timePtr(leaseExpires); err != nil {
		return AlertDispatch{}, err
	}
	if disp.RetryAt, err = timePtr(retryAt); err != nil {
		return AlertDispatch{}, err
	}
	if disp.AppliedAt, err = timePtr(appliedAt); err != nil {
		return AlertDispatch{}, err
	}
	return disp, nil
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
		return nil, nil //nolint:nilnil // a NULL column is a nil time, not an error; callers branch on nil
	}
	out, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil, fmt.Errorf("store: parse delivery time: %w", err)
	}
	return &out, nil
}
