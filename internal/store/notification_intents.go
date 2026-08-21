// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ErrNotificationNotPending means the notification intent is no longer in a
// state that can be claimed, delivered, withheld, or retried — most likely
// because it was already terminally resolved by an earlier call.
var ErrNotificationNotPending = errors.New("store: notification intent is not pending")

// HasRootCreateIntent reports whether situationID already owns a
// situation_root_create notification intent, in any status. "One Situation
// owns one root" holds regardless of delivery state: a still-pending
// root-create already reserves the Situation's one root, so a caller
// planning notifications must treat it exactly like a delivered one and
// never propose a second root-create. This mirrors the DB's own
// notification_intents_one_root_create_idx partial unique index (belt and
// braces: the planner is expected to check first, the index is what makes a
// planner bug fail loudly instead of silently).
func (s *Store) HasRootCreateIntent(ctx context.Context, situationID string) (bool, error) {
	if strings.TrimSpace(situationID) == "" {
		return false, errors.New("store: root-create existence check requires a situation id")
	}
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM notification_intents WHERE situation_id = ? AND kind = 'situation_root_create'
	)`, situationID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: check existing root-create intent: %w", err)
	}
	return exists == 1, nil
}

// CreateNotificationIntent persists one intended outward Slack effect before
// any I/O — the durable guarantee every notification delivery relies on. It
// is idempotent on idempotency_key: a retry that recomputes the identical
// intent succeeds silently; a retry whose content differs under the same
// idempotency_key fails closed rather than silently redefining what was
// promised.
//
// This opens its own transaction, so it is the right call for a
// notification intent that has no atomicity requirement with anything
// else (an envelope review, a dependency-health update). A notification
// intent that must commit atomically with the authoritative transition
// that requires it (a Situation root create/edit/broadcast/thread reply)
// goes through CommitSituationTransition's own intents parameter instead —
// see createNotificationIntentTx.
func (s *Store) CreateNotificationIntent(ctx context.Context, in situationmodel.NotificationIntent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin create notification intent: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := createNotificationIntentTx(ctx, tx, in); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit create notification intent: %w", err)
	}
	return nil
}

// createNotificationIntentTx is the tx-scoped intent-creation primitive:
// insert-or-idempotent-replay against an already-open transaction, so a
// caller that also needs to mutate other rows in the same commit (namely
// CommitSituationTransition, persisting a Situation's required notification
// intents atomically with its Assessment/lifecycle transition, per the D3
// durability guarantee: an outward effect is durably recorded before any
// I/O ever attempts it) gets exactly one commit or rollback for both.
func createNotificationIntentTx(ctx context.Context, tx *sql.Tx, in situationmodel.NotificationIntent) error {
	prepared, err := prepareNotificationIntent(in)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO notification_intents (
		id, idempotency_key, subject_kind, subject_id, situation_id, transition_id, kind,
		main_channel_poke, interruption_priority, status, channel, message_ts, client_msg_id,
		attempt_count, last_error_class, retry_at, created_at, delivered_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(idempotency_key) DO NOTHING`,
		prepared.id, prepared.idempotencyKey, prepared.subjectKind, prepared.subjectID, prepared.situationID, prepared.transitionID,
		prepared.kind, prepared.mainChannelPoke, prepared.interruptionPriority, prepared.status, prepared.channel, prepared.messageTS,
		prepared.clientMsgID, prepared.attemptCount, prepared.lastErrorClass, prepared.retryAt, prepared.createdAt, prepared.deliveredAt)
	if err != nil {
		return fmt.Errorf("store: create notification intent: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count created notification intent: %w", err)
	}
	if changed == 0 {
		existing, err := readPreparedNotificationIntentByKey(ctx, tx, prepared.idempotencyKey)
		if err != nil {
			return err
		}
		if !equalPreparedNotificationIntentIdentity(existing, prepared) {
			return errors.New("store: notification intent identity collision")
		}
	}
	return nil
}

const notificationIntentColumns = `
	id, idempotency_key, subject_kind, subject_id, situation_id, transition_id, kind,
	main_channel_poke, interruption_priority, status, channel, message_ts, client_msg_id,
	attempt_count, last_error_class, retry_at, created_at, delivered_at`

// ClaimNotificationIntents leases due pending intents for delivery. Claiming
// never introduces a new status: the schema's status ladder is exactly
// pending | delivered | failed | withheld_by_operator_slack_floor, so a
// claim instead advances retry_at to the lease deadline while the row stays
// pending — a conditional `retry_at <= now` update, mirroring an SQS-style
// visibility timeout. An abandoned claim (a crash before delivery) is
// therefore naturally reclaimable the moment its lease deadline passes,
// with no separate lease-recovery sweep required.
func (s *Store) ClaimNotificationIntents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]situationmodel.NotificationIntent, error) {
	if lease <= 0 || limit <= 0 {
		return nil, errors.New("store: notification intent claim requires a positive lease and limit")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim notification intents: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		UPDATE notification_intents
		SET retry_at = ?
		WHERE id IN (
			SELECT id FROM notification_intents
			WHERE status = 'pending' AND (retry_at IS NULL OR retry_at <= ?)
			ORDER BY main_channel_poke DESC, created_at ASC, id ASC
			LIMIT ?
		)
		RETURNING id`, canonicalTime(now.Add(lease)), canonicalTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim notification intents: %w", err)
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan claimed notification intent id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store: iterate claimed notification intent ids: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: close claimed notification intent ids: %w", err)
	}
	out := make([]situationmodel.NotificationIntent, 0, len(ids))
	for _, id := range ids {
		intent, err := readNotificationIntent(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, intent)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit notification intent claims: %w", err)
	}
	return out, nil
}

// MarkNotificationDelivered records a successful outward effect. It also
// stamps the durable subject row's own Slack coordinates the first time a
// surface is minted (a new Situation root, a new dependency-health root, or
// an envelope review), so a later edit targets the exact persisted
// channel/message rather than re-deriving it. Re-delivering the same intent
// with the same coordinates (an at-least-once retry after a durable ack was
// lost) is accepted idempotently; a mismatched replay fails closed.
func (s *Store) MarkNotificationDelivered(ctx context.Context, id, channel, messageTS string, deliveredAt time.Time) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(channel) == "" || strings.TrimSpace(messageTS) == "" || deliveredAt.IsZero() {
		return errors.New("store: marking a notification delivered requires id, channel, message ts, and a delivery time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mark notification delivered: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status, kind, subjectID string
	var existingChannel, existingTS sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT status, kind, subject_id, channel, message_ts FROM notification_intents WHERE id = ?`, id).
		Scan(&status, &kind, &subjectID, &existingChannel, &existingTS)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: read notification intent for delivery: %w", err)
	}
	if status == "delivered" {
		if existingChannel.String == channel && existingTS.String == messageTS {
			return tx.Commit()
		}
		return errors.New("store: notification intent already delivered with different coordinates")
	}
	if status != "pending" {
		return ErrNotificationNotPending
	}

	res, err := tx.ExecContext(ctx, `UPDATE notification_intents
		SET status = 'delivered', channel = ?, message_ts = ?, delivered_at = ?, retry_at = NULL
		WHERE id = ? AND status = 'pending'`,
		channel, messageTS, canonicalTime(deliveredAt), id)
	if err != nil {
		return fmt.Errorf("store: mark notification delivered: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count marked notification delivery: %w", err)
	}
	if changed != 1 {
		return ErrNotificationNotPending
	}

	switch situationmodel.NotificationKind(kind) {
	case situationmodel.NotificationSituationRootCreate:
		if _, err := tx.ExecContext(ctx, `UPDATE situations SET slack_channel = COALESCE(slack_channel, ?), slack_root_ts = COALESCE(slack_root_ts, ?) WHERE id = ?`,
			channel, messageTS, subjectID); err != nil {
			return fmt.Errorf("store: stamp situation root coordinates: %w", err)
		}
	case situationmodel.NotificationHealthRoot:
		if _, err := tx.ExecContext(ctx, `UPDATE dependency_health SET slack_channel = ?, slack_message_ts = ?, last_broadcast_at = ?, updated_at = ? WHERE dependency = ?`,
			channel, messageTS, canonicalTime(deliveredAt), canonicalTime(deliveredAt), subjectID); err != nil {
			return fmt.Errorf("store: stamp dependency health coordinates: %w", err)
		}
	case situationmodel.NotificationHealthUpdate:
		if _, err := tx.ExecContext(ctx, `UPDATE dependency_health SET last_broadcast_at = ?, updated_at = ? WHERE dependency = ?`,
			canonicalTime(deliveredAt), canonicalTime(deliveredAt), subjectID); err != nil {
			return fmt.Errorf("store: stamp dependency health broadcast time: %w", err)
		}
	case situationmodel.NotificationEnvelopeReview:
		if _, err := tx.ExecContext(ctx, `UPDATE expected_behavior_envelopes SET slack_channel = ?, slack_message_ts = ?, last_review_prompt_at = ?, updated_at = ? WHERE id = ?`,
			channel, messageTS, canonicalTime(deliveredAt), canonicalTime(deliveredAt), subjectID); err != nil {
			return fmt.Errorf("store: stamp envelope review coordinates: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit mark notification delivered: %w", err)
	}
	return nil
}

// MarkNotificationWithheld persists withheld_by_operator_slack_floor for a
// main-channel poke the outward min_severity floor blocked. It never touches
// Assessment/Situation state — the floor is purely an outward Slack gate.
func (s *Store) MarkNotificationWithheld(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("store: withholding a notification requires an id")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE notification_intents
		SET status = 'withheld_by_operator_slack_floor', retry_at = NULL
		WHERE id = ? AND status = 'pending' AND main_channel_poke = 1`, id)
	if err != nil {
		return fmt.Errorf("store: mark notification withheld: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count withheld notification: %w", err)
	}
	if changed != 1 {
		return ErrNotificationNotPending
	}
	return nil
}

// RetryNotificationIntent releases a claimed intent for a later retry, or
// records a terminal local dead letter. It performs no outbound work itself.
func (s *Store) RetryNotificationIntent(ctx context.Context, id, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(class) == "" {
		return errors.New("store: notification intent retry requires an id and error class")
	}
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status = "failed"
		retry = nil
	} else if retryAt.IsZero() {
		return errors.New("store: notification intent retry time is required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE notification_intents
		SET status = ?, last_error_class = ?, retry_at = ?, attempt_count = attempt_count + 1
		WHERE id = ? AND status = 'pending'`,
		status, class, retry, id)
	if err != nil {
		return fmt.Errorf("store: retry notification intent: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried notification intent: %w", err)
	}
	if changed != 1 {
		return ErrNotificationNotPending
	}
	return nil
}

type preparedNotificationIntent struct {
	id, idempotencyKey, subjectKind, subjectID, kind, status, clientMsgID, createdAt string
	situationID, transitionID, interruptionPriority, channel, messageTS              any
	lastErrorClass, retryAt, deliveredAt                                             any
	mainChannelPoke, attemptCount                                                    int
}

func prepareNotificationIntent(in situationmodel.NotificationIntent) (preparedNotificationIntent, error) {
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.IdempotencyKey) == "" || strings.TrimSpace(in.SubjectID) == "" ||
		strings.TrimSpace(in.ClientMessageID) == "" || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC {
		return preparedNotificationIntent{}, errors.New("store: notification intent requires identity, client message id, and a canonical creation time")
	}
	if !validNotificationSubjectKind(in.SubjectKind) {
		return preparedNotificationIntent{}, fmt.Errorf("store: notification subject kind %q is invalid", in.SubjectKind)
	}
	if !validNotificationKind(in.Kind) {
		return preparedNotificationIntent{}, fmt.Errorf("store: notification kind %q is invalid", in.Kind)
	}
	if !notificationKindMatchesSubject(in.Kind, in.SubjectKind) {
		return preparedNotificationIntent{}, fmt.Errorf("store: notification kind %q does not match subject kind %q", in.Kind, in.SubjectKind)
	}
	if (in.SubjectKind == situationmodel.NotificationSubjectSituation) != (in.SituationID != nil && strings.TrimSpace(*in.SituationID) != "") {
		return preparedNotificationIntent{}, errors.New("store: situation notification intents require situation_id; health/envelope intents forbid it")
	}
	if !validNotificationStatus(in.Status) {
		return preparedNotificationIntent{}, fmt.Errorf("store: notification status %q is invalid", in.Status)
	}
	if in.MainChannelPoke != (in.InterruptionPriority != nil) {
		return preparedNotificationIntent{}, errors.New("store: main-channel pokes require an interruption priority; non-pokes must leave it unset")
	}
	if in.InterruptionPriority != nil && !validInterruptionPriority(*in.InterruptionPriority) {
		return preparedNotificationIntent{}, fmt.Errorf("store: interruption priority %q is invalid", *in.InterruptionPriority)
	}
	if in.Status == situationmodel.NotificationWithheldByOperatorSlackFloor && !in.MainChannelPoke {
		return preparedNotificationIntent{}, errors.New("store: only a main-channel poke can be withheld by the operator slack floor")
	}
	if in.Status == situationmodel.NotificationDelivered && in.DeliveredAt == nil {
		return preparedNotificationIntent{}, errors.New("store: a delivered notification intent requires a delivery time")
	}
	prepared := preparedNotificationIntent{
		id: in.ID, idempotencyKey: in.IdempotencyKey, subjectKind: string(in.SubjectKind), subjectID: in.SubjectID,
		kind: string(in.Kind), status: string(in.Status), clientMsgID: in.ClientMessageID,
		mainChannelPoke: boolInt(in.MainChannelPoke), attemptCount: in.AttemptCount, createdAt: canonicalTime(in.CreatedAt),
	}
	if in.SituationID != nil {
		prepared.situationID = *in.SituationID
	}
	if in.TransitionID != nil {
		prepared.transitionID = *in.TransitionID
	}
	if in.InterruptionPriority != nil {
		prepared.interruptionPriority = string(*in.InterruptionPriority)
	}
	if in.Channel != nil {
		prepared.channel = *in.Channel
	}
	if in.MessageTS != nil {
		prepared.messageTS = *in.MessageTS
	}
	if in.LastErrorClass != nil {
		prepared.lastErrorClass = *in.LastErrorClass
	}
	if in.RetryAt != nil {
		prepared.retryAt = canonicalTime(*in.RetryAt)
	}
	if in.DeliveredAt != nil {
		prepared.deliveredAt = canonicalTime(*in.DeliveredAt)
	}
	return prepared, nil
}

func readNotificationIntent(ctx context.Context, q queryRower, id string) (situationmodel.NotificationIntent, error) {
	return scanNotificationIntent(q.QueryRowContext(ctx, `SELECT `+notificationIntentColumns+` FROM notification_intents WHERE id = ?`, id))
}

func readPreparedNotificationIntentByKey(ctx context.Context, q queryRower, idempotencyKey string) (preparedNotificationIntent, error) {
	intent, err := scanNotificationIntent(q.QueryRowContext(ctx, `SELECT `+notificationIntentColumns+` FROM notification_intents WHERE idempotency_key = ?`, idempotencyKey))
	if err != nil {
		return preparedNotificationIntent{}, fmt.Errorf("store: read replayed notification intent: %w", err)
	}
	return prepareNotificationIntent(intent)
}

func scanNotificationIntent(row rowScanner) (situationmodel.NotificationIntent, error) {
	var out situationmodel.NotificationIntent
	var situationID, transitionID, priority, channel, messageTS, lastErrorClass, retryAt, deliveredAt sql.NullString
	var mainChannelPoke int
	var subjectKind, kind, status, createdAt string
	err := row.Scan(&out.ID, &out.IdempotencyKey, &subjectKind, &out.SubjectID, &situationID, &transitionID, &kind,
		&mainChannelPoke, &priority, &status, &channel, &messageTS, &out.ClientMessageID,
		&out.AttemptCount, &lastErrorClass, &retryAt, &createdAt, &deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.NotificationIntent{}, ErrNotFound
	}
	if err != nil {
		return situationmodel.NotificationIntent{}, fmt.Errorf("store: scan notification intent: %w", err)
	}
	out.SubjectKind = situationmodel.NotificationSubjectKind(subjectKind)
	out.Kind = situationmodel.NotificationKind(kind)
	out.Status = situationmodel.NotificationStatus(status)
	out.MainChannelPoke = mainChannelPoke != 0
	out.SituationID = nullStringPtr(situationID)
	out.TransitionID = nullStringPtr(transitionID)
	if priority.Valid {
		p := situationmodel.InterruptionPriority(priority.String)
		out.InterruptionPriority = &p
	}
	out.Channel = nullStringPtr(channel)
	out.MessageTS = nullStringPtr(messageTS)
	out.LastErrorClass = nullStringPtr(lastErrorClass)
	if out.CreatedAt, err = parseSituationTime("notification created_at", createdAt); err != nil {
		return situationmodel.NotificationIntent{}, err
	}
	if out.RetryAt, err = parseNullableSituationTime("notification retry_at", retryAt); err != nil {
		return situationmodel.NotificationIntent{}, err
	}
	if out.DeliveredAt, err = parseNullableSituationTime("notification delivered_at", deliveredAt); err != nil {
		return situationmodel.NotificationIntent{}, err
	}
	return out, nil
}

func equalPreparedNotificationIntentIdentity(existing, wanted preparedNotificationIntent) bool {
	return existing.idempotencyKey == wanted.idempotencyKey && existing.subjectKind == wanted.subjectKind &&
		existing.subjectID == wanted.subjectID && existing.kind == wanted.kind &&
		existing.mainChannelPoke == wanted.mainChannelPoke && existing.interruptionPriority == wanted.interruptionPriority &&
		anyEqual(existing.situationID, wanted.situationID)
}

func anyEqual(left, right any) bool {
	leftText, leftOK := left.(string)
	rightText, rightOK := right.(string)
	return leftOK == rightOK && (!leftOK || leftText == rightText)
}

func validNotificationSubjectKind(v situationmodel.NotificationSubjectKind) bool {
	switch v {
	case situationmodel.NotificationSubjectSituation, situationmodel.NotificationSubjectDependencyHealth, situationmodel.NotificationSubjectEnvelope:
		return true
	default:
		return false
	}
}

func validNotificationKind(v situationmodel.NotificationKind) bool {
	switch v {
	case situationmodel.NotificationSituationRootCreate, situationmodel.NotificationSituationRootEdit,
		situationmodel.NotificationSituationThreadReply, situationmodel.NotificationSituationBroadcastReply,
		situationmodel.NotificationHealthRoot, situationmodel.NotificationHealthUpdate, situationmodel.NotificationEnvelopeReview:
		return true
	default:
		return false
	}
}

func notificationKindMatchesSubject(kind situationmodel.NotificationKind, subject situationmodel.NotificationSubjectKind) bool {
	switch kind {
	case situationmodel.NotificationSituationRootCreate, situationmodel.NotificationSituationRootEdit,
		situationmodel.NotificationSituationThreadReply, situationmodel.NotificationSituationBroadcastReply:
		return subject == situationmodel.NotificationSubjectSituation
	case situationmodel.NotificationHealthRoot, situationmodel.NotificationHealthUpdate:
		return subject == situationmodel.NotificationSubjectDependencyHealth
	case situationmodel.NotificationEnvelopeReview:
		return subject == situationmodel.NotificationSubjectEnvelope
	default:
		return false
	}
}

func validNotificationStatus(v situationmodel.NotificationStatus) bool {
	switch v {
	case situationmodel.NotificationPending, situationmodel.NotificationDelivered, situationmodel.NotificationFailed, situationmodel.NotificationWithheldByOperatorSlackFloor:
		return true
	default:
		return false
	}
}

func validInterruptionPriority(v situationmodel.InterruptionPriority) bool {
	switch v {
	case situationmodel.PriorityLow, situationmodel.PriorityMedium, situationmodel.PriorityHigh, situationmodel.PriorityCritical:
		return true
	default:
		return false
	}
}
