// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 7: the fenced notification-intent claim/acknowledge surface
// migration 0018's ledger exists for. Every write here is fenced on the
// full (id, status='pending', claim_owner, claim_token) tuple at once, so a
// stale acknowledgement — an expired lease that was swept, a claim another
// worker reclaimed, or a root projection a concurrent authoritative commit
// superseded (R4) — changes exactly zero rows and says so, rather than
// silently writing a delivery outcome onto a row that has moved on.
//
// No Slack call ever happens inside these transactions: the worker
// (internal/situation/notification_worker.go) claims, calls out, and comes
// back to acknowledge.
// ----------------------------------------------------------------------

// These are situation's own sentinels rather than store-local mirrors: the
// claim contract (situation.NotificationClaim) already crosses this
// boundary in both directions, so a second vocabulary plus a translation
// adapter would only create somewhere for the two to drift apart. Mirrors
// store.ErrNotFound = situationmodel.ErrNotFound.
var (
	// ErrNotificationClaimLost is situation.ErrNotificationClaimLost.
	ErrNotificationClaimLost = situation.ErrNotificationClaimLost
	// ErrNotificationIntentSuperseded is
	// situation.ErrNotificationIntentSuperseded.
	ErrNotificationIntentSuperseded = situation.ErrNotificationIntentSuperseded
)

// ErrNewerRootProjectionPending means a root projection could not be
// returned to pending because a NEWER one already holds its Situation's
// single pending-root slot (migration 0018's
// notification_intents_root_sync_pending_idx). The newer projection renders
// the same current state, so the older one has nothing left to say — this
// is a refusal, never a constraint violation.
var ErrNewerRootProjectionPending = errors.New("store: a newer root projection is already pending")

// The claim ordering the plan names: gap generation first (the installation
// recovery notice precedes every Situation's backlog), then Situation, then
// Transition sequence, then creation identity.
//
// Effect class enters that order in exactly ONE place — the coalescible root
// projection sorts ahead of every reply (notificationRootFirst), which is the
// only class ordering the spec requires ("a root edit for a handoff delivers
// before its broadcast reply"; the root's own rank alone achieves it).
// Class must NOT outrank Transition sequence: doing so put every quiet
// thread_append ahead of every broadcast_handoff regardless of sequence, so
// an older poke could deliver after newer entries, against spec.md's
// "immutable journal replies deliver in Transition-sequence order".
// notificationClassRank therefore survives only as an intra-sequence
// tiebreak — the one case it decides is a floor-withheld poke's Transition,
// which carries both a broadcast_handoff and a quiet thread_append at the
// same sequence.
const (
	notificationRootFirst  = `(ni.effect_class <> 'root_sync')`
	notificationClassRank  = `CASE ni.effect_class WHEN 'root_sync' THEN 0 WHEN 'thread_append' THEN 1 ELSE 2 END`
	notificationQueueOrder = `root_first ASC, transition_sequence ASC, class_rank ASC, id ASC`
	notificationClaimOrder = `ORDER BY (gap_generation IS NULL) ASC, gap_generation ASC, situation_id ASC, ` + notificationQueueOrder
	// notificationReloadOrder is notificationClaimOrder expressed directly
	// against the table (alias ni), for the post-claim reload.
	notificationReloadOrder = `ORDER BY (ni.gap_generation IS NULL) ASC, ni.gap_generation ASC, ni.situation_id ASC, ` +
		notificationRootFirst + ` ASC, ni.transition_sequence ASC, ` + notificationClassRank + ` ASC, ni.id ASC`
)

// validateNotificationClaim rejects a claim that cannot fence anything.
func validateNotificationClaim(claim situation.NotificationClaim) error {
	if strings.TrimSpace(claim.Intent.ID) == "" {
		return errors.New("store: notification acknowledgement requires an intent id")
	}
	if strings.TrimSpace(claim.ClaimOwner) == "" {
		return errors.New("store: notification acknowledgement requires a claim owner")
	}
	if claim.ClaimToken <= 0 {
		return errors.New("store: notification acknowledgement requires a positive claim token")
	}
	return nil
}

// validateNotificationErrorClass enforces last_error_class's closed
// lowercase-identifier shape, exactly as the alert dispatch ledger does: it
// is a classification column, never anywhere a raw error message (which
// could embed a URL, a header value, or a provider body) can land.
func validateNotificationErrorClass(class string) error {
	if class == "" {
		return errors.New("store: notification error class is required")
	}
	if len(class) > maxErrorClassLength {
		return fmt.Errorf("store: notification error class exceeds %d characters", maxErrorClassLength)
	}
	if !errorClassPattern.MatchString(class) {
		return errors.New("store: notification error class must be a lowercase identifier (e.g. \"ratelimited\"), not raw error text")
	}
	return nil
}

// ClaimNotificationIntents leases the currently deliverable notification
// intents in one immediate transaction, newest lease wins.
//
// Deliverable means all of:
//
//   - pending, and either unclaimed or holding an expired lease;
//   - due (no retry time, or one that has passed);
//   - root-ready: a thread_append/broadcast_handoff is claimable only once
//     its Situation's root coordinates are durably published, so a reply
//     never consumes a delivery attempt waiting for a root, and a failed or
//     configuration-blocked root leaves its dependents waiting rather than
//     dead-lettering them; and
//   - the HEAD of its Situation's queue. Exactly one intent per Situation
//     is claimable at a time, ranked root projection first and then by
//     Transition SEQUENCE (effect class decides only ties within one
//     sequence), so a later immutable entry can never pass an
//     earlier pending one — including one merely waiting out a retry delay.
//
// A gap generation gates the whole claim: while one is open nothing is
// claimable at all (Slack is down and the recovery notice must precede the
// backlog), and while one is replaying only its own undelivered recovery
// notice is. A recovery notice that ends up blocked or failed therefore
// holds the backlog — deliberately, since the notice is the operator's only
// signal that the history arriving next is delayed; it is reactivated by a
// corrected configuration generation or an explicit redrive, exactly like
// any other intent.
//
// Claiming increments claim_token (fencing every prior holder out) and
// attempt_count. It calls nothing outbound.
func (s *Store) ClaimNotificationIntents(ctx context.Context, owner string, now time.Time,
	lease time.Duration, limit int) ([]situation.NotificationClaim, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: notification claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim notification intents: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	gate, err := deliveryGapGateTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if gate.blocked {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit gated notification claim: %w", err)
		}
		return []situation.NotificationClaim{}, nil
	}

	ids, err := dueNotificationIntentIDsTx(ctx, tx, gate, nowStr, limit)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty notification claim: %w", err)
		}
		return []situation.NotificationClaim{}, nil
	}

	placeholders, args := inPlaceholders(ids)
	updateArgs := append([]any{owner, leaseExpires}, args...)
	// #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(ids); every value is bound.
	// The annotation sits on its own line ABOVE the statement: gosec attaches
	// a #nosec comment to the node it precedes, and a trailing comment on the
	// closing line of a multi-line call is not honored.
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_intents
		SET claim_owner = ?, lease_expires_at = ?, claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE id IN (`+placeholders+`)`, updateArgs...); err != nil {
		return nil, fmt.Errorf("store: claim notification intents: %w", err)
	}

	claims, err := loadClaimedNotificationIntentsTx(ctx, tx, ids, owner)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim notification intents: %w", err)
	}
	return claims, nil
}

// deliveryGapGate is one claim round's gap decision: blocked means nothing
// is claimable; noticeIDs, when non-empty, restricts the round to exactly
// those undelivered recovery notices.
type deliveryGapGate struct {
	blocked   bool
	noticeIDs []string
}

// deliveryGapGateTx reads the gap lifecycle's effect on claimability.
func deliveryGapGateTx(ctx context.Context, tx *sql.Tx) (deliveryGapGate, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT g.status, COALESCE(g.recovery_notice_intent_id, ''), COALESCE(ni.status, '')
		FROM slack_delivery_gaps g
		LEFT JOIN notification_intents ni ON ni.id = g.recovery_notice_intent_id
		WHERE g.status IN ('open','replaying')
		ORDER BY g.opened_at ASC`)
	if err != nil {
		return deliveryGapGate{}, fmt.Errorf("store: read delivery gap gate: %w", err)
	}
	defer func() { _ = rows.Close() }()

	gate := deliveryGapGate{}
	for rows.Next() {
		var status, noticeID, noticeStatus string
		if err := rows.Scan(&status, &noticeID, &noticeStatus); err != nil {
			return deliveryGapGate{}, fmt.Errorf("store: scan delivery gap gate: %w", err)
		}
		if status == "open" {
			// Slack is down and the ADR-0042 notice has to precede the
			// backlog, so no effect is claimable at all until a readiness
			// probe recovers this generation.
			return deliveryGapGate{blocked: true}, nil
		}
		if noticeID != "" && noticeStatus != string(situationmodel.IntentDelivered) {
			gate.noticeIDs = append(gate.noticeIDs, noticeID)
		}
	}
	if err := rows.Err(); err != nil {
		return deliveryGapGate{}, fmt.Errorf("store: iterate delivery gap gate: %w", err)
	}
	return gate, nil
}

// dueNotificationIntentIDsTx selects the ids this round may claim, in
// notificationClaimOrder.
func dueNotificationIntentIDsTx(ctx context.Context, tx *sql.Tx, gate deliveryGapGate,
	nowStr string, limit int) ([]string, error) {
	if len(gate.noticeIDs) > 0 {
		placeholders, args := inPlaceholders(gate.noticeIDs)
		args = append(args, nowStr, nowStr, limit)
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM notification_intents
			WHERE id IN (`+placeholders+`) AND status = 'pending'
			  AND (claim_owner IS NULL OR lease_expires_at <= ?)
			  AND (retry_at IS NULL OR retry_at <= ?)
			ORDER BY created_at ASC, id ASC
			LIMIT ?`, args...) // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(noticeIDs); every value is bound
		if err != nil {
			return nil, fmt.Errorf("store: select due recovery notice: %w", err)
		}
		ids, err := scanStringRows(rows)
		if err != nil {
			return nil, fmt.Errorf("store: read due recovery notice ids: %w", err)
		}
		return ids, nil
	}

	rows, err := tx.QueryContext(ctx, `
		WITH ranked AS (
			SELECT ni.id AS id,
			       ni.gap_generation AS gap_generation,
			       ni.situation_id AS situation_id,
			       ni.transition_sequence AS transition_sequence,
			       `+notificationRootFirst+` AS root_first,
			       `+notificationClassRank+` AS class_rank,
			       (ni.claim_owner IS NULL OR ni.lease_expires_at <= ?) AS unleased,
			       (ni.retry_at IS NULL OR ni.retry_at <= ?) AS due,
			       (ni.requires_root = 0 OR (s.slack_channel IS NOT NULL AND s.slack_root_ts IS NOT NULL)) AS root_ready,
			       ROW_NUMBER() OVER (
			           PARTITION BY ni.situation_id
			           ORDER BY `+notificationRootFirst+` ASC, ni.transition_sequence ASC, `+notificationClassRank+` ASC, ni.id ASC
			       ) AS rn
			FROM notification_intents ni
			LEFT JOIN situations s ON s.id = ni.situation_id
			WHERE ni.status = 'pending'
		)
		SELECT id FROM ranked
		WHERE (situation_id IS NULL OR rn = 1) AND unleased AND due AND root_ready
		`+notificationClaimOrder+`
		LIMIT ?`, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: select due notification intents: %w", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read due notification intent ids: %w", err)
	}
	return ids, nil
}

// loadClaimedNotificationIntentsTx re-reads the just-claimed rows in the
// same deterministic order they were selected in. A bare UPDATE ...
// RETURNING does not guarantee it preserves the subquery's ORDER BY, and
// every column this orders by is one claiming never touches.
func loadClaimedNotificationIntentsTx(ctx context.Context, tx *sql.Tx, ids []string,
	owner string) ([]situation.NotificationClaim, error) {
	placeholders, args := inPlaceholders(ids)
	args = append(args, owner)
	query := `
		SELECT ` + qualifyColumns(notificationIntentColumns, "ni") + `
		FROM notification_intents ni
		WHERE ni.id IN (` + placeholders + `) AND ni.claim_owner = ?
		` + notificationReloadOrder // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(ids); every value is bound
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read claimed notification intents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]situation.NotificationClaim, 0, len(ids))
	for rows.Next() {
		intent, err := scanNotificationIntent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan claimed notification intent: %w", err)
		}
		out = append(out, situation.NotificationClaim{Intent: intent, ClaimOwner: owner, ClaimToken: intent.ClaimToken})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed notification intents: %w", err)
	}
	return out, nil
}

// inPlaceholders builds a "?,?,..." run of len(values) and the matching
// bound argument slice.
func inPlaceholders(values []string) (string, []any) {
	parts := make([]string, len(values))
	args := make([]any, 0, len(values))
	for i, v := range values {
		parts[i] = "?"
		args = append(args, v)
	}
	return strings.Join(parts, ","), args
}

// ----------------------------------------------------------------------
// Fenced acknowledgements.
// ----------------------------------------------------------------------

// fencedNotificationAck applies one fenced lifecycle write and resolves a
// zero-row result into the right typed reason.
func (s *Store) fencedNotificationAck(ctx context.Context, claim situation.NotificationClaim,
	setClause string, args ...any) error {
	if err := validateNotificationClaim(claim); err != nil {
		return err
	}
	args = append(args, claim.Intent.ID, claim.ClaimOwner, claim.ClaimToken)
	res, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents SET `+setClause+`
		WHERE id = ? AND status = 'pending' AND claim_owner = ? AND claim_token = ?`, args...) // #nosec G202 -- setClause is a package-local constant expression; every value is bound
	if err != nil {
		return fmt.Errorf("store: acknowledge notification intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count acknowledged notification intent: %w", err)
	}
	if n != 1 {
		return classifyLostNotificationClaim(ctx, s.db, claim.Intent.ID)
	}
	return nil
}

// rowQueryer is the subset of *sql.DB / *sql.Tx classifyLostNotificationClaim
// needs. Taking it explicitly matters: the store runs on a single pooled
// connection (SetMaxOpenConns(1)), so a caller that already holds an open
// transaction MUST classify through that transaction rather than through
// s.db, which would wait forever for a connection it is itself holding.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// classifyLostNotificationClaim explains a zero-row fenced write: a
// superseded root projection (the expected R4 race, and a status a
// delivered write could never reach anyway — migration 0018's
// supersession CHECKs forbid it) or an ordinary lost claim.
func classifyLostNotificationClaim(ctx context.Context, q rowQueryer, intentID string) error {
	var status string
	err := q.QueryRowContext(ctx, `SELECT status FROM notification_intents WHERE id = ?`, intentID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: notification intent %s: %w", intentID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("store: classify lost notification claim: %w", err)
	}
	if situationmodel.IntentStatus(status) == situationmodel.IntentSuperseded {
		return ErrNotificationIntentSuperseded
	}
	return ErrNotificationClaimLost
}

// MarkNotificationDelivered records one fenced successful delivery and, for
// a root projection only, the Situation's durable root coordinates — the
// single place slack_channel/slack_root_ts is ever written, and only when
// the matching fenced root delivery is acknowledged.
func (s *Store) MarkNotificationDelivered(ctx context.Context, claim situation.NotificationClaim,
	delivery situation.NotificationDelivery, now time.Time) error {
	if err := validateNotificationClaim(claim); err != nil {
		return err
	}
	if strings.TrimSpace(delivery.Channel) == "" || strings.TrimSpace(delivery.MessageTS) == "" {
		return errors.New("store: notification delivery requires channel and message timestamp")
	}
	switch delivery.DeliveredAs {
	case "root", "thread", "broadcast", "delayed_thread", "system":
	default:
		return fmt.Errorf("store: notification delivery mode %q is not one of root|thread|broadcast|delayed_thread|system",
			delivery.DeliveredAs)
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mark notification delivered: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE notification_intents
		SET status = 'delivered', delivered_at = ?, channel = ?, message_ts = ?, delivered_as = ?,
		    claim_owner = NULL, lease_expires_at = NULL, retry_at = NULL
		WHERE id = ? AND status = 'pending' AND claim_owner = ? AND claim_token = ?`,
		canonicalTime(now), delivery.Channel, delivery.MessageTS, delivery.DeliveredAs,
		claim.Intent.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: mark notification delivered: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count delivered notification intent: %w", err)
	}
	if n != 1 {
		return classifyLostNotificationClaim(ctx, tx, claim.Intent.ID)
	}

	// Which Situation's root this is comes from the intent ROW, never from
	// the caller's copy of it: the fence above already proved this row is
	// ours, so the row is also the authority on what it points at.
	if claim.Intent.EffectClass == situationmodel.EffectRootSync {
		if _, err := tx.ExecContext(ctx, `
			UPDATE situations SET slack_channel = ?, slack_root_ts = ?
			WHERE id = (SELECT situation_id FROM notification_intents WHERE id = ? AND effect_class = 'root_sync')`,
			delivery.Channel, delivery.MessageTS, claim.Intent.ID); err != nil {
			return fmt.Errorf("store: persist situation root coordinates: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit mark notification delivered: %w", err)
	}
	return nil
}

// RetryNotificationIntent releases a claimed intent back for a later retry.
// It keeps the intent pending and keeps its attempt count: there is no
// attempt ceiling anywhere in this lifecycle.
func (s *Store) RetryNotificationIntent(ctx context.Context, claim situation.NotificationClaim,
	class string, retryAt time.Time) error {
	if err := validateNotificationErrorClass(class); err != nil {
		return err
	}
	if retryAt.IsZero() {
		return errors.New("store: notification retry time is required")
	}
	return s.fencedNotificationAck(ctx, claim,
		`claim_owner = NULL, lease_expires_at = NULL, last_error_class = ?, retry_at = ?`,
		class, canonicalTime(retryAt))
}

// BlockNotificationConfiguration records a definite Slack configuration
// rejection. The intent stays durable with its attempts intact and no retry
// time: it waits for a corrected configuration generation, never for an
// exhausted attempt budget.
func (s *Store) BlockNotificationConfiguration(ctx context.Context, claim situation.NotificationClaim,
	class string, _ time.Time) error {
	if err := validateNotificationErrorClass(class); err != nil {
		return err
	}
	return s.fencedNotificationAck(ctx, claim,
		`status = 'blocked_configuration', claim_owner = NULL, lease_expires_at = NULL,
		 last_error_class = ?, retry_at = NULL`, class)
}

// FailNotificationIntent records the one non-recoverable outcome: an
// invalid durable intent or another programming/data error. It is
// operator-visible and explicitly redriveable, and it never cascades — a
// failed root leaves its dependents pending, not dead-lettered.
func (s *Store) FailNotificationIntent(ctx context.Context, claim situation.NotificationClaim,
	class string, _ time.Time) error {
	if err := validateNotificationErrorClass(class); err != nil {
		return err
	}
	return s.fencedNotificationAck(ctx, claim,
		`status = 'failed', claim_owner = NULL, lease_expires_at = NULL, last_error_class = ?, retry_at = NULL`,
		class)
}

// HeartbeatNotificationClaim moves a live claim's lease deadline forward
// without changing anything else about the intent.
func (s *Store) HeartbeatNotificationClaim(ctx context.Context, claim situation.NotificationClaim,
	now time.Time, lease time.Duration) error {
	if lease <= 0 {
		return errors.New("store: notification heartbeat requires a positive lease")
	}
	return s.fencedNotificationAck(ctx, claim, `lease_expires_at = ?`, canonicalTime(now.UTC().Add(lease)))
}

// ReleaseNotificationClaim hands a claim straight back, still pending and
// still due — the clean shutdown path, so a stopped worker never leaves a
// durable obligation waiting out a full lease.
func (s *Store) ReleaseNotificationClaim(ctx context.Context, claim situation.NotificationClaim, _ time.Time) error {
	return s.fencedNotificationAck(ctx, claim, `claim_owner = NULL, lease_expires_at = NULL`)
}

// RecoverExpiredNotificationClaims sweeps every claim whose lease has
// expired back to unclaimed, so a crashed worker's in-flight intents become
// claimable again. It never changes status or attempts.
func (s *Store) RecoverExpiredNotificationClaims(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE notification_intents
		SET claim_owner = NULL, lease_expires_at = NULL
		WHERE status = 'pending' AND claim_owner IS NOT NULL AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= ?`, canonicalTime(now.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: recover expired notification claims: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count recovered notification claims: %w", err)
	}
	return int(n), nil
}

// RedriveFailedNotificationIntent returns one explicitly-redriven failed
// intent to pending, due now, with its attempt count preserved. It is the
// only way out of `failed`, and the way a failed root releases the
// dependent history waiting behind it.
//
// It has NO operator-facing caller in this build, deliberately: spec.md
// specifies redrive SEMANTICS ("explicitly redriveable after the underlying
// code or data condition changes"), not a control surface, and Plan 3 adds
// no new operator write surface. Recovering a failed intent today therefore
// means direct Store access. docs/notifications/slack.md states that limit
// plainly under "Delivery: durable intent, indefinite retry, at-least-once"
// rather than leaving it as an undocumented gap; an operator command is
// follow-up work, and should land together with a real recovery for a
// hand-deleted root (a bare redrive cannot fix that case, since the stored
// root coordinates still point at the removed message).
//
// A failed ROOT projection shares reactivation's uniqueness hazard: its
// Situation may have acquired a newer pending root_sync while this one sat
// failed. When the redriven projection is the newer of the two, the pending
// one is coalesced into it exactly as a newer commit would; when it is the
// OLDER, the redrive is refused with ErrNewerRootProjectionPending — the
// newer projection already renders the same current state — rather than
// aborting on migration 0018's index.
func (s *Store) RedriveFailedNotificationIntent(ctx context.Context, intentID string, now time.Time) error {
	if strings.TrimSpace(intentID) == "" {
		return errors.New("store: notification redrive requires an intent id")
	}
	nowStr := canonicalTime(now.UTC())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin redrive failed notification intent: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var effectClass, createdAt string
	var situationID sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT effect_class, situation_id, created_at FROM notification_intents WHERE id = ? AND status = 'failed'`,
		intentID).Scan(&effectClass, &situationID, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: notification intent %s is not in failed status: %w", intentID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("store: read failed notification intent: %w", err)
	}

	if situationmodel.EffectClass(effectClass) == situationmodel.EffectRootSync && situationID.Valid {
		if err := clearPendingRootForRedriveTx(ctx, tx, situationID.String, intentID, createdAt); err != nil {
			return err
		}
	}
	if err := setNotificationIntentPendingTx(ctx, tx, intentID, "failed", nowStr); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit redrive failed notification intent: %w", err)
	}
	return nil
}

// clearPendingRootForRedriveTx frees the Situation's single pending-root slot
// for the projection being redriven, or refuses when a newer projection
// already holds it.
func clearPendingRootForRedriveTx(ctx context.Context, tx *sql.Tx, situationID, intentID, createdAt string) error {
	var pendingID, pendingCreatedAt string
	err := tx.QueryRowContext(ctx, `
		SELECT id, created_at FROM notification_intents
		WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`, situationID).
		Scan(&pendingID, &pendingCreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: read pending root projection for redrive: %w", err)
	}
	// created_at is canonical RFC3339Nano UTC, so string order is time
	// order; the id breaks a same-instant tie the same way the claim
	// ordering does.
	if pendingCreatedAt > createdAt || (pendingCreatedAt == createdAt && pendingID > intentID) {
		return ErrNewerRootProjectionPending
	}
	return supersedePendingRootSyncTx(ctx, tx, situationID, intentID)
}

// GetSituationRootCoordinates reads situationID's durable Slack root
// coordinates. ok is false when no root has been delivered yet — the
// coordinates are nullable COLUMNS on an existing row, so their absence is
// a normal state, not a missing record.
func (s *Store) GetSituationRootCoordinates(ctx context.Context, situationID string) (string, string, bool, error) {
	if strings.TrimSpace(situationID) == "" {
		return "", "", false, errors.New("store: situation root coordinates require a situation id")
	}
	var channel, ts sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT slack_channel, slack_root_ts FROM situations WHERE id = ?`, situationID).Scan(&channel, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, ErrNotFound
	}
	if err != nil {
		return "", "", false, fmt.Errorf("store: read situation root coordinates: %w", err)
	}
	if !channel.Valid || !ts.Valid {
		return "", "", false, nil
	}
	return channel.String, ts.String, true, nil
}
