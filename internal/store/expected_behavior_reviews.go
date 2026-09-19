// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
)

// PlanExpectedBehaviorReviews idempotently creates one standalone reminder
// per active revision/cadence cycle. Review dates never change authority.
func (s *Store) PlanExpectedBehaviorReviews(ctx context.Context, now time.Time, intervalDays int) ([]situation.ExpectedBehaviorReviewIntent, error) {
	if intervalDays < 1 || intervalDays > 365 || now.IsZero() {
		return nil, errors.New("store: expected behavior review interval must be 1-365 days")
	}
	heads, err := s.ListExpectedBehaviors(ctx, ExpectedBehaviorListFilter{}, 1000)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	interval := time.Duration(intervalDays) * 24 * time.Hour
	out := make([]situation.ExpectedBehaviorReviewIntent, 0)
	for _, head := range heads {
		if head.Policy == nil || now.Before(head.Policy.ReviewDueAt) {
			continue
		}
		var lastRaw sql.NullString
		if err := s.db.QueryRowContext(ctx, `SELECT last_review_prompt_at FROM expected_behavior_envelope_heads WHERE envelope_id=?`, head.EnvelopeID).Scan(&lastRaw); err != nil {
			return nil, fmt.Errorf("store: read expected behavior review clock: %w", err)
		}
		anchor := head.Policy.ReviewDueAt.UTC()
		countSince := head.UpdatedAt.UTC()
		if lastRaw.Valid {
			last, err := time.Parse(time.RFC3339Nano, lastRaw.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse expected behavior review clock: %w", err)
			}
			if now.Before(last.Add(interval)) {
				continue
			}
			countSince = last
		}
		cycle := anchor.Add(time.Duration(int(now.Sub(anchor)/interval)) * interval)
		var matchCount int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM expected_behavior_evaluations
			WHERE chosen_envelope_id=? AND chosen_version=? AND disposition='matched' AND evaluated_at>=?`,
			head.EnvelopeID, head.Version, canonicalTime(countSince)).Scan(&matchCount); err != nil {
			return nil, fmt.Errorf("store: count expected behavior matches: %w", err)
		}
		sum := sha256.Sum256([]byte(head.EnvelopeID + "\x00" + fmt.Sprint(head.Version) + "\x00" + canonicalTime(cycle)))
		intent := situation.ExpectedBehaviorReviewIntent{
			ID: "expected-review:sha256:" + hex.EncodeToString(sum[:]), EnvelopeID: head.EnvelopeID,
			EnvelopeVersion: head.Version, CycleStartedAt: cycle, Head: head, MatchCount: matchCount,
			Status: "pending", CreatedAt: now,
		}
		raw, err := json.Marshal(intent)
		if err != nil {
			return nil, fmt.Errorf("store: marshal expected behavior review: %w", err)
		}
		res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO expected_behavior_review_intents
			(id,envelope_id,envelope_version,cycle_started_at,payload_json,status,created_at)
			VALUES (?,?,?,?,?,'pending',?)`, intent.ID, head.EnvelopeID, head.Version,
			canonicalTime(cycle), string(raw), canonicalTime(now))
		if err != nil {
			return nil, fmt.Errorf("store: plan expected behavior review: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			out = append(out, intent)
		}
	}
	return out, nil
}

func (s *Store) RecoverExpiredExpectedBehaviorReviewClaims(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE expected_behavior_review_intents
		SET claim_owner=NULL,lease_expires_at=NULL
		WHERE status='pending' AND lease_expires_at IS NOT NULL AND lease_expires_at<=?`, canonicalTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: recover expected behavior review claims: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *Store) ClaimExpectedBehaviorReviews(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.ExpectedBehaviorReviewClaim, error) {
	if strings.TrimSpace(owner) == "" || now.IsZero() || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: expected behavior review claim requires owner, time, lease, and limit")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM expected_behavior_review_intents
		WHERE status='pending' AND (retry_at IS NULL OR retry_at<=?)
		  AND (lease_expires_at IS NULL OR lease_expires_at<=?) ORDER BY created_at,id LIMIT ?`,
		canonicalTime(now), canonicalTime(now), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	claims := make([]situation.ExpectedBehaviorReviewClaim, 0, len(ids))
	for _, id := range ids {
		res, err := tx.ExecContext(ctx, `UPDATE expected_behavior_review_intents
			SET claim_owner=?,lease_expires_at=?,claim_token=claim_token+1,attempt_count=attempt_count+1
			WHERE id=? AND status='pending' AND (lease_expires_at IS NULL OR lease_expires_at<=?)`,
			owner, canonicalTime(now.Add(lease)), id, canonicalTime(now))
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		var raw string
		var token int64
		var attempts int
		if err := tx.QueryRowContext(ctx, `SELECT payload_json,claim_token,attempt_count FROM expected_behavior_review_intents WHERE id=?`, id).Scan(&raw, &token, &attempts); err != nil {
			return nil, err
		}
		var intent situation.ExpectedBehaviorReviewIntent
		if err := json.Unmarshal([]byte(raw), &intent); err != nil {
			return nil, err
		}
		intent.AttemptCount = attempts
		claims = append(claims, situation.ExpectedBehaviorReviewClaim{Intent: intent, ClaimOwner: owner, ClaimToken: token})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *Store) MarkExpectedBehaviorReviewDelivered(ctx context.Context, claim situation.ExpectedBehaviorReviewClaim, delivery situation.NotificationDelivery, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE expected_behavior_review_intents
		SET status='delivered',delivered_at=?,channel=?,message_ts=?,claim_owner=NULL,lease_expires_at=NULL,last_error_class=NULL,retry_at=NULL
		WHERE id=? AND status='pending' AND claim_owner=? AND claim_token=?`,
		canonicalTime(now), delivery.Channel, delivery.MessageTS, claim.Intent.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return situation.ErrNotificationClaimLost
	}
	if _, err := tx.ExecContext(ctx, `UPDATE expected_behavior_envelope_heads SET last_review_prompt_at=?
		WHERE envelope_id=? AND version=?`, canonicalTime(now), claim.Intent.EnvelopeID, claim.Intent.EnvelopeVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RetryExpectedBehaviorReview(ctx context.Context, claim situation.ExpectedBehaviorReviewClaim, errorClass string, retryAt time.Time) error {
	if err := validateNotificationErrorClass(errorClass); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE expected_behavior_review_intents
		SET retry_at=?,last_error_class=?,claim_owner=NULL,lease_expires_at=NULL
		WHERE id=? AND status='pending' AND claim_owner=? AND claim_token=?`,
		canonicalTime(retryAt), errorClass, claim.Intent.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return situation.ErrNotificationClaimLost
	}
	return nil
}

func supersedeExpectedBehaviorReviewsTx(ctx context.Context, tx *sql.Tx, envelopeID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE expected_behavior_review_intents SET status='superseded',claim_owner=NULL,lease_expires_at=NULL
		WHERE envelope_id=? AND status='pending'`, envelopeID)
	return err
}
