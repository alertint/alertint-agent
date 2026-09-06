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

// ----------------------------------------------------------------------
// Plan 3 Task 9: the durable stdout Transition-stream outbox's claim and
// acknowledgement lifecycle (migration 0017's situation_transition_stream).
//
// Task 4/5 already insert one row per committed Transition inside the
// fenced controller commit, and Task 5's ListPendingTransitionStream reads
// the backlog. This file adds the four writes a worker needs to consume it
// exactly like every other fenced queue in this store: lease a bounded
// batch, acknowledge the real outcome under (id, lease_owner, claim_token),
// release what a shutdown was still holding, and sweep abandoned leases at
// startup.
//
// The stream is at-least-once by construction and says so: the line is
// written to stdout BEFORE the acknowledgement commits, so a crash between
// the two replays the same Transition. Consumers deduplicate by Transition
// ID (which is immutable and unique in this table). A delivered stdout line
// says nothing about Slack — that obligation lives in notification_intents.
// ----------------------------------------------------------------------

// ErrTransitionStreamClaimLost means a fenced stream acknowledgement named a
// claim that is no longer the row's current one: the lease expired and was
// swept or reclaimed, or the row was released. The write changed zero rows.
var ErrTransitionStreamClaimLost = errors.New("store: transition stream claim lost")

// TransitionStreamClaim is one leased stdout-stream row together with the
// immutable Transition it records and the fencing pair every
// acknowledgement must carry.
type TransitionStreamClaim struct {
	StreamID   string
	Transition situationmodel.Transition
	ClaimOwner string
	ClaimToken int64
}

// ClaimTransitionStream leases up to limit due, pending stream rows in one
// immediate transaction, oldest first, and returns each one joined to its
// Transition so the worker needs no second lookup. Claiming increments
// claim_token (fencing every prior holder out) and attempt_count. It calls
// nothing outbound.
//
// Unlike notification intents, stream rows are NOT gated by the Slack
// Delivery gap and are not ordered per Situation: stdout is a local pipe
// with no root dependency and no external provider, so an outage on the
// Slack side must never stop the authoritative state stream.
func (s *Store) ClaimTransitionStream(ctx context.Context, owner string, now time.Time,
	lease time.Duration, limit int) ([]TransitionStreamClaim, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: transition stream claim requires owner, positive lease, and positive limit")
	}
	if limit > maxSituationHistoryPage {
		limit = maxSituationHistoryPage
	}
	now = now.UTC()
	nowStr := canonicalTime(now)
	leaseExpires := canonicalTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim transition stream: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM situation_transition_stream
		WHERE status = 'pending'
		  AND (lease_owner IS NULL OR lease_expires_at <= ?)
		  AND (retry_at IS NULL OR retry_at <= ?)
		ORDER BY created_at ASC, situation_id ASC, sequence ASC
		LIMIT ?`, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store: read due transition stream rows: %w", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: scan due transition stream rows: %w", err)
	}
	if len(ids) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("store: commit empty transition stream claim: %w", err)
		}
		return []TransitionStreamClaim{}, nil
	}

	placeholders, args := inPlaceholders(ids)
	updateArgs := append([]any{owner, leaseExpires}, args...)
	if _, err := tx.ExecContext(ctx, `
		UPDATE situation_transition_stream
		SET lease_owner = ?, lease_expires_at = ?, claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE id IN (`+placeholders+`)`, updateArgs...); err != nil { // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(ids); every value is bound
		return nil, fmt.Errorf("store: claim transition stream rows: %w", err)
	}

	claims, err := loadClaimedTransitionStreamTx(ctx, tx, ids, owner)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit claim transition stream: %w", err)
	}
	return claims, nil
}

// loadClaimedTransitionStreamTx re-reads the just-claimed rows with their
// Transitions inside the claiming transaction, so a claim can never name a
// Transition the same read cannot see.
func loadClaimedTransitionStreamTx(ctx context.Context, tx *sql.Tx, ids []string, owner string) ([]TransitionStreamClaim, error) {
	placeholders, args := inPlaceholders(ids)
	rows, err := tx.QueryContext(ctx, `
		SELECT st.id, st.claim_token, `+prefixedTransitionColumns+`
		FROM situation_transition_stream st
		JOIN situation_transitions t ON t.id = st.transition_id
		WHERE st.id IN (`+placeholders+`)
		ORDER BY st.created_at ASC, st.situation_id ASC, st.sequence ASC`, args...) // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(ids); every value is bound
	if err != nil {
		return nil, fmt.Errorf("store: read claimed transition stream rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]TransitionStreamClaim, 0, len(ids))
	for rows.Next() {
		claim := TransitionStreamClaim{ClaimOwner: owner}
		tr, err := scanClaimedStreamEntry(rows, &claim.StreamID, &claim.ClaimToken)
		if err != nil {
			return nil, err
		}
		claim.Transition = tr
		out = append(out, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate claimed transition stream rows: %w", err)
	}
	return out, nil
}

// MarkTransitionStreamDelivered records one fenced successful stdout write.
func (s *Store) MarkTransitionStreamDelivered(ctx context.Context, claim TransitionStreamClaim, now time.Time) error {
	return s.fencedTransitionStreamAck(ctx, claim,
		`status = 'delivered', delivered_at = ?, lease_owner = NULL, lease_expires_at = NULL, retry_at = NULL`,
		canonicalTime(now.UTC()))
}

// RetryTransitionStreamEntry schedules the next attempt for one row whose
// stdout write failed. Like every other Plan 3 delivery ledger it carries no
// attempt ceiling: an unavailable stdout is retried, not dead-lettered.
func (s *Store) RetryTransitionStreamEntry(ctx context.Context, claim TransitionStreamClaim,
	errorClass string, retryAt time.Time) error {
	if err := validateNotificationErrorClass(errorClass); err != nil {
		return err
	}
	return s.fencedTransitionStreamAck(ctx, claim,
		`last_error_class = ?, retry_at = ?, lease_owner = NULL, lease_expires_at = NULL`,
		errorClass, canonicalTime(retryAt.UTC()))
}

// FailTransitionStreamEntry moves exactly one row to failed — reserved for a
// durable payload this build cannot serialize at all, never for an
// unavailable writer. Failing one row never touches another row, another
// Situation, or any notification intent.
func (s *Store) FailTransitionStreamEntry(ctx context.Context, claim TransitionStreamClaim,
	errorClass string, _ time.Time) error {
	if err := validateNotificationErrorClass(errorClass); err != nil {
		return err
	}
	return s.fencedTransitionStreamAck(ctx, claim,
		`status = 'failed', last_error_class = ?, retry_at = NULL, lease_owner = NULL, lease_expires_at = NULL`,
		errorClass)
}

// ReleaseTransitionStreamClaim hands one still-held claim straight back, so a
// shutdown never leaves a committed Transition waiting out a full lease.
func (s *Store) ReleaseTransitionStreamClaim(ctx context.Context, claim TransitionStreamClaim) error {
	return s.fencedTransitionStreamAck(ctx, claim, `lease_owner = NULL, lease_expires_at = NULL`)
}

// fencedTransitionStreamAck applies one fenced lifecycle write and resolves a
// zero-row result into ErrTransitionStreamClaimLost (or ErrNotFound).
func (s *Store) fencedTransitionStreamAck(ctx context.Context, claim TransitionStreamClaim,
	setClause string, args ...any) error {
	if strings.TrimSpace(claim.StreamID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: transition stream acknowledgement requires a complete claim")
	}
	args = append(args, claim.StreamID, claim.ClaimOwner, claim.ClaimToken)
	res, err := s.db.ExecContext(ctx, `
		UPDATE situation_transition_stream SET `+setClause+`
		WHERE id = ? AND status = 'pending' AND lease_owner = ? AND claim_token = ?`, args...) // #nosec G202 -- setClause is a package-local constant expression; every value is bound
	if err != nil {
		return fmt.Errorf("store: acknowledge transition stream row: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count acknowledged transition stream row: %w", err)
	}
	if n != 1 {
		var status string
		err := s.db.QueryRowContext(ctx,
			`SELECT status FROM situation_transition_stream WHERE id = ?`, claim.StreamID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: transition stream row %s: %w", claim.StreamID, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("store: classify lost transition stream claim: %w", err)
		}
		return ErrTransitionStreamClaimLost
	}
	return nil
}

// RecoverExpiredTransitionStreamClaims returns every abandoned stdout-stream
// lease to the unclaimed pool. Startup-only in production (spec.md's own
// step 2, "recovers expired notification claims"), plus the worker's own
// per-round sweep. It never changes a row's status or attempt count — only
// its lease — so a crashed process's committed Transition is simply
// claimable again.
func (s *Store) RecoverExpiredTransitionStreamClaims(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE situation_transition_stream
		SET lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'pending' AND lease_owner IS NOT NULL AND lease_expires_at <= ?`,
		canonicalTime(now.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: recover expired transition stream claims: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count recovered transition stream claims: %w", err)
	}
	return int(n), nil
}
