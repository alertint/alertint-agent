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

	situation "github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ErrSituationVersionConflict means new input arrived after reconciliation
// started and the stale result was not committed.
var ErrSituationVersionConflict = errors.New("store: situation input version conflict")

// ErrSituationLeaseLost means a worker no longer owns the claimed aggregate.
var ErrSituationLeaseLost = errors.New("store: situation lease lost")

// SituationInput is one durable Incident-to-Situation handoff.
type SituationInput struct {
	ID             string
	IdempotencyKey string
	IncidentID     string
	Kind           string
	GroupKey       string
	DeliveryID     *string
	OccurredAt     time.Time
	ClaimOwner     string
	ClaimToken     int64
}

type storedSituationInput struct {
	SituationInput
	Status         string
	LeaseExpiresAt *time.Time
}

// SituationClaim carries the durable fencing identity for one claimed
// aggregate. Every lease-sensitive mutation requires the complete claim.
type SituationClaim struct {
	Situation  model.Situation
	ClaimOwner string
	ClaimToken int64
}

// ClaimSituationInputs leases pending, retry-due, or expired input work. The
// returned slice contains only rows changed by this claim transaction.
func (s *Store) ClaimSituationInputs(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]SituationInput, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: situation input claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim situation inputs: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		UPDATE situation_input_outbox
		SET status = 'claimed', lease_owner = ?, lease_expires_at = ?,
		    claim_token = claim_token + 1, attempt_count = attempt_count + 1
		WHERE id IN (
			SELECT id FROM situation_input_outbox
			WHERE (status = 'pending' AND (retry_at IS NULL OR retry_at <= ?))
			   OR (status = 'claimed' AND lease_expires_at <= ?)
			ORDER BY occurred_at ASC, id ASC
			LIMIT ?
		)
		RETURNING id`, owner, canonicalTime(now.Add(lease)), canonicalTime(now), canonicalTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim situation inputs: %w", err)
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan claimed situation input id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store: iterate claimed situation input ids: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: close claimed situation input ids: %w", err)
	}
	out := make([]SituationInput, 0, len(ids))
	for _, id := range ids {
		claimed, err := readSituationInput(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, claimed.SituationInput)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].ID < out[j].ID
	})
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit situation input claims: %w", err)
	}
	return out, nil
}

// RetrySituationInput releases a claimed input for a later retry or records a
// terminal local dead letter. It performs no outbound work.
func (s *Store) RetrySituationInput(ctx context.Context, claim SituationInput, class string, retryAt time.Time, terminal bool) error {
	if strings.TrimSpace(claim.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 || strings.TrimSpace(class) == "" {
		return errors.New("store: situation input retry requires id and error class")
	}
	status := "pending"
	var retry any = canonicalTime(retryAt)
	if terminal {
		status = "failed"
		retry = nil
	} else if retryAt.IsZero() {
		return errors.New("store: situation input retry time is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
		    last_error_class = ?, retry_at = ?
		WHERE id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		status, class, retry, claim.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: retry situation input: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count retried situation input: %w", err)
	}
	if changed != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

const situationColumns = `
	id, previous_situation_id, group_key, public_handle, title, lifecycle,
	attention, input_version, fact_hash, current_assessment_id, opened_at,
	effective_started_at, effective_started_at_basis, first_received_at,
	last_lifecycle_observed_at, recovery_observed_at, grace_until, terminal_at,
	terminal_reason, next_assessment_at, due_reasons_json, lease_owner,
	lease_expires_at, attempt_count, last_error_class, retry_at, created_at, updated_at`

// ClaimDueSituations leases due nonterminal aggregates in deterministic
// priority order. Overdue work ages upward by one band per minute.
func (s *Store) ClaimDueSituations(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]SituationClaim, error) {
	if strings.TrimSpace(owner) == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("store: situation claim requires owner, positive lease, and positive limit")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin claim due situations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		WITH due AS (
			SELECT id,
			       CASE
			           WHEN attention = 'urgent' THEN 0
			           WHEN public_handle IS NOT NULL AND EXISTS (
			               SELECT 1 FROM json_each(due_reasons_json)
			               WHERE value IN ('incident_created', 'membership_changed', 'new_symptom', 'alert_resolved',
			                               'alert_refired', 'connector_health_changed', 'operator_judgment', 'envelope_changed')
			           ) THEN 1
			           WHEN EXISTS (SELECT 1 FROM json_each(due_reasons_json) WHERE value IN ('new_symptom', 'envelope_changed', 'envelope_boundary')) THEN 2
			           WHEN EXISTS (SELECT 1 FROM json_each(due_reasons_json) WHERE value IN ('recovery_grace_expired', 'observation_deadline')) THEN 3
			           ELSE 4
			       END AS base_priority,
			       CAST(MAX(0, (unixepoch(?) - unixepoch(next_assessment_at)) / 60) AS INTEGER) AS age_bands,
			       next_assessment_at
			FROM situations
			WHERE lifecycle IN ('active', 'recovery_pending')
			  AND next_assessment_at <= ?
			  AND (retry_at IS NULL OR retry_at <= ?)
			  AND (lease_owner IS NULL OR lease_expires_at <= ?)
		), chosen AS (
			SELECT id FROM due
			ORDER BY MAX(0, base_priority - age_bands) ASC, next_assessment_at ASC, id ASC
			LIMIT ?
		)
		UPDATE situations
		SET lease_owner = ?, lease_expires_at = ?, claim_token = claim_token + 1,
		    attempt_count = attempt_count + 1,
		    updated_at = ?
		WHERE id IN (SELECT id FROM chosen)
		RETURNING id`, canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), limit,
		owner, canonicalTime(now.Add(lease)), canonicalTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: claim due situations: %w", err)
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan claimed situation id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store: iterate claimed situation ids: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: close claimed situation ids: %w", err)
	}
	out := make([]SituationClaim, 0, len(ids))
	for _, id := range ids {
		claimed, err := querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, id)
		if err != nil {
			return nil, err
		}
		var token int64
		if err := tx.QueryRowContext(ctx, `SELECT claim_token FROM situations WHERE id = ?`, id).Scan(&token); err != nil {
			return nil, fmt.Errorf("store: read claimed situation token: %w", err)
		}
		out = append(out, SituationClaim{Situation: claimed, ClaimOwner: owner, ClaimToken: token})
	}
	sort.Slice(out, func(i, j int) bool {
		leftWait := now.Sub(out[i].Situation.NextAssessmentAt)
		rightWait := now.Sub(out[j].Situation.NextAssessmentAt)
		left := situation.PriorityFor(prioritySignalsForSituation(out[i].Situation), leftWait, time.Minute)
		right := situation.PriorityFor(prioritySignalsForSituation(out[j].Situation), rightWait, time.Minute)
		if left != right {
			return left < right
		}
		if !out[i].Situation.NextAssessmentAt.Equal(out[j].Situation.NextAssessmentAt) {
			return out[i].Situation.NextAssessmentAt.Before(out[j].Situation.NextAssessmentAt)
		}
		return out[i].Situation.ID < out[j].Situation.ID
	})
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit due situation claims: %w", err)
	}
	return out, nil
}

func prioritySignalsForSituation(value model.Situation) situation.PrioritySignals {
	signals := situation.PrioritySignals{DeterministicUrgent: value.Attention == model.AttentionUrgent}
	for _, reason := range value.DueReasons {
		if value.PublicHandle != nil && situation.IsPublishedMaterialReason(reason) {
			signals.PublishedMaterialChange = true
		}
		switch reason {
		case model.DueNewSymptom:
			signals.NewSymptom = true
		case model.DueEnvelopeChanged, model.DueEnvelopeBoundary:
			signals.EnvelopeViolation = true
		case model.DueRecoveryGraceExpired:
			signals.RecoveryBoundary = true
		case model.DueObservationDeadline:
			signals.DeadlineBoundary = true
		}
	}
	return signals
}

// RecoverExpiredSituationLeases clears abandoned aggregate claims. Due work
// remains durable and can be claimed again immediately.
func (s *Store) RecoverExpiredSituationLeases(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations
		SET lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE lease_owner IS NOT NULL AND lease_expires_at <= ?`, canonicalTime(now), canonicalTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: recover expired situation leases: %w", err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count recovered situation leases: %w", err)
	}
	return count, nil
}

// ExtendSituationLease heartbeats only a live lease still owned by owner.
func (s *Store) ExtendSituationLease(ctx context.Context, situationID, owner string, claimToken int64, now time.Time, lease time.Duration) error {
	if strings.TrimSpace(situationID) == "" || strings.TrimSpace(owner) == "" || claimToken <= 0 || lease <= 0 {
		return errors.New("store: situation lease extension requires id, owner, and positive lease")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations
		SET lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ? AND lease_expires_at > ?
		  AND lifecycle IN ('active', 'recovery_pending')`,
		canonicalTime(now.Add(lease)), canonicalTime(now), situationID, owner, claimToken, canonicalTime(now))
	if err != nil {
		return fmt.Errorf("store: extend situation lease: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count extended situation lease: %w", err)
	}
	if changed != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

// SituationForIncident returns the Incident's immutable primary owner.
func (s *Store) SituationForIncident(ctx context.Context, incidentID string) (model.Situation, error) {
	if strings.TrimSpace(incidentID) == "" {
		return model.Situation{}, errors.New("store: incident id is required")
	}
	return querySituation(ctx, s.db, `SELECT `+situationColumns+`
		FROM situations AS s
		JOIN situation_incidents AS si ON si.situation_id = s.id
		WHERE si.incident_id = ?`, incidentID)
}

// CurrentSituationForGroup returns the nonterminal aggregate when present,
// otherwise the newest terminal aggregate for the exact group key.
func (s *Store) CurrentSituationForGroup(ctx context.Context, groupKey string) (model.Situation, error) {
	if strings.TrimSpace(groupKey) == "" {
		return model.Situation{}, errors.New("store: situation group key is required")
	}
	return querySituation(ctx, s.db, `SELECT `+situationColumns+`
		FROM situations
		WHERE group_key = ?
		ORDER BY CASE WHEN lifecycle IN ('active', 'recovery_pending') THEN 0 ELSE 1 END,
		         created_at DESC, id DESC
		LIMIT 1`, groupKey)
}

// CommitSituationTransition conditionally applies a reconciler result to the
// exact input version it observed. Stale work has no aggregate effect.
func (s *Store) CommitSituationTransition(ctx context.Context, claim SituationClaim, tr model.Transition, assessmentID *string) error {
	expectedInputVersion := claim.Situation.InputVersion
	if strings.TrimSpace(tr.SituationID) == "" || tr.SituationID != claim.Situation.ID || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 || expectedInputVersion < 1 || tr.InputVersion != expectedInputVersion {
		return errors.New("store: situation transition requires matching positive input version")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin situation transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, tr.SituationID)
	if err != nil {
		return err
	}
	if current.InputVersion != expectedInputVersion {
		return ErrSituationVersionConflict
	}
	var durableToken int64
	if current.LeaseOwner == nil || *current.LeaseOwner != claim.ClaimOwner {
		return ErrSituationLeaseLost
	}
	if err := tx.QueryRowContext(ctx, `SELECT claim_token FROM situations WHERE id = ?`, tr.SituationID).Scan(&durableToken); err != nil {
		return fmt.Errorf("store: read situation transition fence: %w", err)
	}
	if durableToken != claim.ClaimToken {
		return ErrSituationLeaseLost
	}
	if !validSituationAttention(tr.Attention) || !validSituationLifecycle(tr.Lifecycle) {
		return errors.New("store: invalid situation transition state")
	}
	if !legalSituationTransition(current.Lifecycle, tr.Lifecycle) {
		return errors.New("store: invalid situation lifecycle transition")
	}
	createdAt := tr.CreatedAt.UTC()
	if createdAt.IsZero() {
		return errors.New("store: situation transition created time is required")
	}

	attention := tr.Attention
	var recoveryObservedAt, graceUntil, terminalAt, terminalReason any
	if current.RecoveryObservedAt != nil {
		recoveryObservedAt = canonicalTime(*current.RecoveryObservedAt)
	}
	if current.GraceUntil != nil {
		graceUntil = canonicalTime(*current.GraceUntil)
	}
	nextAssessmentAt := current.NextAssessmentAt
	switch tr.Lifecycle {
	case model.LifecycleActive:
		recoveryObservedAt = nil
		graceUntil = nil
		if tr.ActionContract.NextUpdateAt == nil {
			return errors.New("store: active situation transition requires next update time")
		}
		nextAssessmentAt = tr.ActionContract.NextUpdateAt.UTC()
	case model.LifecycleRecoveryPending:
		if current.RecoveryObservedAt == nil {
			recoveryObservedAt = canonicalTime(createdAt)
		}
		if tr.ActionContract.NextUpdateAt != nil {
			graceUntil = canonicalTime(*tr.ActionContract.NextUpdateAt)
			nextAssessmentAt = tr.ActionContract.NextUpdateAt.UTC()
		} else {
			graceUntil = canonicalTime(createdAt)
			nextAssessmentAt = createdAt
		}
	case model.LifecycleRecovered:
		attention = model.AttentionObserve
		terminalAt = canonicalTime(createdAt)
		nextAssessmentAt = createdAt
	case model.LifecycleClosedUnknown:
		reason := model.TerminalReason(tr.Reason)
		if !validTerminalReason(reason) {
			return errors.New("store: closed unknown requires a structured terminal reason")
		}
		firing, err := situationHasFreshAuthoritativeFiring(ctx, tx, tr.SituationID, createdAt)
		if err != nil {
			return err
		}
		if firing {
			return errors.New("store: fresh authoritative firing prevents closed unknown")
		}
		terminalAt = canonicalTime(createdAt)
		terminalReason = string(reason)
		nextAssessmentAt = createdAt
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE situations
		SET lifecycle = ?, attention = ?, current_assessment_id = COALESCE(?, current_assessment_id),
		    recovery_observed_at = ?, grace_until = ?, terminal_at = ?, terminal_reason = ?,
		    next_assessment_at = ?, due_reasons_json = '[]', lease_owner = NULL,
		    lease_expires_at = NULL, last_error_class = NULL, retry_at = NULL,
		    updated_at = ?
		WHERE id = ? AND input_version = ? AND lease_owner = ? AND claim_token = ?`,
		tr.Lifecycle, attention, nullableString(assessmentID), recoveryObservedAt, graceUntil, terminalAt, terminalReason,
		canonicalTime(nextAssessmentAt), canonicalTime(createdAt), tr.SituationID, expectedInputVersion,
		claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: commit situation transition: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count committed situation transition: %w", err)
	}
	if changed != 1 {
		return ErrSituationVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: finish situation transition: %w", err)
	}
	return nil
}

func legalSituationTransition(from, to model.Lifecycle) bool {
	if from == to {
		return from == model.LifecycleActive || from == model.LifecycleRecoveryPending
	}
	switch from {
	case model.LifecycleActive:
		return to == model.LifecycleRecoveryPending || to == model.LifecycleClosedUnknown
	case model.LifecycleRecoveryPending:
		return to == model.LifecycleActive || to == model.LifecycleRecovered || to == model.LifecycleClosedUnknown
	default:
		return false
	}
}

func validSituationLifecycle(value model.Lifecycle) bool {
	switch value {
	case model.LifecycleActive, model.LifecycleRecoveryPending, model.LifecycleRecovered, model.LifecycleClosedUnknown:
		return true
	default:
		return false
	}
}

func validSituationAttention(value model.Attention) bool {
	switch value {
	case model.AttentionObserve, model.AttentionInvestigate, model.AttentionUrgent:
		return true
	default:
		return false
	}
}

func validTerminalReason(value model.TerminalReason) bool {
	switch value {
	case model.TerminalReasonObservationDeadline, model.TerminalReasonResolutionMissing,
		model.TerminalReasonSourceUnavailable, model.TerminalReasonBudgetExhausted:
		return true
	default:
		return false
	}
}

func situationHasFreshAuthoritativeFiring(ctx context.Context, tx *sql.Tx, situationID string, at time.Time) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT d.source, d.status, d.received_at
		FROM situation_incidents AS si
		JOIN incident_alert_deliveries AS iad ON iad.incident_id = si.incident_id
		JOIN alert_deliveries AS d ON d.id = iad.delivery_id
		WHERE si.situation_id = ?
		  AND NOT EXISTS (
			SELECT 1
			FROM situation_incidents AS newer_si
			JOIN incident_alert_deliveries AS newer_iad ON newer_iad.incident_id = newer_si.incident_id
			JOIN alert_deliveries AS newer ON newer.id = newer_iad.delivery_id
			WHERE newer_si.situation_id = si.situation_id
			  AND newer.source_episode_key = d.source_episode_key
			  AND (newer.received_at > d.received_at OR (newer.received_at = d.received_at AND newer.id > d.id))
		  )`, situationID)
	if err != nil {
		return false, fmt.Errorf("store: query authoritative situation lifecycle: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var source, status, receivedRaw string
		if err := rows.Scan(&source, &status, &receivedRaw); err != nil {
			return false, fmt.Errorf("store: scan authoritative situation lifecycle: %w", err)
		}
		receivedAt, err := parseSituationTime("delivery received_at", receivedRaw)
		if err != nil {
			return false, err
		}
		if status == string(model.DeliveryStatusFiring) && at.Before(receivedAt.Add(authoritativeLifecycleWindow(source))) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("store: iterate authoritative situation lifecycle: %w", err)
	}
	return false, nil
}

// Task 11 may extend this default from advisory semantic profiles, but never
// shorten it. The immutable delivery source remains an explicit input so a
// source-specific authority policy can be introduced without consulting the
// mutable compatibility projection.
func authoritativeLifecycleWindow(source string) time.Duration {
	if strings.TrimSpace(source) == "" {
		return 0
	}
	return 24 * time.Hour
}

// ApplySituationInput atomically creates/selects the exact-group aggregate,
// attaches the Incident once, advances the input version once, and marks the
// claimed outbox row applied. Reapplying an applied row is a successful read.
func (s *Store) ApplySituationInput(ctx context.Context, claim SituationInput) (model.Situation, error) {
	if strings.TrimSpace(claim.ID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return model.Situation{}, errors.New("store: situation input claim is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: begin apply situation input: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	in, err := readSituationInput(ctx, tx, claim.ID)
	if err != nil {
		return model.Situation{}, err
	}
	if in.ClaimToken != claim.ClaimToken {
		return model.Situation{}, ErrSituationLeaseLost
	}
	if in.Status == "applied" {
		owned, err := situationForIncidentTx(ctx, tx, in.IncidentID)
		if err != nil {
			return model.Situation{}, fmt.Errorf("store: read applied situation input owner: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return model.Situation{}, fmt.Errorf("store: commit applied situation input read: %w", err)
		}
		return owned, nil
	}
	if in.Status != "claimed" {
		return model.Situation{}, errors.New("store: situation input must be claimed before apply")
	}
	if in.ClaimOwner != claim.ClaimOwner {
		return model.Situation{}, ErrSituationLeaseLost
	}
	appliedAt := time.Now().UTC()

	var incidentGroup, firstAlertAt, incidentCreatedAt string
	if err := tx.QueryRowContext(ctx, `SELECT group_key, first_alert_at, created_at FROM incidents WHERE id = ?`, in.IncidentID).
		Scan(&incidentGroup, &firstAlertAt, &incidentCreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Situation{}, ErrNotFound
		}
		return model.Situation{}, fmt.Errorf("store: read situation input incident: %w", err)
	}
	if incidentGroup != in.GroupKey {
		return model.Situation{}, errors.New("store: situation input group key does not match incident")
	}
	dueReason, err := dueReasonForInputKind(in.Kind)
	if err != nil {
		return model.Situation{}, err
	}
	times, err := situationInputTimes(ctx, tx, in, firstAlertAt, incidentCreatedAt)
	if err != nil {
		return model.Situation{}, err
	}

	owned, ownerErr := situationForIncidentTx(ctx, tx, in.IncidentID)
	if ownerErr == nil {
		if owned.Lifecycle == model.LifecycleRecovered || owned.Lifecycle == model.LifecycleClosedUnknown {
			return model.Situation{}, errors.New("store: terminal situation membership is immutable")
		}
		owned, err = applyInputToExistingSituation(ctx, tx, owned, in, times, appliedAt, dueReason)
	} else if !errors.Is(ownerErr, ErrNotFound) {
		return model.Situation{}, fmt.Errorf("store: read situation input membership: %w", ownerErr)
	} else {
		current, currentErr := currentSituationForGroupTx(ctx, tx, in.GroupKey)
		switch {
		case currentErr == nil && (current.Lifecycle == model.LifecycleActive || current.Lifecycle == model.LifecycleRecoveryPending):
			owned, err = applyInputToExistingSituation(ctx, tx, current, in, times, appliedAt, dueReason)
		case currentErr == nil:
			owned, err = createSituationForInput(ctx, tx, in, times, appliedAt, &current.ID, dueReason)
		case errors.Is(currentErr, ErrNotFound):
			owned, err = createSituationForInput(ctx, tx, in, times, appliedAt, nil, dueReason)
		default:
			return model.Situation{}, fmt.Errorf("store: read current situation for input: %w", currentErr)
		}
	}
	if err != nil {
		return model.Situation{}, err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET status = 'applied', lease_owner = NULL, lease_expires_at = NULL,
		    retry_at = NULL, applied_at = ?
		WHERE id = ? AND status = 'claimed' AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(appliedAt), in.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: mark situation input applied: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: count applied situation input: %w", err)
	}
	if changed != 1 {
		return model.Situation{}, errors.New("store: situation input claim changed before apply")
	}
	if err := tx.Commit(); err != nil {
		return model.Situation{}, fmt.Errorf("store: commit situation input: %w", err)
	}
	return owned, nil
}

type situationTimes struct {
	EffectiveStartedAt      time.Time
	EffectiveStartedAtBasis model.SourceTimeBasis
	FirstReceivedAt         time.Time
	LifecycleObservedAt     *time.Time
}

func situationInputTimes(ctx context.Context, tx *sql.Tx, in storedSituationInput, firstAlertAt, incidentCreatedAt string) (situationTimes, error) {
	effective, err := parseSituationTime("incident first_alert_at", firstAlertAt)
	if err != nil {
		return situationTimes{}, err
	}
	firstReceived, err := parseSituationTime("incident created_at", incidentCreatedAt)
	if err != nil {
		return situationTimes{}, err
	}
	out := situationTimes{EffectiveStartedAt: effective, EffectiveStartedAtBasis: model.SourceTimeBasisReceiptFallback, FirstReceivedAt: firstReceived}
	if in.DeliveryID == nil {
		return out, nil
	}
	var sourceStarted sql.NullString
	var basis model.SourceTimeBasis
	var receivedAt string
	var status model.DeliveryStatus
	if err := tx.QueryRowContext(ctx, `
		SELECT d.source_started_at, d.started_at_basis, d.received_at, d.status
		FROM alert_deliveries AS d
		JOIN incident_alert_deliveries AS iad ON iad.delivery_id = d.id
		WHERE d.id = ? AND iad.incident_id = ?`, *in.DeliveryID, in.IncidentID).
		Scan(&sourceStarted, &basis, &receivedAt, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return situationTimes{}, ErrNotFound
		}
		return situationTimes{}, fmt.Errorf("store: read situation input delivery times: %w", err)
	}
	if sourceStarted.Valid && basis != model.SourceTimeBasisMissing {
		out.EffectiveStartedAt, err = parseSituationTime("delivery source_started_at", sourceStarted.String)
		if err != nil {
			return situationTimes{}, err
		}
		out.EffectiveStartedAtBasis = basis
	}
	out.FirstReceivedAt, err = parseSituationTime("delivery received_at", receivedAt)
	if err != nil {
		return situationTimes{}, err
	}
	if status == model.DeliveryStatusFiring || status == model.DeliveryStatusResolved {
		observedAt := out.FirstReceivedAt
		out.LifecycleObservedAt = &observedAt
	}
	return out, nil
}

func createSituationForInput(ctx context.Context, tx *sql.Tx, in storedSituationInput, times situationTimes, appliedAt time.Time, previousID *string, reason model.DueReason) (model.Situation, error) {
	reasonsJSON, err := json.Marshal([]model.DueReason{reason})
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: marshal initial situation due reason: %w", err)
	}
	id := uuid.NewString()
	lastObserved := time.Time{}
	if times.LifecycleObservedAt != nil {
		lastObserved = *times.LifecycleObservedAt
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situations (
			id, previous_situation_id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis,
			first_received_at, last_lifecycle_observed_at, next_assessment_at,
			due_reasons_json, attempt_count, created_at, updated_at
		) VALUES (?, ?, ?, 'active', 'observe', 1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, nullableString(previousID), in.GroupKey, canonicalTime(appliedAt), canonicalTime(times.EffectiveStartedAt),
		times.EffectiveStartedAtBasis, canonicalTime(times.FirstReceivedAt), canonicalTime(lastObserved), canonicalTime(in.OccurredAt), string(reasonsJSON),
		canonicalTime(appliedAt), canonicalTime(appliedAt)); err != nil {
		return model.Situation{}, fmt.Errorf("store: create situation: %w", err)
	}
	if err := attachIncidentTx(ctx, tx, id, in.IncidentID, appliedAt); err != nil {
		return model.Situation{}, err
	}
	return querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, id)
}

func applyInputToExistingSituation(ctx context.Context, tx *sql.Tx, current model.Situation, in storedSituationInput, times situationTimes, appliedAt time.Time, reason model.DueReason) (model.Situation, error) {
	if err := attachIncidentTx(ctx, tx, current.ID, in.IncidentID, appliedAt); err != nil {
		return model.Situation{}, err
	}
	reasons := situation.MergeDueReasons(current.DueReasons, reason)
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: marshal situation due reasons: %w", err)
	}
	next := situation.EarlierAssessmentAt(current.NextAssessmentAt, in.OccurredAt)
	lastObserved := current.LastLifecycleObservedAt
	if times.LifecycleObservedAt != nil && times.LifecycleObservedAt.After(lastObserved) {
		lastObserved = times.LifecycleObservedAt.UTC()
	}
	effectiveStartedAt := current.EffectiveStartedAt
	if times.EffectiveStartedAt.Before(effectiveStartedAt) {
		effectiveStartedAt = times.EffectiveStartedAt
	}
	basis := current.EffectiveStartedAtBasis
	if basis != times.EffectiveStartedAtBasis {
		basis = model.SourceTimeBasisMixed
	}
	firstReceivedAt := current.FirstReceivedAt
	if times.FirstReceivedAt.Before(firstReceivedAt) {
		firstReceivedAt = times.FirstReceivedAt
	}
	updatedAt := appliedAt.UTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE situations
		SET input_version = input_version + 1, due_reasons_json = ?,
		    next_assessment_at = ?, last_lifecycle_observed_at = ?,
		    effective_started_at = ?, effective_started_at_basis = ?,
		    first_received_at = ?, lease_owner = NULL, lease_expires_at = NULL,
		    attempt_count = 0, last_error_class = NULL, retry_at = NULL, updated_at = ?
		WHERE id = ? AND input_version = ? AND lifecycle IN ('active', 'recovery_pending')`,
		string(reasonsJSON), canonicalTime(next), canonicalTime(lastObserved), canonicalTime(effectiveStartedAt), basis,
		canonicalTime(firstReceivedAt), canonicalTime(updatedAt), current.ID, current.InputVersion)
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: apply situation input: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: count situation input update: %w", err)
	}
	if changed != 1 {
		return model.Situation{}, ErrSituationVersionConflict
	}
	return querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, current.ID)
}

func attachIncidentTx(ctx context.Context, tx *sql.Tx, situationID, incidentID string, attachedAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO situation_incidents(situation_id, incident_id, attached_at) VALUES (?, ?, ?)`, situationID, incidentID, canonicalTime(attachedAt)); err != nil {
		return fmt.Errorf("store: attach incident to situation: %w", err)
	}
	return nil
}

func dueReasonForInputKind(kind string) (model.DueReason, error) {
	switch kind {
	case "incident_created":
		return model.DueIncidentCreated, nil
	case "membership_changed", "incident_ready":
		return model.DueMembershipChanged, nil
	case "incident_resolved":
		return model.DueAlertResolved, nil
	default:
		return "", fmt.Errorf("store: unsupported situation input kind %q", kind)
	}
}

func readSituationInput(ctx context.Context, q queryRower, inputID string) (storedSituationInput, error) {
	var in storedSituationInput
	var deliveryID, leaseOwner, leaseExpires sql.NullString
	var occurredAt string
	err := q.QueryRowContext(ctx, `
		SELECT id, idempotency_key, incident_id, kind, group_key, delivery_id,
		       occurred_at, status, lease_owner, lease_expires_at, claim_token
		FROM situation_input_outbox WHERE id = ?`, inputID).
		Scan(&in.ID, &in.IdempotencyKey, &in.IncidentID, &in.Kind, &in.GroupKey, &deliveryID,
			&occurredAt, &in.Status, &leaseOwner, &leaseExpires, &in.ClaimToken)
	if errors.Is(err, sql.ErrNoRows) {
		return storedSituationInput{}, ErrNotFound
	}
	if err != nil {
		return storedSituationInput{}, fmt.Errorf("store: read situation input: %w", err)
	}
	in.DeliveryID = nullStringPtr(deliveryID)
	if leaseOwner.Valid {
		in.ClaimOwner = leaseOwner.String
	}
	if in.OccurredAt, err = parseSituationTime("input occurred_at", occurredAt); err != nil {
		return storedSituationInput{}, err
	}
	if leaseExpires.Valid {
		parsed, err := parseSituationTime("input lease_expires_at", leaseExpires.String)
		if err != nil {
			return storedSituationInput{}, err
		}
		in.LeaseExpiresAt = &parsed
	}
	return in, nil
}

func situationForIncidentTx(ctx context.Context, tx *sql.Tx, incidentID string) (model.Situation, error) {
	return querySituation(ctx, tx, `SELECT `+situationColumns+`
		FROM situations AS s JOIN situation_incidents AS si ON si.situation_id = s.id
		WHERE si.incident_id = ?`, incidentID)
}

func currentSituationForGroupTx(ctx context.Context, tx *sql.Tx, groupKey string) (model.Situation, error) {
	return querySituation(ctx, tx, `SELECT `+situationColumns+`
		FROM situations WHERE group_key = ?
		ORDER BY CASE WHEN lifecycle IN ('active', 'recovery_pending') THEN 0 ELSE 1 END,
		         created_at DESC, id DESC LIMIT 1`, groupKey)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type rowScanner interface {
	Scan(...any) error
}

func querySituation(ctx context.Context, q queryRower, query string, args ...any) (model.Situation, error) {
	return scanSituation(q.QueryRowContext(ctx, query, args...))
}

func scanSituation(row rowScanner) (model.Situation, error) {
	var out model.Situation
	var previousID, publicHandle, title, factHash, assessmentID sql.NullString
	var recoveryAt, graceUntil, terminalAt, terminalReason sql.NullString
	var leaseOwner, leaseExpires, lastError, retryAt sql.NullString
	var openedAt, effectiveAt, firstReceivedAt, lastObservedAt, nextAt, createdAt, updatedAt string
	var dueReasonsJSON string
	err := row.Scan(
		&out.ID, &previousID, &out.GroupKey, &publicHandle, &title, &out.Lifecycle,
		&out.Attention, &out.InputVersion, &factHash, &assessmentID, &openedAt,
		&effectiveAt, &out.EffectiveStartedAtBasis, &firstReceivedAt, &lastObservedAt,
		&recoveryAt, &graceUntil, &terminalAt, &terminalReason, &nextAt,
		&dueReasonsJSON, &leaseOwner, &leaseExpires, &out.AttemptCount, &lastError,
		&retryAt, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Situation{}, ErrNotFound
	}
	if err != nil {
		return model.Situation{}, fmt.Errorf("store: scan situation: %w", err)
	}
	out.PreviousSituationID = nullStringPtr(previousID)
	out.PublicHandle = nullStringPtr(publicHandle)
	out.Title = nullStringPtr(title)
	out.FactHash = nullStringPtr(factHash)
	out.CurrentAssessmentID = nullStringPtr(assessmentID)
	out.LeaseOwner = nullStringPtr(leaseOwner)
	out.LastErrorClass = nullStringPtr(lastError)
	if err := json.Unmarshal([]byte(dueReasonsJSON), &out.DueReasons); err != nil {
		return model.Situation{}, fmt.Errorf("store: decode situation due reasons: %w", err)
	}
	var parseErr error
	if out.OpenedAt, parseErr = parseSituationTime("opened_at", openedAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.EffectiveStartedAt, parseErr = parseSituationTime("effective_started_at", effectiveAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.FirstReceivedAt, parseErr = parseSituationTime("first_received_at", firstReceivedAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.LastLifecycleObservedAt, parseErr = parseSituationTime("last_lifecycle_observed_at", lastObservedAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.NextAssessmentAt, parseErr = parseSituationTime("next_assessment_at", nextAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.CreatedAt, parseErr = parseSituationTime("created_at", createdAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.UpdatedAt, parseErr = parseSituationTime("updated_at", updatedAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.RecoveryObservedAt, parseErr = parseNullableSituationTime("recovery_observed_at", recoveryAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.GraceUntil, parseErr = parseNullableSituationTime("grace_until", graceUntil); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.TerminalAt, parseErr = parseNullableSituationTime("terminal_at", terminalAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if terminalReason.Valid {
		reason := model.TerminalReason(terminalReason.String)
		out.TerminalReason = &reason
	}
	if out.LeaseExpiresAt, parseErr = parseNullableSituationTime("lease_expires_at", leaseExpires); parseErr != nil {
		return model.Situation{}, parseErr
	}
	if out.RetryAt, parseErr = parseNullableSituationTime("retry_at", retryAt); parseErr != nil {
		return model.Situation{}, parseErr
	}
	return out, nil
}

func parseSituationTime(field, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: parse situation %s: %w", field, err)
	}
	return parsed.UTC(), nil
}

func parseNullableSituationTime(field string, value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseSituationTime(field, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	copy := value.String
	return &copy
}
