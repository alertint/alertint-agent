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
// Plan 3 Task 7: the durable, installation-level Delivery-gap lifecycle
// (migration 0018's slack_delivery_state singleton and slack_delivery_gaps
// generations).
//
// The whole machine is four transitions:
//
//	healthy --first failure-->      ordinary delay (first_failure_at set)
//	ordinary delay --5 continuous minutes--> open generation
//	open --successful readiness probe--> replaying (+ one recovery notice)
//	replaying --backlog drained--> complete
//
// A success at any point clears the failure window, so only CONTINUOUS
// failure ever opens a gap. Generations are never deleted and never merged:
// a second outage during replay gets its own identity after its own full
// five-minute window.
//
// Which intents a generation is replaying is DERIVED, not stored: migration
// 0018 deliberately allows gap_generation only on the recovery notice
// itself, so "replayable" means "a pending Situation-scoped intent that
// already existed when this generation recovered" (created_at <=
// recovered_at). That keeps work committed after recovery — ordinary
// delivery, not replay — from holding a generation open forever.
// ----------------------------------------------------------------------

// GapSnapshot is one durable gap generation's bounded rendering facts: the
// outage interval and the backlog it delayed. It is exactly what
// cmd/alertint's Slack deliverer renders the ADR-0042 recovery notice from.
type GapSnapshot struct {
	ID                     string
	OpenedAt               time.Time
	RecoveredAt            time.Time
	AffectedSituationCount int
	DelayedEffectCount     int
}

// GetDeliveryGap reads one gap generation's rendering facts. Returns
// ErrNotFound when no such generation exists.
func (s *Store) GetDeliveryGap(ctx context.Context, gapGeneration string) (GapSnapshot, error) {
	if strings.TrimSpace(gapGeneration) == "" {
		return GapSnapshot{}, errors.New("store: delivery gap read requires a generation id")
	}
	var openedAt string
	var recoveredAt sql.NullString
	snapshot := GapSnapshot{ID: gapGeneration}
	err := s.db.QueryRowContext(ctx, `
		SELECT opened_at, recovered_at, affected_situation_count, delayed_effect_count
		FROM slack_delivery_gaps WHERE id = ?`, gapGeneration).
		Scan(&openedAt, &recoveredAt, &snapshot.AffectedSituationCount, &snapshot.DelayedEffectCount)
	if errors.Is(err, sql.ErrNoRows) {
		return GapSnapshot{}, ErrNotFound
	}
	if err != nil {
		return GapSnapshot{}, fmt.Errorf("store: read delivery gap: %w", err)
	}
	opened, err := time.Parse(time.RFC3339Nano, openedAt)
	if err != nil {
		return GapSnapshot{}, fmt.Errorf("store: parse delivery gap opened_at: %w", err)
	}
	snapshot.OpenedAt = opened.UTC()
	recovered, err := timePtr(recoveredAt)
	if err != nil {
		return GapSnapshot{}, fmt.Errorf("store: parse delivery gap recovered_at: %w", err)
	}
	if recovered != nil {
		snapshot.RecoveredAt = *recovered
	}
	return snapshot, nil
}

// GetSlackDeliveryState reads the installation-level Slack delivery health
// snapshot in one snapshot transaction, so the failure window, the current
// gap generation's status, and the blocked-configuration backlog can never
// disagree with each other.
func (s *Store) GetSlackDeliveryState(ctx context.Context) (situation.SlackDeliveryState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return situation.SlackDeliveryState{}, fmt.Errorf("store: begin slack delivery state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	state, err := slackDeliveryStateTx(ctx, tx)
	if err != nil {
		return situation.SlackDeliveryState{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM notification_intents WHERE status = 'blocked_configuration'`).
		Scan(&state.BlockedConfigurationCount); err != nil {
		return situation.SlackDeliveryState{}, fmt.Errorf("store: count blocked notification intents: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return situation.SlackDeliveryState{}, fmt.Errorf("store: commit slack delivery state: %w", err)
	}
	return state, nil
}

func slackDeliveryStateTx(ctx context.Context, tx *sql.Tx) (situation.SlackDeliveryState, error) {
	var firstFailureAt, lastSuccessAt, openGap, lastWarningAt, gapStatus sql.NullString
	var updatedAt string
	var configurationGeneration int64
	err := tx.QueryRowContext(ctx, `
		SELECT st.first_failure_at, st.last_success_at, st.open_gap_generation,
		       st.configuration_generation, st.last_warning_at, st.updated_at, g.status
		FROM slack_delivery_state st
		LEFT JOIN slack_delivery_gaps g ON g.id = st.open_gap_generation
		WHERE st.id = 1`).
		Scan(&firstFailureAt, &lastSuccessAt, &openGap, &configurationGeneration, &lastWarningAt, &updatedAt, &gapStatus)
	if err != nil {
		return situation.SlackDeliveryState{}, fmt.Errorf("store: read slack delivery state: %w", err)
	}
	state := situation.SlackDeliveryState{
		ConfigurationGeneration: configurationGeneration,
		OpenGapGeneration:       stringPtr(openGap),
		OpenGapStatus:           gapStatus.String,
	}
	for _, f := range []struct {
		src sql.NullString
		dst **time.Time
	}{
		{firstFailureAt, &state.FirstFailureAt}, {lastSuccessAt, &state.LastSuccessAt}, {lastWarningAt, &state.LastWarningAt},
	} {
		parsed, err := timePtr(f.src)
		if err != nil {
			return situation.SlackDeliveryState{}, fmt.Errorf("store: parse slack delivery state instant: %w", err)
		}
		*f.dst = parsed
	}
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return situation.SlackDeliveryState{}, fmt.Errorf("store: parse slack delivery state updated_at: %w", err)
	}
	state.UpdatedAt = parsed.UTC()
	return state, nil
}

// ObserveSlackFailure records one retryable or configuration failure against
// the current CONTINUOUS failure window. The first failure of a window
// anchors first_failure_at (and stamps the one bounded warning marker the
// console action trail emits at that moment); later failures leave the
// anchor exactly where it is, because the gap threshold measures continuous
// failure, not a sliding window.
func (s *Store) ObserveSlackFailure(ctx context.Context, errorClass string, now time.Time) error {
	if err := validateNotificationErrorClass(errorClass); err != nil {
		return err
	}
	stamp := canonicalTime(now.UTC())
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state
		SET first_failure_at = COALESCE(first_failure_at, ?),
		    last_warning_at = CASE WHEN first_failure_at IS NULL THEN ? ELSE last_warning_at END,
		    updated_at = ?
		WHERE id = 1`, stamp, stamp, stamp); err != nil {
		return fmt.Errorf("store: observe slack failure: %w", err)
	}
	return nil
}

// ObserveSlackSuccess closes the current failure window. It does not touch
// an already-open generation: a gap is only ever retired by the recovery
// and completion transitions below, which have their own ordering
// obligations.
func (s *Store) ObserveSlackSuccess(ctx context.Context, now time.Time) error {
	stamp := canonicalTime(now.UTC())
	if _, err := s.db.ExecContext(ctx, `
		UPDATE slack_delivery_state
		SET first_failure_at = NULL, last_success_at = ?, updated_at = ?
		WHERE id = 1`, stamp, stamp); err != nil {
		return fmt.Errorf("store: observe slack success: %w", err)
	}
	return nil
}

// OpenDueDeliveryGap opens one durable generation when — and only when —
// failures have been continuous for threshold. It reports whether it opened
// one.
//
// It is idempotent twice over: the generation's id is derived from the
// failure window's own anchor, and an already-open generation short-circuits
// the whole call. A generation still REPLAYING does not block a new one: a
// second outage mid-replay gets its own identity after its own full window,
// and the earlier generation still completes on its own drained-backlog
// condition.
func (s *Store) OpenDueDeliveryGap(ctx context.Context, now time.Time, threshold time.Duration) (bool, error) {
	if threshold <= 0 {
		return false, errors.New("store: delivery gap threshold must be positive")
	}
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: begin open delivery gap: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	state, err := slackDeliveryStateTx(ctx, tx)
	if err != nil {
		return false, err
	}
	if state.FirstFailureAt == nil || now.Sub(*state.FirstFailureAt) < threshold {
		return false, nil
	}
	if state.OpenGapStatus == "open" {
		return false, nil
	}

	generation := situation.NewGapGenerationID(*state.FirstFailureAt)
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM slack_delivery_gaps WHERE id = ?`, generation).Scan(&exists); err != nil {
		return false, fmt.Errorf("store: check delivery gap generation: %w", err)
	}
	if exists > 0 {
		return false, nil
	}

	affected, delayed, err := replayableBacklogTx(ctx, tx, canonicalTime(now))
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO slack_delivery_gaps (id, status, opened_at, affected_situation_count, delayed_effect_count)
		VALUES (?, 'open', ?, ?, ?)`,
		generation, canonicalTime(*state.FirstFailureAt), affected, delayed); err != nil {
		return false, fmt.Errorf("store: insert delivery gap generation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = ?, updated_at = ? WHERE id = 1`,
		generation, canonicalTime(now)); err != nil {
		return false, fmt.Errorf("store: point delivery state at the open generation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: commit open delivery gap: %w", err)
	}
	return true, nil
}

// RecoverDeliveryGap moves the oldest open generation into replay in one
// idempotent transaction: it closes the failure window, recomputes the
// backlog the notice reports, and creates the single claimable
// installation_gap_recovery intent that must deliver before any of that
// backlog does. It reports the generation it recovered.
//
// Closing the window here as well as in ObserveSlackSuccess is deliberate,
// not redundant: recovery is by definition proof that Slack answered, and
// the next generation's identity is derived from the NEXT window's anchor
// (NewGapGenerationID). A caller that recovered without first clearing the
// old anchor would leave a second outage unable to open a generation of its
// own, because it would keep computing the completed generation's id.
func (s *Store) RecoverDeliveryGap(ctx context.Context, now time.Time) (string, bool, error) {
	now = now.UTC()
	nowStr := canonicalTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store: begin recover delivery gap: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var generation string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM slack_delivery_gaps WHERE status = 'open' ORDER BY opened_at ASC, id ASC LIMIT 1`).
		Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: select open delivery gap: %w", err)
	}

	affected, delayed, err := replayableBacklogTx(ctx, tx, nowStr)
	if err != nil {
		return "", false, err
	}
	notice, err := situation.GapRecoveryIntent(generation, now)
	if err != nil {
		return "", false, fmt.Errorf("store: build gap recovery notice: %w", err)
	}
	var existing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_intents WHERE id = ?`, notice.ID).Scan(&existing); err != nil {
		return "", false, fmt.Errorf("store: check gap recovery notice: %w", err)
	}
	if existing == 0 {
		if err := insertNotificationIntentTx(ctx, tx, notice); err != nil {
			return "", false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_gaps
		SET status = 'replaying', recovered_at = ?, affected_situation_count = ?, delayed_effect_count = ?,
		    recovery_notice_intent_id = ?
		WHERE id = ? AND status = 'open'`,
		nowStr, affected, delayed, notice.ID, generation); err != nil {
		return "", false, fmt.Errorf("store: move delivery gap into replay: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_state SET first_failure_at = NULL, last_success_at = ?, updated_at = ?
		WHERE id = 1`, nowStr, nowStr); err != nil {
		return "", false, fmt.Errorf("store: close the recovered failure window: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("store: commit recover delivery gap: %w", err)
	}
	return generation, true, nil
}

// CompleteDeliveryGap completes the oldest replaying generation whose
// recovery notice has been delivered and whose replayable backlog has
// drained — never earlier. It reports the generation it completed.
//
// Only work that already existed when the generation recovered counts as
// replayable, so ordinary post-recovery delivery never holds a generation
// open, and a busy installation still reaches "complete".
func (s *Store) CompleteDeliveryGap(ctx context.Context, now time.Time) (string, bool, error) {
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store: begin complete delivery gap: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var generation, recoveredAt string
	err = tx.QueryRowContext(ctx, `
		SELECT g.id, g.recovered_at
		FROM slack_delivery_gaps g
		JOIN notification_intents ni ON ni.id = g.recovery_notice_intent_id
		WHERE g.status = 'replaying' AND ni.status = 'delivered'
		ORDER BY g.opened_at ASC, g.id ASC
		LIMIT 1`).Scan(&generation, &recoveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: select replaying delivery gap: %w", err)
	}

	var remaining int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM notification_intents
		WHERE status = 'pending' AND situation_id IS NOT NULL AND created_at <= ?`, recoveredAt).
		Scan(&remaining); err != nil {
		return "", false, fmt.Errorf("store: count replayable notification intents: %w", err)
	}
	if remaining > 0 {
		return "", false, nil
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_gaps SET status = 'complete', completed_at = ? WHERE id = ? AND status = 'replaying'`,
		canonicalTime(now), generation); err != nil {
		return "", false, fmt.Errorf("store: complete delivery gap: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_state SET open_gap_generation = NULL, updated_at = ?
		WHERE id = 1 AND open_gap_generation = ?`, canonicalTime(now), generation); err != nil {
		return "", false, fmt.Errorf("store: clear the completed generation from delivery state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("store: commit complete delivery gap: %w", err)
	}
	return generation, true, nil
}

// ReactivateConfigurationBlocked applies corrected Slack configuration: it
// advances the durable configuration generation to configurationGeneration
// and returns every blocked_configuration intent to pending, due now, with
// its attempt count preserved. It reports how many it reactivated.
//
// The generation is a compare-and-set, not a blind write: a value that does
// not advance the stored one reactivates nothing, so a restart loop can
// never replay the same correction twice.
//
// Root projections need care (see reactivateBlockedRootSyncTx): returning
// every blocked row to pending in one statement violates migration 0018's
// single-pending-root_sync index the moment a Situation holds both a blocked
// root and a newer pending one, which would roll back the whole
// configuration-generation advance and strand EVERY Situation's
// reactivation, permanently.
func (s *Store) ReactivateConfigurationBlocked(ctx context.Context, configurationGeneration int64,
	now time.Time) (int, error) {
	if configurationGeneration <= 0 {
		return 0, errors.New("store: configuration generation must be positive")
	}
	now = now.UTC()
	nowStr := canonicalTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin reactivate configuration-blocked intents: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE slack_delivery_state SET configuration_generation = ?, updated_at = ?
		WHERE id = 1 AND configuration_generation < ?`, configurationGeneration, nowStr, configurationGeneration)
	if err != nil {
		return 0, fmt.Errorf("store: advance configuration generation: %w", err)
	}
	advanced, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count advanced configuration generation: %w", err)
	}
	if advanced == 0 {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("store: commit unchanged configuration generation: %w", err)
		}
		return 0, nil
	}

	n, err := reactivateBlockedIntentsTx(ctx, tx, nowStr)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit reactivate configuration-blocked intents: %w", err)
	}
	return n, nil
}

// replayableBacklogTx counts the Situation-scoped delivery obligations
// outstanding as of asOf: how many distinct Situations, and how many
// effects. These are exactly the numbers the recovery notice reports.
func replayableBacklogTx(ctx context.Context, tx *sql.Tx, asOf string) (int, int, error) {
	var affected, delayed int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT situation_id), COUNT(*)
		FROM notification_intents
		WHERE status = 'pending' AND situation_id IS NOT NULL AND created_at <= ?`, asOf).
		Scan(&affected, &delayed); err != nil {
		return 0, 0, fmt.Errorf("store: count delayed notification backlog: %w", err)
	}
	return affected, delayed, nil
}

// reactivateBlockedIntentsTx returns every eligible blocked_configuration
// intent to pending, due now, attempts preserved.
//
// It is split by effect class on purpose. thread_append, broadcast_handoff,
// and installation_gap_recovery are immutable one-per-subject effects with no
// pending-uniqueness constraint, so they reactivate in one statement. Root
// projections cannot: migration 0018's
// notification_intents_root_sync_pending_idx allows a Situation exactly ONE
// pending root_sync, and supersession only ever retires a PENDING one — so a
// Situation can legitimately hold a blocked root beside a newer pending root,
// and blindly reactivating the blocked one aborts the transaction.
func reactivateBlockedIntentsTx(ctx context.Context, tx *sql.Tx, nowStr string) (int, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE notification_intents
		SET status = 'pending', retry_at = ?, claim_owner = NULL, lease_expires_at = NULL
		WHERE status = 'blocked_configuration' AND effect_class != 'root_sync'`, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: reactivate configuration-blocked effects: %w", err)
	}
	total, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count reactivated notification effects: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT situation_id FROM notification_intents
		WHERE status = 'blocked_configuration' AND effect_class = 'root_sync' AND situation_id IS NOT NULL
		ORDER BY situation_id ASC`)
	if err != nil {
		return 0, fmt.Errorf("store: list situations with blocked root projections: %w", err)
	}
	situationIDs, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read situations with blocked root projections: %w", err)
	}
	for _, situationID := range situationIDs {
		n, err := reactivateBlockedRootSyncTx(ctx, tx, situationID, nowStr)
		if err != nil {
			return 0, err
		}
		total += int64(n)
	}
	return int(total), nil
}

// liveRootProjection is one root_sync still capable of holding its
// Situation's single pending-root slot: pending, or blocked on
// configuration. delivered/failed/withheld/superseded rows are resolved
// outcomes and never compete for it.
type liveRootProjection struct {
	id     string
	status string
}

// reactivateBlockedRootSyncTx restores exactly one pending root projection
// for situationID and reports how many blocked roots it reactivated (0 or 1).
//
// The newest live projection is the one corrected configuration should
// deliver — it renders current state, and every older one would render state
// already superseded by it. Two cases:
//
//   - The newest is ALREADY pending. It holds the slot and says everything
//     the older blocked ones would; they stay blocked_configuration, which
//     migration 0018 explicitly calls a resolved outcome ("never one already
//     delivered/blocked/failed/withheld ... not live candidates a newer
//     root_sync coalesces away"). Nothing is stranded: the pending projection
//     delivers the root coordinates every dependent effect waits on.
//
//   - The newest is blocked. It is reactivated, and every older live
//     projection is coalesced into it through Task 5's own
//     supersedePendingRootSyncTx — the same supersession a newer commit
//     performs. An older BLOCKED one reaches `superseded` the only way the
//     schema permits, by being reactivated first: that is exactly what
//     happened (corrected configuration returned it to pending) immediately
//     followed by the newer projection coalescing it.
//
// The order is what keeps the unique index satisfied at every step: the
// pre-existing pending row is retired first, then each older blocked row is
// made pending and immediately coalesced, and only then does the keeper
// become pending. At no point do two root projections hold the slot.
func reactivateBlockedRootSyncTx(ctx context.Context, tx *sql.Tx, situationID, nowStr string) (int, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, status FROM notification_intents
		WHERE situation_id = ? AND effect_class = 'root_sync'
		  AND status IN ('pending','blocked_configuration')
		ORDER BY created_at ASC, id ASC`, situationID)
	if err != nil {
		return 0, fmt.Errorf("store: list live root projections for %s: %w", situationID, err)
	}
	live, err := scanLiveRootProjections(rows)
	if err != nil {
		return 0, err
	}
	if len(live) == 0 {
		return 0, nil
	}
	keeper := live[len(live)-1]
	if keeper.status == string(situationmodel.IntentPending) {
		return 0, nil
	}

	// Retire whichever projection currently holds the pending slot, if any.
	if err := supersedePendingRootSyncTx(ctx, tx, situationID, keeper.id); err != nil {
		return 0, err
	}
	for _, older := range live[:len(live)-1] {
		if older.status != string(situationmodel.IntentBlockedConfiguration) {
			continue // already retired by the supersession above
		}
		if err := setNotificationIntentPendingTx(ctx, tx, older.id, "blocked_configuration", nowStr); err != nil {
			return 0, err
		}
		if err := supersedePendingRootSyncTx(ctx, tx, situationID, keeper.id); err != nil {
			return 0, err
		}
	}
	if err := setNotificationIntentPendingTx(ctx, tx, keeper.id, "blocked_configuration", nowStr); err != nil {
		return 0, err
	}
	return 1, nil
}

func scanLiveRootProjections(rows *sql.Rows) ([]liveRootProjection, error) {
	defer func() { _ = rows.Close() }()
	out := []liveRootProjection{}
	for rows.Next() {
		var p liveRootProjection
		if err := rows.Scan(&p.id, &p.status); err != nil {
			return nil, fmt.Errorf("store: scan live root projection: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate live root projections: %w", err)
	}
	return out, nil
}

// setNotificationIntentPendingTx returns one intent in fromStatus to pending,
// due now, keeping its attempt count. It is fenced on the expected status so
// a row that moved on changes nothing.
func setNotificationIntentPendingTx(ctx context.Context, tx *sql.Tx, intentID, fromStatus, nowStr string) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE notification_intents
		SET status = 'pending', retry_at = ?, claim_owner = NULL, lease_expires_at = NULL
		WHERE id = ? AND status = ?`, nowStr, intentID, fromStatus)
	if err != nil {
		return fmt.Errorf("store: return notification intent %s to pending: %w", intentID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count notification intent %s returned to pending: %w", intentID, err)
	}
	if n != 1 {
		return fmt.Errorf("store: notification intent %s is no longer %s", intentID, fromStatus)
	}
	return nil
}
