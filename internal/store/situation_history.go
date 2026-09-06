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

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 5: durable Situation history persistence. Everything here
// runs INSIDE Plan 2's existing fenced CommitController transaction — this
// file opens no transaction of its own, so a Situation's authoritative
// state and its durable history can never diverge: either both land or
// neither does.
// ----------------------------------------------------------------------

// ErrSituationHistoryConflict means the derived history does not continue
// the Situation's durable history: its first Transition is not the one that
// follows the Situation's current Transition sequence, or its Transitions
// are not contiguous among themselves. The controller derived it against a
// prior Transition that is no longer current, so the whole commit is
// rejected rather than writing a gap into an immutable ledger.
var ErrSituationHistoryConflict = errors.New("store: situation history does not continue the current transition sequence")

// SupersessionReasonNewerRootProjection is the one supersession reason this
// task writes: a newer committed root projection replaced a still-pending
// older one (R4). It is the store's own closed vocabulary for
// notification_intents.supersession_reason, the same way Plan 2's
// controller owns controller_parked_reason's closed codes.
const SupersessionReasonNewerRootProjection = "newer_root_projection"

// historyCommitSteps names every durable write step applyHistoryCommitTx
// performs, in order. Tests iterate it to inject a failure after each step
// and prove the whole transaction rolls back (Task 5 brief, Step 1).
var historyCommitSteps = []string{
	"transitions",
	"episode_summary",
	"transition_stream",
	"artifacts",
	"intents",
	"current_pointer",
}

// historyCommitFailpoint is a test-only seam: when non-nil it is consulted
// after each step in historyCommitSteps, and a non-nil result aborts the
// enclosing CommitController transaction. It is nil in every production
// build and costs one nil check per step.
var historyCommitFailpoint func(step string) error

func historyStepDone(step string) error {
	if historyCommitFailpoint == nil {
		return nil
	}
	return historyCommitFailpoint(step)
}

// applyHistoryCommitTx writes one reconciliation's derived history inside
// the caller's already-fenced transaction: every Transition in sequence
// order, one Episode-summary version folded per Transition, one
// transition-stream row per Transition, the consumed operator artifacts'
// journaling cursor (R1), every notification intent (superseding any older
// pending root projection first, R4), and finally the Situation's advanced
// current-Transition pointer.
//
// The Episode summary is re-folded here, from the summary row read inside
// THIS transaction, rather than trusting the single final summary
// HistoryCommit carries: migration 0017's monotonic trigger requires every
// summary write to advance the version by exactly one, so an N-Transition
// commit needs N successive folds, and re-folding from durable truth also
// proves the controller derived its history against the summary that is
// actually current. The final fold is compared against HistoryCommit's own
// canonical summary and a mismatch fails the whole commit closed.
func applyHistoryCommitTx(ctx context.Context, tx *sql.Tx, situationID string, history *situation.HistoryCommit, now time.Time) error {
	if history == nil {
		return nil
	}
	if err := validateHistoryCommit(situationID, history); err != nil {
		return err
	}

	priorSequence, err := currentTransitionSequenceTx(ctx, tx, situationID)
	if err != nil {
		return err
	}
	if len(history.Transitions) > 0 && history.Transitions[0].Sequence != priorSequence+1 {
		return fmt.Errorf("%w: first transition sequence %d does not follow current sequence %d",
			ErrSituationHistoryConflict, history.Transitions[0].Sequence, priorSequence)
	}

	for i := range history.Transitions {
		if err := insertTransitionTx(ctx, tx, history.Transitions[i]); err != nil {
			return err
		}
	}
	if err := historyStepDone("transitions"); err != nil {
		return err
	}

	if err := foldEpisodeSummaryTx(ctx, tx, situationID, history); err != nil {
		return err
	}
	if err := historyStepDone("episode_summary"); err != nil {
		return err
	}

	for i := range history.Transitions {
		if err := insertTransitionStreamTx(ctx, tx, history.Transitions[i], now); err != nil {
			return err
		}
	}
	if err := historyStepDone("transition_stream"); err != nil {
		return err
	}

	for i := range history.Transitions {
		tr := history.Transitions[i]
		if tr.OperatorArtifactInputID == nil {
			continue
		}
		if err := journalOperatorArtifactTx(ctx, tx, *tr.OperatorArtifactInputID, tr.ID); err != nil {
			return err
		}
	}
	if err := historyStepDone("artifacts"); err != nil {
		return err
	}

	if err := insertNotificationIntentsTx(ctx, tx, situationID, history.Intents); err != nil {
		return err
	}
	if err := historyStepDone("intents"); err != nil {
		return err
	}

	if len(history.Transitions) > 0 {
		last := history.Transitions[len(history.Transitions)-1]
		if _, err := tx.ExecContext(ctx, `
			UPDATE situations SET current_transition_id = ?, current_transition_sequence = ? WHERE id = ?`,
			last.ID, last.Sequence, situationID); err != nil {
			return fmt.Errorf("store: advance current transition pointer: %w", err)
		}
	}
	return historyStepDone("current_pointer")
}

// validateHistoryCommit checks the derived history's own coherence before
// any write: every Transition belongs to this Situation, passes its model
// validation, and follows its predecessor by exactly one sequence; the
// summary is present exactly when Transitions are and names the last one;
// and every intent validates and belongs here.
func validateHistoryCommit(situationID string, history *situation.HistoryCommit) error {
	for i, tr := range history.Transitions {
		if tr.SituationID != situationID {
			return fmt.Errorf("store: history transition %d belongs to situation %q, not %q", i, tr.SituationID, situationID)
		}
		if err := tr.Validate(); err != nil {
			return fmt.Errorf("store: history transition %d: %w", i, err)
		}
		if i > 0 && tr.Sequence != history.Transitions[i-1].Sequence+1 {
			return fmt.Errorf("%w: transition %d sequence %d does not follow %d",
				ErrSituationHistoryConflict, i, tr.Sequence, history.Transitions[i-1].Sequence)
		}
	}
	switch {
	case len(history.Transitions) == 0 && history.Summary != nil:
		return errors.New("store: history commit carries a summary with no transitions")
	case len(history.Transitions) > 0 && history.Summary == nil:
		return errors.New("store: history commit carries transitions with no folded summary")
	}
	if history.Summary != nil {
		if err := history.Summary.Validate(); err != nil {
			return fmt.Errorf("store: history episode summary: %w", err)
		}
	}
	for i, intent := range history.Intents {
		if err := intent.Validate(); err != nil {
			return fmt.Errorf("store: history notification intent %d: %w", i, err)
		}
		if intent.SituationID == nil || *intent.SituationID != situationID {
			return fmt.Errorf("store: history notification intent %d does not belong to situation %q", i, situationID)
		}
	}
	return nil
}

func currentTransitionSequenceTx(ctx context.Context, tx *sql.Tx, situationID string) (int, error) {
	var seq int
	err := tx.QueryRowContext(ctx, `SELECT current_transition_sequence FROM situations WHERE id = ?`, situationID).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: read current transition sequence: %w", err)
	}
	return seq, nil
}

// ----------------------------------------------------------------------
// Transition writer/scanner
// ----------------------------------------------------------------------

func insertTransitionTx(ctx context.Context, tx *sql.Tx, t situationmodel.Transition) error {
	contractJSON, err := json.Marshal(t.ActionContract)
	if err != nil {
		return fmt.Errorf("store: marshal transition action contract: %w", err)
	}
	journalJSON, err := json.Marshal(t.Journal)
	if err != nil {
		return fmt.Errorf("store: marshal transition journal: %w", err)
	}
	projectionJSON, err := json.Marshal(t.Projection)
	if err != nil {
		return fmt.Errorf("store: marshal transition projection: %w", err)
	}
	refs := t.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("store: marshal transition evidence refs: %w", err)
	}
	var priority any
	if t.InterruptionPriority != nil {
		priority = string(*t.InterruptionPriority)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, assessment_id,
			lifecycle, attention, action_contract_json, sufficient_reason_id, interruption_priority,
			reason, journal_kind, journal_json, projection_json, operator_artifact_input_id,
			evidence_refs_json, actor, drill, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SituationID, t.Sequence, t.InputVersion, t.MaterialFactHash, nullableString(t.AssessmentID),
		string(t.Lifecycle), string(t.Attention), string(contractJSON), nullableString(t.SufficientReasonID), priority,
		string(t.Reason), string(t.JournalKind), string(journalJSON), string(projectionJSON),
		nullableString(t.OperatorArtifactInputID),
		string(refsJSON), string(t.Actor), boolToInt(t.Drill), canonicalTime(t.CreatedAt)); err != nil {
		return fmt.Errorf("store: insert situation transition %s: %w", t.ID, err)
	}
	return nil
}

// transitionColumns is the exact SELECT list scanTransition consumes.
const transitionColumns = `id, situation_id, sequence, input_version, material_fact_hash, assessment_id,
	lifecycle, attention, action_contract_json, sufficient_reason_id, interruption_priority,
	reason, journal_kind, journal_json, projection_json, operator_artifact_input_id,
	evidence_refs_json, actor, drill, created_at`

func scanTransition(row scanner) (situationmodel.Transition, error) {
	var t situationmodel.Transition
	var assessmentID, reasonID, priority, artifactInputID sql.NullString
	var lifecycle, attention, reason, journalKind, actor string
	var contractJSON, journalJSON, projectionJSON, refsJSON, createdAt string
	var drill int
	if err := row.Scan(&t.ID, &t.SituationID, &t.Sequence, &t.InputVersion, &t.MaterialFactHash, &assessmentID,
		&lifecycle, &attention, &contractJSON, &reasonID, &priority,
		&reason, &journalKind, &journalJSON, &projectionJSON, &artifactInputID,
		&refsJSON, &actor, &drill, &createdAt); err != nil {
		return situationmodel.Transition{}, err
	}
	t.Lifecycle = situationmodel.Lifecycle(lifecycle)
	t.Attention = situationmodel.Attention(attention)
	t.Reason = situationmodel.TransitionReason(reason)
	t.JournalKind = situationmodel.JournalKind(journalKind)
	t.Actor = situationmodel.TransitionActor(actor)
	t.Drill = drill == 1
	if assessmentID.Valid {
		t.AssessmentID = &assessmentID.String
	}
	if reasonID.Valid {
		t.SufficientReasonID = &reasonID.String
	}
	if priority.Valid {
		p := situationmodel.InterruptionPriority(priority.String)
		t.InterruptionPriority = &p
	}
	if artifactInputID.Valid {
		t.OperatorArtifactInputID = &artifactInputID.String
	}
	if err := json.Unmarshal([]byte(contractJSON), &t.ActionContract); err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: unmarshal transition %s action contract: %w", t.ID, err)
	}
	if err := json.Unmarshal([]byte(journalJSON), &t.Journal); err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: unmarshal transition %s journal: %w", t.ID, err)
	}
	if err := json.Unmarshal([]byte(projectionJSON), &t.Projection); err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: unmarshal transition %s projection: %w", t.ID, err)
	}
	if err := json.Unmarshal([]byte(refsJSON), &t.EvidenceRefs); err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: unmarshal transition %s evidence refs: %w", t.ID, err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: parse transition %s created_at: %w", t.ID, err)
	}
	t.CreatedAt = parsed.UTC()
	return t, nil
}

// loadCurrentTransitionTx reads the Situation's current Transition (the one
// situations.current_transition_id names), or nil when none exists yet.
func loadCurrentTransitionTx(ctx context.Context, tx *sql.Tx, situationID string) (*situationmodel.Transition, error) {
	var id sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT current_transition_id FROM situations WHERE id = ?`, situationID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read current transition id: %w", err)
	}
	if !id.Valid {
		return nil, nil //nolint:nilnil // "no Transition yet" is a legitimate, non-error state.
	}
	tr, err := scanTransition(tx.QueryRowContext(ctx,
		`SELECT `+transitionColumns+` FROM situation_transitions WHERE id = ?`, id.String))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: current transition %s is missing from the ledger", id.String)
	}
	if err != nil {
		return nil, fmt.Errorf("store: read current transition: %w", err)
	}
	return &tr, nil
}

// ----------------------------------------------------------------------
// Episode summary writer/scanner
// ----------------------------------------------------------------------

// foldEpisodeSummaryTx folds this commit's Transitions onto the Situation's
// durable current summary, writing one version per Transition, and proves
// the result equals the summary the controller derived.
func foldEpisodeSummaryTx(ctx context.Context, tx *sql.Tx, situationID string, history *situation.HistoryCommit) error {
	if len(history.Transitions) == 0 {
		return nil
	}
	prior, err := loadEpisodeSummaryTx(ctx, tx, situationID)
	if err != nil {
		return err
	}
	exists := prior != nil
	for i, tr := range history.Transitions {
		folded, err := situation.ProjectEpisode(prior, tr)
		if err != nil {
			return fmt.Errorf("store: fold episode summary at transition %d: %w", i, err)
		}
		if err := writeEpisodeSummaryTx(ctx, tx, folded, exists); err != nil {
			return err
		}
		exists = true
		prior = &folded
	}

	got, err := json.Marshal(prior)
	if err != nil {
		return fmt.Errorf("store: marshal folded episode summary: %w", err)
	}
	want, err := json.Marshal(history.Summary)
	if err != nil {
		return fmt.Errorf("store: marshal derived episode summary: %w", err)
	}
	if string(got) != string(want) {
		return fmt.Errorf("store: folded episode summary %s does not match the committed summary %s", got, want)
	}
	return nil
}

func writeEpisodeSummaryTx(ctx context.Context, tx *sql.Tx, s situationmodel.EpisodeSummary, exists bool) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("store: marshal episode summary: %w", err)
	}
	query := `INSERT INTO situation_episode_summaries (situation_id, version, source_transition_sequence, summary_json, updated_at)
		VALUES (?, ?, ?, ?, ?)`
	if exists {
		query = `UPDATE situation_episode_summaries
			SET version = ?, source_transition_sequence = ?, summary_json = ?, updated_at = ?
			WHERE situation_id = ?`
		if _, err := tx.ExecContext(ctx, query, s.Version, s.SourceTransitionSequence,
			string(payload), canonicalTime(s.UpdatedAt), s.SituationID); err != nil {
			return fmt.Errorf("store: update episode summary for %s: %w", s.SituationID, err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, query, s.SituationID, s.Version, s.SourceTransitionSequence,
		string(payload), canonicalTime(s.UpdatedAt)); err != nil {
		return fmt.Errorf("store: insert episode summary for %s: %w", s.SituationID, err)
	}
	return nil
}

func loadEpisodeSummaryTx(ctx context.Context, tx *sql.Tx, situationID string) (*situationmodel.EpisodeSummary, error) {
	var payload string
	err := tx.QueryRowContext(ctx,
		`SELECT summary_json FROM situation_episode_summaries WHERE situation_id = ?`, situationID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no summary yet" is a legitimate, non-error state.
	}
	if err != nil {
		return nil, fmt.Errorf("store: read episode summary: %w", err)
	}
	var summary situationmodel.EpisodeSummary
	if err := json.Unmarshal([]byte(payload), &summary); err != nil {
		return nil, fmt.Errorf("store: unmarshal episode summary for %s: %w", situationID, err)
	}
	return &summary, nil
}

// ----------------------------------------------------------------------
// Transition stream writer
// ----------------------------------------------------------------------

// transitionStreamID derives the stdout-stream outbox row's identity from
// the Transition it records, so the row is as deterministic as the
// Transition itself.
func transitionStreamID(transitionID string) string { return "stream-" + transitionID }

func insertTransitionStreamTx(ctx context.Context, tx *sql.Tx, t situationmodel.Transition, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_transition_stream (id, transition_id, situation_id, sequence, status, created_at)
		VALUES (?, ?, ?, ?, 'pending', ?)`,
		transitionStreamID(t.ID), t.ID, t.SituationID, t.Sequence, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: insert transition stream row for %s: %w", t.ID, err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Operator-artifact journaling cursor (R1)
// ----------------------------------------------------------------------

// journalOperatorArtifactTx marks one applied, pending artifact input as
// journaled by the Transition that consumed it. A row that is not pending
// any more (another commit consumed it, or R2 recorded it against a
// terminal owner) fails the whole commit closed rather than silently
// journaling nothing.
func journalOperatorArtifactTx(ctx context.Context, tx *sql.Tx, inputID, transitionID string) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET journal_state = 'journaled', journaled_transition_id = ?
		WHERE id = ? AND journal_state = 'pending'`, transitionID, inputID)
	if err != nil {
		return fmt.Errorf("store: journal operator artifact %s: %w", inputID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count journaled operator artifact %s: %w", inputID, err)
	}
	if n != 1 {
		return fmt.Errorf("store: operator artifact %s is no longer pending journaling", inputID)
	}
	return nil
}

// ----------------------------------------------------------------------
// Notification intents
// ----------------------------------------------------------------------

// insertNotificationIntentsTx supersedes any still-pending root projection
// this commit replaces and then inserts every planned intent. Migration
// 0018 allows at most one pending, unsuperseded root_sync per Situation, so
// the supersession and its replacement have to happen in this one
// transaction or not at all (R4).
func insertNotificationIntentsTx(ctx context.Context, tx *sql.Tx, situationID string, intents []situationmodel.NotificationIntent) error {
	if len(intents) == 0 {
		return nil
	}
	for _, intent := range intents {
		if intent.EffectClass != situationmodel.EffectRootSync || intent.Status != situationmodel.IntentPending {
			continue
		}
		if err := supersedePendingRootSyncTx(ctx, tx, situationID, intent.ID); err != nil {
			return err
		}
		break // PlanNotificationIntents never plans two root projections per commit.
	}
	for i := range intents {
		if err := insertNotificationIntentTx(ctx, tx, intents[i]); err != nil {
			return err
		}
	}
	return nil
}

// supersedePendingRootSyncTx retires every currently-pending root_sync for
// situationID in favour of replacementID. replacementID is inserted later
// in this same transaction, so foreign-key enforcement is deferred to
// COMMIT for the duration: the self-referencing replacement_intent_id FK
// and the "at most one pending root_sync" index would otherwise make the
// two writes impossible to order. Deferral changes when a violation is
// reported, never whether the transaction is atomic.
//
// FOR THE NOTIFICATION WORKER: superseding CLEARS the intent's
// claim_owner/lease_expires_at (migration 0018's
// `claim_owner IS NULL OR status = 'pending'` CHECK forbids leaving them on
// a non-pending row) and its retry_at. A worker holding a live claim on a
// root_sync can therefore have that claim taken out from under it by a
// concurrent controller commit, and must re-read the intent's status before
// writing any delivery outcome: a superseded row can never become
// 'delivered', because 0018's
// `CHECK ((status = 'superseded') = (supersession_reason IS NOT NULL))`
// aborts that write. Treat the lost claim as the expected R4 outcome — the
// newer root projection supersedes what this one would have posted — not as
// a delivery failure. Supersession is performed here, inside the
// authoritative commit, precisely because the pending-root index makes it
// unorderable anywhere else; the worker must not reimplement it.
func supersedePendingRootSyncTx(ctx context.Context, tx *sql.Tx, situationID, replacementID string) error {
	var pending int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM notification_intents
		WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`, situationID).Scan(&pending); err != nil {
		return fmt.Errorf("store: count pending root projections: %w", err)
	}
	if pending == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return fmt.Errorf("store: defer foreign keys for root supersession: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_intents
		SET status = 'superseded', supersession_reason = ?, replacement_intent_id = ?,
		    claim_owner = NULL, lease_expires_at = NULL, retry_at = NULL
		WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`,
		SupersessionReasonNewerRootProjection, replacementID, situationID); err != nil {
		return fmt.Errorf("store: supersede pending root projections: %w", err)
	}
	return nil
}

func insertNotificationIntentTx(ctx context.Context, tx *sql.Tx, n situationmodel.NotificationIntent) error {
	var priority any
	if n.InterruptionPriority != nil {
		priority = string(*n.InterruptionPriority)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			summary_version, gap_generation, requires_root, main_channel_poke, interruption_priority,
			contract_deadline_at, client_message_id, status, claim_owner, claim_token, lease_expires_at,
			attempt_count, last_error_class, retry_at, supersession_reason, replacement_intent_id,
			delivered_as, channel, message_ts, created_at, delivered_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.IdempotencyKey, string(n.EffectClass), nullableString(n.SituationID), nullableString(n.TransitionID),
		nullableInt(n.TransitionSequence), nullableInt(n.SummaryVersion), nullableString(n.GapGeneration),
		boolToInt(n.RequiresRoot), boolToInt(n.MainChannelPoke), priority,
		nullableTimePtr(n.ContractDeadlineAt), n.ClientMessageID, string(n.Status),
		nullableString(n.ClaimOwner), n.ClaimToken, nullableTimePtr(n.LeaseExpiresAt),
		n.AttemptCount, nullableString(n.LastErrorClass), nullableTimePtr(n.RetryAt),
		nullableString(n.SupersessionReason), nullableString(n.ReplacementIntentID),
		nullableString(n.DeliveredAs), nullableString(n.Channel), nullableString(n.MessageTS),
		canonicalTime(n.CreatedAt), nullableTimePtr(n.DeliveredAt)); err != nil {
		return fmt.Errorf("store: insert notification intent %s: %w", n.ID, err)
	}
	return nil
}

// notificationIntentColumns is the exact SELECT list scanNotificationIntent
// consumes.
const notificationIntentColumns = `id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
	summary_version, gap_generation, requires_root, main_channel_poke, interruption_priority,
	contract_deadline_at, client_message_id, status, claim_owner, claim_token, lease_expires_at,
	attempt_count, last_error_class, retry_at, supersession_reason, replacement_intent_id,
	delivered_as, channel, message_ts, created_at, delivered_at`

func scanNotificationIntent(row scanner) (situationmodel.NotificationIntent, error) {
	var n situationmodel.NotificationIntent
	var effectClass, status, clientMessageID, createdAt string
	var situationID, transitionID, gapGeneration, priority, claimOwner sql.NullString
	var lastErrorClass, supersessionReason, replacementID, deliveredAs, channel, messageTS sql.NullString
	var contractDeadlineAt, leaseExpiresAt, retryAt, deliveredAt sql.NullString
	var transitionSequence, summaryVersion sql.NullInt64
	var requiresRoot, mainChannelPoke int
	if err := row.Scan(&n.ID, &n.IdempotencyKey, &effectClass, &situationID, &transitionID, &transitionSequence,
		&summaryVersion, &gapGeneration, &requiresRoot, &mainChannelPoke, &priority,
		&contractDeadlineAt, &clientMessageID, &status, &claimOwner, &n.ClaimToken, &leaseExpiresAt,
		&n.AttemptCount, &lastErrorClass, &retryAt, &supersessionReason, &replacementID,
		&deliveredAs, &channel, &messageTS, &createdAt, &deliveredAt); err != nil {
		return situationmodel.NotificationIntent{}, err
	}
	n.EffectClass = situationmodel.EffectClass(effectClass)
	n.Status = situationmodel.IntentStatus(status)
	n.ClientMessageID = clientMessageID
	n.RequiresRoot = requiresRoot == 1
	n.MainChannelPoke = mainChannelPoke == 1
	for _, f := range []struct {
		src sql.NullString
		dst **string
	}{
		{situationID, &n.SituationID}, {transitionID, &n.TransitionID}, {gapGeneration, &n.GapGeneration},
		{claimOwner, &n.ClaimOwner}, {lastErrorClass, &n.LastErrorClass}, {supersessionReason, &n.SupersessionReason},
		{replacementID, &n.ReplacementIntentID}, {deliveredAs, &n.DeliveredAs}, {channel, &n.Channel},
		{messageTS, &n.MessageTS},
	} {
		if f.src.Valid {
			v := f.src.String
			*f.dst = &v
		}
	}
	if transitionSequence.Valid {
		v := int(transitionSequence.Int64)
		n.TransitionSequence = &v
	}
	if summaryVersion.Valid {
		v := int(summaryVersion.Int64)
		n.SummaryVersion = &v
	}
	if priority.Valid {
		p := situationmodel.InterruptionPriority(priority.String)
		n.InterruptionPriority = &p
	}
	for _, f := range []struct {
		src sql.NullString
		dst **time.Time
	}{
		{contractDeadlineAt, &n.ContractDeadlineAt}, {leaseExpiresAt, &n.LeaseExpiresAt},
		{retryAt, &n.RetryAt}, {deliveredAt, &n.DeliveredAt},
	} {
		parsed, err := timePtr(f.src)
		if err != nil {
			return situationmodel.NotificationIntent{}, err
		}
		*f.dst = parsed
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return situationmodel.NotificationIntent{}, fmt.Errorf("store: parse notification intent %s created_at: %w", n.ID, err)
	}
	n.CreatedAt = parsed.UTC()
	return n, nil
}

// ----------------------------------------------------------------------
// Small local helpers.
// ----------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

// prefixedTransitionColumns is transitionColumns qualified with the `t`
// table alias, for the joined reads that also select another table's
// columns. Derived from transitionColumns itself so the two can never
// drift apart.
var prefixedTransitionColumns = qualifyColumns(transitionColumns, "t")

func qualifyColumns(list, alias string) string {
	parts := strings.Split(list, ",")
	for i := range parts {
		parts[i] = alias + "." + strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ", ")
}

// scanStreamEntry scans one `SELECT st.id, <prefixedTransitionColumns>` row:
// the stream row's own id into streamID, then the joined Transition.
func scanStreamEntry(rows *sql.Rows, streamID *string) (situationmodel.Transition, error) {
	tr, err := scanTransition(prefixedScanner{rows: rows, prefix: []any{streamID}})
	if err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: scan pending transition stream entry: %w", err)
	}
	return tr, nil
}

// prefixedScanner lets scanTransition consume a row that carries extra
// leading columns (store.scanner's own shape), without duplicating its
// column list.
type prefixedScanner struct {
	rows   *sql.Rows
	prefix []any
}

func (p prefixedScanner) Scan(dest ...any) error {
	all := make([]any, 0, len(p.prefix)+len(dest))
	all = append(all, p.prefix...)
	all = append(all, dest...)
	return p.rows.Scan(all...)
}
