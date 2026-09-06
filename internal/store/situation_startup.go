// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
	"time"
)

// ----------------------------------------------------------------------
// Plan 3 Task 9: the two startup-only, zero-outward-effect catch-up sweeps
// spec.md's own startup order names between Plan 1/2 reconstruction and
// Receivers starting (steps 3 and 6).
//
// Both do exactly one thing: pull a nonterminal Situation's
// next_assessment_at forward so the ordinary controller claim path picks it
// up on its next round. Neither writes history, creates a notification
// intent, or calls anything outward — startup never publishes merely
// because the binary restarted. What the controller then commits is decided
// by the same materiality and publication rules every other cycle uses, so
// a Situation whose truth has not changed produces no Transition and no
// Slack effect at all.
// ----------------------------------------------------------------------

// ScheduleSituationsMissingFirstTransition makes every nonterminal Situation
// that has no Transition at all due now (spec.md startup step 3: "schedules
// nonterminal Plan 2 Situations missing a first Transition").
//
// This is the upgrade path: a Situation that Plan 2 created and reconciled
// before Plan 3's history schema existed carries authoritative current state
// with no immutable history behind it. Scheduling it lets the next ordinary
// controller cycle write its `first_authoritative_state` Transition through
// the same fenced commit every other Transition goes through. It does NOT
// fabricate history for a Situation that is already terminal — spec.md's
// "no fabricated history for pre-Plan-3 terminal state" — because a closed
// Episode is immutable and can no longer be claimed anyway.
//
// It reports how many Situations it pulled forward.
func (s *Store) ScheduleSituationsMissingFirstTransition(ctx context.Context, now time.Time) (int, error) {
	nowStr := canonicalTime(now.UTC())
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations
		SET next_assessment_at = ?
		WHERE lifecycle IN ('active','recovery_pending')
		  AND next_assessment_at > ?
		  AND NOT EXISTS (SELECT 1 FROM situation_transitions tr WHERE tr.situation_id = situations.id)`,
		nowStr, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: schedule situations missing a first transition: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count situations scheduled for a first transition: %w", err)
	}
	return int(n), nil
}

// ScheduleSituationsWithStaleRootProjection makes every nonterminal
// Situation whose one pending root projection is behind its current Episode
// summary due now (spec.md startup step 6: "performs stale-root
// supersession").
//
// Supersession itself is never performed here, and deliberately so:
// migration 0018 requires a superseded root_sync to name the replacement
// that retired it (`CHECK ((status = 'superseded') = (replacement_intent_id
// IS NOT NULL))`), and the replacement is created only by the fenced
// controller commit that supersedes it (situation_history.go's
// insertNotificationIntentsTx). A startup sweep that flipped the status on
// its own would either violate that CHECK or invent an intent no commit
// authored. Scheduling the Situation instead makes the next ordinary commit
// author the fresh root projection AND supersede the stale one atomically,
// which is the only path that keeps "at most one pending unsuperseded
// root_sync per Situation" true. Until then the stale root simply stays
// pending: its delivery attempt fails the deliverer's own summary-version
// check retryably, which delays it and never closes the obligation.
//
// It reports how many Situations it pulled forward.
func (s *Store) ScheduleSituationsWithStaleRootProjection(ctx context.Context, now time.Time) (int, error) {
	nowStr := canonicalTime(now.UTC())
	res, err := s.db.ExecContext(ctx, `
		UPDATE situations
		SET next_assessment_at = ?
		WHERE lifecycle IN ('active','recovery_pending')
		  AND next_assessment_at > ?
		  AND EXISTS (
		      SELECT 1
		      FROM notification_intents ni
		      JOIN situation_episode_summaries es ON es.situation_id = ni.situation_id
		      WHERE ni.situation_id = situations.id
		        AND ni.effect_class = 'root_sync'
		        AND ni.status = 'pending'
		        AND ni.summary_version < es.version)`,
		nowStr, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: schedule situations with a stale root projection: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: count situations scheduled for a stale root projection: %w", err)
	}
	return int(n), nil
}
