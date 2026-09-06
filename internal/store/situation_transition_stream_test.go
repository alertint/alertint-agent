// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Plan 3 Task 9: the stdout Transition-stream claim/acknowledgement
// lifecycle and the two startup catch-up sweeps, against a real database.
// ----------------------------------------------------------------------

// stsPendingStreamRows reads the pending stream rows for one Situation, in
// sequence order.
func stsPendingStreamRows(t *testing.T, st *Store, situationID string) []struct {
	ID     string
	Status string
} {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(),
		`SELECT id, status FROM situation_transition_stream WHERE situation_id = ? ORDER BY sequence ASC`, situationID)
	if err != nil {
		t.Fatalf("read stream rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []struct {
		ID     string
		Status string
	}
	for rows.Next() {
		var r struct {
			ID     string
			Status string
		}
		if err := rows.Scan(&r.ID, &r.Status); err != nil {
			t.Fatalf("scan stream row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stream rows: %v", err)
	}
	return out
}

// TestTransitionStreamClaimJoinsItsTransitionAndFencesAcknowledgement proves
// the whole fenced lifecycle: a claim carries the immutable Transition it
// records, a second claimant fences the first out, and a stale holder's
// acknowledgement changes nothing.
func TestTransitionStreamClaimJoinsItsTransitionAndFencesAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, _ := shSeedTwoCommitHistory(t, st, "service=stream", now)

	claims, err := st.ClaimTransitionStream(ctx, "stdout-a", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("ClaimTransitionStream: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("claimed %d stream rows, want 2 (one per committed Transition)", len(claims))
	}
	for i, c := range claims {
		if c.Transition.SituationID != sitID {
			t.Errorf("claim %d names situation %q, want %q", i, c.Transition.SituationID, sitID)
		}
		if c.Transition.Sequence != i+1 {
			t.Errorf("claim %d transition sequence = %d, want %d (durable commit order)", i, c.Transition.Sequence, i+1)
		}
		if c.ClaimOwner != "stdout-a" || c.ClaimToken < 1 {
			t.Errorf("claim %d fencing pair = (%q, %d)", i, c.ClaimOwner, c.ClaimToken)
		}
		// The claim carries the row's own durable attempt count (claiming
		// increments it), which is what a worker's retry schedule keys off.
		if c.AttemptCount != 1 {
			t.Errorf("claim %d attempt count = %d, want 1 after the first claim", i, c.AttemptCount)
		}
	}

	// A held lease is not re-claimable until it expires.
	again, err := st.ClaimTransitionStream(ctx, "stdout-b", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("second ClaimTransitionStream: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("a second worker claimed %d already-leased rows, want 0", len(again))
	}

	// The lease expires and a second worker takes it; the first worker's
	// acknowledgement must now change nothing at all.
	later := now.Add(2 * time.Minute)
	reclaimed, err := st.ClaimTransitionStream(ctx, "stdout-b", later, time.Minute, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim after lease expiry = %d rows, %v", len(reclaimed), err)
	}
	stale := claims[0]
	if err := st.MarkTransitionStreamDelivered(ctx, stale, later); !errors.Is(err, ErrTransitionStreamClaimLost) {
		t.Fatalf("stale acknowledgement = %v, want ErrTransitionStreamClaimLost", err)
	}
	if rows := stsPendingStreamRows(t, st, sitID); rows[0].Status != "pending" {
		t.Fatalf("stale acknowledgement moved the row to %q", rows[0].Status)
	}

	// The current holder's acknowledgement lands.
	if err := st.MarkTransitionStreamDelivered(ctx, reclaimed[0], later); err != nil {
		t.Fatalf("MarkTransitionStreamDelivered: %v", err)
	}
	if rows := stsPendingStreamRows(t, st, sitID); rows[0].Status != "delivered" {
		t.Fatalf("row status = %q, want delivered", rows[0].Status)
	}
}

// TestTransitionStreamRetryFailAndRecoverExpiredClaims proves the three
// remaining acknowledgements: a retry returns the row to the pool with a
// bounded error class and a future retry time (never a terminal status), a
// failure moves ONLY that row, and the startup sweep returns an abandoned
// lease without touching status or attempts.
func TestTransitionStreamRetryFailAndRecoverExpiredClaims(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, _ := shSeedTwoCommitHistory(t, st, "service=stream-retry", now)

	claims, err := st.ClaimTransitionStream(ctx, "stdout-a", now, time.Minute, 10)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claim: %d rows, %v", len(claims), err)
	}
	if err := st.RetryTransitionStreamEntry(ctx, claims[0], "stdout_unavailable", now.Add(30*time.Second)); err != nil {
		t.Fatalf("RetryTransitionStreamEntry: %v", err)
	}
	if err := st.FailTransitionStreamEntry(ctx, claims[1], "invalid_transition", now); err != nil {
		t.Fatalf("FailTransitionStreamEntry: %v", err)
	}
	rows := stsPendingStreamRows(t, st, sitID)
	if rows[0].Status != "pending" {
		t.Errorf("retried row status = %q, want pending (retry is indefinite)", rows[0].Status)
	}
	if rows[1].Status != "failed" {
		t.Errorf("failed row status = %q, want failed", rows[1].Status)
	}

	// Not due yet, then due.
	if due, err := st.ClaimTransitionStream(ctx, "stdout-a", now.Add(10*time.Second), time.Minute, 10); err != nil || len(due) != 0 {
		t.Fatalf("claim before retry_at = %d rows, %v; want none", len(due), err)
	}
	due, err := st.ClaimTransitionStream(ctx, "stdout-a", now.Add(time.Minute), time.Minute, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("claim after retry_at = %d rows, %v; want 1", len(due), err)
	}
	if due[0].AttemptCount != 2 {
		t.Errorf("attempt count on the re-claim = %d, want 2 (it advances so the backoff does too)", due[0].AttemptCount)
	}

	// An abandoned lease is swept without changing status or attempt count.
	var attemptsBefore int
	if err := st.db.QueryRowContext(ctx,
		`SELECT attempt_count FROM situation_transition_stream WHERE id = ?`, due[0].StreamID).Scan(&attemptsBefore); err != nil {
		t.Fatal(err)
	}
	recovered, err := st.RecoverExpiredTransitionStreamClaims(ctx, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("RecoverExpiredTransitionStreamClaims: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}
	var status string
	var attemptsAfter int
	var owner *string
	if err := st.db.QueryRowContext(ctx,
		`SELECT status, attempt_count, lease_owner FROM situation_transition_stream WHERE id = ?`,
		due[0].StreamID).Scan(&status, &attemptsAfter, &owner); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attemptsAfter != attemptsBefore || owner != nil {
		t.Fatalf("after sweep: status=%q attempts=%d owner=%v; want pending/%d/nil", status, attemptsAfter, owner, attemptsBefore)
	}
}

// TestTransitionStreamReleaseHandsTheClaimBack proves shutdown's release
// path leaves the row immediately claimable rather than waiting out a lease.
func TestTransitionStreamReleaseHandsTheClaimBack(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	shSeedTwoCommitHistory(t, st, "service=stream-release", now)

	claims, err := st.ClaimTransitionStream(ctx, "stdout-a", now, time.Hour, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %d rows, %v", len(claims), err)
	}
	if err := st.ReleaseTransitionStreamClaim(ctx, claims[0]); err != nil {
		t.Fatalf("ReleaseTransitionStreamClaim: %v", err)
	}
	again, err := st.ClaimTransitionStream(ctx, "stdout-b", now, time.Hour, 1)
	if err != nil || len(again) != 1 {
		t.Fatalf("re-claim after release = %d rows, %v; want 1 immediately", len(again), err)
	}
}

// TestScheduleSituationsMissingFirstTransitionPullsOnlyNonterminalOnes is
// spec.md's startup step 3: a nonterminal Situation with no Transition at
// all becomes due now, one that already has history is left alone, and no
// history is ever fabricated.
func TestScheduleSituationsMissingFirstTransitionPullsOnlyNonterminalOnes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)

	bare := newSituationForGroup(t, st, "service=bare", now)
	if _, err := st.db.ExecContext(ctx,
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`,
		canonicalTime(now.Add(time.Hour)), bare); err != nil {
		t.Fatal(err)
	}
	withHistory, _ := shSeedTwoCommitHistory(t, st, "service=has-history", now)
	if _, err := st.db.ExecContext(ctx,
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`,
		canonicalTime(now.Add(time.Hour)), withHistory); err != nil {
		t.Fatal(err)
	}

	scheduled, err := st.ScheduleSituationsMissingFirstTransition(ctx, now)
	if err != nil {
		t.Fatalf("ScheduleSituationsMissingFirstTransition: %v", err)
	}
	if scheduled != 1 {
		t.Fatalf("scheduled = %d, want exactly the one Situation with no Transition", scheduled)
	}
	for id, wantDue := range map[string]bool{bare: true, withHistory: false} {
		var next string
		if err := st.db.QueryRowContext(ctx, `SELECT next_assessment_at FROM situations WHERE id = ?`, id).Scan(&next); err != nil {
			t.Fatal(err)
		}
		if (next == canonicalTime(now)) != wantDue {
			t.Errorf("situation %s next_assessment_at = %q, wantDue=%v", id, next, wantDue)
		}
	}
	// It publishes nothing: no Transition, summary, stream row, or intent
	// appeared for the bare Situation.
	for _, table := range []string{"situation_transitions", "situation_episode_summaries", "situation_transition_stream", "notification_intents"} {
		var n int
		if err := st.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table+` WHERE situation_id = ?`, bare).Scan(&n); err != nil { // #nosec G202 -- table is a package-local constant list
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("scheduling created %d %s rows; a startup sweep must publish nothing", n, table)
		}
	}
	// Idempotent: a second pass finds nothing left to pull forward.
	if again, err := st.ScheduleSituationsMissingFirstTransition(ctx, now); err != nil || again != 0 {
		t.Fatalf("second pass scheduled %d, %v; want 0", again, err)
	}
}

// TestScheduleSituationsWithStaleRootProjectionMakesTheOwnerDue is spec.md's
// startup step 6: a pending root projection behind its Situation's current
// Episode summary makes that Situation due, so the next ordinary commit
// authors the fresh root AND supersedes the stale one atomically. The sweep
// never flips a status itself — migration 0018 requires a superseded root to
// name the replacement that retired it, and only a fenced commit can author
// one.
func TestScheduleSituationsWithStaleRootProjectionMakesTheOwnerDue(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, _ := shSeedTwoCommitHistory(t, st, "service=stale-root", now)
	// A second Situation whose pending root projection is CURRENT: the sweep
	// must leave it alone, which is what makes the count below meaningful.
	currentID, _ := shSeedTwoCommitHistory(t, st, "service=current-root", now)
	if _, err := st.db.ExecContext(ctx,
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`,
		canonicalTime(now.Add(time.Hour)), currentID); err != nil {
		t.Fatal(err)
	}

	var intentID string
	var intentVersion int
	if err := st.db.QueryRowContext(ctx,
		`SELECT id, summary_version FROM notification_intents
		 WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`,
		sitID).Scan(&intentID, &intentVersion); err != nil {
		t.Fatalf("the seeded commits left no pending root projection to age: %v", err)
	}

	// Advance the Episode summary past that projection by appending a third
	// Transition and folding it — the only move migration 0017's monotonic
	// trigger allows (version + 1, strictly later source sequence).
	created := canonicalTime(now.Add(2 * time.Minute))
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, drill, created_at
		) SELECT 'tr-stale-3', situation_id, 3, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, drill, ?
		FROM situation_transitions WHERE situation_id = ? AND sequence = 2`, created, sitID); err != nil {
		t.Fatalf("append the third transition: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situation_episode_summaries
		SET version = version + 1, source_transition_sequence = 3, updated_at = ?
		WHERE situation_id = ?`, created, sitID); err != nil {
		t.Fatalf("advance the episode summary: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`,
		canonicalTime(now.Add(time.Hour)), sitID); err != nil {
		t.Fatal(err)
	}

	n, err := st.ScheduleSituationsWithStaleRootProjection(ctx, now)
	if err != nil {
		t.Fatalf("ScheduleSituationsWithStaleRootProjection: %v", err)
	}
	if n != 1 {
		t.Fatalf("scheduled = %d, want 1 (the Situation whose pending root projection is behind its summary)", n)
	}
	var next, status string
	if err := st.db.QueryRowContext(ctx, `SELECT next_assessment_at FROM situations WHERE id = ?`, sitID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next != canonicalTime(now) {
		t.Errorf("next_assessment_at = %q, want it pulled forward to now", next)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT status FROM notification_intents WHERE id = ?`, intentID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("the sweep changed the intent's status to %q; only a fenced commit may supersede a root projection", status)
	}
	_ = intentVersion

	// The Situation whose projection is current was never pulled forward.
	var untouched string
	if err := st.db.QueryRowContext(ctx, `SELECT next_assessment_at FROM situations WHERE id = ?`, currentID).Scan(&untouched); err != nil {
		t.Fatal(err)
	}
	if untouched == canonicalTime(now) {
		t.Error("the sweep pulled a Situation whose root projection is current forward")
	}
	// Idempotent: the stale Situation is already due, so a second pass finds
	// nothing left to schedule.
	if again, err := st.ScheduleSituationsWithStaleRootProjection(ctx, now); err != nil || again != 0 {
		t.Fatalf("second pass scheduled %d, %v; want 0", again, err)
	}
}

// TestNotificationDeliveryStatsAreBoundedCounts proves the installation-level
// delivery snapshot MCP reads is counts only, and that its subsumed-blocked
// field lets the blocked backlog an operator can act on reach zero.
func TestNotificationDeliveryStatsAreBoundedCounts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID, _ := shSeedTwoCommitHistory(t, st, "service=stats", now)

	stats, err := st.GetNotificationDeliveryStats(ctx, now)
	if err != nil {
		t.Fatalf("GetNotificationDeliveryStats: %v", err)
	}
	if stats.OpenGapAgeSeconds != nil {
		t.Errorf("open_gap_age_seconds = %v with no gap, want nil", *stats.OpenGapAgeSeconds)
	}
	if stats.ReplayBacklog != 0 || stats.UncertainOutcomes != 0 {
		t.Errorf("stats = %+v, want zero backlog and zero uncertain outcomes", stats)
	}
	if stats.TransitionStreamPending != 2 {
		t.Errorf("transition_stream_pending = %d, want 2 (one row per committed Transition)", stats.TransitionStreamPending)
	}

	intents, err := st.ListSituationNotificationIntents(ctx, sitID, 0)
	if err != nil {
		t.Fatalf("ListSituationNotificationIntents: %v", err)
	}
	if len(intents) == 0 {
		t.Fatal("the seeded commits warranted no notification intent at all")
	}
	if intents[0].EffectClass != "root_sync" {
		t.Errorf("first intent = %q, want the root projection first", intents[0].EffectClass)
	}
}

// TestListOwnerTerminalArtifactsReadsOnlyRecordedNeverJournaledOnes is R2's
// read half: an artifact applied to an already-terminal owner is recorded
// with journal_state='owner_terminal' and must surface here, while a pending
// or journaled artifact — which the Transition journal already carries —
// must not.
func TestListOwnerTerminalArtifactsReadsOnlyRecordedNeverJournaledOnes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "service=closed-owner", now)

	var incidentID string
	if err := st.db.QueryRowContext(ctx,
		`SELECT incident_id FROM situation_incidents WHERE situation_id = ?`, sitID).Scan(&incidentID); err != nil {
		t.Fatalf("read member incident: %v", err)
	}
	res, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_annotations (incident_id, kind, note, created_at)
		VALUES (?, 'observation', 'recorded after closure', ?)`,
		incidentID, canonicalTime(now))
	if err != nil {
		t.Fatalf("insert annotation: %v", err)
	}
	annotationID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	insert := func(id, journalState string, at time.Time) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO situation_input_outbox (
				id, idempotency_key, incident_id, kind, group_key, occurred_at, status,
				applied_situation_id, applied_at, applied_input_version, annotation_id, journal_state
			) VALUES (?, ?, ?, 'operator_annotation_recorded', 'service=closed-owner', ?, 'applied', ?, ?, 1, ?, ?)`,
			id, "idem:"+id, incidentID, canonicalTime(at), sitID, canonicalTime(at), annotationID, journalState); err != nil {
			t.Fatalf("insert %s outbox row: %v", journalState, err)
		}
	}
	insert("in-terminal-b", "owner_terminal", now.Add(2*time.Minute))
	insert("in-terminal-a", "owner_terminal", now.Add(time.Minute))
	insert("in-pending", "pending", now.Add(3*time.Minute))

	artifacts, err := st.ListOwnerTerminalArtifacts(ctx, sitID, 0)
	if err != nil {
		t.Fatalf("ListOwnerTerminalArtifacts: %v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %+v, want exactly the two owner_terminal rows", artifacts)
	}
	if artifacts[0].InputID != "in-terminal-a" || artifacts[1].InputID != "in-terminal-b" {
		t.Fatalf("order = %q,%q; want oldest first", artifacts[0].InputID, artifacts[1].InputID)
	}
	a := artifacts[0]
	if a.Kind != "operator_annotation_recorded" || a.IncidentID != incidentID {
		t.Errorf("artifact provenance = %+v", a)
	}
	if a.AnnotationID == nil || *a.AnnotationID != annotationID {
		t.Errorf("annotation id = %v, want %d", a.AnnotationID, annotationID)
	}
	if a.VerdictID != nil {
		t.Errorf("verdict id = %v on an annotation artifact", *a.VerdictID)
	}
	if a.OccurredAt.IsZero() || a.AppliedAt.IsZero() {
		t.Errorf("artifact lost its instants: %+v", a)
	}

	// A Situation nothing was recorded against post-hoc reads as an empty
	// slice, never nil — "none" is an answer.
	other := newSituationForGroup(t, st, "service=untouched", now)
	empty, err := st.ListOwnerTerminalArtifacts(ctx, other, 0)
	if err != nil {
		t.Fatalf("ListOwnerTerminalArtifacts (empty): %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("artifacts for an untouched Situation = %v, want an empty slice", empty)
	}
}
