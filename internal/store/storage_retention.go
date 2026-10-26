// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// Storage retention (migration 0048, issue #99). The memory is kept forever:
// every Situation, its journal, and its current state at any age. The
// working record expires: the detail of old Transitions (briefing, operator
// candidates, cited fact IDs), the observation evidence only they cited,
// superseded facts and the coverage of attempts that are no longer current.
// Every step below runs in short pages, like observation retention (#159): a
// page is one transaction of about retentionPageTime, and the store's other
// calls get the connection between pages.
var (
	retentionPageRows  = 256
	retentionPageTime  = 100 * time.Millisecond
	retentionPagePause = 20 * time.Millisecond
)

// StorageRemoved counts what one maintenance pass removed or moved.
type StorageRemoved struct {
	// CompactedBriefings counts existing briefings moved into compressed storage.
	CompactedBriefings int `json:"compacted_briefings"`
	// RepeatedFacts counts facts written before 0048 that repeated the previous one.
	RepeatedFacts int `json:"repeated_facts"`
	// Facts counts superseded or expired facts.
	Facts int `json:"facts"`
	// Coverage counts coverage rows of attempts that are no longer current.
	Coverage int `json:"coverage"`
	// TransitionDetails counts Transitions whose detail expired.
	TransitionDetails int `json:"transition_details"`
	// AttemptEvidence counts assessment attempts that released their
	// evidence (their calls' with it), and calls that never got an attempt.
	AttemptEvidence int `json:"attempt_evidence"`
	// LifecycleEvidence counts old lifecycle decisions that released theirs.
	LifecycleEvidence int `json:"lifecycle_evidence"`
	// Observation counts expired observation runs plus removed cycles.
	Observation int `json:"observation"`
	// Audit counts pruned audit entries.
	Audit int `json:"audit"`
}

func (r StorageRemoved) plus(o StorageRemoved) StorageRemoved {
	r.CompactedBriefings += o.CompactedBriefings
	r.RepeatedFacts += o.RepeatedFacts
	r.Facts += o.Facts
	r.Coverage += o.Coverage
	r.TransitionDetails += o.TransitionDetails
	r.AttemptEvidence += o.AttemptEvidence
	r.LifecycleEvidence += o.LifecycleEvidence
	r.Observation += o.Observation
	r.Audit += o.Audit
	return r
}

// Total is every removed or moved row.
func (r StorageRemoved) Total() int {
	return r.CompactedBriefings + r.RepeatedFacts + r.Facts + r.Coverage + r.TransitionDetails +
		r.AttemptEvidence + r.LifecycleEvidence + r.Observation + r.Audit
}

// CompactStorageBacklog moves what was written before migration 0048 into its
// new shape: briefings into compressed storage, and repeated facts out.
// Coverage of attempts that are no longer current is removed too, whatever
// its age, because nothing reads it. Each step remembers its progress, so a
// finished step costs one read.
func (s *Store) CompactStorageBacklog(ctx context.Context) (StorageRemoved, error) {
	var out StorageRemoved
	if retentionFailpoint != nil {
		if err := retentionFailpoint("backlog"); err != nil {
			return out, err
		}
	}
	var errs [3]error
	out.Coverage, errs[0] = s.pruneSupersededCoverage(ctx)
	out.CompactedBriefings, errs[1] = s.compactLegacyBriefings(ctx)
	out.RepeatedFacts, errs[2] = s.pruneLegacyFactRepeats(ctx)
	return out, errors.Join(errs[:]...)
}

// retentionFailpoint, set only by tests, fails the named maintenance step.
var retentionFailpoint func(step string) error

// ExpireWorkingRecord removes the working record older than cutoff, at now:
// the detail of Transitions nothing current uses, the evidence of old
// attempts and lifecycle decisions, and superseded facts. Observation detail
// and cycles left without a reference go through observation retention with
// observationCutoff.
func (s *Store) ExpireWorkingRecord(ctx context.Context, now, cutoff, observationCutoff time.Time) (StorageRemoved, error) {
	var out StorageRemoved
	var errs [5]error
	if !cutoff.IsZero() {
		out.TransitionDetails, errs[0] = s.expireTransitionDetails(ctx, now, cutoff)
		out.AttemptEvidence, errs[1] = s.releaseAttemptEvidence(ctx, now, cutoff)
		out.LifecycleEvidence, errs[2] = s.releaseLifecycleEvidence(ctx, cutoff)
		out.Facts, errs[3] = s.expireFacts(ctx, cutoff)
	}
	out.Observation, errs[4] = s.PruneObservationRetentionBefore(ctx, now, observationCutoff)
	return out, errors.Join(errs[:]...)
}

// retentionPages runs page until it reports done, one transaction per page,
// pausing between pages so other store calls get the connection.
func (s *Store) retentionPages(ctx context.Context, name string, page func(tx *sql.Tx, deadline time.Time) (int, bool, error)) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return total, fmt.Errorf("store: begin %s: %w", name, err)
		}
		n, done, err := page(tx, time.Now().Add(retentionPageTime))
		if err != nil {
			_ = tx.Rollback()
			return total, fmt.Errorf("store: %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return total, fmt.Errorf("store: commit %s: %w", name, err)
		}
		total += n
		if done {
			return total, nil
		}
		if retentionPagePause > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(retentionPagePause):
			}
		}
	}
}

func authorizeRetentionTx(ctx context.Context, tx *sql.Tx, kind, id string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO storage_retention_pruning (kind, id) VALUES (?, ?)`, kind, id); err != nil {
		return fmt.Errorf("authorize %s %s: %w", kind, id, err)
	}
	return nil
}

func endRetentionTx(ctx context.Context, tx *sql.Tx, kind, id string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM storage_retention_pruning WHERE kind = ? AND id = ?`, kind, id); err != nil {
		return fmt.Errorf("end %s %s authorization: %w", kind, id, err)
	}
	return nil
}

func retentionStateTx(ctx context.Context, tx *sql.Tx, key string) (int64, error) {
	var value string
	err := tx.QueryRowContext(ctx, `SELECT value FROM storage_retention_state WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read retention state %s: %w", key, err)
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("retention state %s: %w", key, err)
	}
	return n, nil
}

func setRetentionStateTx(ctx context.Context, tx *sql.Tx, key string, value int64) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO storage_retention_state (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, strconv.FormatInt(value, 10)); err != nil {
		return fmt.Errorf("write retention state %s: %w", key, err)
	}
	return nil
}

func (s *Store) retentionState(ctx context.Context, key string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, fmt.Errorf("store: begin read retention state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return retentionStateTx(ctx, tx, key)
}

// cutoffText is cutoff as a stored timestamp prefix for SQL range filters. A
// stored RFC3339Nano value within cutoff's second sorts before it, so such a
// filter can include a row up to a second early; the Go-side checks compare
// exact instants.
func cutoffText(cutoff time.Time) string {
	return cutoff.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func parseStoredTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored time %q: %w", value, err)
	}
	return t.UTC(), nil
}

// ----------------------------------------------------------------------
// Backlog: coverage, legacy briefings, legacy fact repeats.
// ----------------------------------------------------------------------

// pruneSupersededCoverage deletes the coverage of every attempt that is not a
// Situation's current assessment: only the current one's is ever read.
func (s *Store) pruneSupersededCoverage(ctx context.Context) (int, error) {
	after := ""
	return s.retentionPages(ctx, "prune superseded coverage", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT assessment_attempt_id FROM situation_assessment_coverage
			WHERE assessment_attempt_id > ? AND assessment_attempt_id NOT IN (
				SELECT current_assessment_id FROM situations WHERE current_assessment_id IS NOT NULL)
			ORDER BY assessment_attempt_id LIMIT ?`, after, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select superseded coverage: %w", err)
		}
		ids, err := scanStrings(rows)
		if err != nil {
			return 0, false, err
		}
		removed := 0
		for _, id := range ids {
			if time.Now().After(deadline) {
				return removed, false, nil
			}
			if err := authorizeRetentionTx(ctx, tx, "coverage", id); err != nil {
				return removed, false, err
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM situation_assessment_coverage WHERE assessment_attempt_id = ?`, id)
			if err != nil {
				return removed, false, fmt.Errorf("delete coverage of %s: %w", id, err)
			}
			n, _ := res.RowsAffected()
			removed += int(n)
			if err := endRetentionTx(ctx, tx, "coverage", id); err != nil {
				return removed, false, err
			}
			after = id
		}
		return removed, len(ids) < retentionPageRows, nil
	})
}

// compactLegacyBriefings moves the briefing of every Transition written before
// 0048 out of projection_json into situation_transition_briefings, compressed,
// oldest first. Its cursor persists, so the walk happens once.
func (s *Store) compactLegacyBriefings(ctx context.Context) (int, error) {
	const batch = 8 // a legacy briefing can be hundreds of KiB
	return s.retentionPages(ctx, "compact legacy briefings", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		legacyMax, err := retentionStateTx(ctx, tx, "transitions_legacy_max_rowid")
		if err != nil {
			return 0, false, err
		}
		cursor, err := retentionStateTx(ctx, tx, "transitions_compaction_cursor")
		if err != nil || cursor >= legacyMax {
			return 0, true, err
		}
		page, err := readLegacyBriefings(ctx, tx, cursor, legacyMax, batch)
		if err != nil {
			return 0, false, err
		}
		moved := 0
		for _, l := range page {
			if moved > 0 && time.Now().After(deadline) {
				return moved, false, setRetentionStateTx(ctx, tx, "transitions_compaction_cursor", cursor)
			}
			blob, err := compressBriefing([]byte(l.body))
			if err != nil {
				return moved, false, err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO situation_transition_briefings (transition_id, encoding, raw_bytes, briefing) VALUES (?, ?, ?, ?)`,
				l.id, briefingEncoding, len(l.body), blob); err != nil {
				return moved, false, fmt.Errorf("store briefing of %s: %w", l.id, err)
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE situation_transitions SET projection_json = json_remove(projection_json, '$.briefing') WHERE id = ?`,
				l.id); err != nil {
				return moved, false, fmt.Errorf("move briefing of %s: %w", l.id, err)
			}
			cursor = l.rowID
			moved++
		}
		if len(page) < batch {
			cursor = legacyMax
		}
		return moved, cursor >= legacyMax, setRetentionStateTx(ctx, tx, "transitions_compaction_cursor", cursor)
	})
}

// legacyBriefing is one Transition whose briefing is still in projection_json.
type legacyBriefing struct {
	rowID    int64
	id, body string
}

func readLegacyBriefings(ctx context.Context, tx *sql.Tx, cursor, legacyMax int64, limit int) ([]legacyBriefing, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT rowid, id, json_extract(projection_json, '$.briefing') FROM situation_transitions
		WHERE rowid > ? AND rowid <= ? AND json_type(projection_json, '$.briefing') = 'object'
		ORDER BY rowid LIMIT ?`, cursor, legacyMax, limit)
	if err != nil {
		return nil, fmt.Errorf("select legacy briefings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var page []legacyBriefing
	for rows.Next() {
		var l legacyBriefing
		if err := rows.Scan(&l.rowID, &l.id, &l.body); err != nil {
			return nil, fmt.Errorf("scan legacy briefing: %w", err)
		}
		page = append(page, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read legacy briefings: %w", err)
	}
	return page, nil
}

// pruneLegacyFactRepeats deletes, among facts written before 0048, every row
// whose content equals the previous kept row of its (Situation, kind,
// subject): one Situation at a time, in input-version order. A Situation
// interrupted part way is walked again from its start, which is cheap once
// its repeats are gone.
func (s *Store) pruneLegacyFactRepeats(ctx context.Context) (int, error) {
	done, err := s.retentionState(ctx, "facts_repeats_done")
	if err != nil || done == 1 {
		return 0, err
	}
	legacyMax, err := s.retentionState(ctx, "facts_legacy_max_rowid")
	if err != nil {
		return 0, err
	}
	total := 0
	for {
		situationID, found, err := s.nextLegacyFactSituation(ctx)
		if err != nil {
			return total, err
		}
		if !found {
			_, err := s.retentionPages(ctx, "finish legacy fact repeats", func(tx *sql.Tx, _ time.Time) (int, bool, error) {
				return 0, true, setRetentionStateTx(ctx, tx, "facts_repeats_done", 1)
			})
			return total, err
		}
		n, err := s.pruneSituationFactRepeats(ctx, situationID, legacyMax)
		total += n
		if err != nil {
			return total, err
		}
	}
}

// nextLegacyFactSituation is the first Situation after the last one whose
// repeats are gone. The walk's position is the Situation id itself.
func (s *Store) nextLegacyFactSituation(ctx context.Context) (string, bool, error) {
	var after string
	if err := s.db.QueryRowContext(ctx, `
		SELECT coalesce((SELECT value FROM storage_retention_state WHERE key = 'facts_repeats_after'), '')`).Scan(&after); err != nil {
		return "", false, fmt.Errorf("store: read legacy fact walk position: %w", err)
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE id > ? ORDER BY id LIMIT 1`, after).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: select next legacy fact situation: %w", err)
	}
	return id, true, nil
}

func (s *Store) pruneSituationFactRepeats(ctx context.Context, situationID string, legacyMax int64) (int, error) {
	walk := legacyFactWalk{situationID: situationID, legacyMax: legacyMax, kept: map[string]string{}}
	finished := false
	return s.retentionPages(ctx, "prune legacy fact repeats", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		if finished {
			return 0, true, nil
		}
		repeats, read, err := walk.page(ctx, tx, deadline)
		if err != nil {
			return 0, false, err
		}
		if len(repeats) > 0 {
			if err := authorizeRetentionTx(ctx, tx, "legacy_facts", "repeats"); err != nil {
				return 0, false, err
			}
			for _, id := range repeats {
				if _, err := tx.ExecContext(ctx, `DELETE FROM situation_facts WHERE rowid = ?`, id); err != nil {
					return 0, false, fmt.Errorf("delete repeated fact: %w", err)
				}
			}
			if err := endRetentionTx(ctx, tx, "legacy_facts", "repeats"); err != nil {
				return 0, false, err
			}
		}
		if read < retentionPageRows && !time.Now().After(deadline) {
			finished = true
			return len(repeats), true, setRetentionStateTextTx(ctx, tx, "facts_repeats_after", situationID)
		}
		return len(repeats), false, nil
	})
}

// legacyFactWalk is one Situation's walk over its legacy facts in
// (input_version, kind, rowid) order: its position and, per (kind, subject),
// the content hash of the last row it kept.
type legacyFactWalk struct {
	situationID string
	legacyMax   int64
	kept        map[string]string
	version     int64
	kind        string
	rowID       int64
}

// page reads the next page of the walk, returning the repeated rows' rowids
// and how many rows it read. It stops early at deadline.
func (w *legacyFactWalk) page(ctx context.Context, tx *sql.Tx, deadline time.Time) ([]int64, int, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT rowid, input_version, kind, subject, digest, value_json, result_status, evidence_refs_json, material
		FROM situation_facts
		WHERE situation_id = ? AND rowid <= ? AND (input_version, kind, rowid) > (?, ?, ?)
		ORDER BY input_version, kind, rowid LIMIT ?`,
		w.situationID, w.legacyMax, w.version, w.kind, w.rowID, retentionPageRows)
	if err != nil {
		return nil, 0, fmt.Errorf("select legacy facts of %s: %w", w.situationID, err)
	}
	defer func() { _ = rows.Close() }()
	var repeats []int64
	read := 0
	for rows.Next() {
		var p preparedFact
		var status string
		if err := rows.Scan(&w.rowID, &w.version, &w.kind, &p.f.Subject, &p.f.Digest, &p.valueJSON, &status,
			&p.evidenceRefsJSON, &p.material); err != nil {
			return nil, 0, fmt.Errorf("scan legacy fact: %w", err)
		}
		read++
		p.f.Kind, p.f.ResultStatus = w.kind, situationmodel.FactResultStatus(status)
		key, hash := w.kind+"\x00"+p.f.Subject, factContentHash(p)
		if w.kept[key] == hash {
			repeats = append(repeats, w.rowID)
		} else {
			w.kept[key] = hash
		}
		if time.Now().After(deadline) {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read legacy facts: %w", err)
	}
	return repeats, read, nil
}

func setRetentionStateTextTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO storage_retention_state (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("write retention state %s: %w", key, err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Working record past the cutoff.
// ----------------------------------------------------------------------

// retentionCandidate is one row a retention walk may remove, in walk order.
type retentionCandidate struct {
	rowID int64
	id    string
}

// scanRetentionCandidates reads one walk page of (rowid, id, stored time,
// protected) rows in rowid order, which is creation order. It stops at the
// first row created at or after cutoff: reached reports that the walk is
// done, as it does when the page ran short. Protected rows are skipped and
// stepped over, so after names the last row the walk needs never read again.
func scanRetentionCandidates(rows *sql.Rows, cutoff time.Time, after *int64) ([]retentionCandidate, bool, error) {
	defer func() { _ = rows.Close() }()
	var out []retentionCandidate
	read := 0
	for rows.Next() {
		var c retentionCandidate
		var at string
		var protected bool
		if err := rows.Scan(&c.rowID, &c.id, &at, &protected); err != nil {
			return nil, false, fmt.Errorf("scan retention candidate: %w", err)
		}
		read++
		created, err := parseStoredTime(at)
		if err != nil {
			return nil, false, err
		}
		if !created.Before(cutoff) {
			return out, true, rows.Err()
		}
		if protected {
			if len(out) == 0 {
				*after = c.rowID
			}
			continue
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("read retention candidates: %w", err)
	}
	return out, read < retentionPageRows, nil
}

// expireTransitionDetails drops the detail of every Transition created before
// cutoff that nothing current uses: its stored briefing, its operator
// candidates and cited fact IDs, and the observation references it owns.
// The row, its journal and its history facts stay.
func (s *Store) expireTransitionDetails(ctx context.Context, now, cutoff time.Time) (int, error) {
	var after int64
	expiredAt := canonicalTime(now)
	return s.retentionPages(ctx, "expire transition details", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT t.rowid, t.id, t.created_at, t.id IN (SELECT transition_id FROM storage_protected_transitions)
			FROM situation_transitions t INDEXED BY situation_transitions_unexpired_idx
			WHERE t.detail_expired_at IS NULL AND t.rowid > ?
			ORDER BY t.rowid LIMIT ?`, after, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select transitions past retention: %w", err)
		}
		return expireCandidates(rows, cutoff, &after, deadline, func(id string) error {
			return expireTransitionDetailTx(ctx, tx, id, expiredAt)
		})
	})
}

// expireCandidates applies expire to one page's candidates until the page's
// deadline, keeping after on the last row handled.
func expireCandidates(rows *sql.Rows, cutoff time.Time, after *int64, deadline time.Time, expire func(id string) error) (int, bool, error) {
	candidates, reached, err := scanRetentionCandidates(rows, cutoff, after)
	if err != nil {
		return 0, false, err
	}
	for i, c := range candidates {
		if i > 0 && time.Now().After(deadline) {
			return i, false, nil
		}
		if err := expire(c.id); err != nil {
			return i, false, err
		}
		*after = c.rowID
	}
	return len(candidates), reached, nil
}

func expireTransitionDetailTx(ctx context.Context, tx *sql.Tx, id, expiredAt string) error {
	if err := authorizeRetentionTx(ctx, tx, "transition", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM situation_transition_briefings WHERE transition_id = ?`, id); err != nil {
		return fmt.Errorf("expire briefing of %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE situation_transitions
		SET projection_json = json_remove(projection_json, '$.briefing', '$.operator_delta.candidates'),
		    evidence_refs_json = '[]', detail_expired_at = ?
		WHERE id = ?`, expiredAt, id); err != nil {
		return fmt.Errorf("expire detail of %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM situation_observation_references WHERE owner_id = ? AND reference_kind = 'transition' AND permanent = 1`,
		id); err != nil {
		return fmt.Errorf("release evidence of %s: %w", id, err)
	}
	return endRetentionTx(ctx, tx, "transition", id)
}

// releaseAttemptEvidence deletes the observation references owned by every
// assessment attempt completed before cutoff that nothing current uses, and
// by its calls. The attempt row stays; evidence_released_at records the
// release. Then it releases calls that never got an attempt.
func (s *Store) releaseAttemptEvidence(ctx context.Context, now, cutoff time.Time) (int, error) {
	var after int64
	releasedAt := canonicalTime(now)
	released, err := s.retentionPages(ctx, "release attempt evidence", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.rowid, a.id, a.completed_at, a.id IN (SELECT attempt_id FROM storage_protected_attempts)
			FROM situation_assessment_attempts a INDEXED BY situation_assessment_attempts_unreleased_idx
			WHERE a.evidence_released_at IS NULL AND a.rowid > ?
			ORDER BY a.rowid LIMIT ?`, after, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select attempts past retention: %w", err)
		}
		return expireCandidates(rows, cutoff, &after, deadline, func(id string) error {
			if err := authorizeRetentionTx(ctx, tx, "assessment_attempt", id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE situation_assessment_attempts SET evidence_released_at = ? WHERE id = ?`, releasedAt, id); err != nil {
				return fmt.Errorf("release attempt %s: %w", id, err)
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM situation_observation_references
				WHERE owner_id = ? AND reference_kind = 'assessment_attempt' AND permanent = 1`, id); err != nil {
				return fmt.Errorf("release evidence of attempt %s: %w", id, err)
			}
			if err := releaseAttemptCallsTx(ctx, tx, id); err != nil {
				return err
			}
			return endRetentionTx(ctx, tx, "assessment_attempt", id)
		})
	})
	if err != nil {
		return released, err
	}
	orphans, err := s.releaseOrphanCallEvidence(ctx, cutoff)
	return released + orphans, err
}

// releaseAttemptCallsTx releases the evidence each call of an attempt's work
// attempt pinned at dispatch, under the call's ID: the draft and the
// verification call alike. A work attempt that a protected attempt shares
// keeps its calls' evidence.
func releaseAttemptCallsTx(ctx context.Context, tx *sql.Tx, attemptID string) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id FROM situation_assessment_attempts a
		JOIN situation_assessment_calls c ON c.situation_id = a.situation_id AND c.input_version = a.input_version
		  AND c.retry_epoch = a.retry_epoch AND c.work_attempt = a.work_attempt
		WHERE a.id = ? AND NOT EXISTS (
		  SELECT 1 FROM situation_assessment_attempts p INDEXED BY situation_assessment_attempts_work_idx
		  WHERE p.situation_id = a.situation_id AND p.input_version = a.input_version
		    AND p.retry_epoch = a.retry_epoch AND p.work_attempt = a.work_attempt
		    AND p.id <> a.id AND p.id IN (SELECT attempt_id FROM storage_protected_attempts))`, attemptID)
	if err != nil {
		return fmt.Errorf("select calls of attempt %s: %w", attemptID, err)
	}
	callIDs, err := scanStrings(rows)
	if err != nil {
		return err
	}
	for _, callID := range callIDs {
		if err := releaseCallEvidenceTx(ctx, tx, callID); err != nil {
			return err
		}
	}
	return nil
}

func releaseCallEvidenceTx(ctx context.Context, tx *sql.Tx, callID string) error {
	if err := authorizeRetentionTx(ctx, tx, "assessment_attempt", callID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM situation_observation_references
		WHERE owner_id = ? AND reference_kind = 'assessment_attempt' AND permanent = 1`, callID); err != nil {
		return fmt.Errorf("release evidence of call %s: %w", callID, err)
	}
	return endRetentionTx(ctx, tx, "assessment_attempt", callID)
}

// releaseOrphanCallEvidence releases the evidence of calls dispatched before
// cutoff that never got an attempt (the agent stopped or lost its lease
// between dispatch and commit), once their Situation has moved past that
// input or ended: nothing records an attempt for them after that.
func (s *Store) releaseOrphanCallEvidence(ctx context.Context, cutoff time.Time) (int, error) {
	var after int64
	return s.retentionPages(ctx, "release orphan call evidence", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT c.rowid, c.id, c.dispatched_at FROM situation_assessment_calls c
			JOIN situations s ON s.id = c.situation_id
			WHERE c.rowid > ? AND (s.input_version > c.input_version OR s.terminal_at IS NOT NULL)
			  AND NOT EXISTS (SELECT 1 FROM situation_assessment_attempts a INDEXED BY situation_assessment_attempts_work_idx
			    WHERE a.situation_id = c.situation_id AND a.input_version = c.input_version
			      AND a.retry_epoch = c.retry_epoch AND a.work_attempt = c.work_attempt)
			  AND NOT EXISTS (SELECT 1 FROM situation_assessment_attempts a WHERE a.call_id = c.id)
			  AND EXISTS (SELECT 1 FROM situation_observation_references r
			    WHERE r.owner_id = c.id AND r.reference_kind = 'assessment_attempt' AND r.superseded = 0)
			ORDER BY c.rowid LIMIT ?`, after, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select orphan calls past retention: %w", err)
		}
		candidates, reached, err := scanRetentionCandidatesUnprotected(rows, cutoff, &after)
		if err != nil {
			return 0, false, err
		}
		for i, c := range candidates {
			if i > 0 && time.Now().After(deadline) {
				return i, false, nil
			}
			if err := releaseCallEvidenceTx(ctx, tx, c.id); err != nil {
				return i, false, err
			}
		}
		return len(candidates), reached, nil
	})
}

// releaseLifecycleEvidence deletes the observation references of lifecycle
// decisions made before cutoff. A Situation's current evidence is pinned by
// its current cycle, Transition and assessment, never by these alone.
func (s *Store) releaseLifecycleEvidence(ctx context.Context, cutoff time.Time) (int, error) {
	before := cutoffText(cutoff)
	return s.retentionPages(ctx, "release lifecycle evidence", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT owner_id FROM situation_observation_references INDEXED BY situation_observation_references_lifecycle_idx
			WHERE reference_kind = 'lifecycle_decision' AND created_at < ?
			LIMIT ?`, before, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select lifecycle decisions past retention: %w", err)
		}
		owners, err := scanStrings(rows)
		if err != nil {
			return 0, false, err
		}
		for i, owner := range owners {
			if i > 0 && time.Now().After(deadline) {
				return i, false, nil
			}
			if err := authorizeRetentionTx(ctx, tx, "lifecycle_decision", owner); err != nil {
				return i, false, err
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM situation_observation_references
				WHERE owner_id = ? AND reference_kind = 'lifecycle_decision' AND permanent = 1`, owner); err != nil {
				return i, false, fmt.Errorf("release lifecycle evidence %s: %w", owner, err)
			}
			if err := endRetentionTx(ctx, tx, "lifecycle_decision", owner); err != nil {
				return i, false, err
			}
		}
		return len(owners), len(owners) < retentionPageRows, nil
	})
}

// expireFacts deletes facts superseded before cutoff, the facts of Situations
// that ended before cutoff, and facts written before 0048 that were observed
// before cutoff. Nothing reads facts back; a Situation's current facts are
// its heads.
func (s *Store) expireFacts(ctx context.Context, cutoff time.Time) (int, error) {
	superseded, err := s.retentionPages(ctx, "expire superseded facts", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT rowid, fact_id, superseded_at FROM situation_fact_supersessions ORDER BY rowid LIMIT ?`, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select superseded facts: %w", err)
		}
		var after int64
		candidates, reached, err := scanRetentionCandidatesUnprotected(rows, cutoff, &after)
		if err != nil {
			return 0, false, err
		}
		for i, c := range candidates {
			if i > 0 && time.Now().After(deadline) {
				return i, false, nil
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM situation_facts WHERE id = ?`, c.id); err != nil {
				return i, false, fmt.Errorf("delete superseded fact %s: %w", c.id, err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM situation_fact_supersessions WHERE rowid = ?`, c.rowID); err != nil {
				return i, false, fmt.Errorf("dequeue superseded fact %s: %w", c.id, err)
			}
		}
		return len(candidates), reached, nil
	})
	if err != nil {
		return superseded, err
	}
	ended, err := s.expireEndedSituationFacts(ctx, cutoff)
	if err != nil {
		return superseded + ended, err
	}
	legacy, err := s.expireLegacyFacts(ctx, cutoff)
	return superseded + ended + legacy, err
}

// scanRetentionCandidatesUnprotected is scanRetentionCandidates for a walk
// with nothing to protect, reading (rowid, id, stored time) rows.
func scanRetentionCandidatesUnprotected(rows *sql.Rows, cutoff time.Time, after *int64) ([]retentionCandidate, bool, error) {
	defer func() { _ = rows.Close() }()
	var out []retentionCandidate
	read := 0
	for rows.Next() {
		var c retentionCandidate
		var at string
		if err := rows.Scan(&c.rowID, &c.id, &at); err != nil {
			return nil, false, fmt.Errorf("scan retention candidate: %w", err)
		}
		read++
		stored, err := parseStoredTime(at)
		if err != nil {
			return nil, false, err
		}
		if !stored.Before(cutoff) {
			return out, true, rows.Err()
		}
		out = append(out, c)
		*after = c.rowID
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("read retention candidates: %w", err)
	}
	return out, read < retentionPageRows, nil
}

func (s *Store) expireEndedSituationFacts(ctx context.Context, cutoff time.Time) (int, error) {
	before := cutoffText(cutoff)
	return s.retentionPages(ctx, "expire facts of ended situations", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT h.situation_id FROM situation_fact_heads h
			JOIN situations s ON s.id = h.situation_id
			WHERE s.terminal_at IS NOT NULL AND s.terminal_at < ?
			LIMIT 16`, before)
		if err != nil {
			return 0, false, fmt.Errorf("select ended situations with facts: %w", err)
		}
		situationIDs, err := scanStrings(rows)
		if err != nil {
			return 0, false, err
		}
		removed := 0
		for i, situationID := range situationIDs {
			if i > 0 && time.Now().After(deadline) {
				return removed, false, nil
			}
			heads, err := tx.QueryContext(ctx, `SELECT fact_id FROM situation_fact_heads WHERE situation_id = ?`, situationID)
			if err != nil {
				return removed, false, fmt.Errorf("select facts of %s: %w", situationID, err)
			}
			factIDs, err := scanStrings(heads)
			if err != nil {
				return removed, false, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM situation_fact_heads WHERE situation_id = ?`, situationID); err != nil {
				return removed, false, fmt.Errorf("delete fact heads of %s: %w", situationID, err)
			}
			for _, factID := range factIDs {
				if err := authorizeRetentionTx(ctx, tx, "fact", factID); err != nil {
					return removed, false, err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM situation_facts WHERE id = ?`, factID); err != nil {
					return removed, false, fmt.Errorf("delete fact %s: %w", factID, err)
				}
				if err := endRetentionTx(ctx, tx, "fact", factID); err != nil {
					return removed, false, err
				}
				removed++
			}
		}
		return removed, len(situationIDs) < 16, nil
	})
}

// expireLegacyFacts deletes facts written before 0048 that were observed
// before cutoff, oldest first; its cursor persists.
func (s *Store) expireLegacyFacts(ctx context.Context, cutoff time.Time) (int, error) {
	return s.retentionPages(ctx, "expire legacy facts", func(tx *sql.Tx, deadline time.Time) (int, bool, error) {
		legacyMax, err := retentionStateTx(ctx, tx, "facts_legacy_max_rowid")
		if err != nil {
			return 0, false, err
		}
		cursor, err := retentionStateTx(ctx, tx, "facts_legacy_age_cursor")
		if err != nil || cursor >= legacyMax {
			return 0, true, err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT rowid, id, observed_at FROM situation_facts WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT ?`,
			cursor, legacyMax, retentionPageRows)
		if err != nil {
			return 0, false, fmt.Errorf("select legacy facts past retention: %w", err)
		}
		var after int64
		candidates, reached, err := scanRetentionCandidatesUnprotected(rows, cutoff, &after)
		if err != nil {
			return 0, false, err
		}
		if len(candidates) > 0 {
			if err := authorizeRetentionTx(ctx, tx, "legacy_facts", "age"); err != nil {
				return 0, false, err
			}
		}
		removed := 0
		for _, c := range candidates {
			if removed > 0 && time.Now().After(deadline) {
				reached = false
				break
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM situation_facts WHERE rowid = ?`, c.rowID); err != nil {
				return removed, false, fmt.Errorf("delete legacy fact %s: %w", c.id, err)
			}
			cursor = c.rowID
			removed++
		}
		if len(candidates) > 0 {
			if err := endRetentionTx(ctx, tx, "legacy_facts", "age"); err != nil {
				return removed, false, err
			}
		}
		return removed, reached, setRetentionStateTx(ctx, tx, "facts_legacy_age_cursor", cursor)
	})
}

func scanRowIDs(rows *sql.Rows) ([]int64, error) {
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read rows: %w", err)
	}
	return out, nil
}

func scanStrings(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read rows: %w", err)
	}
	return out, nil
}
