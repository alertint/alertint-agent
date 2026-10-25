// SPDX-License-Identifier: FSL-1.1-ALv2

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// KindAuditPruned is the anchor storage retention appends to the chain before
// it removes the entries it covers: the last removed seq and its hash. The
// first entry kept then names that hash as its prev_hash, and Verify accepts
// it only when an anchor in the verified chain accounts for it.
const KindAuditPruned = "storage.audit_pruned"

const auditPruneActor = "store.retention"

// One prune step is one transaction: it removes at most auditPruneStep
// entries, so it never holds the store's only connection for long.
var (
	auditPruneStep  = 2000
	auditPrunePause = 20 * time.Millisecond
)

// prunedAnchor is KindAuditPruned's payload.
type prunedAnchor struct {
	ThroughSeq  int64  `json:"through_seq"`
	ThroughHash string `json:"through_hash"`
	ThroughTS   string `json:"through_ts"`
	Pruned      int    `json:"pruned"`
	Cutoff      string `json:"cutoff"`
}

// PruneBefore removes the oldest audit entries recorded before cutoff, in
// steps, each anchored in the chain first. It stops at the first entry at or
// after cutoff, so an entry appended late with an older time is kept until
// the entries before it go. Returns the entries removed.
func (a *Auditor) PruneBefore(ctx context.Context, cutoff time.Time) (int, error) {
	total := 0
	for {
		n, err := a.pruneStep(ctx, cutoff)
		total += n
		if err != nil || n == 0 {
			return total, err
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(auditPrunePause):
		}
	}
}

func (a *Auditor) pruneStep(ctx context.Context, cutoff time.Time) (int, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("audit: begin prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	through, err := readPrunablePrefix(ctx, tx, cutoff)
	if err != nil {
		return 0, err
	}
	if through.Pruned == 0 {
		return 0, nil
	}
	through.Cutoff = cutoff.UTC().Format(time.RFC3339Nano)
	if err := a.AppendTx(ctx, tx, auditPruneActor, KindAuditPruned, through, a.now().UTC()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= ?`, through.ThroughSeq); err != nil {
		return 0, fmt.Errorf("audit: prune through seq %d: %w", through.ThroughSeq, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit: commit prune: %w", err)
	}
	return through.Pruned, nil
}

// readPrunablePrefix reads, among the oldest auditPruneStep entries, the run
// recorded before cutoff, and returns the anchor that would account for it.
func readPrunablePrefix(ctx context.Context, tx *sql.Tx, cutoff time.Time) (prunedAnchor, error) {
	var through prunedAnchor
	rows, err := tx.QueryContext(ctx, `SELECT seq, ts, hash FROM audit_log ORDER BY seq LIMIT ?`, auditPruneStep)
	if err != nil {
		return through, fmt.Errorf("audit: read oldest entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var seq int64
		var ts, hash string
		if err := rows.Scan(&seq, &ts, &hash); err != nil {
			return through, fmt.Errorf("audit: scan oldest entry: %w", err)
		}
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return through, fmt.Errorf("audit: entry %d time %q: %w", seq, ts, err)
		}
		if !at.Before(cutoff) {
			break
		}
		through.ThroughSeq, through.ThroughHash, through.ThroughTS = seq, hash, ts
		through.Pruned++
	}
	if err := rows.Err(); err != nil {
		return through, fmt.Errorf("audit: read oldest entries: %w", err)
	}
	return through, nil
}

// OldestEntry returns the time of the oldest audit entry kept.
func (a *Auditor) OldestEntry(ctx context.Context) (time.Time, bool, error) {
	var ts string
	err := a.db.QueryRowContext(ctx, `SELECT ts FROM audit_log ORDER BY seq LIMIT 1`).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("audit: read oldest entry: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("audit: oldest entry time %q: %w", ts, err)
	}
	return at.UTC(), true, nil
}

// pruneAnchorFor finds the anchor that accounts for a chain starting at
// firstSeq with prev_hash prev: a KindAuditPruned entry that removed every
// entry before firstSeq and whose last removed hash is prev.
func (a *Auditor) pruneAnchorFor(ctx context.Context, firstSeq int64, prev string) (anchorSeq, throughSeq int64, found bool, err error) {
	err = a.db.QueryRowContext(ctx, `
		SELECT seq, json_extract(payload_json, '$.through_seq') FROM audit_log
		WHERE kind = ? AND json_extract(payload_json, '$.through_hash') = ?
		  AND json_extract(payload_json, '$.through_seq') < ?
		ORDER BY seq DESC LIMIT 1`, KindAuditPruned, prev, firstSeq).Scan(&anchorSeq, &throughSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, fmt.Errorf("audit: find prune anchor: %w", err)
	}
	return anchorSeq, throughSeq, true, nil
}
