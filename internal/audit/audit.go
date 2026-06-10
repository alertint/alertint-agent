// Package audit implements the agent's hash-chained audit log.
//
// Every action in the agent appends a row to the audit_log table. Each
// row's hash includes the previous row's hash, so any tampering with an
// earlier row's stored fields (ts, actor, kind, payload, prev_hash) will
// cause Verify to fail at that row.
//
// Hash input (per pivot_to_agent_PLAN.md, Slice 03):
//
//	hash = SHA256( ts \x1f actor \x1f kind \x1f canonical_json(payload) \x1f COALESCE(prev_hash, "") )
//
// The 0x1f (ASCII unit separator) byte between fields prevents
// concatenation collisions: without a separator, ("ab", "cdef") and
// ("abc", "def") would hash to the same value. seq is intentionally
// excluded so we don't need a two-step INSERT...RETURNING + UPDATE.
//
// v1 is chain-only. v2 will add Ed25519 signing per row plus an external
// anchor (e.g. a daily root hash committed to a Git repo).
package audit

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
)

// Separator placed between hash input fields. ASCII unit separator.
const fieldSep byte = 0x1f

// Auditor appends and verifies hash-chained audit rows.
type Auditor struct {
	db  *sql.DB
	now func() time.Time
}

// New constructs an Auditor backed by the given database handle. The
// database must already have the schema from internal/store applied.
func New(db *sql.DB) *Auditor {
	return &Auditor{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// withClock returns a copy of a using the provided clock. Used in tests
// to make timestamps deterministic.
func (a *Auditor) withClock(now func() time.Time) *Auditor {
	cp := *a
	cp.now = now
	return &cp
}

// Append writes a new audit row inside a transaction. actor is a short
// identifier of who performed the action (e.g. "ingress", "skill:acute-triage").
// kind is the event type (e.g. "alert.received"). payload may be any
// JSON-marshalable value; it is normalized into canonical JSON before
// hashing so the same logical payload always produces the same hash.
func (a *Auditor) Append(ctx context.Context, actor, kind string, payload any) error {
	if err := validateAppendArgs(actor, kind); err != nil {
		return err
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("audit: canonicalize payload: %w", err)
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var prev sql.NullString
	row := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
	if err := row.Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit: read prev_hash: %w", err)
	}

	ts := a.now().UTC().Format(time.RFC3339Nano)
	hash := computeHash(ts, actor, kind, canonical, prev.String)

	var prevArg any
	if prev.Valid {
		prevArg = prev.String
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor, kind, payload_json, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?)
	`, ts, actor, kind, string(canonical), prevArg, hash); err != nil {
		return fmt.Errorf("audit: insert row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// VerifyReport summarizes a Verify call.
type VerifyReport struct {
	// RowsChecked is the number of rows successfully verified before
	// either reaching the end (OK) or hitting the first mismatch.
	RowsChecked int
	// OK is true when the entire chain verifies cleanly.
	OK bool
	// FailedSeq is the seq of the first failing row (0 when OK).
	FailedSeq int64
	// Reason describes the failure (empty when OK).
	Reason string
}

// Verify walks the audit log in seq order and recomputes each row's
// hash. It returns a non-nil error if the chain is broken, with the
// report pointing at the first failing row.
func (a *Auditor) Verify(ctx context.Context) (*VerifyReport, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT seq, ts, actor, kind, payload_json, prev_hash, hash
		FROM audit_log
		ORDER BY seq ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("audit: query log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	report := &VerifyReport{OK: true}
	var lastHash string

	for rows.Next() {
		var (
			seq                      int64
			ts, actor, kind, payload string
			storedHash               string
			storedPrev               sql.NullString
		)
		if err := rows.Scan(&seq, &ts, &actor, &kind, &payload, &storedPrev, &storedHash); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}

		// Chain link: stored prev_hash must equal the previous row's hash.
		// First row must have NULL prev_hash.
		actualPrev := ""
		if storedPrev.Valid {
			actualPrev = storedPrev.String
		}
		if actualPrev != lastHash {
			report.OK = false
			report.FailedSeq = seq
			report.Reason = fmt.Sprintf("prev_hash mismatch (stored=%q, expected=%q)", actualPrev, lastHash)
			return report, fmt.Errorf("audit: chain broken at seq %d: %s", seq, report.Reason)
		}

		// Hash recomputation.
		expected := computeHash(ts, actor, kind, []byte(payload), actualPrev)
		if expected != storedHash {
			report.OK = false
			report.FailedSeq = seq
			report.Reason = "hash mismatch (row was tampered with after insert)"
			return report, fmt.Errorf("audit: hash mismatch at seq %d", seq)
		}

		lastHash = storedHash
		report.RowsChecked++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return report, nil
}

// computeHash returns the hex-encoded SHA-256 of the chained input.
// prevHash is empty string for the first row.
func computeHash(ts, actor, kind string, canonical []byte, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(ts))
	h.Write([]byte{fieldSep})
	h.Write([]byte(actor))
	h.Write([]byte{fieldSep})
	h.Write([]byte(kind))
	h.Write([]byte{fieldSep})
	h.Write(canonical)
	h.Write([]byte{fieldSep})
	h.Write([]byte(prevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON returns a stable JSON encoding of payload. It works by
// marshaling once, decoding into any (which converts every object into
// map[string]any), then re-marshaling. encoding/json marshals map keys
// in sorted order, so the output is deterministic for any payload that
// is JSON-equivalent.
//
// nil payloads encode as "null", matching json.Marshal(nil).
func canonicalJSON(payload any) ([]byte, error) {
	first, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(first, &normalized); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func validateAppendArgs(actor, kind string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("audit: actor is required")
	}
	if strings.TrimSpace(kind) == "" {
		return errors.New("audit: kind is required")
	}
	return nil
}
