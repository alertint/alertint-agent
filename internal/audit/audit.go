// SPDX-License-Identifier: FSL-1.1-ALv2

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

// ----------------------------------------------------------------------
// Plan 3 Task 9: the Situation history and delivery event catalog.
//
// Audit event kinds are ordinary strings elsewhere in this codebase, written
// at their emitting call site. Plan 3's are named here instead for one
// reason: spec.md requires a specific, complete set of events, and plan.md
// requires that none of them collide with Plan 2's existing catalog. A
// catalog stated in one place is the only way a test can prove both — and
// this package, which every emitter already depends on, is the one place
// that cannot create an import cycle.
//
// Every Plan 3 kind lives under exactly one of three dotted prefixes:
// situation.history.* (what durably happened to a Situation's operator
// history), situation.notification.* (what happened to a durable Slack
// delivery obligation), and situation.transition_stream.* (what happened to
// the stdout state stream). Plan 2's names are underscore-separated after
// "situation." (situation.assessment_*, situation.triage_*) or a different
// dotted namespace (situation.controller.commit_failed, incident.triage_*),
// so the two families cannot overlap.
// ----------------------------------------------------------------------

const (
	// KindHistoryTransitionCommitted records one immutable Transition
	// landing in the fenced controller commit.
	KindHistoryTransitionCommitted = "situation.history.transition_committed"
	// KindHistorySummaryProjected records the Episode-summary version that
	// commit folded.
	KindHistorySummaryProjected = "situation.history.summary_projected"
	// KindHistoryArtifactJournaled records one operator artifact consumed
	// into an operator_artifact_recorded Transition (R1).
	KindHistoryArtifactJournaled = "situation.history.artifact_journaled"
	// KindHistoryArtifactOwnerTerminal records an artifact that reached an
	// already-terminal owner: visible, never journaled (R2). Its emitter is
	// the input-application path (Store.ApplySituationInput, which marks the
	// row owner_terminal), which carries no audit seam in this slice —
	// ApplySituationInput returns only an error, so the applying worker
	// cannot tell that outcome from an ordinary attach. The name is reserved
	// here because spec.md's event list requires it and because reserving it
	// keeps the collision check honest; wiring the emitter needs
	// ApplySituationInput to report the outcome, which is Plan 3's
	// input-application contract, not this task's.
	KindHistoryArtifactOwnerTerminal = "situation.history.artifact_owner_terminal"

	// KindNotificationIntentCreated records one durable delivery obligation
	// created by the authoritative commit.
	KindNotificationIntentCreated = "situation.notification.intent_created"
	// KindNotificationClaimed records one fenced claim of that obligation.
	KindNotificationClaimed = "situation.notification.claimed"
	// KindNotificationDelivered records an acknowledged Slack delivery and
	// its coordinates.
	KindNotificationDelivered = "situation.notification.delivered"
	// KindNotificationRetried records one scheduled indefinite retry.
	KindNotificationRetried = "situation.notification.retried"
	// KindNotificationConfigurationBlocked records a definite token, scope,
	// or channel rejection holding the effect until configuration changes.
	KindNotificationConfigurationBlocked = "situation.notification.configuration_blocked"
	// KindNotificationFailed records the one permanent outcome: a durable
	// intent this build proved invalid. It stays operator-redriveable.
	KindNotificationFailed = "situation.notification.failed"
	// KindNotificationWithheld records a poke the operator's Slack floor
	// withheld — a durable decision, never an absent row.
	KindNotificationWithheld = "situation.notification.withheld"
	// KindNotificationSuperseded records an older root projection retired by
	// a newer one.
	KindNotificationSuperseded = "situation.notification.superseded"
	// KindNotificationGapOpened, ...Recovered, and ...Completed record the
	// ADR-0042 Delivery-gap generation lifecycle.
	KindNotificationGapOpened    = "situation.notification.gap_opened"
	KindNotificationGapRecovered = "situation.notification.gap_recovered"
	KindNotificationGapCompleted = "situation.notification.gap_completed"

	// KindTransitionStreamEmitted records one acknowledged stdout line;
	// KindTransitionStreamFailed records a durable stream row this build
	// cannot render at all.
	KindTransitionStreamEmitted = "situation.transition_stream.emitted"
	KindTransitionStreamFailed  = "situation.transition_stream.failed"
)

// SituationHistoryKinds returns every Plan 3 event kind, in catalog order.
// Its completeness against spec.md's own required event list, and its
// disjointness from ReservedPlan2Kinds, are both pinned by this package's
// tests.
func SituationHistoryKinds() []string {
	return []string{
		KindHistoryTransitionCommitted,
		KindHistorySummaryProjected,
		KindHistoryArtifactJournaled,
		KindHistoryArtifactOwnerTerminal,
		KindNotificationIntentCreated,
		KindNotificationClaimed,
		KindNotificationDelivered,
		KindNotificationRetried,
		KindNotificationConfigurationBlocked,
		KindNotificationFailed,
		KindNotificationWithheld,
		KindNotificationSuperseded,
		KindNotificationGapOpened,
		KindNotificationGapRecovered,
		KindNotificationGapCompleted,
		KindTransitionStreamEmitted,
		KindTransitionStreamFailed,
	}
}

// ReservedPlan2Kinds is the existing Situation/Incident audit vocabulary
// Plan 3 must not collide with: the controller's Assessment and Triage
// events (internal/situation/controller.go), its commit-failure diagnostic,
// the Triage worker's own skip event, and the Incident Triage exhaustion
// event the startup horizon and the Triage worker both emit. It exists so
// the collision rule is checkable rather than merely stated.
func ReservedPlan2Kinds() []string {
	return []string{
		"situation.assessment_authoritative",
		"situation.assessment_fallback",
		"situation.assessment_reused",
		"situation.assessment_stale",
		"situation.assessment_call_dispatched",
		"situation.assessment_rejected",
		"situation.assessment_failed",
		"situation.triage_requested",
		"situation.triage_skipped",
		"situation.controller.commit_failed",
		"incident.triage_exhausted",
	}
}
