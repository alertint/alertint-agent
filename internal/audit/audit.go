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
	"sort"
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
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := a.AppendTx(ctx, tx, actor, kind, payload, a.now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// AppendTx appends one hash-chained row inside the caller's transaction.
// It lets a domain write and its audit evidence commit or roll back together.
// The caller owns commit/rollback and supplies the authoritative event time.
func (a *Auditor) AppendTx(ctx context.Context, tx *sql.Tx, actor, kind string, payload any, at time.Time) error {
	if tx == nil {
		return errors.New("audit: append tx requires a transaction")
	}
	if err := validateAppendArgs(actor, kind); err != nil {
		return err
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("audit: canonicalize payload: %w", err)
	}

	var prev sql.NullString
	row := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
	if err := row.Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit: read prev_hash: %w", err)
	}

	ts := at.UTC().Format(time.RFC3339Nano)
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

// UsageStats is the stable operational summary exposed by
// alertint_usage_stats over the half-open window [Since, Until). All values
// come from append-only audit history rather than mutable projections.
type UsageStats struct {
	Since, Until time.Time

	AlertDeliveries int
	AlertsReceived  int

	LLMCalls               int
	LLMInputTokens         int64
	LLMOutputTokens        int64
	LLMCacheCreationTokens int64
	LLMCacheReadTokens     int64
	LLMByModel             []ModelUsage

	SlackCardsPosted int
	SlackSkipped     int

	IncidentsAnalyzed        int
	IncidentsTriageExhausted int
}

// ModelUsage is one provider/model breakdown within UsageStats.
type ModelUsage struct {
	Provider            string `json:"provider"`
	Model               string `json:"model"`
	Calls               int    `json:"calls"`
	InputTokens         int64  `json:"input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	CacheCreationTokens int64  `json:"cache_creation_tokens"`
	CacheReadTokens     int64  `json:"cache_read_tokens"`
}

// UsageStats aggregates operational counters from the audit log. It accepts
// both the pre-Situation Slack audit vocabulary and the current Situation
// notification ledger so upgrades preserve the full requested window.
func (a *Auditor) UsageStats(ctx context.Context, since, until time.Time) (UsageStats, error) {
	out := UsageStats{Since: since.UTC(), Until: until.UTC()}
	w := tsWindow(since, until)
	if err := a.scanUsageCounts(ctx, w, &out); err != nil {
		return UsageStats{}, err
	}
	if err := a.scanIntakeAndSlack(ctx, w, &out); err != nil {
		return UsageStats{}, err
	}
	if err := a.scanLLMUsage(ctx, w, &out); err != nil {
		return UsageStats{}, err
	}
	return out, nil
}

type tsWindowPred struct {
	sql  string
	args []any
}

const tsNormalizedCol = `(substr(ts, 1, 19) || '.' || substr(ltrim(rtrim(substr(ts, 20), 'Z'), '.') || '000000000', 1, 9))`

func tsWindow(since, until time.Time) tsWindowPred {
	const exactLayout = "2006-01-02T15:04:05.000000000"
	const coarseLayout = "2006-01-02T15:04:05"
	since, until = since.UTC(), until.UTC()
	return tsWindowPred{
		sql: `ts >= ? AND ts < ? AND ` + tsNormalizedCol + ` >= ? AND ` + tsNormalizedCol + ` < ?`,
		args: []any{
			since.Truncate(time.Second).Format(coarseLayout),
			until.Truncate(time.Second).Add(time.Second).Format(coarseLayout),
			since.Format(exactLayout), until.Format(exactLayout),
		},
	}
}

func (a *Auditor) scanUsageCounts(ctx context.Context, w tsWindowPred, out *UsageStats) error {
	rows, err := a.db.QueryContext(ctx, usageCountsQuery(w), w.args...)
	if err != nil {
		return fmt.Errorf("audit: usage stats counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var actor, kind string
		var n int
		if err := rows.Scan(&actor, &kind, &n); err != nil {
			return fmt.Errorf("audit: usage stats scan: %w", err)
		}
		switch {
		case actor == "notify.slack" && kind == "notify.skipped":
			out.SlackSkipped += n
		case kind == "incident.analyzed":
			out.IncidentsAnalyzed += n
		case kind == "incident.triage_exhausted":
			out.IncidentsTriageExhausted += n
		}
	}
	return rows.Err()
}

func (a *Auditor) scanIntakeAndSlack(ctx context.Context, w tsWindowPred, out *UsageStats) error {
	if err := a.db.QueryRowContext(ctx, usageAlertIntakeQuery(w), w.args...).
		Scan(&out.AlertDeliveries, &out.AlertsReceived); err != nil {
		return fmt.Errorf("audit: usage stats alert intake: %w", err)
	}
	if err := a.db.QueryRowContext(ctx, usageSlackCardsQuery(w), w.args...).Scan(&out.SlackCardsPosted); err != nil {
		return fmt.Errorf("audit: usage stats slack cards: %w", err)
	}
	var situationWithheld int
	if err := a.db.QueryRowContext(ctx, usageWithheldQuery(w), w.args...).Scan(&situationWithheld); err != nil {
		return fmt.Errorf("audit: usage stats withheld notifications: %w", err)
	}
	out.SlackSkipped += situationWithheld
	return nil
}

func usageCountsQuery(w tsWindowPred) string {
	return `SELECT actor, kind, COUNT(*) FROM audit_log WHERE ` + w.sql + ` GROUP BY actor, kind`
}

func usageAlertIntakeQuery(w tsWindowPred) string {
	return `SELECT COUNT(*), COALESCE(SUM(COALESCE(json_extract(payload_json, '$.alert_count'), 1)), 0)
		FROM audit_log WHERE kind = 'alert.received' AND ` + w.sql
}

func usageSlackCardsQuery(w tsWindowPred) string {
	return `SELECT COUNT(*) FROM audit_log
		WHERE kind IN ('notify.sent', 'situation.notification.delivered')
		  AND ((actor = 'notify.slack' AND kind = 'notify.sent'
		        AND COALESCE(json_extract(payload_json, '$.new_card'), json_extract(payload_json, '$.event') = 'firing') = 1)
		       OR (kind = 'situation.notification.delivered'
		           AND json_extract(payload_json, '$.effect_class') = 'root_sync'
		           AND json_extract(payload_json, '$.new_root') = 1))
		  AND ` + w.sql
}

func usageWithheldQuery(w tsWindowPred) string {
	return `SELECT COUNT(*) FROM audit_log
		WHERE kind = 'situation.notification.withheld'
		  AND json_extract(payload_json, '$.main_channel_poke') = 1
		  AND ` + w.sql
}

func usageLLMResponsesQuery(w tsWindowPred) string {
	return `SELECT actor, payload_json FROM audit_log WHERE kind = 'llm.response' AND ` + w.sql
}

type llmResponsePayload struct {
	Model                    string `json:"model"`
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
}

func (a *Auditor) scanLLMUsage(ctx context.Context, w tsWindowPred, out *UsageStats) error {
	rows, err := a.db.QueryContext(ctx, usageLLMResponsesQuery(w), w.args...)
	if err != nil {
		return fmt.Errorf("audit: usage stats llm scan: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byModel := map[[2]string]*ModelUsage{}
	for rows.Next() {
		var actor, payload string
		if err := rows.Scan(&actor, &payload); err != nil {
			return fmt.Errorf("audit: usage stats llm row scan: %w", err)
		}
		var p llmResponsePayload
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			continue
		}
		out.LLMCalls++
		out.LLMInputTokens += p.InputTokens
		out.LLMOutputTokens += p.OutputTokens
		out.LLMCacheCreationTokens += p.CacheCreationInputTokens
		out.LLMCacheReadTokens += p.CacheReadInputTokens
		key := [2]string{actor, p.Model}
		row := byModel[key]
		if row == nil {
			row = &ModelUsage{Provider: actor, Model: p.Model}
			byModel[key] = row
		}
		row.Calls++
		row.InputTokens += p.InputTokens
		row.OutputTokens += p.OutputTokens
		row.CacheCreationTokens += p.CacheCreationInputTokens
		row.CacheReadTokens += p.CacheReadInputTokens
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: usage stats llm iterate: %w", err)
	}
	for _, row := range byModel {
		out.LLMByModel = append(out.LLMByModel, *row)
	}
	sort.Slice(out.LLMByModel, func(i, j int) bool {
		if out.LLMByModel[i].Provider != out.LLMByModel[j].Provider {
			return out.LLMByModel[i].Provider < out.LLMByModel[j].Provider
		}
		return out.LLMByModel[i].Model < out.LLMByModel[j].Model
	})
	return nil
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
