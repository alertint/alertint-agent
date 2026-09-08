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

// UsageStats is the aggregate operational summary backing the
// alertint_usage_stats MCP tool: LLM call/token volume (with a per-model
// breakdown), Slack delivery outcomes, and incident processing counts, over
// the half-open window [Since, Until). Alert intake is deliberately absent —
// no "alert received" kind is ever appended to the audit log, so the MCP
// handler sources that count from store.CountAlertsReceived instead.
type UsageStats struct {
	Since, Until time.Time

	LLMCalls               int
	LLMInputTokens         int64
	LLMOutputTokens        int64
	LLMCacheCreationTokens int64
	LLMCacheReadTokens     int64
	LLMByModel             []ModelUsage

	SlackSent    int
	SlackSkipped int

	IncidentsProcessed int
	IncidentsFailed    int
}

// ModelUsage is one (provider, model) breakdown row within
// UsageStats.LLMByModel. Provider is the audit actor that emitted the calls
// ("llm.anthropic" or "llm.openaicompat"), not a free-form label.
type ModelUsage struct {
	Provider            string
	Model               string
	Calls               int
	InputTokens         int64
	OutputTokens        int64
	CacheCreationTokens int64
	CacheReadTokens     int64
}

// UsageStats aggregates operational counters from the audit log over the
// half-open window [since, until). It runs two scoped queries: one grouped
// count over (actor, kind) for the Slack/incident counters, and one scan of
// llm.response rows in-window to sum token fields out of their payload_json
// (that column already carries input/output/cache token counts — see
// internal/llm/anthropic and internal/llm/openaicompat) and build the
// per-model breakdown.
func (a *Auditor) UsageStats(ctx context.Context, since, until time.Time) (UsageStats, error) {
	sinceStr := since.UTC().Format(time.RFC3339Nano)
	untilStr := until.UTC().Format(time.RFC3339Nano)
	out := UsageStats{Since: since.UTC(), Until: until.UTC()}

	if err := a.scanUsageCounts(ctx, sinceStr, untilStr, &out); err != nil {
		return UsageStats{}, err
	}
	if err := a.scanLLMUsage(ctx, sinceStr, untilStr, &out); err != nil {
		return UsageStats{}, err
	}
	return out, nil
}

// scanUsageCounts fills the Slack and incident counters via one grouped
// COUNT(*) query over (actor, kind). Any (actor, kind) pair not named below
// is deliberately ignored — alertint_usage_stats returns a curated summary,
// not a raw per-kind dump.
func (a *Auditor) scanUsageCounts(ctx context.Context, sinceStr, untilStr string, out *UsageStats) error {
	rows, err := a.db.QueryContext(ctx, `
		SELECT actor, kind, COUNT(*)
		FROM audit_log
		WHERE ts >= ? AND ts < ?
		GROUP BY actor, kind
	`, sinceStr, untilStr)
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
		case actor == "notify.slack" && kind == "notify.sent":
			out.SlackSent = n
		case actor == "notify.slack" && kind == "notify.skipped":
			out.SlackSkipped = n
		case kind == "incident.analyzed":
			out.IncidentsProcessed = n
		case kind == "incident.analysis_failed":
			out.IncidentsFailed = n
		}
	}
	return rows.Err()
}

// llmResponsePayload is the subset of an llm.response audit payload
// UsageStats needs — see internal/llm/anthropic/client.go and
// internal/llm/openaicompat/client.go for the full shape written at Append time.
type llmResponsePayload struct {
	Model                    string `json:"model"`
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
}

// scanLLMUsage fills the LLM call/token totals and per-model breakdown by
// scanning llm.response rows in-window. A row whose payload_json doesn't
// unmarshal into llmResponsePayload is skipped rather than failing the whole
// call — it stays out of both the total and the per-model breakdown.
func (a *Auditor) scanLLMUsage(ctx context.Context, sinceStr, untilStr string, out *UsageStats) error {
	rows, err := a.db.QueryContext(ctx, `
		SELECT actor, payload_json
		FROM audit_log
		WHERE ts >= ? AND ts < ? AND kind = 'llm.response'
	`, sinceStr, untilStr)
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
		mu, ok := byModel[key]
		if !ok {
			mu = &ModelUsage{Provider: actor, Model: p.Model}
			byModel[key] = mu
		}
		mu.Calls++
		mu.InputTokens += p.InputTokens
		mu.OutputTokens += p.OutputTokens
		mu.CacheCreationTokens += p.CacheCreationInputTokens
		mu.CacheReadTokens += p.CacheReadInputTokens
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: usage stats llm iterate: %w", err)
	}

	out.LLMByModel = make([]ModelUsage, 0, len(byModel))
	for _, mu := range byModel {
		out.LLMByModel = append(out.LLMByModel, *mu)
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
