// SPDX-License-Identifier: FSL-1.1-ALv2

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func newAuditor(t *testing.T) (*Auditor, *store.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s.DB()), s, ctx
}

func TestAppend_AndVerify_OnEmptyLog(t *testing.T) {
	a, _, ctx := newAuditor(t)
	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 0 {
		t.Errorf("empty log report: %+v", report)
	}
}

func TestAppend_OneRowChain(t *testing.T) {
	a, _, ctx := newAuditor(t)

	if err := a.Append(ctx, "ingress", "alert.received", map[string]any{
		"fingerprint": "abc",
		"alertname":   "HighCPU",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 1 {
		t.Fatalf("one-row report: %+v", report)
	}
}

func TestAppend_100Rows_Verifies(t *testing.T) {
	a, _, ctx := newAuditor(t)

	for i := 0; i < 100; i++ {
		if err := a.Append(ctx, "test", "tick", map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 100 {
		t.Errorf("verify report: %+v", report)
	}
}

func TestVerify_DetectsTamperedPayload(t *testing.T) {
	a, s, ctx := newAuditor(t)

	for i := 0; i < 5; i++ {
		if err := a.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Tamper with row 3's payload.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET payload_json = ? WHERE seq = 3`,
		`{"i":999}`,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := a.Verify(ctx)
	if err == nil {
		t.Fatal("expected verify to fail after tamper")
	}
	if report == nil || report.OK {
		t.Fatalf("expected non-OK report, got %+v", report)
	}
	if report.FailedSeq != 3 {
		t.Errorf("FailedSeq = %d, want 3", report.FailedSeq)
	}
}

func TestVerify_DetectsTamperedPrevHash(t *testing.T) {
	a, s, ctx := newAuditor(t)
	for i := 0; i < 4; i++ {
		_ = a.Append(ctx, "t", "k", map[string]any{"i": i})
	}

	// Break the prev_hash linkage at row 2.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET prev_hash = ? WHERE seq = 2`,
		"00",
	); err != nil {
		t.Fatalf("tamper prev: %v", err)
	}

	report, err := a.Verify(ctx)
	if err == nil || report == nil || report.OK || report.FailedSeq != 2 {
		t.Fatalf("expected chain break at seq 2, got err=%v report=%+v", err, report)
	}
}

func TestVerify_SurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	s1, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	a1 := New(s1.DB())
	for i := 0; i < 10; i++ {
		if err := a1.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	// Re-open: this re-runs the migration runner. The chain must still verify.
	s2, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer func() { _ = s2.Close() }()
	a2 := New(s2.DB())

	report, err := a2.Verify(ctx)
	if err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
	if !report.OK || report.RowsChecked != 10 {
		t.Errorf("post-reopen report: %+v", report)
	}

	// Append more rows after reopen and verify again.
	for i := 10; i < 15; i++ {
		if err := a2.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append after reopen: %v", err)
		}
	}
	report, err = a2.Verify(ctx)
	if err != nil || !report.OK || report.RowsChecked != 15 {
		t.Fatalf("post-append report: %+v err=%v", report, err)
	}
}

func TestCanonicalJSON_StableForEquivalentMaps(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1, "c": map[string]any{"y": 2, "x": 1}}
	b := map[string]any{"a": 1, "c": map[string]any{"x": 1, "y": 2}, "b": 2}
	x, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := canonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Errorf("canonical JSON differs:\n a=%s\n b=%s", x, y)
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	canonical := []byte(`{"a":1}`)
	h1 := computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "")
	h2 := computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "")
	if h1 != h2 {
		t.Error("computeHash not deterministic")
	}
	// Sanity: changing any input changes the output.
	cases := []string{
		computeHash("2026-05-22T09:55:01Z", "ingress", "alert.received", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "other", "alert.received", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.resolved", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", []byte(`{"a":2}`), ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "deadbeef"),
	}
	for i, c := range cases {
		if c == h1 {
			t.Errorf("case %d collides with base hash", i)
		}
	}
}

func TestAppend_RejectsMissingActorOrKind(t *testing.T) {
	a, _, ctx := newAuditor(t)
	if err := a.Append(ctx, "", "k", nil); err == nil {
		t.Error("expected error for empty actor")
	}
	if err := a.Append(ctx, "a", "  ", nil); err == nil {
		t.Error("expected error for blank kind")
	}
}

func TestAppend_DistinctRowsPerCall_TimestampsAdvance(t *testing.T) {
	// Use a controlled clock so we don't depend on test wall-clock granularity.
	a, _, ctx := newAuditor(t)
	base := time.Date(2026, 5, 22, 9, 55, 0, 0, time.UTC)
	steps := 0
	a = a.withClock(func() time.Time {
		t := base.Add(time.Duration(steps) * time.Second)
		steps++
		return t
	})

	for i := 0; i < 3; i++ {
		if err := a.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	report, err := a.Verify(ctx)
	if err != nil || !report.OK || report.RowsChecked != 3 {
		t.Fatalf("verify: report=%+v err=%v", report, err)
	}
}

// Sanity check that table sizes stay bounded by the chain semantics: a
// failed transaction should not leave a partial row behind.
func TestAppend_RollbackLeavesNoRow(t *testing.T) {
	a, s, ctx := newAuditor(t)
	// Force a marshal failure: channels are not JSON-serializable.
	err := a.Append(ctx, "t", "k", map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error")
	}
	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("audit_log row count after failed append = %d, want 0", count)
	}
	// Channel referenced to silence "declared and not used" suspicion.
	_ = fmt.Sprintf("%v", err)
}

func TestUsageStats_AggregatesWithinWindow(t *testing.T) {
	a, _, ctx := newAuditor(t)
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	steps := 0
	a = a.withClock(func() time.Time {
		ts := base.Add(time.Duration(steps) * time.Minute)
		steps++
		return ts
	})

	llmResponse := func(actor, model string, in, out, cacheCreate, cacheRead int64) {
		t.Helper()
		if err := a.Append(ctx, actor, "llm.response", map[string]any{
			"model":                       model,
			"input_tokens":                in,
			"output_tokens":               out,
			"cache_creation_input_tokens": cacheCreate,
			"cache_read_input_tokens":     cacheRead,
		}); err != nil {
			t.Fatalf("append llm.response: %v", err)
		}
	}
	slackSent := func(event string, newCard bool) {
		t.Helper()
		if err := a.Append(ctx, "notify.slack", "notify.sent", map[string]any{
			"incident_id": "inc-1", "event": event, "recipient": "slack", "new_card": newCard,
		}); err != nil {
			t.Fatalf("append notify.sent %s: %v", event, err)
		}
	}
	// Rows written before the notifier recorded new_card: only a "firing"
	// event meant a new card back then.
	slackSentLegacy := func(event string) {
		t.Helper()
		if err := a.Append(ctx, "notify.slack", "notify.sent", map[string]any{
			"incident_id": "inc-0", "event": event, "recipient": "slack",
		}); err != nil {
			t.Fatalf("append legacy notify.sent %s: %v", event, err)
		}
	}

	llmResponse("llm.anthropic", "claude-x", 100, 50, 10, 5)                       // t=10:00
	llmResponse("llm.anthropic", "claude-x", 200, 80, 0, 0)                        // t=10:01
	llmResponse("llm.openaicompat", "gpt-y", 40, 20, 0, 0)                         // t=10:02
	slackSent("firing", true)                                                      // t=10:03 — a new card: one poke
	slackSent("resolved", true)                                                    // t=10:04 — resolved before any firing card: a new card, one poke
	slackSent("rejudge", false)                                                    // t=10:05 — in-place edit, not a poke
	slackSent("resolved", false)                                                   // t=10:06 — resolved update on an existing card, not a poke
	slackSentLegacy("firing")                                                      // t=10:07 — pre-new_card row: firing meant a new card
	slackSentLegacy("resolved")                                                    // t=10:08 — pre-new_card row: ambiguous, not counted
	mustAppend(t, a, ctx, "notify.slack", "notify.skipped")                        // t=10:09
	mustAppend(t, a, ctx, "notify.stdout", "notify.sent")                          // t=10:10 — not Slack, must be excluded
	mustAppend(t, a, ctx, "skill:acute-triage", "incident.analyzed")               // t=10:11
	mustAppend(t, a, ctx, "skill:acute-triage", "incident.analyzed")               // t=10:12
	mustAppend(t, a, ctx, "skill:acute-triage", "incident.analysis_failed")        // t=10:13 — retryable attempt failure, not terminal
	mustAppend(t, a, ctx, "skill:acute-triage", "incident.analysis_failed")        // t=10:14 — same incident, retried again
	mustAppend(t, a, ctx, "correlator", "incident.triage_exhausted")               // t=10:15 — terminal: one failed incident
	mustAppend(t, a, ctx, "llm.anthropic", "llm.request")                          // t=10:16 — request, not response
	mustAppendPayload(t, a, ctx, "alertmanager", "alert.received", map[string]any{ // t=10:17 — one delivery, three alerts
		"alert_count": 3, "persisted_count": 3,
	})
	mustAppendPayload(t, a, ctx, "alertmanager", "alert.received", map[string]any{ // t=10:18 — repeat delivery of a known alert still counts
		"alert_count": 1, "persisted_count": 1,
	})
	mustAppendPayload(t, a, ctx, "zabbix", "alert.received", map[string]any{ // t=10:19 — Zabbix rows carry no alert_count: one alert
		"event_id": "42", "persisted": true,
	})
	llmResponse("llm.anthropic", "claude-x", 999, 999, 0, 0) // t=10:20 — outside window (until excludes it)

	since := base
	until := base.Add(20 * time.Minute) // half-open: excludes the t=10:20 row

	got, err := a.UsageStats(ctx, since, until)
	if err != nil {
		t.Fatalf("UsageStats: %v", err)
	}

	if got.AlertDeliveries != 3 || got.AlertsReceived != 5 {
		t.Errorf("alerts = deliveries:%d received:%d, want deliveries:3 received:5", got.AlertDeliveries, got.AlertsReceived)
	}
	if got.LLMCalls != 3 {
		t.Errorf("LLMCalls = %d, want 3", got.LLMCalls)
	}
	if got.LLMInputTokens != 340 || got.LLMOutputTokens != 150 {
		t.Errorf("LLM tokens = in:%d out:%d, want in:340 out:150", got.LLMInputTokens, got.LLMOutputTokens)
	}
	if got.LLMCacheCreationTokens != 10 || got.LLMCacheReadTokens != 5 {
		t.Errorf("LLM cache tokens = create:%d read:%d, want create:10 read:5", got.LLMCacheCreationTokens, got.LLMCacheReadTokens)
	}
	if len(got.LLMByModel) != 2 {
		t.Fatalf("LLMByModel len = %d, want 2: %+v", len(got.LLMByModel), got.LLMByModel)
	}
	anthropic, openai := got.LLMByModel[0], got.LLMByModel[1]
	if anthropic.Provider != "llm.anthropic" || anthropic.Model != "claude-x" || anthropic.Calls != 2 ||
		anthropic.InputTokens != 300 || anthropic.OutputTokens != 130 ||
		anthropic.CacheCreationTokens != 10 || anthropic.CacheReadTokens != 5 {
		t.Errorf("anthropic breakdown = %+v", anthropic)
	}
	if openai.Provider != "llm.openaicompat" || openai.Model != "gpt-y" || openai.Calls != 1 ||
		openai.InputTokens != 40 || openai.OutputTokens != 20 {
		t.Errorf("openaicompat breakdown = %+v", openai)
	}

	if got.SlackCardsPosted != 3 || got.SlackSkipped != 1 {
		t.Errorf("Slack = cards:%d skipped:%d, want cards:3 skipped:1 (firing, resolved-first, legacy firing)", got.SlackCardsPosted, got.SlackSkipped)
	}
	if got.IncidentsAnalyzed != 2 || got.IncidentsTriageExhausted != 1 {
		t.Errorf("Incidents = analyzed:%d exhausted:%d, want analyzed:2 exhausted:1", got.IncidentsAnalyzed, got.IncidentsTriageExhausted)
	}
}

// TestUsageStats_WindowBoundariesWithFractionalTimestamps pins the boundary
// semantics against the variable-precision RFC3339Nano ts column: a row at
// 12:00:00.5Z must fall inside [12:00:00Z, 13:00:00Z) and a row at
// 13:00:00.5Z outside it, even though a plain lexical comparison of the
// stored strings says the opposite for both.
func TestUsageStats_WindowBoundariesWithFractionalTimestamps(t *testing.T) {
	a, _, ctx := newAuditor(t)
	clock := time.Time{}
	a = a.withClock(func() time.Time { return clock })
	at := func(ts time.Time) {
		t.Helper()
		clock = ts
		mustAppend(t, a, ctx, "skill:acute-triage", "incident.analyzed")
	}
	h := func(hour, minute, sec, nsec int) time.Time {
		return time.Date(2026, 9, 8, hour, minute, sec, nsec, time.UTC)
	}

	at(h(11, 59, 59, 999_999_999)) // just before since: out
	at(h(12, 0, 0, 0))             // exactly since: in (inclusive)
	at(h(12, 0, 0, 500_000_000))   // fractional just after since: in
	at(h(12, 30, 0, 0))            // middle: in
	at(h(12, 59, 59, 999_999_999)) // just before until: in
	at(h(13, 0, 0, 0))             // exactly until: out (exclusive)
	at(h(13, 0, 0, 500_000_000))   // fractional just after until: out
	at(h(13, 0, 1, 0))             // a second after until: out

	got, err := a.UsageStats(ctx, h(12, 0, 0, 0), h(13, 0, 0, 0))
	if err != nil {
		t.Fatalf("UsageStats: %v", err)
	}
	if got.IncidentsAnalyzed != 4 {
		t.Errorf("IncidentsAnalyzed = %d, want 4 (12:00:00, 12:00:00.5, 12:30:00, 12:59:59.999999999)", got.IncidentsAnalyzed)
	}

	// Fractional bounds must work too: [12:00:00.25, 13:00:00.25) drops the
	// 12:00:00 row and picks up the 13:00:00 row.
	got, err = a.UsageStats(ctx, h(12, 0, 0, 250_000_000), h(13, 0, 0, 250_000_000))
	if err != nil {
		t.Fatalf("UsageStats (fractional bounds): %v", err)
	}
	if got.IncidentsAnalyzed != 4 {
		t.Errorf("IncidentsAnalyzed (fractional bounds) = %d, want 4 (12:00:00.5, 12:30:00, 12:59:59.999999999, 13:00:00)", got.IncidentsAnalyzed)
	}
}

func TestUsageStats_SkipsMalformedPayloadWithoutFailing(t *testing.T) {
	a, s, ctx := newAuditor(t)

	if err := a.Append(ctx, "llm.anthropic", "llm.response", map[string]any{
		"model": "claude-x", "input_tokens": int64(100), "output_tokens": int64(50),
	}); err != nil {
		t.Fatalf("append good row: %v", err)
	}
	if err := a.Append(ctx, "llm.anthropic", "llm.response", map[string]any{
		"model": "claude-x", "input_tokens": int64(999), "output_tokens": int64(999),
	}); err != nil {
		t.Fatalf("append row to corrupt: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET payload_json = ? WHERE seq = 2`, `not-json`,
	); err != nil {
		t.Fatalf("corrupt payload: %v", err)
	}

	got, err := a.UsageStats(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("UsageStats: %v", err)
	}
	if got.LLMCalls != 1 || got.LLMInputTokens != 100 {
		t.Errorf("malformed row should be skipped, got LLMCalls=%d LLMInputTokens=%d", got.LLMCalls, got.LLMInputTokens)
	}
}

func mustAppend(t *testing.T, a *Auditor, ctx context.Context, actor, kind string) {
	t.Helper()
	mustAppendPayload(t, a, ctx, actor, kind, nil)
}

func mustAppendPayload(t *testing.T, a *Auditor, ctx context.Context, actor, kind string, payload any) {
	t.Helper()
	if err := a.Append(ctx, actor, kind, payload); err != nil {
		t.Fatalf("append %s/%s: %v", actor, kind, err)
	}
}

// TestUsageStats_QueriesUseIndexes pins the planner's index choice for every
// usage-stats query: kind-scoped ones must walk audit_log_kind_ts_idx and the
// unscoped grouped count audit_log_ts_idx, so a narrow window over a long
// retained history reads only the window, never every row of a kind.
func TestUsageStats_QueriesUseIndexes(t *testing.T) {
	_, s, ctx := newAuditor(t)
	w := tsWindow(time.Now().Add(-time.Hour), time.Now())

	cases := []struct {
		name, sql, wantIndex string
	}{
		{"counts", usageCountsQuery(w), "audit_log_ts_idx"},
		{"alert intake", usageAlertIntakeQuery(w), "audit_log_kind_ts_idx"},
		{"slack cards", usageSlackCardsQuery(w), "audit_log_kind_ts_idx"},
		{"llm responses", usageLLMResponsesQuery(w), "audit_log_kind_ts_idx"},
	}
	for _, tc := range cases {
		plan, err := queryPlan(ctx, s.DB(), tc.sql, w.args...)
		if err != nil {
			t.Fatalf("%s: explain: %v", tc.name, err)
		}
		if !strings.Contains(plan, "USING INDEX "+tc.wantIndex) {
			t.Errorf("%s: plan %q does not use %s", tc.name, plan, tc.wantIndex)
		}
	}
}

// queryPlan returns the EXPLAIN QUERY PLAN detail lines for sql, joined.
func queryPlan(ctx context.Context, db *sql.DB, query string, args ...any) (string, error) {
	rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			return "", err
		}
		plan = append(plan, detail)
	}
	return strings.Join(plan, " | "), rows.Err()
}
