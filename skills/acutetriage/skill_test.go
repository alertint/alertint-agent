// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
	"github.com/google/uuid"
)

// --------------------------------------------------------------------------
// Fake LLM client
// --------------------------------------------------------------------------

type fakeLLM struct {
	response json.RawMessage
	err      error
	calls    int
	lastUser string // captures the last user prompt for assertions
}

func (f *fakeLLM) Complete(_ context.Context, _ string, p llm.Prompt, _ []string) (llm.Completion, error) {
	f.calls++
	f.lastUser = p.Prefix + p.Suffix
	return llm.Completion{
		Raw:          f.response,
		Model:        "fake-model",
		InputTokens:  11,
		OutputTokens: 22,
		Latency:      5 * time.Millisecond,
	}, f.err
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func insertTestIncident(t *testing.T, st *store.Store, ctx context.Context) store.Incident {
	t.Helper()
	now := time.Now()
	inc := store.Incident{
		ID:           uuid.NewString(),
		GroupKey:     "alertname=DiskFull,host=web1",
		FirstAlertAt: now,
		LastAlertAt:  now,
		ReadyAt:      now,
		AlertCount:   0,
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	// Transition to "ready" so SaveIncidentOutput accepts it.
	if err := st.MarkIncidentReady(ctx, inc.ID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	inc.Status = "ready"
	return inc
}

func insertTestAlert(t *testing.T, st *store.Store, ctx context.Context, incidentID string, fp string, labels map[string]string) store.Alert {
	t.Helper()
	now := time.Now()
	a := store.Alert{
		ID:          uuid.NewString(),
		Fingerprint: fp,
		Status:      "firing",
		Labels:      labels,
		Annotations: map[string]string{"summary": "disk is full"},
		StartsAt:    now,
		ReceivedAt:  now,
	}
	stored, err := st.UpsertAlertByFingerprint(ctx, a)
	if err != nil {
		t.Fatalf("upsert alert: %v", err)
	}
	a = stored
	if err := st.AddAlertToIncident(ctx, incidentID, a.ID, a.ReceivedAt); err != nil {
		t.Fatalf("add alert to incident: %v", err)
	}
	return a
}

// validLLMResponse builds a minimal valid llmResponse JSON for the given alert IDs.
func validLLMResponse(alertIDs []string) json.RawMessage {
	alerts := make([]map[string]string, len(alertIDs))
	for i, id := range alertIDs {
		alerts[i] = map[string]string{
			"alert_id":         id,
			"role_in_incident": "primary",
		}
	}
	resp := map[string]any{
		"analysis_name":        "DiskFull on web1",
		"overall_issue":        "Disk utilisation reached 95% on web1",
		"correlation_findings": []string{"all alerts share host=web1"},
		"severity":             "high",
		"confidence":           0.85,
		"alerts":               alerts,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestRunPersistsOutput verifies that a successful Run saves output_json,
// summary, root_cause, confidence on the incident and sets status=analyzed.
func TestRunPersistsOutput(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)

	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-1", map[string]string{"alertname": "DiskFull", "host": "web1"})
	a2 := insertTestAlert(t, st, ctx, inc.ID, "fp-2", map[string]string{"alertname": "DiskFull", "host": "web1"})
	a3 := insertTestAlert(t, st, ctx, inc.ID, "fp-3", map[string]string{"alertname": "DiskFull", "host": "web1"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID, a2.ID, a3.ID})}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{WindowSeconds: 60}, st, fllm, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify the incident is now "analyzed" with expected fields.
	row := st.DB().QueryRowContext(ctx, `SELECT status, summary, root_cause, confidence, output_json FROM incidents WHERE id = ?`, inc.ID)
	var status, summary, rootCause, outputJSON string
	var confidence float64
	if err := row.Scan(&status, &summary, &rootCause, &confidence, &outputJSON); err != nil {
		t.Fatalf("scan incident: %v", err)
	}
	if status != "analyzed" {
		t.Errorf("status = %q, want analyzed", status)
	}
	if summary != "DiskFull on web1" {
		t.Errorf("summary = %q, want DiskFull on web1", summary)
	}
	// The fake LLM claims 0.85, but this fixture carries no live evidence
	// (no metrics/logs/changes/sentry), so the deterministic metadata-only
	// cap lowers the persisted confidence to 0.6.
	if confidence != 0.6 {
		t.Errorf("confidence = %v, want 0.6 (metadata-only cap)", confidence)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(outputJSON), &raw); err != nil {
		t.Errorf("output_json not valid JSON: %v", err)
	}
}

// TestRunNoCapWithLiveEvidence verifies the metadata-only confidence cap does
// NOT fire when any live evidence reached the prompt (here: a Sentry issue) —
// the model's own confidence passes through.
func TestRunNoCapWithLiveEvidence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{
		issues: []sentry.Issue{recentIssue(t, "101", "ValueError", "app.checkout in refund", "missing tenant_id", 3)},
		events: map[string]sentry.IssueEvent{},
	}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var confidence float64
	if err := st.DB().QueryRowContext(ctx, `SELECT confidence FROM incidents WHERE id = ?`, inc.ID).Scan(&confidence); err != nil {
		t.Fatalf("scan confidence: %v", err)
	}
	if confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85 (no cap with live evidence)", confidence)
	}
}

// TestRunSingleAlertAnalyzedByDefault verifies the min_alerts fallback is 1:
// with MinAlerts unset (zero), a lone first alert still produces a finding.
func TestRunSingleAlertAnalyzedByDefault(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-solo", map[string]string{"alertname": "DiskFull", "host": "web1"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	skill := acutetriage.New(acutetriage.Config{}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var status string
	if err := st.DB().QueryRowContext(ctx, `SELECT status FROM incidents WHERE id = ?`, inc.ID).Scan(&status); err != nil {
		t.Fatalf("scan status: %v", err)
	}
	if status != "analyzed" {
		t.Errorf("status = %q, want analyzed (single alert must triage by default)", status)
	}
}

// TestRunEmitsLLMResponded verifies the skill emits the "llm responded"
// action-trail line on the happy path, carrying model, token counts, and the
// incident ID (the success sibling of the "llm failed" error line).
func TestRunEmitsLLMResponded(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-lr1", map[string]string{"alertname": "DiskFull"})
	a2 := insertTestAlert(t, st, ctx, inc.ID, "fp-lr2", map[string]string{"alertname": "DiskFull"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID, a2.ID})}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2}, st, fllm, nil, nil, logger)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "llm responded") {
		t.Fatalf("missing llm responded line: %s", s)
	}
	for _, tok := range []string{"model=fake-model", "tokens_in=11", "tokens_out=22", "incident=" + inc.ID} {
		if !strings.Contains(s, tok) {
			t.Errorf("llm responded missing %q: %s", tok, s)
		}
	}
}

// TestRunSetsAlertRoles verifies that per-alert roles from the LLM response
// are written to incident_alerts.
func TestRunSetsAlertRoles(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)

	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-r1", map[string]string{"alertname": "Net"})
	a2 := insertTestAlert(t, st, ctx, inc.ID, "fp-r2", map[string]string{"alertname": "Net"})

	roleResp, err := json.Marshal(map[string]any{
		"analysis_name":        "Net issue",
		"overall_issue":        "packet loss",
		"correlation_findings": []string{},
		"severity":             "medium",
		"confidence":           0.7,
		"alerts": []map[string]string{
			{"alert_id": a1.ID, "role_in_incident": "primary"},
			{"alert_id": a2.ID, "role_in_incident": "downstream"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fllm := &fakeLLM{response: roleResp}
	skill := acutetriage.New(acutetriage.Config{WindowSeconds: 60}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rows, err := st.DB().QueryContext(ctx, `SELECT alert_id, role FROM incident_alerts WHERE incident_id = ? ORDER BY alert_id`, inc.ID)
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer func() { _ = rows.Close() }()
	roles := map[string]string{}
	for rows.Next() {
		var alertID string
		var role sql.NullString
		if err := rows.Scan(&alertID, &role); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if role.Valid {
			roles[alertID] = role.String
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if roles[a1.ID] != "primary" {
		t.Errorf("a1 role = %q, want primary", roles[a1.ID])
	}
	if roles[a2.ID] != "downstream" {
		t.Errorf("a2 role = %q, want downstream", roles[a2.ID])
	}
}

// TestRunAuditsCorrectKinds verifies that analysis_started and analyzed
// audit rows are written on success.
func TestRunAuditsCorrectKinds(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-audit", map[string]string{"alertname": "X"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, fllm, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, kind := range []string{"incident.analysis_started", "incident.analyzed"} {
		var n int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE kind = ?`, kind).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", kind, err)
		}
		if n != 1 {
			t.Errorf("%s audit rows = %d, want 1", kind, n)
		}
	}
}

// TestRunLLMError verifies that an LLM error is propagated and an
// analysis_failed audit row is written.
func TestRunLLMError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-err", map[string]string{"alertname": "Y"})

	fllm := &fakeLLM{err: errors.New("timeout")}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, fllm, auditor, nil, nil)

	err := skill.Run(ctx, inc)
	if err == nil {
		t.Fatal("expected error from llm, got nil")
	}

	var n int
	if scanErr := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE kind = 'incident.analysis_failed'`).Scan(&n); scanErr != nil {
		t.Fatalf("count failed: %v", scanErr)
	}
	if n != 1 {
		t.Errorf("analysis_failed audit rows = %d, want 1", n)
	}
}

// TestRunSchemaViolation verifies that a missing required key returns an error
// and does NOT persist partial output.
func TestRunSchemaViolation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-sv", map[string]string{"alertname": "Z"})

	_ = a1
	// Return JSON missing "overall_issue".
	partial, merr := json.Marshal(map[string]any{
		"analysis_name": "bad",
		"confidence":    0.5,
	})
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	fllm := &fakeLLM{err: fmt.Errorf("%w: missing keys [overall_issue]", llm.ErrSchemaViolation)}
	_ = partial

	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, fllm, nil, nil, nil)
	runErr := skill.Run(ctx, inc)
	if runErr == nil {
		t.Fatal("expected error on schema violation, got nil")
	}

	// Incident must not be marked analyzed.
	var status string
	if scanErr := st.DB().QueryRowContext(ctx, `SELECT status FROM incidents WHERE id = ?`, inc.ID).Scan(&status); scanErr != nil {
		t.Fatalf("scan: %v", scanErr)
	}
	if status == "analyzed" {
		t.Error("incident was marked analyzed despite schema violation")
	}
}

// --------------------------------------------------------------------------
// Sentry Error-source integration (U5)
// --------------------------------------------------------------------------

// fakeSentryReader is an external-package SentryReader: it builds sentry.Issue
// values via JSON (the count-decode type is unexported) and records call counts.
type fakeSentryReader struct {
	issues     []sentry.Issue
	err        error
	events     map[string]sentry.IssueEvent
	listCalls  int
	eventCalls int
}

func (f *fakeSentryReader) ListIssues(_ context.Context, _, _ string, _, _ time.Time, _ string) ([]sentry.Issue, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.issues, nil
}

func (f *fakeSentryReader) LatestEvent(_ context.Context, issueID string) (sentry.IssueEvent, error) {
	f.eventCalls++
	return f.events[issueID], nil
}

func (f *fakeSentryReader) GetIssue(_ context.Context, _ string) (sentry.IssueStatus, error) {
	return sentry.IssueStatus{}, nil
}

// recentIssue builds a JSON-decoded issue whose first/last-seen sit just inside
// W relative to wall-clock now, so it is active+NEW regardless of when the test
// runs (W is computed from the live incident time).
func recentIssue(t *testing.T, id, typ, culprit, message string, userCount int) sentry.Issue {
	t.Helper()
	ts := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	raw := fmt.Sprintf(`{"id":%q,"level":"error","userCount":%d,"count":"10","firstSeen":%q,"lastSeen":%q,"metadata":{"type":%q,"value":%q},"culprit":%q}`,
		id, userCount, ts, ts, typ, message, culprit)
	var iss sentry.Issue
	if err := json.Unmarshal([]byte(raw), &iss); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	return iss
}

func sentryEnabledParams() acutetriage.SentryParams {
	return acutetriage.SentryParams{Enabled: true, LookbackMinutes: 30, MaxIssues: 3, FetchTimeoutSeconds: 15, IncludeMessage: true}
}

func scopedAlerts(t *testing.T, st *store.Store, ctx context.Context, incID string) []string {
	t.Helper()
	a1 := insertTestAlert(t, st, ctx, incID, "fp-s1", map[string]string{"alertname": "DiskFull", "service": "checkout", "environment": "production"})
	a2 := insertTestAlert(t, st, ctx, incID, "fp-s2", map[string]string{"alertname": "DiskFull", "service": "checkout", "environment": "production"})
	return []string{a1.ID, a2.ID}
}

func TestRunPersistsSentryEnrichment(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{
		issues: []sentry.Issue{recentIssue(t, "100", "KeyError", "app.checkout in pay", "missing tenant_id", 7)},
		events: map[string]sentry.IssueEvent{},
	}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reader.listCalls != 1 {
		t.Errorf("want exactly one ListIssues call, got %d", reader.listCalls)
	}

	var enrichmentJSON sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id = ?`, inc.ID).Scan(&enrichmentJSON); err != nil {
		t.Fatalf("scan enrichment_json: %v", err)
	}
	if !enrichmentJSON.Valid {
		t.Fatal("enrichment_json is NULL; the sentry section was not persisted")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(enrichmentJSON.String), &envelope); err != nil {
		t.Fatalf("envelope not valid JSON: %v", err)
	}
	sec, ok := envelope["sentry"]
	if !ok {
		t.Fatalf("envelope missing the sentry key: %s", enrichmentJSON.String)
	}
	if !strings.Contains(string(sec), `"exception_type":"KeyError"`) || !strings.Contains(string(sec), `"project":"checkout"`) {
		t.Errorf("persisted sentry section missing distilled fields: %s", sec)
	}
}

func TestRunSentryDegradedDoesNotAbort(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{err: &sentry.APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"}}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run must complete despite a degraded Sentry fetch: %v", err)
	}

	var status string
	var enrichmentJSON sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT status, enrichment_json FROM incidents WHERE id = ?`, inc.ID).Scan(&status, &enrichmentJSON); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != "analyzed" {
		t.Errorf("status = %q, want analyzed (degraded Sentry must not block the finding)", status)
	}
	if !enrichmentJSON.Valid || !strings.Contains(enrichmentJSON.String, "rate-limited") {
		t.Errorf("degraded note not persisted: %v", enrichmentJSON)
	}
}

func TestRunSentryAuditDigestIsCountsOnly(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{
		issues: []sentry.Issue{recentIssue(t, "100", "KeyError", "app.checkout in pay", "secret tenant id 42", 7)},
		events: map[string]sentry.IssueEvent{},
	}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var payload string
	if err := st.DB().QueryRowContext(ctx, `SELECT payload_json FROM audit_log WHERE kind = 'incident.sentry_enriched'`).Scan(&payload); err != nil {
		t.Fatalf("no incident.sentry_enriched audit row: %v", err)
	}
	if !strings.Contains(payload, "checkout") || !strings.Contains(payload, "issue_count") {
		t.Errorf("digest should carry project + issue_count: %s", payload)
	}
	// The digest also carries the verdict — a fixed enum tag + an integer count
	// (KTD6). recentIssue is NEW-in-window, so this look reconciles to matched/1.
	if !strings.Contains(payload, `"tag":"matched"`) || !strings.Contains(payload, `"corroborating":1`) {
		t.Errorf("digest should carry the matched verdict (tag + corroborating count): %s", payload)
	}
	// The digest must NOT leak exception text, message, culprit, or file:line.
	for _, leak := range []string{"KeyError", "secret tenant id 42", "app.checkout in pay"} {
		if strings.Contains(payload, leak) {
			t.Errorf("audit digest leaked %q: %s", leak, payload)
		}
	}
}

// TestRunPersistsReconciliationVerdict covers AE6: a NEW-in-window error makes the
// look reconcile to `matched`, and the verdict (outcome + tag + corroborating ids)
// persists in the sentry envelope — riding the exact enrichment_json path the
// evidence-pack MCP replays verbatim, so no internal/mcp change is needed.
func TestRunPersistsReconciliationVerdict(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{
		issues: []sentry.Issue{recentIssue(t, "issue-777", "KeyError", "app.checkout in pay", "missing tenant_id", 7)},
		events: map[string]sentry.IssueEvent{},
	}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, nil, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var enrichmentJSON sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id = ?`, inc.ID).Scan(&enrichmentJSON); err != nil {
		t.Fatalf("scan enrichment_json: %v", err)
	}
	if !enrichmentJSON.Valid {
		t.Fatal("enrichment_json is NULL; the reconciliation verdict was not persisted")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(enrichmentJSON.String), &envelope); err != nil {
		t.Fatalf("envelope not valid JSON: %v", err)
	}
	var sec struct {
		Outcome        string `json:"outcome"`
		Reconciliation *struct {
			Tag                   string   `json:"tag"`
			CorroboratingIssueIDs []string `json:"corroborating_issue_ids"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal(envelope["sentry"], &sec); err != nil {
		t.Fatalf("sentry block not valid JSON: %v", err)
	}
	if sec.Outcome != "ok" {
		t.Errorf("persisted outcome = %q, want ok", sec.Outcome)
	}
	if sec.Reconciliation == nil || sec.Reconciliation.Tag != "matched" {
		t.Fatalf("want matched verdict persisted, got %#v", sec.Reconciliation)
	}
	if len(sec.Reconciliation.CorroboratingIssueIDs) != 1 || sec.Reconciliation.CorroboratingIssueIDs[0] != "issue-777" {
		t.Errorf("want corroborating id [issue-777] persisted, got %v", sec.Reconciliation.CorroboratingIssueIDs)
	}
}

// TestRunSentryDegradedAuditDigestSafe guards KTD6's nil-guard: the digest fires on
// the degraded path too (Reconciliation nil), and must emit safely with empty tag /
// zero count rather than deref a nil verdict and panic the triage goroutine.
func TestRunSentryDegradedAuditDigestSafe(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{err: &sentry.APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"}}
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, auditor, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run must complete on a degraded fetch: %v", err)
	}

	var payload string
	if err := st.DB().QueryRowContext(ctx, `SELECT payload_json FROM audit_log WHERE kind = 'incident.sentry_enriched'`).Scan(&payload); err != nil {
		t.Fatalf("no sentry digest row on the degraded path: %v", err)
	}
	if !strings.Contains(payload, `"tag":""`) || !strings.Contains(payload, `"corroborating":0`) {
		t.Errorf("degraded digest should carry empty tag / zero count (no nil deref), got %s", payload)
	}
}

// TestRunPersistsInfraOnlyVerdict covers AE3 end-to-end (the counterpart to
// TestRunPersistsReconciliationVerdict's matched path): a conclusive zero-match look
// drives the full Run() → marshalEnrichments → SaveIncidentOutput → DB chain and the
// audit digest, and the persisted sentry block carries outcome=ok + tag=infra-only
// with no corroborating ids.
func TestRunPersistsInfraOnlyVerdict(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)

	reader := &fakeSentryReader{issues: nil, events: map[string]sentry.IssueEvent{}} // conclusive zero-match look
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2, Sentry: reader, SentryParams: sentryEnabledParams()}, st, fllm, auditor, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var enrichmentJSON sql.NullString
	if err := st.DB().QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id = ?`, inc.ID).Scan(&enrichmentJSON); err != nil {
		t.Fatalf("scan enrichment_json: %v", err)
	}
	if !enrichmentJSON.Valid {
		t.Fatal("enrichment_json is NULL; the infra-only verdict was not persisted")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(enrichmentJSON.String), &envelope); err != nil {
		t.Fatalf("envelope not valid JSON: %v", err)
	}
	var sec struct {
		Outcome        string `json:"outcome"`
		Reconciliation *struct {
			Tag                   string   `json:"tag"`
			CorroboratingIssueIDs []string `json:"corroborating_issue_ids"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal(envelope["sentry"], &sec); err != nil {
		t.Fatalf("sentry block not valid JSON: %v", err)
	}
	if sec.Outcome != "ok" {
		t.Errorf("persisted outcome = %q, want ok on a conclusive zero-match look", sec.Outcome)
	}
	if sec.Reconciliation == nil || sec.Reconciliation.Tag != "infra-only" {
		t.Fatalf("want infra-only verdict persisted, got %#v", sec.Reconciliation)
	}
	if len(sec.Reconciliation.CorroboratingIssueIDs) != 0 {
		t.Errorf("infra-only verdict must carry no corroborating ids, got %v", sec.Reconciliation.CorroboratingIssueIDs)
	}

	var payload string
	if err := st.DB().QueryRowContext(ctx, `SELECT payload_json FROM audit_log WHERE kind = 'incident.sentry_enriched'`).Scan(&payload); err != nil {
		t.Fatalf("no sentry digest row: %v", err)
	}
	if !strings.Contains(payload, `"tag":"infra-only"`) || !strings.Contains(payload, `"corroborating":0`) {
		t.Errorf("audit digest should carry the infra-only tag / zero count, got %s", payload)
	}
}

// TestEvidencePackSharedLabels unit-tests the shared-label computation.
func TestEvidencePackSharedLabels(t *testing.T) {
	now := time.Now()
	alerts := []store.Alert{
		{ID: "a1", Labels: map[string]string{"env": "prod", "svc": "api", "host": "web1"}, StartsAt: now, ReceivedAt: now},
		{ID: "a2", Labels: map[string]string{"env": "prod", "svc": "api", "host": "web2"}, StartsAt: now, ReceivedAt: now},
		{ID: "a3", Labels: map[string]string{"env": "prod", "svc": "api", "host": "web3"}, StartsAt: now, ReceivedAt: now},
	}
	inc := store.Incident{ID: "i1", FirstAlertAt: now, LastAlertAt: now, AlertCount: 3}
	pack := acutetriage.BuildEvidencePack(inc, alerts, 60)

	if pack.SharedLabels["env"] != "prod" {
		t.Errorf("shared env = %q, want prod", pack.SharedLabels["env"])
	}
	if pack.SharedLabels["svc"] != "api" {
		t.Errorf("shared svc = %q, want api", pack.SharedLabels["svc"])
	}
	if _, ok := pack.SharedLabels["host"]; ok {
		t.Error("host should NOT be a shared label (differs per alert)")
	}
}

// --------------------------------------------------------------------------
// Re-judgment (U4)
// --------------------------------------------------------------------------

func namedLLMResponse(name, issue string, alertIDs []string, confidence float64) json.RawMessage {
	alerts := make([]map[string]string, len(alertIDs))
	for i, id := range alertIDs {
		alerts[i] = map[string]string{"alert_id": id, "role_in_incident": "primary"}
	}
	b, err := json.Marshal(map[string]any{
		"analysis_name":        name,
		"overall_issue":        issue,
		"correlation_findings": []string{"recurrence"},
		"severity":             "high",
		"confidence":           confidence,
		"alerts":               alerts,
	})
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// analyzedFixture runs an initial triage so the incident is analyzed, then
// returns the reloaded incident, the store, the skill, and its fake LLM.
func analyzedFixture(t *testing.T) (context.Context, *store.Store, *acutetriage.Skill, *fakeLLM, store.Incident, store.Alert) {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-1", map[string]string{"alertname": "DiskFull", "host": "web1"})
	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	auditor := audit.New(st.DB())
	skill := acutetriage.New(acutetriage.Config{}, st, fllm, auditor, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("setup Run: %v", err)
	}
	analyzed, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil || analyzed == nil {
		t.Fatalf("reload analyzed incident: %v", err)
	}
	if analyzed.Status != "analyzed" {
		t.Fatalf("setup: status %q, want analyzed", analyzed.Status)
	}
	return ctx, st, skill, fllm, *analyzed, a1
}

func addOccurrence(t *testing.T, st *store.Store, ctx context.Context, incidentID string, at time.Time) {
	t.Helper()
	_, err := st.InsertOccurrence(ctx, store.Occurrence{
		IncidentID:   incidentID,
		OccurredAt:   at,
		LastSeen:     at,
		Fingerprints: []string{"fp-" + at.Format("150405.000")},
		Payload:      []store.OccurrenceMember{{Fingerprint: "fp-x", Annotations: map[string]string{"summary": "disk 95%"}}},
	})
	if err != nil {
		t.Fatalf("insert occurrence: %v", err)
	}
}

func TestRejudgeReplacesFindingInPlace(t *testing.T) {
	ctx, st, skill, fllm, analyzed, a1 := analyzedFixture(t)
	firstJudged := analyzed.LastJudgedAt
	if firstJudged == nil {
		t.Fatal("setup: last_judged_at not set by initial triage")
	}
	addOccurrence(t, st, ctx, analyzed.ID, time.Now().UTC())

	fllm.response = namedLLMResponse("Recurring disk fill", "same condition, seen repeatedly", []string{a1.ID}, 0.9)
	time.Sleep(2 * time.Millisecond) // let last_judged_at advance measurably
	if err := skill.Rejudge(ctx, analyzed, "ceiling"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}

	after, _ := st.GetIncidentByID(ctx, analyzed.ID)
	if after.Status != "analyzed" {
		t.Errorf("status = %q, want analyzed (replace keeps status)", after.Status)
	}
	if after.Summary != "Recurring disk fill" {
		t.Errorf("summary = %q, want the replaced finding", after.Summary)
	}
	if after.LastJudgedAt == nil || !after.LastJudgedAt.After(*firstJudged) {
		t.Errorf("last_judged_at not advanced: before=%v after=%v", firstJudged, after.LastJudgedAt)
	}
}

func TestRejudgeFailedLLMLeavesPriorFinding(t *testing.T) {
	ctx, st, skill, fllm, analyzed, _ := analyzedFixture(t)
	before, _ := st.GetIncidentByID(ctx, analyzed.ID)
	addOccurrence(t, st, ctx, analyzed.ID, time.Now().UTC())

	fllm.err = errors.New("model timeout")
	if err := skill.Rejudge(ctx, analyzed, "ceiling"); err == nil {
		t.Fatal("Rejudge with a failing LLM returned nil, want an error")
	}
	after, _ := st.GetIncidentByID(ctx, analyzed.ID)
	if after.Summary != before.Summary {
		t.Errorf("summary changed to %q on a failed re-judgment, want prior %q", after.Summary, before.Summary)
	}
	if after.Status != "analyzed" {
		t.Errorf("status = %q, want analyzed unchanged", after.Status)
	}
	if before.LastJudgedAt == nil || after.LastJudgedAt == nil || !after.LastJudgedAt.Equal(*before.LastJudgedAt) {
		t.Errorf("last_judged_at moved on a failed re-judgment: before=%v after=%v", before.LastJudgedAt, after.LastJudgedAt)
	}
}

func TestRejudgeResolvedIncidentKeepsStatus(t *testing.T) {
	ctx, st, skill, fllm, analyzed, a1 := analyzedFixture(t)
	if err := st.MarkIncidentResolved(ctx, analyzed.ID); err != nil {
		t.Fatalf("mark resolved: %v", err)
	}
	resolved, _ := st.GetIncidentByID(ctx, analyzed.ID)
	addOccurrence(t, st, ctx, analyzed.ID, time.Now().UTC())

	fllm.response = namedLLMResponse("Regression after recovery", "condition returned", []string{a1.ID}, 0.8)
	if err := skill.Rejudge(ctx, *resolved, "severity"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	after, _ := st.GetIncidentByID(ctx, analyzed.ID)
	if after.Status != "resolved" {
		t.Errorf("status = %q, want resolved (a re-judgment never reverts status)", after.Status)
	}
	if after.Summary != "Regression after recovery" {
		t.Errorf("summary = %q, want the replaced finding", after.Summary)
	}
}

func TestRejudgePromptCarriesRecurrenceContext(t *testing.T) {
	ctx, st, skill, fllm, analyzed, a1 := analyzedFixture(t)
	// Three occurrences 5 minutes apart -> episodes ×4, cadence ~5m.
	base := time.Now().UTC().Add(-10 * time.Minute)
	addOccurrence(t, st, ctx, analyzed.ID, base)
	addOccurrence(t, st, ctx, analyzed.ID, base.Add(5*time.Minute))
	addOccurrence(t, st, ctx, analyzed.ID, base.Add(10*time.Minute))

	fllm.response = namedLLMResponse("Recurring", "recurs", []string{a1.ID}, 0.7)
	if err := skill.Rejudge(ctx, analyzed, "cadence"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	prompt := fllm.lastUser
	for _, want := range []string{"Recurrence context", "trigger: cadence", "Seen ×4", "roughly every", "Recent occurrences"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("re-judgment prompt missing %q\n---\n%s", want, prompt)
		}
	}
}

// capturingNotifier records the last Finding it was asked to notify.
type capturingNotifier struct {
	last notify.Finding
}

func (c *capturingNotifier) Notify(_ context.Context, f notify.Finding) error {
	c.last = f
	return nil
}
func (c *capturingNotifier) Name() string { return "capture" }

// newLocalRuleEngine builds a rules.Engine from a single-rule known-issue pack
// written to a temp directory, so a real Run() short-circuit can be exercised
// through the public API (no internal test seam exists for this).
func newLocalRuleEngine(t *testing.T) *rules.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte("name: test\nversion: \"0.0.1\"\nupdated: \"2026-07-08\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ruleYAML := `rules:
  - id: test.known-disk-issue
    kind: known_issue
    description: Known disk issue
    when:
      all:
        - label: alertname
          op: equals
          value: KnownDiskIssue
    then:
      short_circuit_llm: true
      root_cause_hint: known disk cleanup job stalled
      severity: high
    updated: "2026-07-08"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "01-known.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := rules.NewEngine(context.Background(), nil, rules.NewLocalDirSource(dir, 0))
	if err != nil {
		t.Fatalf("build rule engine: %v", err)
	}
	return e
}

// TestPipeline_AttachesEvidenceSummaryAndPersistsMetrics builds a skill with a
// fake Prometheus backend (an httptest server behind the real client), runs an
// incident, and asserts the Finding carries a Prometheus evidence entry and the
// persisted enrichment envelope has a "metrics" key. A second, short-circuited
// incident asserts the evidence line collapses to the skipped state.
func TestPipeline_AttachesEvidenceSummaryAndPersistsMetrics(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	promSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"up","service":"checkout"},"value":[0,"1"]}
		]}}`))
	}))
	t.Cleanup(promSrv.Close)
	prom := promclient.NewClient(promclient.Config{BaseURL: promSrv.URL, TimeoutSeconds: 5})

	notifier := &capturingNotifier{}
	cfg := acutetriage.Config{
		MinAlerts:    2,
		Prometheus:   prom,
		MetricParams: acutetriage.MetricParams{TimeoutSeconds: 5},
	}

	// Normal incident: metrics fetched, evidence attached, envelope persisted.
	inc := insertTestIncident(t, st, ctx)
	ids := scopedAlerts(t, st, ctx, inc.ID)
	fllm := &fakeLLM{response: validLLMResponse(ids)}
	skill := acutetriage.New(cfg, st, fllm, nil, notifier, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(notifier.last.Evidence.Sources) == 0 || notifier.last.Evidence.Sources[0].Source != "Prometheus" {
		t.Fatalf("want a Prometheus evidence entry, got %+v", notifier.last.Evidence)
	}
	if notifier.last.Evidence.Sources[0].Count != 1 {
		t.Errorf("want Prometheus count 1, got %+v", notifier.last.Evidence.Sources[0])
	}
	var enrichmentJSON string
	if err := st.DB().QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id = ?`, inc.ID).Scan(&enrichmentJSON); err != nil {
		t.Fatalf("scan enrichment_json: %v", err)
	}
	if !strings.Contains(enrichmentJSON, `"metrics"`) {
		t.Errorf("persisted enrichment envelope missing metrics key: %s", enrichmentJSON)
	}

	// Short-circuit incident: no fetch runs, evidence collapses to skipped.
	scCfg := cfg
	scCfg.Rules = newLocalRuleEngine(t)
	scSkill := acutetriage.New(scCfg, st, fllm, nil, notifier, nil)
	scInc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, scInc.ID, "fp-known-1", map[string]string{"alertname": "KnownDiskIssue", "host": "web1"})
	insertTestAlert(t, st, ctx, scInc.ID, "fp-known-2", map[string]string{"alertname": "KnownDiskIssue", "host": "web1"})
	if err := scSkill.Run(ctx, scInc); err != nil {
		t.Fatalf("Run (short-circuit): %v", err)
	}
	if !notifier.last.Evidence.Skipped {
		t.Errorf("short-circuit finding must report Evidence.Skipped, got %+v", notifier.last.Evidence)
	}
}

// TestRunDefaultsUnitemizedAlertRoles: member alerts the model omits from its
// alerts array get the "correlated" role deterministically (bounded
// itemization) — MCP consumers always see a role on every member.
func TestRunDefaultsUnitemizedAlertRoles(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)

	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-u1", map[string]string{"alertname": "Net"})
	a2 := insertTestAlert(t, st, ctx, inc.ID, "fp-u2", map[string]string{"alertname": "Net"})
	a3 := insertTestAlert(t, st, ctx, inc.ID, "fp-u3", map[string]string{"alertname": "Net"})

	// The model itemizes only a1; a2 and a3 are omitted (top-N behavior).
	roleResp, err := json.Marshal(map[string]any{
		"analysis_name":        "Net issue",
		"overall_issue":        "packet loss",
		"correlation_findings": []string{},
		"severity":             "medium",
		"confidence":           0.7,
		"alerts": []map[string]string{
			{"alert_id": a1.ID, "role_in_incident": "primary"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fllm := &fakeLLM{response: roleResp}
	skill := acutetriage.New(acutetriage.Config{WindowSeconds: 60}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rows, err := st.DB().QueryContext(ctx, `SELECT alert_id, role FROM incident_alerts WHERE incident_id = ? ORDER BY alert_id`, inc.ID)
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer func() { _ = rows.Close() }()
	roles := map[string]string{}
	for rows.Next() {
		var alertID string
		var role sql.NullString
		if err := rows.Scan(&alertID, &role); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if role.Valid {
			roles[alertID] = role.String
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if roles[a1.ID] != "primary" {
		t.Errorf("a1 role = %q, want primary (model's own call must win)", roles[a1.ID])
	}
	if roles[a2.ID] != "correlated" {
		t.Errorf("a2 role = %q, want correlated (defaulted)", roles[a2.ID])
	}
	if roles[a3.ID] != "correlated" {
		t.Errorf("a3 role = %q, want correlated (defaulted)", roles[a3.ID])
	}
}

// TestRejudgeDoesNotDowngradePreviouslyItemizedRole: an alert itemized as
// "primary" on the initial triage must keep that role on a later re-judgment
// even if the new response's (independently capped) itemization omits it —
// omission on a later call must not be read as a fresh "correlated" verdict
// overwriting an earlier explicit classification.
func TestRejudgeDoesNotDowngradePreviouslyItemizedRole(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)

	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-rd1", map[string]string{"alertname": "Net"})
	a2 := insertTestAlert(t, st, ctx, inc.ID, "fp-rd2", map[string]string{"alertname": "Net"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID, a2.ID})}
	skill := acutetriage.New(acutetriage.Config{WindowSeconds: 60}, st, fllm, nil, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("initial Run: %v", err)
	}

	analyzed, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil || analyzed == nil {
		t.Fatalf("reload analyzed incident: %v", err)
	}

	// The re-judgment's own itemization omits a2 (independently capped —
	// nothing to do with a2's earlier classification).
	fllm.response = namedLLMResponse("Net issue, revisited", "packet loss persists", []string{a1.ID}, 0.8)
	if err := skill.Rejudge(ctx, *analyzed, "cadence"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}

	rows, err := st.DB().QueryContext(ctx, `SELECT alert_id, role FROM incident_alerts WHERE incident_id = ? ORDER BY alert_id`, inc.ID)
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer func() { _ = rows.Close() }()
	roles := map[string]string{}
	for rows.Next() {
		var alertID string
		var role sql.NullString
		if err := rows.Scan(&alertID, &role); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if role.Valid {
			roles[alertID] = role.String
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if roles[a2.ID] != "primary" {
		t.Errorf("a2 role = %q, want primary (must not be downgraded by omission on re-judgment)", roles[a2.ID])
	}
}
