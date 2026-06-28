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
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
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
}

func (f *fakeLLM) Complete(_ context.Context, _, _ string, _ []string) (llm.Completion, error) {
	f.calls++
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
	if confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85", confidence)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(outputJSON), &raw); err != nil {
		t.Errorf("output_json not valid JSON: %v", err)
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
	// The digest must NOT leak exception text, message, culprit, or file:line.
	for _, leak := range []string{"KeyError", "secret tenant id 42", "app.checkout in pay"} {
		if strings.Contains(payload, leak) {
			t.Errorf("audit digest leaked %q: %s", leak, payload)
		}
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
