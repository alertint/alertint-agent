// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func seedJudgmentSituationForMCP(t *testing.T, st *store.Store, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	signalID, signalVersion := "HighCPU", "rule-v3"
	delivery := store.DeliveryInput{
		ID: "delivery-judgment-mcp",
		Alert: store.Alert{
			ID: "alert-high-cpu", Fingerprint: "fp-high-cpu", Status: "firing",
			Labels:      map[string]string{"alertname": "HighCPU", "instance": "db-prod-1", "service": "postgres", "severity": "warning"},
			Annotations: map[string]string{"summary": "Sustained CPU load"}, StartsAt: now, ReceivedAt: now,
		},
		Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp-high-cpu:episode",
		StartedAtBasis: model.SourceTimeBasisSourcePayload, ResolvedAtBasis: model.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "instance=db-prod-1", PayloadDigest: "sha256:delivery-judgment-mcp",
		SourceProvenance: store.SourceProvenance{SignalID: &signalID, SignalVersion: &signalVersion, AcquisitionMode: store.SourceAcquisitionWebhook},
	}
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{delivery}); err != nil {
		t.Fatal(err)
	}
	situationID := seedSituationForMCP(t, st, "inc-judgment-mcp", "instance=db-prod-1", "incident_created", now)
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		"inc-judgment-mcp", delivery.ID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	seedControllerAssessmentFixture(t, st, situationID, "inc-judgment-mcp", now, now.Add(time.Minute))
	return situationID
}

func judgmentArgs(situationID string, situationVersion, judgmentVersion int, requestID string, until time.Time) map[string]any {
	return map[string]any{
		"situation_id": situationID, "situation_input_version": situationVersion,
		"expected_judgment_version": judgmentVersion, "request_id": requestID,
		"asserted_operator": "Janis", "confirmed": true, "valid_until": until.Format(time.RFC3339),
	}
}

func TestSituationExpectedToolsExposeExplicitOperations(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	for want, factory := range map[string]func() string{
		"alertint_record_situation_expected":  func() string { tool, _ := s.toolRecordSituationExpected(); return tool.Name },
		"alertint_replace_situation_expected": func() string { tool, _ := s.toolReplaceSituationExpected(); return tool.Name },
		"alertint_revoke_situation_expected":  func() string { tool, _ := s.toolRevokeSituationExpected(); return tool.Name },
		"alertint_restore_situation_expected": func() string { tool, _ := s.toolRestoreSituationExpected(); return tool.Name },
		"alertint_list_situation_judgments":   func() string { tool, _ := s.toolListSituationJudgments(); return tool.Name },
	} {
		if got := factory(); got != want {
			t.Fatalf("tool = %q, want %q", got, want)
		}
	}
}

func TestSituationExpectedMCPRecordReadIdempotencyAndHistory(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	situationID := seedJudgmentSituationForMCP(t, st, now)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	s.now = func() time.Time { return now }
	sit, _ := st.GetSituation(context.Background(), situationID)
	args := judgmentArgs(situationID, sit.InputVersion, 0, "mcp-record-1", now.Add(time.Hour))

	res, err := s.handleRecordSituationExpected(context.Background(), reqWith(args))
	if err != nil || res.IsError {
		t.Fatalf("record: %v %s", err, resultText(t, res))
	}
	var recorded store.SituationJudgmentWriteResult
	if err := json.Unmarshal([]byte(resultText(t, res)), &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Judgment.Revision != 1 || recorded.Judgment.AssertedOperator != "Janis" || recorded.IdempotentReplay {
		t.Fatalf("recorded = %+v", recorded)
	}

	retry, _ := s.handleRecordSituationExpected(context.Background(), reqWith(args))
	var replay store.SituationJudgmentWriteResult
	_ = json.Unmarshal([]byte(resultText(t, retry)), &replay)
	if retry.IsError || !replay.IdempotentReplay || replay.Judgment.ID != recorded.Judgment.ID {
		t.Fatalf("retry = %s", resultText(t, retry))
	}
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	lateRetry, _ := s.handleRecordSituationExpected(context.Background(), reqWith(args))
	_ = json.Unmarshal([]byte(resultText(t, lateRetry)), &replay)
	if lateRetry.IsError || !replay.IdempotentReplay || replay.Judgment.ID != recorded.Judgment.ID {
		t.Fatalf("post-deadline retry = %s", resultText(t, lateRetry))
	}
	s.now = func() time.Time { return now }

	current, _ := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	var payload map[string]any
	_ = json.Unmarshal([]byte(resultText(t, current)), &payload)
	active, ok := payload["active_judgment"].(map[string]any)
	if !ok || active["asserted_operator"] != "Janis" || payload["judgment_version"] != float64(1) {
		t.Fatalf("current judgment = %#v version=%v", payload["active_judgment"], payload["judgment_version"])
	}

	history, _ := s.handleListSituationJudgments(context.Background(), reqWith(map[string]any{"situation_id": situationID, "limit": 10}))
	if history.IsError || !strings.Contains(resultText(t, history), `"operation":"record"`) {
		t.Fatalf("history = %s", resultText(t, history))
	}
}

func TestSituationExpectedMCPReplaceRevokeRestoreAndStaleGuidance(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	situationID := seedJudgmentSituationForMCP(t, st, now)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	s.now = func() time.Time { return now }
	sit, _ := st.GetSituation(context.Background(), situationID)
	_, _ = s.handleRecordSituationExpected(context.Background(), reqWith(judgmentArgs(situationID, sit.InputVersion, 0, "record", now.Add(time.Hour))))

	stale, _ := s.handleReplaceSituationExpected(context.Background(), reqWith(judgmentArgs(situationID, sit.InputVersion, 1, "stale", now.Add(2*time.Hour))))
	if !stale.IsError || !strings.Contains(resultText(t, stale), "alertint_get_situation") {
		t.Fatalf("stale response = %s", resultText(t, stale))
	}

	current, _ := st.GetSituation(context.Background(), situationID)
	replace, _ := s.handleReplaceSituationExpected(context.Background(), reqWith(judgmentArgs(situationID, current.InputVersion, 1, "replace", now.Add(2*time.Hour))))
	if replace.IsError || !strings.Contains(resultText(t, replace), `"revision":2`) {
		t.Fatalf("replace = %s", resultText(t, replace))
	}

	current, _ = st.GetSituation(context.Background(), situationID)
	revokeArgs := judgmentArgs(situationID, current.InputVersion, 2, "revoke", time.Time{})
	delete(revokeArgs, "valid_until")
	revoke, _ := s.handleRevokeSituationExpected(context.Background(), reqWith(revokeArgs))
	if revoke.IsError || !strings.Contains(resultText(t, revoke), `"state":"revoked"`) {
		t.Fatalf("revoke = %s", resultText(t, revoke))
	}

	currentRead, _ := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	var payload map[string]any
	_ = json.Unmarshal([]byte(resultText(t, currentRead)), &payload)
	if payload["active_judgment"] != nil || payload["judgment_version"] != float64(3) {
		t.Fatalf("revoked current = %#v", payload)
	}

	current, _ = st.GetSituation(context.Background(), situationID)
	restore, _ := s.handleRestoreSituationExpected(context.Background(), reqWith(judgmentArgs(situationID, current.InputVersion, 3, "restore", now.Add(3*time.Hour))))
	if restore.IsError || !strings.Contains(resultText(t, restore), `"operation":"restore"`) {
		t.Fatalf("restore = %s", resultText(t, restore))
	}

	page1, _ := s.handleListSituationJudgments(context.Background(), reqWith(map[string]any{"situation_id": situationID, "limit": 2}))
	var firstPage struct {
		Judgments []model.SituationJudgment `json:"judgments"`
		Next      *struct {
			Revision int `json:"revision"`
		} `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(resultText(t, page1)), &firstPage); err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Judgments) != 2 || firstPage.Next == nil || firstPage.Next.Revision != 2 {
		t.Fatalf("first history page = %+v", firstPage)
	}
	page2, _ := s.handleListSituationJudgments(context.Background(), reqWith(map[string]any{
		"situation_id": situationID, "limit": 2, "cursor_revision": firstPage.Next.Revision,
	}))
	var secondPage struct {
		Judgments []model.SituationJudgment `json:"judgments"`
		Next      any                       `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(resultText(t, page2)), &secondPage); err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Judgments) != 2 || secondPage.Judgments[0].Revision != 3 || secondPage.Judgments[1].Revision != 4 || secondPage.Next != nil {
		t.Fatalf("second history page = %+v", secondPage)
	}
}

func TestSituationCurrentReadNeverPresentsExpiredAuthority(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 18, 20, 10, 0, 0, time.UTC)
	situationID := seedJudgmentSituationForMCP(t, st, now)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	s.now = func() time.Time { return now }
	sit, _ := st.GetSituation(context.Background(), situationID)
	_, _ = s.handleRecordSituationExpected(context.Background(), reqWith(judgmentArgs(situationID, sit.InputVersion, 0, "expiring", now.Add(time.Minute))))
	s.now = func() time.Time { return now.Add(time.Minute) }

	res, _ := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	var payload map[string]any
	_ = json.Unmarshal([]byte(resultText(t, res)), &payload)
	if payload["active_judgment"] != nil {
		t.Fatalf("expired authority presented: %#v", payload["active_judgment"])
	}
	app := payload["judgment_applicability"].(map[string]any)
	if app["reason"] != "expired" {
		t.Fatalf("applicability = %#v", app)
	}
}
