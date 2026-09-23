// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestExpectedBehaviorToolsExposeApprovedOperations(t *testing.T) {
	s := NewServer(Config{}, newMCPStore(t), nil)
	tools := []struct {
		want string
		got  func() string
	}{
		{"alertint_expected_behavior_prepare", func() string { tool, _ := s.toolExpectedBehaviorPrepare(); return tool.Name }},
		{"alertint_get_expected_behavior_validation", func() string { tool, _ := s.toolGetExpectedBehaviorValidation(); return tool.Name }},
		{"alertint_expected_behavior_confirm", func() string { tool, _ := s.toolExpectedBehaviorConfirm(); return tool.Name }},
		{"alertint_expected_behavior_replace", func() string { tool, _ := s.toolExpectedBehaviorReplace(); return tool.Name }},
		{"alertint_expected_behavior_revoke", func() string { tool, _ := s.toolExpectedBehaviorRevoke(); return tool.Name }},
		{"alertint_expected_behavior_restore", func() string { tool, _ := s.toolExpectedBehaviorRestore(); return tool.Name }},
		{"alertint_get_expected_behavior", func() string { tool, _ := s.toolGetExpectedBehavior(); return tool.Name }},
		{"alertint_list_expected_behaviors", func() string { tool, _ := s.toolListExpectedBehaviors(); return tool.Name }},
		{"alertint_list_expected_behavior_history", func() string { tool, _ := s.toolListExpectedBehaviorHistory(); return tool.Name }},
	}
	for _, tc := range tools {
		if got := tc.got(); got != tc.want {
			t.Fatalf("tool=%q want=%q", got, tc.want)
		}
	}
}

func TestExpectedBehaviorPrepareCreatesNonAuthoritativeValidationOnly(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-expected-prepare", "host=db-01", "incident_created", now)
	sit, _ := st.GetSituation(context.Background(), situationID)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	s.now = func() time.Time { return now }
	result, err := s.handleExpectedBehaviorPrepare(context.Background(), reqWith(map[string]any{
		"situation_id": situationID, "situation_input_version": sit.InputVersion,
		"required_companions": []any{}, "allowed_companions": []any{}, "forbidden_signals": []any{},
	}))
	if err != nil || result.IsError {
		t.Fatalf("prepare: err=%v result=%s", err, resultText(t, result))
	}
	var validation model.ExpectedBehaviorValidation
	if err := json.Unmarshal([]byte(resultText(t, result)), &validation); err != nil {
		t.Fatal(err)
	}
	if validation.Status != model.ExpectedBehaviorValidationReady || validation.ID == "" {
		t.Fatalf("validation=%+v", validation)
	}
	if got, _ := st.ListExpectedBehaviors(context.Background(), store.ExpectedBehaviorListFilter{}, 10); len(got) != 0 {
		t.Fatalf("prepare created authority: %+v", got)
	}
}

func TestExpectedBehaviorPolicyParserAcceptsNestedDurationContract(t *testing.T) {
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	policy, err := expectedBehaviorPolicyFromRequest(reqWith(map[string]any{
		"scope": map[string]any{"group_key": "host=db-01", "source": "zabbix", "source_instance_id": "prod-zbx", "host": "db-01", "primary_trigger_id": "100", "primary_trigger_version": "v1"},
		"conditions": map[string]any{
			"workload": "nightly_reconciliation", "schedule": map[string]any{"days": []string{"mon"}, "local_start": "22:00", "local_end": "23:00", "timezone": "Europe/Riga", "start_tolerance_minutes": 10},
			"duration_minutes": map[string]any{"max": 55}, "required_companions": []any{}, "allowed_companions": []any{}, "forbidden_signals": []any{},
		},
		"review_due_at": now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}))
	if err != nil || policy.Conditions.MaxDurationMinutes != 55 || policy.Scope.Source != "zabbix" {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}

func TestExpectedBehaviorReadsExposeReviewUsageAndInvalidationHistory(t *testing.T) {
	st := newMCPStore(t)
	now := time.Date(2026, 9, 21, 19, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-expected-read", "host=db-01", "incident_created", now)
	sit, err := st.GetSituation(context.Background(), situationID)
	if err != nil {
		t.Fatal(err)
	}
	judgmentID, envelopeID := "judgment-expected-read", "envelope-expected-read"
	policy := model.ExpectedBehaviorPolicy{
		Scope:       model.ExpectedBehaviorScope{GroupKey: "host=db-01", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01", PrimaryTriggerID: "18422", PrimaryTriggerVersion: "sha256:v1"},
		Conditions:  model.ExpectedBehaviorConditions{Workload: "nightly_reconciliation", Schedule: model.ExpectedBehaviorSchedule{Days: []model.ExpectedBehaviorWeekday{model.ExpectedBehaviorMonday}, LocalStart: "22:00", LocalEnd: "06:00", Timezone: "Europe/Riga", StartToleranceMinutes: 10}, MaxDurationMinutes: 55},
		ReviewDueAt: now.Add(30 * 24 * time.Hour),
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO situation_judgments
		(id,situation_id,revision,operation,state,asserted_operator,trust_domain,request_id,request_hash,result_input_version,valid_until,coverage_json,created_at)
		VALUES (?,?,1,'record','expected','default','authenticated_mcp','mcp-read-judgment','hash',?,?,?,?)`,
		judgmentID, situationID, sit.InputVersion, now.Add(time.Hour).Format(time.RFC3339Nano), `{}`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO expected_behavior_envelope_revisions
		(id,envelope_id,version,operation,state,policy_json,source_judgment_id,source_situation_id,asserted_operator,trust_domain,request_id,request_hash,expected_previous_version,created_at)
		VALUES ('revision-expected-read',?,1,'confirm','active',?,?,?,'default','authenticated_mcp','mcp-read-confirm','hash',0,?)`,
		envelopeID, string(policyJSON), judgmentID, situationID, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO expected_behavior_envelope_heads
		(envelope_id,revision_id,version,state,group_key,source,source_instance_id,host,primary_trigger_id,primary_trigger_version,updated_at)
		VALUES (?,'revision-expected-read',1,'active','host=db-01','zabbix','prod-zbx','db-01','18422','sha256:v1',?)`, envelopeID, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	invalidatedAt := now.Add(time.Minute)
	if _, err := st.InvalidateExpectedBehavior(context.Background(), audit.New(st.DB()), envelopeID, 1,
		model.ExpectedBehaviorPrimaryDefinitionChanged, map[string]any{"observed_version": "sha256:v2"}, invalidatedAt); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{}, st, audit.New(st.DB()))
	s.now = func() time.Time { return policy.ReviewDueAt.Add(time.Minute) }
	current, err := s.handleGetExpectedBehavior(context.Background(), reqWith(map[string]any{"envelope_id": envelopeID}))
	if err != nil || current.IsError {
		t.Fatalf("get: err=%v result=%s", err, resultText(t, current))
	}
	var currentPayload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, current)), &currentPayload); err != nil {
		t.Fatal(err)
	}
	if currentPayload["authority_state"] != "invalidated" {
		t.Fatalf("current payload = %s", resultText(t, current))
	}
	review, ok := currentPayload["review"].(map[string]any)
	if !ok || review["status"] != "invalidated" {
		t.Fatalf("review = %#v", currentPayload["review"])
	}
	if _, ok := currentPayload["usage"].(map[string]any); !ok {
		t.Fatalf("usage missing: %s", resultText(t, current))
	}
	listed, err := s.handleListExpectedBehaviors(context.Background(), reqWith(map[string]any{"review_status": "invalidated"}))
	if err != nil || listed.IsError {
		t.Fatalf("list: err=%v result=%s", err, resultText(t, listed))
	}
	var listPayload struct {
		ExpectedBehaviors []store.ExpectedBehaviorOverview `json:"expected_behaviors"`
	}
	if err := json.Unmarshal([]byte(resultText(t, listed)), &listPayload); err != nil {
		t.Fatal(err)
	}
	if len(listPayload.ExpectedBehaviors) != 1 || listPayload.ExpectedBehaviors[0].EnvelopeID != envelopeID {
		t.Fatalf("list payload = %s", resultText(t, listed))
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO expected_behavior_envelope_revisions
		(id,envelope_id,version,operation,state,policy_json,source_judgment_id,source_situation_id,asserted_operator,trust_domain,request_id,request_hash,expected_previous_version,created_at)
		VALUES ('revision-expected-read-restored',?,2,'restore','active',?,?,?,'default','authenticated_mcp','mcp-read-restore','hash-restore',1,?)`,
		envelopeID, string(policyJSON), judgmentID, situationID, now.Add(2*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `UPDATE expected_behavior_envelope_heads
		SET revision_id='revision-expected-read-restored',version=2,invalidated_at=NULL,invalidation_reason=NULL,updated_at=? WHERE envelope_id=?`,
		now.Add(2*time.Minute).Format(time.RFC3339Nano), envelopeID); err != nil {
		t.Fatal(err)
	}
	history, err := s.handleListExpectedBehaviorHistory(context.Background(), reqWith(map[string]any{"envelope_id": envelopeID}))
	if err != nil || history.IsError {
		t.Fatalf("history: err=%v result=%s", err, resultText(t, history))
	}
	var historyPayload struct {
		SystemEvents []model.ExpectedBehaviorSystemEvent `json:"system_events"`
	}
	if err := json.Unmarshal([]byte(resultText(t, history)), &historyPayload); err != nil {
		t.Fatal(err)
	}
	if len(historyPayload.SystemEvents) != 1 || historyPayload.SystemEvents[0].Reason != model.ExpectedBehaviorPrimaryDefinitionChanged {
		t.Fatalf("history payload = %s", resultText(t, history))
	}
}
