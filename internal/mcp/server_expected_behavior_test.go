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
