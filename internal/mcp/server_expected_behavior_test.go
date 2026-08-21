// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func seedTestJudgmentAndEnvelope(t *testing.T, st *store.Store, auditor *audit.Auditor, situationID, groupKey string, now time.Time) *model.EnvelopeVersion {
	t.Helper()
	seedTestSituation(t, st, situationID, groupKey, "", model.LifecycleActive, now)
	ts := now.UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().Exec(`INSERT INTO situation_judgments (
			id, situation_id, judged_input_version, covered_fact_hash, covered_symptoms_json, covered_impact_json,
			judgment, basis, evidence_refs_json, authenticated_as, asserted_operator, created_at
		) VALUES (?, ?, 1, 'sha256:test', '[]', '[]', 'expected_this_episode', 'operator_knowledge', '[]', 'slack:U1', 'janis', ?)`,
		"j-"+situationID, situationID, ts); err != nil {
		t.Fatal(err)
	}
	confirmation := model.EnvelopeConfirmation{
		SourceJudgmentID: "j-" + situationID, ExpectedCurrentVersion: 0, Scope: model.EnvelopeScope{GroupKey: groupKey},
		ReviewDueAt: now.Add(30 * 24 * time.Hour), OperatorConfirmed: true, ConfirmedBy: "janis",
	}
	v, err := st.ConfirmEnvelope(context.Background(), confirmation, "slack:U1", now, auditor,
		[]store.SituationPolicyAuditEvent{{Kind: "envelope.confirmed", Payload: map[string]any{"ok": true}}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestHandleExpectedBehaviorListReturnsEnvelopeHeads(t *testing.T) {
	st := newMCPStore(t)
	auditor := audit.New(st.DB())
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, auditor)
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	v := seedTestJudgmentAndEnvelope(t, st, auditor, "sit-env-list", "host=env-list", now)

	res, err := s.handleExpectedBehaviorList(context.Background(), reqWith(nil))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if out := resultText(t, res); !strings.Contains(out, v.EnvelopeID) {
		t.Fatalf("expected envelope %q in list response: %s", v.EnvelopeID, out)
	}
}

func TestHandleExpectedBehaviorConfirmDelegatesToCommand(t *testing.T) {
	fake := &fakeSituationCommands{envelopeConfirm: &model.EnvelopeVersion{EnvelopeID: "env-1", Version: 1, Status: model.EnvelopeStatusActive}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleExpectedBehaviorConfirm(context.Background(), reqWith(map[string]any{
		"source_judgment_id": "j-1", "expected_current_version": 0,
		"scope":              map[string]any{"group_key": "host=db-1", "source": "zabbix", "trigger_id": "18422"},
		"conditions":         map[string]any{"required_companion_signals": []any{"database_lock"}},
		"review_due_at":      "2026-11-20T00:00:00Z",
		"operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if fake.lastConfirm.SourceJudgmentID != "j-1" || fake.lastConfirm.Scope.GroupKey != "host=db-1" ||
		len(fake.lastConfirm.Conditions.RequiredCompanionSignals) != 1 || fake.lastConfirm.ConfirmedBy != "janis" {
		t.Fatalf("confirmation=%+v", fake.lastConfirm)
	}
	if fake.lastConfirm.ReviewDueAt.IsZero() {
		t.Fatal("review_due_at must be parsed")
	}
	if out := resultText(t, res); !strings.Contains(out, "env-1") {
		t.Fatalf("expected confirmed envelope in response: %s", out)
	}
}

func TestHandleExpectedBehaviorConfirmRequiresScopeAndReviewDate(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleExpectedBehaviorConfirm(context.Background(), reqWith(map[string]any{
		"source_judgment_id": "j-1", "expected_current_version": 0, "operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing review_due_at")
	}
}

func TestHandleExpectedBehaviorRevokeDelegatesToCommand(t *testing.T) {
	fake := &fakeSituationCommands{envelopeRevoke: &model.EnvelopeVersion{EnvelopeID: "env-1", Version: 2, Status: model.EnvelopeStatusRevoked}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleExpectedBehaviorRevoke(context.Background(), reqWith(map[string]any{
		"envelope_id": "env-1", "expected_current_version": 1, "reason": "trigger retired",
		"operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if fake.lastRevoke.EnvelopeID != "env-1" || fake.lastRevoke.Reason != "trigger retired" {
		t.Fatalf("revocation=%+v", fake.lastRevoke)
	}
	if out := resultText(t, res); !strings.Contains(out, "revoked") {
		t.Fatalf("expected revoked status in response: %s", out)
	}
}

func TestHandleExpectedBehaviorRevokeRequiresReason(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleExpectedBehaviorRevoke(context.Background(), reqWith(map[string]any{
		"envelope_id": "env-1", "expected_current_version": 1, "operator_confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing reason")
	}
}
