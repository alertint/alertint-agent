// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func testProfileVersion(id, signature string) profilemodel.ProfileVersion {
	material := json.RawMessage(`{"source":"zabbix","trigger_id":"18422","template_identity":"sha256:923b"}`)
	return profilemodel.ProfileVersion{
		ID: id, SignatureKey: signature, Source: "zabbix", SignatureMaterial: material,
		Profile: profilemodel.Profile{
			Signature: signature, SubjectKind: "database_host", EventKind: "resource_saturation", PossibleRole: "symptom",
			CandidateScope: []string{"host"}, HorizonTier: "hours", UsefulCapabilities: []string{"zabbix_metric_range"},
			Uncertainty: []string{"workload unknown"},
		},
		Origin: profilemodel.OriginInferred, InputDigest: "sha256:input", CreatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}
}

func seedTestDelivery(t *testing.T, st *store.Store, id, alertID, incidentID, source string, labels map[string]string, now time.Time) {
	t.Helper()
	ts := now.UTC().Format(time.RFC3339Nano)
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT OR IGNORE INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, received_at)
		VALUES (?, ?, 'firing', ?, '{}', ?, ?)`, alertID, alertID, string(labelsJSON), ts, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO alert_deliveries (
		id, alert_id, source, source_episode_key, status, labels_json, annotations_json,
		starts_at, started_at_basis, resolved_at_basis, receiver_grouping_identity, payload_digest, received_at
	) VALUES (?, ?, ?, ?, 'firing', ?, '{}', ?, 'source_payload', 'missing', 'zabbix:webhook', ?, ?)`,
		id, alertID, source, id, string(labelsJSON), ts, id, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incidentID, id, ts); err != nil {
		t.Fatal(err)
	}
}

func TestHandleSemanticProfileGetBySignature(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
	v := testProfileVersion("profile-1", "zabbix:trigger=18422:template=sha256:923b")
	if err := st.AppendSemanticProfileVersion(context.Background(), 0, v); err != nil {
		t.Fatal(err)
	}

	res, err := s.handleSemanticProfileGet(context.Background(), reqWith(map[string]any{"signature": v.SignatureKey}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, v.SignatureKey) || !strings.Contains(out, "database_host") {
		t.Fatalf("expected profile history in response: %s", out)
	}
}

func TestHandleSemanticProfileGetBySituationEvidence(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	seedTestSituation(t, st, "sit-profile-1", "host=db-2", "", model.LifecycleActive, now)
	seedTestIncident(t, st, "inc-profile-1", "host=db-2", now)
	attachTestIncident(t, st, "sit-profile-1", "inc-profile-1", now)
	seedTestDelivery(t, st, "del-1", "alert-1", "inc-profile-1", "zabbix", map[string]string{"zabbix_trigger_id": "18422"}, now)

	deliveries, err := st.SituationDeliveries(context.Background(), "sit-profile-1")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("deliveries=%+v err=%v", deliveries, err)
	}
	signature := semanticprofile.Signature(deliveries[0])
	v := testProfileVersion("profile-2", signature)
	if err := st.AppendSemanticProfileVersion(context.Background(), 0, v); err != nil {
		t.Fatal(err)
	}

	res, err := s.handleSemanticProfileGet(context.Background(), reqWith(map[string]any{"situation": "sit-profile-1"}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if out := resultText(t, res); !strings.Contains(out, signature) {
		t.Fatalf("expected resolved signature %q in response: %s", signature, out)
	}
}

func TestHandleSemanticProfileGetRequiresSignatureOrSituation(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleSemanticProfileGet(context.Background(), reqWith(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result when neither signature nor situation is given")
	}
}

func TestHandleSemanticProfileCorrectDelegatesToCommand(t *testing.T) {
	fake := &fakeSituationCommands{profileVersion: &profilemodel.ProfileVersion{ID: "profile-3", SignatureKey: "sig-1"}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))

	res, err := s.handleSemanticProfileCorrect(context.Background(), reqWith(map[string]any{
		"signature": "sig-1", "expected_version": 1,
		"profile": map[string]any{
			"signature": "sig-1", "subject_kind": "database_host", "event_kind": "resource_saturation",
			"possible_role": "symptom", "candidate_scope": []any{"host"}, "horizon_tier": "hours",
			"useful_capabilities": []any{"zabbix_metric_range"}, "uncertainty": []any{"workload unknown"},
		},
		"confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	if fake.lastCorrection.Signature != "sig-1" || fake.lastCorrection.ExpectedVersion != 1 || !fake.lastCorrection.Confirmed || fake.lastCorrection.ConfirmedBy != "janis" {
		t.Fatalf("correction=%+v", fake.lastCorrection)
	}
	if out := resultText(t, res); !strings.Contains(out, "profile-3") {
		t.Fatalf("expected corrected profile version in response: %s", out)
	}
}

func TestHandleSemanticProfileCorrectRequiresSignature(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handleSemanticProfileCorrect(context.Background(), reqWith(map[string]any{
		"expected_version": 1, "profile": map[string]any{}, "confirmed": true, "confirmed_by": "janis",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing signature")
	}
}

func TestHandleSemanticProfileCorrectRejectsUnconfirmedOrMissingAttribution(t *testing.T) {
	fake := &fakeSituationCommands{profileVersion: &profilemodel.ProfileVersion{ID: "profile-3", SignatureKey: "sig-1"}}
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: fake}, st, audit.New(st.DB()))
	profile := map[string]any{
		"signature": "sig-1", "subject_kind": "database_host", "event_kind": "resource_saturation",
		"possible_role": "symptom", "candidate_scope": []any{"host"}, "horizon_tier": "hours",
		"useful_capabilities": []any{"zabbix_metric_range"}, "uncertainty": []any{"workload unknown"},
	}

	res, err := s.handleSemanticProfileCorrect(context.Background(), reqWith(map[string]any{
		"signature": "sig-1", "expected_version": 1, "profile": profile, "confirmed": false, "confirmed_by": "janis",
	}))
	if err != nil || !res.IsError {
		t.Fatalf("expected an error result for confirmed=false, err=%v", err)
	}

	res, err = s.handleSemanticProfileCorrect(context.Background(), reqWith(map[string]any{
		"signature": "sig-1", "expected_version": 1, "profile": profile, "confirmed": true, "confirmed_by": "",
	}))
	if err != nil || !res.IsError {
		t.Fatalf("expected an error result for empty confirmed_by, err=%v", err)
	}

	if fake.lastCorrection.Signature != "" {
		t.Fatalf("CorrectSemanticProfile must not be called without valid confirmation, got %+v", fake.lastCorrection)
	}
}
