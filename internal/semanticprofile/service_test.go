// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestSignatureDoesNotFragmentByHostValue(t *testing.T) {
	a := sampleDelivery(map[string]string{"alertname": "HighCPU", "host": "db-01"})
	b := sampleDelivery(map[string]string{"alertname": "HighCPU", "host": "db-02"})
	if got, want := Signature(a), Signature(b); got != want {
		t.Fatalf("%q != %q", got, want)
	}
}

func TestCorrectRejectsStaleHeadAndForbiddenFields(t *testing.T) {
	svc, st := newService(t)
	current := seedProfile(t, st, "zabbix:trigger=18422:template=sha256:923b", 1)
	_, err := svc.Correct(context.Background(), Correction{Signature: current.SignatureKey, ExpectedVersion: 0, Confirmed: true, ConfirmedBy: "janis"})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v", err)
	}
	_, err = svc.Correct(context.Background(), Correction{Signature: current.SignatureKey, ExpectedVersion: 1, Confirmed: true, ConfirmedBy: "janis", Raw: json.RawMessage(`{"attention":"urgent"}`)})
	if err == nil || !strings.Contains(err.Error(), "unknown field attention") {
		t.Fatalf("err=%v", err)
	}
}

func TestInferIfMissingCachesValidatedProfile(t *testing.T) {
	svc, _ := newService(t)
	delivery := sampleDelivery(map[string]string{"alertname": "HighCPU", "host": "db-01"})
	history, err := svc.InferIfMissing(context.Background(), delivery)
	if err != nil || history == nil || history.CurrentVersion != 1 {
		t.Fatalf("infer = %+v, %v", history, err)
	}
	cached, err := svc.InferIfMissing(context.Background(), delivery)
	if err != nil || cached.CurrentVersion != 1 {
		t.Fatalf("cached infer = %+v, %v", cached, err)
	}
}

func TestCorrectAuditsRejectedStaleWriteWithoutRawProfile(t *testing.T) {
	svc, st := newService(t)
	svc.SetAuditor(audit.New(st.DB()))
	current := seedProfile(t, st, "zabbix:trigger=18422:template=sha256:923b", 1)
	_, err := svc.Correct(context.Background(), Correction{Signature: current.SignatureKey, ExpectedVersion: 0, Confirmed: true, ConfirmedBy: "janis"})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err=%v", err)
	}
	var kind, payload string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT kind, payload_json FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind, &payload); err != nil {
		t.Fatal(err)
	}
	if kind != "semantic_profile.correction_rejected" || strings.Contains(payload, "janis") || strings.Contains(payload, "profile") {
		t.Fatalf("audit = %q %s", kind, payload)
	}
}

type staticLLM struct{}

func (staticLLM) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return llm.Completion{Model: "test-model", Raw: json.RawMessage(`{
		"signature":"","subject_kind":"database_host","event_kind":"resource_saturation","possible_role":"symptom",
		"candidate_scope":["host"],"companion_signal_kinds":["availability"],"horizon_tier":"hours",
		"useful_capabilities":["zabbix_metric_range"],"uncertainty":["workload unknown"]
	}`)}, nil
}

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, staticLLM{}, "semantic-profile-v1", "configured-model"), st
}

func seedProfile(t *testing.T, st *store.Store, signature string, version int) ProfileVersion {
	t.Helper()
	for i := 0; i < version; i++ {
		v := ProfileVersion{ID: "profile-" + string(rune('1'+i)), SignatureKey: signature, Source: "zabbix", SignatureMaterial: json.RawMessage(`{"source":"zabbix","trigger_id":"18422","template_identity":"sha256:923b"}`), Profile: Profile{Signature: signature, SubjectKind: "database_host", EventKind: "resource_saturation", PossibleRole: "symptom", CandidateScope: []string{"host"}, HorizonTier: "hours", UsefulCapabilities: []string{"zabbix_metric_range"}, Uncertainty: []string{"workload unknown"}}, Origin: OriginInferred, InputDigest: "sha256:input", CreatedAt: time.Date(2026, 8, 20, 10, 0, i, 0, time.UTC)}
		if err := st.AppendSemanticProfileVersion(context.Background(), i, v); err != nil {
			t.Fatal(err)
		}
	}
	h, err := st.SemanticProfile(context.Background(), signature)
	if err != nil {
		t.Fatal(err)
	}
	return h.Versions[len(h.Versions)-1]
}

func sampleDelivery(labels map[string]string) store.AlertDelivery {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	return store.AlertDelivery{Source: "zabbix", PayloadDigest: "sha256:delivery", Alert: store.Alert{Fingerprint: "fp", Status: "firing", Labels: labels, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}}
}
