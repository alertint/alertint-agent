// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestSignatureDoesNotFragmentByHostValue(t *testing.T) {
	a := sampleDelivery(map[string]string{"alertname": "HighCPU", "host": "db-01"})
	b := sampleDelivery(map[string]string{"alertname": "HighCPU", "host": "db-02"})
	if got, want := Signature(a), Signature(b); got != want {
		t.Fatalf("%q != %q", got, want)
	}
}

func TestSignatureNormalizesUppercaseSHA256Prefix(t *testing.T) {
	a := sampleDelivery(map[string]string{"alertname": "HighCPU", "zabbix_trigger_id": "18422", "template_identity": "SHA256:923B"})
	b := sampleDelivery(map[string]string{"alertname": "HighCPU", "zabbix_trigger_id": "18422", "template_identity": "sha256:923b"})
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

func TestInferencePromptBoundsSourceText(t *testing.T) {
	delivery := sampleDelivery(map[string]string{"alertname": "HighCPU"})
	delivery.Source = strings.Repeat("source", 100)
	prompt := inferencePrompt(delivery, "zabbix:schema=sha256:test")
	if strings.Contains(prompt.Prefix, delivery.Source) || len(prompt.Prefix) > 5_000 {
		t.Fatalf("prompt retained unbounded source: %d bytes", len(prompt.Prefix))
	}
}

func TestHugeLabelMapsKeepPromptAndSignatureMaterialBounded(t *testing.T) {
	labels := make(map[string]string, 4_096)
	annotations := make(map[string]string, 4_096)
	for i := 0; i < 4_096; i++ {
		key := fmt.Sprintf("label-%04d", i)
		labels[key] = strings.Repeat("v", 4_096)
		annotations[key] = strings.Repeat("a", 4_096)
	}
	delivery := sampleDelivery(labels)
	delivery.Alert.Annotations = annotations
	_, material := signatureMaterial(delivery)
	prompt := inferencePrompt(delivery, Signature(delivery))
	if len(material) > maxProfileJSONBytes || len(prompt.Prefix) > 20_000 {
		t.Fatalf("material=%d prompt=%d", len(material), len(prompt.Prefix))
	}
}

func TestDecodeProfileRejectsOversizedRawAndCollections(t *testing.T) {
	tooLarge := json.RawMessage(`{"` + strings.Repeat("x", maxProfileJSONBytes) + `":"x"}`)
	if _, err := decodeProfile(tooLarge, "zabbix:test"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized raw err=%v", err)
	}
	profile := `{"signature":"","subject_kind":"database_host","event_kind":"resource_saturation","possible_role":"symptom","candidate_scope":["host"],"companion_signal_kinds":[` + strings.Repeat(`"availability",`, maxProfileListEntries) + `"availability"],"horizon_tier":"hours","useful_capabilities":["zabbix_metric_range"],"uncertainty":["workload unknown"]}`
	if _, err := decodeProfile(json.RawMessage(profile), "zabbix:test"); err == nil || !strings.Contains(err.Error(), "too many companion signal kinds") {
		t.Fatalf("unbounded collection err=%v", err)
	}
}

func TestCorrectRetainsAttributionAndDurablyHandsOffProfileChange(t *testing.T) {
	svc, st := newService(t)
	current := seedProfile(t, st, "zabbix:trigger=18422:template=sha256:923b", 1)
	updated, err := svc.Correct(context.Background(), Correction{Signature: current.SignatureKey, ExpectedVersion: 1, Confirmed: true, ConfirmedBy: "janis", Raw: validProfileJSON()})
	if err != nil {
		t.Fatal(err)
	}
	if updated.AssertedBy != "janis" {
		t.Fatalf("asserted attribution = %q", updated.AssertedBy)
	}
	changes, err := st.SemanticProfileChanges(context.Background(), 10)
	if err != nil || len(changes) != 2 || changes[1].Reason != "semantic_profile_changed" || changes[1].Version != 2 {
		t.Fatalf("changes=%+v err=%v", changes, err)
	}
	var payload string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT payload_json FROM audit_log WHERE kind = 'semantic_profile.corrected' ORDER BY seq DESC LIMIT 1`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"asserted_by":"janis"`) || strings.Contains(payload, string(validProfileJSON())) {
		t.Fatalf("correction audit=%s", payload)
	}
}

func TestCorrectionSurfacesRequiredRejectedAuditFailure(t *testing.T) {
	base := &failingAuditStore{history: &profilemodel.History{SignatureKey: "zabbix:test", CurrentVersion: 1, Versions: []profilemodel.ProfileVersion{{SignatureKey: "zabbix:test", Version: 1}}}}
	svc := New(base, staticLLM{}, "semantic-profile-v1", "configured-model", failingAuditSink{})
	_, err := svc.Correct(context.Background(), Correction{Signature: "zabbix:test", ExpectedVersion: 0, Confirmed: true, ConfirmedBy: "janis"})
	if !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestSuccessfulAuditFailureRollsBackProfileAndOutbox(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	seedProfile(t, st, "zabbix:trigger=18422:template=sha256:923b", 1)
	svc := New(st, staticLLM{}, "semantic-profile-v1", "configured-model", failingTransactionalAuditSink{})
	_, err = svc.Correct(context.Background(), Correction{Signature: "zabbix:trigger=18422:template=sha256:923b", ExpectedVersion: 1, Confirmed: true, ConfirmedBy: "janis", Raw: validProfileJSON()})
	if !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("err=%v", err)
	}
	history, err := st.SemanticProfile(context.Background(), "zabbix:trigger=18422:template=sha256:923b")
	if err != nil || history.CurrentVersion != 1 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	changes, err := st.SemanticProfileChanges(context.Background(), 10)
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes=%+v err=%v", changes, err)
	}
}

func TestCorrectRejectsOversizedAttribution(t *testing.T) {
	svc, st := newService(t)
	current := seedProfile(t, st, "zabbix:trigger=18422:template=sha256:923b", 1)
	_, err := svc.Correct(context.Background(), Correction{Signature: current.SignatureKey, ExpectedVersion: 1, Confirmed: true, ConfirmedBy: strings.Repeat("j", maxAttributionBytes+1), Raw: validProfileJSON()})
	if err == nil || !strings.Contains(err.Error(), "asserted attribution is too large") {
		t.Fatalf("err=%v", err)
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

var errAuditUnavailable = errors.New("audit unavailable")

type failingAuditStore struct{ history *profilemodel.History }

func (s *failingAuditStore) SemanticProfile(context.Context, string) (*profilemodel.History, error) {
	return s.history, nil
}
func (*failingAuditStore) AppendSemanticProfileVersion(context.Context, int, profilemodel.ProfileVersion) error {
	return nil
}
func (*failingAuditStore) AppendSemanticProfileVersionWithAudit(context.Context, int, profilemodel.ProfileVersion, store.SemanticProfileAuditAppender, []store.SemanticProfileAuditEvent) error {
	return nil
}

type failingAuditSink struct{}

func (failingAuditSink) Append(context.Context, string, string, any) error {
	return errAuditUnavailable
}

func (failingAuditSink) AppendTx(context.Context, *sql.Tx, string, string, any) error {
	return errAuditUnavailable
}

type failingTransactionalAuditSink struct{}

func (failingTransactionalAuditSink) Append(context.Context, string, string, any) error {
	return errAuditUnavailable
}

func (failingTransactionalAuditSink) AppendTx(context.Context, *sql.Tx, string, string, any) error {
	return errAuditUnavailable
}

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, staticLLM{}, "semantic-profile-v1", "configured-model", audit.New(st.DB())), st
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

func validProfileJSON() json.RawMessage {
	return json.RawMessage(`{"signature":"","subject_kind":"database_host","event_kind":"resource_saturation","possible_role":"symptom","candidate_scope":["host"],"companion_signal_kinds":["availability"],"horizon_tier":"hours","useful_capabilities":["zabbix_metric_range"],"uncertainty":["workload unknown"]}`)
}
