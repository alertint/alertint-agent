// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

func TestAppendSemanticProfileVersionAdvancesHeadAndRetainsHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	first := testProfileVersion("profile-1", "zabbix:trigger=18422:template=sha256:923b", "inferred")
	if err := s.AppendSemanticProfileVersion(ctx, 0, first); err != nil {
		t.Fatal(err)
	}
	second := testProfileVersion("profile-2", first.SignatureKey, "correction")
	if err := s.AppendSemanticProfileVersion(ctx, 1, second); err != nil {
		t.Fatal(err)
	}

	history, err := s.SemanticProfile(ctx, first.SignatureKey)
	if err != nil {
		t.Fatal(err)
	}
	if history.CurrentVersion != 2 || len(history.Versions) != 2 {
		t.Fatalf("history = %+v", history)
	}
	if history.Versions[0].Version != 1 || history.Versions[0].SupersededAt == nil {
		t.Fatalf("first version was not superseded: %+v", history.Versions[0])
	}
	if history.Versions[1].Version != 2 || history.Versions[1].SupersededAt != nil {
		t.Fatalf("second version is not current: %+v", history.Versions[1])
	}
}

func TestAppendSemanticProfileVersionRejectsStaleHead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	first := testProfileVersion("profile-1", "zabbix:trigger=18422:template=sha256:923b", "inferred")
	if err := s.AppendSemanticProfileVersion(ctx, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendSemanticProfileVersion(ctx, 0, testProfileVersion("profile-2", first.SignatureKey, "correction")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("err = %v, want version conflict", err)
	}
}

func testProfileVersion(id, signature, origin string) model.ProfileVersion {
	material := json.RawMessage(`{"source":"zabbix","trigger_id":"18422","template_identity":"sha256:923b"}`)
	return model.ProfileVersion{
		ID: id, SignatureKey: signature, Source: "zabbix", SignatureMaterial: material,
		Profile: model.Profile{Signature: signature, SubjectKind: "database_host", EventKind: "resource_saturation", PossibleRole: "symptom", CandidateScope: []string{"host"}, HorizonTier: "hours", UsefulCapabilities: []string{"zabbix_metric_range"}, Uncertainty: []string{"workload unknown"}},
		Origin:  model.Origin(origin), InputDigest: "sha256:input", CreatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}
}
