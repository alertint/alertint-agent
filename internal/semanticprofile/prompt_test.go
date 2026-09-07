// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

func TestBuildInferencePromptRendersFrozenInputAndSchema(t *testing.T) {
	frozen := profilemodel.SignatureInput{
		Source: "zabbix", AlertName: "DiskFull", ProvenSignalID: "item:123", ProvenVersion: "v2",
		LabelKeys: []string{"service", "severity"},
	}
	frozenJSON, err := json.Marshal(frozen)
	if err != nil {
		t.Fatalf("marshal frozen input: %v", err)
	}

	prompt, err := semanticprofile.BuildInferencePrompt(frozenJSON)
	if err != nil {
		t.Fatalf("BuildInferencePrompt: %v", err)
	}
	if !strings.Contains(prompt.Text(), "zabbix") || !strings.Contains(prompt.Text(), "DiskFull") {
		t.Fatalf("prompt does not render the frozen input: %s", prompt.Text())
	}
	if !strings.Contains(prompt.Text(), "subject_kind") || !strings.Contains(prompt.Text(), "useful_capabilities") {
		t.Fatalf("prompt does not render the closed profile schema: %s", prompt.Text())
	}
	for _, forbidden := range []string{"attention", "apply_envelope"} {
		if strings.Contains(strings.ToLower(prompt.Text()), forbidden) {
			t.Fatalf("prompt must never offer %q as a field: %s", forbidden, prompt.Text())
		}
	}
	if !strings.Contains(prompt.Text(), "no tools") {
		t.Fatalf("prompt must explicitly forbid tools: %s", prompt.Text())
	}
	if prompt.MaxOutputTokens <= 0 {
		t.Fatal("expected a bounded MaxOutputTokens")
	}
}

func TestBuildInferencePromptRejectsMalformedFrozenInput(t *testing.T) {
	if _, err := semanticprofile.BuildInferencePrompt(json.RawMessage(`not json`)); err == nil {
		t.Fatal("expected an error for malformed frozen input JSON")
	}
}

func TestBuildInferencePromptListsEveryHorizonTierAndCapability(t *testing.T) {
	frozen, err := json.Marshal(profilemodel.SignatureInput{Source: "alertmanager", AlertName: "HighLatency"})
	if err != nil {
		t.Fatalf("marshal frozen input: %v", err)
	}
	prompt, err := semanticprofile.BuildInferencePrompt(frozen)
	if err != nil {
		t.Fatalf("BuildInferencePrompt: %v", err)
	}
	for _, tier := range []string{profilemodel.HorizonUnknown, profilemodel.HorizonMinutes, profilemodel.HorizonHours, profilemodel.HorizonDays} {
		if !strings.Contains(prompt.Text(), tier) {
			t.Fatalf("prompt must list horizon tier %q: %s", tier, prompt.Text())
		}
	}
	for _, cap := range []string{
		profilemodel.CapabilityStoreRead, profilemodel.CapabilityPrometheusQuery, profilemodel.CapabilityZabbixMetricRange,
		profilemodel.CapabilityZabbixProblemHist, profilemodel.CapabilityLokiQuery, profilemodel.CapabilitySentryIssues,
		profilemodel.CapabilityChangeEvents,
	} {
		if !strings.Contains(prompt.Text(), cap) {
			t.Fatalf("prompt must list capability %q: %s", cap, prompt.Text())
		}
	}
}
