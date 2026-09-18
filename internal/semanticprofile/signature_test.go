// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"strings"
	"testing"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

func TestBuildSignatureProvenPairIsStableAndDistinctFromIDOnly(t *testing.T) {
	withVersion := profilemodel.SignatureInput{Source: "zabbix", ProvenSignalID: "trigger-42", ProvenVersion: "3"}
	sigA, err := BuildSignature(withVersion)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := BuildSignature(withVersion)
	if err != nil {
		t.Fatal(err)
	}
	if sigA.Key != sigB.Key {
		t.Fatalf("identical proven input produced different signatures: %s != %s", sigA.Key, sigB.Key)
	}
	if sigA.AdvisoryOnly {
		t.Fatal("proven signal ID+version must not be AdvisoryOnly")
	}
	if sigA.Mode != profilemodel.SignatureModeSignalVersion {
		t.Fatalf("mode = %q, want %q", sigA.Mode, profilemodel.SignatureModeSignalVersion)
	}

	idOnly := profilemodel.SignatureInput{Source: "zabbix", ProvenSignalID: "trigger-42"}
	sigIDOnly, err := BuildSignature(idOnly)
	if err != nil {
		t.Fatal(err)
	}
	if sigIDOnly.Key == sigA.Key {
		t.Fatal("absent version must not collide with a proven version signature")
	}
	if sigIDOnly.Mode != profilemodel.SignatureModeSignalIDOnly {
		t.Fatalf("mode = %q, want %q", sigIDOnly.Mode, profilemodel.SignatureModeSignalIDOnly)
	}
}

func TestBuildSignatureChangedProvenVersionDiffers(t *testing.T) {
	v1, err := BuildSignature(profilemodel.SignatureInput{Source: "zabbix", ProvenSignalID: "trigger-42", ProvenVersion: "3"})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := BuildSignature(profilemodel.SignatureInput{Source: "zabbix", ProvenSignalID: "trigger-42", ProvenVersion: "4"})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Key == v2.Key {
		t.Fatal("a changed proven version must produce a different signature")
	}
}

func TestBuildSignatureFallbackSameSchemaAcrossDifferentHostsShareIdentity(t *testing.T) {
	// Two deliveries from different hosts but the same rule/schema: same
	// source, alert name, and label/annotation KEY set (never concrete
	// values like the host name) must share one advisory signature.
	hostA := profilemodel.SignatureInput{
		Source: "alertmanager", AlertName: "HighErrorRate",
		LabelKeys: []string{"service", "host", "severity"}, AnnotationKeys: []string{"summary"},
	}
	hostB := profilemodel.SignatureInput{
		Source: "alertmanager", AlertName: "HighErrorRate",
		LabelKeys: []string{"severity", "service", "host"}, AnnotationKeys: []string{"summary"},
	}
	sigA, err := BuildSignature(hostA)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := BuildSignature(hostB)
	if err != nil {
		t.Fatal(err)
	}
	if sigA.Key != sigB.Key {
		t.Fatalf("same schema across hosts produced different signatures: %s != %s", sigA.Key, sigB.Key)
	}
	if !sigA.AdvisoryOnly {
		t.Fatal("fallback signature must report AdvisoryOnly")
	}
}

func TestBuildSignatureFallbackDifferentAlertNameDiffers(t *testing.T) {
	a, err := BuildSignature(profilemodel.SignatureInput{Source: "alertmanager", AlertName: "HighErrorRate", LabelKeys: []string{"service"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSignature(profilemodel.SignatureInput{Source: "alertmanager", AlertName: "LowDiskSpace", LabelKeys: []string{"service"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Key == b.Key {
		t.Fatal("different alert names must not share a fallback signature")
	}
}

func TestBuildSignatureRequiresSource(t *testing.T) {
	if _, err := BuildSignature(profilemodel.SignatureInput{}); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestBuildSignatureOversizeMaterialRejected(t *testing.T) {
	huge := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		huge = append(huge, strings.Repeat("x", 32))
	}
	_, err := BuildSignature(profilemodel.SignatureInput{Source: "loki", AlertName: "x", LabelKeys: huge})
	if err == nil {
		t.Fatal("expected oversize material rejection")
	}
	if err != profilemodel.ErrOversizeSignatureMaterial {
		t.Fatalf("expected ErrOversizeSignatureMaterial, got: %v", err)
	}
}

func TestBuildSignatureAbsentProvenanceStaysAbsentInMaterial(t *testing.T) {
	sig, err := BuildSignature(profilemodel.SignatureInput{Source: "sentry", AlertName: "crash"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sig.Material), "signal_id") {
		t.Fatalf("fallback material must never fabricate a signal_id field: %s", sig.Material)
	}
}
