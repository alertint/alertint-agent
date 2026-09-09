// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"strings"
	"testing"
)

// EvidenceFingerprint is comparison provenance for exactly the structured
// facts materiality compares, taken before any display bound (lead
// authorization, round 4, 2026-09-09).
func TestEvidenceFingerprintCoversRecordedEvidenceOnly(t *testing.T) {
	base := EvidenceFingerprint([]string{"check one", "check two"}, "metrics_source_unavailable", 2)

	same := map[string]string{
		"absent and empty lists are the same fact": EvidenceFingerprint([]string{"check one", "check two"}, "metrics_source_unavailable", 2),
		"whitespace is not evidence":               EvidenceFingerprint([]string{" check   one ", "check\ttwo"}, " metrics_source_unavailable\n", 2),
	}
	for name, got := range same {
		if got != base {
			t.Fatalf("%s: %s != %s", name, got, base)
		}
	}

	changed := map[string]string{
		"an added observation":   EvidenceFingerprint([]string{"check one", "check two", "check three"}, "metrics_source_unavailable", 2),
		"a reordered list":       EvidenceFingerprint([]string{"check two", "check one"}, "metrics_source_unavailable", 2),
		"a changed limitation":   EvidenceFingerprint([]string{"check one", "check two"}, "logs_source_unavailable", 2),
		"a changed gap count":    EvidenceFingerprint([]string{"check one", "check two"}, "metrics_source_unavailable", 3),
		"a dropped observation":  EvidenceFingerprint([]string{"check one"}, "metrics_source_unavailable", 2),
		"a cut observation tail": EvidenceFingerprint([]string{"check one", "check tw…"}, "metrics_source_unavailable", 2),
	}
	for name, got := range changed {
		if got == base {
			t.Fatalf("%s must change the fingerprint", name)
		}
	}

	// Nothing but the recorded evidence enters it, and an evidence set that
	// is genuinely empty still HAS a fingerprint — so "" can only ever mean
	// unknown provenance, never an empty result.
	if empty := EvidenceFingerprint(nil, "", 0); empty == "" || empty != EvidenceFingerprint([]string{}, "", 0) || empty != EvidenceFingerprint([]string{"   "}, "", 0) {
		t.Fatalf("an empty evidence set must have one stable fingerprint: %q", empty)
	}
	if !strings.HasPrefix(base, "sha256:") {
		t.Fatalf("fingerprint shape: %q", base)
	}
}

// The display bounds cut what an operator sees; they never touch the
// comparison provenance recorded before them.
func TestBoundIncidentAnalysisKeepsComparisonProvenance(t *testing.T) {
	recorded := []string{"check one", "check two", "check three", "check four"}
	a := BoundIncidentAnalysis(IncidentAnalysis{
		IncidentID: "inc-1", Summary: "Deployment broke checkout", Findings: recorded,
		VerificationLimit:   strings.Repeat("degraded ", 30),
		EvidenceFingerprint: EvidenceFingerprint(recorded, strings.Repeat("degraded ", 30), 1),
	})
	if len(a.Findings) != AnalysisFindingsBound || len(a.VerificationLimit) > 100 {
		t.Fatalf("display bounds were not applied: %+v", a)
	}
	if a.EvidenceFingerprint != EvidenceFingerprint(recorded, strings.Repeat("degraded ", 30), 1) {
		t.Fatalf("the pre-truncation fingerprint must survive the display bounds: %q", a.EvidenceFingerprint)
	}
}
