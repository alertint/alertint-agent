// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func sampleJudgmentSnapshot() Snapshot {
	return Snapshot{
		SituationID: "sit-1", InputVersion: 3, MaterialHash: "sha256:abc",
		Symptoms: []Symptom{
			{ID: "database_lock", Lifecycle: model.DeliveryStatusFiring, TriggerVersion: "v1"},
			{ID: "resolved_symptom", Lifecycle: model.DeliveryStatusResolved},
		},
		Impact: []ImpactFact{{Kind: "availability", Confirmed: true}, {Kind: "ignored_unconfirmed", Confirmed: false}},
	}
}

func validJudgmentRequest() model.JudgmentRequest {
	return model.JudgmentRequest{
		Situation: "sit-1", Judgment: model.JudgmentExpectedThisEpisode, Basis: model.JudgmentBasisOperatorKnowledge,
		OperatorConfirmed: true, ConfirmedBy: "alice",
	}
}

func TestValidateJudgmentRequestRequiresConfirmation(t *testing.T) {
	req := validJudgmentRequest()
	req.OperatorConfirmed = false
	if err := ValidateJudgmentRequest(req); err == nil {
		t.Fatal("expected an error for an unconfirmed judgment request")
	}
}

func TestValidateJudgmentRequestRequiresConfirmedBy(t *testing.T) {
	req := validJudgmentRequest()
	req.ConfirmedBy = "  "
	if err := ValidateJudgmentRequest(req); err == nil {
		t.Fatal("expected an error for a blank confirming operator")
	}
}

func TestValidateJudgmentRequestRejectsClosedEnumViolations(t *testing.T) {
	req := validJudgmentRequest()
	req.Judgment = model.JudgmentKind("free text steering attempt")
	if err := ValidateJudgmentRequest(req); err == nil {
		t.Fatal("expected an error for a non-enum judgment kind")
	}

	req = validJudgmentRequest()
	req.Basis = model.JudgmentBasis("some vibe")
	if err := ValidateJudgmentRequest(req); err == nil {
		t.Fatal("expected an error for a non-enum judgment basis")
	}
}

func TestBuildJudgmentCapturesExactCoverage(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", now)
	if err != nil {
		t.Fatal(err)
	}
	if j.SituationID != "sit-1" || j.JudgedInputVersion != 3 || j.CoveredFactHash != "sha256:abc" {
		t.Fatalf("judgment identity=%+v", j)
	}
	if len(j.CoveredSymptoms) != 1 || j.CoveredSymptoms[0] != "database_lock@v1" {
		t.Fatalf("covered symptoms=%v, want exactly [database_lock@v1] (resolved symptom excluded)", j.CoveredSymptoms)
	}
	if len(j.CoveredImpact) != 1 || j.CoveredImpact[0] != "availability" {
		t.Fatalf("covered impact=%v, want exactly [availability] (unconfirmed impact excluded)", j.CoveredImpact)
	}
	if j.AuthenticatedAs != "slack:U123" || j.AssertedOperator != "alice" {
		t.Fatalf("attribution=%+v", j)
	}
}

func TestBuildJudgmentRejectsInvalidRequest(t *testing.T) {
	req := validJudgmentRequest()
	req.OperatorConfirmed = false
	if _, err := BuildJudgment("j-1", sampleJudgmentSnapshot(), req, "slack:U123", time.Now().UTC()); err == nil {
		t.Fatal("expected BuildJudgment to reject an unconfirmed request")
	}
}

func TestJudgmentApplicableExpires(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	validUntil := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", validUntil.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	j.ValidUntil = &validUntil

	stillOK, reason := JudgmentApplicable(snap, j, validUntil.Add(-time.Minute))
	if !stillOK || reason != JudgmentStillApplicable {
		t.Fatalf("before expiry: applicable=%v reason=%s", stillOK, reason)
	}
	expired, reason := JudgmentApplicable(snap, j, validUntil)
	if expired || reason != JudgmentSupersessionExpired {
		t.Fatalf("at expiry: applicable=%v reason=%s", expired, reason)
	}
}

func TestJudgmentApplicableNewSymptomSupersedes(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	later := snap
	later.Symptoms = append(append([]Symptom(nil), snap.Symptoms...), Symptom{ID: "new_symptom", Lifecycle: model.DeliveryStatusFiring})
	ok, reason := JudgmentApplicable(later, j, time.Now().UTC())
	if ok || reason != JudgmentSupersessionOutOfScope {
		t.Fatalf("applicable=%v reason=%s, want superseded by a new symptom", ok, reason)
	}
}

func TestJudgmentApplicableNewImpactSupersedes(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	later := snap
	later.Impact = append(append([]ImpactFact(nil), snap.Impact...), ImpactFact{Kind: "data_loss", Confirmed: true})
	ok, reason := JudgmentApplicable(later, j, time.Now().UTC())
	if ok || reason != JudgmentSupersessionOutOfScope {
		t.Fatalf("applicable=%v reason=%s, want superseded by a new confirmed impact", ok, reason)
	}
}

func TestJudgmentApplicableTriggerVersionChangeSupersedes(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	later := snap
	later.Symptoms = append([]Symptom(nil), snap.Symptoms...)
	later.Symptoms[0].TriggerVersion = "v2" // same symptom id, new trigger/template version
	ok, reason := JudgmentApplicable(later, j, time.Now().UTC())
	if ok || reason != JudgmentSupersessionOutOfScope {
		t.Fatalf("applicable=%v reason=%s, want a trigger-version change to supersede", ok, reason)
	}
}

func TestJudgmentApplicableResolvedSymptomDoesNotSupersede(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	later := snap
	later.Symptoms = append([]Symptom(nil), snap.Symptoms...)
	later.Symptoms[0].Lifecycle = model.DeliveryStatusResolved // the covered symptom recovers
	ok, reason := JudgmentApplicable(later, j, time.Now().UTC())
	if !ok || reason != JudgmentStillApplicable {
		t.Fatalf("applicable=%v reason=%s, want a resolved symptom to remain harmless", ok, reason)
	}
}

func TestJudgmentApplicableLaterReceiptTimestampAloneDoesNotSupersede(t *testing.T) {
	snap := sampleJudgmentSnapshot()
	j, err := BuildJudgment("j-1", snap, validJudgmentRequest(), "slack:U123", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	later := snap
	later.FirstReceivedAt = snap.FirstReceivedAt.Add(time.Hour)
	later.ElapsedSeconds = snap.ElapsedSeconds + 999
	ok, reason := JudgmentApplicable(later, j, time.Now().UTC())
	if !ok || reason != JudgmentStillApplicable {
		t.Fatalf("applicable=%v reason=%s, want receipt-timing-only change to remain applicable", ok, reason)
	}
}
