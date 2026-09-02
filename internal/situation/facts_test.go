// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// current_duration fact: identity/value stability within a class, and
// identity change on class crossing.
// ----------------------------------------------------------------------

func TestDurationFactIdentityAndValueStableWithinClass(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(20 * time.Minute) // medium
	first := findFact(t, DeriveStoreFacts(in), "current_duration", "medium")

	in2 := in
	in2.Now = in.Situation.EffectiveStartedAt.Add(40 * time.Minute) // still medium
	second := findFact(t, DeriveStoreFacts(in2), "current_duration", "medium")

	wantID := "duration:situation-1:1:medium"
	if first.ID != wantID {
		t.Fatalf("fact ID = %q, want %q", first.ID, wantID)
	}
	if first.ID != second.ID {
		t.Fatalf("fact ID changed across wall-time advance within class: %q vs %q", first.ID, second.ID)
	}
	if string(first.Value) != string(second.Value) {
		t.Fatalf("fact value changed across wall-time advance within class: %s vs %s", first.Value, second.Value)
	}
	if first.Digest != second.Digest {
		t.Fatal("fact digest changed across wall-time advance within class")
	}

	var val map[string]any
	if err := json.Unmarshal(first.Value, &val); err != nil {
		t.Fatal(err)
	}
	if _, ok := val["threshold_crossed_at"]; !ok {
		t.Fatal("duration fact value missing threshold_crossed_at")
	}
	if _, ok := val["elapsed_seconds"]; ok {
		t.Fatal("duration fact value must not contain elapsed_seconds")
	}
	if val["class"] != "medium" {
		t.Fatalf("class = %v, want medium", val["class"])
	}
}

func TestDurationFactCrossesClassBoundaryExactlyOnce(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(20 * time.Minute)
	medium := findFact(t, DeriveStoreFacts(in), "current_duration", "medium")

	in.Now = in.Situation.EffectiveStartedAt.Add(2 * time.Hour)
	long := findFact(t, DeriveStoreFacts(in), "current_duration", "long")

	if medium.ID == long.ID {
		t.Fatal("crossing a duration class boundary must produce a new fact identity")
	}

	// Only one current_duration fact should be present per reduction (the
	// one matching the current class) — DeriveStoreFacts derives the
	// *current* class fact, not a full history of every crossed class.
	facts := DeriveStoreFacts(in)
	count := 0
	for _, f := range facts {
		if f.Kind == "current_duration" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want exactly 1 current_duration fact, got %d", count)
	}
}

// ----------------------------------------------------------------------
// DeriveStoreFacts: all 8 kinds, correct result statuses, deterministic
// ordering.
// ----------------------------------------------------------------------

func TestStoreFactsIncludesAllEightKinds(t *testing.T) {
	in := baseSnapshotInput(t)
	facts := DeriveStoreFacts(in)
	want := []string{
		"source_symptom_state", "source_lifecycle_summary", "current_duration",
		"incident_membership", "incident_triage_state", "acute_finding",
		"prior_situation_duration_distribution", "capability_limitation",
	}
	seen := map[string]bool{}
	for _, f := range facts {
		seen[f.Kind] = true
	}
	for _, k := range want {
		if !seen[k] {
			t.Errorf("missing fact kind %q", k)
		}
	}
}

func TestStoreFactsAcuteFindingNeverConfirmedEmptyWhenUnwired(t *testing.T) {
	in := baseSnapshotInput(t) // LatestAttempt nil by construction
	f := findFact(t, DeriveStoreFacts(in), "acute_finding", "incident-1")
	if f.ResultStatus == model.FactConfirmedEmpty {
		t.Fatal("nil LatestAttempt must never be represented as confirmed_empty")
	}
	if f.ResultStatus != model.FactUnavailable {
		t.Fatalf("ResultStatus = %q, want %q for an unwired Finding source", f.ResultStatus, model.FactUnavailable)
	}
}

func TestStoreFactsAcuteFindingConfirmedValueWhenPresent(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Incidents = append([]IncidentState{}, in.Incidents...)
	findingID := "finding-1"
	in.Incidents[0].Triage.LatestAttempt = &TriageAttemptResult{
		ResultCode: "success", OutputDigest: "od-1", FindingID: &findingID, CompletedAt: in.Now,
	}
	f := findFact(t, DeriveStoreFacts(in), "acute_finding", "incident-1")
	if f.ResultStatus != model.FactConfirmedValue {
		t.Fatalf("ResultStatus = %q, want %q", f.ResultStatus, model.FactConfirmedValue)
	}
}

func TestStoreFactsPriorDurationDistributionConfirmedEmptyWithNoHistory(t *testing.T) {
	in := baseSnapshotInput(t) // PriorSituations nil
	f := findFact(t, DeriveStoreFacts(in), "prior_situation_duration_distribution", "group-1")
	if f.ResultStatus != model.FactConfirmedEmpty {
		t.Fatalf("ResultStatus = %q, want %q for zero prior situations", f.ResultStatus, model.FactConfirmedEmpty)
	}
}

func TestStoreFactsCapabilityLimitationNeverConfirmedEmpty(t *testing.T) {
	in := baseSnapshotInput(t)
	f := findFact(t, DeriveStoreFacts(in), "capability_limitation", "plan2")
	if f.ResultStatus == model.FactConfirmedEmpty {
		t.Fatal("an unsupported capability must never be represented as confirmed_empty")
	}
	if f.ResultStatus != model.FactUnavailable {
		t.Fatalf("ResultStatus = %q, want %q", f.ResultStatus, model.FactUnavailable)
	}
}

func TestStoreFactsIncidentTriageStateUnavailableBeforeFirstTriageRow(t *testing.T) {
	in := baseSnapshotInput(t) // Triage.Phase == "" by construction
	f := findFact(t, DeriveStoreFacts(in), "incident_triage_state", "incident-1")
	if f.ResultStatus != model.FactUnavailable {
		t.Fatalf("ResultStatus = %q, want %q for an Incident with no incident_triage row yet", f.ResultStatus, model.FactUnavailable)
	}
}

func TestStoreFactsSortedByKindSubjectID(t *testing.T) {
	in := baseSnapshotInput(t)
	facts := DeriveStoreFacts(in)
	for i := 1; i < len(facts); i++ {
		a, b := facts[i-1], facts[i]
		switch {
		case a.Kind > b.Kind:
			t.Fatalf("facts not sorted by kind at index %d: %q > %q", i, a.Kind, b.Kind)
		case a.Kind == b.Kind && a.Subject > b.Subject:
			t.Fatalf("facts not sorted by subject at index %d: %q > %q", i, a.Subject, b.Subject)
		case a.Kind == b.Kind && a.Subject == b.Subject && a.ID > b.ID:
			t.Fatalf("facts not sorted by id at index %d: %q > %q", i, a.ID, b.ID)
		}
	}
}

func TestStoreFactsEveryFactCarriesRequiredIdentity(t *testing.T) {
	in := baseSnapshotInput(t)
	for _, f := range DeriveStoreFacts(in) {
		if f.ID == "" || f.SituationID != in.Situation.ID || f.Digest == "" || len(f.Value) == 0 || f.ObservedAt.IsZero() {
			t.Fatalf("fact %+v missing required identity/content", f)
		}
	}
}

// ----------------------------------------------------------------------
// MaterialFactHash: materiality/non-materiality, shuffled order,
// exactly-once change per included dimension.
// ----------------------------------------------------------------------

func materialHashFor(t *testing.T, in SnapshotInput) string {
	t.Helper()
	symptoms := deriveSymptoms(in.Deliveries)
	class := DurationClass(elapsedDuration(in))
	return MaterialFactHash(in, symptoms, class)
}

func TestMaterialFactHashStableWithinDurationClass(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(20 * time.Minute)
	h1 := materialHashFor(t, in)

	in2 := in
	in2.Now = in.Situation.EffectiveStartedAt.Add(45 * time.Minute)
	h2 := materialHashFor(t, in2)

	if DurationClass(elapsedDuration(in)) != DurationClass(elapsedDuration(in2)) {
		t.Fatal("test setup invalid: expected same duration class")
	}
	if h1 != h2 {
		t.Fatal("elapsed seconds within a duration class changed material fact hash")
	}
}

func TestMaterialFactHashChangesOnSymptomLifecycle(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := materialHashFor(t, in)

	resolved := in
	resolved.Deliveries = append([]Delivery{}, in.Deliveries...)
	resolved.Deliveries[0].Status = model.DeliveryStatusResolved
	h2 := materialHashFor(t, resolved)

	if h1 == h2 {
		t.Fatal("symptom lifecycle change did not change material fact hash")
	}
}

func TestMaterialFactHashChangesOnDurationClass(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(20 * time.Minute) // medium
	h1 := materialHashFor(t, in)

	in.Now = in.Situation.EffectiveStartedAt.Add(2 * time.Hour) // long
	h2 := materialHashFor(t, in)

	if h1 == h2 {
		t.Fatal("duration class change did not change material fact hash")
	}
}

func TestMaterialFactHashChangesOnMembership(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := materialHashFor(t, in)

	added := in
	added.Deliveries = append([]Delivery{}, in.Deliveries...)
	added.Deliveries = append(added.Deliveries, deliveryFor("delivery-2", "incident-1", "pd-2", in.Situation.EffectiveStartedAt.Add(time.Minute)))
	h2 := materialHashFor(t, added)

	if h1 == h2 {
		t.Fatal("material Incident membership change did not change material fact hash")
	}
}

func TestMaterialFactHashReflectsNormalizedFindingOutcomeAndEvidenceDigest(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := materialHashFor(t, in)

	withFinding := in
	withFinding.Incidents = append([]IncidentState{}, in.Incidents...)
	withFinding.Incidents[0].Triage.LatestAttempt = &TriageAttemptResult{
		ResultCode: "success", OutputDigest: "od-1", CompletedAt: in.Now,
	}
	h2 := materialHashFor(t, withFinding)
	if h1 == h2 {
		t.Fatal("normalized Acute Triage outcome class did not change material fact hash")
	}

	differentEvidence := withFinding
	differentEvidence.Incidents = append([]IncidentState{}, withFinding.Incidents...)
	evidenceDigest := "evidence-pack-2"
	differentEvidence.Incidents[0].Triage.LatestAttempt = &TriageAttemptResult{
		ResultCode: "success", OutputDigest: "od-1", EvidencePackDigest: &evidenceDigest, CompletedAt: in.Now,
	}
	h3 := materialHashFor(t, differentEvidence)
	if h2 == h3 {
		t.Fatal("evidence pack digest change did not change material fact hash")
	}
}

func TestMaterialFactHashIgnoresTriageSchedulingMachinery(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := materialHashFor(t, in)

	mutated := in
	mutated.Incidents = append([]IncidentState{}, in.Incidents...)
	mutated.Incidents[0].Triage.Phase = "pending"
	mutated.Incidents[0].Triage.Attempts = 3
	next := in.Now.Add(time.Minute)
	mutated.Incidents[0].Triage.NextAt = &next
	decision := "request"
	mutated.Incidents[0].Triage.Decision = &decision
	reason := "insufficient_coverage"
	mutated.Incidents[0].Triage.DecisionReason = &reason

	h2 := materialHashFor(t, mutated)
	if h1 != h2 {
		t.Fatal("triage scheduling/decision machinery (phase/attempts/next_at/decision) changed material fact hash")
	}
}

func TestMaterialFactHashAndAssessmentBasisHashIgnoreLeaseClaimRetryState(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := materialHashFor(t, in)
	b1 := AssessmentBasisHash(in, h1, nil)

	mutated := in
	owner := "worker-1"
	errClass := "timeout"
	retryAt := in.Now.Add(time.Minute)
	mutated.Situation.LeaseOwner = &owner
	mutated.Situation.ClaimToken = 99
	mutated.Situation.AttemptCount = 4
	mutated.Situation.LastErrorClass = &errClass
	mutated.Situation.RetryAt = &retryAt

	h2 := materialHashFor(t, mutated)
	b2 := AssessmentBasisHash(mutated, h2, nil)

	if h1 != h2 {
		t.Fatal("lease/claim/retry state changed material fact hash")
	}
	if b1 != b2 {
		t.Fatal("lease/claim/retry state changed assessment basis hash")
	}
}

func TestMaterialFactHashChangesOnLimitationSet(t *testing.T) {
	in := baseSnapshotInput(t)
	before := materialHashFor(t, in)

	orig := plan2UnsupportedCapabilities
	plan2UnsupportedCapabilities = append(append([]model.Limitation{}, orig...), model.Limitation{Code: "test_extra_limitation", Detail: "test"})
	defer func() { plan2UnsupportedCapabilities = orig }()

	after := materialHashFor(t, in)
	if before == after {
		t.Fatal("adding a limitation code did not change material fact hash")
	}
}

func TestMaterialFactHashOrderIndependentOfIncidentAndPriorSituationRowOrder(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Deliveries = []Delivery{
		deliveryFor("delivery-1", "incident-1", "pd-1", in.Situation.EffectiveStartedAt),
		deliveryFor("delivery-2", "incident-2", "pd-2", in.Situation.EffectiveStartedAt),
	}
	in.Incidents = []IncidentState{baseIncident(t, "incident-1"), baseIncident(t, "incident-2")}
	in.PriorSituations = fiveShortPriorSituations("group-1", in.Situation.EffectiveStartedAt)
	h1 := materialHashFor(t, in)

	shuffled := in
	shuffled.Incidents = []IncidentState{in.Incidents[1], in.Incidents[0]}
	shuffled.PriorSituations = append([]CompletedSituation{}, in.PriorSituations...)
	shuffled.PriorSituations[0], shuffled.PriorSituations[4] = shuffled.PriorSituations[4], shuffled.PriorSituations[0]
	h2 := materialHashFor(t, shuffled)

	if h1 != h2 {
		t.Fatal("material fact hash depends on Incident/PriorSituation row order")
	}
}

func TestMaterialFactHashDTOIncludesSchemaAndFactSchemaVersions(t *testing.T) {
	base := materialFactHashDTO{SchemaVersion: 1, FactSchemaVersion: 1}

	changedSchema := base
	changedSchema.SchemaVersion = 2
	if canonicalDigest(base) == canonicalDigest(changedSchema) {
		t.Fatal("schema_version change did not change digest")
	}

	changedFactSchema := base
	changedFactSchema.FactSchemaVersion = 2
	if canonicalDigest(base) == canonicalDigest(changedFactSchema) {
		t.Fatal("fact_schema_version change did not change digest")
	}
}

// ----------------------------------------------------------------------
// AssessmentBasisHash: reason catalog/predicate versions, lifecycle
// floor/attention, validator/schema versions.
// ----------------------------------------------------------------------

func TestAssessmentBasisHashReflectsReasonCatalogAndPredicateVersions(t *testing.T) {
	in := baseSnapshotInput(t)
	material := "sha256:fixed"
	r1 := model.ReasonCandidate{ID: "reason:x:v1:s:1", Code: "duration_outlier", CatalogVersion: 1, PredicateVersion: 1}

	r2 := r1
	r2.PredicateVersion = 2
	h1 := AssessmentBasisHash(in, material, []model.ReasonCandidate{r1})
	h2 := AssessmentBasisHash(in, material, []model.ReasonCandidate{r2})
	if h1 == h2 {
		t.Fatal("predicate version change did not change assessment basis hash")
	}

	r3 := r1
	r3.CatalogVersion = 2
	h3 := AssessmentBasisHash(in, material, []model.ReasonCandidate{r3})
	if h1 == h3 {
		t.Fatal("catalog version change did not change assessment basis hash")
	}
}

func TestAssessmentBasisHashReflectsLifecycleAttentionAndFloor(t *testing.T) {
	in := baseSnapshotInput(t)
	material := "sha256:fixed"
	base := AssessmentBasisHash(in, material, nil)

	changedLifecycle := in
	changedLifecycle.Situation.Lifecycle = model.LifecycleRecoveryPending
	if AssessmentBasisHash(changedLifecycle, material, nil) == base {
		t.Fatal("lifecycle change did not change assessment basis hash")
	}

	changedAttention := in
	changedAttention.Situation.Attention = model.AttentionUrgent
	if AssessmentBasisHash(changedAttention, material, nil) == base {
		t.Fatal("attention change did not change assessment basis hash")
	}

	floorReason := model.ReasonCandidate{ID: "r1", Code: "critical_anchor", CatalogVersion: 1, PredicateVersion: 1, DeterministicFloor: true}
	nonFloorReason := floorReason
	nonFloorReason.DeterministicFloor = false
	hFloor := AssessmentBasisHash(in, material, []model.ReasonCandidate{floorReason})
	hNonFloor := AssessmentBasisHash(in, material, []model.ReasonCandidate{nonFloorReason})
	if hFloor == hNonFloor {
		t.Fatal("deterministic floor flag change did not change assessment basis hash")
	}
}

func TestAssessmentBasisHashChangesOnMaterialFactHash(t *testing.T) {
	in := baseSnapshotInput(t)
	h1 := AssessmentBasisHash(in, "sha256:one", nil)
	h2 := AssessmentBasisHash(in, "sha256:two", nil)
	if h1 == h2 {
		t.Fatal("material fact hash change did not change assessment basis hash")
	}
}

func TestAssessmentBasisHashDTOIncludesValidatorAndSchemaVersion(t *testing.T) {
	base := assessmentBasisHashDTO{AssessmentSchemaVersion: 1, ValidatorVersion: 1}

	changedAssessment := base
	changedAssessment.AssessmentSchemaVersion = 2
	if canonicalDigest(base) == canonicalDigest(changedAssessment) {
		t.Fatal("assessment_schema_version change did not change digest")
	}

	changedValidator := base
	changedValidator.ValidatorVersion = 2
	if canonicalDigest(base) == canonicalDigest(changedValidator) {
		t.Fatal("validator_version change did not change digest")
	}
}
