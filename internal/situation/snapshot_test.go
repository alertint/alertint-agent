// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestMaterialFactHashIgnoresSlackAndExactSecondsWithinClass(t *testing.T) {
	a := sampleSnapshot()
	b := a
	b.ElapsedSeconds = a.ElapsedSeconds + 12
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatal("non-material fields changed hash")
	}
	b.DurationClass = "long"
	if MaterialFactHash(a) == MaterialFactHash(b) {
		t.Fatal("duration class did not change hash")
	}
}

func TestBuildSnapshotSanitizesProhibitedNoise(t *testing.T) {
	workload := "nightly"
	validUntil := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	input := baseSnapshotInput()
	input.Judgments = []model.Judgment{{
		ID: "judgment:a", SituationID: "s-1", JudgedInputVersion: 3, CoveredFactHash: "sha256:covered",
		CoveredSymptoms: []string{"cpu"}, CoveredImpact: []string{"availability"}, Judgment: model.JudgmentUnexpected,
		Basis: model.JudgmentBasisOperatorKnowledge, Workload: &workload, ValidUntil: &validUntil,
		EvidenceRefs: []string{"fact:cpu"}, AuthenticatedAs: "installation-token", AssertedOperator: "janis",
		CreatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}}
	input.Envelope = &model.EnvelopeEvaluation{ID: "evaluation:a", EnvelopeID: "envelope:1", EnvelopeVersion: 2,
		SituationID: "s-1", InputVersion: 3, Result: model.EnvelopeEvaluationMatch, MatchedFields: []string{"scope"},
		Observability: []string{"mandatory_signals_observable"}, QuietingAuthority: true,
		CreatedAt: time.Date(2026, 8, 20, 10, 1, 0, 0, time.UTC)}
	input.L1 = &L1Output{Status: "complete", Summary: "raw model prose", RootCauseClass: "resource_saturation",
		ConfidenceClass: "high", FactDigests: []string{"sha256:fact"}, EvidenceRefs: []string{"fact:cpu"}}
	setStringField(&input, "SlackChannel", "C123")

	snapshot, err := BuildSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"generated_at", "slack_channel"} {
		if _, ok := document[field]; ok {
			t.Fatalf("snapshot exposed %q: %s", field, raw)
		}
	}
	assertNestedFieldsAbsent(t, document, "judgments", []string{"id", "situation_id", "judged_input_version", "authenticated_as", "asserted_operator", "created_at"})
	assertNestedFieldsAbsent(t, document, "envelope", []string{"id", "situation_id", "input_version", "created_at"})
	assertNestedFieldsAbsent(t, document, "l1", []string{"summary", "confidence_class"})
}

func TestMaterialFactHashIgnoresJudgmentAuditMetadata(t *testing.T) {
	first := baseSnapshotInput()
	second := baseSnapshotInput()
	workloadA, workloadB := "nightly", "nightly"
	first.Judgments = []model.Judgment{{
		ID: "judgment:a", SituationID: "s-1", JudgedInputVersion: 3, CoveredFactHash: "sha256:covered",
		CoveredSymptoms: []string{"cpu"}, CoveredImpact: []string{"availability"}, Judgment: model.JudgmentUnexpected,
		Basis: model.JudgmentBasisOperatorKnowledge, Workload: &workloadA, EvidenceRefs: []string{"fact:cpu"},
		AuthenticatedAs: "token:a", AssertedOperator: "janis", CreatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}}
	second.Judgments = []model.Judgment{{
		ID: "judgment:b", SituationID: "another", JudgedInputVersion: 99, CoveredFactHash: "sha256:covered",
		CoveredSymptoms: []string{"cpu"}, CoveredImpact: []string{"availability"}, Judgment: model.JudgmentUnexpected,
		Basis: model.JudgmentBasisOperatorKnowledge, Workload: &workloadB, EvidenceRefs: []string{"fact:cpu"},
		AuthenticatedAs: "token:b", AssertedOperator: "liene", CreatedAt: time.Date(2026, 8, 20, 10, 5, 0, 0, time.UTC),
	}}
	a, err := BuildSnapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSnapshot(second)
	if err != nil {
		t.Fatal(err)
	}
	if a.MaterialHash != b.MaterialHash {
		t.Fatalf("judgment audit metadata changed hash:\n%s\n%s", a.MaterialHash, b.MaterialHash)
	}
}

func TestMaterialFactHashCanonicalizesEqualKeyPoliciesAndConnectors(t *testing.T) {
	a := sampleSnapshot()
	a.UrgentPolicies = []UrgentPolicy{
		{ID: "policy:1", Active: false, Scoped: true, EvidenceRefs: []string{"policy:inactive"}},
		{ID: "policy:1", Active: true, Scoped: true, EvidenceRefs: []string{"policy:active"}},
	}
	a.ConnectorStates = []ConnectorState{
		{Capability: observationmodel.CapabilityStoreRead, Status: observationmodel.ResultStatusUnavailable, Freshness: observationmodel.FreshnessUnknown, EvidenceRefs: []string{"run:b"}},
		{Capability: observationmodel.CapabilityStoreRead, Status: observationmodel.ResultStatusUnavailable, Freshness: observationmodel.FreshnessUnknown, EvidenceRefs: []string{"run:a"}},
	}
	b := a
	b.UrgentPolicies = []UrgentPolicy{a.UrgentPolicies[1], a.UrgentPolicies[0]}
	b.ConnectorStates = []ConnectorState{a.ConnectorStates[1], a.ConnectorStates[0]}
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatal("equal-key policy or connector input order changed hash")
	}
}

func TestBuildSnapshotRejectsUnknownEffectiveStartBasis(t *testing.T) {
	for _, basis := range []model.SourceTimeBasis{model.SourceTimeBasisMissing, model.SourceTimeBasis("invented")} {
		t.Run(string(basis), func(t *testing.T) {
			input := baseSnapshotInput()
			input.Situation.EffectiveStartedAtBasis = basis
			if _, err := BuildSnapshot(input); err == nil {
				t.Fatalf("accepted persisted effective-start basis %q", basis)
			}

			input = baseSnapshotInput()
			input.Deliveries = []Delivery{{ID: "d-1", StableSymptomID: "zabbix:1", Status: model.DeliveryStatusFiring,
				SourceStartedAt: utcPtr(2026, 8, 20, 8, 0), StartedAtBasis: basis,
				ReceivedAt: time.Date(2026, 8, 20, 8, 1, 0, 0, time.UTC)}}
			if _, err := BuildSnapshot(input); err == nil {
				t.Fatalf("accepted delivery effective-start basis %q", basis)
			}
		})
	}
}

func TestMaterialFactHashCanonicalizesOrderingJSONAndUTC(t *testing.T) {
	a := sampleSnapshot()
	a.CrossedMilestones = []string{"30m", "15m"}
	a.Facts = []observationmodel.Fact{
		fact("fact:b", "availability", `{"up":true,"zones":["a","b"]}`),
		fact("fact:a", "impact", `{"affected":20,"kind":"users"}`),
	}
	a.EffectiveStartedAt = time.Date(2026, 8, 20, 10, 0, 0, 0, time.FixedZone("EEST", 3*60*60))
	b := a
	b.CrossedMilestones = []string{"15m", "30m", "15m"}
	b.Facts = []observationmodel.Fact{
		fact("fact:a", "impact", `{ "kind": "users", "affected": 20 }`),
		fact("fact:b", "availability", `{ "zones": ["a", "b"], "up": true }`),
	}
	b.EffectiveStartedAt = time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatalf("canonical-equivalent snapshots differ:\n%s\n%s", MaterialFactHash(a), MaterialFactHash(b))
	}
	b.Facts[0].Digest = "sha256:changed"
	if MaterialFactHash(a) == MaterialFactHash(b) {
		t.Fatal("material evidence digest did not change hash")
	}
}

func TestMaterialFactHashIncludesNormalizedL1AndEnvelopeSemantics(t *testing.T) {
	a := sampleSnapshot()
	a.L1 = &L1Finding{Status: "complete", RootCauseClass: "resource_saturation", FactDigests: []string{"sha256:fact"}, EvidenceRefs: []string{"fact:cpu"}}
	a.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 2, Result: model.EnvelopeEvaluationMatch, MatchedFields: []string{"scope"}, QuietingAuthority: true}
	b := a
	b.L1 = &L1Finding{Status: "complete", RootCauseClass: "resource_saturation", FactDigests: []string{"sha256:fact"}, EvidenceRefs: []string{"fact:cpu"}}
	b.Envelope = &EnvelopeResult{EnvelopeID: "envelope:1", EnvelopeVersion: 2, Result: model.EnvelopeEvaluationMatch, MatchedFields: []string{"scope"}, QuietingAuthority: true}
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatal("equivalent normalized l1 or envelope semantics changed hash")
	}
	b.L1.RootCauseClass = "database_lock"
	if MaterialFactHash(a) == MaterialFactHash(b) {
		t.Fatal("normalized l1 finding did not change hash")
	}
}

func TestBuildSnapshotDerivesEarliestStartAndPreservesReceipt(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 45, 0, 0, time.UTC)
	workload := "nightly"
	input := SnapshotInput{
		Situation: model.Situation{
			ID:                      "s-1",
			InputVersion:            4,
			Lifecycle:               model.LifecycleActive,
			EffectiveStartedAt:      time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
			EffectiveStartedAtBasis: model.SourceTimeBasisReceiptFallback,
			FirstReceivedAt:         time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		},
		Now: now,
		Deliveries: []Delivery{
			{ID: "d-late", IncidentID: "inc-b", StableSymptomID: "zabbix:2", Status: model.DeliveryStatusFiring, SourceStartedAt: utcPtr(2026, 8, 20, 10, 5), StartedAtBasis: model.SourceTimeBasisSourcePayload, ReceivedAt: time.Date(2026, 8, 20, 10, 6, 0, 0, time.UTC)},
			{ID: "d-early", IncidentID: "inc-a", StableSymptomID: "zabbix:1", Status: model.DeliveryStatusFiring, Severity: "high", SourceStartedAt: utcPtr(2026, 8, 20, 9, 30), StartedAtBasis: model.SourceTimeBasisSourceAPI, ReceivedAt: time.Date(2026, 8, 20, 9, 45, 0, 0, time.UTC)},
		},
		DurationClass:   "medium",
		RecurrenceClass: "recurring",
		Judgments:       []model.Judgment{{ID: "judgment:1", Workload: &workload}},
	}

	got, err := BuildSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
	if !got.EffectiveStartedAt.Equal(wantStart) || got.EffectiveStartedAtBasis != model.SourceTimeBasisMixed {
		t.Fatalf("effective start = %s (%s)", got.EffectiveStartedAt, got.EffectiveStartedAtBasis)
	}
	wantReceipt := time.Date(2026, 8, 20, 9, 45, 0, 0, time.UTC)
	if !got.FirstReceivedAt.Equal(wantReceipt) {
		t.Fatalf("first receipt = %s", got.FirstReceivedAt)
	}
	if got.ElapsedSeconds != int64(75*time.Minute/time.Second) || got.MaterialHash == "" {
		t.Fatalf("elapsed/hash = %d %q", got.ElapsedSeconds, got.MaterialHash)
	}
	if len(got.IncidentIDs) != 2 || got.IncidentIDs[0] != "inc-a" || got.Deliveries[0].ID != "d-early" {
		t.Fatalf("snapshot not canonical: incidents=%v deliveries=%+v", got.IncidentIDs, got.Deliveries)
	}
	input.Deliveries[0].ID = "mutated"
	workload = "mutated"
	if got.Deliveries[1].ID != "d-late" {
		t.Fatal("snapshot aliases mutable input")
	}
	if got.Judgments[0].Workload != "nightly" {
		t.Fatal("snapshot aliases nested judgment input")
	}
}

func TestBuildSnapshotRejectsIncompleteOrNonCanonicalIdentity(t *testing.T) {
	_, err := BuildSnapshot(SnapshotInput{Situation: model.Situation{ID: "s-1", InputVersion: 1, Lifecycle: model.LifecycleActive}, Now: time.Now()})
	if err == nil || err.Error() != "situation: snapshot requires canonical effective start and first receipt" {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildSnapshotDerivesBasisAndReceiptFallbackWithoutPriorProjection(t *testing.T) {
	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		delivery  Delivery
		wantStart time.Time
		wantBasis model.SourceTimeBasis
	}{
		{
			name: "source api",
			delivery: Delivery{ID: "d-api", StableSymptomID: "zabbix:1", Status: model.DeliveryStatusFiring,
				SourceStartedAt: utcPtr(2026, 8, 20, 9, 30), StartedAtBasis: model.SourceTimeBasisSourceAPI,
				ReceivedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)},
			wantStart: time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC), wantBasis: model.SourceTimeBasisSourceAPI,
		},
		{
			name: "receipt fallback",
			delivery: Delivery{ID: "d-receipt", StableSymptomID: "webhook:1", Status: model.DeliveryStatusFiring,
				StartedAtBasis: model.SourceTimeBasisReceiptFallback, ReceivedAt: time.Date(2026, 8, 20, 10, 5, 0, 0, time.UTC)},
			wantStart: time.Date(2026, 8, 20, 10, 5, 0, 0, time.UTC), wantBasis: model.SourceTimeBasisReceiptFallback,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildSnapshot(SnapshotInput{Situation: model.Situation{ID: "s-1", InputVersion: 1, Lifecycle: model.LifecycleActive}, Now: now, Deliveries: []Delivery{tc.delivery}})
			if err != nil {
				t.Fatal(err)
			}
			if !got.EffectiveStartedAt.Equal(tc.wantStart) || got.EffectiveStartedAtBasis != tc.wantBasis {
				t.Fatalf("effective start = %s (%s)", got.EffectiveStartedAt, got.EffectiveStartedAtBasis)
			}
		})
	}
}

func sampleSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion:           1,
		SituationID:             "s-1",
		InputVersion:            3,
		Lifecycle:               model.LifecycleActive,
		EffectiveStartedAt:      time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
		EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt:         time.Date(2026, 8, 20, 9, 1, 0, 0, time.UTC),
		ElapsedSeconds:          1812,
		DurationClass:           "medium",
		RecurrenceClass:         "recurring",
		IncidentIDs:             []string{"inc-1"},
		Symptoms:                []Symptom{{ID: "zabbix:18422", Lifecycle: model.DeliveryStatusFiring, Severity: "high", EvidenceRefs: []string{"delivery:d-1"}}},
		Limitations:             []model.Limitation{{Code: "metrics_unavailable", Detail: "prometheus unavailable"}},
	}
}

func baseSnapshotInput() SnapshotInput {
	return SnapshotInput{
		Situation: model.Situation{
			ID: "s-1", InputVersion: 3, Lifecycle: model.LifecycleActive,
			EffectiveStartedAt:      time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
			EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
			FirstReceivedAt:         time.Date(2026, 8, 20, 9, 1, 0, 0, time.UTC),
		},
		Now:           time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		DurationClass: "medium", RecurrenceClass: "recurring",
	}
}

func setStringField(target any, name, value string) {
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
		field.SetString(value)
	}
}

func assertNestedFieldsAbsent(t *testing.T, document map[string]any, name string, forbidden []string) {
	t.Helper()
	value := document[name]
	if list, ok := value.([]any); ok && len(list) > 0 {
		value = list[0]
	}
	nested, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("snapshot %q is not an object: %#v", name, value)
	}
	for _, field := range forbidden {
		if _, ok := nested[field]; ok {
			t.Fatalf("snapshot %q exposed %q: %#v", name, field, nested)
		}
	}
}

func fact(id, kind, value string) observationmodel.Fact {
	return observationmodel.Fact{
		ID: id, SituationID: "s-1", InputVersion: 3, Kind: kind, Subject: "subject",
		Value: json.RawMessage(value), SourceCapability: observationmodel.CapabilityStoreRead,
		ObservedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC), Freshness: observationmodel.FreshnessFresh,
		ResultStatus: observationmodel.ResultStatusConfirmedValue, Digest: "sha256:" + id, EvidenceRefs: []string{"delivery:d-1"}, Material: true,
	}
}

func utcPtr(year int, month time.Month, day, hour, minute int) *time.Time {
	v := time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
	return &v
}
