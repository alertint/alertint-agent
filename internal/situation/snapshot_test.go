// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestMaterialFactHashIgnoresSlackAndExactSecondsWithinClass(t *testing.T) {
	a := sampleSnapshot()
	b := a
	b.SlackChannel = "C999"
	b.ElapsedSeconds = a.ElapsedSeconds + 12
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatal("non-material fields changed hash")
	}
	b.DurationClass = "long"
	if MaterialFactHash(a) == MaterialFactHash(b) {
		t.Fatal("duration class did not change hash")
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

func TestMaterialFactHashOmitsModelProseAndEnvelopeAuditNoise(t *testing.T) {
	a := sampleSnapshot()
	a.L1 = &L1Finding{Status: "complete", Summary: "first prose", RootCauseClass: "resource_saturation", ConfidenceClass: "high", FactDigests: []string{"sha256:fact"}, EvidenceRefs: []string{"fact:cpu"}}
	a.Envelope = &model.EnvelopeEvaluation{ID: "evaluation:a", EnvelopeID: "envelope:1", EnvelopeVersion: 2, SituationID: "s-1", InputVersion: 3, Result: model.EnvelopeEvaluationMatch, MatchedFields: []string{"scope"}, QuietingAuthority: true, CreatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)}
	b := a
	b.L1 = &L1Finding{Status: "complete", Summary: "rewritten prose", RootCauseClass: "resource_saturation", ConfidenceClass: "low", FactDigests: []string{"sha256:fact"}, EvidenceRefs: []string{"fact:cpu"}}
	b.Envelope = &model.EnvelopeEvaluation{ID: "evaluation:b", EnvelopeID: "envelope:1", EnvelopeVersion: 2, SituationID: "another", InputVersion: 99, Result: model.EnvelopeEvaluationMatch, MatchedFields: []string{"scope"}, QuietingAuthority: true, CreatedAt: time.Date(2026, 8, 20, 10, 5, 0, 0, time.UTC)}
	if MaterialFactHash(a) != MaterialFactHash(b) {
		t.Fatal("model prose or envelope audit metadata changed hash")
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
	if got.Judgments[0].Workload == nil || *got.Judgments[0].Workload != "nightly" {
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
		SlackChannel:            "C123",
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
