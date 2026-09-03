// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Shared fixtures used by snapshot_test.go, facts_test.go,
// incident_digest_test.go, and reasons_test.go — all in package situation.
// ----------------------------------------------------------------------

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("mustTime(%q): %v", s, err)
	}
	return parsed
}

// deliveryFor defaults AlertID to id — each delivery represents its own
// distinct Alert unless a test explicitly overrides AlertID (e.g. to model a
// re-fire: a second delivery naming the same AlertID as an earlier one).
func deliveryFor(id, incidentID, payloadDigest string, receivedAt time.Time) Delivery {
	return Delivery{
		ID:            id,
		IncidentID:    incidentID,
		AlertID:       id,
		Status:        model.DeliveryStatusFiring,
		PayloadDigest: payloadDigest,
		ReceivedAt:    receivedAt,
	}
}

func baseIncident(t *testing.T, id string) IncidentState {
	t.Helper()
	start := mustTime(t, "2026-09-01T12:00:00Z")
	return IncidentState{
		ID:           id,
		GroupKey:     "group-1",
		Status:       "ready",
		FirstAlertAt: start,
		LastAlertAt:  start,
		ReadyAt:      start,
		AlertCount:   1,
	}
}

func baseSnapshotInput(t *testing.T) SnapshotInput {
	t.Helper()
	start := mustTime(t, "2026-09-01T12:00:00Z")
	return SnapshotInput{
		Situation: model.Situation{
			ID:                 "situation-1",
			GroupKey:           "group-1",
			Lifecycle:          model.LifecycleActive,
			Attention:          model.AttentionObserve,
			InputVersion:       1,
			EffectiveStartedAt: start,
		},
		Deliveries: []Delivery{deliveryFor("delivery-1", "incident-1", "payload-digest-1", start)},
		Incidents:  []IncidentState{baseIncident(t, "incident-1")},
		Now:        start.Add(5 * time.Minute),
	}
}

func findFact(t *testing.T, facts []model.Fact, kind, subject string) model.Fact {
	t.Helper()
	for _, f := range facts {
		if f.Kind == kind && f.Subject == subject {
			return f
		}
	}
	t.Fatalf("no fact found kind=%s subject=%s", kind, subject)
	return model.Fact{}
}

func fiveShortPriorSituations(groupKey string, base time.Time) []CompletedSituation {
	out := make([]CompletedSituation, 0, 5)
	for i := 0; i < 5; i++ {
		start := base.Add(-time.Duration(i+1) * 24 * time.Hour)
		out = append(out, CompletedSituation{
			ID:                 "prior-" + string(rune('a'+i)),
			GroupKey:           groupKey,
			EffectiveStartedAt: start,
			TerminalAt:         start.Add(5 * time.Minute),
			TerminalReason:     model.TerminalReasonObservationDeadline,
		})
	}
	return out
}

// ----------------------------------------------------------------------
// DurationClass boundary tests.
// ----------------------------------------------------------------------

func TestDurationClassBoundaries(t *testing.T) {
	cases := []struct {
		elapsed time.Duration
		want    string
	}{
		{0, DurationClassSubminute},
		{59 * time.Second, DurationClassSubminute},
		{time.Minute, DurationClassShort},
		{14*time.Minute + 59*time.Second, DurationClassShort},
		{15 * time.Minute, DurationClassMedium},
		{59*time.Minute + 59*time.Second, DurationClassMedium},
		{time.Hour, DurationClassLong},
		{25 * time.Hour, DurationClassLong},
	}
	for _, c := range cases {
		if got := DurationClass(c.elapsed); got != c.want {
			t.Errorf("DurationClass(%s) = %q, want %q", c.elapsed, got, c.want)
		}
	}
}

func TestDurationClassNegativeElapsedClampsToSubminute(t *testing.T) {
	if got := DurationClass(-time.Hour); got != DurationClassSubminute {
		t.Fatalf("DurationClass(-1h) = %q, want %q", got, DurationClassSubminute)
	}
}

// ----------------------------------------------------------------------
// BuildSnapshot / Snapshot tests.
// ----------------------------------------------------------------------

func TestSnapshotPopulatesAllFields(t *testing.T) {
	in := baseSnapshotInput(t)
	snap := BuildSnapshot(in)

	if snap.SituationID != in.Situation.ID {
		t.Errorf("SituationID = %q, want %q", snap.SituationID, in.Situation.ID)
	}
	if snap.InputVersion != in.Situation.InputVersion {
		t.Errorf("InputVersion = %d, want %d", snap.InputVersion, in.Situation.InputVersion)
	}
	if snap.Lifecycle != in.Situation.Lifecycle {
		t.Errorf("Lifecycle = %q, want %q", snap.Lifecycle, in.Situation.Lifecycle)
	}
	if snap.DurationClass == "" {
		t.Error("DurationClass is empty")
	}
	if len(snap.Facts) == 0 {
		t.Error("Facts is empty")
	}
	if len(snap.Symptoms) == 0 {
		t.Error("Symptoms is empty")
	}
	if len(snap.Incidents) != len(in.Incidents) {
		t.Errorf("Incidents count = %d, want %d", len(snap.Incidents), len(in.Incidents))
	}
	if snap.MaterialFactHash == "" {
		t.Error("MaterialFactHash is empty")
	}
	if snap.AssessmentBasisHash == "" {
		t.Error("AssessmentBasisHash is empty")
	}
}

func TestSnapshotIncidentsSortedByID(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Incidents = []IncidentState{baseIncident(t, "incident-b"), baseIncident(t, "incident-a")}

	snap := BuildSnapshot(in)
	if len(snap.Incidents) != 2 || snap.Incidents[0].ID != "incident-a" || snap.Incidents[1].ID != "incident-b" {
		t.Fatalf("incidents not sorted by ID: %+v", snap.Incidents)
	}
}

func TestSnapshotElapsedSecondsIsHeaderMetadataOnly(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Now = in.Situation.EffectiveStartedAt.Add(20 * time.Minute)
	snap1 := BuildSnapshot(in)

	in2 := in
	in2.Now = in.Situation.EffectiveStartedAt.Add(45 * time.Minute)
	snap2 := BuildSnapshot(in2)

	if snap1.ElapsedSeconds == snap2.ElapsedSeconds {
		t.Fatal("test setup invalid: expected different elapsed seconds")
	}
	if snap1.DurationClass != snap2.DurationClass {
		t.Fatalf("test setup invalid: expected same duration class, got %s vs %s", snap1.DurationClass, snap2.DurationClass)
	}
	if snap1.MaterialFactHash != snap2.MaterialFactHash {
		t.Fatal("elapsed seconds change within a duration class changed material fact hash")
	}
	if snap1.AssessmentBasisHash != snap2.AssessmentBasisHash {
		t.Fatal("elapsed seconds change within a duration class changed assessment basis hash")
	}
}

func TestSnapshotDeterministicUnderShuffledDeliveryOrder(t *testing.T) {
	in := baseSnapshotInput(t)
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", in.Situation.EffectiveStartedAt)
	d2 := deliveryFor("delivery-2", "incident-1", "pd-2", in.Situation.EffectiveStartedAt.Add(time.Minute))
	in.Deliveries = []Delivery{d1, d2}
	snap1 := BuildSnapshot(in)

	shuffled := in
	shuffled.Deliveries = []Delivery{d2, d1}
	snap2 := BuildSnapshot(shuffled)

	if snap1.MaterialFactHash != snap2.MaterialFactHash {
		t.Fatal("shuffled delivery order changed material fact hash")
	}
	if snap1.AssessmentBasisHash != snap2.AssessmentBasisHash {
		t.Fatal("shuffled delivery order changed assessment basis hash")
	}
}

func TestSnapshotDeterministicUnderShuffledIncidentOrder(t *testing.T) {
	in := baseSnapshotInput(t)
	in.Deliveries = []Delivery{
		deliveryFor("delivery-1", "incident-1", "pd-1", in.Situation.EffectiveStartedAt),
		deliveryFor("delivery-2", "incident-2", "pd-2", in.Situation.EffectiveStartedAt),
	}
	inc1, inc2 := baseIncident(t, "incident-1"), baseIncident(t, "incident-2")
	in.Incidents = []IncidentState{inc1, inc2}
	snap1 := BuildSnapshot(in)

	shuffled := in
	shuffled.Incidents = []IncidentState{inc2, inc1}
	snap2 := BuildSnapshot(shuffled)

	if snap1.MaterialFactHash != snap2.MaterialFactHash {
		t.Fatal("shuffled incident order changed material fact hash")
	}
	if len(snap1.Incidents) != len(snap2.Incidents) || snap1.Incidents[0].ID != snap2.Incidents[0].ID {
		t.Fatal("shuffled incident order changed canonical Incidents ordering")
	}
}

func TestSnapshotSymptomsGroupByIncidentAndTakeLatestStatus(t *testing.T) {
	first := mustTime(t, "2026-09-01T12:00:00Z")
	last := mustTime(t, "2026-09-01T12:05:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", first)
	d1.Status = model.DeliveryStatusFiring
	d2 := deliveryFor("delivery-2", "incident-1", "pd-2", last)
	d2.Status = model.DeliveryStatusResolved

	// Deliberately shuffled input order — deriveSymptoms must not depend on
	// it.
	symptoms := deriveSymptoms([]Delivery{d2, d1})
	if len(symptoms) != 1 {
		t.Fatalf("want 1 symptom, got %d", len(symptoms))
	}
	s := symptoms[0]
	if s.Key != "incident-1" {
		t.Fatalf("Key = %q, want %q", s.Key, "incident-1")
	}
	if s.Status != model.DeliveryStatusResolved {
		t.Fatalf("Status = %q, want latest delivery's status %q", s.Status, model.DeliveryStatusResolved)
	}
	if !s.FirstObservedAt.Equal(first) {
		t.Fatalf("FirstObservedAt = %s, want earliest delivery's ReceivedAt %s", s.FirstObservedAt, first)
	}
}
