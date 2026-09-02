// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestIncidentDigestMembershipSortedAndDeterministic(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-b", "incident-1", "pd-1", base)
	d2 := deliveryFor("delivery-a", "incident-1", "pd-2", base.Add(time.Minute))

	ordered := MembershipDigest("incident-1", []Delivery{d1, d2})
	shuffled := MembershipDigest("incident-1", []Delivery{d2, d1})
	if ordered != shuffled {
		t.Fatal("membership digest depends on caller-supplied delivery order")
	}
}

func TestIncidentDigestMembershipChangesOnMemberSet(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	// deliveryFor defaults AlertID to each delivery's own ID, so d1 and d2
	// represent two genuinely distinct Alerts here, not a re-fire of one.
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	d2 := deliveryFor("delivery-2", "incident-1", "pd-2", base)

	withOne := MembershipDigest("incident-1", []Delivery{d1})
	withTwo := MembershipDigest("incident-1", []Delivery{d1, d2})
	if withOne == withTwo {
		t.Fatal("adding a member delivery for a genuinely distinct Alert did not change membership digest")
	}
}

// TestIncidentDigestMembershipCollapsesRefireOfSameAlert is Finding #2's
// core regression: Alertmanager's routine re-send of an unchanged alert
// appends a new alert_deliveries row (a new Delivery.ID) that still names
// the same underlying Alert (the same AlertID). That re-fire must collapse
// into the existing member, not manufacture a new one and churn
// MembershipDigest (and therefore MaterialFactHash) on every routine
// re-fire.
func TestIncidentDigestMembershipCollapsesRefireOfSameAlert(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	original := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	refire := deliveryFor("delivery-2", "incident-1", "pd-2", base.Add(time.Hour))
	refire.AlertID = original.AlertID // same underlying Alert re-firing

	solo := MembershipDigest("incident-1", []Delivery{original})
	withRefire := MembershipDigest("incident-1", []Delivery{original, refire})
	if solo != withRefire {
		t.Fatal("a later re-fire of the same Alert (new delivery, same AlertID) changed the membership digest")
	}
}

// TestIncidentDigestMembershipFirstDeliveryPicksChronologicalNotLexicalOrInsertionOrder
// pins FirstDeliveryIDs' derivation: it must pick the chronologically
// earliest delivery (deliveryLess' ordering) for a given Alert, never the
// lexically-first delivery ID or the first one appended to the caller's
// slice. "delivery-z" is deliberately lexically last and appended second,
// yet is the chronologically earliest — so a solo-delivery digest built
// from exactly "delivery-z" only agrees with the two-delivery digest if
// MembershipDigest correctly picked "delivery-z" as the first delivery.
func TestIncidentDigestMembershipFirstDeliveryPicksChronologicalNotLexicalOrInsertionOrder(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")

	early := deliveryFor("delivery-z", "incident-1", "pd-1", base)
	later := deliveryFor("delivery-a", "incident-1", "pd-2", base.Add(time.Hour))
	later.AlertID = early.AlertID // same Alert; "delivery-a" is a later re-fire

	withEarlyFirst := MembershipDigest("incident-1", []Delivery{later, early}) // "delivery-a" appended first
	solo := MembershipDigest("incident-1", []Delivery{early})

	if withEarlyFirst != solo {
		t.Fatal("membership digest's first delivery must be the chronologically-earliest delivery, not the lexically-first or first-appended one")
	}
}

func TestIncidentDigestMembershipScopedToIncident(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	other := deliveryFor("delivery-2", "incident-2", "pd-2", base)

	scoped := MembershipDigest("incident-1", []Delivery{d1})
	withOther := MembershipDigest("incident-1", []Delivery{d1, other})
	if scoped != withOther {
		t.Fatal("membership digest for incident-1 must ignore incident-2's deliveries")
	}
}

func TestIncidentDigestInputIncludesMembershipDigest(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	d2 := deliveryFor("delivery-2", "incident-1", "pd-2", base)

	a := IncidentInputDigest("incident-1", "group-1", []Delivery{d1})
	b := IncidentInputDigest("incident-1", "group-1", []Delivery{d1, d2})
	if a == b {
		t.Fatal("membership change did not change incident input digest")
	}
}

func TestIncidentDigestInputReflectsGroupKey(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)

	a := IncidentInputDigest("incident-1", "group-1", []Delivery{d1})
	b := IncidentInputDigest("incident-1", "group-2", []Delivery{d1})
	if a == b {
		t.Fatal("group key change did not change incident input digest")
	}
}

func TestIncidentDigestInputReflectsPayloadStatusAndSourceTimes(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	baseline := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	a := IncidentInputDigest("incident-1", "group-1", []Delivery{baseline})

	changedPayload := baseline
	changedPayload.PayloadDigest = "pd-2"
	b := IncidentInputDigest("incident-1", "group-1", []Delivery{changedPayload})
	if a == b {
		t.Fatal("payload digest change did not change incident input digest")
	}

	changedStatus := baseline
	changedStatus.Status = model.DeliveryStatusResolved
	c := IncidentInputDigest("incident-1", "group-1", []Delivery{changedStatus})
	if a == c {
		t.Fatal("delivery status (lifecycle) change did not change incident input digest")
	}

	started := base
	changedSource := baseline
	changedSource.SourceStartedAt = &started
	changedSource.StartedAtBasis = model.SourceTimeBasisSourcePayload
	d := IncidentInputDigest("incident-1", "group-1", []Delivery{changedSource})
	if a == d {
		t.Fatal("source time/basis change did not change incident input digest")
	}
}

// TestIncidentDigestInputReflectsDrillMarker proves the drillParity
// placeholder's retirement: IncidentInputDigest now reads live per-Incident
// Drill data off Delivery.Drill (incidentDrillParity) instead of a
// hardcoded false, so a Drill-marked delivery changes the digest.
func TestIncidentDigestInputReflectsDrillMarker(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	baseline := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	a := IncidentInputDigest("incident-1", "group-1", []Delivery{baseline})

	drill := baseline
	drill.Drill = true
	b := IncidentInputDigest("incident-1", "group-1", []Delivery{drill})
	if a == b {
		t.Fatal("Drill marker change did not change incident input digest")
	}
}

// TestIncidentDigestInputAnyDrillDeliveryMakesIncidentDrillParityTrue pins
// incidentDrillParity's any-drill-delivery policy: when an Incident's member
// deliveries disagree on Drill status (which should not happen in practice —
// see incidentDrillParity's doc comment), at least one Drill delivery is
// enough to treat the whole Incident as a Drill.
func TestIncidentDigestInputAnyDrillDeliveryMakesIncidentDrillParityTrue(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	real := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	real.Drill = false
	drill := deliveryFor("delivery-2", "incident-1", "pd-2", base)
	drill.Drill = true

	allReal := IncidentInputDigest("incident-1", "group-1", []Delivery{real})
	mixed := IncidentInputDigest("incident-1", "group-1", []Delivery{real, drill})
	if allReal == mixed {
		t.Fatal("adding a Drill-marked delivery did not change incident input digest")
	}
}

func TestIncidentDigestInputOrderIndependent(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)
	d2 := deliveryFor("delivery-2", "incident-1", "pd-2", base.Add(time.Minute))

	ordered := IncidentInputDigest("incident-1", "group-1", []Delivery{d1, d2})
	shuffled := IncidentInputDigest("incident-1", "group-1", []Delivery{d2, d1})
	if ordered != shuffled {
		t.Fatal("incident input digest depends on caller-supplied delivery order")
	}
}

// TestIncidentDigestsIgnoreScheduleAttemptLeaseAndFindingState documents a
// structural guarantee rather than exercising a runtime code path:
// MembershipDigest and IncidentInputDigest take no TriageState parameter at
// all, so schedule phase, attempts, leases, due times, and Findings can
// never reach either function — there is no way to construct an input that
// would let them influence the digest, because neither signature accepts
// one. Both calls below use identical scoped inputs and must always agree.
func TestIncidentDigestsIgnoreScheduleAttemptLeaseAndFindingState(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	d1 := deliveryFor("delivery-1", "incident-1", "pd-1", base)

	m1 := MembershipDigest("incident-1", []Delivery{d1})
	i1 := IncidentInputDigest("incident-1", "group-1", []Delivery{d1})
	m2 := MembershipDigest("incident-1", []Delivery{d1})
	i2 := IncidentInputDigest("incident-1", "group-1", []Delivery{d1})

	if m1 != m2 || i1 != i2 {
		t.Fatal("digest functions must be pure and deterministic for identical scoped input")
	}
}

func TestIncidentDigestInputDeliveryOrderKeyIsSourceTimeThenReceivedThenID(t *testing.T) {
	base := mustTime(t, "2026-09-01T12:00:00Z")
	earlier := base.Add(-time.Hour)
	later := base.Add(time.Hour)

	// A missing SourceStartedAt sorts as the zero time.Time, which precedes
	// any real timestamp — so a delivery with no source_started_at sorts
	// before one with a real (even chronologically earlier) one. This is
	// purely a deterministic ordering tiebreak (never part of the hashed
	// content — see TestIncidentDigestInputOrderIndependent), so any total
	// order would do; this test pins the specific one deliveryLess uses.
	withoutSourceTime := deliveryFor("delivery-z", "incident-1", "pd-1", base)
	withEarlierSourceTime := deliveryFor("delivery-a", "incident-1", "pd-2", base)
	withEarlierSourceTime.SourceStartedAt = &earlier
	if !deliveryLess(withoutSourceTime, withEarlierSourceTime) {
		t.Fatal("a delivery with no source_started_at (zero time) must sort before one with a real source_started_at")
	}

	// Two deliveries with the same source_started_at fall back to
	// received_at, then to id.
	sameSourceA := deliveryFor("delivery-a", "incident-1", "pd-1", earlier)
	sameSourceA.SourceStartedAt = &base
	sameSourceB := deliveryFor("delivery-b", "incident-1", "pd-2", later)
	sameSourceB.SourceStartedAt = &base
	if !deliveryLess(sameSourceA, sameSourceB) {
		t.Fatal("equal source_started_at must fall back to received_at ordering")
	}

	if deliveryLess(withoutSourceTime, withoutSourceTime) {
		t.Fatal("deliveryLess must be irreflexive")
	}
}
