// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// largeSituationDeliveries is one long-lived Situation's member deliveries:
// incidents Incidents with perIncident deliveries each, interleaved the way
// the store returns them.
func largeSituationDeliveries(incidents, perIncident int) []Delivery {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	out := make([]Delivery, 0, incidents*perIncident)
	for n := 0; n < perIncident; n++ {
		for i := 0; i < incidents; i++ {
			id := fmt.Sprintf("delivery-%03d-%02d", i, n)
			out = append(out, deliveryFor(id, fmt.Sprintf("incident-%03d", i), "pd-"+id, base.Add(time.Duration(n*incidents+i)*time.Second)))
		}
	}
	return out
}

// TestIncidentDigestsAllocateForTheIncidentNotTheSituation guards the cost
// step 5 of the #99 lab found: each digest call allocated room for every
// delivery of the Situation to pick one Incident's members, once per
// Incident and call site, so a Situation with 255 Incidents and 2,827
// deliveries allocated gigabytes per reconcile. One call must allocate in
// proportion to the Incident's own members.
func TestIncidentDigestsAllocateForTheIncidentNotTheSituation(t *testing.T) {
	deliveries := largeSituationDeliveries(1000, 10) // 10,000 deliveries, 10 per Incident
	const calls = 50
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < calls; i++ {
		_ = IncidentInputDigest("incident-007", "group-1", deliveries)
	}
	runtime.ReadMemStats(&after)
	perCall := (after.TotalAlloc - before.TotalAlloc) / calls
	if perCall > 64<<10 {
		t.Fatalf("IncidentInputDigest allocated %d bytes per call for a 10-member Incident among %d deliveries; want under 64 KiB",
			perCall, len(deliveries))
	}
}

func BenchmarkIncidentDigestsLargeSituation(b *testing.B) {
	// Step 4's main Situation: 255 Incidents, 2,827 deliveries (~11 each).
	deliveries := largeSituationDeliveries(255, 11)
	b.ReportAllocs()
	for b.Loop() {
		for i := 0; i < 255; i++ {
			incidentID := fmt.Sprintf("incident-%03d", i)
			_ = MembershipDigest(incidentID, deliveries)
			_ = IncidentInputDigest(incidentID, "group-1", deliveries)
		}
	}
}
