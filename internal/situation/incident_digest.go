// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"sort"
	"time"
)

// ----------------------------------------------------------------------
// Task 4: canonical per-Incident coverage digests (spec.md "Incident
// coverage digests"). Both digests are pure functions of a scoped delivery
// set plus (for IncidentInputDigest) the Incident's own group key — never
// of TriageState. Schedule phase, attempts, leases, due times, Findings,
// and post-begin connector evidence are all structurally excluded: neither
// function's signature accepts a TriageState at all, so none of that state
// can ever reach either digest.
// ----------------------------------------------------------------------

// Fixed version constants for pre-Triage input dimensions spec.md names
// that Plan 2's SnapshotInput has no live data source for yet:
// acuteInputSchemaVersion, ruleCatalogVersion, and promptProfileVersion are
// versioned identities for machinery (the Acute-input schema, the rule
// catalog, the prompt profile) that exists as build-time configuration, not
// per-Situation input — Plan 2 has exactly one of each, so a fixed version
// is the versioned identity until a later plan makes any of them selectable
// per Situation. Drill parity, by contrast, is live per-Incident input now
// — see incidentDrillParity below — because Delivery.Drill threads the
// alertint_drill marker through from the store layer.
const (
	acuteInputSchemaVersion = 1
	ruleCatalogVersion      = 1
	promptProfileVersion    = 1
)

// membershipDigestSchemaVersion is bumped to 2 (round 2, Task 4 hygiene):
// round 1 changed MembershipDigest's grouping from delivery identity to
// Alert identity (Delivery.AlertID) without bumping this constant. A hash
// produced under the old delivery-level grouping must never be silently
// treated as compatible with one produced under the current Alert-level
// grouping.
const membershipDigestSchemaVersion = 2

type membershipDigestDTO struct {
	SchemaVersion    int      `json:"schema_version"`
	IncidentID       string   `json:"incident_id"`
	MemberIDs        []string `json:"member_ids"`
	FirstDeliveryIDs []string `json:"first_delivery_ids"`
}

// MembershipDigest hashes the sorted immutable member identities belonging
// to incidentID plus their first-delivery identities, per spec.md: "hashes
// the sorted immutable member identities and their first delivery
// identities. It answers which Alerts belong to the Incident." A member
// identity is a distinct Delivery.AlertID, not a distinct Delivery.ID:
// Alertmanager's routine re-send of an unchanged alert appends a new
// alert_deliveries row (a new delivery ID) that still names the same
// underlying Alert, and that re-fire must not manufacture a new member or
// change this digest. MemberIDs is therefore the sorted set of distinct
// AlertIDs scoped to incidentID; FirstDeliveryIDs is, for each of those
// AlertIDs in the same order, the ID of that Alert's chronologically
// earliest delivery (deliveryLess' (source_time,received_at,id) ordering —
// never row/slice/insertion order, and never a lexical comparison of IDs).
func MembershipDigest(incidentID string, deliveries []Delivery) string {
	scoped := make([]Delivery, 0, len(deliveries))
	for _, d := range deliveries {
		if d.IncidentID != incidentID {
			continue
		}
		scoped = append(scoped, d)
	}

	earliestByAlert := make(map[string]Delivery, len(scoped))
	for _, d := range scoped {
		cur, ok := earliestByAlert[d.AlertID]
		if !ok || deliveryLess(d, cur) {
			earliestByAlert[d.AlertID] = d
		}
	}

	alertIDs := make([]string, 0, len(earliestByAlert))
	for alertID := range earliestByAlert {
		alertIDs = append(alertIDs, alertID)
	}
	sort.Strings(alertIDs)

	firstDeliveryIDs := make([]string, len(alertIDs))
	for i, alertID := range alertIDs {
		firstDeliveryIDs[i] = earliestByAlert[alertID].ID
	}

	return canonicalDigest(membershipDigestDTO{
		SchemaVersion:    membershipDigestSchemaVersion,
		IncidentID:       incidentID,
		MemberIDs:        alertIDs,
		FirstDeliveryIDs: firstDeliveryIDs,
	})
}

// incidentDrillParity reports whether scoped (already filtered to one
// Incident's member deliveries) contains at least one Drill-marked
// delivery. In practice every member of one Incident should agree on Drill
// status (a real alert and a Drill alert should never correlate into the
// same Incident), but this reduction does not assume that: any-drill-
// delivery is treated as drill-true for the whole Incident rather than
// requiring unanimous agreement, so a real disagreement (were one ever to
// occur) fails safe toward treating the Incident as a Drill rather than
// silently hiding it. See the Task 4 report for this policy call.
func incidentDrillParity(scoped []Delivery) bool {
	for _, d := range scoped {
		if d.Drill {
			return true
		}
	}
	return false
}

// incidentInputDigestSchemaVersion is bumped to 2 (round 2, Task 4 hygiene):
// round 1 changed incidentDrillParity from a fixed placeholder constant to
// live per-Incident Delivery.Drill data, and transitively depends on
// MembershipDigest's now-bumped schema, without bumping this constant. A
// hash produced under the old drill-parity-constant/delivery-level-
// membership shape must never be silently treated as compatible with one
// produced under the current live-data shape.
const incidentInputDigestSchemaVersion = 2

type incidentInputDeliveryDTO struct {
	ID               string     `json:"id"`
	PayloadDigest    string     `json:"payload_digest"`
	Status           string     `json:"status"`
	SourceStartedAt  *time.Time `json:"source_started_at"`
	StartedAtBasis   string     `json:"started_at_basis"`
	SourceResolvedAt *time.Time `json:"source_resolved_at"`
	ResolvedAtBasis  string     `json:"resolved_at_basis"`
}

type incidentInputDigestDTO struct {
	SchemaVersion           int                        `json:"schema_version"`
	MembershipDigest        string                     `json:"membership_digest"`
	GroupKey                string                     `json:"group_key"`
	DrillParity             bool                       `json:"drill_parity"`
	Deliveries              []incidentInputDeliveryDTO `json:"deliveries"`
	AcuteInputSchemaVersion int                        `json:"acute_input_schema_version"`
	RuleCatalogVersion      int                        `json:"rule_catalog_version"`
	PromptProfileVersion    int                        `json:"prompt_profile_version"`
}

// IncidentInputDigest hashes MembershipDigest(incidentID, deliveries) plus
// the bounded durable pre-Triage input spec.md names: exact group key,
// Drill parity (incidentDrillParity, live per-Incident Delivery.Drill data
// — see its doc comment), and each member delivery's immutable
// identity/payload digest/lifecycle/source times, sorted (source_time,
// received_at, id) so database row order can never change the digest — plus
// the fixed Acute-input schema, rule-catalog, and prompt-profile versions
// (see the constants above for why these are fixed rather than live input).
// It deliberately never reads TriageState: schedule phase, attempts,
// leases, due times, Findings, generated prose, and post-begin connector
// evidence cannot reach this function because it has no parameter that
// could carry them.
func IncidentInputDigest(incidentID, groupKey string, deliveries []Delivery) string {
	membership := MembershipDigest(incidentID, deliveries)

	scoped := make([]Delivery, 0, len(deliveries))
	for _, d := range deliveries {
		if d.IncidentID == incidentID {
			scoped = append(scoped, d)
		}
	}
	sort.Slice(scoped, func(i, j int) bool { return deliveryLess(scoped[i], scoped[j]) })

	dtos := make([]incidentInputDeliveryDTO, 0, len(scoped))
	for _, d := range scoped {
		dtos = append(dtos, incidentInputDeliveryDTO{
			ID:               d.ID,
			PayloadDigest:    d.PayloadDigest,
			Status:           string(d.Status),
			SourceStartedAt:  d.SourceStartedAt,
			StartedAtBasis:   string(d.StartedAtBasis),
			SourceResolvedAt: d.SourceResolvedAt,
			ResolvedAtBasis:  string(d.ResolvedAtBasis),
		})
	}

	return canonicalDigest(incidentInputDigestDTO{
		SchemaVersion:           incidentInputDigestSchemaVersion,
		MembershipDigest:        membership,
		GroupKey:                groupKey,
		DrillParity:             incidentDrillParity(scoped),
		Deliveries:              dtos,
		AcuteInputSchemaVersion: acuteInputSchemaVersion,
		RuleCatalogVersion:      ruleCatalogVersion,
		PromptProfileVersion:    promptProfileVersion,
	})
}

// sourceTimeKey is the primary canonical-order key the spec's "deliveries
// (source_time,received_at,id)" sort names: a delivery's SourceStartedAt
// when known, else the zero time (sorts first — a deterministic ordering
// tiebreak only, never itself part of the hashed content).
func sourceTimeKey(d Delivery) time.Time {
	if d.SourceStartedAt != nil {
		return *d.SourceStartedAt
	}
	return time.Time{}
}

func deliveryLess(a, b Delivery) bool {
	at, bt := sourceTimeKey(a), sourceTimeKey(b)
	if !at.Equal(bt) {
		return at.Before(bt)
	}
	if !a.ReceivedAt.Equal(b.ReceivedAt) {
		return a.ReceivedAt.Before(b.ReceivedAt)
	}
	return a.ID < b.ID
}
