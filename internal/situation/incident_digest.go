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
//
//   - acuteInputSchemaVersion / ruleCatalogVersion / promptProfileVersion:
//     versioned identities for machinery (the Acute-input schema, the rule
//     catalog, the prompt profile) that exists as build-time configuration,
//     not per-Situation input — Plan 2 has exactly one of each, so a fixed
//     version is the versioned identity until a later plan makes any of
//     them selectable per Situation.
//   - drillParity: situation.Delivery (Task 3's trim of
//     store.AlertDelivery) carries no Drill flag — the alertint_drill
//     marker lives on the mutable Alert/label projection Task 3
//     deliberately excluded as an SQL-facing internal. Every
//     IncidentInputDigest this build computes therefore treats drill
//     parity as uniformly false. This is a genuine, documented data gap: a
//     future task that needs to distinguish drill from real Incident input
//     digests must thread a real per-Incident (or per-Delivery) Drill
//     field through SnapshotInput before this constant can become live
//     input. See the Task 4 report.
const (
	acuteInputSchemaVersion = 1
	ruleCatalogVersion      = 1
	promptProfileVersion    = 1
	drillParity             = false
)

const membershipDigestSchemaVersion = 1

type membershipDigestDTO struct {
	SchemaVersion    int      `json:"schema_version"`
	IncidentID       string   `json:"incident_id"`
	MemberIDs        []string `json:"member_ids"`
	FirstDeliveryIDs []string `json:"first_delivery_ids"`
}

// MembershipDigest hashes the sorted immutable member identities belonging
// to incidentID plus their first-delivery identities, per spec.md: "hashes
// the sorted immutable member identities and their first delivery
// identities. It answers which Alerts belong to the Incident." Plan 2's
// situation.Delivery carries no identity distinguishing "the Alert this
// delivery represents" from "this delivery itself" — no separate Alert ID
// reaches this pure layer (see Symptom's doc comment in snapshot.go for the
// same gap). This reduction therefore treats each Delivery as its own
// member, so MemberIDs and FirstDeliveryIDs are the same sorted Delivery-ID
// list for now; the two fields are kept distinct in the DTO so a future
// task that threads a genuine Alert-vs-delivery distinction into Delivery
// can change FirstDeliveryIDs' derivation without changing this digest's
// shape.
func MembershipDigest(incidentID string, deliveries []Delivery) string {
	ids := make([]string, 0, len(deliveries))
	for _, d := range deliveries {
		if d.IncidentID != incidentID {
			continue
		}
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return canonicalDigest(membershipDigestDTO{
		SchemaVersion:    membershipDigestSchemaVersion,
		IncidentID:       incidentID,
		MemberIDs:        ids,
		FirstDeliveryIDs: append([]string(nil), ids...),
	})
}

const incidentInputDigestSchemaVersion = 1

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
// Drill parity, and each member delivery's immutable identity/payload
// digest/lifecycle/source times, sorted (source_time, received_at, id) so
// database row order can never change the digest — plus the fixed
// Acute-input schema, rule-catalog, and prompt-profile versions (see the
// constants above for why these are fixed rather than live input). It
// deliberately never reads TriageState: schedule phase, attempts, leases,
// due times, Findings, generated prose, and post-begin connector evidence
// cannot reach this function because it has no parameter that could carry
// them.
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
		DrillParity:             drillParity,
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
