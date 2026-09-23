// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"time"
)

// FactResultStatus is the closed result state of one collected material
// fact: the store attempted to derive it and got exactly one of these
// outcomes. It holds no free-form provider error text.
type FactResultStatus string

const (
	FactConfirmedValue FactResultStatus = "confirmed_value"
	FactConfirmedEmpty FactResultStatus = "confirmed_empty"
	FactUnavailable    FactResultStatus = "unavailable"
	FactFailed         FactResultStatus = "failed"
	FactStale          FactResultStatus = "stale"
)

// Validate reports an error unless s is one of the closed FactResultStatus
// values.
func (s FactResultStatus) Validate() error {
	return validateEnum("fact_result_status", s,
		FactConfirmedValue, FactConfirmedEmpty, FactUnavailable, FactFailed, FactStale)
}

// Fact is one immutable, store-derived material fact recorded against a
// Situation input version. Facts are the only production evidence source in
// this slice (store- and delivery-derived); external evidence preparation
// and semantic profiles belong to a later plan.
type Fact struct {
	ID           string           `json:"id"`
	SituationID  string           `json:"situation_id"`
	Kind         string           `json:"kind"`
	Subject      string           `json:"subject"`
	Digest       string           `json:"digest"`
	InputVersion int              `json:"input_version"`
	Value        json.RawMessage  `json:"value"`
	ResultStatus FactResultStatus `json:"result_status"`
	EvidenceRefs []string         `json:"evidence_refs"`
	Material     bool             `json:"material"`
	ObservedAt   time.Time        `json:"observed_at"`
}

// MarshalJSON canonicalizes EvidenceRefs to [] before marshaling: a
// nil-constructed Fact (e.g. json.RawMessage decoded from a persisted
// record, or a zero-value struct literal) must never serialize
// evidence_refs as JSON null.
func (f Fact) MarshalJSON() ([]byte, error) {
	type factAlias Fact
	a := factAlias(f)
	a.EvidenceRefs = canonicalizeSlice(a.EvidenceRefs)
	return json.Marshal(a)
}

// ReasonCandidate is one deterministic Sufficient-reason candidate offered
// in a controller Snapshot. The model may select and explain only an
// eligible candidate already present here — it cannot invent a reason.
type ReasonCandidate struct {
	ID                 string   `json:"id"`
	Code               string   `json:"code"`
	Summary            string   `json:"summary"`
	CatalogVersion     int      `json:"catalog_version"`
	PredicateVersion   int      `json:"predicate_version"`
	EvidenceRefs       []string `json:"evidence_refs"`
	DeterministicFloor bool     `json:"deterministic_floor"`
}

// MarshalJSON canonicalizes EvidenceRefs to [] before marshaling: a
// nil-constructed ReasonCandidate must never serialize evidence_refs as
// JSON null.
func (r ReasonCandidate) MarshalJSON() ([]byte, error) {
	type reasonCandidateAlias ReasonCandidate
	a := reasonCandidateAlias(r)
	a.EvidenceRefs = canonicalizeSlice(a.EvidenceRefs)
	return json.Marshal(a)
}
