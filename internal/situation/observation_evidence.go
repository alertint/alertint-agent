// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"sort"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// ObservationCheck gives even factless results readable query context. Window
// clocks belong in the prompt, not the material hash: refreshing an unchanged
// result must not count as a new finding merely because the query window moved.
type ObservationCheck struct {
	Key        string                        `json:"key"`
	RunID      string                        `json:"run_id"`
	Capability observationmodel.Capability   `json:"capability"`
	Scope      *observationmodel.Scope       `json:"scope"`
	Parameters json.RawMessage               `json:"parameters,omitempty"`
	Start      time.Time                     `json:"start"`
	End        time.Time                     `json:"end"`
	Status     observationmodel.ResultStatus `json:"status"`
}

// PreparedEvidenceSize measures the entire normalized prompt evidence, including
// query metadata and synthesized result markers. The store uses this in addition
// to its Run bound so stripping facts cannot leave oversized metadata behind.
func PreparedEvidenceSize(prepared PreparedState) (int, error) {
	encoded, err := json.Marshal(struct { //nolint:musttag // matches the existing transport-neutral Fact prompt projection
		Checks []ObservationCheck      `json:"observation_checks,omitempty"`
		Facts  []observationmodel.Fact `json:"observations,omitempty"`
	}{preparedObservationChecks(prepared), preparedObservationFacts(prepared)})
	return len(encoded), err
}

func preparedObservationChecks(prepared PreparedState) []ObservationCheck {
	var checks []ObservationCheck
	for _, run := range prepared.Runs {
		if run.Scope == nil {
			continue
		}
		checks = append(checks, ObservationCheck{Key: run.ScopeKey, RunID: run.ID,
			Capability: run.Capability, Scope: run.Scope, Parameters: run.Parameters,
			Start: run.Coverage.Start, End: run.Coverage.End, Status: run.Status})
	}
	return checks
}

// preparedObservationFacts keeps capability outcome and coverage material even
// when a check produced no facts. Collection clocks and run IDs are not meaning.
func preparedObservationFacts(prepared PreparedState) []observationmodel.Fact {
	var facts []observationmodel.Fact
	for _, run := range prepared.Runs {
		facts = append(facts, run.Facts...)
		if run.ScopeKey == "" {
			continue
		} // legacy, local-only fixtures
		codes := append([]string(nil), run.LimitationCodes...)
		sort.Strings(codes)
		value, err := json.Marshal(struct {
			Capability  observationmodel.Capability `json:"capability"`
			Complete    bool                        `json:"complete"`
			Returned    int                         `json:"returned"`
			Omitted     int                         `json:"omitted"`
			Limitations []string                    `json:"limitations"`
		}{run.Capability, run.Coverage.Complete, run.Coverage.Returned, run.Coverage.Omitted, codes})
		if err != nil {
			panic(err)
		} // closed scalar-only shape, cannot fail
		freshness := observationmodel.FreshnessFresh
		if run.Status == observationmodel.ResultStale {
			freshness = observationmodel.FreshnessStale
		}
		facts = append(facts, observationmodel.Fact{ID: "observation-status:" + run.ScopeKey,
			Kind: "capability_result", Subject: run.ScopeKey, SchemaVersion: observationmodel.FactSchemaVersion,
			Value: value, ResultStatus: run.Status, Freshness: freshness, Material: true,
			ObservedAt: run.ObservedAt, ExpiresAt: run.ExpiresAt})
	}
	return facts
}

func observationExists(snap Snapshot, id string) bool {
	for _, f := range snap.Observations {
		if f.ID == id {
			return true
		}
	}
	return false
}
