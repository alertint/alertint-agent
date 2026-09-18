// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"sort"
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// ----------------------------------------------------------------------
// Plan 4 review round 1 (F2, F16): the bounded current-observation
// projection the Assessment actually reasons from — prepared connector
// facts plus one capability result per run — and the limitation catalog
// derived from it.
// ----------------------------------------------------------------------

// CapabilityResult is one prepared run's outcome as the Assessment sees it:
// which capability observed which subject, with what result status and
// coverage, under which limitations. It is the "result catalog" spec.md
// A5/A10 require alongside the normalized facts — per-cycle, per-run
// capability state, never a blanket unsupported statement.
type CapabilityResult struct {
	RunID           string    `json:"run_id"`
	Capability      string    `json:"capability"`
	Subject         string    `json:"subject"`
	Status          string    `json:"status"`
	Freshness       string    `json:"freshness"`
	CoverageStart   time.Time `json:"coverage_start"`
	CoverageEnd     time.Time `json:"coverage_end"`
	Complete        bool      `json:"complete"`
	Returned        int       `json:"returned"`
	Omitted         int       `json:"omitted"`
	LimitationCodes []string  `json:"limitation_codes,omitempty"`
	Reused          bool      `json:"reused,omitempty"`
}

// LimitationInvestigationDeferred is the dynamic limitation code a cycle
// carries when fairness/budget deferred at least one due read.
const LimitationInvestigationDeferred = "investigation_deferred"

// ProjectObservations reduces prepared (a durably reloaded cycle) into the
// Snapshot's observation facts and capability results. Facts of a run
// whose detail expired are already withheld by the store; facts whose own
// ExpiresAt has passed at now read as stale. Output is deterministically
// ordered (facts by ID, results by run ID). prepared.CycleID == "" yields
// nil, nil — every pre-Plan-4 fixture is unchanged.
func ProjectObservations(prepared PreparedState, planCapabilities map[string]observationmodel.Plan, now time.Time) ([]observationmodel.Fact, []CapabilityResult) {
	if prepared.CycleID == "" {
		return nil, nil
	}
	var facts []observationmodel.Fact
	results := make([]CapabilityResult, 0, len(prepared.Runs))
	for _, run := range prepared.Runs {
		capability, subject := "", ""
		if p, ok := planCapabilities[run.PlanID]; ok {
			capability, subject = string(p.Capability), p.Scope.SubjectID
		}
		freshness := string(observationmodel.FreshnessFresh)
		if !run.ExpiresAt.IsZero() && !now.Before(run.ExpiresAt) {
			freshness = string(observationmodel.FreshnessStale)
		}
		if run.Status == observationmodel.ResultStale {
			freshness = string(observationmodel.FreshnessStale)
		}
		results = append(results, CapabilityResult{
			RunID: run.ID, Capability: capability, Subject: subject, Status: string(run.Status), Freshness: freshness,
			CoverageStart: run.Coverage.Start, CoverageEnd: run.Coverage.End, Complete: run.Coverage.Complete,
			Returned: run.Coverage.Returned, Omitted: run.Coverage.Omitted,
			LimitationCodes: append([]string(nil), run.LimitationCodes...),
			Reused:          run.ReusedFromRunID != nil,
		})
		for _, f := range run.Facts {
			if f.Kind == "source_lifecycle" {
				continue // lifecycle evidence is the controller's, never the model's
			}
			if !f.ExpiresAt.IsZero() && !now.Before(f.ExpiresAt) {
				f.Freshness = observationmodel.FreshnessStale
			}
			facts = append(facts, f)
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	sort.Slice(results, func(i, j int) bool { return results[i].RunID < results[j].RunID })
	return facts, results
}

// DynamicLimitationCodes derives the per-cycle limitation codes a model
// may cite for this Snapshot: "<capability>_<status>" for every capability
// result that is not a confirmed value, plus investigation_deferred when
// the cycle deferred due reads. Sorted, deduplicated.
func DynamicLimitationCodes(results []CapabilityResult, deferred []string) []string {
	seen := make(map[string]bool)
	for _, r := range results {
		if r.Status == string(observationmodel.ResultConfirmedValue) || r.Capability == "" {
			continue
		}
		seen[r.Capability+"_"+r.Status] = true
	}
	if len(deferred) > 0 {
		seen[LimitationInvestigationDeferred] = true
	}
	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

// dynamicLimitationCode reports whether code is a well-formed
// "<capability>_<status>" pair over the closed capability and result
// vocabularies — the shape DynamicLimitationCodes produces.
func dynamicLimitationCode(code string) bool {
	if code == LimitationInvestigationDeferred {
		return true
	}
	for _, c := range observationmodel.Capabilities {
		prefix := string(c) + "_"
		if strings.HasPrefix(code, prefix) && observationmodel.ValidResultStatus(observationmodel.ResultStatus(strings.TrimPrefix(code, prefix))) {
			return true
		}
	}
	return false
}

func observationFactExists(facts []observationmodel.Fact, id string) bool {
	for _, f := range facts {
		if f.ID == id {
			return true
		}
	}
	return false
}
