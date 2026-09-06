// SPDX-License-Identifier: FSL-1.1-ALv2

// Package observation implements deterministic, bounded evidence
// preparation: turning a Situation's coherent member/profile state into a
// frozen set of canonical plans (planner.go), executing them through
// registered capability executors under durable physical-request budgets
// (runner.go), and the investigative-fairness allocation math shared
// between planning and execution (this file). No LLM ever selects a query
// or capability directly here — see spec.md "Deterministic planning and
// connector contracts".
package observation

import (
	"sort"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// optionalRequestCreditCost mirrors internal/store's
// investigationCreditCostPerRequest (spec.md "each optional physical
// reservation spends three units"). Duplicated here as the planner's own
// admission-affordability check; internal/store enforces the same debit
// durably at reservation time, so a planner miscalculation here can only
// ever under-admit work, never over-spend budget the store would refuse.
const optionalRequestCreditCost = 3

// Candidate is one member/capability read the planner is deciding whether
// and how to admit into this cycle — the planner's own working unit before
// it becomes a frozen Plan.
type Candidate struct {
	Subject       string
	Capability    model.Capability
	Scope         model.Scope
	Phase         model.Phase
	Window        [2]time.Time
	Limit         int
	MaxRequests   int
	Purpose       string
	TimeSensitive bool
	// Deadline is the earliest checkpoint making this candidate
	// time-sensitive (a member observation deadline or active recovery-grace
	// checkpoint); zero for a routine or optional candidate.
	Deadline time.Time
	// LastServedAt orders same-tier candidates by least-recently-served
	// (spec.md: "least-recently-served subject and canonical scope").
	LastServedAt time.Time
	// Optional marks a candidate profiles/investigation suggest beyond
	// routine lifecycle cadence — the class the one-third credit rule
	// protects a turn for.
	Optional bool
}

// Allocation is BuildPlans' own decision record — the same shape persisted
// into CycleDraft.Allocation (model.PhaseAllocation) plus which candidates
// were actually admitted, for planner tests to assert against directly
// without re-deriving indices into the returned Plan slice.
type Allocation struct {
	model.PhaseAllocation

	Admitted []Candidate
	Deferred []Candidate
}

// allocateFairly implements spec.md's investigative-fairness rule (grill
// decision G1): time-sensitive lifecycle candidates are admitted first,
// without limit other than the total cycle cap; while active, a bounded
// share is reserved for the least-recently-served OPTIONAL candidate whose
// full MaxRequests the combination of available credit and remaining
// cycle capacity can cover; remaining capacity fills with the
// least-recently-served ROUTINE lifecycle candidates. A single leftover
// slot can never fragment a multi-request optional plan — it either fits
// entirely or is deferred, retaining its earned credit for a later round.
func allocateFairly(cycleCap int, credit int, timeSensitive, optional, routine []Candidate) Allocation {
	sortByDeadlineThenLastServed(timeSensitive)
	sortByLastServed(optional)
	sortByLastServed(routine)

	var admitted, deferred []Candidate
	used := 0

	for _, c := range timeSensitive {
		if used+c.MaxRequests > cycleCap {
			deferred = append(deferred, c)
			continue
		}
		admitted = append(admitted, c)
		used += c.MaxRequests
	}
	timeSensitiveUsed := used

	var optionalPlanID string
	optionalUsed := 0
	remainingCapacity := cycleCap - used
	for i, c := range optional {
		affordableCredit := credit / optionalRequestCreditCost
		if c.MaxRequests <= remainingCapacity && c.MaxRequests <= affordableCredit {
			admitted = append(admitted, c)
			optionalUsed = c.MaxRequests
			optionalPlanID = candidateKey(c)
			used += c.MaxRequests
			deferred = append(deferred, optional[i+1:]...)
			break
		}
		deferred = append(deferred, c)
	}

	remainingCapacity = cycleCap - used
	routineUsed := 0
	for _, c := range routine {
		if remainingCapacity <= 0 {
			deferred = append(deferred, c)
			continue
		}
		take := c.MaxRequests
		if take > remainingCapacity {
			take = remainingCapacity
		}
		admitted = append(admitted, c)
		routineUsed += take
		remainingCapacity -= take
		used += take
	}

	return Allocation{
		PhaseAllocation: model.PhaseAllocation{
			TimeSensitiveRequests:    timeSensitiveUsed,
			RoutineLifecycleRequests: routineUsed,
			OptionalRequests:         optionalUsed,
			OptionalPlanID:           optionalPlanID,
		},
		Admitted: admitted,
		Deferred: deferred,
	}
}

// candidateKey is a stable, cheap identity for correlating a Candidate to
// its later-assigned canonical Plan ID before that ID exists (BeginPreparation
// assigns real Plan IDs only once a cycle is durably created) — used only to
// mark which admitted candidate is the protected optional one so the
// planner's own caller can find it again in the returned Plan slice by
// matching (Subject, Capability).
func candidateKey(c Candidate) string {
	return string(c.Capability) + ":" + c.Subject
}

func sortByDeadlineThenLastServed(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if !cs[i].Deadline.Equal(cs[j].Deadline) {
			return cs[i].Deadline.Before(cs[j].Deadline)
		}
		if !cs[i].LastServedAt.Equal(cs[j].LastServedAt) {
			return cs[i].LastServedAt.Before(cs[j].LastServedAt)
		}
		return candidateKey(cs[i]) < candidateKey(cs[j])
	})
}

func sortByLastServed(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if !cs[i].LastServedAt.Equal(cs[j].LastServedAt) {
			return cs[i].LastServedAt.Before(cs[j].LastServedAt)
		}
		return candidateKey(cs[i]) < candidateKey(cs[j])
	})
}

// AccrualDue reports whether a fresh investigative-fairness credit round is
// owed: a genuinely new cycle (not a retry/reload) at least refreshInterval
// after the last accrual (or one that has never accrued). Callers pass this
// to internal/store's AccrueInvestigationCredit gate check up front so a
// retry, input churn, or schedule-only cycle never mints credit — mirroring
// (never replacing) that store-side durable check.
func AccrualDue(lastAccruedAt *time.Time, now time.Time, refreshInterval time.Duration) bool {
	if lastAccruedAt == nil {
		return true
	}
	return !now.Before(lastAccruedAt.Add(refreshInterval))
}
