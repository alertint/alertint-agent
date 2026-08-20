// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// Run is the bounded execution record. It contains plans and reduced result
// metadata, but never a raw connector response.
type Run struct {
	ID            string                        `json:"id"`
	ProposedPlan  observationmodel.Plan         `json:"proposed_plan"`
	ValidatedPlan observationmodel.Plan         `json:"validated_plan"`
	Capability    observationmodel.Capability   `json:"capability"`
	Status        observationmodel.ResultStatus `json:"status"`
	ObservedAt    time.Time                     `json:"observed_at"`
	Freshness     observationmodel.Freshness    `json:"freshness"`
	Truncated     bool                          `json:"truncated"`
	Digest        string                        `json:"digest"`
	ErrorClass    string                        `json:"error_class,omitempty"`
	Cost          Cost                          `json:"cost"`
}

// Runner enforces per-input call and concurrency limits around the catalog's
// per-capability bounds.
type Runner struct {
	catalog     *Catalog
	maxCalls    int
	concurrency chan struct{}
	clock       func() time.Time
}

// NewRunner constructs a bounded runner. Non-positive limits are normalized to
// one so construction can never produce an unbounded executor.
func NewRunner(catalog *Catalog, maxCalls, concurrency int) *Runner {
	if maxCalls <= 0 {
		maxCalls = 1
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	return &Runner{catalog: catalog, maxCalls: maxCalls, concurrency: make(chan struct{}, concurrency), clock: time.Now}
}

// Execute validates the complete plan set before any source call. Operational
// absence/failure is represented in each Run's closed status; only invalid
// input prevents execution and returns an error.
func (r *Runner) Execute(ctx context.Context, plans []observationmodel.Plan, allowed Scope) ([]observationmodel.Fact, []Run, error) {
	if r == nil || r.catalog == nil {
		return nil, nil, errors.New("observation: runner requires a catalog")
	}
	for i, plan := range plans {
		if err := r.catalog.Validate(plan, allowed); err != nil {
			return nil, nil, fmt.Errorf("observation: validate plan %d: %w", i, err)
		}
	}
	runs := make([]Run, len(plans))
	factsByPlan := make([][]observationmodel.Fact, len(plans))
	var wg sync.WaitGroup
	for index, plan := range plans {
		if index >= r.maxCalls {
			runs[index] = r.withheldRun(plan)
			continue
		}
		wg.Add(1)
		go func(index int, plan observationmodel.Plan) {
			defer wg.Done()
			select {
			case r.concurrency <- struct{}{}:
				defer func() { <-r.concurrency }()
			case <-ctx.Done():
				runs[index] = r.failedRun(plan, "cancelled")
				return
			}
			factsByPlan[index], runs[index] = r.executeOne(ctx, plan)
		}(index, plan)
	}
	wg.Wait()
	var facts []observationmodel.Fact
	for _, batch := range factsByPlan {
		facts = append(facts, batch...)
	}
	return facts, runs, nil
}

func (r *Runner) executeOne(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, Run) {
	capability, _ := r.catalog.capability(plan.Capability)
	startedAt := r.clock().UTC()
	run := Run{ID: uuid.NewString(), ProposedPlan: plan, ValidatedPlan: plan, Capability: plan.Capability,
		ObservedAt: startedAt, Freshness: observationmodel.FreshnessUnknown}
	callCtx, cancel := context.WithTimeout(ctx, capability.Timeout)
	defer cancel()
	facts, cost, err := capability.Executor.Execute(callCtx, plan)
	run.ObservedAt = r.clock().UTC()
	run.Cost = cost
	if err != nil {
		run.Status, run.ErrorClass = classifyError(err)
		if run.Status == observationmodel.ResultStatusStale {
			run.Freshness = observationmodel.FreshnessStale
		} else {
			run.Freshness = observationmodel.FreshnessUnknown
		}
		run.Truncated = run.Status == observationmodel.ResultStatusTruncated
		run.Digest = digestFacts(nil)
		return nil, run
	}
	if cost.SourceCalls < 0 || cost.Tokens < 0 || cost.SourceCalls > capability.MaxCost.SourceCalls ||
		(plan.Budget > 0 && cost.SourceCalls > plan.Budget) || (capability.MaxCost.Tokens > 0 && cost.Tokens > capability.MaxCost.Tokens) {
		run.Status = observationmodel.ResultStatusFailed
		run.ErrorClass = "cost_bound_exceeded"
		run.Digest = digestFacts(nil)
		return nil, run
	}
	validated := make([]observationmodel.Fact, 0, len(facts))
	used := 0
	for _, fact := range facts {
		if err := validateFact(fact, plan); err != nil {
			run.Status = observationmodel.ResultStatusFailed
			run.ErrorClass = "invalid_reduced_fact"
			run.Digest = digestFacts(nil)
			return nil, run
		}
		encoded, err := json.Marshal(fact)
		if err != nil {
			run.Status = observationmodel.ResultStatusFailed
			run.ErrorClass = "invalid_reduced_fact"
			run.Digest = digestFacts(nil)
			return nil, run
		}
		if used+len(encoded) > capability.MaxResultBytes {
			run.Truncated = true
			continue
		}
		used += len(encoded)
		validated = append(validated, fact)
	}
	run.Status, run.Freshness = classifyFacts(validated)
	if run.Truncated {
		run.Status = observationmodel.ResultStatusTruncated
	}
	run.Digest = digestFacts(validated)
	return validated, run
}

func (r *Runner) withheldRun(plan observationmodel.Plan) Run {
	now := r.clock().UTC()
	return Run{ID: uuid.NewString(), ProposedPlan: plan, ValidatedPlan: plan, Capability: plan.Capability,
		Status: observationmodel.ResultStatusWithheldByBudget, ObservedAt: now,
		Freshness: observationmodel.FreshnessUnknown, Digest: digestFacts(nil), ErrorClass: "input_call_budget"}
}

func (r *Runner) failedRun(plan observationmodel.Plan, class string) Run {
	now := r.clock().UTC()
	return Run{ID: uuid.NewString(), ProposedPlan: plan, ValidatedPlan: plan, Capability: plan.Capability,
		Status: observationmodel.ResultStatusFailed, ObservedAt: now,
		Freshness: observationmodel.FreshnessUnknown, Digest: digestFacts(nil), ErrorClass: class}
}

func classifyError(err error) (observationmodel.ResultStatus, string) {
	switch {
	case errors.Is(err, ErrUnavailable):
		return observationmodel.ResultStatusUnavailable, "unavailable"
	case errors.Is(err, ErrUnconfirmedEmpty):
		return observationmodel.ResultStatusUnconfirmedEmpty, "unconfirmed_empty"
	case errors.Is(err, ErrStale):
		return observationmodel.ResultStatusStale, "stale"
	case errors.Is(err, ErrTruncated):
		return observationmodel.ResultStatusTruncated, "truncated"
	case errors.Is(err, context.DeadlineExceeded):
		return observationmodel.ResultStatusFailed, "timeout"
	case errors.Is(err, context.Canceled):
		return observationmodel.ResultStatusFailed, "cancelled"
	default:
		return observationmodel.ResultStatusFailed, "connector_error"
	}
}

func classifyFacts(facts []observationmodel.Fact) (observationmodel.ResultStatus, observationmodel.Freshness) {
	if len(facts) == 0 {
		return observationmodel.ResultStatusConfirmedEmpty, observationmodel.FreshnessFresh
	}
	status := observationmodel.ResultStatusConfirmedValue
	freshness := observationmodel.FreshnessFresh
	for _, fact := range facts {
		if fact.Freshness == observationmodel.FreshnessStale {
			freshness = observationmodel.FreshnessStale
		} else if fact.Freshness == observationmodel.FreshnessUnknown && freshness == observationmodel.FreshnessFresh {
			freshness = observationmodel.FreshnessUnknown
		}
		switch fact.ResultStatus {
		case observationmodel.ResultStatusTruncated:
			status = observationmodel.ResultStatusTruncated
		case observationmodel.ResultStatusStale:
			if status != observationmodel.ResultStatusTruncated {
				status = observationmodel.ResultStatusStale
			}
		case observationmodel.ResultStatusUnconfirmedEmpty, observationmodel.ResultStatusUnavailable,
			observationmodel.ResultStatusFailed, observationmodel.ResultStatusVocabularyUnresolved:
			if status == observationmodel.ResultStatusConfirmedValue {
				status = fact.ResultStatus
			}
		}
	}
	return status, freshness
}

func validateFact(fact observationmodel.Fact, plan observationmodel.Plan) error {
	if strings.TrimSpace(fact.ID) == "" || strings.TrimSpace(fact.SituationID) == "" || fact.InputVersion < 1 ||
		strings.TrimSpace(fact.Kind) == "" || strings.TrimSpace(fact.Subject) == "" || strings.TrimSpace(fact.Digest) == "" {
		return errors.New("observation: reduced fact identity is incomplete")
	}
	if fact.SourceCapability != plan.Capability || fact.ObservedAt.IsZero() || fact.ObservedAt.Location() != time.UTC ||
		!validFreshness(fact.Freshness) || !validResultStatus(fact.ResultStatus) {
		return errors.New("observation: reduced fact classification is invalid")
	}
	if fact.ResultStatus == observationmodel.ResultStatusConfirmedValue && (len(fact.Value) == 0 || !json.Valid(fact.Value)) {
		return errors.New("observation: confirmed fact value must be valid json")
	}
	if len(fact.Value) > 0 && !json.Valid(fact.Value) {
		return errors.New("observation: fact value must be valid json")
	}
	if len(fact.EvidenceRefs) > 128 {
		return errors.New("observation: fact evidence references exceed bound")
	}
	if situationID := plan.Scope["situation_id"]; situationID != "" && fact.SituationID != situationID {
		return errors.New("observation: fact situation is outside plan scope")
	}
	return nil
}

func digestFacts(facts []observationmodel.Fact) string {
	encoded, _ := json.Marshal(facts)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
