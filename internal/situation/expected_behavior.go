// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ExpectedBehaviorSignal is one exact current source observation available
// to ADR-0054's pure reusable-schedule evaluator.
type ExpectedBehaviorSignal struct {
	SourceInstanceID string
	Host             string
	TriggerID        string
	TriggerVersion   string
	Presence         string
	EvidenceRefs     []string
	ObservedAt       time.Time
	ExpiresAt        time.Time
}

// ExpectedBehaviorInput contains only coherent durable facts. It performs no
// I/O and grants no authority itself.
type ExpectedBehaviorInput struct {
	SituationID         string
	SituationVersion    int
	GroupKey            string
	Now                 time.Time
	PrimaryStartedAt    time.Time
	Source              string
	SourceInstanceID    string
	Host                string
	PrimaryTriggerID    string
	PrimaryVersion      string
	HasCriticalFiring   bool
	IndependentlyUrgent bool
	FiringSignals       []ExpectedBehaviorSignal
	Observations        []ExpectedBehaviorSignal
	Heads               []model.ExpectedBehaviorHead
}

// EvaluateExpectedBehaviors evaluates same-scope alternatives in stable
// envelope order. Any match wins; otherwise temporary uncertainty wins over
// violation, and only all-proven violations produce violated.
func EvaluateExpectedBehaviors(in ExpectedBehaviorInput) model.ExpectedBehaviorEvaluation {
	heads := append([]model.ExpectedBehaviorHead(nil), in.Heads...)
	sort.Slice(heads, func(i, j int) bool { return heads[i].EnvelopeID < heads[j].EnvelopeID })
	evaluation := model.ExpectedBehaviorEvaluation{
		SituationID: in.SituationID, SituationVersion: in.SituationVersion,
		Disposition: model.ExpectedBehaviorDispositionNotApplicable, Candidates: []model.ExpectedBehaviorCandidate{}, EvaluatedAt: in.Now.UTC(),
	}
	for _, head := range heads {
		candidate := evaluateExpectedBehaviorCandidate(in, head)
		evaluation.Candidates = append(evaluation.Candidates, candidate)
	}
	for _, candidate := range evaluation.Candidates {
		if candidate.Status == model.ExpectedBehaviorMatched {
			evaluation.Disposition, evaluation.Reason = model.ExpectedBehaviorDispositionMatched, candidate.Reason
			evaluation.ChosenEnvelopeID, evaluation.ChosenVersion, evaluation.Occurrence = candidate.EnvelopeID, candidate.Version, candidate.Occurrence
			evaluation.BasisHash = expectedBehaviorBasisHash(evaluation)
			return evaluation
		}
	}
	for _, candidate := range evaluation.Candidates {
		if candidate.Status == model.ExpectedBehaviorAuthorityUnavailable {
			evaluation.Disposition, evaluation.Reason = model.ExpectedBehaviorDispositionAuthorityUnavailable, candidate.Reason
			evaluation.BasisHash = expectedBehaviorBasisHash(evaluation)
			return evaluation
		}
	}
	for _, candidate := range evaluation.Candidates {
		if candidate.Status == model.ExpectedBehaviorViolated {
			evaluation.Disposition, evaluation.Reason = model.ExpectedBehaviorDispositionViolated, candidate.Reason
			evaluation.BasisHash = expectedBehaviorBasisHash(evaluation)
			return evaluation
		}
	}
	if len(evaluation.Candidates) > 0 {
		evaluation.Reason = evaluation.Candidates[0].Reason
	}
	evaluation.BasisHash = expectedBehaviorBasisHash(evaluation)
	return evaluation
}

func evaluateExpectedBehaviorCandidate(in ExpectedBehaviorInput, head model.ExpectedBehaviorHead) model.ExpectedBehaviorCandidate { //nolint:gocyclo // ordered safety gates intentionally remain visible in one pure evaluator.
	c := model.ExpectedBehaviorCandidate{EnvelopeID: head.EnvelopeID, Version: head.Version, Status: model.ExpectedBehaviorNotCandidate}
	set := func(status model.ExpectedBehaviorCandidateStatus, reason model.ExpectedBehaviorReason) model.ExpectedBehaviorCandidate {
		c.Status, c.Reason = status, reason
		return c
	}
	if head.State == model.ExpectedBehaviorStateRevoked {
		return set(model.ExpectedBehaviorNotCandidate, model.ExpectedBehaviorReasonRevoked)
	}
	if head.InvalidatedAt != nil || head.Policy == nil {
		return set(model.ExpectedBehaviorNotCandidate, model.ExpectedBehaviorReasonInvalidated)
	}
	scope := head.Policy.Scope
	if scope.GroupKey != in.GroupKey || scope.Source != in.Source || scope.SourceInstanceID != in.SourceInstanceID || scope.Host != in.Host || scope.PrimaryTriggerID != in.PrimaryTriggerID {
		return set(model.ExpectedBehaviorNotCandidate, model.ExpectedBehaviorReasonScopeMismatch)
	}
	if in.HasCriticalFiring || in.IndependentlyUrgent {
		return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonUrgent)
	}
	if in.PrimaryVersion == "" {
		return set(model.ExpectedBehaviorAuthorityUnavailable, model.ExpectedBehaviorReasonDefinitionUnavailable)
	}
	if scope.PrimaryTriggerVersion != in.PrimaryVersion {
		return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonPrimaryDefinitionChanged)
	}
	occurrence, err := ResolveExpectedBehaviorOccurrence(head.Policy.Conditions.Schedule, head.Policy.Conditions.MaxDurationMinutes, in.PrimaryStartedAt)
	if err != nil {
		return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonStartOutsideTolerance)
	}
	c.Occurrence = &occurrence
	if !in.Now.Before(occurrence.Boundary) {
		if occurrence.Boundary.Equal(occurrence.End) {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonOutsideSchedule)
		}
		return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonDurationExceeded)
	}

	observed := make(map[string]ExpectedBehaviorSignal, len(in.Observations))
	for _, signal := range in.Observations {
		observed[expectedBehaviorSignalKey(signal.SourceInstanceID, signal.Host, signal.TriggerID)] = signal
	}
	allowed := map[string]bool{}
	for _, binding := range append(append(append([]model.ExpectedBehaviorBinding{}, head.Policy.Conditions.RequiredCompanions...), head.Policy.Conditions.AllowedCompanions...), head.Policy.Conditions.ForbiddenSignals...) {
		allowed[expectedBehaviorBindingSignalKey(binding)] = true
	}
	for _, binding := range append(append([]model.ExpectedBehaviorBinding{}, head.Policy.Conditions.RequiredCompanions...), head.Policy.Conditions.ForbiddenSignals...) {
		key := expectedBehaviorSignalKey(binding.SourceInstanceID, binding.Host, binding.TriggerID)
		observation, ok := observed[key]
		if !ok || observation.Presence == "unknown" || !observation.ExpiresAt.After(in.Now) {
			return set(model.ExpectedBehaviorAuthorityUnavailable, model.ExpectedBehaviorReasonObservationUnavailable)
		}
		c.EvidenceRefs = append(c.EvidenceRefs, observation.EvidenceRefs...)
		if observation.TriggerVersion != binding.TriggerVersion {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonBindingDefinitionChanged)
		}
	}
	for _, binding := range head.Policy.Conditions.AllowedCompanions {
		key := expectedBehaviorBindingSignalKey(binding)
		observation, ok := observed[key]
		if !ok || observation.Presence == "unknown" || !observation.ExpiresAt.After(in.Now) {
			if expectedBehaviorSignalFiring(in.FiringSignals, key) {
				return set(model.ExpectedBehaviorAuthorityUnavailable, model.ExpectedBehaviorReasonObservationUnavailable)
			}
			continue
		}
		c.EvidenceRefs = append(c.EvidenceRefs, observation.EvidenceRefs...)
		if observation.TriggerVersion != binding.TriggerVersion {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonBindingDefinitionChanged)
		}
	}
	for _, binding := range head.Policy.Conditions.RequiredCompanions {
		if observed[expectedBehaviorBindingSignalKey(binding)].Presence != "present" {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonRequiredMissing)
		}
	}
	for _, binding := range head.Policy.Conditions.ForbiddenSignals {
		if observed[expectedBehaviorBindingSignalKey(binding)].Presence == "present" {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonForbiddenPresent)
		}
	}
	for _, signal := range in.FiringSignals {
		key := expectedBehaviorSignalKey(signal.SourceInstanceID, signal.Host, signal.TriggerID)
		if signal.TriggerID == in.PrimaryTriggerID && signal.SourceInstanceID == in.SourceInstanceID && signal.Host == in.Host {
			continue
		}
		if !allowed[key] {
			return set(model.ExpectedBehaviorViolated, model.ExpectedBehaviorReasonUnexpectedSymptom)
		}
	}
	sort.Strings(c.EvidenceRefs)
	c.EvidenceRefs = compactExpectedBehaviorStrings(c.EvidenceRefs)
	return set(model.ExpectedBehaviorMatched, model.ExpectedBehaviorReasonMatched)
}

func expectedBehaviorSignalFiring(signals []ExpectedBehaviorSignal, key string) bool {
	for _, signal := range signals {
		if expectedBehaviorSignalKey(signal.SourceInstanceID, signal.Host, signal.TriggerID) == key {
			return true
		}
	}
	return false
}

func expectedBehaviorSignalKey(instance, host, trigger string) string {
	return instance + "\x00" + host + "\x00" + trigger
}
func expectedBehaviorBindingSignalKey(binding model.ExpectedBehaviorBinding) string {
	return expectedBehaviorSignalKey(binding.SourceInstanceID, binding.Host, binding.TriggerID)
}

func expectedBehaviorBasisHash(evaluation model.ExpectedBehaviorEvaluation) string {
	snapshot := evaluation
	snapshot.ID, snapshot.BasisHash, snapshot.EvaluatedAt = "", "", time.Time{}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func compactExpectedBehaviorStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// ApplyExpectedBehaviorAuthority overlays only the covered human request and
// bounds the next check at the frozen occurrence boundary.
func ApplyExpectedBehaviorAuthority(commit *ControllerCommit, evaluation *model.ExpectedBehaviorEvaluation) {
	if evaluation == nil || evaluation.Disposition != model.ExpectedBehaviorDispositionMatched || evaluation.Occurrence == nil || commit.Lifecycle.Terminal() || commit.Attention == model.AttentionUrgent || commit.Assessment.Attention == model.AttentionUrgent {
		return
	}
	c := &commit.Assessment.ActionContract
	c.OperatorActionRequired = nil
	if c.AlertINTAction != nil {
		c.NextActor = model.NextActorAlertINT
	} else {
		c.NextActor = model.NextActorNone
	}
	if c.NextUpdateAt == nil || evaluation.Occurrence.Boundary.Before(*c.NextUpdateAt) {
		boundary := evaluation.Occurrence.Boundary.UTC()
		c.NextUpdateAt = &boundary
	}
}

// RefreshExpectedBehaviorEvaluationForCommit applies facts learned by the
// controller after the coherent input load and rehashes the final payload.
func RefreshExpectedBehaviorEvaluationForCommit(evaluation *model.ExpectedBehaviorEvaluation, urgent bool, now time.Time) {
	if evaluation == nil {
		return
	}
	evaluation.EvaluatedAt = now.UTC()
	if urgent {
		evaluation.Disposition, evaluation.Reason = model.ExpectedBehaviorDispositionViolated, model.ExpectedBehaviorReasonUrgent
		evaluation.ChosenEnvelopeID, evaluation.ChosenVersion, evaluation.Occurrence = "", 0, nil
		for i := range evaluation.Candidates {
			if evaluation.Candidates[i].Status != model.ExpectedBehaviorNotCandidate {
				evaluation.Candidates[i].Status = model.ExpectedBehaviorViolated
				evaluation.Candidates[i].Reason = model.ExpectedBehaviorReasonUrgent
			}
		}
	} else if evaluation.Disposition == model.ExpectedBehaviorDispositionMatched && evaluation.Occurrence != nil && !now.Before(evaluation.Occurrence.Boundary) {
		evaluation.Disposition = model.ExpectedBehaviorDispositionViolated
		if evaluation.Occurrence.Boundary.Equal(evaluation.Occurrence.End) {
			evaluation.Reason = model.ExpectedBehaviorReasonOutsideSchedule
		} else {
			evaluation.Reason = model.ExpectedBehaviorReasonDurationExceeded
		}
		evaluation.ChosenEnvelopeID, evaluation.ChosenVersion = "", 0
	}
	evaluation.BasisHash = expectedBehaviorBasisHash(*evaluation)
}
