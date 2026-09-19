// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// DeriveExpectedJudgmentCoverage captures typed, stable facts from one
// coherent current Situation read. It intentionally excludes receipt times,
// delivery IDs, payload digests, counters, and clock-derived duration.
func DeriveExpectedJudgmentCoverage(in SnapshotInput) (model.ExpectedJudgmentCoverage, error) {
	if in.Situation.Lifecycle.Terminal() {
		return model.ExpectedJudgmentCoverage{}, errors.New("situation: expected judgment requires an open situation")
	}
	if in.CurrentAssessment == nil {
		return model.ExpectedJudgmentCoverage{}, errors.New("situation: expected judgment requires a current assessment")
	}
	latest := latestDeliveryPerAlert(in.Deliveries)
	definitions := make(map[string]observationDefinition)
	for _, definition := range in.Prepared.SourceDefinitions {
		definitions[sourceDefinitionKey(definition.InstanceID, definition.RuleID)] = observationDefinition{
			available: definition.Available, instanceID: definition.InstanceID, version: definition.Version,
		}
	}
	covered := make([]model.ExpectedJudgmentSymptom, 0, len(latest))
	for _, d := range latest {
		if d.Status != model.DeliveryStatusFiring {
			continue
		}
		labels := make(map[string]string, len(d.Labels))
		for k, v := range d.Labels {
			if k == "severity" || strings.HasPrefix(k, "alertint_") {
				continue
			}
			labels[k] = v
		}
		symptom := model.ExpectedJudgmentSymptom{
			AlertID: d.AlertID, Source: d.Source, EpisodeKey: d.EpisodeKey,
			SourceSignalID: cloneString(d.SourceSignalID), SourceSignalVersion: cloneString(d.SourceSignalVersion),
			SourceInstanceID: cloneString(d.SourceInstanceID), Severity: d.Severity, IdentityLabels: labels,
		}
		if d.Source == "zabbix" && d.SourceInstanceID != nil {
			if definition, ok := definitions[sourceDefinitionKey(*d.SourceInstanceID, d.Labels["zabbix_trigger_id"])]; ok && definition.available {
				symptom.ObservedSourceInstanceID = stringPtr(definition.instanceID)
				symptom.ObservedSourceConfigVersion = stringPtr(definition.version)
			}
		}
		covered = append(covered, symptom)
	}
	if len(covered) == 0 {
		return model.ExpectedJudgmentCoverage{}, errors.New("situation: expected judgment requires at least one firing symptom")
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i].AlertID < covered[j].AlertID })
	refs := []string{}
	if r := in.CurrentAssessment.Assessment.SufficientReason; r != nil {
		refs = append(refs, r.EvidenceRefs...)
		sort.Strings(refs)
	}
	return model.ExpectedJudgmentCoverage{
		Scope: in.Situation.GroupKey, Impact: in.CurrentAssessment.Assessment.Impact,
		Symptoms: covered, EvidenceRefs: refs,
	}, nil
}

type observationDefinition struct {
	available  bool
	instanceID string
	version    string
}

func sourceDefinitionKey(instanceID, ruleID string) string { return instanceID + "\x00" + ruleID }

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func cloneString(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

// EvaluateExpectedJudgment decides current authority from typed facts. The
// ordering is deliberate: critical or independently urgent truth is always
// reported as urgent, even if another material field changed at the same
// time.
func EvaluateExpectedJudgment(j model.SituationJudgment, in SnapshotInput, now time.Time) model.JudgmentApplicability {
	result := func(reason model.JudgmentApplicabilityReason) model.JudgmentApplicability {
		return model.JudgmentApplicability{Applicable: reason == model.JudgmentApplicable, Reason: reason}
	}
	if j.State != model.JudgmentStateExpected {
		return result(model.JudgmentRevoked)
	}
	if !now.Before(j.ValidUntil) {
		return result(model.JudgmentExpired)
	}
	if in.Situation.Lifecycle.Terminal() {
		return result(model.JudgmentSituationTerminal)
	}
	if in.Situation.Attention == model.AttentionUrgent || hasCriticalFiring(in.Deliveries) {
		return result(model.JudgmentUrgent)
	}
	current, err := DeriveExpectedJudgmentCoverage(in)
	if err != nil {
		return result(model.JudgmentEvidenceMissing)
	}
	if current.Scope != j.Coverage.Scope {
		return result(model.JudgmentScopeChanged)
	}
	if current.Impact != j.Coverage.Impact {
		return result(model.JudgmentImpactChanged)
	}
	if len(current.Symptoms) != len(j.Coverage.Symptoms) {
		return result(model.JudgmentSymptomsChanged)
	}
	for i := range current.Symptoms {
		cur, covered := current.Symptoms[i], j.Coverage.Symptoms[i]
		if cur.AlertID != covered.AlertID || !equalLabels(cur.IdentityLabels, covered.IdentityLabels) {
			return result(model.JudgmentSymptomsChanged)
		}
		if cur.Severity != covered.Severity {
			return result(model.JudgmentSeverityChanged)
		}
		if cur.Source != covered.Source || cur.EpisodeKey != covered.EpisodeKey ||
			!equalStringPtr(cur.SourceSignalID, covered.SourceSignalID) ||
			!equalStringPtr(cur.SourceSignalVersion, covered.SourceSignalVersion) ||
			!equalStringPtr(cur.SourceInstanceID, covered.SourceInstanceID) {
			return result(model.JudgmentSourceSignatureChanged)
		}
		if (covered.ObservedSourceInstanceID != nil || covered.ObservedSourceConfigVersion != nil) &&
			(cur.ObservedSourceInstanceID == nil || cur.ObservedSourceConfigVersion == nil) {
			return result(model.JudgmentSourceDefinitionUnavailable)
		}
		if !equalStringPtr(cur.ObservedSourceInstanceID, covered.ObservedSourceInstanceID) ||
			!equalStringPtr(cur.ObservedSourceConfigVersion, covered.ObservedSourceConfigVersion) {
			return result(model.JudgmentSourceSignatureChanged)
		}
	}
	if !equalStrings(current.EvidenceRefs, j.Coverage.EvidenceRefs) {
		return result(model.JudgmentEvidenceMissing)
	}
	return result(model.JudgmentApplicable)
}

func hasCriticalFiring(deliveries []Delivery) bool {
	for _, d := range latestDeliveryPerAlert(deliveries) {
		if d.Status == model.DeliveryStatusFiring && severity.Rank(d.Severity) >= 4 {
			return true
		}
	}
	return false
}

func equalStringPtr(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// applyExpectedJudgment overlays only the current covered human request. It
// never changes lifecycle, Attention, findings, Triage decisions, budgets or
// AlertINT work. Independent urgent assessment always wins.
func applyExpectedJudgment(commit *ControllerCommit, in SnapshotInput, now time.Time) {
	commit.JudgmentCheckedAt = now.UTC()
	if in.Judgment == nil {
		return
	}
	commit.JudgmentRevision = in.Judgment.Revision
	app := in.JudgmentApplicability
	if app.Applicable || app.Reason == "" {
		current := in
		current.Situation.Lifecycle = commit.Lifecycle
		current.Situation.Attention = commit.Attention
		assessment := AuthoritativeAssessment{Assessment: commit.Assessment}
		current.CurrentAssessment = &assessment
		app = EvaluateExpectedJudgment(*in.Judgment, current, now)
	}
	if commit.Attention == model.AttentionUrgent || commit.Assessment.Attention == model.AttentionUrgent {
		app = model.JudgmentApplicability{Reason: model.JudgmentUrgent}
	}
	commit.JudgmentApplicabilityReason = app.Reason
	if !app.Applicable {
		return
	}
	commit.JudgmentApplicable = true
	c := &commit.Assessment.ActionContract
	c.OperatorActionRequired = nil
	if c.AlertINTAction != nil {
		c.NextActor = model.NextActorAlertINT
	} else {
		c.NextActor = model.NextActorNone
	}
	if c.NextUpdateAt == nil || in.Judgment.ValidUntil.Before(*c.NextUpdateAt) {
		deadline := in.Judgment.ValidUntil.UTC()
		c.NextUpdateAt = &deadline
	}
	consumed := commit.ConsumedDueReasons[:0]
	for _, reason := range commit.ConsumedDueReasons {
		if reason != model.DueJudgmentBoundary {
			consumed = append(consumed, reason)
		}
	}
	commit.ConsumedDueReasons = consumed
}
