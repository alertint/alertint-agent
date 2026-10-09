// SPDX-License-Identifier: FSL-1.1-ALv2

// Package ntfy provides a Situation event policy and an independent HTTP push sink.
package ntfy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Events is the version-one public event catalogue, in stable rendering order.
var Events = []string{"first_notification", "priority_escalated", "operator_action_required", "recovered", "closed_uncertain", "investigation_started", "investigation_completed", "coverage_degraded", "coverage_restored", "recovery_pending", "recovery_refired", "members_changed", "operator_updated"}

func Defaults() []string { return slices.Clone(Events[:5]) }

// Config stores names, never secret values. Nil Events means defaults; empty means none.
type Config struct {
	Enabled  bool     `yaml:"enabled"`
	BaseURL  string   `yaml:"base_url"`
	Topic    string   `yaml:"topic"`
	TokenEnv string   `yaml:"token_env"`
	Events   []string `yaml:"events"`
}

func (c Config) SelectedEvents() []string {
	if c.Events == nil {
		return Defaults()
	}
	return slices.Clone(c.Events)
}

func (c Config) Destination() string { return strings.TrimRight(c.BaseURL, "/") + "/" + c.Topic }

var topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (c Config) Validate() error {
	for _, event := range c.SelectedEvents() {
		if !slices.Contains(Events, event) {
			return fmt.Errorf("notify.ntfy.events: unknown event %q", event)
		}
	}
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("notify.ntfy.base_url: requires an http(s) URL without credentials, query or fragment")
	}
	if !topicPattern.MatchString(c.Topic) {
		return fmt.Errorf("notify.ntfy.topic: use 1–64 letters, digits, underscores or hyphens")
	}
	return nil
}

// Select combines material categories. published means a prior warranted publication
// exists in committed history, independent of Slack or ntfy delivery success.
func Select(t model.Transition, prior *model.Transition, published bool, enabled []string) []string {
	if t.Reason == model.ReasonOperatorArtifactRecorded {
		if slices.Contains(enabled, "operator_updated") {
			return []string{"operator_updated"}
		}
		return nil
	}
	matched := map[string]bool{}
	if !published && situation.PublicationAuthority(t) && !t.Lifecycle.Terminal() {
		matched["first_notification"] = true
	}
	switch t.Reason { //nolint:exhaustive // Only these reasons identify notification edges.
	case model.ReasonInvestigationConcluded:
		matched["investigation_completed"] = true
	case model.ReasonRecoveryObserved:
		matched["recovery_pending"] = true
	case model.ReasonRecoveryFailed:
		matched["recovery_refired"] = true
	case model.ReasonRecovered:
		matched["recovered"] = true
	case model.ReasonClosedUnknown:
		matched["closed_uncertain"] = true
	case model.ReasonOperatorArtifactRecorded:
		matched["operator_updated"] = true
	}
	if prior != nil && !t.Lifecycle.Terminal() && situation.DeriveInterruptionPriority(*prior).Less(situation.DeriveInterruptionPriority(t)) {
		matched["priority_escalated"] = true
	}
	if t.ActionContract.OperatorActionRequired != nil && (prior == nil || prior.ActionContract.OperatorActionRequired == nil || *prior.ActionContract.OperatorActionRequired != *t.ActionContract.OperatorActionRequired) {
		matched["operator_action_required"] = true
	}
	selectProgress(t, prior, matched)
	current, previous := limitationCodes(t), []string(nil)
	if prior != nil {
		previous = limitationCodes(*prior)
	}
	for _, code := range current {
		if !slices.Contains(previous, code) {
			matched["coverage_degraded"] = true
		}
	}
	for _, code := range previous {
		if !slices.Contains(current, code) {
			matched["coverage_restored"] = true
		}
	}
	var selected []string
	for _, event := range Events {
		if matched[event] && slices.Contains(enabled, event) {
			selected = append(selected, event)
		}
	}
	return selected
}

func limitationCodes(t model.Transition) []string {
	var codes []string
	if t.Projection.Assessment != nil {
		codes = append(codes, t.Projection.Assessment.LimitationCodes...)
	}
	if t.Projection.Briefing != nil && t.Projection.Briefing.BlockedReason != "" {
		codes = append(codes, t.Projection.Briefing.BlockedReason)
	}
	return codes
}

func selectProgress(t model.Transition, prior *model.Transition, matched map[string]bool) {
	if d := t.Projection.OperatorDelta; d != nil {
		if d.AttentionIncreased && prior != nil {
			matched["priority_escalated"] = true
		}
		if d.HumanRequestChanged && t.ActionContract.OperatorActionRequired != nil {
			matched["operator_action_required"] = true
		}
		selectCandidates(d.Candidates, matched)
	}
	if t.Projection.Briefing != nil && t.Projection.Briefing.Work.ExecutionStarted &&
		(prior == nil || prior.Projection.Briefing == nil || !prior.Projection.Briefing.Work.ExecutionStarted) {
		matched["investigation_started"] = true
	}
}

func selectCandidates(candidates []model.MaterialCandidate, matched map[string]bool) {
	for _, candidate := range candidates {
		switch candidate.Kind { //nolint:exhaustive // Other candidates are covered by contract/lifecycle comparisons.
		case model.CandidateFirstExecutionAssurance:
			matched["investigation_started"] = true
		case model.CandidateUsefulFinding, model.CandidateInconclusiveCompletion:
			matched["investigation_completed"] = true
		case model.CandidateMembersChanged:
			matched["members_changed"] = true
		case model.CandidateAbilityChanged:
			if candidate.Limitation != nil {
				if candidate.Limitation.Cleared {
					matched["coverage_restored"] = true
				} else {
					matched["coverage_degraded"] = true
				}
			}
		}
	}
}
