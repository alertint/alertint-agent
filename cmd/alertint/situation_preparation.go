// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/logs/loki"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/observation/connectors"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// ----------------------------------------------------------------------
// Plan 4 Task 9: bounded evidence preparation runtime.
//
// productionPreparer is the concrete situation.EvidencePreparer adapter:
// the ONLY place in this process that maps a situation.Claim/SnapshotInput
// onto the narrow observation.Fence Task 2's store methods require
// (spec.md: "Map situation.Claim to the narrow observation Fence only in
// this adapter"). It never trusts its own Prepare() return value as
// evidence — see internal/situation/preparation.go's own doc comment — and
// never blocks a Situation's own lifecycle on a connector failure: only a
// durable STORE failure (BeginPreparation, RunPhase's own commit, refresh
// admission) is returned as a hard error; a per-plan connector failure is
// already durable evidence limitation by construction (Runner.RunPhase's
// own contract).
// ----------------------------------------------------------------------

// productionPreparer implements situation.EvidencePreparer over the real
// store, the real observation.Runner (wired with every configured
// capability's real executor), and the real planner.
type productionPreparer struct {
	st           *store.Store
	runner       *observation.Runner
	capabilities []observation.CapabilityDescriptor
	configDigest string
	prepCfg      config.SituationPreparationConfig
	// selectorKeys is the Selector allowlist every constructed metric/log/
	// change selector may assert: the built-in six keys, configured extra
	// selector labels, and the correlator's group-key labels.
	selectorKeys []string
	logger       *slog.Logger
	// auditor is optional — nil disables audit emission, matching
	// internal/situation.Controller's own auditSink convention (there it is
	// an abstract interface guarded by a nil check; here it is the concrete
	// *audit.Auditor cmd/alertint already always constructs, so a nil value
	// only ever occurs in a test that deliberately omits it).
	auditor                *audit.Auditor
	alertmanagerInstanceID string
	prometheusProducerID   string
	alertmanagerRules      map[string]config.AlertmanagerRuleMappingConfig
}

// Prepare runs one bounded phase: coherently derive this Situation's
// expected member subjects, load current profile guidance and the
// per-subject/capability refresh cursor, build this phase's canonical plan
// set, freeze it into a durable cycle (retry-safe — BeginPreparation
// returns the SAME frozen draft on a later attempt for the same input),
// execute it, and record the fresh reads' cadence admission. Returns the
// zero PreparedState on every non-error path — its caller (Controller.
// reconcile) discards it and reloads durable truth instead (preparation.go
// EvidencePreparer's own doc comment), so there is nothing this receipt
// needs to carry.
//
// The preparation wall (situations.preparation.max_wall_seconds) is shared
// by BOTH phases of one Reconcile cycle (spec.md: "The preparation wall
// includes all lifecycle and assessment reads in that attempt"), never
// reset per phase: it is computed from req.Now, the SAME wall-clock anchor
// Task 6's own reconcile() captures once and passes to both its lifecycle-
// and assessment-phase Prepare calls, so a phase that already consumed part
// of the shared budget correctly leaves less of it for the other.
func (p *productionPreparer) Prepare(ctx context.Context, req situation.PreparationRequest) (situation.PreparedState, error) {
	// The preparation wall bounds connector I/O ONLY (review F9): every
	// durable write below runs under the caller's own context, whose
	// lease-bounded wall the controller still owns, so a slow source can
	// never turn into a lost run commit or a blocked controller commit.
	deadline := req.Now.Add(time.Duration(p.prepCfg.MaxWallSeconds) * time.Second)
	ioCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	sit := req.Claim.Situation
	fence := model.Fence{SituationID: sit.ID, InputVersion: sit.InputVersion, Owner: req.Claim.ClaimOwner, Token: req.Claim.ClaimToken}

	deliveryIDs := make([]string, 0, len(req.Input.Deliveries))
	for _, d := range req.Input.Deliveries {
		deliveryIDs = append(deliveryIDs, d.ID)
	}
	guidance, versionIDs, err := p.st.LoadProfileGuidanceForDeliveries(ctx, deliveryIDs)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load profile guidance: %w", err)
	}

	members := membersFromDeliveries(req.Input, p.selectorKeys, model.WidestHorizonTier(guidance))
	if len(members) == 0 {
		return situation.PreparedState{}, nil
	}

	rawCursors, err := p.st.LoadObservationRefreshCursors(ctx, sit.ID)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load observation refresh cursors: %w", err)
	}
	cursors := make([]observation.RefreshCursor, 0, len(rawCursors))
	for _, c := range rawCursors {
		cursors = append(cursors, observation.RefreshCursor{
			Subject: c.Subject, Capability: model.Capability(c.Capability),
			ScopeDigest: c.ScopeDigest, NextRefreshAt: c.NextRefreshAt, LastRunID: c.LastRunID,
		})
	}

	refreshInterval := time.Duration(p.prepCfg.RefreshSeconds) * time.Second
	credit, err := p.st.AccrueInvestigationCredit(ctx, sit.ID, req.Now, refreshInterval, p.prepCfg.MaxSourceCallsPerCycle)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: accrue investigation credit: %w", err)
	}

	// Both phases' plans are frozen together under one fairness allocation
	// (review F11); BeginPreparation then returns this same frozen cycle to
	// the assessment-phase call, which executes only its own subset.
	plans, alloc, err := observation.BuildPlans(observation.PlannerInput{
		Anchor: req.Now, GroupKey: sit.GroupKey, SituationID: sit.ID, Phase: "",
		Members: members, Configured: p.capabilities, ProfileGuidance: guidance,
		RefreshCursors: cursors, CycleCap: p.prepCfg.MaxSourceCallsPerCycle,
		InvestigationCredit: credit, RecoveryPending: sit.Lifecycle == situationmodel.LifecycleRecoveryPending,
		RefreshInterval: refreshInterval, PreparationWall: deadline.Sub(req.Now),
	})
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: build observation plans: %w", err)
	}
	pendingValidations, err := p.st.ListPendingExpectedBehaviorValidations(ctx, sit.ID, sit.InputVersion, req.Now)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load expected behavior validations: %w", err)
	}
	plans, err = appendExpectedBehaviorValidationPlans(plans, pendingValidations, sit.GroupKey, req.Now)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: plan expected behavior validation: %w", err)
	}
	expectedHeads, err := p.st.ListExpectedBehaviors(ctx, store.ExpectedBehaviorListFilter{GroupKey: sit.GroupKey}, 100)
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: load expected behavior heads: %w", err)
	}
	plans = appendExpectedBehaviorSchedulePlans(plans, expectedHeads, sit.GroupKey, req.Now)
	plans = p.appendAlertmanagerRulePlans(plans, req.Input, sit.GroupKey, req.Now)

	// Every nonterminal reconcile freezes (or reloads) its cycle — even a
	// phase whose plan set is entirely reuse projections — so the current
	// cycle is always a complete, explicit projection (review F16).
	cycle, err := p.st.BeginPreparation(ctx, fence, model.CycleDraft{
		Anchor: req.Now, ConfigDigest: p.configDigest, RefreshInterval: refreshInterval,
		ProfileVersionIDs: versionIDs, ProfileGuidance: guidance,
		Plans: plans, Allocation: alloc.PhaseAllocation,
	}, p.prepCfg.MaxSourceCallsPerCycle)
	if err != nil {
		p.auditRefusal(ctx, sit.ID, string(req.Phase), "begin_preparation", err)
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: begin preparation: %w", err)
	}
	// Audited immediately after the frozen cycle durably commits —
	// BeginPreparation returns the SAME cycle on a later retry for the same
	// input, so this fires again (harmlessly) on a retried attempt, exactly
	// like the reservation/outcome events it sits beside.
	p.auditAppend(ctx, "situation.preparation.cycle_begun", map[string]any{
		"situation_id": sit.ID, "cycle_id": cycle.ID, "generation": cycle.Generation,
		"phase": string(req.Phase), "plan_count": len(plans), "deferred": alloc.PhaseAllocation.Deferred,
	})

	if err := p.runner.RunPhaseBounded(ctx, ioCtx, fence, cycle, req.Phase); err != nil {
		p.auditRefusal(ctx, sit.ID, string(req.Phase), "run_phase", err)
		return situation.PreparedState{}, fmt.Errorf("cmd/alertint: run preparation phase: %w", err)
	}
	if req.Phase == model.PhaseAssessment && len(pendingValidations) > 0 {
		if err := p.st.CompleteExpectedBehaviorValidationsFromCycle(ctx, fence, cycle, req.Now); err != nil {
			p.auditRefusal(ctx, sit.ID, string(req.Phase), "complete_expected_behavior_validation", err)
			return situation.PreparedState{}, fmt.Errorf("cmd/alertint: complete expected behavior validation: %w", err)
		}
	}
	if req.Phase == model.PhaseAssessment {
		invalidated, err := p.invalidateChangedExpectedBehaviors(ctx, req.Claim, req.Now)
		if err != nil {
			return situation.PreparedState{}, err
		}
		if invalidated {
			return situation.PreparedState{}, store.ErrSituationVersionConflict
		}
	}
	p.auditAppend(ctx, "situation.preparation.phase_completed", map[string]any{
		"situation_id": sit.ID, "cycle_id": cycle.ID, "generation": cycle.Generation, "phase": string(req.Phase),
	})

	return situation.PreparedState{CycleID: cycle.ID, Generation: cycle.Generation}, nil
}

func (p *productionPreparer) appendAlertmanagerRulePlans(plans []model.Plan, in situation.SnapshotInput, groupKey string, now time.Time) []model.Plan {
	if p.alertmanagerInstanceID == "" || p.prometheusProducerID == "" {
		return plans
	}
	seen := map[string]bool{}
	for _, delivery := range in.Deliveries {
		if delivery.Source != "alertmanager" || delivery.Status != situationmodel.DeliveryStatusFiring || delivery.SourceInstanceID == nil || *delivery.SourceInstanceID != p.alertmanagerInstanceID || delivery.SourceSignalID == nil {
			continue
		}
		mapping, ok := p.alertmanagerRules[*delivery.SourceSignalID]
		if !ok {
			continue
		}
		scope := map[string]string{}
		complete := true
		for _, label := range mapping.ScopeLabels {
			value := delivery.Labels[label]
			if value == "" {
				complete = false
				break
			}
			scope[label] = value
		}
		if !complete {
			continue
		}
		encodedScope, err := json.Marshal(scope)
		if err != nil {
			continue
		}
		key := *delivery.SourceSignalID + "\x00" + string(encodedScope)
		if seen[key] || len(plans) >= model.MaxPlansPerCycle {
			continue
		}
		params, err := json.Marshal(map[string]any{"source_instance_id": p.alertmanagerInstanceID, "producer_id": p.prometheusProducerID, "group": mapping.Group, "rule": mapping.Rule, "scope_labels": scope, "fresh_for_seconds": 300})
		if err != nil {
			continue
		}
		plans = append(plans, model.Plan{Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment,
			Scope: model.Scope{GroupKey: groupKey, Source: "alertmanager", SubjectID: "rule:" + key, Labels: scope}, Parameters: params,
			Start: now.UTC(), End: now.UTC(), EligibleAt: now.UTC(), Limit: 1, MaxRequests: 2, Purpose: "alertmanager_rule_definition",
			Tier: model.TierTimeSensitive, ReconsiderOn: []string{"situation_input_changed", "envelope_changed", "observation_expired"}})
		seen[key] = true
	}
	return plans
}

func (p *productionPreparer) invalidateChangedExpectedBehaviors(ctx context.Context, claim situation.Claim, now time.Time) (bool, error) {
	if p.auditor == nil {
		return false, nil
	}
	in, err := p.st.LoadReconciliationInput(ctx, claim, now)
	if err != nil || in.ExpectedBehavior == nil {
		return false, err
	}
	invalidated := false
	for _, candidate := range in.ExpectedBehavior.Candidates {
		var reason situationmodel.ExpectedBehaviorInvalidationReason
		switch candidate.Reason { //nolint:exhaustive // only proven definition changes permanently invalidate an envelope.
		case situationmodel.ExpectedBehaviorReasonPrimaryDefinitionChanged:
			reason = situationmodel.ExpectedBehaviorPrimaryDefinitionChanged
		case situationmodel.ExpectedBehaviorReasonBindingDefinitionChanged:
			reason = situationmodel.ExpectedBehaviorBindingDefinitionChanged
		default:
			continue
		}
		changed, err := p.st.InvalidateExpectedBehavior(ctx, p.auditor, candidate.EnvelopeID, candidate.Version, reason, map[string]any{
			"situation_id": claim.Situation.ID, "evidence_refs": candidate.EvidenceRefs,
		}, now)
		if err != nil && !errors.Is(err, store.ErrExpectedBehaviorVersionConflict) && !errors.Is(err, store.ErrExpectedBehaviorStale) {
			return invalidated, fmt.Errorf("cmd/alertint: invalidate changed expected behavior: %w", err)
		}
		invalidated = invalidated || changed
	}
	return invalidated, nil
}

const expectedBehaviorValidationPurposePrefix = "expected_behavior_validation:"

func appendExpectedBehaviorValidationPlans(plans []model.Plan, validations []situationmodel.ExpectedBehaviorValidation, groupKey string, now time.Time) ([]model.Plan, error) {
	for _, validation := range validations {
		for _, binding := range validation.Bindings {
			if len(plans) >= model.MaxPlansPerCycle {
				return plans, nil
			}
			capability, maxRequests := model.CapabilityZabbixProblemState, 6
			parametersBody := map[string]any{"host": binding.Host, "trigger_id": binding.TriggerID, "trigger_version": binding.TriggerVersion, "source_instance_id": binding.SourceInstanceID, "fresh_for_seconds": 300}
			if binding.Source == "alertmanager" {
				capability, maxRequests = model.CapabilityPrometheusQuery, 2
				parametersBody = map[string]any{"source_instance_id": binding.SourceInstanceID, "producer_id": binding.ProducerID, "group": binding.RuleGroup, "rule": binding.RuleName, "scope_labels": binding.ScopeLabels, "fresh_for_seconds": 300}
			}
			parameters, err := json.Marshal(parametersBody)
			if err != nil {
				return nil, err
			}
			plans = append(plans, model.Plan{
				Capability: capability, Phase: model.PhaseAssessment,
				Scope:      model.Scope{GroupKey: groupKey, Source: binding.Source, SubjectID: validation.ID + ":" + binding.Role},
				Parameters: parameters, Start: now.UTC(), End: now.UTC(), EligibleAt: now.UTC(),
				Limit: 1, MaxRequests: maxRequests, Purpose: expectedBehaviorValidationPurposePrefix + validation.ID + ":" + binding.Role,
				Tier: model.TierTimeSensitive, ReconsiderOn: []string{"situation_input_changed", "validation_expired"},
			})
		}
	}
	return plans, nil
}

func appendExpectedBehaviorSchedulePlans(plans []model.Plan, heads []situationmodel.ExpectedBehaviorHead, groupKey string, now time.Time) []model.Plan {
	seen := make(map[string]bool)
	for _, plan := range plans {
		if plan.Capability == model.CapabilityZabbixProblemState {
			var params map[string]any
			if json.Unmarshal(plan.Parameters, &params) == nil {
				seen[fmt.Sprint(params["source_instance_id"])+"\x00"+fmt.Sprint(params["host"])+"\x00"+fmt.Sprint(params["trigger_id"])] = true
			}
		}
		if plan.Capability == model.CapabilityPrometheusQuery && plan.Purpose == "alertmanager_rule_definition" {
			var params map[string]any
			if json.Unmarshal(plan.Parameters, &params) == nil {
				scope, err := json.Marshal(params["scope_labels"])
				if err != nil {
					continue
				}
				seen[fmt.Sprint(params["source_instance_id"])+"\x00"+fmt.Sprint(params["producer_id"])+"\x00prometheus:"+fmt.Sprint(params["producer_id"])+":"+fmt.Sprint(params["group"])+":"+fmt.Sprint(params["rule"])+"\x00"+string(scope)] = true
			}
		}
	}
	for _, head := range heads {
		if head.Policy == nil {
			continue
		}
		bindings := append(append(append([]situationmodel.ExpectedBehaviorBinding{}, head.Policy.Conditions.RequiredCompanions...), head.Policy.Conditions.AllowedCompanions...), head.Policy.Conditions.ForbiddenSignals...)
		for _, binding := range bindings {
			key := binding.SourceInstanceID + "\x00" + binding.Host + "\x00" + binding.TriggerID
			if binding.Source == "alertmanager" {
				scope, err := json.Marshal(binding.ScopeLabels)
				if err != nil {
					continue
				}
				key = binding.SourceInstanceID + "\x00" + binding.ProducerID + "\x00" + binding.RuleID + "\x00" + string(scope)
			}
			if seen[key] {
				continue
			}
			if len(plans) >= model.MaxPlansPerCycle {
				return plans
			}
			capability, maxRequests, purpose := model.CapabilityZabbixProblemState, 6, "expected_behavior_evaluation"
			parametersBody := map[string]any{"host": binding.Host, "trigger_id": binding.TriggerID, "trigger_version": binding.TriggerVersion, "source_instance_id": binding.SourceInstanceID, "fresh_for_seconds": 300}
			if binding.Source == "alertmanager" {
				capability, maxRequests, purpose = model.CapabilityPrometheusQuery, 2, "alertmanager_rule_definition"
				parametersBody = map[string]any{"source_instance_id": binding.SourceInstanceID, "producer_id": binding.ProducerID, "group": binding.RuleGroup, "rule": binding.RuleName, "scope_labels": binding.ScopeLabels, "fresh_for_seconds": 300}
			}
			params, err := json.Marshal(parametersBody)
			if err != nil {
				continue
			}
			plans = append(plans, model.Plan{
				Capability: capability, Phase: model.PhaseAssessment,
				Scope:      model.Scope{GroupKey: groupKey, Source: binding.Source, SubjectID: "expected:" + key},
				Parameters: params, Start: now.UTC(), End: now.UTC(), EligibleAt: now.UTC(), Limit: 1, MaxRequests: maxRequests,
				Purpose: purpose, Tier: model.TierTimeSensitive,
				ReconsiderOn: []string{"situation_input_changed", "envelope_changed", "observation_expired"},
			})
			seen[key] = true
		}
	}
	return plans
}

// auditRefusal records a fenced preparation write the store refused
// (lease lost, input version moved on, cycle sealed/not current) — the
// "stale refusal" event spec.md's audit list requires — as a bounded class,
// never the raw error text.
func (p *productionPreparer) auditRefusal(ctx context.Context, situationID, phase, step string, err error) {
	class := "store_error"
	switch {
	case errors.Is(err, situationmodel.ErrSituationLeaseLost):
		class = "lease_lost"
	case errors.Is(err, store.ErrSituationVersionConflict):
		class = "input_version_conflict"
	case errors.Is(err, store.ErrPreparationCycleSealed):
		class = "cycle_sealed"
	case errors.Is(err, store.ErrPreparationCycleNotCurrent):
		class = "cycle_not_current"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		class = "context_done"
	}
	p.auditAppend(ctx, "situation.preparation.refused", map[string]any{
		"situation_id": situationID, "phase": phase, "step": step, "class": class,
	})
}

// auditAppend is a best-effort audit emission: a failure is logged and
// swallowed, matching internal/situation.Controller.auditAppend and
// semanticprofile.Worker.auditAppend exactly — an audit-log failure must
// never lose the durable state change it describes. A nil auditor (every
// test fixture that omits one) disables emission rather than panicking.
func (p *productionPreparer) auditAppend(ctx context.Context, kind string, payload any) {
	if p.auditor == nil {
		return
	}
	if err := p.auditor.Append(ctx, preparationAuditActor, kind, payload); err != nil {
		p.logger.Warn("cmd/alertint: preparation audit append failed", "kind", kind, "err", err)
	}
}

// preparationAuditActor is the fixed audit actor for every event
// productionPreparer emits.
const preparationAuditActor = "situation.preparer"

// membersFromDeliveries reduces in's deliveries to one MemberSubject per
// distinct Alert (Delivery.AlertID, chronologically-latest delivery wins —
// the same identity/ordering internal/situation's own incidentSymptomStatus
// uses): Firing from that latest delivery's own Status, Labels the full
// immutable delivery label set (typed parameters only), SelectorLabels the
// allowlisted subset (review F18), and ObservationDeadlineAt anchored at
// that member's LAST trustworthy observation plus the lifecycle horizon
// (review F1: spec.md "Deadlines are anchored at the last trustworthy
// observation, not the first start"; a profile may widen the horizon).
func membersFromDeliveries(in situation.SnapshotInput, selectorKeys []string, horizonTier string) []observation.MemberSubject {
	latest := make(map[string]situation.Delivery, len(in.Deliveries))
	for _, d := range in.Deliveries {
		key := d.AlertID
		if key == "" {
			key = "delivery:" + d.ID
		}
		cur, ok := latest[key]
		if !ok || d.ReceivedAt.After(cur.ReceivedAt) {
			latest[key] = d
		}
	}
	if len(latest) == 0 {
		return nil
	}

	keys := make([]string, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	horizon := model.LifecycleHorizon(horizonTier)
	members := make([]observation.MemberSubject, 0, len(keys))
	for _, k := range keys {
		d := latest[k]
		members = append(members, observation.MemberSubject{
			SubjectID: k, Source: d.Source, SourceInstanceID: d.SourceInstanceID, Labels: d.Labels, SelectorLabels: selectorLabels(d.Labels, selectorKeys),
			ObservationDeadlineAt: d.ReceivedAt.UTC().Add(horizon), RecoveryGraceUntil: in.Situation.GraceUntil,
			Firing: d.Status == situationmodel.DeliveryStatusFiring,
		})
	}
	return members
}

// selectorKeysFromConfig resolves the Selector allowlist (glossary
// "Selector allowlist"): the built-in six keys, cfg.Triage.
// ExtraSelectorLabels, and the correlator group-key labels — exactly what
// skills/acutetriage/selector.go's own allowedSelectorKeys admits, plus the
// group identity every scope must preserve. Sorted, deduplicated.
func selectorKeysFromConfig(cfg *config.Config) []string {
	seen := make(map[string]bool)
	for _, k := range logs.AllowedSelectorKeys {
		seen[k] = true
	}
	for _, k := range cfg.Triage.ExtraSelectorLabels {
		seen[k] = true
	}
	for _, k := range cfg.Correlator.GroupLabels {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// selectorLabels projects labels onto the allowlist — alert-only metadata
// (alertname, severity, ...) never becomes a metric/log/change matcher.
func selectorLabels(labels map[string]string, keys []string) map[string]string {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := labels[k]; ok && v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// capabilityDescriptorsFromConfig resolves the currently ENABLED capability
// set, each with a reasonable, versioned-cap-respecting default window/
// limit/request hint — the enablement boundary BuildPlans' own doc comment
// requires ("a capability absent from Configured is never planned
// regardless of what a profile suggests"). store_read is always enabled:
// it is a local SQLite read, never gated behind any external connector
// configuration.
func capabilityDescriptorsFromConfig(cfg *config.Config) []observation.CapabilityDescriptor {
	descs := []observation.CapabilityDescriptor{
		{Capability: model.CapabilityStoreRead, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 0},
	}
	if cfg.PrometheusEnabled() {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: 1000, MaxRequestsHint: 1,
		})
	}
	if cfg.LogsEnabled() {
		// Review F21: the configured tighter log bounds win over the
		// versioned defaults (spec.md: "configured tighter limits win").
		window := time.Hour
		if m := cfg.Logs.MaxWindowMinutes; m > 0 && time.Duration(m)*time.Minute < window {
			window = time.Duration(m) * time.Minute
		}
		limit := 200
		if cfg.Logs.MaxLines > 0 && cfg.Logs.MaxLines < limit {
			limit = cfg.Logs.MaxLines
		}
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityLokiQuery, DefaultWindow: window, DefaultLimit: limit, MaxRequestsHint: 2,
		})
	}
	if cfg.Sentry.Issues.Enabled {
		limit := 10
		if cfg.Sentry.Issues.MaxIssues > 0 && cfg.Sentry.Issues.MaxIssues < limit {
			limit = cfg.Sentry.Issues.MaxIssues
		}
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilitySentryIssues, DefaultWindow: 24 * time.Hour, DefaultLimit: limit, MaxRequestsHint: 2,
		})
	}
	if cfg.ChangesEnrichmentEnabled() {
		descs = append(descs, observation.CapabilityDescriptor{
			Capability: model.CapabilityChangeEvents, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 0,
		})
	}
	if cfg.ZabbixAPIEnabled() {
		// zabbix_metric_range needs an exact item lookup PLUS the history/
		// trend read: two physical requests (review F17).
		descs = append(descs,
			observation.CapabilityDescriptor{Capability: model.CapabilityZabbixMetricRange, DefaultWindow: time.Hour, DefaultLimit: 100, MaxRequestsHint: 2},
			observation.CapabilityDescriptor{Capability: model.CapabilityZabbixProblemHist, DefaultWindow: 24 * time.Hour, DefaultLimit: 20, MaxRequestsHint: 6},
		)
	}
	return descs
}

// preparationConfigDigest hashes the resolved capability set plus the
// preparation cadence knobs — spec.md: the persisted cycle freezes "its own
// ... configuration digest," so a later config change is at least
// detectable (never itself invalidating an already-frozen cycle: "Retry
// uses those exact values even if ... the configuration ... have
// changed").
func preparationConfigDigest(descs []observation.CapabilityDescriptor, prepCfg config.SituationPreparationConfig) string {
	b, err := json.Marshal(struct { //nolint:musttag // hash input only, never persisted/exchanged — encoding/json's default field-name marshaling is fine for a stable digest
		Descs []observation.CapabilityDescriptor
		Cfg   config.SituationPreparationConfig
	}{descs, prepCfg})
	if err != nil {
		// descs/prepCfg are always plain, marshalable values — unreachable
		// outside a programming-time invariant violation.
		panic(fmt.Sprintf("cmd/alertint: marshal preparation config digest: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// executorsFromClients registers one observation.Executor per currently
// ENABLED capability — a nil client for a capability means it was never
// configured, and Runner.RunPhase's own contract (no registered executor)
// already handles that honestly (vocabulary_unresolved), so this simply
// omits the entry rather than registering a nil-backed one. Every executor
// struct's own Client field is satisfied structurally by the real
// production client type directly (each connector file's own doc comment
// names this: "*prometheus.Client structurally satisfies it", etc.) — no
// adapter shim needed anywhere in this function.
func executorsFromClients(st *store.Store, prom *promclient.Client, lokiClient *loki.Client, sentryClient *sentry.Client, zbxClient *zabbix.Client, includeSentryMessage bool, now func() time.Time) map[model.Capability]observation.Executor {
	execs := map[model.Capability]observation.Executor{
		model.CapabilityStoreRead:    &connectors.StoreReadExecutor{Store: st, Clock: now},
		model.CapabilityChangeEvents: &connectors.ChangesExecutor{Store: st, Clock: now},
	}
	if prom != nil {
		execs[model.CapabilityPrometheusQuery] = &connectors.PrometheusExecutor{Client: prom, Clock: now}
	}
	if lokiClient != nil {
		execs[model.CapabilityLokiQuery] = &connectors.LokiExecutor{Client: lokiClient, Clock: now}
	}
	if sentryClient != nil {
		execs[model.CapabilitySentryIssues] = &connectors.SentryExecutor{
			Client: sentryClient, ProjectEnv: sentryProjectEnvFromScope, IncludeMessage: includeSentryMessage, Clock: now,
		}
	}
	if zbxClient != nil {
		execs[model.CapabilityZabbixMetricRange] = &connectors.ZabbixMetricExecutor{Client: zbxClient, Clock: now}
		execs[model.CapabilityZabbixProblemHist] = &connectors.ZabbixProblemExecutor{Client: zbxClient, SourceDefinition: zbxClient, Clock: now}
		execs[model.CapabilityZabbixProblemState] = &connectors.ZabbixProblemStateExecutor{Client: zbxClient, SourceDefinition: zbxClient, Clock: now}
	}
	return execs
}

// sentryProjectEnvFromScope derives (project, env) from a plan's own Scope
// labels — the exact label-key convention skills/acutetriage/sentry.go's
// own unexported sentryScope already established for Acute Triage's Error
// source ("service"|"project"|"app"|"job" for project,
// "environment"|"env" for env), duplicated here as a small, standalone
// lookup (not exported by that package, and this package must not import
// skills/acutetriage for one four-line function) since Scope already
// carries one member's own labels directly — no "shared across multiple
// alerts" reduction is needed the way Acute Triage's own sharedLabels does.
func sentryProjectEnvFromScope(scope model.Scope) (project, env string, ok bool) {
	for _, k := range []string{"service", "project", "app", "job"} {
		if v := scope.Labels[k]; v != "" {
			project = v
			break
		}
	}
	for _, k := range []string{"environment", "env"} {
		if v := scope.Labels[k]; v != "" {
			env = v
			break
		}
	}
	return project, env, project != ""
}

// buildPreparationRuntime resolves the semantic-profile worker's own
// one-shot L0 boundary (the SAME configured provider client Acute Triage/
// Assessment use — llm.anthropic.Client/llm.openaicompat.Client already
// implement semanticprofile.CompletionClient's identical CompleteOnce
// shape, exactly like buildAssessmentClient's own type assertion) and the
// concrete *loki.Client FetchRecentBounded needs (recovered from logSrc's
// own logs.Source interface value — nil when logs are disabled, or
// configured with a future non-Loki provider), constructs the ONE shared
// llm.InferenceLimiter L2 dispatch and every profile worker acquire from
// (never a second, independently-bounded pool), builds the full
// preparation runtime, and wires the resulting EvidencePreparer/limiter
// into crt — the construction runServe used to inline directly.
//
// Both of newPreparationRuntime's own error cases (llmClient not
// implementing CompleteOnce, an empty owner) are unreachable by the time
// runServe calls this: llmClient already passed buildAssessmentClient's
// IDENTICAL structural check inside the already-succeeded
// buildControllerRuntime call this always follows, and owner is the same
// non-empty identity newControllerRuntime's own panic guard already
// validated. Panicking on them here (rather than threading a THIRD
// "impossible in production" error return through runServe) keeps
// runServe's own golangci-lint gocyclo complexity under the repo's
// threshold — Task 9 fix round, Finding #3's own established convention,
// applied to a call-site invariant instead of a closure.
func buildPreparationRuntime(
	st *store.Store, cfg *config.Config, owner string, llmClient acutetriage.LLMClient, llmHealth *llmhealth.Tracker,
	prom *promclient.Client, logSrc logs.Source, sentryClient *sentry.Client, zbxClient *zabbix.Client,
	crt *controllerRuntime, auditor *audit.Auditor, logger *slog.Logger,
) *preparationRuntime {
	profileClient, ok := llmClient.(semanticprofile.CompletionClient)
	if !ok {
		panic(fmt.Sprintf("cmd/alertint: configured LLM client %T does not implement CompleteOnce; the semantic profile worker cannot dispatch L0 work", llmClient))
	}
	lokiClient, _ := logSrc.(*loki.Client)
	limiter := llm.NewInferenceLimiter(cfg.Situations.LLMConcurrency)

	prt, preparer, err := newPreparationRuntime(st, cfg, owner, prom, lokiClient, sentryClient, zbxClient,
		profileClient, limiter, llmHealthProfileObserver{tracker: llmHealth}, auditor, logger)
	if err != nil {
		panic(fmt.Sprintf("cmd/alertint: build preparation runtime: %v", err))
	}
	crt.SetEvidencePreparer(preparer)
	crt.SetInferenceLimiter(limiter)
	return prt
}

// newPreparationRuntime wires the full Plan 4 Task 9 preparation runtime:
// the concrete EvidencePreparer adapter (returned separately so the caller
// can inject it into every controller — situation.ControllerWorker.
// SetEvidencePreparer — since profile inference never imports internal/
// situation and cannot do that wiring itself), the semantic-profile
// inference workers (cfg.SemanticProfiles.Workers of them, sharing ONE
// llm.InferenceLimiter with the Situation controller's own L2 dispatch),
// and the three bounded sweeps (profile-change fan-out, active-mapping
// backfill, ten-day detail cleanup). owner must be the SAME non-empty,
// per-process identity foundationRuntime/controllerRuntime derive their own
// lease-owner suffixes from.
func newPreparationRuntime(
	st *store.Store, cfg *config.Config, owner string,
	prom *promclient.Client, lokiClient *loki.Client, sentryClient *sentry.Client, zbxClient *zabbix.Client,
	profileClient semanticprofile.CompletionClient, limiter *llm.InferenceLimiter,
	health semanticprofile.HealthObserver, auditor *audit.Auditor, logger *slog.Logger,
) (*preparationRuntime, situation.EvidencePreparer, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, nil, fmt.Errorf("cmd/alertint: preparation runtime requires a non-empty owner")
	}
	if logger == nil {
		logger = slog.Default()
	}
	now := func() time.Time { return time.Now().UTC() }

	prepCfg := cfg.Situations.Preparation
	descs := capabilityDescriptorsFromConfig(cfg)
	execs := executorsFromClients(st, prom, lokiClient, sentryClient, zbxClient, cfg.Sentry.Issues.MessageIncluded(), now)
	runner := observation.NewRunner(&auditingPreparationStore{Store: st, auditor: auditor, logger: logger}, execs, now)
	preparer := &productionPreparer{
		st: st, runner: runner, capabilities: descs, selectorKeys: selectorKeysFromConfig(cfg),
		configDigest: preparationConfigDigest(descs, prepCfg) + ":" + alertmanagerProvenanceDigest(cfg), prepCfg: prepCfg, logger: logger, auditor: auditor,
		alertmanagerInstanceID: cfg.Alertmanager.InstanceID, prometheusProducerID: cfg.Prometheus.InstanceID,
		alertmanagerRules: alertmanagerRuleMap(cfg),
	}

	profileCfg := cfg.Situations.SemanticProfiles
	// Review F12: the operator's max_attempts (validated 1..5) freezes onto
	// every job this process creates — set before recovery/backfill/ingress
	// can enqueue one.
	if profileCfg.MaxAttempts > 0 {
		st.SetSemanticProfileMaxAttempts(profileCfg.MaxAttempts)
	}
	workerCount := profileCfg.Workers
	if workerCount <= 0 {
		workerCount = 1
	}
	workers := make([]*semanticprofile.Worker, 0, workerCount)
	for i := 0; i < workerCount; i++ {
		w := semanticprofile.NewWorker(st, profileClient, limiter, semanticprofile.WorkerConfig{
			Owner:       fmt.Sprintf("%s:profile:%d", owner, i),
			Lease:       time.Duration(cfg.Situations.LeaseSeconds) * time.Second,
			Heartbeat:   time.Duration(cfg.Situations.HeartbeatSeconds) * time.Second,
			Interval:    time.Duration(cfg.Situations.ReconcilePollSeconds) * time.Second,
			AttemptWall: time.Duration(profileCfg.AttemptWallSeconds) * time.Second,
			Provider:    llmProviderName(cfg),
		}, nil, logger)
		w.SetHealthObserver(health)
		w.SetAuditSink(auditor)
		workers = append(workers, w)
	}

	sweepInterval := time.Duration(prepCfg.RefreshSeconds) * time.Second
	if sweepInterval <= 0 {
		sweepInterval = 5 * time.Minute
	}
	sweeps := []*preparationSweep{
		newPreparationSweep("semantic_profile_fanout", 10*time.Second, func(ctx context.Context, now time.Time) (int, error) {
			delivery, err := st.DeliverSemanticProfileChangesDetailed(ctx, now, 100)
			n := len(delivery.SituationIDs)
			if err == nil && delivery.ChangeID != "" && auditor != nil {
				_ = auditor.Append(ctx, preparationAuditActor, "semantic_profile.change_delivered", map[string]any{
					"change_id": delivery.ChangeID, "signature_key": delivery.SignatureKey,
					"version_id": delivery.VersionID, "situation_ids": delivery.SituationIDs,
					"delivered_count": n, "acknowledged": delivery.Acknowledged,
				})
			}
			return n, err
		}, now, logger),
		newPreparationSweep("semantic_profile_backfill", sweepInterval, func(ctx context.Context, now time.Time) (int, error) {
			return st.BackfillActiveSemanticMappings(ctx, now, 100)
		}, now, logger),
		newPreparationSweep("observation_detail_cleanup", time.Hour, func(ctx context.Context, now time.Time) (int, error) {
			return st.PruneUnusedObservationDetails(ctx, now, 100)
		}, now, logger),
	}

	rt := &preparationRuntime{st: st, workers: workers, sweeps: sweeps, logger: logger}
	return rt, preparer, nil
}

func alertmanagerRuleMap(cfg *config.Config) map[string]config.AlertmanagerRuleMappingConfig {
	out := make(map[string]config.AlertmanagerRuleMappingConfig, len(cfg.Alertmanager.Rules))
	for _, mapping := range cfg.Alertmanager.Rules {
		id := "prometheus:" + cfg.Prometheus.InstanceID + ":" + mapping.Group + ":" + mapping.Rule
		out[id] = mapping
	}
	return out
}

func alertmanagerProvenanceDigest(cfg *config.Config) string {
	raw, err := json.Marshal(struct { //nolint:musttag // private hash input only; field names are part of the local digest contract.
		AlertmanagerInstanceID, PrometheusInstanceID string
		Rules                                        []config.AlertmanagerRuleMappingConfig
	}{cfg.Alertmanager.InstanceID, cfg.Prometheus.InstanceID, cfg.Alertmanager.Rules})
	if err != nil {
		panic(fmt.Sprintf("cmd/alertint: marshal Alertmanager provenance digest: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// llmProviderName names the shared primary provider for durably recorded
// semantic_profile_versions/call_outcomes rows — resolved the same way
// buildAssessmentClient's own doc comment describes the L2 boundary: the
// SAME configured provider Acute Triage/Assessment use, never a second
// independently-configured one.
func llmProviderName(cfg *config.Config) string {
	return strings.ToLower(strings.TrimSpace(cfg.LLM.Provider))
}

// ----------------------------------------------------------------------
// preparationRuntime: bundles the preparer's dependent Runner/executors,
// the semantic-profile inference workers, and the bounded sweep loops
// (profile-change fan-out, active-mapping backfill, ten-day detail
// cleanup) — mirroring controllerRuntime's own construction/Recover/Start/
// Drain/Stop shape.
// ----------------------------------------------------------------------

type preparationRuntime struct {
	st      *store.Store
	workers []*semanticprofile.Worker
	sweeps  []*preparationSweep
	logger  *slog.Logger
}

// Recover runs the startup-only recovery pass: release stranded semantic-
// inference job leases (RecoverSemanticInference — a worker process that
// died mid-attempt), and backfill any missed delivery-to-signature
// attachment for active/recovery_pending followers (BackfillActiveSemanticMappings
// — an interrupted ApplySituationInput crash, or a pre-Task-7 upgrade).
// Both are zero-outward-effect, safe to call repeatedly, and must run
// before any profile worker starts claiming jobs.
func (r *preparationRuntime) Recover(ctx context.Context) error {
	now := time.Now().UTC()
	recovered, err := r.st.RecoverSemanticInference(ctx, now)
	if err != nil {
		return fmt.Errorf("cmd/alertint: recover semantic inference: %w", err)
	}
	backfilled, err := r.st.BackfillActiveSemanticMappings(ctx, now, 100)
	if err != nil {
		return fmt.Errorf("cmd/alertint: backfill active semantic mappings: %w", err)
	}
	r.logger.Info("semantic profile preparation recovered",
		slog.Int("inference_jobs_recovered", recovered),
		slog.Int("active_mappings_backfilled", backfilled),
	)
	return nil
}

// Start launches every semantic-profile worker, then every bounded sweep,
// each on its own background schedule.
func (r *preparationRuntime) Start(ctx context.Context) {
	for _, w := range r.workers {
		w.Start(ctx)
	}
	for _, s := range r.sweeps {
		s.Start(ctx)
	}
}

// Drain runs every worker's and every sweep's due work to quiescence,
// mirroring controllerRuntime.Drain's own "repeat until zero, ctx bounds
// it, only a genuine error propagates" contract.
func (r *preparationRuntime) Drain(ctx context.Context) (int, error) {
	handled := 0
	for _, w := range r.workers {
		n, err := w.Drain(ctx)
		handled += n
		if err != nil && !isShutdownErr(err) {
			return handled, fmt.Errorf("cmd/alertint: drain semantic profile worker: %w", err)
		}
	}
	for _, s := range r.sweeps {
		n, err := s.Drain(ctx)
		handled += n
		if err != nil && !isShutdownErr(err) {
			return handled, fmt.Errorf("cmd/alertint: drain preparation sweep %s: %w", s.name, err)
		}
	}
	return handled, nil
}

// Stop stops every sweep, then every semantic-profile worker (the reverse
// of Start's own order), each waiting for its current round to finish.
func (r *preparationRuntime) Stop(ctx context.Context) error {
	var errs []error
	for _, s := range r.sweeps {
		if err := s.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("preparation sweep %s stop: %w", s.name, err))
		}
	}
	for _, w := range r.workers {
		if err := w.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("semantic profile worker stop: %w", err))
		}
	}
	return joinErrors(errs)
}

func isShutdownErr(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded //nolint:errorlint // both workers/sweeps return these sentinels bare, never wrapped
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// preparationSweep runs a bounded, idempotent store primitive (profile-
// change fan-out, active-mapping backfill, ten-day detail cleanup) on its
// own schedule — the generic shape every one of Task 9's "bounded sweeps"
// shares, factored out once rather than duplicated three times.
type preparationSweep struct {
	name     string
	interval time.Duration
	run      func(ctx context.Context, now time.Time) (int, error)
	now      func() time.Time
	logger   *slog.Logger

	wakeCh    chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	startOnce sync.Once
}

func newPreparationSweep(name string, interval time.Duration, run func(ctx context.Context, now time.Time) (int, error), now func() time.Time, logger *slog.Logger) *preparationSweep {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &preparationSweep{
		name: name, interval: interval, run: run, now: now, logger: logger,
		wakeCh: make(chan struct{}, 1), stopCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
}

// RunOnce runs the sweep's own primitive exactly once, returning how many
// rows it handled.
func (s *preparationSweep) RunOnce(ctx context.Context) (int, error) {
	return s.run(ctx, s.now())
}

// Drain runs RunOnce repeatedly until a round handles zero rows or ctx is
// done — the same "repeat to quiescence" contract every worker's own Drain
// uses.
func (s *preparationSweep) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := s.RunOnce(ctx)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

func (s *preparationSweep) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		go s.run_(ctx)
	})
}

func (s *preparationSweep) run_(ctx context.Context) {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if _, err := s.Drain(ctx); err != nil && !isShutdownErr(err) {
			s.logger.Error("preparation sweep failed", "sweep", s.name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
		case <-s.wakeCh:
		}
	}
}

func (s *preparationSweep) Stop(ctx context.Context) error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	select {
	case <-s.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// auditingPreparationStore decorates the real store for the Runner so every
// durable reservation, outcome, and run commit is audited AFTER its commit
// (review F24; plan.md: audit follows the corresponding durable write).
type auditingPreparationStore struct {
	*store.Store

	auditor *audit.Auditor
	logger  *slog.Logger
}

func (a *auditingPreparationStore) audit(ctx context.Context, kind string, payload map[string]any) {
	if a.auditor == nil {
		return
	}
	if err := a.auditor.Append(ctx, preparationAuditActor, kind, payload); err != nil && a.logger != nil {
		a.logger.Warn("cmd/alertint: preparation audit append failed", "kind", kind, "err", err)
	}
}

func (a *auditingPreparationStore) ReserveObservationRequest(ctx context.Context, f model.Fence, cycleID, planID string, now time.Time) (model.RequestReservation, error) {
	res, err := a.Store.ReserveObservationRequest(ctx, f, cycleID, planID, now)
	if err == nil {
		a.audit(ctx, "situation.preparation.request_reserved", map[string]any{
			"situation_id": f.SituationID, "cycle_id": cycleID, "plan_id": planID, "reservation_id": res.ID, "ordinal": res.Ordinal,
		})
	}
	return res, err
}

func (a *auditingPreparationStore) CompleteObservationRequest(ctx context.Context, outcome model.RequestOutcome) error {
	err := a.Store.CompleteObservationRequest(ctx, outcome)
	if err == nil {
		a.audit(ctx, "situation.preparation.request_completed", map[string]any{
			"reservation_id": outcome.ReservationID, "request_started": outcome.RequestStarted, "code": outcome.Code,
		})
	}
	return err
}

func (a *auditingPreparationStore) CommitObservationRun(ctx context.Context, f model.Fence, run model.Run, now time.Time) error {
	err := a.Store.CommitObservationRun(ctx, f, run, now)
	if err == nil {
		payload := map[string]any{
			"situation_id": f.SituationID, "cycle_id": run.CycleID, "plan_id": run.PlanID, "run_id": run.ID,
			"status": string(run.Status), "fact_count": len(run.Facts), "limitation_codes": run.LimitationCodes,
		}
		if run.ReusedFromRunID != nil {
			payload["reused_from_run_id"] = *run.ReusedFromRunID
		}
		a.audit(ctx, "situation.preparation.run_committed", payload)
	}
	return err
}
