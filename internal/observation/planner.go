// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// MemberSubject is one exact evidence target the planner may build
// Candidates for: a group member's identity/labels/provenance, plus the
// lifecycle timing that makes some of its reads time-sensitive.
type MemberSubject struct {
	SubjectID string
	Source    string
	// SourceInstanceID is the immutable installation identity recorded by
	// ingress for this member's latest delivery. It is never inferred from
	// endpoint configuration or labels.
	SourceInstanceID *string
	// Labels is the member's full immutable delivery label set — used only
	// to derive typed, capability-specific plan parameters (Zabbix host/
	// item/trigger, Sentry project/environment), never as a query selector.
	Labels map[string]string
	// SelectorLabels is the already-allowlisted subset of Labels every
	// constructed metric/log/change selector may assert (the built-in six
	// selector keys, configured extra selector labels, and the group-key
	// labels) — alert-only metadata such as alertname/severity never enters
	// it. Empty means the member has no admissible selector.
	SelectorLabels map[string]string
	// ObservationDeadlineAt is the member's current unobserved-horizon
	// deadline (spec.md "Normalized evidence and lifecycle"); zero if none
	// applies yet.
	ObservationDeadlineAt time.Time
	// RecoveryGraceUntil is the active recovery-grace checkpoint, if any.
	RecoveryGraceUntil *time.Time
	// Firing reports whether this member's latest known lifecycle state is
	// firing (still active).
	Firing bool
}

// CapabilityDescriptor is one configured, enabled capability's default
// planning parameters — resolved from config by the caller (Task 9's
// runtime wiring), never read from config directly by this package.
type CapabilityDescriptor struct {
	Capability      model.Capability
	DefaultWindow   time.Duration
	DefaultLimit    int
	MaxRequestsHint int // a reasonable default MaxRequests for one plan of this capability
}

// RefreshCursor is one (subject, capability, scope) admission cursor
// already loaded from internal/store's situation_observation_refresh.
// LastRunID names the last committed, still-retained run for the pair (an
// empty value means no reusable run exists).
type RefreshCursor struct {
	Subject       string
	Capability    model.Capability
	ScopeDigest   string
	NextRefreshAt time.Time
	LastRunID     string
}

// PlannerInput is BuildPlans' complete, already-coherent input: nothing in
// this package ever performs I/O to gather it.
type PlannerInput struct {
	Anchor      time.Time
	GroupKey    string
	SituationID string
	// Phase restricts the plan set to one phase; empty builds BOTH phases'
	// plans under ONE frozen fairness allocation (spec.md G1: "Freeze a
	// correct allocation over both phase plan sets") — the production
	// cycle is frozen once, then each phase executes its own subset.
	Phase               model.Phase
	Members             []MemberSubject
	Configured          []CapabilityDescriptor
	ProfileGuidance     []model.ProfileGuidance
	RefreshCursors      []RefreshCursor
	CycleCap            int
	InvestigationCredit int
	RecoveryPending     bool
	// RefreshInterval is the source cadence: a member checkpoint falling
	// within Anchor+RefreshInterval makes its lifecycle reads
	// time-sensitive (the next permitted refresh would otherwise miss it).
	RefreshInterval time.Duration
	// PreparationWall is the whole cycle's preparation wall; one third of it
	// is protected for the admitted optional plan (G1).
	PreparationWall time.Duration
}

var errNoMembers = errors.New("observation: planner input requires at least one member")

// lifecycleCapabilities are the capabilities whose reads decide recovery/
// closure and therefore run in the lifecycle phase: local delivery truth
// (store_read emits source_lifecycle observations) and exact source problem
// episodes. Every other capability corroborates and runs in the assessment
// phase only while the Situation stays active.
var lifecycleCapabilities = map[model.Capability]bool{
	model.CapabilityStoreRead:         true,
	model.CapabilityZabbixProblemHist: true,
}

// PhaseForCapability reports which preparation phase capability runs in.
func PhaseForCapability(c model.Capability) model.Phase {
	if lifecycleCapabilities[c] {
		return model.PhaseLifecycle
	}
	return model.PhaseAssessment
}

// BuildPlans deterministically constructs this phase's canonical plan set
// plus its investigative-fairness allocation from in. It never performs
// I/O and never lets any profile-suggested capability escape the closed
// seven-name catalog or the configured/enabled descriptor set — in.Configured
// is itself the enablement boundary; a capability absent from it is never
// planned regardless of what a profile suggests.
//
// Every (member, capability) pair of this phase yields exactly one plan:
// a fresh read when the pair is due and admitted, an explicit reuse plan
// (Tier reuse, ReuseRunID) when the pair is not due — or due but deferred —
// and a retained prior run exists, so a cycle's projection is always
// complete and unchanged evidence never changes hash merely because a
// different subset refreshed. A due pair that cannot be admitted and has no
// reusable run is recorded in Allocation.Deferred.
func BuildPlans(in PlannerInput) ([]model.Plan, Allocation, error) {
	if len(in.Members) == 0 {
		return nil, Allocation{}, errNoMembers
	}
	if in.CycleCap <= 0 {
		return nil, Allocation{}, errors.New("observation: planner input requires a positive cycle cap")
	}

	enabled := make(map[model.Capability]CapabilityDescriptor, len(in.Configured))
	for _, d := range in.Configured {
		if model.ValidCapability(d.Capability) {
			enabled[d.Capability] = d
		}
	}
	cursors := make(map[string]RefreshCursor, len(in.RefreshCursors))
	for _, c := range in.RefreshCursors {
		cursors[c.Subject+"|"+string(c.Capability)] = c
	}
	suggested := suggestedCapabilities(in.ProfileGuidance)
	horizonTier := model.WidestHorizonTier(in.ProfileGuidance)

	// store_read is a group-scoped local read: one plan per cycle keyed to
	// the Situation group, never one per member.
	var timeSensitive, optional, routine, local, reuse []Candidate
	seenGroupRead := false
	for _, m := range in.Members {
		for capability, desc := range enabled {
			phase := PhaseForCapability(capability)
			if in.Phase != "" && phase != in.Phase {
				continue
			}
			subject := m.SubjectID
			if capability == model.CapabilityStoreRead {
				if seenGroupRead {
					continue
				}
				seenGroupRead = true
				subject = groupSubject(in.GroupKey)
			}

			cursorKey := subject + "|" + string(capability)
			cursor, hasCursor := cursors[cursorKey]
			due := !hasCursor || !in.Anchor.Before(cursor.NextRefreshAt)

			c, err := buildCandidate(in, m, subject, capability, desc, phase, horizonTier)
			if err != nil {
				continue // vocabulary_unresolved scope: silently excluded from planning, never a broad fallback
			}
			c.LastServedAt = cursor.NextRefreshAt // best available proxy for "last served" ordering
			c.ReuseRunID = cursor.LastRunID

			if !due {
				if c.ReuseRunID != "" {
					c.Tier = model.TierReuse
					reuse = append(reuse, c)
				}
				continue
			}

			timeSens, deadline := memberTimeSensitivity(m, in.Anchor, in.RefreshInterval)
			c.TimeSensitive = timeSens && phase == model.PhaseLifecycle
			c.Deadline = deadline

			switch {
			case c.MaxRequests == 0:
				c.Tier = model.TierLocal
				local = append(local, c)
			case c.TimeSensitive:
				c.Tier = model.TierTimeSensitive
				timeSensitive = append(timeSensitive, c)
			case phase == model.PhaseLifecycle:
				// Profiles advise investigation only. They cannot demote a
				// source-lifecycle read into the optional pool, where a large
				// bounded read could repeatedly lose its refresh turn to
				// smaller assessment plans.
				c.Tier = model.TierRoutine
				routine = append(routine, c)
			case suggested[capability] && !in.RecoveryPending:
				c.Optional = true
				c.Tier = model.TierOptional
				optional = append(optional, c)
			case !in.RecoveryPending || phase == model.PhaseLifecycle:
				c.Tier = model.TierRoutine
				routine = append(routine, c)
			}
		}
	}

	alloc := allocateFairly(in.CycleCap, in.InvestigationCredit, timeSensitive, optional, routine)
	if alloc.OptionalPlanID != "" && in.PreparationWall > 0 {
		alloc.OptionalWallMilliseconds = (in.PreparationWall / 3).Milliseconds()
	}
	admitted := append([]Candidate(nil), local...)
	admitted = append(admitted, alloc.Admitted...)

	// A deferred candidate with a retained prior run is still projected by
	// explicit reuse; only a deferred candidate with nothing to reuse is a
	// bare deferral.
	reuse, bareDeferred := splitDeferredCandidates(reuse, alloc.Deferred)
	admitted = append(admitted, reuse...)
	sortByTierThenKey(admitted)

	if len(admitted) > model.MaxPlansPerCycle {
		bareDeferred = append(bareDeferred, admitted[model.MaxPlansPerCycle:]...)
		admitted = admitted[:model.MaxPlansPerCycle]
	}
	alloc.Admitted = admitted
	alloc.Deferred = bareDeferred
	alloc.PhaseAllocation.Deferred = nil
	for i, c := range bareDeferred {
		if i >= model.MaxPlansPerCycle {
			break
		}
		alloc.PhaseAllocation.Deferred = append(alloc.PhaseAllocation.Deferred, candidateKey(c))
	}

	plans := make([]model.Plan, 0, len(admitted))
	for _, c := range admitted {
		plans = append(plans, candidateToPlan(c))
	}
	return plans, alloc, nil
}

// groupSubject is the store_read plan's subject: the Situation group itself.
func groupSubject(groupKey string) string {
	return "group:" + groupKey
}

// tierRank orders execution: local reads first (no request, no wall), then
// time-sensitive lifecycle, the protected optional plan, routine, and
// finally reuse projections (pure bookkeeping).
func tierRank(t string) int {
	switch t {
	case model.TierLocal:
		return 0
	case model.TierTimeSensitive:
		return 1
	case model.TierOptional:
		return 2
	case model.TierRoutine, "":
		return 3
	case model.TierReuse:
		return 4
	}
	return 5
}

func sortByTierThenKey(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		ri, rj := tierRank(cs[i].Tier), tierRank(cs[j].Tier)
		if ri != rj {
			return ri < rj
		}
		if ri == tierRank(model.TierTimeSensitive) && !cs[i].Deadline.Equal(cs[j].Deadline) {
			return cs[i].Deadline.Before(cs[j].Deadline)
		}
		return candidateKey(cs[i]) < candidateKey(cs[j])
	})
}

func suggestedCapabilities(guidance []model.ProfileGuidance) map[model.Capability]bool {
	out := make(map[model.Capability]bool)
	for _, g := range guidance {
		for _, c := range g.UsefulCapabilities {
			out[c] = true
		}
	}
	return out
}

// memberTimeSensitivity reports whether m's next read is time-sensitive —
// its observation deadline or an active recovery-grace checkpoint falls no
// later than the next permitted refresh (anchor+refreshInterval), so
// waiting one more cadence round would miss the checkpoint — and the
// earliest such checkpoint for ordering.
func memberTimeSensitivity(m MemberSubject, anchor time.Time, refreshInterval time.Duration) (bool, time.Time) {
	var earliest time.Time
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	consider(m.ObservationDeadlineAt)
	if m.RecoveryGraceUntil != nil {
		consider(*m.RecoveryGraceUntil)
	}
	if earliest.IsZero() {
		return false, time.Time{}
	}
	if refreshInterval < 0 {
		refreshInterval = 0
	}
	return !anchor.Add(refreshInterval).Before(earliest), earliest
}

func buildCandidate(in PlannerInput, m MemberSubject, subject string, capability model.Capability, desc CapabilityDescriptor, phase model.Phase, horizonTier string) (Candidate, error) {
	if m.SubjectID == "" || m.Source == "" {
		return Candidate{}, fmt.Errorf("observation: member subject requires id and source")
	}
	if in.GroupKey == "" {
		return Candidate{}, fmt.Errorf("observation: planner input requires the situation group key")
	}
	window := desc.DefaultWindow
	if capped, ok := windowCapFor(capability); ok && window > capped {
		window = capped
	}
	limit := desc.DefaultLimit
	if limit <= 0 {
		limit = 1
	}
	maxRequests := desc.MaxRequestsHint
	if maxRequests < 0 {
		maxRequests = 0
	}
	if maxRequests == 0 && capability != model.CapabilityStoreRead && capability != model.CapabilityChangeEvents {
		maxRequests = 1
	}
	start := in.Anchor.Add(-window)
	scope := model.Scope{GroupKey: in.GroupKey, Source: m.Source, SubjectID: subject, Labels: m.SelectorLabels}
	purpose := "corroborate_member"
	if phase == model.PhaseLifecycle {
		purpose = "lifecycle_watch"
	}
	params, err := capabilityParameters(in, capability, m, horizonTier)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		Subject: subject, Capability: capability, Scope: scope, Phase: phase,
		Window: [2]time.Time{start, in.Anchor}, Limit: limit, MaxRequests: maxRequests, Purpose: purpose,
		Parameters: params,
	}, nil
}

// storeReadParameters is store_read's typed Plan.Parameters shape (mirrored
// by connectors/store.go): the exact Situation group to read, the current
// Situation to exclude from prior history, and the lifecycle horizon the
// lifecycle phase applies when emitting member observations.
type storeReadParameters struct {
	GroupKey           string `json:"group_key"`
	SituationID        string `json:"situation_id,omitempty"`
	ExcludeSituationID string `json:"exclude_situation_id,omitempty"`
	HorizonTier        string `json:"horizon_tier,omitempty"`
}

// capabilityParameters derives capability's own typed Plan.Parameters
// payload from the member's immutable, adapter-decoded label set (never a
// raw label map any executor itself parses). Zabbix needs the exact
// technical host plus item key / trigger id (internal/ingress/zabbix.go's
// established webhook label conventions); Sentry needs project/environment
// (skills/acutetriage/sentry.go's sentryScope conventions); store_read
// needs the group identity. A capability with no label to offer gets nil
// Parameters, and the connector then honestly reports vocabulary_unresolved.
func capabilityParameters(in PlannerInput, capability model.Capability, member MemberSubject, horizonTier string) (json.RawMessage, error) {
	labels := member.Labels
	switch capability {
	case model.CapabilityStoreRead:
		return json.Marshal(storeReadParameters{
			GroupKey: in.GroupKey, SituationID: in.SituationID, ExcludeSituationID: in.SituationID, HorizonTier: horizonTier,
		})
	case model.CapabilityZabbixMetricRange:
		host, itemKey := labels["host"], labels["item_key"]
		if host == "" || itemKey == "" {
			return nil, nil
		}
		return json.Marshal(struct {
			Host    string `json:"host"`
			ItemKey string `json:"item_key"`
		}{Host: host, ItemKey: itemKey})
	case model.CapabilityZabbixProblemHist:
		host, triggerID := labels["host"], labels["zabbix_trigger_id"]
		if host == "" || triggerID == "" {
			return nil, nil
		}
		return json.Marshal(struct {
			Host             string `json:"host"`
			TriggerID        string `json:"trigger_id"`
			SourceInstanceID string `json:"source_instance_id,omitempty"`
			FreshForSeconds  int    `json:"fresh_for_seconds,omitempty"`
		}{Host: host, TriggerID: triggerID, SourceInstanceID: dereferenceString(member.SourceInstanceID), FreshForSeconds: int(in.RefreshInterval.Seconds())})
	case model.CapabilitySentryIssues:
		project, env := sentryProjectEnv(labels)
		if project == "" {
			return nil, nil
		}
		return json.Marshal(struct {
			Project     string `json:"project"`
			Environment string `json:"environment,omitempty"`
		}{Project: project, Environment: env})
	case model.CapabilityPrometheusQuery, model.CapabilityLokiQuery, model.CapabilityChangeEvents:
		return nil, nil // Scope (allowlisted selector labels) alone is enough.
	default:
		return nil, nil
	}
}

func dereferenceString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// sentryProjectEnv applies skills/acutetriage/sentry.go's own label-key
// convention ("service"|"project"|"app"|"job" for project, "environment"|
// "env" for environment) to one member's full label set.
func sentryProjectEnv(labels map[string]string) (project, env string) {
	for _, k := range []string{"service", "project", "app", "job"} {
		if v := labels[k]; v != "" {
			project = v
			break
		}
	}
	for _, k := range []string{"environment", "env"} {
		if v := labels[k]; v != "" {
			env = v
			break
		}
	}
	return project, env
}

// windowCapFor mirrors internal/observation/model's unexported windowCapFor
// (the model package deliberately keeps that function private — a hard,
// versioned cap is not part of its public surface, only ValidatePlan's own
// enforcement of it is). The planner needs the SAME cap to avoid proposing
// a window ValidatePlan would then reject; duplicating this small mapping
// here (rather than exporting model's private helper) keeps the model
// package's public surface exactly what plan.md's Cross-Task Contract lists.
func windowCapFor(capability model.Capability) (time.Duration, bool) {
	switch capability {
	case model.CapabilityPrometheusQuery, model.CapabilityLokiQuery, model.CapabilityZabbixMetricRange:
		return model.MaxWindowHoursMetricsLogs * time.Hour, true
	case model.CapabilityZabbixProblemHist, model.CapabilityChangeEvents, model.CapabilitySentryIssues:
		return model.MaxWindowDaysHistory * 24 * time.Hour, true
	case model.CapabilityStoreRead:
		return 0, false
	default:
		return 0, false
	}
}

func candidateToPlan(c Candidate) model.Plan {
	p := model.Plan{
		Capability: c.Capability, Phase: c.Phase, Scope: c.Scope,
		Start: c.Window[0], End: c.Window[1], EligibleAt: c.Window[1],
		Limit: c.Limit, MaxRequests: c.MaxRequests, Purpose: c.Purpose,
		Parameters: c.Parameters, Tier: c.Tier,
	}
	if c.Tier == model.TierReuse {
		p.ReuseRunID = c.ReuseRunID
		p.MaxRequests = 0
	}
	return p
}

// splitDeferredCandidates preserves retained evidence for deferred reads.
func splitDeferredCandidates(reuse, deferred []Candidate) ([]Candidate, []Candidate) {
	var bareDeferred []Candidate
	for _, c := range deferred {
		if c.ReuseRunID != "" {
			c.Tier = model.TierReuse
			c.Optional = false
			reuse = append(reuse, c)
			continue
		}
		bareDeferred = append(bareDeferred, c)
	}
	return reuse, bareDeferred
}
