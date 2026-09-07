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
	Labels    map[string]string
	// ObservationDeadlineAt is the member's current unobserved-horizon
	// deadline (spec.md "Normalized evidence and lifecycle"); zero if none
	// applies yet.
	ObservationDeadlineAt time.Time
	// RecoveryGraceUntil is the active recovery-grace checkpoint, if any.
	RecoveryGraceUntil *time.Time
	// Firing reports whether this member's latest known lifecycle state is
	// firing (still active) — recovery-pending optional work must not plan
	// firing-only investigation, per spec.md's phase-3 rule.
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
type RefreshCursor struct {
	Subject       string
	Capability    model.Capability
	ScopeDigest   string
	NextRefreshAt time.Time
}

// PlannerInput is BuildPlans' complete, already-coherent input: nothing in
// this package ever performs I/O to gather it.
type PlannerInput struct {
	Anchor              time.Time
	GroupKey            string
	Phase               model.Phase
	Members             []MemberSubject
	Configured          []CapabilityDescriptor
	ProfileGuidance     []model.ProfileGuidance
	RefreshCursors      []RefreshCursor
	CycleCap            int
	InvestigationCredit int
	RecoveryPending     bool
}

var errNoMembers = errors.New("observation: planner input requires at least one member")

// BuildPlans deterministically constructs this phase's canonical plan set
// plus its investigative-fairness allocation from in. It never performs
// I/O and never lets any profile-suggested capability escape the closed
// seven-name catalog or the configured/enabled descriptor set — in.Configured
// is itself the enablement boundary; a capability absent from it is never
// planned regardless of what a profile suggests.
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

	var timeSensitive, optional, routine []Candidate
	for _, m := range in.Members {
		for capability, desc := range enabled {
			cursorKey := m.SubjectID + "|" + string(capability)
			cursor, hasCursor := cursors[cursorKey]
			due := !hasCursor || !in.Anchor.Before(cursor.NextRefreshAt)
			if !due {
				continue
			}

			phase := model.PhaseAssessment
			timeSens, deadline := memberTimeSensitivity(m, in.Anchor)
			if timeSens {
				phase = model.PhaseLifecycle
			}
			if phase != in.Phase {
				continue
			}

			c, err := buildCandidate(in.Anchor, m, capability, desc, phase)
			if err != nil {
				continue // vocabulary_unresolved scope: silently excluded from planning, never a broad fallback
			}
			c.LastServedAt = cursor.NextRefreshAt // best available proxy for "last served" ordering
			c.TimeSensitive = timeSens
			c.Deadline = deadline

			switch {
			case timeSens:
				timeSensitive = append(timeSensitive, c)
			case suggested[capability] && !in.RecoveryPending && !m.Firing:
				c.Optional = true
				optional = append(optional, c)
			case !in.RecoveryPending || phase == model.PhaseLifecycle:
				routine = append(routine, c)
			}
		}
	}

	alloc := allocateFairly(in.CycleCap, in.InvestigationCredit, timeSensitive, optional, routine)
	sort.SliceStable(alloc.Admitted, func(i, j int) bool { return candidateKey(alloc.Admitted[i]) < candidateKey(alloc.Admitted[j]) })

	if len(alloc.Admitted) > model.MaxPlansPerCycle {
		alloc.Deferred = append(alloc.Admitted[model.MaxPlansPerCycle:], alloc.Deferred...)
		alloc.Admitted = alloc.Admitted[:model.MaxPlansPerCycle]
	}

	plans := make([]model.Plan, 0, len(alloc.Admitted))
	for _, c := range alloc.Admitted {
		plans = append(plans, candidateToPlan(c))
	}
	return plans, alloc, nil
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
// later than the anchor — and the earliest such checkpoint for ordering.
func memberTimeSensitivity(m MemberSubject, anchor time.Time) (bool, time.Time) {
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
	return !anchor.Before(earliest), earliest
}

func buildCandidate(anchor time.Time, m MemberSubject, capability model.Capability, desc CapabilityDescriptor, phase model.Phase) (Candidate, error) {
	if m.SubjectID == "" || m.Source == "" {
		return Candidate{}, fmt.Errorf("observation: member subject requires id and source")
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
	if maxRequests <= 0 {
		maxRequests = 1
	}
	start := anchor.Add(-window)
	scope := model.Scope{GroupKey: m.Source + ":" + m.SubjectID, Source: m.Source, SubjectID: m.SubjectID, Labels: m.Labels}
	purpose := "corroborate_member"
	if phase == model.PhaseLifecycle {
		purpose = "lifecycle_watch"
	}
	params, err := capabilityParameters(capability, m.Labels)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		Subject: m.SubjectID, Capability: capability, Scope: scope, Phase: phase,
		Window: [2]time.Time{start, anchor}, Limit: limit, MaxRequests: maxRequests, Purpose: purpose,
		Parameters: params,
	}, nil
}

// capabilityParameters derives capability's own typed Plan.Parameters
// payload from labels — the member's immutable, adapter-decoded label set
// (never a raw label map any executor itself parses; see connectors/
// store.go's own "this pure package never parses labels JSON itself"
// convention). Only zabbix_metric_range/zabbix_problem_history need one:
// ZabbixMetricExecutor/ZabbixProblemExecutor's own ItemKey/TriggerID have
// no Scope.SubjectID fallback the way Host does (their own doc comments).
// zabbix_trigger_id and item_key are internal/ingress/zabbix.go's own
// established webhook label conventions — adapter-proven, never invented
// here. A capability with no label to offer gets nil Parameters (the
// connector's own "no fallback" check then honestly reports
// vocabulary_unresolved, never a guessed target).
func capabilityParameters(capability model.Capability, labels map[string]string) (json.RawMessage, error) {
	switch capability {
	case model.CapabilityZabbixMetricRange:
		itemKey := labels["item_key"]
		if itemKey == "" {
			return nil, nil
		}
		return json.Marshal(struct {
			ItemKey string `json:"item_key"`
		}{ItemKey: itemKey})
	case model.CapabilityZabbixProblemHist:
		triggerID := labels["zabbix_trigger_id"]
		if triggerID == "" {
			return nil, nil
		}
		return json.Marshal(struct {
			TriggerID string `json:"trigger_id"`
		}{TriggerID: triggerID})
	case model.CapabilityStoreRead, model.CapabilityPrometheusQuery, model.CapabilityLokiQuery,
		model.CapabilitySentryIssues, model.CapabilityChangeEvents:
		return nil, nil // no typed parameters needed — Scope alone (plus store_read's own GroupKey fallback) is enough.
	default:
		return nil, nil
	}
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
	return model.Plan{
		Capability: c.Capability, Phase: c.Phase, Scope: c.Scope,
		Start: c.Window[0], End: c.Window[1], EligibleAt: c.Window[1],
		Limit: c.Limit, MaxRequests: c.MaxRequests, Purpose: c.Purpose,
		Parameters: c.Parameters,
	}
}
