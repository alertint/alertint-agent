// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/store"
)

// State is the rolled-up installation-level LLM dependency state.
type State string

const (
	StateHealthy     State = "healthy"
	StateDegraded    State = "degraded"
	StateUnavailable State = "unavailable"
)

const (
	DeliveryNone            = "none"
	DeliveryPending         = "pending"
	DeliveryDelivered       = "delivered"
	DeliveryRecoveryPending = "recovery_pending"
	DeliveryRecovered       = "recovered"
	DeliverySuppressed      = "suppressed"

	minProbeInterval   = time.Minute
	maxContentSubjects = 8
)

// Auditor is the subset of internal/audit.Auditor the tracker needs.
type Auditor interface {
	Append(ctx context.Context, actor, kind string, payload any) error
}

// Options configures a Tracker. Zero values default: Now to time.Now().UTC,
// Logger to slog.Default(), Auditor to nil (no audit rows), and both
// durations to 5 minutes (matching the config.HealthConfig defaults).
type Options struct {
	Now            func() time.Time
	Logger         *slog.Logger
	Auditor        Auditor
	BroadcastAfter time.Duration
	IdleProbeAfter time.Duration
}

// Snapshot is the read-only view of installation LLM dependency health,
// suitable for /health and for driving Slack delivery.
type Snapshot struct {
	State             State                `json:"state"`
	Reason            Reason               `json:"reason,omitempty"`
	Detail            string               `json:"detail,omitempty"`
	UnhealthySince    *time.Time           `json:"unhealthy_since,omitempty"`
	OutageGeneration  int64                `json:"outage_generation"`
	LastRealSuccessAt *time.Time           `json:"last_real_success_at,omitempty"`
	LastProbeAt       *time.Time           `json:"last_probe_at,omitempty"`
	LastProbeOutcome  string               `json:"last_probe_outcome,omitempty"`
	InFlight          int                  `json:"in_flight"`
	Capabilities      []CapabilitySnapshot `json:"capabilities"`
}

// CapabilitySnapshot is the read-only view of one capability's health.
type CapabilitySnapshot struct {
	Capability     Capability `json:"capability"`
	Healthy        bool       `json:"healthy"`
	Reason         Reason     `json:"reason,omitempty"`
	Detail         string     `json:"detail,omitempty"`
	UnhealthySince *time.Time `json:"unhealthy_since,omitempty"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt  *time.Time `json:"last_failure_at,omitempty"`
}

// Tracker owns the in-memory + durable installation LLM dependency state: one
// aggregate plus one record per observed Capability. All mutation goes
// through Begin/Finish/ObserveProbe; Snapshot and ProbeDue are read-only.
type Tracker struct {
	st      *store.Store
	now     func() time.Time
	logger  *slog.Logger
	auditor Auditor

	broadcastAfter time.Duration
	idleAfter      time.Duration

	mu                sync.Mutex
	rec               store.LLMHealthRecord
	caps              map[Capability]*store.LLMCapabilityRecord
	contentSubjects   map[Capability][]string
	inFlight          int
	idleSince         time.Time
	probeUnsupported  bool
	unsupportedLogged bool
	kick              chan struct{}
}

// Observation is one in-flight LLM call started by Tracker.Begin. Exactly one
// Finish call ends it; further calls are no-ops.
type Observation struct {
	t       *Tracker
	cap     Capability
	subject string
	done    bool
}

// New loads persisted installation LLM dependency state and returns a ready
// Tracker. A load failure fails loud: the caller should not start serving
// with unknown dependency state.
func New(ctx context.Context, st *store.Store, opts Options) (*Tracker, error) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.BroadcastAfter <= 0 {
		opts.BroadcastAfter = 5 * time.Minute
	}
	if opts.IdleProbeAfter <= 0 {
		opts.IdleProbeAfter = 5 * time.Minute
	}

	rec, capRecs, err := st.GetLLMHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("llmhealth: load state: %w", err)
	}

	caps := make(map[Capability]*store.LLMCapabilityRecord, len(capRecs))
	for i := range capRecs {
		c := capRecs[i]
		caps[Capability(c.Capability)] = &c
	}

	now := opts.Now()
	return &Tracker{
		st:               st,
		now:              opts.Now,
		logger:           opts.Logger,
		auditor:          opts.Auditor,
		broadcastAfter:   opts.BroadcastAfter,
		idleAfter:        opts.IdleProbeAfter,
		rec:              rec,
		caps:             caps,
		contentSubjects:  make(map[Capability][]string),
		inFlight:         0,
		idleSince:        now,
		probeUnsupported: rec.LastProbeOutcome == string(llm.ProbeUnsupported),
		kick:             make(chan struct{}, 1),
	}, nil
}

// Begin starts one observation of cap for subject (an Incident ID). A nil
// Tracker returns nil so Health: nil call sites need no branch.
func (t *Tracker) Begin(cap Capability, subject string) *Observation {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.inFlight++
	t.mu.Unlock()
	return &Observation{t: t, cap: cap, subject: subject}
}

// Finish ends the observation with err (nil on success). Safe on a nil
// Observation and idempotent — a second call is a no-op.
func (o *Observation) Finish(err error) {
	if o == nil || o.t == nil || o.done {
		return
	}
	o.done = true
	o.t.finish(o.cap, o.subject, err)
}

func (t *Tracker) finish(cap Capability, subject string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.inFlight--

	reason := Classify(err)
	if reason.Class() == ClassIgnored {
		// Shutdown-driven cancellation is not an observation: no capability
		// mutation, no persist, no audit, no idle-clock reset.
		return
	}

	now := t.now()
	t.idleSince = now
	callAt := now
	t.rec.LastRealCallAt = &callAt

	switch reason.Class() {
	case ClassOK:
		t.markCapabilityHealthy(cap, now)
		successAt := now
		t.rec.LastRealSuccessAt = &successAt
		delete(t.contentSubjects, cap)
		if cap == CapabilityTriageDraft || cap == CapabilityVerificationRejudge {
			t.markCapabilityHealthy(CapabilityProbe, now)
		}
	case ClassDependency:
		t.markCapabilityUnhealthy(cap, reason, SafeDetail(err), now)
	case ClassContent:
		t.recordContentFailure(cap, subject, reason, SafeDetail(err), now)
	}

	t.recomputeAndPersist(now)
}

// ObserveProbe records the result of one idle reachability probe.
func (t *Tracker) ObserveProbe(res llm.ProbeResult) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	probeAt := now
	t.rec.LastProbeAt = &probeAt
	t.rec.LastProbeOutcome = string(res.Outcome)

	switch res.Outcome {
	case llm.ProbeOK:
		t.probeUnsupported = false
		t.markCapabilityHealthy(CapabilityProbe, now)
	case llm.ProbeUnsupported:
		t.probeUnsupported = true
		if !t.unsupportedLogged {
			t.logger.Warn("llm health: probe route unsupported; idle probing disabled")
			t.unsupportedLogged = true
		}
	case llm.ProbeFailed:
		reason := Classify(res.Err)
		if reason.Class() == ClassDependency {
			t.markCapabilityUnhealthy(CapabilityProbe, reason, SafeDetail(res.Err), now)
		} else {
			t.logger.Warn("llm health: probe failed with a non-dependency reason", "reason", string(reason))
		}
	}

	t.recomputeAndPersist(now)
	t.auditAppend("llm.health.probe", map[string]any{
		"outcome": string(res.Outcome),
		"method":  res.Method,
		"path":    res.Path,
		"status":  res.StatusCode,
	})
}

// Snapshot returns the current installation LLM dependency state.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := Snapshot{
		State:             State(t.rec.State),
		Reason:            Reason(t.rec.ReasonCode),
		Detail:            t.rec.Detail,
		UnhealthySince:    t.rec.UnhealthySince,
		OutageGeneration:  t.rec.OutageGeneration,
		LastRealSuccessAt: t.rec.LastRealSuccessAt,
		LastProbeAt:       t.rec.LastProbeAt,
		LastProbeOutcome:  t.rec.LastProbeOutcome,
		InFlight:          t.inFlight,
	}

	names := make([]Capability, 0, len(t.caps))
	for cap := range t.caps {
		names = append(names, cap)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, cap := range names {
		c := t.caps[cap]
		snap.Capabilities = append(snap.Capabilities, CapabilitySnapshot{
			Capability:     cap,
			Healthy:        c.Healthy,
			Reason:         Reason(c.ReasonCode),
			Detail:         c.Detail,
			UnhealthySince: c.UnhealthySince,
			LastSuccessAt:  c.LastSuccessAt,
			LastFailureAt:  c.LastFailureAt,
		})
	}
	return snap
}

// ProbeDue reports whether an idle reachability probe should run now: no
// in-flight call, no known-unsupported route, at least idleAfter since the
// last completed real call, and at least one minute since the last probe.
func (t *Tracker) ProbeDue(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.probeUnsupported || t.inFlight > 0 {
		return false
	}
	if now.Sub(t.idleSince) < t.idleAfter {
		return false
	}
	if t.rec.LastProbeAt != nil && now.Sub(*t.rec.LastProbeAt) < minProbeInterval {
		return false
	}
	return true
}

// Kick returns the channel the Runner selects on to wake immediately after a
// state or Slack-delivery-relevant transition, instead of waiting a full tick.
func (t *Tracker) Kick() <-chan struct{} {
	return t.kick
}

// getOrCreateCap returns cap's record, creating it healthy-by-default (a
// capability that has never been observed, or has only had uncorroborated
// content failures, is not yet grounds to call it unhealthy).
func (t *Tracker) getOrCreateCap(cap Capability) *store.LLMCapabilityRecord {
	c, ok := t.caps[cap]
	if !ok {
		c = &store.LLMCapabilityRecord{Capability: string(cap), Healthy: true}
		t.caps[cap] = c
	}
	return c
}

func (t *Tracker) markCapabilityHealthy(cap Capability, now time.Time) {
	c := t.getOrCreateCap(cap)
	wasUnhealthy := !c.Healthy
	c.Healthy = true
	c.ReasonCode = ""
	c.Detail = ""
	c.UnhealthySince = nil
	successAt := now
	c.LastSuccessAt = &successAt
	if wasUnhealthy {
		t.logger.Info("llm health: capability recovered", "capability", string(cap))
	}
}

func (t *Tracker) markCapabilityUnhealthy(cap Capability, reason Reason, detail string, now time.Time) {
	c := t.getOrCreateCap(cap)
	wasHealthy := c.Healthy
	c.Healthy = false
	c.ReasonCode = string(reason)
	c.Detail = detail
	failAt := now
	c.LastFailureAt = &failAt
	if c.UnhealthySince == nil {
		since := now
		c.UnhealthySince = &since
	}
	if wasHealthy {
		t.logger.Warn("llm health: capability unhealthy", "capability", string(cap), "reason", string(reason), "detail", detail)
	}
}

// recordContentFailure implements the content-class corroboration rule: a
// capability is marked unhealthy only once two or more distinct subjects
// have content-failed since its last success, so one pathological Incident
// cannot declare the LLM unhealthy.
func (t *Tracker) recordContentFailure(cap Capability, subject string, reason Reason, detail string, now time.Time) {
	c := t.getOrCreateCap(cap)
	failAt := now
	c.LastFailureAt = &failAt
	c.ReasonCode = string(reason)
	c.Detail = detail

	subjects := t.contentSubjects[cap]
	found := false
	for _, s := range subjects {
		if s == subject {
			found = true
			break
		}
	}
	if !found {
		subjects = append(subjects, subject)
		if len(subjects) > maxContentSubjects {
			subjects = subjects[len(subjects)-maxContentSubjects:]
		}
		t.contentSubjects[cap] = subjects
	}

	if len(subjects) >= 2 && c.Healthy {
		c.Healthy = false
		since := now
		c.UnhealthySince = &since
		t.logger.Warn("llm health: capability unhealthy", "capability", string(cap), "reason", string(reason), "detail", detail)
	}
}

// aggregate computes the rolled-up state and the reason/detail of the first
// unhealthy capability in priority order — triage_draft and probe drive
// unavailable, verification_rejudge alone drives degraded, and this order
// coincides exactly with the priority the state itself implies.
func (t *Tracker) aggregate() (State, string, string) {
	order := []Capability{CapabilityTriageDraft, CapabilityProbe, CapabilityVerificationRejudge}
	for _, cap := range order {
		c, ok := t.caps[cap]
		if !ok || c.Healthy {
			continue
		}
		state := StateDegraded
		if cap == CapabilityTriageDraft || cap == CapabilityProbe {
			state = StateUnavailable
		}
		return state, c.ReasonCode, c.Detail
	}
	return StateHealthy, "", ""
}

// recomputeAndPersist recomputes the aggregate, persists the durable state,
// and kicks the Runner if the aggregate transitioned.
func (t *Tracker) recomputeAndPersist(now time.Time) {
	changed := t.recompute(now)
	t.persist()
	if changed {
		t.kickLocked()
	}
}

func (t *Tracker) recompute(now time.Time) bool {
	newState, reasonCode, detail := t.aggregate()
	oldState := State(t.rec.State)

	if newState == oldState {
		t.rec.ReasonCode = reasonCode
		t.rec.Detail = detail
		return false
	}

	switch {
	case oldState == StateHealthy:
		t.rec.OutageGeneration++
		since := now
		t.rec.UnhealthySince = &since
		t.rec.RecoveredAt = nil
		t.rec.SlackDelivery = DeliveryNone
		t.rec.SlackTS = ""
		t.rec.SlackChannel = ""
		t.rec.SlackGeneration = t.rec.OutageGeneration
		t.rec.SlackState = ""
		t.rec.State = string(newState)
		t.rec.ReasonCode = reasonCode
		t.rec.Detail = detail
		t.auditAppend("llm.health.changed", map[string]any{
			"from": string(oldState), "to": string(newState),
			"reason": reasonCode, "detail": detail, "generation": t.rec.OutageGeneration,
		})
		t.logger.Warn("llm health: installation LLM "+string(newState), "reason", reasonCode, "detail", detail, "generation", t.rec.OutageGeneration)

	case newState == StateHealthy:
		recoveredAt := now
		t.rec.RecoveredAt = &recoveredAt
		var downFor time.Duration
		if t.rec.UnhealthySince != nil {
			downFor = now.Sub(*t.rec.UnhealthySince)
		}
		t.rec.State = string(newState)
		t.rec.ReasonCode = ""
		t.rec.Detail = ""
		t.auditAppend("llm.health.changed", map[string]any{
			"from": string(oldState), "to": string(newState), "generation": t.rec.OutageGeneration,
		})
		t.logger.Info("llm health: installation LLM healthy", "down_for", downFor.String(), "generation", t.rec.OutageGeneration)

		switch t.rec.SlackDelivery {
		case DeliveryDelivered:
			t.rec.SlackDelivery = DeliveryRecoveryPending
		case DeliveryNone, DeliveryPending:
			t.rec.SlackDelivery = DeliverySuppressed
			t.auditAppend("llm.health.slack_suppressed", map[string]any{
				"generation": t.rec.OutageGeneration, "down_for_ms": downFor.Milliseconds(),
			})
		}

	default:
		t.rec.State = string(newState)
		t.rec.ReasonCode = reasonCode
		t.rec.Detail = detail
		t.auditAppend("llm.health.changed", map[string]any{
			"from": string(oldState), "to": string(newState),
			"reason": reasonCode, "detail": detail, "generation": t.rec.OutageGeneration,
		})
		t.logger.Warn("llm health: installation LLM "+string(newState), "reason", reasonCode, "detail", detail, "generation", t.rec.OutageGeneration)
	}
	return true
}

// persist saves the current aggregate + capability records. A failure is
// logged, not surfaced: the in-memory state stays authoritative and the
// observation that triggered this persist is never dropped.
func (t *Tracker) persist() {
	rec := t.rec
	caps := make([]store.LLMCapabilityRecord, 0, len(t.caps))
	for _, c := range t.caps {
		caps = append(caps, *c)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].Capability < caps[j].Capability })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := t.st.SaveLLMHealth(ctx, rec, caps); err != nil {
		t.logger.Error("llm health: persist failed", "err", err)
	}
}

func (t *Tracker) kickLocked() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *Tracker) auditAppend(kind string, payload map[string]any) {
	if t.auditor == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.auditor.Append(ctx, "llmhealth", kind, payload)
}
