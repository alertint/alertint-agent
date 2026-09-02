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
	// DeliveryIndeterminate: a root POST was started (persisted before the
	// HTTP call) and its outcome is unknown — a transport failure after the
	// request may have been accepted, or a crash before the coordinates were
	// written. Slack may hold a root, so it is never re-posted.
	DeliveryIndeterminate = "indeterminate"

	minProbeInterval   = time.Minute
	maxContentSubjects = 8
	// unsupportedRecheck bounds how long an "unsupported" probe verdict
	// suppresses idle probing in-process before the route is re-validated.
	unsupportedRecheck = time.Hour
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

	mu   sync.Mutex
	rec  store.LLMHealthRecord
	caps map[Capability]*store.LLMCapabilityRecord
	// content-failure corroboration evidence (the bounded distinct-subject
	// set) lives on each capability's own ContentSubjects field, so it is
	// persisted/restored automatically alongside everything else in caps —
	// no separate bookkeeping map needed.
	inFlight  int
	idleSince time.Time
	// sealed is set by Seal once the Runner has acknowledged the final
	// state: from then on observations are dropped (logged), not recorded.
	sealed            bool
	probeUnsupported  bool
	unsupportedLogged bool
	kick              chan struct{}

	// activityGen counts every real call start (Begin) and every completed
	// non-ignored real call (finish); ProbeDue snapshots it into
	// probeReservedGen so ObserveProbe can detect a real call that began or
	// finished while a probe was in flight and discard the stale probe
	// failure instead of letting it override the fresher, stronger signal.
	activityGen      int64
	probeReservedGen int64

	// outstandingPosts tracks every root POST that has left planDelivery and
	// not yet returned to applyDeliveryResult, keyed by the Slack generation
	// the plan carried. A recovery that closes an episode while its POST is
	// still in flight records that episode's duration here (closed), so
	// however many episodes come and go before the POST returns, a root
	// that lands late still gets its OWN episode's recovery edit. Entries
	// are removed when the POST returns; roots awaiting their late edit are
	// durable on rec.LateRoots, never process-local.
	outstandingPosts map[int64]outstandingPost
}

// outstandingPost is the recovery metadata kept for one in-flight root POST.
type outstandingPost struct {
	closed  bool
	downFor time.Duration
}

// Observation is one in-flight LLM call started by Tracker.Begin. Exactly one
// Finish call ends it; further calls are no-ops.
type Observation struct {
	t          *Tracker
	capability Capability
	subject    string
	done       bool
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
	// probeUnsupported is deliberately NOT restored from rec.LastProbeOutcome:
	// the verdict is process-local, because the endpoint or provider it was
	// reached against may have changed in config across the restart. The
	// first idle window after boot re-validates the route.
	return &Tracker{
		st:               st,
		now:              opts.Now,
		logger:           opts.Logger,
		auditor:          opts.Auditor,
		broadcastAfter:   opts.BroadcastAfter,
		idleAfter:        opts.IdleProbeAfter,
		rec:              rec,
		caps:             caps,
		inFlight:         0,
		idleSince:        now,
		kick:             make(chan struct{}, 1),
		outstandingPosts: map[int64]outstandingPost{},
	}, nil
}

// Seal ends observation for good: the Runner calls it BEFORE its final
// delivery pass, so that pass acknowledges one immutable snapshot and the
// state it acknowledged is the state that survives. Owners join every
// producer before that pass; a join can still time out on a wedged handler,
// and whatever finishes after Seal is dropped with a warning — it can
// neither move the durable state behind (or under) the acknowledgment,
// kick a Runner that is gone, nor write to a store that is closing. Slack
// delivery is not observation: Deliver's own mutations (root coordinates,
// delivery markers, late-root edits) proceed on a sealed Tracker. Nil-safe.
func (t *Tracker) Seal() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.sealed = true
	t.mu.Unlock()
}

// Begin starts one observation of capability for subject (an Incident ID). A nil
// Tracker returns nil so Health: nil call sites need no branch.
func (t *Tracker) Begin(capability Capability, subject string) *Observation {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.sealed {
		t.mu.Unlock()
		return &Observation{t: t, capability: capability, subject: subject, done: true}
	}
	t.inFlight++
	// Starting a real call already invalidates any probe in flight: the
	// call's own Finish is the authoritative reachability signal, and a
	// probe failure landing while it runs must not pre-empt that verdict.
	t.activityGen++
	t.mu.Unlock()
	return &Observation{t: t, capability: capability, subject: subject}
}

// Finish ends the observation with err (nil on success). Safe on a nil
// Observation and idempotent — a second call is a no-op.
func (o *Observation) Finish(err error) {
	if o == nil || o.t == nil || o.done {
		return
	}
	o.done = true
	o.t.finish(o.capability, o.subject, err)
}

func (t *Tracker) finish(capability Capability, subject string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.inFlight--

	reason := Classify(err)
	if t.sealed && reason.Class() != ClassIgnored {
		t.logger.Warn("llm health: observation after the final acknowledgment dropped; the producer outlived shutdown",
			"capability", string(capability), "reason", string(reason))
		return
	}
	if reason.Class() == ClassIgnored {
		// Shutdown-driven cancellation is not an observation: no capability
		// mutation, no persist, no audit, no idle-clock reset.
		return
	}

	now := t.now()
	t.idleSince = now
	t.activityGen++
	callAt := now
	t.rec.LastRealCallAt = &callAt

	switch reason.Class() {
	case ClassOK:
		t.markCapabilityHealthy(capability, now)
		successAt := now
		t.rec.LastRealSuccessAt = &successAt
		if capability == CapabilityTriageDraft || capability == CapabilityVerificationRejudge || capability == CapabilityQueryRepair {
			t.clearCapabilityIfPresent(CapabilityProbe, now)
		}
	case ClassDependency:
		t.markCapabilityUnhealthy(capability, reason, SafeDetail(err), now)
	case ClassContent:
		t.recordContentFailure(capability, subject, reason, SafeDetail(err), now)
	case ClassIgnored:
		// Unreachable: handled by the early return above.
	}

	t.recomputeAndPersist(now)
}

// ObserveProbe records the result of one idle reachability probe.
func (t *Tracker) ObserveProbe(res llm.ProbeResult) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sealed {
		return
	}

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
		switch {
		case t.activityGen != t.probeReservedGen:
			// A real call began or completed while this probe was in
			// flight: that stronger signal (its Finish) must not be
			// pre-empted or overridden by a now-stale probe failure (the flip
			// side of "probe success cannot erase a real inference failure" —
			// a stale probe failure cannot erase a real inference success
			// either).
			t.logger.Warn("llm health: stale probe failure discarded; a real call began or completed while the probe was in flight")
		case reason.Class() == ClassDependency:
			t.markCapabilityUnhealthy(CapabilityProbe, reason, SafeDetail(res.Err), now)
		default:
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
	for capability := range t.caps {
		names = append(names, capability)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, capability := range names {
		c := t.caps[capability]
		snap.Capabilities = append(snap.Capabilities, CapabilitySnapshot{
			Capability:     capability,
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
// in-flight call, at least idleAfter since the last completed real call, at
// least one minute since the last probe, and — after an "unsupported"
// verdict — at least unsupportedRecheck since that probe, so a backend that
// gains a probe route is discovered without a restart.
func (t *Tracker) ProbeDue(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Reserve the current activity generation regardless of the outcome
	// below: if a probe does run off this decision, ObserveProbe compares
	// against this snapshot to detect a real call that raced it.
	t.probeReservedGen = t.activityGen
	if t.inFlight > 0 {
		return false
	}
	if t.probeUnsupported && (t.rec.LastProbeAt == nil || now.Sub(*t.rec.LastProbeAt) < unsupportedRecheck) {
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

// getOrCreateCap returns capability's record, creating it healthy-by-default (a
// capability that has never been observed, or has only had uncorroborated
// content failures, is not yet grounds to call it unhealthy).
func (t *Tracker) getOrCreateCap(capability Capability) *store.LLMCapabilityRecord {
	c, ok := t.caps[capability]
	if !ok {
		c = &store.LLMCapabilityRecord{Capability: string(capability), Healthy: true}
		t.caps[capability] = c
	}
	return c
}

func (t *Tracker) markCapabilityHealthy(capability Capability, now time.Time) {
	c := t.getOrCreateCap(capability)
	wasUnhealthy := !c.Healthy
	c.Healthy = true
	c.ReasonCode = ""
	c.Detail = ""
	c.UnhealthySince = nil
	// A success closes the corroboration window: content failures recorded
	// before it no longer count toward the next window's two-subject rule.
	c.ContentSubjects = nil
	successAt := now
	c.LastSuccessAt = &successAt
	if wasUnhealthy {
		t.logger.Info("llm health: capability recovered", "capability", string(capability))
	}
}

// clearCapabilityIfPresent clears an existing unhealthy record for capability
// without creating one — used when a stronger signal (a real primary-client
// success) proves reachability the probe capability itself was never asked
// about. A capability that has genuinely never been observed stays absent
// from Snapshot rather than gaining a synthetic healthy entry.
func (t *Tracker) clearCapabilityIfPresent(capability Capability, now time.Time) {
	if _, ok := t.caps[capability]; !ok {
		return
	}
	t.markCapabilityHealthy(capability, now)
}

func (t *Tracker) markCapabilityUnhealthy(capability Capability, reason Reason, detail string, now time.Time) {
	c := t.getOrCreateCap(capability)
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
		t.logger.Warn("llm health: capability unhealthy", "capability", string(capability), "reason", string(reason), "detail", detail)
	}
}

// recordContentFailure implements the content-class corroboration rule: a
// capability is marked unhealthy only once two or more distinct subjects
// have content-failed since its last success, so one pathological Incident
// cannot declare the LLM unhealthy.
func (t *Tracker) recordContentFailure(capability Capability, subject string, reason Reason, detail string, now time.Time) {
	c := t.getOrCreateCap(capability)
	failAt := now
	c.LastFailureAt = &failAt
	// A capability already unhealthy for a dependency-class reason keeps that
	// reason/detail: one uncorroborated content hiccup during a real outage
	// must not overwrite what aggregate() reports as the outage cause.
	if c.Healthy || Reason(c.ReasonCode).Class() == ClassContent {
		c.ReasonCode = string(reason)
		c.Detail = detail
	}

	subjects := c.ContentSubjects
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
		c.ContentSubjects = subjects
	}

	if len(subjects) >= 2 && c.Healthy {
		c.Healthy = false
		since := now
		c.UnhealthySince = &since
		t.logger.Warn("llm health: capability unhealthy", "capability", string(capability), "reason", string(reason), "detail", detail)
	}
}

// aggregate computes the rolled-up state and the reason/detail of the first
// unhealthy capability in priority order — triage_draft, assessment, and
// probe drive unavailable, verification_rejudge alone drives degraded, and
// this order coincides exactly with the priority the state itself implies.
// triage_draft and assessment are treated as peers (spec.md: "LLM health
// remains one installation-level capability state fed by real Acute Triage
// and Assessment outcomes") — both are primary, first-class model
// capabilities the product's core loop depends on (Acute Triage judges
// Incidents, the Situation controller's L2 dispatch judges Situations), so
// either one failing means the installation is genuinely unavailable, not
// merely degraded. memory_classifier and query_repair are reported per
// capability only: a repair success happens only when the model proposes
// invalid PromQL, so no normal-path success could ever clear a repair
// failure — driving the aggregate from it would leave the installation
// degraded indefinitely.
func (t *Tracker) aggregate() (State, string, string) {
	order := []Capability{CapabilityTriageDraft, CapabilityAssessment, CapabilityProbe, CapabilityVerificationRejudge}
	for _, capability := range order {
		c, ok := t.caps[capability]
		if !ok || c.Healthy {
			continue
		}
		state := StateDegraded
		if capability == CapabilityTriageDraft || capability == CapabilityAssessment || capability == CapabilityProbe {
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
	_ = t.persist() // logged inside; the observation is never dropped
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
		// SlackGeneration is its own independent monotonic fence, never
		// assigned from OutageGeneration: the recovery branch below also
		// increments it, so copying OutageGeneration here can coincidentally
		// reproduce a value already in flight on a stale (pre-recovery)
		// delivery plan, letting it pass applyDeliveryResult's staleness
		// check and corrupt this brand-new episode's Slack state.
		t.rec.SlackGeneration++
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
		// Bump the fence so a delivery plan computed before this recovery (an
		// in-flight PostSystemMessage/UpdateSystemMessage HTTP call that
		// hasn't returned yet) is discarded by applyDeliveryResult's
		// generation check instead of resurrecting pre-recovery Slack state
		// once it finally completes. If a root POST for this episode is still
		// in flight, remember this recovery against its generation so the
		// late root can still get this episode's own recovery edit.
		if op, ok := t.outstandingPosts[t.rec.SlackGeneration]; ok {
			op.closed, op.downFor = true, downFor
			t.outstandingPosts[t.rec.SlackGeneration] = op
		}
		t.rec.SlackGeneration++
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
		case DeliveryNone, DeliveryPending, DeliveryIndeterminate:
			// No confirmed root to edit. If an indeterminate post later
			// turns out to have succeeded (its result arrives after this
			// recovery), applyDeliveryResult adopts the root and moves this
			// to recovery_pending so it still gets its recovery edit.
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
// logged and returned; most callers ignore it by design — the in-memory
// state stays authoritative and the observation that triggered the persist
// is never dropped. The one caller that must not ignore it is the Slack
// write-ahead marker in planDelivery.
func (t *Tracker) persist() error {
	rec := t.rec
	caps := make([]store.LLMCapabilityRecord, 0, len(t.caps))
	for _, c := range t.caps {
		caps = append(caps, *c)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].Capability < caps[j].Capability })

	ctx, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	if err := t.st.SaveLLMHealth(ctx, rec, caps); err != nil {
		t.logger.Error("llm health: persist failed", "err", err)
		return err
	}
	return nil
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
	ctx, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	_ = t.auditor.Append(ctx, "llmhealth", kind, payload)
}
