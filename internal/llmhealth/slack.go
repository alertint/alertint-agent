// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrDeliveryIndeterminate is wrapped by a Publisher when a PostSystemMessage
// failed in a way that leaves it unknown whether Slack accepted the message
// (a transport error after the request was sent). The tracker never retries
// such a post: a root may already exist, and there is no lookup to find it.
// A definite Slack rejection is returned unwrapped and is retried.
var ErrDeliveryIndeterminate = errors.New("llmhealth: slack delivery indeterminate")

// IsDeliveryIndeterminate reports whether err wraps ErrDeliveryIndeterminate.
func IsDeliveryIndeterminate(err error) bool { return errors.Is(err, ErrDeliveryIndeterminate) }

// Publisher posts and edits the one plain-text AlertINT system Slack root per
// Outage episode. Implementations never thread, never add blocks, and never
// go through the Finding notification path.
type Publisher interface {
	PostSystemMessage(ctx context.Context, text string) (channel, ts string, err error)
	UpdateSystemMessage(ctx context.Context, channel, ts, text string) error
}

// RenderOutage renders the root/edit copy for a sustained unhealthy state.
// Copy never claims uninterrupted Alert intake and never mentions Situations.
// Callers never pass StateHealthy (planDelivery only reaches here when
// state != StateHealthy); default renders the unavailable copy for
// StateUnavailable and is deliberately not split out per-value.
func RenderOutage(state State, down time.Duration) string {
	switch state { //nolint:exhaustive // StateHealthy is a caller-enforced unreachable input, not a case to render
	case StateDegraded:
		return fmt.Sprintf("⚠️ AlertINT system · LLM degraded for %s. Verification re-judgment is failing; draft Findings continue with reduced confidence.", FormatDuration(down))
	default:
		return fmt.Sprintf("⚠️ AlertINT system · LLM unavailable for %s. New Incident triage is retrying; correlation may be delayed.", FormatDuration(down))
	}
}

// RenderRecovery renders the in-place recovery edit that closes an episode.
func RenderRecovery(down time.Duration) string {
	return fmt.Sprintf("✅ AlertINT system · LLM recovered after %s. Pending triage retries continue automatically.", FormatDuration(down))
}

// FormatDuration renders a duration the way Slack copy wants it: sub-minute
// collapses to "<1m", otherwise whole minutes/hours only.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dh %dm", h, m)
	}
}

type deliverOp int

const (
	deliverNone deliverOp = iota
	deliverPost
	deliverUpdateState
	deliverUpdateRecovery
)

// deliveryPlan is computed under the tracker lock and executed unlocked, so
// the Slack HTTP call never happens under mu.
type deliveryPlan struct {
	op         deliverOp
	text       string
	channel    string
	ts         string
	generation int64
	state      State
}

// Deliver drives the Slack system-message state machine one step: post the
// root once an episode has been unhealthy for broadcastAfter, edit it in
// place on every degraded↔unavailable change inside the episode, and edit it
// once more to the recovery copy when the episode ends. pub == nil (Slack
// disabled) is a no-op — the episode still lives in state/audit/logs only.
func (t *Tracker) Deliver(ctx context.Context, pub Publisher) {
	if pub == nil {
		return
	}
	// planDelivery and applyDeliveryResult persist with their own bounded
	// context.Background() by design: the "post started" marker and the
	// delivery result must both be recorded even if ctx is canceled around
	// the HTTP call.
	plan := t.planDelivery() //nolint:contextcheck
	switch plan.op {
	case deliverNone:
	case deliverPost:
		channel, ts, err := pub.PostSystemMessage(ctx, plan.text)
		t.applyDeliveryResult(plan, channel, ts, err) //nolint:contextcheck
	case deliverUpdateState, deliverUpdateRecovery:
		err := pub.UpdateSystemMessage(ctx, plan.channel, plan.ts, plan.text)
		t.applyDeliveryResult(plan, plan.channel, plan.ts, err) //nolint:contextcheck
	}
	t.editLateRoots(ctx, pub)
}

// editLateRoots gives every root that landed after its episode had already
// closed that episode's own recovery edit, independently of the current
// episode's delivery state. A failed edit stays queued for the next step.
func (t *Tracker) editLateRoots(ctx context.Context, pub Publisher) {
	t.mu.Lock()
	pending := t.lateRoots
	t.lateRoots = nil
	t.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	var failed []lateRoot
	for _, r := range pending {
		if err := pub.UpdateSystemMessage(ctx, r.channel, r.ts, RenderRecovery(r.downFor)); err != nil {
			t.logger.Warn("llm health: late slack root recovery edit failed; will retry", "channel", r.channel, "ts", r.ts)
			failed = append(failed, r)
			continue
		}
		// auditAppend uses its own bounded context.Background() by design: a
		// delivered edit must be recorded even if ctx is canceled around it.
		t.auditAppend("llm.health.slack_updated", map[string]any{"late_root": true, "channel": r.channel, "ts": r.ts, "state": "recovered"}) //nolint:contextcheck
	}
	if len(failed) > 0 {
		t.mu.Lock()
		t.lateRoots = append(failed, t.lateRoots...)
		t.mu.Unlock()
	}
}

func (t *Tracker) planDelivery() deliveryPlan {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	state := State(t.rec.State)
	gen := t.rec.SlackGeneration

	switch {
	case state != StateHealthy && (t.rec.SlackDelivery == DeliveryNone || t.rec.SlackDelivery == DeliveryPending):
		if t.rec.UnhealthySince == nil || now.Sub(*t.rec.UnhealthySince) < t.broadcastAfter {
			return deliveryPlan{}
		}
		// Durably mark the post as started BEFORE the HTTP call: if the
		// process dies between Slack accepting the message and the
		// coordinates being written, the restarted tracker sees
		// "indeterminate" and never posts a second root for this episode.
		// A definite rejection moves it back to pending (retried); a
		// success to delivered. The guarantee only holds if the marker
		// actually commits, so a failed write means no POST this step —
		// the state reverts and the next step tries again.
		prev := t.rec.SlackDelivery
		t.rec.SlackDelivery = DeliveryIndeterminate
		if err := t.persist(); err != nil {
			t.rec.SlackDelivery = prev
			t.logger.Warn("llm health: slack system message not posted; write-ahead marker could not be persisted", "err", err)
			return deliveryPlan{}
		}
		return deliveryPlan{op: deliverPost, text: RenderOutage(state, now.Sub(*t.rec.UnhealthySince)), generation: gen, state: state}

	case state != StateHealthy && t.rec.SlackDelivery == DeliveryDelivered && t.rec.SlackState != string(state):
		var down time.Duration
		if t.rec.UnhealthySince != nil {
			down = now.Sub(*t.rec.UnhealthySince)
		}
		return deliveryPlan{op: deliverUpdateState, text: RenderOutage(state, down), channel: t.rec.SlackChannel, ts: t.rec.SlackTS, generation: gen, state: state}

	case state == StateHealthy && t.rec.SlackDelivery == DeliveryRecoveryPending:
		var down time.Duration
		if t.rec.RecoveredAt != nil && t.rec.UnhealthySince != nil {
			down = t.rec.RecoveredAt.Sub(*t.rec.UnhealthySince)
		}
		return deliveryPlan{op: deliverUpdateRecovery, text: RenderRecovery(down), channel: t.rec.SlackChannel, ts: t.rec.SlackTS, generation: gen}
	}
	return deliveryPlan{}
}

// applyDeliveryResult re-locks and applies the outcome of a Slack call, but
// only if the outage generation is still the one the plan was computed for —
// the episode may have already moved on while the HTTP call was in flight.
// The one stale result that cannot simply be dropped is a SUCCESSFUL post:
// Slack now shows a root, so its coordinates are adopted (adoptStaleRoot)
// rather than forgotten as a permanent false outage.
func (t *Tracker) applyDeliveryResult(plan deliveryPlan, channel, ts string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if plan.generation != t.rec.SlackGeneration {
		if plan.op == deliverPost && err == nil {
			t.adoptStaleRoot(plan, channel, ts)
		}
		return
	}

	switch plan.op {
	case deliverNone:
		// Deliver never calls applyDeliveryResult for deliverNone.
		return
	case deliverPost:
		if err != nil {
			if IsDeliveryIndeterminate(err) {
				// Slack may have accepted the message: leave the durable
				// "indeterminate" marker in place so this episode is never
				// posted twice. The outage still lives in /health, logs and
				// audit; a missing root is recoverable, a duplicate is not.
				t.logger.Warn("llm health: slack system message delivery indeterminate; not retrying to avoid a duplicate root")
				t.auditAppend("llm.health.slack_indeterminate", map[string]any{"generation": plan.generation, "op": "post"})
				_ = t.persist() // logged inside; the marker was already committed before the POST
				return
			}
			t.rec.SlackDelivery = DeliveryPending
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			t.auditAppend("llm.health.slack_failed", map[string]any{"generation": plan.generation, "op": "post"})
			_ = t.persist() // logged inside; the in-memory result stands
			return
		}
		t.rec.SlackDelivery = DeliveryDelivered
		t.rec.SlackTS = ts
		t.rec.SlackChannel = channel
		t.rec.SlackState = string(plan.state)
		t.auditAppend("llm.health.slack_posted", map[string]any{"generation": plan.generation, "state": string(plan.state)})

	case deliverUpdateState:
		if err != nil {
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			_ = t.persist() // logged inside; the in-memory result stands
			return
		}
		t.rec.SlackState = string(plan.state)
		t.auditAppend("llm.health.slack_updated", map[string]any{"generation": plan.generation, "state": string(plan.state)})

	case deliverUpdateRecovery:
		if err != nil {
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			_ = t.persist() // logged inside; the in-memory result stands
			return
		}
		t.rec.SlackDelivery = DeliveryRecovered
		t.auditAppend("llm.health.slack_updated", map[string]any{"generation": plan.generation, "state": "recovered"})
	}
	_ = t.persist() // logged inside; the in-memory result stands
}

// adoptStaleRoot reconciles a root that a now-stale plan successfully posted
// while its episode closed under it. Called under mu. The root belongs to
// the episode whose generation the plan carried, and only ever receives THAT
// episode's recovery edit — episodes are separate histories, so it is never
// reassigned to a later one.
//
//   - The plan's episode is the one that just recovered and nothing else has
//     happened since (state healthy, delivery suppressed): adopt the root and
//     move to recovery_pending, so the durable state machine edits it.
//   - The plan's episode is the one that just recovered but a new episode has
//     already begun: queue the root for its own recovery edit (in-memory, see
//     lateRoots); the new episode keeps its own delivery state and its own
//     broadcast_after threshold.
//   - Anything else cannot happen with the single-goroutine Runner (it would
//     need two overlapping Deliver calls); it is audited as orphaned so the
//     stray root is at least visible to an operator.
func (t *Tracker) adoptStaleRoot(plan deliveryPlan, channel, ts string) {
	if !t.lastRecovery.valid || t.lastRecovery.slackGen != plan.generation {
		t.logger.Warn("llm health: a stale slack root was posted for an episode that is no longer tracked; it will not be edited", "channel", channel, "ts", ts)
		t.auditAppend("llm.health.slack_orphaned", map[string]any{"posted_generation": plan.generation, "channel": channel, "ts": ts})
		return
	}
	if State(t.rec.State) == StateHealthy && t.rec.SlackDelivery == DeliverySuppressed {
		t.rec.SlackTS, t.rec.SlackChannel = ts, channel
		t.rec.SlackState = string(plan.state)
		t.rec.SlackDelivery = DeliveryRecoveryPending
		t.logger.Info("llm health: adopted a slack root posted during recovery; editing it to recovered")
		t.auditAppend("llm.health.slack_adopted", map[string]any{"posted_generation": plan.generation, "into": DeliveryRecoveryPending})
		_ = t.persist() // logged inside; the in-memory adoption stands
		t.kickLocked()
		return
	}
	t.lateRoots = append(t.lateRoots, lateRoot{channel: channel, ts: ts, downFor: t.lastRecovery.downFor})
	t.logger.Info("llm health: a slack root landed late for an already-closed episode; editing it to that episode's recovery")
	t.auditAppend("llm.health.slack_adopted", map[string]any{"posted_generation": plan.generation, "into": "late_recovery_edit"})
	t.kickLocked()
}
